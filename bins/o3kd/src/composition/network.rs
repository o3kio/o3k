use async_trait::async_trait;
use o3k_network;
use o3k_network_protocol;
use std::path::PathBuf;
use std::sync::Arc;
use tracing;
use uuid::Uuid;

#[derive(Clone)]
pub(crate) struct NetworkAgentDispatcher {
    pub(crate) endpoint: String,
    pub(crate) server_name: String,
    pub(crate) ca_certificate: PathBuf,
    pub(crate) client_certificate: PathBuf,
    pub(crate) client_key: PathBuf,
}

pub(crate) fn network_dispatcher_from_env()
-> Result<Option<Arc<dyn o3k_network::NetworkPlanDispatcher>>, Box<dyn std::error::Error>> {
    let names = [
        "O3K_NETWORK_AGENT_ENDPOINT",
        "O3K_NETWORK_AGENT_SERVER_NAME",
        "O3K_NETWORK_AGENT_CA",
        "O3K_NETWORK_AGENT_CLIENT_CERT",
        "O3K_NETWORK_AGENT_CLIENT_KEY",
    ];
    let values = names
        .iter()
        .map(|name| std::env::var(name).ok())
        .collect::<Vec<_>>();
    if values.iter().all(Option::is_none) {
        return Ok(None);
    }
    if values.iter().any(Option::is_none) {
        return Err("all O3K_NETWORK_AGENT_* transport variables are required".into());
    }
    let [
        endpoint,
        server_name,
        ca_certificate,
        client_certificate,
        client_key,
    ] = values
        .try_into()
        .map_err(|_| "invalid network agent transport configuration")?;
    Ok(Some(Arc::new(NetworkAgentDispatcher {
        endpoint: endpoint.ok_or("missing network agent endpoint")?,
        server_name: server_name.ok_or("missing network agent server name")?,
        ca_certificate: PathBuf::from(ca_certificate.ok_or("missing network agent CA")?),
        client_certificate: PathBuf::from(
            client_certificate.ok_or("missing network agent client certificate")?,
        ),
        client_key: PathBuf::from(client_key.ok_or("missing network agent client key")?),
    })))
}

#[async_trait]
impl o3k_network::NetworkPlanDispatcher for NetworkAgentDispatcher {
    async fn dispatch(
        &self,
        command: o3k_network::NetworkPlanCommand,
    ) -> Result<o3k_network::NetworkPlanStatus, o3k_network::NetworkDispatchError> {
        let client = o3k_network_protocol::NetworkAgentClient::connect(
            &self.endpoint,
            &self.server_name,
            &self.ca_certificate,
            &self.client_certificate,
            &self.client_key,
        )
        .await
        .map_err(|error| o3k_network::NetworkDispatchError::Transport(error.to_string()))?;
        let command_id = command.command_id.to_string();
        let result = client
            .execute(
                o3k_network_protocol::proto::Register {
                    agent_id: command.target.agent_id.clone(),
                    agent_epoch: command.target.agent_epoch.clone(),
                },
                o3k_network_protocol::proto::NetworkCommand {
                    command_id: command_id.clone(),
                    operation_id: command.operation_id.to_string(),
                    idempotency_key: command.idempotency_key,
                    agent_id: command.target.agent_id,
                    agent_epoch: command.target.agent_epoch,
                    controller_id: command.controller.controller_id,
                    controller_epoch: command.controller.controller_epoch,
                    fencing_token: command.controller.fencing_token,
                    deadline_unix_ms: command.deadline_unix_ms,
                    plan_json: serde_json::to_string(&command.plan).map_err(|error| {
                        o3k_network::NetworkDispatchError::Rejected(error.to_string())
                    })?,
                    remove: matches!(command.action, o3k_network::NetworkPlanAction::Remove),
                },
            )
            .await
            .map_err(|error| {
                tracing::warn!(
                    command_id = %command_id,
                    operation_id = %command.operation_id,
                    error = %error,
                    "network agent dispatch failed"
                );
                o3k_network::NetworkDispatchError::Transport(error.to_string())
            })?;
        tracing::debug!(
            command_id = %command_id,
            operation_id = %command.operation_id,
            status = %result.status,
            replayed = result.replayed,
            error_code = %result.error_code,
            "network agent dispatch completed"
        );
        match result.status.as_str() {
            "succeeded" | "replayed" | "recovered" => Ok(o3k_network::NetworkPlanStatus::Succeeded),
            "unknown" | "requires_observation" => Ok(o3k_network::NetworkPlanStatus::Unknown),
            other => Err(o3k_network::NetworkDispatchError::Rejected(
                if result.error_code.is_empty() {
                    other.to_owned()
                } else {
                    result.error_code
                },
            )),
        }
    }
}

pub(crate) fn public_allocator_from_env(
    data_dir: &std::path::Path,
) -> Result<Option<o3k_network::PublicAddressAllocator>, Box<dyn std::error::Error>> {
    let cidr = std::env::var("O3K_PUBLIC_POOL_CIDR").ok();
    let first = std::env::var("O3K_PUBLIC_POOL_FIRST").ok();
    let last = std::env::var("O3K_PUBLIC_POOL_LAST").ok();
    if cidr.is_none() && first.is_none() && last.is_none() {
        return Ok(None);
    }
    let cidr = cidr.ok_or("O3K_PUBLIC_POOL_CIDR is required")?;
    let first = first.ok_or("O3K_PUBLIC_POOL_FIRST is required")?.parse()?;
    let last = last.ok_or("O3K_PUBLIC_POOL_LAST is required")?.parse()?;
    let (network, prefix_len) = cidr
        .split_once('/')
        .ok_or("O3K_PUBLIC_POOL_CIDR must be IPv4/prefix-length")?;
    let prefix = o3k_domain::Ipv4Prefix::new(network.parse()?, prefix_len.parse()?)
        .ok_or("O3K_PUBLIC_POOL_CIDR is invalid")?;
    Ok(Some(o3k_network::PublicAddressAllocator::open(
        data_dir.join("public-addresses"),
        o3k_network::PublicAddressPool {
            prefix,
            first_usable: first,
            last_usable: last,
        },
    )?))
}

/// Projects terminal compute outcomes into the durable port binding state of
/// the network control plane. Wired only for the agent provider profile,
/// where the resolver records binding intent at create dispatch.
#[derive(Clone)]
pub(crate) struct NetworkBindingProjector {
    pub(crate) network: o3k_network::NetworkService,
    pub(crate) registry: Arc<dyn o3k_provider::AgentNodeRegistry>,
    pub(crate) network_dispatcher: Option<Arc<dyn o3k_network::NetworkPlanDispatcher>>,
    pub(crate) network_controller: o3k_network::NetworkControllerLease,
    pub(crate) network_external_realm_id: Option<Uuid>,
    pub(crate) network_agent: Option<o3k_network::NetworkAgentIdentity>,
    pub(crate) public_allocator: Option<Arc<o3k_network::PublicAddressAllocator>>,
    /// Terminal compute observations can be delivered more than once. Keep
    /// the read/dispatch/unbind sequence single-flight so a concurrent
    /// observation cannot construct a different remove plan while policy
    /// resources are being destroyed.
    pub(crate) unbind_lock: Arc<tokio::sync::Mutex<()>>,
}

impl NetworkBindingProjector {
    /// Resolves the canonical AddressRealm id of the configured external pool
    /// network. The canonical egress identity is the realm id, matching
    /// `compile_l3_gateway_intents`' egress identity so the routed provider
    /// sees one coherent external realm across the flat and gateway paths.
    /// Returns `None` only when no external pool network was configured. A
    /// configured pool must resolve to exactly one active canonical Realm;
    /// missing or ambiguous identity is returned as an error.
    async fn resolve_external_realm_route_id(
        &self,
        project_id: &str,
    ) -> Result<Option<Uuid>, std::io::Error> {
        let Some(network_id) = self.network_external_realm_id else {
            return Ok(None);
        };
        let realms = self
            .network
            .list_canonical_realms_for_project(project_id, network_id)
            .await
            .map_err(|error| std::io::Error::other(error.to_string()))?;
        select_active_external_realm(&realms)
            .map(Some)
            .map_err(std::io::Error::other)
    }

    async fn remove_public_binding(
        &self,
        project_id: &str,
        allocation_id: Uuid,
    ) -> Result<(), String> {
        let Some(dispatcher) = self.network_dispatcher.as_ref() else {
            return Ok(());
        };
        let Some(binding) = self
            .public_allocator
            .as_ref()
            .ok_or_else(|| "public allocator is not configured".to_owned())?
            .get(project_id, allocation_id)
            .map_err(|error| error.to_string())?
            .endpoint_id
            .map(|endpoint_id| (endpoint_id, allocation_id))
        else {
            return Ok(());
        };
        let _guard = self.unbind_lock.lock().await;
        let allocator = self
            .public_allocator
            .as_ref()
            .ok_or_else(|| "public allocator is not configured".to_owned())?;
        let allocation = allocator
            .get(project_id, binding.1)
            .map_err(|error| error.to_string())?;
        let port = self
            .network
            .get_port_for_project(project_id, binding.0)
            .await
            .map_err(|error| error.to_string())?;
        let Some(host) = port.binding_host.as_deref() else {
            return Ok(());
        };
        let agent = if let Some(configured) = self.network_agent.as_ref() {
            if configured.agent_id != host {
                return Err("bound network agent identity changed".to_owned());
            }
            configured.clone()
        } else {
            let snapshot = self
                .registry
                .snapshot(host)
                .await
                .ok_or_else(|| "network agent snapshot unavailable".to_owned())?;
            o3k_network::NetworkAgentIdentity {
                agent_id: snapshot.agent_id,
                agent_epoch: snapshot.agent_epoch,
            }
        };
        let subnet_id = port
            .subnet_id
            .ok_or_else(|| "bound port has no subnet".to_owned())?;
        let subnet = self
            .network
            .get_subnet_for_project(project_id, subnet_id)
            .await
            .map_err(|error| error.to_string())?;
        let realms = self
            .network
            .list_canonical_realms_for_project(project_id, port.network_id)
            .await
            .map_err(|error| error.to_string())?;
        let realm_id = select_active_external_realm(&realms).map_err(str::to_owned)?;
        let external_realm_route_id = self
            .resolve_external_realm_route_id(project_id)
            .await
            .map_err(|error| error.to_string())?;
        let operation_id = Uuid::new_v5(
            &Uuid::NAMESPACE_URL,
            format!(
                "o3k:native:network:public-remove:{allocation_id}:{}",
                allocation.generation
            )
            .as_bytes(),
        );
        let deadline_unix_ms = super::unix_time_millis().saturating_add(30_000);
        let plan = o3k_network::compile_attachment_plan(o3k_network::AttachmentPlanInput {
            endpoint_id: binding.0,
            realm_id,
            project_id,
            mac: &port.mac_address,
            fixed_ip: port.fixed_ip,
            subnet_cidr: &subnet.cidr,
            node_id: host,
            operation_id,
            deadline_unix_ms,
            public_address: Some(allocation.public_address),
            external_realm_id: external_realm_route_id,
            policies: Vec::new(),
        })
        .map_err(|error| error.to_string())?;
        let command_id = Uuid::new_v5(
            &Uuid::NAMESPACE_URL,
            format!("o3k:native:network:public-remove-command:{operation_id}").as_bytes(),
        );
        let status = dispatcher
            .dispatch(o3k_network::NetworkPlanCommand {
                command_id,
                operation_id,
                idempotency_key: format!("o3k:native:network:public-remove:{allocation_id}"),
                action: o3k_network::NetworkPlanAction::Remove,
                target: agent,
                controller: self.network_controller.clone(),
                deadline_unix_ms,
                plan,
            })
            .await
            .map_err(|error| error.to_string())?;
        if status != o3k_network::NetworkPlanStatus::Succeeded {
            return Err("public binding removal requires observed provider success".to_owned());
        }
        Ok(())
    }
}

#[async_trait]
impl crate::native_adapters::resource::PublicAddressWorkflow for NetworkBindingProjector {
    async fn remove(&self, project_id: &str, allocation_id: Uuid) -> Result<(), String> {
        self.remove_public_binding(project_id, allocation_id).await
    }
}

fn select_active_external_realm(
    realms: &[o3k_store::CanonicalAddressRealmRecord],
) -> Result<Uuid, &'static str> {
    let active: Vec<_> = realms
        .iter()
        .filter(|realm| realm.state == "active")
        .collect();
    match active.as_slice() {
        [realm] => Ok(realm.id),
        [] => Err("configured external network has no active canonical AddressRealm"),
        _ => Err("configured external network has multiple active canonical AddressRealms"),
    }
}

#[async_trait]
impl o3k_compute::PortBindingProjector for NetworkBindingProjector {
    async fn project_create_outcome(
        &self,
        project_id: &str,
        port_id: &str,
        succeeded: bool,
    ) -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
        let port_id = port_id.parse::<Uuid>().map_err(|error| {
            std::io::Error::new(
                std::io::ErrorKind::InvalidInput,
                format!("invalid port id {port_id:?}: {error}"),
            )
        })?;
        // Every terminal outcome and terminal unbind share the same durable
        // binding. Keep the dispatch/projection sequence in the same
        // single-flight boundary as unbind so they cannot cross between the
        // binding read and intent update.
        let _guard = self.unbind_lock.lock().await;
        let state = if succeeded {
            o3k_network::PortBindingState::Bound
        } else {
            o3k_network::PortBindingState::Error
        };
        if succeeded {
            self.dispatch_unbound_port(project_id, port_id).await?;
        }
        self.network
            .project_create_outcome(project_id, port_id, state)
            .await
            .map(|_| ())
            .map_err(|error| std::io::Error::other(error.to_string()))?;
        Ok(())
    }

    async fn unbind_port(
        &self,
        project_id: &str,
        port_id: &str,
        operation_id: uuid::Uuid,
    ) -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
        let port_id = port_id.parse::<Uuid>().map_err(|error| {
            std::io::Error::new(
                std::io::ErrorKind::InvalidInput,
                format!("invalid port id {port_id:?}: {error}"),
            )
        })?;
        let _guard = self.unbind_lock.lock().await;
        let port = self
            .network
            .get_port_for_project(project_id, port_id)
            .await
            .map_err(|error| std::io::Error::other(error.to_string()))?;
        if let (Some(dispatcher), Some(host)) = (
            self.network_dispatcher.as_ref(),
            port.binding_host.as_deref(),
        ) {
            let agent = if let Some(configured) = self.network_agent.as_ref() {
                if configured.agent_id != host {
                    return Err(
                        std::io::Error::other("bound network agent identity changed").into(),
                    );
                }
                configured.clone()
            } else {
                let snapshot =
                    self.registry.snapshot(host).await.ok_or_else(|| {
                        std::io::Error::other("network agent snapshot unavailable")
                    })?;
                o3k_network::NetworkAgentIdentity {
                    agent_id: snapshot.agent_id,
                    agent_epoch: snapshot.agent_epoch,
                }
            };
            let subnet_id = port
                .subnet_id
                .ok_or_else(|| std::io::Error::other("bound port has no subnet"))?;
            let subnet = self
                .network
                .get_subnet_for_project(project_id, subnet_id)
                .await
                .map_err(|error| std::io::Error::other(error.to_string()))?;
            let external_realm_route_id = self.resolve_external_realm_route_id(project_id).await?;
            let deadline_unix_ms = super::unix_time_millis().saturating_add(30_000);
            let plan = o3k_network::compile_attachment_plan(o3k_network::AttachmentPlanInput {
                endpoint_id: port.id,
                realm_id: port.network_id,
                project_id,
                mac: &port.mac_address,
                fixed_ip: port.fixed_ip,
                subnet_cidr: &subnet.cidr,
                node_id: host,
                operation_id,
                deadline_unix_ms,
                public_address: None,
                external_realm_id: external_realm_route_id,
                // Removal must remain stable while Terraform/OpenStack
                // destroys policy resources concurrently.  The agent removes
                // the endpoint-scoped realization; including a mutable policy
                // snapshot here would reuse the deterministic remove command
                // with a different fingerprint and be rejected as a replay.
                policies: Vec::new(),
            })
            .map_err(|error| std::io::Error::other(error.to_string()))?;
            let command_id = Uuid::new_v5(
                &Uuid::NAMESPACE_URL,
                format!("o3k:network:remove-command:{operation_id}:{port_id}").as_bytes(),
            );
            let status = dispatcher
                .dispatch(o3k_network::NetworkPlanCommand {
                    command_id,
                    operation_id,
                    idempotency_key: format!(
                        "o3k:network:remove:{project_id}:{port_id}:{operation_id}"
                    ),
                    action: o3k_network::NetworkPlanAction::Remove,
                    target: agent,
                    controller: self.network_controller.clone(),
                    deadline_unix_ms,
                    plan,
                })
                .await
                .map_err(|error| std::io::Error::other(error.to_string()))?;
            if status != o3k_network::NetworkPlanStatus::Succeeded {
                return Err(std::io::Error::other(
                    "network removal requires observation before unbinding",
                )
                .into());
            }
        }
        self.network
            .unbind_port(project_id, port_id)
            .await
            .map(|_| ())
            .map_err(|error| std::io::Error::other(error.to_string()))?;
        Ok(())
    }

    /// Releases the endpoint once its binding is cleared and its server is
    /// terminally deleted. Only an endpoint carrying O3K's reserved
    /// server-owned identity is removed: a port the caller created and supplied
    /// itself is preserved, and so is a port of any other project. An endpoint
    /// that is already gone is success.
    ///
    /// The counts are projected into the compute boundary's report type so the
    /// #1035 orphan repair sweep can log exactly what it discovered and
    /// repaired; the ownership decision itself stays in the network service.
    async fn release_server_owned_endpoint(
        &self,
        project_id: &str,
        port_id: &str,
    ) -> Result<o3k_compute::ServerEndpointRelease, Box<dyn std::error::Error + Send + Sync>> {
        let port_id = port_id.parse::<Uuid>().map_err(|error| {
            std::io::Error::new(
                std::io::ErrorKind::InvalidInput,
                format!("invalid port id {port_id:?}: {error}"),
            )
        })?;
        let report = self
            .network
            .cleanup_server_owned_ports_for_project(project_id, &[port_id])
            .await
            .map_err(|error| std::io::Error::other(error.to_string()))?;
        Ok(o3k_compute::ServerEndpointRelease {
            discovered: report.discovered,
            released: report.released,
            preserved: report.preserved,
            absent: report.absent,
        })
    }

    async fn port_binding(
        &self,
        project_id: &str,
        port_id: &str,
    ) -> Result<Option<o3k_compute::PortBindingInfo>, Box<dyn std::error::Error + Send + Sync>>
    {
        let port_id = port_id.parse::<Uuid>().map_err(|error| {
            std::io::Error::new(
                std::io::ErrorKind::InvalidInput,
                format!("invalid port id {port_id:?}: {error}"),
            )
        })?;
        let port = match self.network.get_port_for_project(project_id, port_id).await {
            Ok(port) => port,
            Err(o3k_network::NetworkError::NotFound) => return Ok(None),
            Err(error) => return Err(std::io::Error::other(error.to_string()).into()),
        };
        Ok(Some(o3k_compute::PortBindingInfo {
            server_owned: o3k_network::is_server_owned_endpoint_name(project_id, &port.name),
            binding_state: port.binding_state,
        }))
    }
}

impl NetworkBindingProjector {
    /// The agent-provider resolver dispatches before compute mutation.  Other
    /// providers (notably the portable fake/TestLab provider) complete the
    /// server operation without that resolver, so the terminal binding
    /// projection is the safe point at which to admit their network plan.
    /// This is deliberately limited to an explicitly configured network
    /// agent; without one, the historical binding projection remains a
    /// control-plane-only observation.
    async fn dispatch_unbound_port(
        &self,
        project_id: &str,
        port_id: Uuid,
    ) -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
        let Some(dispatcher) = self.network_dispatcher.as_ref() else {
            return Ok(());
        };
        let Some(agent) = self.network_agent.as_ref() else {
            return Ok(());
        };
        let port = self
            .network
            .get_port_for_project(project_id, port_id)
            .await
            .map_err(|error| std::io::Error::other(error.to_string()))?;
        // `down` is a durable explicit-unbind tombstone.  Do not recreate a
        // host-side binding from a late compute-create callback after the
        // server has already been deleted.
        if port.binding_host.is_some() || port.binding_state.as_deref() == Some("down") {
            return Ok(());
        }
        let subnet_id = port
            .subnet_id
            .ok_or_else(|| std::io::Error::other("network port has no subnet"))?;
        let subnet = self
            .network
            .get_subnet_for_project(project_id, subnet_id)
            .await
            .map_err(|error| std::io::Error::other(error.to_string()))?;
        self.network
            .record_binding_intent(project_id, port_id, &agent.agent_id)
            .await
            .map_err(|error| std::io::Error::other(error.to_string()))?;
        let external_realm_route_id = self.resolve_external_realm_route_id(project_id).await?;
        let policies = self
            .network
            .list_policies_for_project(project_id, port.network_id)
            .await
            .map_err(|error| std::io::Error::other(error.to_string()))?
            .into_iter()
            .filter(|policy| policy.endpoint_id == port.id)
            .collect();
        let policy_defaults = self
            .network
            .policy_defaults_for_endpoint(project_id, port.id)
            .await
            .map_err(|error| std::io::Error::other(error.to_string()))?;
        let public_address = self
            .public_allocator
            .as_ref()
            .map(|allocator| {
                allocator
                    .list(project_id)
                    .map_err(|error| std::io::Error::other(error.to_string()))
            })
            .transpose()?
            .and_then(|bindings| {
                bindings
                    .into_iter()
                    .find(|binding| binding.endpoint_id == Some(port.id))
                    .map(|binding| binding.public_address)
            });
        let operation_id = Uuid::new_v5(
            &Uuid::NAMESPACE_URL,
            format!("o3k:network:terminal-binding:{project_id}:{port_id}").as_bytes(),
        );
        let deadline_unix_ms = super::unix_time_millis().saturating_add(30_000);
        let plan = o3k_network::compile_attachment_plan_with_defaults(
            o3k_network::AttachmentPlanInput {
                endpoint_id: port.id,
                realm_id: port.network_id,
                project_id,
                mac: &port.mac_address,
                fixed_ip: port.fixed_ip,
                subnet_cidr: &subnet.cidr,
                node_id: &agent.agent_id,
                operation_id,
                deadline_unix_ms,
                public_address,
                external_realm_id: external_realm_route_id,
                policies,
            },
            policy_defaults,
        )
        .map_err(|error| std::io::Error::other(error.to_string()))?;
        let command_id = Uuid::new_v5(
            &Uuid::NAMESPACE_URL,
            format!("o3k:network:terminal-binding-command:{operation_id}").as_bytes(),
        );
        let status = dispatcher
            .dispatch(o3k_network::NetworkPlanCommand {
                command_id,
                operation_id,
                idempotency_key: format!("o3k:network:terminal-binding:{project_id}:{port_id}"),
                action: o3k_network::NetworkPlanAction::Apply,
                target: agent.clone(),
                controller: self.network_controller.clone(),
                deadline_unix_ms,
                plan,
            })
            .await
            .map_err(|error| std::io::Error::other(error.to_string()))?;
        if status != o3k_network::NetworkPlanStatus::Succeeded {
            return Err(std::io::Error::other(
                "network binding requires observed provider success",
            )
            .into());
        }
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::select_active_external_realm;
    use o3k_store::CanonicalAddressRealmRecord;
    use uuid::Uuid;

    fn realm(id: u128, state: &str) -> CanonicalAddressRealmRecord {
        CanonicalAddressRealmRecord {
            id: Uuid::from_u128(id),
            network_id: Uuid::from_u128(100),
            project_id: "project".to_owned(),
            prefix: "198.51.100.0/24".to_owned(),
            overlapping_prefixes: false,
            generation: 1,
            state: state.to_owned(),
        }
    }

    #[test]
    fn external_realm_selection_requires_exactly_one_active_realm() {
        let records = [realm(1, "active"), realm(2, "retired")];
        assert_eq!(
            select_active_external_realm(&records),
            Ok(Uuid::from_u128(1))
        );
    }

    #[test]
    fn external_realm_selection_fails_closed_without_active_realm() {
        assert_eq!(
            select_active_external_realm(&[realm(1, "retired")]),
            Err("configured external network has no active canonical AddressRealm")
        );
    }

    #[test]
    fn external_realm_selection_fails_closed_on_ambiguity() {
        assert_eq!(
            select_active_external_realm(&[realm(1, "active"), realm(2, "active")]),
            Err("configured external network has multiple active canonical AddressRealms")
        );
    }
}
