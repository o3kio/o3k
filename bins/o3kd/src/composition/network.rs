use async_trait::async_trait;
use o3k_network;
use o3k_network_protocol;
use serde::Deserialize;
use std::collections::BTreeMap;
use std::path::PathBuf;
use std::sync::Arc;
use tracing;
use uuid::Uuid;

#[derive(Debug, Clone, Deserialize)]
#[serde(deny_unknown_fields)]
struct NetworkAgentControlTarget {
    host_id: String,
    agent_id: String,
    endpoint: String,
    tls_server_name: String,
}

#[derive(Clone)]
struct NetworkAgentTransport {
    endpoint: String,
    server_name: String,
}

#[derive(Clone)]
pub(crate) struct NetworkAgentDispatcher {
    legacy_target: Option<NetworkAgentTransport>,
    fabric_targets: BTreeMap<String, NetworkAgentControlTarget>,
    control: Option<NetworkAgentControlLease>,
    control_lock: Arc<tokio::sync::Mutex<()>>,
    pub(crate) ca_certificate: PathBuf,
    pub(crate) client_certificate: PathBuf,
    pub(crate) client_key: PathBuf,
}

#[derive(Clone)]
struct NetworkAgentControlLease {
    coordination: Arc<dyn o3k_store::CoordinationRepository>,
    durable: Arc<dyn o3k_store::DurableStore>,
    controller_id: o3k_store::ControllerId,
    controller_epoch: o3k_store::ControllerEpoch,
}

const NETWORK_AGENT_CONTROL_TTL: std::time::Duration = std::time::Duration::from_secs(15);
// Deliberately shorter than the coordination lease. The agent independently
// stops accepting mutations if renewal is lost, even while a stale controller
// still believes its database lease is current.
const NETWORK_AGENT_REMOTE_LEASE: std::time::Duration = std::time::Duration::from_secs(8);

pub(crate) fn network_dispatcher_from_env(
    coordination: Arc<dyn o3k_store::CoordinationRepository>,
    durable: Arc<dyn o3k_store::DurableStore>,
    controller_id: o3k_store::ControllerId,
    controller_epoch: o3k_store::ControllerEpoch,
) -> Result<Option<Arc<dyn o3k_network::NetworkPlanDispatcher>>, Box<dyn std::error::Error>> {
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
    let directory_json = std::env::var("O3K_NETWORK_AGENT_DIRECTORY").ok();
    if values.iter().all(Option::is_none) && directory_json.is_none() {
        return Ok(None);
    }
    let credentials_configured = values[2..].iter().all(Option::is_some);
    if !credentials_configured {
        return Err("O3K network agent CA, client certificate, and client key are required".into());
    }
    let (legacy_target, fabric_targets) = match (values[0].as_ref(), values[1].as_ref(), directory_json) {
        (Some(endpoint), Some(server_name), None) => (
            Some(NetworkAgentTransport { endpoint: endpoint.clone(), server_name: server_name.clone() }),
            BTreeMap::new(),
        ),
        (None, None, Some(json)) => {
            let configured: Vec<NetworkAgentControlTarget> = serde_json::from_str(&json)?;
            let mut targets = BTreeMap::new();
            let mut host_ids = std::collections::BTreeSet::new();
            for target in configured {
                if target.host_id.trim().is_empty()
                    || target.agent_id.trim().is_empty()
                    || !target.endpoint.starts_with("https://")
                    || target.tls_server_name.trim().is_empty()
                    || !host_ids.insert(target.host_id.clone())
                    || targets.insert(target.agent_id.clone(), target).is_some()
                {
                    return Err("O3K_NETWORK_AGENT_DIRECTORY contains an invalid or duplicate target".into());
                }
            }
            if targets.is_empty() {
                return Err("O3K_NETWORK_AGENT_DIRECTORY must contain at least one target".into());
            }
            (None, targets)
        }
        _ => return Err("configure either the legacy single-agent endpoint or O3K_NETWORK_AGENT_DIRECTORY, not both".into()),
    };
    Ok(Some(Arc::new(NetworkAgentDispatcher {
        legacy_target,
        fabric_targets,
        control: Some(NetworkAgentControlLease {
            coordination,
            durable,
            controller_id,
            controller_epoch,
        }),
        control_lock: Arc::new(tokio::sync::Mutex::new(())),
        ca_certificate: PathBuf::from(values[2].as_ref().ok_or("missing network agent CA")?),
        client_certificate: PathBuf::from(
            values[3]
                .as_ref()
                .ok_or("missing network agent client certificate")?,
        ),
        client_key: PathBuf::from(
            values[4]
                .as_ref()
                .ok_or("missing network agent client key")?,
        ),
    })))
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct FabricHostEnrollmentConfig {
    host_id: String,
    agent_id: String,
    public_key: String,
    underlay_endpoint: String,
    fabric_transport_ip: String,
    provider_version: String,
    fabric_generation: u64,
    underlay_mtu: u16,
    fabric_mtu: u16,
    administrative_state: String,
}

/// Loads operator-enrolled, non-secret host identities into canonical durable
/// state. A conflicting current identity is rejected; rotating one requires
/// an explicit successor generation in configuration.
pub(crate) async fn enroll_fabric_hosts_from_env(
    network: &o3k_network::NetworkService,
) -> Result<(), Box<dyn std::error::Error>> {
    let Some(json) = std::env::var("O3K_FABRIC_HOST_IDENTITIES").ok() else {
        return Ok(());
    };
    let configured: Vec<FabricHostEnrollmentConfig> = serde_json::from_str(&json)?;
    if configured.is_empty() {
        return Err("O3K_FABRIC_HOST_IDENTITIES must not be an empty list".into());
    }
    let mut host_ids = std::collections::BTreeSet::new();
    for host in configured {
        if !host_ids.insert(host.host_id.clone()) {
            return Err("O3K_FABRIC_HOST_IDENTITIES has duplicate stable host IDs".into());
        }
        let identity = o3k_store::FabricHostTransportIdentityRecord {
            host_id: host.host_id,
            agent_id: host.agent_id,
            public_key: host.public_key,
            underlay_endpoint: host.underlay_endpoint,
            fabric_transport_ip: host.fabric_transport_ip.parse()?,
            provider_version: host.provider_version,
            fabric_generation: host.fabric_generation,
            underlay_mtu: host.underlay_mtu,
            fabric_mtu: host.fabric_mtu,
            administrative_state: host.administrative_state,
        };
        let current = network
            .list_fabric_host_transport_identities()
            .await?
            .into_iter()
            .find(|current| current.host_id == identity.host_id);
        let expected_generation = match current {
            None => None,
            Some(current) if current == identity => Some(identity.fabric_generation),
            Some(current) if identity.fabric_generation == current.fabric_generation + 1 => {
                Some(current.fabric_generation)
            }
            Some(_) => return Err("Fabric host identity conflicts with durable generation".into()),
        };
        network
            .enroll_fabric_host_transport_identity(&identity, expected_generation)
            .await?;
    }
    Ok(())
}

#[derive(Clone)]
pub(crate) struct FabricRealmReconciler {
    pub(crate) network: o3k_network::NetworkService,
    pub(crate) registry: Arc<dyn o3k_provider::AgentNodeRegistry>,
    pub(crate) dispatcher: Arc<dyn o3k_network::NetworkPlanDispatcher>,
    pub(crate) controller: o3k_network::NetworkControllerLease,
    pub(crate) fabric_domain_id: Uuid,
    pub(crate) network_external_realm_id: Option<Uuid>,
    pub(crate) public_allocator: Option<Arc<o3k_network::PublicAddressAllocator>>,
}

fn fabric_identity(
    identity: &o3k_store::FabricHostTransportIdentityRecord,
) -> o3k_domain::FabricHostIdentity {
    o3k_domain::FabricHostIdentity {
        host_id: identity.host_id.clone(),
        public_key: identity.public_key.clone(),
        underlay_endpoint: identity.underlay_endpoint.clone(),
        fabric_transport_ip: identity.fabric_transport_ip,
        provider_version: identity.provider_version.clone(),
        fabric_generation: identity.fabric_generation,
        underlay_mtu: identity.underlay_mtu,
        fabric_mtu: identity.fabric_mtu,
    }
}

impl FabricRealmReconciler {
    pub(crate) async fn reconcile_realm(
        &self,
        project_id: &str,
        network_id: Uuid,
        operation_id: Uuid,
        deadline_unix_ms: u64,
    ) -> Result<(), String> {
        self.reconcile_realm_internal(project_id, network_id, operation_id, deadline_unix_ms, None)
            .await
    }

    pub(crate) async fn reconcile_realm_after_unbind(
        &self,
        project_id: &str,
        network_id: Uuid,
        operation_id: Uuid,
        deadline_unix_ms: u64,
        departing_agent_id: &str,
    ) -> Result<(), String> {
        self.reconcile_realm_internal(
            project_id,
            network_id,
            operation_id,
            deadline_unix_ms,
            Some(departing_agent_id),
        )
        .await
    }

    /// Reconstructs the complete desired realm directory from canonical
    /// endpoints plus accepted port bindings, then sends one host-local v3
    /// plan to each current participating agent.
    async fn reconcile_realm_internal(
        &self,
        project_id: &str,
        network_id: Uuid,
        operation_id: Uuid,
        deadline_unix_ms: u64,
        departing_agent_id: Option<&str>,
    ) -> Result<(), String> {
        let realms = self
            .network
            .list_canonical_realms_for_project(project_id, network_id)
            .await
            .map_err(|error| error.to_string())?
            .into_iter()
            .filter(|realm| realm.state == "active")
            .collect::<Vec<_>>();
        let [realm_record] = realms.as_slice() else {
            return Err(
                "Fabric v3 requires exactly one active AddressRealm per network".to_owned(),
            );
        };
        let (prefix_address, prefix_len) = realm_record
            .prefix
            .split_once('/')
            .ok_or_else(|| "canonical AddressRealm prefix is malformed".to_owned())?;
        let prefix = o3k_domain::Ipv4Prefix::new(
            prefix_address
                .parse()
                .map_err(|_| "canonical AddressRealm IPv4 prefix is malformed")?,
            prefix_len
                .parse()
                .map_err(|_| "canonical AddressRealm prefix length is malformed")?,
        )
        .ok_or_else(|| "canonical AddressRealm prefix is invalid".to_owned())?;
        let realm = o3k_domain::AddressRealm {
            id: realm_record.id,
            network_id,
            project_id: project_id.to_owned(),
            prefix,
            overlapping_prefixes: realm_record.overlapping_prefixes,
        };
        let endpoints = self
            .network
            .list_canonical_endpoints_for_project(project_id, realm.id)
            .await
            .map_err(|error| error.to_string())?;
        let identities = self
            .network
            .list_fabric_host_transport_identities()
            .await
            .map_err(|error| error.to_string())?;
        let identities_by_agent = identities
            .into_iter()
            .map(|identity| (identity.agent_id.clone(), identity))
            .collect::<BTreeMap<_, _>>();
        let departing_identity = departing_agent_id
            .map(|agent_id| {
                identities_by_agent
                    .get(agent_id)
                    .cloned()
                    .ok_or_else(|| "departing endpoint host lacks Fabric enrollment".to_owned())
            })
            .transpose()?;
        let mut locations = Vec::new();
        let mut identities_by_host = BTreeMap::new();
        let mut selected_ports = BTreeMap::new();
        for endpoint in endpoints
            .into_iter()
            .filter(|endpoint| endpoint.state == "active")
        {
            let port = self
                .network
                .get_port_for_project(project_id, endpoint.id)
                .await
                .map_err(|error| error.to_string())?;
            let Some(agent_id) = port.binding_host.as_deref() else {
                continue;
            };
            if port.binding_state.as_deref() == Some("down") {
                continue;
            }
            if port.binding_generation == 0 {
                return Err("selected Fabric endpoint lacks placement generation".to_owned());
            }
            let identity = identities_by_agent
                .get(agent_id)
                .ok_or_else(|| "selected endpoint host lacks Fabric enrollment".to_owned())?;
            if identity.administrative_state != "enabled" {
                return Err("selected endpoint host is disabled or draining for Fabric".to_owned());
            }
            let snapshot = self
                .registry
                .snapshot(agent_id)
                .await
                .ok_or_else(|| "selected endpoint compute agent is not enrolled".to_owned())?;
            if snapshot.agent_id != agent_id
                || snapshot.availability != o3k_provider::AgentAvailability::Available
                || snapshot.administrative_state != o3k_provider::AgentAdministrativeState::Enabled
            {
                return Err("selected endpoint compute agent is stale or ineligible".to_owned());
            }
            let fabric_identity = fabric_identity(identity);
            match identities_by_host.get(&fabric_identity.host_id) {
                Some(existing) if existing != &fabric_identity => {
                    return Err("conflicting Fabric identities resolve to one host".to_owned());
                }
                Some(_) => {}
                None => {
                    identities_by_host.insert(fabric_identity.host_id.clone(), fabric_identity);
                }
            }
            locations.push(o3k_domain::EndpointLocation {
                endpoint_id: endpoint.id,
                project_id: endpoint.project_id,
                realm_id: endpoint.realm_id,
                fixed_ip: endpoint.fixed_ip,
                mac: endpoint.mac,
                selected_host: identity.host_id.clone(),
                endpoint_generation: endpoint.generation,
                placement_generation: port.binding_generation,
            });
            selected_ports.insert(endpoint.id, port);
        }
        let participants = identities_by_host.values().cloned().collect::<Vec<_>>();
        let binding = self
            .network
            .ensure_vxlan_realm_binding(self.fabric_domain_id, realm_record)
            .await
            .map_err(|error| error.to_string())?;
        if participants.is_empty() {
            let Some(identity_record) = departing_identity.as_ref() else {
                return Err("Fabric realm has no current participating endpoint".to_owned());
            };
            let identity = fabric_identity(identity_record);
            let directory = o3k_domain::RealmEndpointDirectory::build(
                &realm,
                Vec::new(),
                &[],
                realm_record.generation,
            )
            .map_err(|error| error.to_string())?;
            let tenant_mtu = identity.fabric_mtu.checked_sub(50).ok_or_else(|| {
                "departing Fabric host MTU is below the tenant minimum".to_owned()
            })?;
            let fabric = directory
                .compile_fabric_plan(
                    &identity,
                    std::slice::from_ref(&identity),
                    tenant_mtu,
                    &binding,
                )
                .map_err(|error| error.to_string())?;
            let plan = o3k_network::NodeNetworkPlan {
                schema_version: o3k_network::NODE_NETWORK_PLAN_SCHEMA_VERSION,
                plan_id: Uuid::new_v5(
                    &operation_id,
                    format!("fabric-realm-remove:{}:{}", realm.id, identity.host_id).as_bytes(),
                ),
                node_id: identity.host_id.clone(),
                operation_id,
                deadline_unix_ms,
                resource_generations: BTreeMap::from([(realm.id, realm_record.generation)]),
                intents: Vec::new(),
                fabric: None,
                gateway: None,
                fingerprint_sha256: String::new(),
            }
            .with_fabric(fabric)
            .map_err(|error| error.to_string())?;
            return self
                .dispatch_realm_plan(
                    &identity_record.agent_id,
                    &identity.host_id,
                    plan,
                    o3k_network::NetworkPlanAction::Remove,
                    operation_id,
                    deadline_unix_ms,
                )
                .await;
        }
        let plan_set = o3k_network::compile_fabric_realm_plans(
            &realm,
            locations,
            &participants,
            &binding,
            realm_record.generation,
            operation_id,
            deadline_unix_ms,
        )
        .map_err(|error| error.to_string())?;
        let all_policies = self
            .network
            .list_policies_for_project(project_id, network_id)
            .await
            .map_err(|error| error.to_string())?;
        let realm_generations = plan_set
            .plans
            .values()
            .next()
            .map(|plan| plan.resource_generations.clone())
            .unwrap_or_else(|| BTreeMap::from([(realm.id, realm_record.generation)]));
        let external_realm = if let Some(external_network_id) = self.network_external_realm_id {
            let external_realms = self
                .network
                .list_canonical_realms_for_project(project_id, external_network_id)
                .await
                .map_err(|error| error.to_string())?
                .into_iter()
                .filter(|realm| realm.state == "active")
                .collect::<Vec<_>>();
            match external_realms.as_slice() {
                [realm] => Some(realm.id),
                _ => {
                    return Err(
                        "configured external AddressRealm is missing or ambiguous".to_owned()
                    );
                }
            }
        } else {
            None
        };
        for (host_id, mut plan) in plan_set.plans {
            let local_endpoints = plan_set
                .directory
                .entries
                .iter()
                .filter(|entry| entry.selected_host == host_id)
                .collect::<Vec<_>>();
            for endpoint in local_endpoints {
                let port = selected_ports
                    .get(&endpoint.endpoint_id)
                    .ok_or_else(|| "local Fabric endpoint lost its placement record".to_owned())?;
                let subnet_id = port
                    .subnet_id
                    .ok_or_else(|| "Fabric endpoint has no subnet".to_owned())?;
                let subnet = self
                    .network
                    .get_subnet_for_project(project_id, subnet_id)
                    .await
                    .map_err(|error| error.to_string())?;
                let policies = all_policies
                    .iter()
                    .filter(|policy| policy.endpoint_id == endpoint.endpoint_id)
                    .cloned()
                    .collect();
                let defaults = self
                    .network
                    .policy_defaults_for_endpoint(project_id, endpoint.endpoint_id)
                    .await
                    .map_err(|error| error.to_string())?;
                let public_address = self
                    .public_allocator
                    .as_ref()
                    .map(|allocator| {
                        allocator
                            .list(project_id)
                            .map_err(|error| error.to_string())
                    })
                    .transpose()?
                    .and_then(|bindings| {
                        bindings
                            .into_iter()
                            .find(|allocation| allocation.endpoint_id == Some(endpoint.endpoint_id))
                            .map(|allocation| allocation.public_address)
                    });
                let attachment = o3k_network::compile_attachment_plan_with_defaults(
                    o3k_network::AttachmentPlanInput {
                        endpoint_id: endpoint.endpoint_id,
                        realm_id: realm.id,
                        project_id,
                        mac: &endpoint.mac,
                        fixed_ip: endpoint.fixed_ip,
                        subnet_cidr: &subnet.cidr,
                        node_id: &host_id,
                        operation_id,
                        deadline_unix_ms,
                        public_address,
                        external_realm_id: external_realm,
                        policies,
                    },
                    defaults,
                )
                .map_err(|error| error.to_string())?;
                plan.intents.extend(attachment.intents);
            }
            let fabric = plan
                .fabric
                .take()
                .ok_or_else(|| "compiled realm plan has no Fabric payload".to_owned())?;
            plan = plan
                .with_fabric(fabric)
                .map_err(|error| error.to_string())?;
            let target_agent_id = identities_by_agent
                .values()
                .find(|identity| identity.host_id == host_id)
                .map(|identity| identity.agent_id.as_str())
                .ok_or_else(|| "Fabric plan target has no compute agent mapping".to_owned())?;
            let snapshot = self
                .registry
                .snapshot(target_agent_id)
                .await
                .ok_or_else(|| "Fabric plan target compute agent is not enrolled".to_owned())?;
            if snapshot.agent_id != target_agent_id
                || snapshot.availability != o3k_provider::AgentAvailability::Available
                || snapshot.administrative_state != o3k_provider::AgentAdministrativeState::Enabled
            {
                return Err("Fabric plan target compute agent is stale or ineligible".to_owned());
            }
            let lease = self
                .registry
                .lease_current_epoch(target_agent_id, &snapshot.agent_epoch)
                .await
                .ok_or_else(|| "Fabric plan target agent epoch is stale".to_owned())?;
            let command_id = Uuid::new_v5(
                &operation_id,
                format!(
                    "fabric-realm-command:{}:{}:{}",
                    realm.id, host_id, realm_record.generation
                )
                .as_bytes(),
            );
            let result = self
                .dispatcher
                .dispatch(o3k_network::NetworkPlanCommand {
                    command_id,
                    operation_id,
                    idempotency_key: format!(
                        "fabric-realm:{}:{}:{}",
                        realm.id, host_id, realm_record.generation
                    ),
                    action: o3k_network::NetworkPlanAction::Apply,
                    target: o3k_network::NetworkAgentIdentity {
                        agent_id: target_agent_id.to_owned(),
                        agent_epoch: snapshot.agent_epoch.clone(),
                    },
                    controller: self.controller.clone(),
                    deadline_unix_ms,
                    plan,
                })
                .await
                .map_err(|error| error.to_string())?;
            drop(lease);
            if result != o3k_network::NetworkPlanStatus::Succeeded {
                return Err("Fabric realm plan outcome is not observed successful".to_owned());
            }
        }
        if let Some(identity_record) = departing_identity
            && !identities_by_host.contains_key(&identity_record.host_id)
        {
            let identity = fabric_identity(&identity_record);
            let mut all_identities = participants.clone();
            all_identities.push(identity.clone());
            let tenant_mtu = identity.fabric_mtu.checked_sub(50).ok_or_else(|| {
                "departing Fabric host MTU is below the tenant minimum".to_owned()
            })?;
            let fabric = plan_set
                .directory
                .compile_fabric_plan(&identity, &all_identities, tenant_mtu, &binding)
                .map_err(|error| error.to_string())?;
            let plan = o3k_network::NodeNetworkPlan {
                schema_version: o3k_network::NODE_NETWORK_PLAN_SCHEMA_VERSION,
                plan_id: Uuid::new_v5(
                    &operation_id,
                    format!("fabric-realm-remove:{}:{}", realm.id, identity.host_id).as_bytes(),
                ),
                node_id: identity.host_id.clone(),
                operation_id,
                deadline_unix_ms,
                resource_generations: realm_generations,
                intents: Vec::new(),
                fabric: None,
                gateway: None,
                fingerprint_sha256: String::new(),
            }
            .with_fabric(fabric)
            .map_err(|error| error.to_string())?;
            self.dispatch_realm_plan(
                &identity_record.agent_id,
                &identity.host_id,
                plan,
                o3k_network::NetworkPlanAction::Remove,
                operation_id,
                deadline_unix_ms,
            )
            .await?;
        }
        Ok(())
    }

    async fn dispatch_realm_plan(
        &self,
        agent_id: &str,
        host_id: &str,
        plan: o3k_network::NodeNetworkPlan,
        action: o3k_network::NetworkPlanAction,
        operation_id: Uuid,
        deadline_unix_ms: u64,
    ) -> Result<(), String> {
        if plan.node_id != host_id
            || plan
                .fabric
                .as_ref()
                .is_none_or(|fabric| fabric.local_host != host_id)
        {
            return Err("Fabric plan host does not match its dispatch target".to_owned());
        }
        let snapshot = self
            .registry
            .snapshot(agent_id)
            .await
            .ok_or_else(|| "Fabric plan target compute agent is not enrolled".to_owned())?;
        if snapshot.agent_id != agent_id
            || snapshot.availability != o3k_provider::AgentAvailability::Available
            || snapshot.administrative_state != o3k_provider::AgentAdministrativeState::Enabled
        {
            return Err("Fabric plan target compute agent is stale or ineligible".to_owned());
        }
        let lease = self
            .registry
            .lease_current_epoch(agent_id, &snapshot.agent_epoch)
            .await
            .ok_or_else(|| "Fabric plan target agent epoch is stale".to_owned())?;
        let realm_id = plan
            .fabric
            .as_ref()
            .map(|fabric| fabric.realm_id)
            .ok_or_else(|| "missing Fabric plan".to_owned())?;
        let generation = plan
            .fabric
            .as_ref()
            .map(|fabric| fabric.directory_generation)
            .unwrap_or_default();
        let action_key = match action {
            o3k_network::NetworkPlanAction::Apply => "apply",
            o3k_network::NetworkPlanAction::Remove => "remove",
        };
        let command_id = Uuid::new_v5(
            &operation_id,
            format!("fabric-realm-command:{action_key}:{realm_id}:{host_id}:{generation}")
                .as_bytes(),
        );
        let status = self
            .dispatcher
            .dispatch(o3k_network::NetworkPlanCommand {
                command_id,
                operation_id,
                idempotency_key: format!(
                    "fabric-realm:{action_key}:{realm_id}:{host_id}:{generation}:{operation_id}"
                ),
                action,
                target: o3k_network::NetworkAgentIdentity {
                    agent_id: agent_id.to_owned(),
                    agent_epoch: snapshot.agent_epoch,
                },
                controller: self.controller.clone(),
                deadline_unix_ms,
                plan,
            })
            .await
            .map_err(|error| error.to_string())?;
        drop(lease);
        if status != o3k_network::NetworkPlanStatus::Succeeded {
            return Err("Fabric realm plan outcome is not observed successful".to_owned());
        }
        Ok(())
    }
}

/// Replays durable history as observation only, then rediscovers active
/// canonical realms through the same reconciler used by endpoint lifecycle.
/// Registration notifications wake the scan; the bounded interval also
/// retries transiently unavailable agents and observes enrollment generation
/// changes that arrive through durable configuration reload.
pub(crate) fn spawn_fabric_recovery(
    reconciler: Arc<FabricRealmReconciler>,
    durable: Arc<dyn o3k_store::DurableStore>,
    registration_notify: Arc<tokio::sync::Notify>,
) -> tokio::task::JoinHandle<()> {
    tokio::spawn(async move {
        let mut retry = tokio::time::interval(std::time::Duration::from_secs(15));
        retry.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Delay);
        // Consume the interval's immediate first tick; scans below run now,
        // then on either a wake event or the bounded retry cadence.
        retry.tick().await;
        loop {
            recover_fabric_state(&reconciler, durable.as_ref()).await;
            tokio::select! {
                _ = registration_notify.notified() => {},
                _ = retry.tick() => {},
            }
        }
    })
}

async fn recover_fabric_state(
    reconciler: &FabricRealmReconciler,
    durable: &dyn o3k_store::DurableStore,
) {
    let mut blocked_realms = std::collections::BTreeSet::new();
    match durable.list_unresolved_network_plan_work().await {
        Ok(work) => {
            for record in work {
                let Ok(command) =
                    serde_json::from_slice::<o3k_network::NetworkPlanCommand>(&record.snapshot)
                else {
                    tracing::error!(command_id = %record.command_id, "unresolved Fabric command snapshot is corrupt; preserving fail-closed state");
                    // The realm identity is not trustworthy without its
                    // immutable command snapshot. Do not mutate any realm
                    // until this historical work is repaired/observed.
                    return;
                };
                let Some(fabric) = command.plan.fabric.as_ref() else {
                    continue;
                };
                let realm_id = fabric.realm_id;
                let Ok(command_id) = Uuid::parse_str(&record.command_id) else {
                    blocked_realms.insert(realm_id);
                    tracing::error!(realm_id = %realm_id, "unresolved Fabric command ID is malformed; preserving fail-closed state");
                    continue;
                };
                let Some(snapshot) = reconciler.registry.snapshot(&record.target_agent_id).await
                else {
                    blocked_realms.insert(realm_id);
                    tracing::warn!(realm_id = %realm_id, target_agent_id = %record.target_agent_id, "cannot observe historical network command while target agent is unavailable");
                    continue;
                };
                if snapshot.availability != o3k_provider::AgentAvailability::Available
                    || snapshot.administrative_state
                        != o3k_provider::AgentAdministrativeState::Enabled
                {
                    blocked_realms.insert(realm_id);
                    continue;
                }
                match reconciler
                    .dispatcher
                    .observe_command(
                        &record.target_host_id,
                        o3k_network::NetworkAgentIdentity {
                            agent_id: record.target_agent_id.clone(),
                            agent_epoch: snapshot.agent_epoch,
                        },
                        command_id,
                    )
                    .await
                {
                    Ok(Some(o3k_network::NetworkPlanStatus::Succeeded)) | Ok(None) => {}
                    Ok(Some(o3k_network::NetworkPlanStatus::Unknown)) => {
                        blocked_realms.insert(realm_id);
                    }
                    Ok(Some(_)) | Err(_) => {
                        blocked_realms.insert(realm_id);
                        tracing::warn!(realm_id = %realm_id, command_id = %record.command_id, "historical Fabric command was not conclusively observed");
                    }
                }
            }
        }
        Err(error) => {
            tracing::error!(%error, "cannot list unresolved Fabric work; skipping realm mutation this cycle");
            return;
        }
    }

    let realms = match reconciler
        .network
        .list_active_realms_for_reconciliation()
        .await
    {
        Ok(realms) => realms,
        Err(error) => {
            tracing::error!(%error, "cannot discover canonical active AddressRealms");
            return;
        }
    };
    for realm in realms {
        let realm_id = realm.id;
        if blocked_realms.contains(&realm_id) {
            continue;
        }
        let endpoints = match reconciler
            .network
            .list_canonical_endpoints_for_project(&realm.project_id, realm.id)
            .await
        {
            Ok(endpoints) => endpoints,
            Err(error) => {
                tracing::warn!(realm_id = %realm_id, %error, "cannot read canonical realm endpoints");
                continue;
            }
        };
        if !endpoints.iter().any(|endpoint| endpoint.state == "active") {
            continue;
        }
        if let Err(error) = reconciler
            .reconcile_realm(
                &realm.project_id,
                realm.network_id,
                Uuid::new_v4(),
                super::unix_time_millis().saturating_add(30_000),
            )
            .await
        {
            tracing::warn!(realm_id = %realm_id, %error, "Fabric realm startup reconciliation did not converge");
        }
    }
}

#[async_trait]
impl o3k_network::NetworkPlanDispatcher for NetworkAgentDispatcher {
    async fn dispatch(
        &self,
        mut command: o3k_network::NetworkPlanCommand,
    ) -> Result<o3k_network::NetworkPlanStatus, o3k_network::NetworkDispatchError> {
        let transport = self.transport_for(&command)?;
        let dynamic_fabric = command.plan.fabric.is_some();
        let _control_guard = if dynamic_fabric {
            Some(self.control_lock.lock().await)
        } else {
            None
        };
        let (controller_lease, work): (
            Option<o3k_network_protocol::proto::ControllerLease>,
            Option<(
                Arc<dyn o3k_store::DurableStore>,
                o3k_store::NetworkPlanWorkRecord,
            )>,
        ) = if dynamic_fabric {
            let control = self.control.as_ref().ok_or_else(|| {
                o3k_network::NetworkDispatchError::Rejected(
                    "Fabric v3 requires coordination-backed network-agent control ownership"
                        .to_owned(),
                )
            })?;
            let realm_id = command
                .plan
                .fabric
                .as_ref()
                .map(|fabric| fabric.realm_id)
                .ok_or_else(|| {
                    o3k_network::NetworkDispatchError::Rejected("missing Fabric realm".to_owned())
                })?;
            for unresolved in control
                .durable
                .list_unresolved_network_plan_work()
                .await
                .map_err(|_| o3k_network::NetworkDispatchError::Unavailable)?
            {
                let prior: o3k_network::NetworkPlanCommand =
                    serde_json::from_slice(&unresolved.snapshot)
                        .map_err(|_| o3k_network::NetworkDispatchError::Unavailable)?;
                if prior
                    .plan
                    .fabric
                    .as_ref()
                    .is_some_and(|fabric| fabric.realm_id == realm_id)
                {
                    return Err(o3k_network::NetworkDispatchError::Unavailable);
                }
            }
            let work_key = format!("network-agent:{}", command.target.agent_id);
            let acquired = control
                .coordination
                .acquire_work_lease(
                    &work_key,
                    "network_agent_control",
                    &control.controller_id,
                    &control.controller_epoch,
                    NETWORK_AGENT_CONTROL_TTL,
                )
                .await
                .map_err(|_| o3k_network::NetworkDispatchError::Unavailable)?;
            let lease = match acquired {
                o3k_store::LeaseAcquireOutcome::Acquired { lease } => lease,
                o3k_store::LeaseAcquireOutcome::Busy { .. } => {
                    return Err(o3k_network::NetworkDispatchError::Unavailable);
                }
            };
            let still_owner = control
                .coordination
                .inspect_work_lease(&work_key)
                .await
                .map_err(|_| o3k_network::NetworkDispatchError::Unavailable)?
                .is_some_and(|current| {
                    current.owner_controller_id == control.controller_id
                        && current.owner_controller_epoch == control.controller_epoch
                        && current.fencing_token == lease.fencing_token
                });
            if !still_owner {
                return Err(o3k_network::NetworkDispatchError::Unavailable);
            }
            command.controller = o3k_network::NetworkControllerLease {
                controller_id: control.controller_id.to_string(),
                controller_epoch: control.controller_epoch.to_string(),
                fencing_token: lease.fencing_token,
            };
            let now = super::unix_time_millis();
            if command.deadline_unix_ms <= now {
                return Err(o3k_network::NetworkDispatchError::Rejected(
                    "network plan deadline has expired".to_owned(),
                ));
            }
            let work_record = o3k_store::NetworkPlanWorkRecord {
                command_id: command.command_id.to_string(),
                operation_id: command.operation_id,
                idempotency_key: command.idempotency_key.clone(),
                target_host_id: command.plan.node_id.clone(),
                target_agent_id: command.target.agent_id.clone(),
                target_agent_epoch: command.target.agent_epoch.clone(),
                controller_id: command.controller.controller_id.clone(),
                controller_epoch: command.controller.controller_epoch.clone(),
                fencing_token: command.controller.fencing_token,
                deadline_unix_ms: command.deadline_unix_ms,
                fingerprint_sha256: command.plan.fingerprint_sha256.clone(),
                snapshot: serde_json::to_vec(&command).map_err(|error| {
                    o3k_network::NetworkDispatchError::Rejected(error.to_string())
                })?,
                state: o3k_store::NetworkPlanWorkState::Pending,
                revision: 0,
                outcome: None,
            };
            let persisted = control
                .durable
                .insert_network_plan_work(&work_record)
                .await
                .map_err(|error| o3k_network::NetworkDispatchError::Rejected(error.to_string()))?;
            if !persisted.same_command_identity(&work_record) {
                return Err(o3k_network::NetworkDispatchError::Rejected(
                    "network plan work command identity conflict".to_owned(),
                ));
            }
            if persisted.state == o3k_store::NetworkPlanWorkState::Succeeded {
                return Ok(o3k_network::NetworkPlanStatus::Succeeded);
            }
            if persisted.state != o3k_store::NetworkPlanWorkState::Pending {
                return Err(o3k_network::NetworkDispatchError::Rejected(
                    "network plan command is unresolved and requires observation before retry"
                        .to_owned(),
                ));
            }
            let running = control
                .durable
                .update_network_plan_work(
                    &persisted.command_id,
                    persisted.revision,
                    o3k_store::NetworkPlanWorkState::Running,
                    None,
                )
                .await
                .map_err(|error| o3k_network::NetworkDispatchError::Rejected(error.to_string()))?;
            let remote_expiry =
                now.saturating_add(
                    NETWORK_AGENT_REMOTE_LEASE.as_millis().min(u64::MAX as u128) as u64
                );
            (
                Some(o3k_network_protocol::proto::ControllerLease {
                    controller_id: command.controller.controller_id.clone(),
                    controller_epoch: command.controller.controller_epoch.clone(),
                    fencing_token: command.controller.fencing_token,
                    lease_expiry_unix_ms: remote_expiry,
                }),
                Some((control.durable.clone(), running)),
            )
        } else {
            (None, None)
        };
        let client = o3k_network_protocol::NetworkAgentClient::connect(
            &transport.endpoint,
            &transport.server_name,
            &self.ca_certificate,
            &self.client_certificate,
            &self.client_key,
        )
        .await
        .map_err(|error| o3k_network::NetworkDispatchError::Transport(error.to_string()))?;
        let command_id = command.command_id.to_string();
        let result = client
            .execute_with_lease(
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
                controller_lease,
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
            });
        let result = match result {
            Ok(result) => result,
            Err(error) => {
                if let Some((durable, current)) = work {
                    let outcome = error.to_string();
                    let _ = durable
                        .update_network_plan_work(
                            &current.command_id,
                            current.revision,
                            o3k_store::NetworkPlanWorkState::UnknownOutcome,
                            Some(outcome.as_bytes()),
                        )
                        .await;
                }
                return Err(error);
            }
        };
        tracing::debug!(
            command_id = %command_id,
            operation_id = %command.operation_id,
            status = %result.status,
            replayed = result.replayed,
            error_code = %result.error_code,
            "network agent dispatch completed"
        );
        let status = match result.status.as_str() {
            "succeeded" | "replayed" | "recovered" => o3k_network::NetworkPlanStatus::Succeeded,
            "unknown" | "requires_observation" => o3k_network::NetworkPlanStatus::Unknown,
            other => {
                if let Some((durable, current)) = work {
                    let outcome = if result.error_code.is_empty() {
                        other.to_owned()
                    } else {
                        result.error_code.clone()
                    };
                    let _ = durable
                        .update_network_plan_work(
                            &current.command_id,
                            current.revision,
                            o3k_store::NetworkPlanWorkState::Failed,
                            Some(outcome.as_bytes()),
                        )
                        .await;
                }
                return Err(o3k_network::NetworkDispatchError::Rejected(
                    if result.error_code.is_empty() {
                        other.to_owned()
                    } else {
                        result.error_code
                    },
                ));
            }
        };
        if let Some((durable, current)) = work {
            let next = if status == o3k_network::NetworkPlanStatus::Succeeded {
                o3k_store::NetworkPlanWorkState::Succeeded
            } else {
                o3k_store::NetworkPlanWorkState::UnknownOutcome
            };
            durable
                .update_network_plan_work(
                    &current.command_id,
                    current.revision,
                    next,
                    Some(result.status.as_bytes()),
                )
                .await
                .map_err(|error| o3k_network::NetworkDispatchError::Rejected(error.to_string()))?;
        }
        Ok(status)
    }

    async fn observe_command(
        &self,
        target_host_id: &str,
        target: o3k_network::NetworkAgentIdentity,
        command_id: Uuid,
    ) -> Result<Option<o3k_network::NetworkPlanStatus>, o3k_network::NetworkDispatchError> {
        let _control_guard = self.control_lock.lock().await;
        let control = self.control.as_ref().ok_or_else(|| {
            o3k_network::NetworkDispatchError::Rejected(
                "historical Fabric command observation requires coordination ownership".to_owned(),
            )
        })?;
        let configured = self.fabric_targets.get(&target.agent_id).ok_or_else(|| {
            o3k_network::NetworkDispatchError::Rejected(
                "historical target agent is not enrolled".to_owned(),
            )
        })?;
        if configured.host_id != target_host_id || configured.agent_id != target.agent_id {
            return Err(o3k_network::NetworkDispatchError::Rejected(
                "historical target does not match enrolled host identity".to_owned(),
            ));
        }
        let key = format!("network-agent:{}", target.agent_id);
        let lease = match control
            .coordination
            .acquire_work_lease(
                &key,
                "network_agent_control",
                &control.controller_id,
                &control.controller_epoch,
                NETWORK_AGENT_CONTROL_TTL,
            )
            .await
            .map_err(|_| o3k_network::NetworkDispatchError::Unavailable)?
        {
            o3k_store::LeaseAcquireOutcome::Acquired { lease } => lease,
            o3k_store::LeaseAcquireOutcome::Busy { .. } => {
                return Err(o3k_network::NetworkDispatchError::Unavailable);
            }
        };
        let current = control
            .coordination
            .inspect_work_lease(&key)
            .await
            .map_err(|_| o3k_network::NetworkDispatchError::Unavailable)?;
        if !current.is_some_and(|current| {
            current.owner_controller_id == control.controller_id
                && current.owner_controller_epoch == control.controller_epoch
                && current.fencing_token == lease.fencing_token
        }) {
            return Err(o3k_network::NetworkDispatchError::Unavailable);
        }
        let now = super::unix_time_millis();
        let client = o3k_network_protocol::NetworkAgentClient::connect(
            &configured.endpoint,
            &configured.tls_server_name,
            &self.ca_certificate,
            &self.client_certificate,
            &self.client_key,
        )
        .await
        .map_err(|error| o3k_network::NetworkDispatchError::Transport(error.to_string()))?;
        let result = client
            .observe_with_lease(
                o3k_network_protocol::proto::Register {
                    agent_id: target.agent_id.clone(),
                    agent_epoch: target.agent_epoch,
                },
                o3k_network_protocol::proto::ControllerLease {
                    controller_id: control.controller_id.to_string(),
                    controller_epoch: control.controller_epoch.to_string(),
                    fencing_token: lease.fencing_token,
                    lease_expiry_unix_ms: now.saturating_add(
                        NETWORK_AGENT_REMOTE_LEASE.as_millis().min(u64::MAX as u128) as u64,
                    ),
                },
                command_id.to_string(),
            )
            .await
            .map_err(|error| o3k_network::NetworkDispatchError::Transport(error.to_string()))?;
        let status = match result.status.as_str() {
            "succeeded" => Some(o3k_network::NetworkPlanStatus::Succeeded),
            "unknown" => Some(o3k_network::NetworkPlanStatus::Unknown),
            "not_found" => None,
            other => {
                return Err(o3k_network::NetworkDispatchError::Rejected(
                    if result.error_code.is_empty() {
                        other.to_owned()
                    } else {
                        result.error_code
                    },
                ));
            }
        };
        let historical = control
            .durable
            .get_network_plan_work(&command_id.to_string())
            .await
            .map_err(|error| o3k_network::NetworkDispatchError::Rejected(error.to_string()))?;
        if historical.target_agent_id != target.agent_id
            || historical.target_host_id != target_host_id
        {
            return Err(o3k_network::NetworkDispatchError::Rejected(
                "historical work target identity does not match observation target".to_owned(),
            ));
        }
        let next = match status {
            Some(o3k_network::NetworkPlanStatus::Succeeded) => {
                o3k_store::NetworkPlanWorkState::Succeeded
            }
            Some(o3k_network::NetworkPlanStatus::Unknown) => {
                o3k_store::NetworkPlanWorkState::UnknownOutcome
            }
            Some(_) => {
                return Err(o3k_network::NetworkDispatchError::Rejected(
                    "invalid historical observation status".to_owned(),
                ));
            }
            None => o3k_store::NetworkPlanWorkState::Failed,
        };
        let outcome = match status {
            Some(o3k_network::NetworkPlanStatus::Succeeded) => b"observed_succeeded".as_slice(),
            Some(o3k_network::NetworkPlanStatus::Unknown) => b"observation_unknown".as_slice(),
            None => b"not_admitted_superseded_by_canonical_reconciliation".as_slice(),
            Some(_) => unreachable!(),
        };
        if historical.state != next {
            control
                .durable
                .update_network_plan_work(
                    &historical.command_id,
                    historical.revision,
                    next,
                    Some(outcome),
                )
                .await
                .map_err(|error| o3k_network::NetworkDispatchError::Rejected(error.to_string()))?;
        }
        Ok(status)
    }
}

impl NetworkAgentDispatcher {
    fn transport_for(
        &self,
        command: &o3k_network::NetworkPlanCommand,
    ) -> Result<NetworkAgentTransport, o3k_network::NetworkDispatchError> {
        let target = self.fabric_targets.get(&command.target.agent_id);
        let target_host = command
            .plan
            .fabric
            .as_ref()
            .map_or(command.plan.node_id.as_str(), |fabric| {
                fabric.local_host.as_str()
            });
        if let Some(target) = target.filter(|target| {
            target.agent_id == command.target.agent_id && target.host_id == target_host
        }) {
            return Ok(NetworkAgentTransport {
                endpoint: target.endpoint.clone(),
                server_name: target.tls_server_name.clone(),
            });
        }
        if command.plan.fabric.is_some() || !self.fabric_targets.is_empty() {
            return Err(o3k_network::NetworkDispatchError::Rejected(
                "network plan target does not resolve to its enrolled host control endpoint"
                    .to_owned(),
            ));
        }
        self.legacy_target.clone().ok_or_else(|| {
            o3k_network::NetworkDispatchError::Rejected(
                "legacy network agent endpoint is not configured".to_owned(),
            )
        })
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
    pub(crate) fabric_reconciler: Option<Arc<FabricRealmReconciler>>,
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

#[cfg(test)]
#[allow(clippy::expect_used)]
mod dispatcher_tests {
    use super::*;
    use async_trait::async_trait;
    use std::sync::Mutex;

    fn dispatcher() -> NetworkAgentDispatcher {
        NetworkAgentDispatcher {
            legacy_target: None,
            control: None,
            control_lock: Arc::new(tokio::sync::Mutex::new(())),
            fabric_targets: BTreeMap::from([
                (
                    "agent-a".to_owned(),
                    NetworkAgentControlTarget {
                        host_id: "compute-a".to_owned(),
                        agent_id: "agent-a".to_owned(),
                        endpoint: "https://10.0.0.1:7443".to_owned(),
                        tls_server_name: "compute-a.internal".to_owned(),
                    },
                ),
                (
                    "agent-b".to_owned(),
                    NetworkAgentControlTarget {
                        host_id: "compute-b".to_owned(),
                        agent_id: "agent-b".to_owned(),
                        endpoint: "https://10.0.0.2:7443".to_owned(),
                        tls_server_name: "compute-b.internal".to_owned(),
                    },
                ),
            ]),
            ca_certificate: PathBuf::new(),
            client_certificate: PathBuf::new(),
            client_key: PathBuf::new(),
        }
    }

    fn command(agent_id: &str, host_id: &str) -> o3k_network::NetworkPlanCommand {
        o3k_network::NetworkPlanCommand {
            command_id: Uuid::now_v7(),
            operation_id: Uuid::now_v7(),
            idempotency_key: "dispatch-test".to_owned(),
            action: o3k_network::NetworkPlanAction::Apply,
            target: o3k_network::NetworkAgentIdentity {
                agent_id: agent_id.to_owned(),
                agent_epoch: "epoch-1".to_owned(),
            },
            controller: o3k_network::NetworkControllerLease {
                controller_id: "controller".to_owned(),
                controller_epoch: "epoch-1".to_owned(),
                fencing_token: 1,
            },
            deadline_unix_ms: u64::MAX,
            plan: o3k_network::NodeNetworkPlan {
                schema_version: o3k_network::NODE_NETWORK_PLAN_SCHEMA_VERSION,
                plan_id: Uuid::now_v7(),
                node_id: host_id.to_owned(),
                operation_id: Uuid::now_v7(),
                deadline_unix_ms: u64::MAX,
                resource_generations: BTreeMap::new(),
                intents: Vec::new(),
                fabric: None,
                gateway: None,
                fingerprint_sha256: String::new(),
            },
        }
    }

    fn fabric_command(agent_id: &str, host_id: &str) -> o3k_network::NetworkPlanCommand {
        let mut command = command(agent_id, host_id);
        let realm = o3k_domain::AddressRealm {
            id: Uuid::from_u128(800),
            network_id: Uuid::from_u128(801),
            project_id: "project-a".to_owned(),
            prefix: o3k_domain::Ipv4Prefix::new(std::net::Ipv4Addr::new(10, 80, 0, 0), 24)
                .expect("realm prefix"),
            overlapping_prefixes: false,
        };
        let directory = o3k_domain::RealmEndpointDirectory::build(
            &realm,
            vec![o3k_domain::EndpointLocation {
                endpoint_id: Uuid::from_u128(802),
                project_id: "project-a".to_owned(),
                realm_id: realm.id,
                fixed_ip: std::net::Ipv4Addr::new(10, 80, 0, 10),
                mac: "02:00:00:00:00:10".to_owned(),
                selected_host: host_id.to_owned(),
                endpoint_generation: 1,
                placement_generation: 1,
            }],
            &[],
            1,
        )
        .expect("directory");
        let identity = o3k_domain::FabricHostIdentity {
            host_id: host_id.to_owned(),
            public_key: "public-key".to_owned(),
            underlay_endpoint: "198.18.0.1:65001".to_owned(),
            fabric_transport_ip: std::net::Ipv4Addr::new(198, 18, 0, 1),
            provider_version: "0.1.5".to_owned(),
            fabric_generation: 1,
            underlay_mtu: 1500,
            fabric_mtu: 1440,
        };
        let binding = o3k_domain::RealmEncapsulationBinding {
            fabric_domain_id: Uuid::from_u128(803),
            realm_id: realm.id,
            provider_kind: o3k_domain::FabricProviderKind::Vxlan,
            provider_segment_id: 1001,
            binding_generation: 1,
        };
        command.plan.fabric = Some(
            directory
                .compile_fabric_plan(&identity, std::slice::from_ref(&identity), 1390, &binding)
                .expect("Fabric plan"),
        );
        command
    }

    #[test]
    fn target_aware_dispatch_resolves_each_host_independently() {
        let dispatcher = dispatcher();
        let a = dispatcher
            .transport_for(&fabric_command("agent-a", "compute-a"))
            .expect("host A target");
        let b = dispatcher
            .transport_for(&fabric_command("agent-b", "compute-b"))
            .expect("host B target");
        assert_eq!(a.endpoint, "https://10.0.0.1:7443");
        assert_eq!(b.endpoint, "https://10.0.0.2:7443");
        assert_ne!(a.server_name, b.server_name);
    }

    #[test]
    fn target_aware_dispatch_rejects_unknown_or_mismatched_hosts() {
        let dispatcher = dispatcher();
        assert!(
            dispatcher
                .transport_for(&fabric_command("agent-b", "compute-a"))
                .is_err()
        );
        assert!(
            dispatcher
                .transport_for(&fabric_command("unregistered", "compute-c"))
                .is_err()
        );
    }

    #[derive(Default)]
    struct RecordingDispatcher {
        commands: Mutex<Vec<o3k_network::NetworkPlanCommand>>,
    }

    #[async_trait]
    impl o3k_network::NetworkPlanDispatcher for RecordingDispatcher {
        async fn dispatch(
            &self,
            command: o3k_network::NetworkPlanCommand,
        ) -> Result<o3k_network::NetworkPlanStatus, o3k_network::NetworkDispatchError> {
            self.commands
                .lock()
                .map_err(|_| o3k_network::NetworkDispatchError::Rejected("poisoned".to_owned()))?
                .push(command);
            Ok(o3k_network::NetworkPlanStatus::Succeeded)
        }
    }

    fn host_identity(
        host_id: &str,
        agent_id: &str,
        public_key: &str,
        octet: u8,
    ) -> o3k_store::FabricHostTransportIdentityRecord {
        o3k_store::FabricHostTransportIdentityRecord {
            host_id: host_id.to_owned(),
            agent_id: agent_id.to_owned(),
            public_key: public_key.to_owned(),
            underlay_endpoint: format!("192.0.2.{octet}:65001"),
            fabric_transport_ip: std::net::Ipv4Addr::new(198, 18, 0, octet),
            provider_version: "0.1.5".to_owned(),
            fabric_generation: 1,
            underlay_mtu: 1500,
            fabric_mtu: 1440,
            administrative_state: "enabled".to_owned(),
        }
    }

    #[tokio::test]
    async fn canonical_network_lifecycle_derives_and_dispatches_three_host_her()
    -> Result<(), Box<dyn std::error::Error>> {
        let root = std::env::temp_dir().join(format!("o3kd-fabric-reconcile-{}", Uuid::now_v7()));
        std::fs::create_dir_all(&root)?;
        let store = Arc::new(o3k_store::testkit::open_memory().await?);
        let repository: Arc<dyn o3k_store::NetworkRepository> = store.clone();
        let network =
            o3k_network::NetworkService::open_for_test(root.join("network"), repository).await?;
        let network_record = network
            .create_network_for_project("project-a", "tenant-a".to_owned())
            .await?;
        let subnet = network
            .create_subnet_for_project(
                "project-a",
                network_record.id,
                "tenant-a-subnet".to_owned(),
                "10.90.0.0/24".to_owned(),
                None,
                None,
                None,
            )
            .await?;
        let endpoints = [
            (
                "compute-a",
                "agent-a",
                "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA=",
                1_u8,
            ),
            (
                "compute-b",
                "agent-b",
                "AQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQE=",
                2_u8,
            ),
            (
                "compute-c",
                "agent-c",
                "AgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgI=",
                3_u8,
            ),
        ];
        let registry = Arc::new(o3k_compute_agent::NodeRegistry::default());
        for (host_id, agent_id, public_key, octet) in endpoints.iter().copied() {
            network
                .enroll_fabric_host_transport_identity(
                    &host_identity(host_id, agent_id, public_key, octet),
                    None,
                )
                .await?;
            registry
                .register(&o3k_compute_agent::proto::RegisterRequest {
                    agent_id: agent_id.to_owned(),
                    agent_epoch: "epoch-1".to_owned(),
                    software_version: "test".to_owned(),
                    host_label: host_id.to_owned(),
                    supported_versions: vec![o3k_compute_agent::PROTOCOL_VERSION],
                    capabilities: Some(o3k_compute_agent::proto::Capabilities::default()),
                })
                .await?;
        }
        let dispatcher = Arc::new(RecordingDispatcher::default());
        let reconciler = FabricRealmReconciler {
            network: network.clone(),
            registry,
            dispatcher: dispatcher.clone(),
            controller: o3k_network::NetworkControllerLease {
                controller_id: "controller".to_owned(),
                controller_epoch: "epoch-1".to_owned(),
                fencing_token: 1,
            },
            fabric_domain_id: Uuid::from_u128(990),
            network_external_realm_id: None,
            public_allocator: None,
        };
        let mut port_by_host = BTreeMap::new();
        for (index, (host_id, agent_id, _, _)) in endpoints.iter().copied().enumerate() {
            let port = network
                .create_port_for_project("project-a", network_record.id, format!("port-{host_id}"))
                .await?;
            assert_eq!(port.subnet_id, Some(subnet.id));
            network
                .record_fabric_binding_intent("project-a", port.id, agent_id)
                .await?;
            port_by_host.insert(host_id.to_owned(), port.id);
            reconciler
                .reconcile_realm(
                    "project-a",
                    network_record.id,
                    Uuid::from_u128(991 + index as u128),
                    u64::MAX,
                )
                .await?;
        }
        {
            let commands = dispatcher
                .commands
                .lock()
                .map_err(|_| "recording dispatcher poisoned")?;
            assert_eq!(commands.len(), 6);
            for (expected_entries, commands_for_addition) in [
                (1, &commands[0..1]),
                (2, &commands[1..3]),
                (3, &commands[3..6]),
            ] {
                let mut addition_hosts = std::collections::BTreeSet::new();
                for command in commands_for_addition {
                    let fabric = command
                        .plan
                        .fabric
                        .as_ref()
                        .ok_or("missing Fabric v3 plan")?;
                    assert_eq!(command.plan.node_id, fabric.local_host);
                    assert_eq!(fabric.directory.entries.len(), expected_entries);
                    assert_eq!(fabric.peers.len(), expected_entries - 1);
                    addition_hosts.insert(fabric.local_host.clone());
                }
                let expected = endpoints[..expected_entries]
                    .iter()
                    .map(|(host_id, _, _, _)| (*host_id).to_owned())
                    .collect::<std::collections::BTreeSet<_>>();
                assert_eq!(addition_hosts, expected);
            }
        }

        // Unbinding the final endpoint on C keeps the binding tombstone until
        // the full directory has withdrawn C from A/B HER and C has received
        // an owned realm removal plan.
        let departing_port = port_by_host["compute-c"];
        network
            .advance_fabric_realm_generation("project-a", network_record.id)
            .await?;
        network
            .project_binding_observation("project-a", departing_port, "agent-c", "down")
            .await?;
        reconciler
            .reconcile_realm_after_unbind(
                "project-a",
                network_record.id,
                Uuid::from_u128(992),
                u64::MAX,
                "agent-c",
            )
            .await?;
        network.unbind_port("project-a", departing_port).await?;
        {
            let commands = dispatcher
                .commands
                .lock()
                .map_err(|_| "recording dispatcher poisoned")?;
            assert_eq!(commands.len(), 9);
            let withdrawn = commands[6..8]
                .iter()
                .map(|command| {
                    let fabric = command.plan.fabric.as_ref().expect("Fabric plan");
                    assert_eq!(command.action, o3k_network::NetworkPlanAction::Apply);
                    assert_eq!(fabric.directory.entries.len(), 2);
                    assert_eq!(fabric.peers.len(), 1);
                    fabric.local_host.clone()
                })
                .collect::<std::collections::BTreeSet<_>>();
            assert_eq!(
                withdrawn,
                ["compute-a", "compute-b"]
                    .into_iter()
                    .map(str::to_owned)
                    .collect()
            );
            assert_eq!(commands[8].target.agent_id, "agent-c");
            assert_eq!(commands[8].action, o3k_network::NetworkPlanAction::Remove);
        }

        // A controller restart must recover from durable canonical state
        // without another endpoint mutation. After C's supported unbind, a
        // startup scan should recreate the current A/B realm plan set.
        dispatcher
            .commands
            .lock()
            .map_err(|_| "recording dispatcher poisoned")?
            .clear();
        let durable_realms = network.list_active_realms_for_reconciliation().await?;
        assert_eq!(durable_realms.len(), 1, "canonical realm missing");
        assert_eq!(durable_realms[0].id, subnet.id);
        recover_fabric_state(&reconciler, store.as_ref()).await;
        {
            let commands = dispatcher
                .commands
                .lock()
                .map_err(|_| "recording dispatcher poisoned")?;
            assert_eq!(commands.len(), 2);
            let hosts = commands
                .iter()
                .map(|command| {
                    let fabric = command.plan.fabric.as_ref().expect("Fabric plan");
                    assert_eq!(fabric.directory.entries.len(), 2);
                    assert_eq!(fabric.peers.len(), 1);
                    fabric.local_host.clone()
                })
                .collect::<std::collections::BTreeSet<_>>();
            assert_eq!(
                hosts,
                ["compute-a", "compute-b"]
                    .into_iter()
                    .map(str::to_owned)
                    .collect()
            );
        }
        let _ = std::fs::remove_dir_all(root);
        Ok(())
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
        let v3_reconciler = self.fabric_reconciler.as_ref();
        if v3_reconciler.is_none()
            && let (Some(dispatcher), Some(host)) = (
                self.network_dispatcher.as_ref(),
                port.binding_host.as_deref(),
            )
        {
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
        if let (Some(host), Some(reconciler)) = (port.binding_host.as_deref(), v3_reconciler) {
            // Keep the selected host durable as a down tombstone until every
            // affected realm plan has converged. A retry can therefore still
            // identify and withdraw the departing host after an unknown
            // dispatch outcome or controller restart.
            if port.binding_state.as_deref() != Some("down") {
                self.network
                    .advance_fabric_realm_generation(project_id, port.network_id)
                    .await
                    .map_err(|error| std::io::Error::other(error.to_string()))?;
                self.network
                    .project_binding_observation(project_id, port_id, host, "down")
                    .await
                    .map_err(|error| std::io::Error::other(error.to_string()))?;
            }
            reconciler
                .reconcile_realm_after_unbind(
                    project_id,
                    port.network_id,
                    operation_id,
                    super::unix_time_millis().saturating_add(30_000),
                    host,
                )
                .await
                .map_err(std::io::Error::other)?;
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
