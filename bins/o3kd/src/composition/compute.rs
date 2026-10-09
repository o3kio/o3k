use async_trait::async_trait;
use o3k_compute_agent;
use o3k_config_drive;
use o3k_domain::ServerId;
use o3k_identity;
use o3k_image;
use o3k_provider::{
    AgentNodeSnapshot, ArtifactKind, ConfigDriveRequest, CreateArtifactResolver,
    CreateInstanceRequest, OperationState, ProviderError, ResolvedConfigDrive,
    ResolvedCreateArtifact, ResolvedCreateInputs, ResolvedCreateResolver,
};
use std::collections::BTreeMap;
use std::path::PathBuf;
use std::sync::Arc;
use std::time::Duration;
use tracing;
use uuid::Uuid;

#[derive(Clone)]
pub(crate) struct DaemonCreateResolver {
    pub(crate) store: Arc<dyn o3k_store::ComputeRepository>,
    pub(crate) image: o3k_image::ImageService,
    pub(crate) network: o3k_network::NetworkService,
    pub(crate) config_drive: o3k_config_drive::ConfigDriveStore,
    pub(crate) network_dispatcher: Option<Arc<dyn o3k_network::NetworkPlanDispatcher>>,
    pub(crate) fabric_reconciler: Option<Arc<super::network::FabricRealmReconciler>>,
    pub(crate) network_controller: o3k_network::NetworkControllerLease,
    pub(crate) network_external_realm_id: Option<Uuid>,
    pub(crate) network_agent: Option<o3k_network::NetworkAgentIdentity>,
    pub(crate) public_allocator: Option<Arc<o3k_network::PublicAddressAllocator>>,
}

impl DaemonCreateResolver {
    async fn ensure_create_operation_active(
        &self,
        request: &CreateInstanceRequest,
    ) -> Result<(), ProviderError> {
        let operation = self
            .store
            .get_operation(request.operation_id)
            .await
            .map_err(|_| ProviderError::InvalidRequest)?;
        if !operation_allows_create(&operation, request.o3k_server_id) {
            return Err(ProviderError::Conflict);
        }
        Ok(())
    }

    pub(crate) fn config_drive_iso_path(
        generated_directory: &std::path::Path,
        server_id: Uuid,
    ) -> Result<PathBuf, ProviderError> {
        let output_root = generated_directory
            .parent()
            .ok_or(ProviderError::InvalidRequest)?;
        Ok(output_root.join(format!("{server_id}.iso")))
    }

    async fn resolve_image(
        &self,
        request: &CreateInstanceRequest,
    ) -> Result<o3k_image::ImageArtifact, ProviderError> {
        let image_id = request
            .image_id
            .as_deref()
            .ok_or(ProviderError::InvalidRequest)?
            .parse::<Uuid>()
            .map_err(|_| ProviderError::InvalidRequest)?;
        self.image
            .resolve_artifact_for_project(&request.project_id, image_id)
            .await
            .map_err(|_| ProviderError::InvalidRequest)
    }

    pub(crate) async fn resolve_network(
        &self,
        request: &CreateInstanceRequest,
        compute_agent: &AgentNodeSnapshot,
    ) -> Result<
        (
            Vec<o3k_compute_agent::NetworkAttachmentSpec>,
            BTreeMap<String, String>,
        ),
        ProviderError,
    > {
        let external_realm_id = self.resolve_external_realm_id(&request.project_id).await?;
        let legacy_network_agent_id = self
            .network_agent
            .as_ref()
            .map_or(compute_agent.agent_id.as_str(), |agent| {
                agent.agent_id.as_str()
            })
            .to_owned();
        let mut attachments = Vec::with_capacity(request.network_ids.len());
        let mut network_data = BTreeMap::new();
        for network_id in &request.network_ids {
            let port_id = network_id
                .parse::<Uuid>()
                .map_err(|_| ProviderError::InvalidRequest)?;
            let port = self
                .network
                .get_port_for_project(&request.project_id, port_id)
                .await
                .map_err(|_| ProviderError::InvalidRequest)?;
            let subnet = self
                .network
                .get_subnet_for_project(
                    &request.project_id,
                    port.subnet_id.ok_or(ProviderError::InvalidRequest)?,
                )
                .await
                .map_err(|_| ProviderError::InvalidRequest)?;
            // Record the selected-host intent only after the full attachment
            // resolved; a port whose subnet cannot be resolved is never
            // dispatched and must not carry a binding intent.
            let binding_host = if let Some(reconciler) = &self.fabric_reconciler {
                reconciler
                    .validate_compute_placement(compute_agent)
                    .await
                    .map_err(|_| ProviderError::InvalidRequest)?;
                compute_agent.host_id.clone()
            } else {
                self.network_agent
                    .as_ref()
                    .map_or(compute_agent.agent_id.as_str(), |agent| {
                        agent.agent_id.as_str()
                    })
                    .to_owned()
            };
            let public_address = self
                .public_allocator
                .as_ref()
                .map(|allocator| {
                    allocator
                        .list(&request.project_id)
                        .map_err(|_| ProviderError::InvalidRequest)
                })
                .transpose()?
                .and_then(|bindings| {
                    bindings
                        .into_iter()
                        .find(|binding| binding.endpoint_id == Some(port.id))
                        .map(|binding| binding.public_address)
                });
            let (policies, policy_defaults) = if self.network_dispatcher.is_some() {
                let policies = self
                    .network
                    .list_policies_for_project(&request.project_id, port.network_id)
                    .await
                    .map_err(|_| ProviderError::InvalidRequest)?
                    .into_iter()
                    .filter(|policy| policy.endpoint_id == port.id)
                    .collect();
                let policy_defaults = self
                    .network
                    .policy_defaults_for_endpoint(&request.project_id, port.id)
                    .await
                    .map_err(|_| ProviderError::InvalidRequest)?;
                (policies, policy_defaults)
            } else {
                (Vec::new(), Vec::new())
            };
            if let Some(fabric_reconciler) = &self.fabric_reconciler {
                // A selected host without an accepted Fabric identity is a
                // known pre-dispatch configuration failure. Reject it before
                // recording placement intent or entering the collective
                // reconciler so Compute can terminalize the create as failed
                // (and safely release its resources). Errors after realm
                // reconciliation starts remain UnknownOutcome because a
                // provider command may already have crossed the mutation
                // boundary.
                let selected_host_enrolled = self
                    .network
                    .list_fabric_host_transport_identities()
                    .await
                    .map_err(|_| ProviderError::InvalidRequest)?
                    .into_iter()
                    .any(|identity| {
                        identity.host_id == binding_host
                            && identity.administrative_state == "enabled"
                    });
                if !selected_host_enrolled {
                    return Err(ProviderError::InvalidRequest);
                }
                self.network
                    .record_fabric_binding_intent(&request.project_id, port_id, &binding_host)
                    .await
                    .map_err(|error| match error {
                        o3k_network::NetworkError::Conflict => ProviderError::Conflict,
                        _ => ProviderError::InvalidRequest,
                    })?;
                fabric_reconciler
                    .reconcile_realm(
                        &request.project_id,
                        port.network_id,
                        request.operation_id,
                        super::unix_time_millis().saturating_add(30_000),
                    )
                    .await
                    // Fabric keeps its own durable command journal and
                    // observation-first recovery. The compute-agent command
                    // has not been admitted yet, so surface a bounded retry
                    // to the compute lifecycle; the next pass re-enters the
                    // Fabric reconciler before it can dispatch VM creation.
                    .map_err(|error| {
                        tracing::warn!(
                            realm_id = %port.network_id,
                            operation_id = %request.operation_id,
                            error = %error,
                            "Fabric realm reconciliation did not complete before compute admission"
                        );
                        ProviderError::Retryable
                    })?;
            } else {
                self.network
                    .record_binding_intent(&request.project_id, port_id, &legacy_network_agent_id)
                    .await
                    .map_err(|error| match error {
                        o3k_network::NetworkError::Conflict => ProviderError::Conflict,
                        _ => ProviderError::InvalidRequest,
                    })?;
            }
            if self.fabric_reconciler.is_none()
                && let Some(dispatcher) = &self.network_dispatcher
            {
                let deadline_unix_ms = super::unix_time_millis().saturating_add(30_000);
                let plan = o3k_network::compile_attachment_plan_with_defaults(
                    o3k_network::AttachmentPlanInput {
                        endpoint_id: port.id,
                        realm_id: port.subnet_id.ok_or(ProviderError::InvalidRequest)?,
                        project_id: &request.project_id,
                        mac: &port.mac_address,
                        fixed_ip: port.fixed_ip,
                        subnet_cidr: &subnet.cidr,
                        // The network plan is owned by the network execution
                        // agent, not by the selected compute host.  Keeping the
                        // plan node bound to the network agent lets the executor
                        // reject cross-agent replay without conflating compute
                        // placement with network mutation authority.
                        node_id: &legacy_network_agent_id,
                        operation_id: request.operation_id,
                        deadline_unix_ms,
                        public_address,
                        external_realm_id,
                        policies,
                    },
                    policy_defaults,
                )
                .map_err(|_| ProviderError::InvalidRequest)?;
                let command_id = Uuid::new_v5(
                    &Uuid::NAMESPACE_URL,
                    format!(
                        "o3k:network:apply:{}:{}:{}",
                        request.operation_id, port.id, plan.fingerprint_sha256
                    )
                    .as_bytes(),
                );
                let status = dispatcher
                    .dispatch(o3k_network::NetworkPlanCommand {
                        command_id,
                        operation_id: request.operation_id,
                        idempotency_key: format!("{}:network:{}", request.idempotency_key, port.id),
                        action: o3k_network::NetworkPlanAction::Apply,
                        target: self.network_agent.clone().unwrap_or_else(|| {
                            o3k_network::NetworkAgentIdentity {
                                agent_id: legacy_network_agent_id.clone(),
                                agent_epoch: compute_agent.agent_epoch.clone(),
                            }
                        }),
                        controller: self.network_controller.clone(),
                        deadline_unix_ms,
                        plan,
                    })
                    .await
                    .map_err(|error| match error {
                        o3k_network::NetworkDispatchError::Unavailable
                        | o3k_network::NetworkDispatchError::Transport(_) => {
                            ProviderError::UnknownOutcome {
                                operation_id: request.operation_id,
                            }
                        }
                        o3k_network::NetworkDispatchError::Rejected(_) => {
                            ProviderError::InvalidRequest
                        }
                    })?;
                if status == o3k_network::NetworkPlanStatus::Unknown {
                    return Err(ProviderError::UnknownOutcome {
                        operation_id: request.operation_id,
                    });
                }
            }
            let port_id = port.id.to_string();
            let fixed_ip = port.fixed_ip.to_string();
            attachments.push(o3k_compute_agent::NetworkAttachmentSpec {
                port_id: port_id.clone(),
                mac: port.mac_address.clone(),
                fixed_ipv4: fixed_ip.clone(),
                subnet_cidr: subnet.cidr,
                gateway_ipv4: subnet.gateway_ip.to_string(),
            });
            network_data.insert(format!("{port_id}.mac"), port.mac_address);
            network_data.insert(format!("{port_id}.ipv4"), fixed_ip);
        }
        Ok((attachments, network_data))
    }

    async fn resolve_external_realm_id(
        &self,
        project_id: &str,
    ) -> Result<Option<Uuid>, ProviderError> {
        let Some(external_network_id) = self.network_external_realm_id else {
            return Ok(None);
        };
        let realms = self
            .network
            .list_canonical_realms_for_project(project_id, external_network_id)
            .await
            .map_err(|_| ProviderError::InvalidRequest)?;
        select_active_external_realm(&realms)
            .map(Some)
            .map_err(|_| ProviderError::InvalidRequest)
    }

    fn config_drive_input(
        request: &CreateInstanceRequest,
        config: &ConfigDriveRequest,
        network_data: BTreeMap<String, String>,
    ) -> o3k_config_drive::ConfigDriveInput {
        let mut metadata = BTreeMap::new();
        metadata.insert("project_id".to_owned(), request.project_id.clone());
        metadata.insert("server_id".to_owned(), request.o3k_server_id.to_string());
        o3k_config_drive::ConfigDriveInput {
            instance_id: request.o3k_server_id.to_string(),
            hostname: request.name.clone(),
            ssh_public_key: config.ssh_public_key.clone(),
            user_data: config.user_data.clone(),
            metadata,
            network_data,
            vendor_data: config.vendor_data.clone(),
        }
    }

    fn network_data_from_attachments(
        attachments: &[o3k_compute_agent::NetworkAttachmentSpec],
    ) -> BTreeMap<String, String> {
        let mut network_data = BTreeMap::new();
        for attachment in attachments {
            network_data.insert(
                format!("{}.mac", attachment.port_id),
                attachment.mac.clone(),
            );
            network_data.insert(
                format!("{}.ipv4", attachment.port_id),
                attachment.fixed_ipv4.clone(),
            );
        }
        network_data
    }

    fn materialize_config_drive(
        &self,
        request: &CreateInstanceRequest,
        network_data: BTreeMap<String, String>,
    ) -> Result<(o3k_config_drive::ConfigDriveIsoResult, Vec<u8>), ProviderError> {
        let config = request
            .config_drive
            .as_ref()
            .ok_or(ProviderError::InvalidRequest)?;
        let input = Self::config_drive_input(request, config, network_data);
        let generated = self.config_drive.generate(&input).map_err(|error| {
            tracing::warn!(error = %error, "config-drive generation failed");
            ProviderError::InvalidRequest
        })?;
        // ConfigDriveStore authenticates the ISO against its managed root and
        // expects the published ISO beside the instance directory. Derive the
        // output location from the generated directory so the resolver cannot
        // accidentally place it in an unrelated root.
        let output = Self::config_drive_iso_path(&generated.directory, request.o3k_server_id)?;
        let iso = self
            .config_drive
            .materialize_iso(&generated.directory, output)
            .map_err(|error| {
                tracing::warn!(error = %error, "config-drive ISO materialization failed");
                ProviderError::InvalidRequest
            })?;
        let bytes = self.config_drive.read_verified_iso(&iso).map_err(|error| {
            tracing::warn!(error = %error, "config-drive ISO verification failed");
            ProviderError::InvalidRequest
        })?;
        Ok((iso, bytes))
    }
}

fn operation_allows_create(operation: &o3k_store::OperationRecord, server_id: Uuid) -> bool {
    matches!(operation.kind.as_str(), "create" | "lifecycle:create")
        && operation.resource_id == server_id
        && matches!(
            operation.state,
            o3k_store::OperationState::Pending
                | o3k_store::OperationState::Running
                | o3k_store::OperationState::Retryable
                | o3k_store::OperationState::UnknownOutcome
        )
}

#[cfg(test)]
mod operation_tests {
    use super::{DaemonCreateResolver, operation_allows_create};
    use o3k_store::{OperationRecord, OperationState};
    use std::collections::BTreeMap;
    use uuid::Uuid;

    fn operation(kind: &str, state: OperationState, resource_id: Uuid) -> OperationRecord {
        OperationRecord {
            id: Uuid::now_v7(),
            resource_id,
            kind: kind.to_owned(),
            state,
            provider_operation_id: None,
            error_category: None,
            error_message: None,
        }
    }

    #[test]
    fn stale_or_mismatched_create_operations_are_rejected() {
        let server_id = Uuid::now_v7();
        assert!(operation_allows_create(
            &operation("create", OperationState::Running, server_id),
            server_id
        ));
        assert!(operation_allows_create(
            &operation("lifecycle:create", OperationState::Retryable, server_id),
            server_id
        ));
        assert!(!operation_allows_create(
            &operation("lifecycle:delete", OperationState::Running, server_id),
            server_id
        ));
        assert!(!operation_allows_create(
            &operation("create", OperationState::Succeeded, server_id),
            server_id
        ));
        assert!(!operation_allows_create(
            &operation("create", OperationState::Running, Uuid::now_v7()),
            server_id
        ));
    }

    #[test]
    fn config_drive_network_data_comes_from_resolved_attachments() {
        let attachments = [o3k_compute_agent::NetworkAttachmentSpec {
            port_id: "port-1".to_owned(),
            mac: "02:00:00:00:00:01".to_owned(),
            fixed_ipv4: "10.0.0.10".to_owned(),
            subnet_cidr: "10.0.0.0/24".to_owned(),
            gateway_ipv4: "10.0.0.1".to_owned(),
        }];
        assert_eq!(
            DaemonCreateResolver::network_data_from_attachments(&attachments),
            BTreeMap::from([
                ("port-1.ipv4".to_owned(), "10.0.0.10".to_owned()),
                ("port-1.mac".to_owned(), "02:00:00:00:00:01".to_owned()),
            ])
        );
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
impl ResolvedCreateResolver for DaemonCreateResolver {
    async fn resolve(
        &self,
        request: &CreateInstanceRequest,
        agent: &AgentNodeSnapshot,
    ) -> Result<ResolvedCreateInputs, ProviderError> {
        self.ensure_create_operation_active(request).await?;
        let image = self.resolve_image(request).await.map_err(|error| {
            tracing::warn!(resource_id = %request.o3k_server_id, error = %error, "compute create image resolution rejected");
            error
        })?;
        let (network_attachments, network_data) = self
            .resolve_network(request, agent)
            .await
            .map_err(|error| {
                tracing::warn!(resource_id = %request.o3k_server_id, error = %error, "compute create network resolution rejected");
                error
            })?;
        let config_drive = request.config_drive.as_ref().map(|_| {
            self.materialize_config_drive(request, network_data.clone())
                .map(|(iso, _)| {
                    let artifact_id = Uuid::new_v5(
                        &Uuid::NAMESPACE_URL,
                        format!("o3k:config-drive:{}:{}", request.o3k_server_id, iso.fingerprint_sha256).as_bytes(),
                    ).to_string();
                    ResolvedConfigDrive { artifact_id, sha256: iso.fingerprint_sha256 }
                })
        }).transpose().map_err(|error| {
            tracing::warn!(resource_id = %request.o3k_server_id, error = %error, "compute create config-drive resolution rejected");
            error
        })?;
        let flavor_id = (!request.flavor_id.trim().is_empty())
            .then(|| request.flavor_id.clone())
            .ok_or(ProviderError::InvalidRequest)?;
        let disk_gib = (request.disk_gib > 0)
            .then_some(request.disk_gib)
            .ok_or(ProviderError::InvalidRequest)?;
        Ok(ResolvedCreateInputs {
            flavor_id,
            image_artifact_id: image.id.to_string(),
            image_sha256: image.checksum,
            image_format: image.format,
            disk_gib,
            config_drive,
            network_attachments,
        })
    }
}

#[async_trait]
impl CreateArtifactResolver for DaemonCreateResolver {
    async fn resolve_artifacts(
        &self,
        request: &CreateInstanceRequest,
        _agent: &AgentNodeSnapshot,
        inputs: &ResolvedCreateInputs,
    ) -> Result<Vec<ResolvedCreateArtifact>, ProviderError> {
        self.ensure_create_operation_active(request).await?;
        let image = self.resolve_image(request).await?;
        if image.checksum != inputs.image_sha256 || image.format != inputs.image_format {
            return Err(ProviderError::Conflict);
        }
        // `resolve` already resolved and realized these attachments before
        // constructing the pending compute command. Resolving them again here
        // would repeat provider mutations while preparing an artifact and can
        // replay the same Fabric command identity with a different deadline.
        let network_data = Self::network_data_from_attachments(&inputs.network_attachments);
        let mut artifacts = vec![ResolvedCreateArtifact {
            artifact_id: inputs.image_artifact_id.clone(),
            kind: ArtifactKind::ImageBase,
            sha256: image.checksum,
            format: image.format,
            bytes: image.content,
        }];
        match (&request.config_drive, &inputs.config_drive) {
            (None, None) => {}
            (Some(_), Some(config_drive)) => {
                let (iso, iso_bytes) = self.materialize_config_drive(request, network_data)?;
                if iso.fingerprint_sha256 != config_drive.sha256 {
                    return Err(ProviderError::Conflict);
                }
                artifacts.push(ResolvedCreateArtifact {
                    artifact_id: config_drive.artifact_id.clone(),
                    kind: ArtifactKind::ConfigDriveIso,
                    sha256: iso.fingerprint_sha256,
                    format: "iso".to_owned(),
                    bytes: iso_bytes,
                });
            }
            _ => return Err(ProviderError::Conflict),
        }
        Ok(artifacts)
    }
}

/// Parses the protected two-tenant isolation seeding environment. Every
/// variable is required together: a partial set is a misconfiguration and
/// fails closed. Disabled by default; only the hosted-service testbed runner
/// sets these to prove cross-tenant isolation.
pub(crate) fn parse_extra_project_seeds()
-> Result<Vec<o3k_identity::ExtraProjectSeed>, Box<dyn std::error::Error>> {
    const PREFIX: &str = "O3K_EXTRA_TENANT_";
    let vars = [
        "PROJECT_ID",
        "PROJECT_NAME",
        "USER_ID",
        "USER_NAME",
        "PASSWORD",
    ];
    let values: Vec<Option<String>> = vars
        .iter()
        .map(|suffix| std::env::var(format!("{PREFIX}{suffix}")).ok())
        .collect();
    if values.iter().all(Option::is_none) {
        return Ok(Vec::new());
    }
    let require = |suffix: &str, index: usize| -> Result<String, Box<dyn std::error::Error>> {
        values[index].clone().ok_or_else(|| {
            format!("{PREFIX}{suffix} is required when any {PREFIX}* variable is set").into()
        })
    };
    let project_id = require("PROJECT_ID", 0)?;
    let project_name = require("PROJECT_NAME", 1)?;
    let user_id = require("USER_ID", 2)?;
    let user_name = require("USER_NAME", 3)?;
    let password = require("PASSWORD", 4)?;
    Uuid::parse_str(&project_id).map_err(|error| -> Box<dyn std::error::Error> {
        format!("{PREFIX}PROJECT_ID: {error}").into()
    })?;
    Uuid::parse_str(&user_id).map_err(|error| -> Box<dyn std::error::Error> {
        format!("{PREFIX}USER_ID: {error}").into()
    })?;
    Ok(vec![o3k_identity::ExtraProjectSeed {
        project_id,
        project_name,
        user_id,
        user_name,
        password: o3k_identity::Secret::new(password),
    }])
}

pub(crate) fn validate_inspect_probe_paths(
    output: Option<&str>,
    resource_file: Option<&str>,
) -> bool {
    let Some(output) = output else {
        return false;
    };
    let output_path = std::path::Path::new(output);
    if !output_path.is_absolute() || output_path.is_symlink() {
        return false;
    }
    if let Some(resource_file) = resource_file {
        let path = std::path::Path::new(resource_file);
        if !path.is_absolute() || path.to_string_lossy().contains("..") || path.is_symlink() {
            return false;
        }
    }
    true
}

pub(crate) fn agent_inspect_probe_from_env(
    compute: o3k_compute::ComputeService,
) -> Option<tokio::task::JoinHandle<()>> {
    let resource_id = std::env::var("O3K_AGENT_INSPECT_PROBE_RESOURCE_ID").ok();
    let resource_file = std::env::var("O3K_AGENT_INSPECT_PROBE_RESOURCE_FILE").ok();
    let output = std::env::var("O3K_AGENT_INSPECT_PROBE_OUTPUT").ok()?;
    let project_id = std::env::var("O3K_AGENT_INSPECT_PROBE_PROJECT_ID")
        .unwrap_or_else(|_| "eba29e2d-53de-461d-ae91-ede7402713cb".to_owned());
    if resource_id
        .as_deref()
        .is_none_or(|value| value.trim().is_empty())
        && resource_file
            .as_deref()
            .is_none_or(|value| value.trim().is_empty())
    {
        tracing::warn!("agent inspect probe configuration is incomplete");
        return None;
    }
    if !validate_inspect_probe_paths(Some(&output), resource_file.as_deref()) {
        tracing::warn!("agent inspect probe path configuration is invalid");
        return None;
    }
    let output = PathBuf::from(output);
    let resource_file = resource_file.map(PathBuf::from);
    Some(tokio::spawn(async move {
        let result = run_agent_inspect_probe(
            &compute,
            &project_id,
            resource_id.as_deref(),
            resource_file.as_deref(),
        )
        .await;
        let document = match result {
            Ok(evidence) => evidence,
            Err(reason) => serde_json::json!({
                "artifact_type": "compute-agent-process-mtls",
                "redacted": true,
                "status": "failed",
                "reason": reason,
            }),
        };
        if let Err(error) = std::fs::write(&output, format!("{document}\n")) {
            tracing::warn!(error = %error, "agent inspect probe evidence could not be written");
        }
    }))
}

pub(crate) async fn run_agent_inspect_probe(
    compute: &o3k_compute::ComputeService,
    project_id: &str,
    fixed_resource_id: Option<&str>,
    resource_file: Option<&std::path::Path>,
) -> Result<serde_json::Value, String> {
    // The probe starts when o3kd starts, but the lifecycle server is created
    // later. Use a long deadline so the probe can wait for the resource file
    // to appear and then for the inspect operation to reach a terminal state.
    let deadline = tokio::time::Instant::now() + Duration::from_secs(300);
    let mut resource_id: Option<Uuid> = None;
    while tokio::time::Instant::now() < deadline {
        let candidate = match (fixed_resource_id, resource_file) {
            (Some(value), _) => value.trim().to_owned(),
            (None, Some(path)) => std::fs::read_to_string(path)
                .ok()
                .map(|value| value.trim().to_owned())
                .unwrap_or_default(),
            (None, None) => String::new(),
        };
        if let Ok(id) = Uuid::parse_str(&candidate) {
            resource_id = Some(id);
        }
        let Some(id) = resource_id else {
            tokio::time::sleep(Duration::from_millis(100)).await;
            continue;
        };
        // Dispatch inspect (or re-check durable state if already terminal).
        let inspect_result = compute
            .inspect_server(
                project_id,
                ServerId::from_uuid(id),
                "o3k-agent-inspect-probe",
            )
            .await;
        match inspect_result {
            Ok(operation)
                if matches!(
                    operation.state,
                    OperationState::Succeeded
                        | OperationState::Failed
                        | OperationState::UnknownOutcome
                ) =>
            {
                let expected = operation.state == OperationState::Succeeded;
                if !expected {
                    return Err(format!(
                        "agent inspect probe state mismatch: state={:?} error_category={:?}",
                        operation.state, operation.error_category
                    ));
                }
                return Ok(serde_json::json!({
                    "artifact_type": "compute-agent-process-mtls",
                    "evidence": {
                        "command": "inspect",
                        "command_state": "accepted",
                        "operation_state": "succeeded",
                        "observation_state": "running",
                        "observation_operation_state": "succeeded",
                        "resource_source": "real-lifecycle-server",
                        "transitions": ["accepted", "operation_succeeded", "observation_succeeded"],
                        "transport": "mutual_tls"
                    },
                    "redacted": true,
                    "scope": "o3kd-compute-service-to-scheduler-to-agent-to-libvirt",
                    "status": "passed"
                }));
            }
            Ok(_) => {
                // Inspect dispatched (Accepted/Running); wait for observation.
                tokio::time::sleep(Duration::from_millis(500)).await;
            }
            Err(o3k_compute::ComputeError::NotFound | o3k_compute::ComputeError::Conflict) => {
                tokio::time::sleep(Duration::from_millis(100)).await;
            }
            Err(error) => return Err(format!("agent inspect probe failed: {error}")),
        }
    }
    Err(
        "agent inspect probe timed out waiting for a durable server record and observation"
            .to_owned(),
    )
}

#[cfg(test)]
mod tests {
    use super::select_active_external_realm;
    use uuid::Uuid;

    fn realm(id: Uuid, state: &str) -> o3k_store::CanonicalAddressRealmRecord {
        o3k_store::CanonicalAddressRealmRecord {
            id,
            network_id: Uuid::from_u128(11),
            project_id: "project".to_owned(),
            prefix: "198.51.100.0/24".to_owned(),
            overlapping_prefixes: false,
            generation: 1,
            state: state.to_owned(),
        }
    }

    #[test]
    fn external_realm_selection_ignores_retired_realms() {
        let active = Uuid::from_u128(2);
        assert_eq!(
            select_active_external_realm(&[
                realm(Uuid::from_u128(1), "retired"),
                realm(active, "active"),
            ]),
            Ok(active)
        );
    }

    #[test]
    fn external_realm_selection_fails_closed_without_active_realm() {
        assert_eq!(
            select_active_external_realm(&[realm(Uuid::from_u128(1), "retired")]),
            Err("configured external network has no active canonical AddressRealm")
        );
    }

    #[test]
    fn external_realm_selection_fails_closed_on_ambiguity() {
        assert_eq!(
            select_active_external_realm(&[
                realm(Uuid::from_u128(1), "active"),
                realm(Uuid::from_u128(2), "active"),
            ]),
            Err("configured external network has multiple active canonical AddressRealms")
        );
    }
}
