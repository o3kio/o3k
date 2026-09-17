use super::cleanup::{
    cleanup_console_log, reap_config_drive_artifacts, reap_orphaned_transfer_parts,
};
use super::dhcp::DhcpRuntime;
use super::iscsi;
use super::network::{
    DomainPresence, NetworkPreparation, cleanup_instance_network, prepare_network,
    reap_stale_instance_networks, return_after_create_rollback, return_after_network_rollback,
};
use super::test_fault_pause_ms;
use async_trait::async_trait;
use o3k_compute_agent::{AgentError, CommandExecutionResult, CommandExecutor, ConsoleLogResult};
use o3k_libvirt::{ErrorCategory, LibvirtAdapter, stable_domain_name};
use o3k_provider_contract::compute_proto as proto;
use std::{
    os::unix::fs::PermissionsExt,
    path::PathBuf,
    sync::{Arc, Mutex},
    time::Duration,
};

pub(crate) struct LibvirtCommandExecutor {
    pub(crate) adapter: LibvirtAdapter,
    pub(crate) artifact_root: PathBuf,
    pub(crate) image_materializer: o3k_compute_agent::ImageMaterializer,
    pub(crate) network: Arc<o3k_network::HostNetworkManager>,
    pub(crate) dhcp: Arc<Mutex<DhcpRuntime>>,
    /// The agent's configured disk capacity (`O3K_COMPUTE_MAX_DISK_GB`). The
    /// same value is published to placement as the DISK_GB inventory; the
    /// create arm uses it as an agent-side backstop (issue #606).
    pub(crate) max_disk_gb: u64,
    pub(crate) network_owned_by_external_agent: bool,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct CommittedArtifact {
    pub(crate) artifact_id: String,
    pub(crate) kind: proto::ArtifactKind,
    pub(crate) format: String,
    pub(crate) sha256: String,
    pub(crate) path: PathBuf,
}

/// A TAP name is usable only together with the network subsystem's ownership
/// evidence.  A port id and MAC address alone are not sufficient proof that a
/// host device may be attached to a domain.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct OwnedTap {
    pub(crate) port_id: String,
    pub(crate) tap_name: String,
    pub(crate) mac_address: String,
    pub(crate) ownership_token: String,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct CreateDomainIdentity {
    pub(crate) server_id: String,
    pub(crate) project_id: String,
    pub(crate) generation: u64,
    pub(crate) operation_id: String,
    pub(crate) managed_by: String,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct CommittedCreateInputs {
    pub(crate) image: CommittedArtifact,
    pub(crate) config_drive: CommittedArtifact,
    pub(crate) owned_taps: Vec<OwnedTap>,
    pub(crate) identity: CreateDomainIdentity,
}

/// Resolve the host-local inputs for a create command before touching
/// libvirt.
///
/// The control-plane command deliberately carries artifact references, not
/// host paths.  The agent-side artifact store also requires the complete
/// authenticated `ArtifactOffer` (including its transfer identity and
/// expiry) to resolve a committed file.  Those fields are not part of
/// `CreateCommand.resolved`, so deriving a path from a digest or rebuilding an
/// offer here would weaken the transfer identity fence.  Network attachments
/// likewise contain only port/MAC/IP data; a libvirt interface requires a TAP
/// name that has been proven to be owned by the host network subsystem.
///
/// Keep this boundary explicit and fail closed until both authenticated
/// lookup metadata and a durable network-ownership lookup are present in the
/// command/executor contract.
pub(crate) fn resolve_create_domain_spec(
    command: &proto::Command,
    committed: Option<&CommittedCreateInputs>,
) -> Result<o3k_libvirt::DomainSpec, AgentError> {
    let Some(proto::command::Action::Create(create)) = command.action.as_ref() else {
        return Err(AgentError::Protocol(
            "create command action is missing or has the wrong type".to_owned(),
        ));
    };
    let Some(resolved) = create.resolved.as_ref() else {
        return Err(AgentError::Protocol(
            "create command resolved inputs are missing".to_owned(),
        ));
    };
    if resolved.image_artifact_id.trim().is_empty()
        || resolved.image_sha256.trim().is_empty()
        || resolved.image_format.trim().is_empty()
        || resolved.config_drive_artifact_id.trim().is_empty()
        || resolved.config_drive_sha256.trim().is_empty()
    {
        return Err(AgentError::Protocol(
            "create command artifact references are incomplete".to_owned(),
        ));
    }

    let Some(committed) = committed else {
        return Err(AgentError::Protocol(
            "create is fail-closed: committed artifact bytes and owned TAP names are not available"
                .to_owned(),
        ));
    };

    if committed.image.artifact_id != resolved.image_artifact_id
        || committed.image.kind != proto::ArtifactKind::ImageBase
        || committed.image.sha256 != resolved.image_sha256
        || committed.image.format != resolved.image_format
        || committed.config_drive.artifact_id != resolved.config_drive_artifact_id
        || committed.config_drive.kind != proto::ArtifactKind::ConfigDriveIso
        || committed.config_drive.sha256 != resolved.config_drive_sha256
        || committed.config_drive.format != "iso"
    {
        return Err(AgentError::Protocol(
            "committed artifact evidence does not match create references".to_owned(),
        ));
    }
    if committed.identity.server_id != command.resource_id
        || committed.identity.project_id.trim().is_empty()
        || committed.identity.operation_id != command.operation_id
        || committed.identity.managed_by.trim().is_empty()
    {
        return Err(AgentError::Protocol(
            "create domain ownership identity is incomplete or mismatched".to_owned(),
        ));
    }
    if committed.image.path.as_os_str().is_empty()
        || !committed.image.path.is_absolute()
        || committed.config_drive.path.as_os_str().is_empty()
        || !committed.config_drive.path.is_absolute()
    {
        return Err(AgentError::Protocol(
            "committed artifact paths must be absolute host-local paths".to_owned(),
        ));
    }
    if committed.owned_taps.len() != resolved.network_attachments.len()
        || committed
            .owned_taps
            .iter()
            .any(|tap| tap.ownership_token.trim().is_empty())
    {
        return Err(AgentError::Protocol(
            "owned TAP evidence is incomplete or does not cover network attachments".to_owned(),
        ));
    }
    let network_interfaces = resolved
        .network_attachments
        .iter()
        .map(|attachment| {
            let tap = committed
                .owned_taps
                .iter()
                .find(|tap| tap.port_id == attachment.port_id);
            let Some(tap) = tap else {
                return Err(AgentError::Protocol(
                    "network attachment has no matching owned TAP".to_owned(),
                ));
            };
            if tap.mac_address != attachment.mac || tap.tap_name.trim().is_empty() {
                return Err(AgentError::Protocol(
                    "owned TAP evidence does not match network attachment".to_owned(),
                ));
            }
            Ok(o3k_libvirt::DomainNetworkInterface {
                tap_name: tap.tap_name.clone(),
                mac_address: tap.mac_address.clone(),
            })
        })
        .collect::<Result<Vec<_>, _>>()?;

    let spec = o3k_libvirt::DomainSpec {
        metadata: o3k_libvirt::DomainMetadata {
            server_id: committed.identity.server_id.clone(),
            project_id: committed.identity.project_id.clone(),
            generation: committed.identity.generation,
            operation_id: committed.identity.operation_id.clone(),
            managed_by: committed.identity.managed_by.clone(),
        },
        vcpus: resolved.vcpus,
        memory_mib: resolved.memory_mib,
        image_id: committed.image.path.to_string_lossy().into_owned(),
        config_drive_image: Some(o3k_libvirt::ConfigDriveImage {
            path: committed.config_drive.path.to_string_lossy().into_owned(),
            sha256: committed.config_drive.sha256.clone(),
        }),
        network_interfaces,
    };
    o3k_libvirt::build_domain_xml(&spec)
        .map(|_| spec)
        .map_err(|_| {
            AgentError::Protocol("resolved domain inputs failed libvirt validation".to_owned())
        })
}

pub(crate) fn resolve_committed_create_inputs(
    command: &proto::Command,
    artifact_root: &std::path::Path,
    image_materializer: &o3k_compute_agent::ImageMaterializer,
    network: &o3k_network::HostNetworkManager,
    network_owned_by_external_agent: bool,
) -> Result<CommittedCreateInputs, AgentError> {
    let Some(proto::command::Action::Create(create)) = command.action.as_ref() else {
        return Err(AgentError::Protocol("create action is missing".to_owned()));
    };
    let Some(resolved) = create.resolved.as_ref() else {
        return Err(AgentError::Protocol(
            "resolved create inputs are missing".to_owned(),
        ));
    };
    let store = o3k_compute_agent::ArtifactStore::open(artifact_root, &command.agent_id)
        .map_err(|_| AgentError::Protocol("agent artifact store is unavailable".to_owned()))?;
    store
        .resolve_committed_artifact(&o3k_compute_agent::CommittedArtifactQuery {
            command_id: command.command_id.clone(),
            operation_id: command.operation_id.clone(),
            resource_id: command.resource_id.clone(),
            artifact_id: resolved.image_artifact_id.clone(),
            kind: proto::ArtifactKind::ImageBase,
            sha256: resolved.image_sha256.clone(),
            format: resolved.image_format.clone(),
        })
        .map_err(|_| AgentError::Protocol("committed image artifact is unavailable".to_owned()))?;
    let materialization_request = o3k_compute_agent::image_materialization_request(command)
        .map_err(|_| {
            AgentError::Protocol("image materialization identity is invalid".to_owned())
        })?;
    let image_path = image_materializer
        .materialize(&materialization_request)
        .map_err(|_| {
            AgentError::Protocol("instance image overlay could not be realized".to_owned())
        })?
        .overlay_path;
    let config_path = store
        .resolve_committed_artifact(&o3k_compute_agent::CommittedArtifactQuery {
            command_id: command.command_id.clone(),
            operation_id: command.operation_id.clone(),
            resource_id: command.resource_id.clone(),
            artifact_id: resolved.config_drive_artifact_id.clone(),
            kind: proto::ArtifactKind::ConfigDriveIso,
            sha256: resolved.config_drive_sha256.clone(),
            format: "iso".to_owned(),
        })
        .map_err(|_| {
            AgentError::Protocol("committed config-drive artifact is unavailable".to_owned())
        })?;
    let mut owned_taps = Vec::with_capacity(resolved.network_attachments.len());
    for attachment in &resolved.network_attachments {
        let tap_name = network
            .resolve_owned_tap(&o3k_network::TapSpec {
                instance_id: if network_owned_by_external_agent {
                    attachment.port_id.clone()
                } else {
                    command.resource_id.clone()
                },
                port_id: attachment.port_id.clone(),
                mac: attachment.mac.clone(),
            })
            .map_err(|error| {
                let managed_taps = network.discover_managed().unwrap_or_default();
                AgentError::Protocol(format!(
                    "owned TAP is unavailable for port {}: {error}; managed_taps={managed_taps:?}",
                    attachment.port_id,
                ))
            })?;
        owned_taps.push(OwnedTap {
            port_id: attachment.port_id.clone(),
            tap_name,
            mac_address: attachment.mac.clone(),
            ownership_token: "durable-network-manifest".to_owned(),
        });
    }
    Ok(CommittedCreateInputs {
        image: CommittedArtifact {
            artifact_id: resolved.image_artifact_id.clone(),
            kind: proto::ArtifactKind::ImageBase,
            format: resolved.image_format.clone(),
            sha256: resolved.image_sha256.clone(),
            path: image_path,
        },
        config_drive: CommittedArtifact {
            artifact_id: resolved.config_drive_artifact_id.clone(),
            kind: proto::ArtifactKind::ConfigDriveIso,
            format: "iso".to_owned(),
            sha256: resolved.config_drive_sha256.clone(),
            path: config_path,
        },
        owned_taps,
        identity: CreateDomainIdentity {
            server_id: command.resource_id.clone(),
            project_id: resolved.project_id.clone(),
            generation: 1,
            operation_id: command.operation_id.clone(),
            managed_by: "o3k-compute".to_owned(),
        },
    })
}

#[async_trait]
impl CommandExecutor for LibvirtCommandExecutor {
    async fn execute(
        &self,
        command: &proto::Command,
    ) -> Result<CommandExecutionResult, AgentError> {
        let name = stable_domain_name(&command.resource_id);
        let success = |message: &str, resource_state: proto::ResourceState| {
            Ok(CommandExecutionResult {
                state: proto::OperationState::Succeeded as i32,
                error_category: proto::ErrorCategory::Unspecified as i32,
                resource_state: resource_state as i32,
                redacted_message: message.to_owned(),
                provider_resource_id: name.clone(),
                console_log: None,
                block_device: None,
            })
        };
        match command.action.as_ref() {
            Some(proto::command::Action::Inspect(_)) => {
                let inspection = match self.adapter.inspect(name.clone()).await {
                    Ok(inspection) => inspection,
                    Err(error) if error.category == ErrorCategory::NotFound => {
                        return Ok(inspect_not_found_result(name));
                    }
                    Err(error) => return Err(agent_error(error)),
                };
                verify_owned_domain(&inspection, &command.resource_id)?;
                success(
                    if inspection.active {
                        "domain is active"
                    } else {
                        "domain is inactive"
                    },
                    resource_state(&inspection),
                )
            }
            Some(proto::command::Action::Start(_)) => {
                let inspection = match self.adapter.inspect(name.clone()).await {
                    Ok(value) => value,
                    Err(error) if error.category == ErrorCategory::NotFound => {
                        return Err(agent_error(error));
                    }
                    Err(error) => return Err(agent_error(error)),
                };
                verify_owned_domain(&inspection, &command.resource_id)?;
                self.adapter
                    .start_owned(name.clone(), command.resource_id.clone())
                    .await
                    .map_err(agent_error)?;
                let inspection = self
                    .adapter
                    .inspect(name.clone())
                    .await
                    .map_err(agent_error)?;
                verify_owned_domain(&inspection, &command.resource_id)?;
                success("domain started", resource_state(&inspection))
            }
            Some(proto::command::Action::Stop(_)) => {
                let inspection = self
                    .adapter
                    .inspect(name.clone())
                    .await
                    .map_err(agent_error)?;
                verify_owned_domain(&inspection, &command.resource_id)?;
                // CirrOS guests ignore ACPI shutdown requests, and public
                // Nova/libvirt powers off hard by default; a graceful
                // shutdown would never reach SHUTOFF. Force the stop, then
                // confirm the guest is actually inactive before projecting
                // the stopped state.
                self.adapter
                    .force_stop_owned(name.clone(), command.resource_id.clone())
                    .await
                    .map_err(agent_error)?;
                let inspection = self
                    .wait_for_domain_inactive(name.clone(), &command.resource_id)
                    .await?;
                success("domain stopped", resource_state(&inspection))
            }
            Some(proto::command::Action::Reboot(_)) => {
                let inspection = self
                    .adapter
                    .inspect(name.clone())
                    .await
                    .map_err(agent_error)?;
                verify_owned_domain(&inspection, &command.resource_id)?;
                // Hard reboot only exists as force stop plus start: guests
                // without ACPI handling (CirrOS) never react to an ACPI
                // reboot request.
                self.adapter
                    .force_stop_owned(name.clone(), command.resource_id.clone())
                    .await
                    .map_err(agent_error)?;
                self.adapter
                    .start_owned(name.clone(), command.resource_id.clone())
                    .await
                    .map_err(agent_error)?;
                let inspection = self
                    .adapter
                    .inspect(name.clone())
                    .await
                    .map_err(agent_error)?;
                verify_owned_domain(&inspection, &command.resource_id)?;
                success("domain rebooted", resource_state(&inspection))
            }
            Some(proto::command::Action::Delete(_)) => {
                let inspection = match self.adapter.inspect(name.clone()).await {
                    Ok(value) => value,
                    Err(error) if error.category == ErrorCategory::NotFound => {
                        if !self.network_owned_by_external_agent {
                            cleanup_instance_network(
                                &self.network,
                                &self.dhcp,
                                &command.resource_id,
                            )?;
                        }
                        self.image_materializer
                            .delete_instance(&command.resource_id)
                            .map_err(|_| {
                                AgentError::Protocol("instance image cleanup failed".to_owned())
                            })?;
                        reap_config_drive_artifacts(
                            &self.artifact_root,
                            &command.agent_id,
                            &command.resource_id,
                        );
                        reap_orphaned_transfer_parts(
                            &self.artifact_root,
                            &command.agent_id,
                            Some(&command.resource_id),
                        );
                        cleanup_console_log(&self.artifact_root, &command.resource_id)?;
                        return success("domain already absent", proto::ResourceState::Deleted);
                    }
                    Err(error) => return Err(agent_error(error)),
                };
                verify_owned_domain(&inspection, &command.resource_id)?;
                if inspection.active {
                    self.adapter
                        .force_stop_owned(name.clone(), command.resource_id.clone())
                        .await
                        .map_err(agent_error)?;
                }
                self.adapter
                    .undefine_owned(name.clone(), command.resource_id.clone())
                    .await
                    .map_err(agent_error)?;
                if !self.network_owned_by_external_agent {
                    cleanup_instance_network(&self.network, &self.dhcp, &command.resource_id)?;
                }
                self.image_materializer
                    .delete_instance(&command.resource_id)
                    .map_err(|_| {
                        AgentError::Protocol("instance image cleanup failed".to_owned())
                    })?;
                reap_config_drive_artifacts(
                    &self.artifact_root,
                    &command.agent_id,
                    &command.resource_id,
                );
                reap_orphaned_transfer_parts(
                    &self.artifact_root,
                    &command.agent_id,
                    Some(&command.resource_id),
                );
                cleanup_console_log(&self.artifact_root, &command.resource_id)?;
                success("domain deleted", proto::ResourceState::Deleted)
            }
            Some(proto::command::Action::Create(_)) => {
                // Agent-side disk-capacity backstop (issue #606): reject an
                // over-capacity create BEFORE any host mutation. The
                // placement gate normally rejects it earlier, but in the
                // agent-restart staleness window the ledger can still carry
                // the pre-restart capacity; the capacity classification makes
                // this indistinguishable from a placement rejection on the
                // control plane. The guard reads only the resolved protobuf
                // inputs, so no TAP, bridge, overlay, or domain exists yet.
                if let Some(disk_gib) = create_disk_gib(command)
                    && disk_gib > self.max_disk_gb
                {
                    tracing::warn!(
                        resource_id = %command.resource_id,
                        disk_gib,
                        max_disk_gb = self.max_disk_gb,
                        "create rejected before host mutation: requested disk \
                         exceeds the agent capacity"
                    );
                    return Ok(capacity_failure_result(disk_gib, self.max_disk_gb));
                }
                // Failures that provably happened before libvirt could create
                // the domain are definitive: the instance does not exist, so
                // the operation is terminally Failed rather than of unknown
                // outcome. Unknown-outcome reporting is preserved for
                // failures after a possible provider side effect (define,
                // start, or a failed rollback) and for observation errors.
                let definitive_failure = |error: AgentError| {
                    definitive_create_failure_result(
                        &self.artifact_root,
                        &command.agent_id,
                        &command.resource_id,
                        &command.operation_id,
                        error,
                    )
                };
                let preparation = if self.network_owned_by_external_agent {
                    NetworkPreparation {
                        created_taps: Vec::new(),
                        added_dhcp_ports: Vec::new(),
                        external_owner: true,
                    }
                } else {
                    match prepare_network(command, &self.network, &self.dhcp) {
                        Ok(preparation) => preparation,
                        Err(error) => return definitive_failure(error),
                    }
                };
                match self.adapter.inspect(name.clone()).await {
                    Ok(existing) => {
                        if let Err(error) = verify_owned_domain(&existing, &command.resource_id) {
                            return definitive_failure(return_after_network_rollback(
                                &self.network,
                                &self.dhcp,
                                &preparation,
                                error,
                            ));
                        }
                        return success("domain already exists", resource_state(&existing));
                    }
                    Err(error) if error.category == ErrorCategory::NotFound => {}
                    Err(error) => {
                        return Err(return_after_network_rollback(
                            &self.network,
                            &self.dhcp,
                            &preparation,
                            agent_error(error),
                        ));
                    }
                }
                let committed = match resolve_committed_create_inputs(
                    command,
                    &self.artifact_root,
                    &self.image_materializer,
                    &self.network,
                    self.network_owned_by_external_agent,
                ) {
                    Ok(value) => value,
                    Err(error) => {
                        // Issue #611 (ASR-021 agent-control-plane-network-interruption):
                        // a missing committed artifact is a CONTROL-PLANE delivery
                        // problem, not a definitive absence. The artifact transfer
                        // can be re-offered by the create re-drive, so this failure
                        // must never be reported as a terminal absence-proven
                        // failure (which would strand the server in ERROR with no
                        // recovery path). The create provably never executed (the
                        // failure is upstream of the define/start boundary), so the
                        // unknown-outcome classification is safe: the reconciler
                        // re-drives the create and the transfer loop re-offers the
                        // missing artifact. The network/console rollback still runs,
                        // exactly as for the definitive classification.
                        return unknown_create_outcome_result(
                            &self.artifact_root,
                            &command.agent_id,
                            &command.resource_id,
                            return_after_create_rollback(
                                &self.network,
                                &self.dhcp,
                                &preparation,
                                &self.image_materializer,
                                &self.artifact_root,
                                &command.resource_id,
                                error,
                            ),
                        );
                    }
                };
                let spec = match resolve_create_domain_spec(command, Some(&committed)) {
                    Ok(value) => value,
                    Err(error) => {
                        return definitive_failure(return_after_create_rollback(
                            &self.network,
                            &self.dhcp,
                            &preparation,
                            &self.image_materializer,
                            &self.artifact_root,
                            &command.resource_id,
                            error,
                        ));
                    }
                };
                let definition = match o3k_libvirt::build_domain_xml(&spec) {
                    Ok(value) => value,
                    Err(_) => {
                        return definitive_failure(return_after_create_rollback(
                            &self.network,
                            &self.dhcp,
                            &preparation,
                            &self.image_materializer,
                            &self.artifact_root,
                            &command.resource_id,
                            AgentError::Protocol("domain XML is invalid".to_owned()),
                        ));
                    }
                };
                let definition_name = definition.name.clone();
                let console_path = match o3k_libvirt::console_log_path(
                    &committed.image.path.to_string_lossy(),
                    &definition_name,
                ) {
                    Ok(path) => path,
                    Err(error) => {
                        return definitive_failure(return_after_create_rollback(
                            &self.network,
                            &self.dhcp,
                            &preparation,
                            &self.image_materializer,
                            &self.artifact_root,
                            &command.resource_id,
                            agent_error(error),
                        ));
                    }
                };
                let console_root = match std::path::Path::new(&console_path)
                    .parent()
                    .ok_or_else(|| AgentError::Protocol("console log root is invalid".to_owned()))
                {
                    Ok(root) => root,
                    Err(error) => {
                        return definitive_failure(return_after_create_rollback(
                            &self.network,
                            &self.dhcp,
                            &preparation,
                            &self.image_materializer,
                            &self.artifact_root,
                            &command.resource_id,
                            error,
                        ));
                    }
                };
                if let Err(error) = std::fs::create_dir_all(console_root) {
                    return definitive_failure(return_after_create_rollback(
                        &self.network,
                        &self.dhcp,
                        &preparation,
                        &self.image_materializer,
                        &self.artifact_root,
                        &command.resource_id,
                        AgentError::Protocol(format!(
                            "console log root could not be created: {error}"
                        )),
                    ));
                }
                #[cfg(unix)]
                if let Err(error) =
                    std::fs::set_permissions(console_root, std::fs::Permissions::from_mode(0o2730))
                {
                    return definitive_failure(return_after_create_rollback(
                        &self.network,
                        &self.dhcp,
                        &preparation,
                        &self.image_materializer,
                        &self.artifact_root,
                        &command.resource_id,
                        AgentError::Protocol(format!(
                            "console log root permissions could not be set: {error}"
                        )),
                    ));
                }
                let console_file = match std::fs::OpenOptions::new()
                    .create(true)
                    .append(true)
                    .open(&console_path)
                {
                    Ok(file) => file,
                    Err(error) => {
                        return definitive_failure(return_after_create_rollback(
                            &self.network,
                            &self.dhcp,
                            &preparation,
                            &self.image_materializer,
                            &self.artifact_root,
                            &command.resource_id,
                            AgentError::Protocol(format!(
                                "console log could not be created: {error}"
                            )),
                        ));
                    }
                };
                #[cfg(unix)]
                if let Err(error) =
                    console_file.set_permissions(std::fs::Permissions::from_mode(0o660))
                {
                    return definitive_failure(return_after_create_rollback(
                        &self.network,
                        &self.dhcp,
                        &preparation,
                        &self.image_materializer,
                        &self.artifact_root,
                        &command.resource_id,
                        AgentError::Protocol(format!(
                            "console log permissions could not be set: {error}"
                        )),
                    ));
                }
                tracing::warn!(
                    command_id = %command.command_id,
                    operation_id = %command.operation_id,
                    resource_id = %command.resource_id,
                    domain = %definition_name,
                    vcpus = spec.vcpus,
                    memory_mib = spec.memory_mib,
                    network_attachment_count = spec.network_interfaces.len(),
                    image_artifact_id = %committed.image.artifact_id,
                    config_drive_artifact_id = %committed.config_drive.artifact_id,
                    xml_bytes = definition.xml.len(),
                    "libvirt create request"
                );
                if let Err(error) = self
                    .adapter
                    .define(o3k_libvirt::DomainDefinition {
                        name: definition_name.clone(),
                        xml: definition.xml,
                    })
                    .await
                {
                    tracing::warn!(
                        operation_id = %command.operation_id,
                        resource_id = %command.resource_id,
                        domain = %definition_name,
                        libvirt_stage = "define",
                        libvirt_detail = %error.message(),
                        "libvirt create failed"
                    );
                    return Err(return_after_create_rollback(
                        &self.network,
                        &self.dhcp,
                        &preparation,
                        &self.image_materializer,
                        &self.artifact_root,
                        &command.resource_id,
                        agent_error(error),
                    ));
                }
                test_fault_pause_ms("after-define", "O3K_TEST_FAULT_PAUSE_AFTER_DEFINE_MS");
                if let Err(error) = self
                    .adapter
                    .start_owned(definition_name.clone(), command.resource_id.clone())
                    .await
                {
                    tracing::warn!(
                        operation_id = %command.operation_id,
                        resource_id = %command.resource_id,
                        domain = %definition_name,
                        libvirt_stage = "start",
                        libvirt_detail = %error.message(),
                        "libvirt create failed"
                    );
                    let undefine_result = self
                        .adapter
                        .undefine_owned(definition_name.clone(), command.resource_id.clone())
                        .await;
                    let error = match undefine_result {
                        Ok(()) => agent_error(error),
                        Err(cleanup_error) => AgentError::Protocol(format!(
                            "{}; domain rollback also failed: {}",
                            agent_error(error),
                            cleanup_error
                        )),
                    };
                    return Err(return_after_create_rollback(
                        &self.network,
                        &self.dhcp,
                        &preparation,
                        &self.image_materializer,
                        &self.artifact_root,
                        &command.resource_id,
                        error,
                    ));
                }
                test_fault_pause_ms("after-start", "O3K_TEST_FAULT_PAUSE_AFTER_START_MS");
                let inspection = match self.adapter.inspect(definition_name.clone()).await {
                    Ok(value) => value,
                    Err(error) => {
                        tracing::warn!(
                            operation_id = %command.operation_id,
                            resource_id = %command.resource_id,
                            domain = %definition_name,
                            libvirt_stage = "inspect",
                            libvirt_detail = %error.message(),
                            "libvirt create failed"
                        );
                        let error = match self
                            .adapter
                            .undefine_owned(name.clone(), command.resource_id.clone())
                            .await
                        {
                            Ok(()) => agent_error(error),
                            Err(cleanup_error) => AgentError::Protocol(format!(
                                "{}; domain rollback also failed: {}",
                                agent_error(error),
                                cleanup_error
                            )),
                        };
                        return Err(return_after_create_rollback(
                            &self.network,
                            &self.dhcp,
                            &preparation,
                            &self.image_materializer,
                            &self.artifact_root,
                            &command.resource_id,
                            error,
                        ));
                    }
                };
                if let Err(error) = verify_owned_domain(&inspection, &command.resource_id) {
                    let error = match self
                        .adapter
                        .undefine_owned(name.clone(), command.resource_id.clone())
                        .await
                    {
                        Ok(()) => error,
                        Err(cleanup_error) => AgentError::Protocol(format!(
                            "{error}; domain rollback also failed: {cleanup_error}"
                        )),
                    };
                    return Err(return_after_create_rollback(
                        &self.network,
                        &self.dhcp,
                        &preparation,
                        &self.image_materializer,
                        &self.artifact_root,
                        &command.resource_id,
                        error,
                    ));
                }
                let console_log = match self
                    .adapter
                    .read_console(
                        definition_name,
                        o3k_console::MAX_CONSOLE_BYTES,
                        command.resource_id.clone(),
                    )
                    .await
                {
                    Ok(bytes) if !bytes.is_empty() => Some(ConsoleLogResult {
                        truncated: bytes.len() == o3k_console::MAX_CONSOLE_BYTES,
                        complete: bytes.len() < o3k_console::MAX_CONSOLE_BYTES,
                        offset: 0,
                        bytes,
                    }),
                    Ok(_) => None,
                    Err(error) => {
                        tracing::warn!(%error, server_id = %command.resource_id, "initial console capture failed");
                        None
                    }
                };
                let mut result = success("domain created", resource_state(&inspection))?;
                result.console_log = console_log;
                Ok(result)
            }
            Some(proto::command::Action::ConsoleLog(request)) => {
                if request.offset > 0 {
                    return Err(AgentError::Protocol(
                        "libvirt console snapshots only support offset zero".to_owned(),
                    ));
                }
                let max_bytes = usize::try_from(request.max_bytes)
                    .map_err(|_| AgentError::Protocol("console bound is invalid".to_owned()))?
                    .min(o3k_console::MAX_CONSOLE_BYTES);
                if max_bytes == 0 {
                    return Err(AgentError::Protocol("console bound is invalid".to_owned()));
                }
                tracing::info!(
                    server_id = %command.resource_id,
                    domain = %name,
                    max_bytes,
                    "console inspect start"
                );
                let inspection = self.adapter.inspect(name.clone()).await.map_err(|error| {
                    tracing::warn!(
                        %error,
                        server_id = %command.resource_id,
                        "console inspect failed"
                    );
                    agent_error(error)
                })?;
                verify_owned_domain(&inspection, &command.resource_id).inspect_err(|error| {
                    tracing::warn!(
                        %error,
                        server_id = %command.resource_id,
                        "console ownership verification failed"
                    );
                })?;
                tracing::info!(
                    server_id = %command.resource_id,
                    active = inspection.active,
                    persistent = inspection.persistent,
                    state = %inspection.state,
                    "console inspect end"
                );
                let bytes = self
                    .adapter
                    .read_console(name.clone(), max_bytes, command.resource_id.clone())
                    .await
                    .map_err(|error| {
                        tracing::warn!(
                            %error,
                            server_id = %command.resource_id,
                            "console read failed"
                        );
                        agent_error(error)
                    })?;
                tracing::info!(
                    server_id = %command.resource_id,
                    bytes = bytes.len(),
                    "console read end"
                );
                Ok(CommandExecutionResult {
                    state: proto::OperationState::Succeeded as i32,
                    error_category: proto::ErrorCategory::Unspecified as i32,
                    resource_state: resource_state(&inspection) as i32,
                    redacted_message: "libvirt console output read".to_owned(),
                    provider_resource_id: name,
                    console_log: Some(ConsoleLogResult {
                        truncated: bytes.len() == max_bytes,
                        complete: bytes.len() < max_bytes,
                        offset: 0,
                        bytes,
                    }),
                    block_device: None,
                })
            }
            Some(proto::command::Action::CollectConnector(_)) => {
                let connector = iscsi::collect_host_connector()?;
                let mut result = success("connector collected", proto::ResourceState::Running)?;
                result.block_device = Some(proto::BlockDeviceObservation {
                    volume_id: String::new(),
                    attachment_id: String::new(),
                    driver_volume_type: String::new(),
                    device_path: String::new(),
                    host_path: String::new(),
                    attached: false,
                    found: true,
                    initiator: connector.initiator.clone().unwrap_or_default(),
                    host_name: connector.host,
                    ip_address: connector.ip,
                    iscsi_logged_in: false,
                });
                Ok(result)
            }
            Some(proto::command::Action::AttachDisk(device)) => {
                let inspection = self
                    .adapter
                    .inspect(name.clone())
                    .await
                    .map_err(agent_error)?;
                verify_owned_domain(&inspection, &command.resource_id)?;
                if device.driver_volume_type != "iscsi" && device.driver_volume_type != "local" {
                    return Err(AgentError::Protocol(format!(
                        "unsupported driver_volume_type {}",
                        device.driver_volume_type
                    )));
                }
                let host_path = if device.driver_volume_type == "iscsi" {
                    let chap_auth =
                        if device.auth_username.is_empty() || device.auth_password.is_empty() {
                            None
                        } else {
                            Some((device.auth_username.as_str(), device.auth_password.as_str()))
                        };
                    let host_path = iscsi::iscsi_login(
                        &device.target_iqn,
                        &device.target_portal,
                        device.target_lun,
                        chap_auth,
                    )?;
                    host_path.ok_or_else(|| {
                        AgentError::Protocol(
                            "iscsi login succeeded but no device path was observed".to_owned(),
                        )
                    })?
                } else {
                    device.device_path.clone()
                };
                let guest_device =
                    iscsi::attach_device_letter(&command.resource_id, &device.volume_id);
                // Idempotent hotplug: a concurrent attach or a reconciler
                // resume may already have hotplugged the disk. If the durable
                // o3k-<uuid> disk serial is present, skip the attach and
                // report success rather than failing with "device already
                // exists".
                if self
                    .adapter
                    .observe_disk(name.clone(), device.volume_id.clone())
                    .await
                    .unwrap_or(false)
                {
                    let host_path = host_path.clone();
                    let mut result =
                        success("block device attached", proto::ResourceState::Running)?;
                    result.block_device = Some(proto::BlockDeviceObservation {
                        volume_id: device.volume_id.clone(),
                        attachment_id: device.attachment_id.clone(),
                        driver_volume_type: device.driver_volume_type.clone(),
                        device_path: format!("/dev/{guest_device}"),
                        host_path,
                        attached: true,
                        found: true,
                        initiator: device.initiator.clone(),
                        host_name: String::new(),
                        ip_address: String::new(),
                        iscsi_logged_in: device.driver_volume_type == "iscsi",
                    });
                    return Ok(result);
                }
                if let Err(error) = self
                    .adapter
                    .attach_disk(
                        name.clone(),
                        device.volume_id.clone(),
                        device.attachment_id.clone(),
                        host_path.clone(),
                        guest_device.clone(),
                    )
                    .await
                {
                    // The hotplug raced with a concurrent attach: verify by the
                    // durable ownership metadata before failing.
                    if self
                        .adapter
                        .observe_disk(name.clone(), device.volume_id.clone())
                        .await
                        .unwrap_or(false)
                    {
                        tracing::info!(
                            volume_id = %device.volume_id,
                            "disk already hotplugged by a concurrent attach; treating as success"
                        );
                    } else {
                        return Err(agent_error(error));
                    }
                }
                let mut result = success("block device attached", proto::ResourceState::Running)?;
                result.block_device = Some(proto::BlockDeviceObservation {
                    volume_id: device.volume_id.clone(),
                    attachment_id: device.attachment_id.clone(),
                    driver_volume_type: device.driver_volume_type.clone(),
                    device_path: format!("/dev/{guest_device}"),
                    host_path,
                    attached: true,
                    found: true,
                    initiator: device.initiator.clone(),
                    host_name: String::new(),
                    ip_address: String::new(),
                    iscsi_logged_in: device.driver_volume_type == "iscsi",
                });
                Ok(result)
            }
            Some(proto::command::Action::DetachDisk(device)) => {
                let inspection = self
                    .adapter
                    .inspect(name.clone())
                    .await
                    .map_err(agent_error)?;
                verify_owned_domain(&inspection, &command.resource_id)?;
                let detached = self
                    .adapter
                    .detach_disk(name.clone(), device.volume_id.clone())
                    .await
                    .map_err(agent_error)?;
                if device.driver_volume_type == "iscsi" {
                    let _ = iscsi::iscsi_logout(&device.target_iqn, &device.target_portal);
                }
                let mut result = success("block device detached", proto::ResourceState::Running)?;
                result.block_device = Some(proto::BlockDeviceObservation {
                    volume_id: device.volume_id.clone(),
                    attachment_id: device.attachment_id.clone(),
                    driver_volume_type: device.driver_volume_type.clone(),
                    device_path: String::new(),
                    host_path: String::new(),
                    attached: false,
                    found: detached,
                    initiator: device.initiator.clone(),
                    host_name: String::new(),
                    ip_address: String::new(),
                    iscsi_logged_in: false,
                });
                Ok(result)
            }
            Some(proto::command::Action::ObserveDisk(observe)) => {
                let inspection = self
                    .adapter
                    .inspect(name.clone())
                    .await
                    .map_err(agent_error)?;
                verify_owned_domain(&inspection, &command.resource_id)?;
                let attached = self
                    .adapter
                    .observe_disk(name.clone(), observe.volume_id.clone())
                    .await
                    .map_err(agent_error)?;
                let mut result = success(
                    if attached {
                        "disk is attached"
                    } else {
                        "disk is not attached"
                    },
                    proto::ResourceState::Running,
                )?;
                result.block_device = Some(proto::BlockDeviceObservation {
                    volume_id: observe.volume_id.clone(),
                    attachment_id: observe.attachment_id.clone(),
                    driver_volume_type: String::new(),
                    device_path: String::new(),
                    host_path: String::new(),
                    attached,
                    found: attached,
                    initiator: String::new(),
                    host_name: String::new(),
                    ip_address: String::new(),
                    iscsi_logged_in: attached,
                });
                Ok(result)
            }
            None => Err(AgentError::Protocol("command action is missing".to_owned())),
        }
    }
}

pub(crate) fn inspect_not_found_result(provider_resource_id: String) -> CommandExecutionResult {
    CommandExecutionResult {
        state: proto::OperationState::Failed as i32,
        error_category: proto::ErrorCategory::NotFound as i32,
        resource_state: proto::ResourceState::Error as i32,
        redacted_message: "requested domain was not found".to_owned(),
        provider_resource_id,
        console_log: None,
        block_device: None,
    }
}

/// Builds the definitive (absence-proven) terminal failure result for a
/// create that failed before libvirt could define the domain. The control
/// plane terminalizes this outcome as Failed and later completes the delete
/// locally through the never-reached-provider path — no agent delete command
/// is ever dispatched — so the resource's committed config-drive transfer
/// state would otherwise leak (issue #88 C6). The resource's owned
/// config-drive artifacts are therefore reaped here, best-effort: a failed
/// reap is logged and never changes the command outcome. This is the ONLY
/// create path that reaps; unknown-outcome and retryable failures never
/// reach it, so a retried create still finds its committed manifests.
pub(crate) fn definitive_create_failure_result(
    artifact_root: &std::path::Path,
    agent_id: &str,
    resource_id: &str,
    operation_id: &str,
    error: AgentError,
) -> Result<CommandExecutionResult, AgentError> {
    // The redacted reason is also carried in the result so the control plane
    // can persist it; log the same redacted string here so host-side
    // diagnosis does not require the durable store.
    tracing::warn!(
        error = %error,
        operation_id = %operation_id,
        resource_id = %resource_id,
        "create failed definitively; reporting terminal failure"
    );
    reap_config_drive_artifacts(artifact_root, agent_id, resource_id);
    Ok(definitive_failure_result(&error))
}

/// Result for a create failure that provably happened before libvirt could
/// define the domain (issue-87 C-1 qemu-img materialization, network
/// preparation, domain-spec and console-log failures). Absence is proven by
/// construction: every caller is upstream of the define/start boundary, so
/// the instance can never exist and the operation is terminally Failed
/// rather than of unknown outcome. The category reports the absence so the
/// control plane can recognize that no provider side effect can exist and
/// complete a local delete; the redacted reason is carried in the message
/// for the durable record.
pub(crate) fn definitive_failure_result(error: &AgentError) -> CommandExecutionResult {
    CommandExecutionResult {
        state: proto::OperationState::Failed as i32,
        error_category: proto::ErrorCategory::NotFound as i32,
        resource_state: proto::ResourceState::Error as i32,
        redacted_message: error.to_string(),
        provider_resource_id: String::new(),
        console_log: None,
        block_device: None,
    }
}

/// Result for a create that failed before libvirt could define the domain
/// because a REQUIRED COMMITTED ARTIFACT was missing (issue #611,
/// ASR-021 agent-control-plane-network-interruption). Absence is proven by
/// construction (the failure is upstream of the define/start boundary), but
/// the missing artifact is a control-plane delivery problem the create
/// re-drive can fix by re-offering the transfer — so the outcome is UNKNOWN,
/// never terminal. The reconciler's unknown-outcome recovery re-drives the
/// create, and the provider's transfer loop re-offers the missing artifact.
pub(crate) fn unknown_create_outcome_result(
    artifact_root: &std::path::Path,
    agent_id: &str,
    resource_id: &str,
    error: AgentError,
) -> Result<CommandExecutionResult, AgentError> {
    tracing::warn!(
        error = %error,
        resource_id = %resource_id,
        "create could not resolve committed artifacts; reporting an unknown outcome"
    );
    reap_config_drive_artifacts(artifact_root, agent_id, resource_id);
    Ok(CommandExecutionResult {
        state: proto::OperationState::UnknownOutcome as i32,
        error_category: proto::ErrorCategory::UnknownOutcome as i32,
        resource_state: proto::ResourceState::Error as i32,
        redacted_message: error.to_string(),
        provider_resource_id: String::new(),
        console_log: None,
        block_device: None,
    })
}

/// Result for a create rejected by the agent's disk-capacity backstop
/// (issue #606). The rejection provably happens before any host mutation, so
/// the capacity classification mirrors the placement gate's rejection and the
/// control plane persists the same durable `capacity` category.
pub(crate) fn capacity_failure_result(disk_gib: u64, max_disk_gb: u64) -> CommandExecutionResult {
    CommandExecutionResult {
        state: proto::OperationState::Failed as i32,
        error_category: proto::ErrorCategory::Capacity as i32,
        resource_state: proto::ResourceState::Error as i32,
        redacted_message: format!(
            "create requires {disk_gib} GiB disk but the agent capacity is {max_disk_gb} GiB"
        ),
        provider_resource_id: String::new(),
        console_log: None,
        block_device: None,
    }
}

/// The create command's resolved disk demand, or `None` when the command is
/// not a create or carries no resolved inputs. Pure protobuf read: no host
/// state is touched, so the create arm can evaluate it before any mutation.
pub(crate) fn create_disk_gib(command: &proto::Command) -> Option<u64> {
    let proto::command::Action::Create(create) = command.action.as_ref()? else {
        return None;
    };
    create.resolved.as_ref().map(|resolved| resolved.disk_gib)
}

pub(crate) fn resource_state(inspection: &o3k_libvirt::DomainInspection) -> proto::ResourceState {
    match o3k_libvirt::project_domain_state(inspection.active, &inspection.state) {
        o3k_provider::InstanceState::Running => proto::ResourceState::Running,
        o3k_provider::InstanceState::Stopped => proto::ResourceState::Stopped,
        o3k_provider::InstanceState::Creating => proto::ResourceState::Creating,
        o3k_provider::InstanceState::Deleting => proto::ResourceState::Deleting,
        o3k_provider::InstanceState::Deleted => proto::ResourceState::Deleted,
        o3k_provider::InstanceState::Error => proto::ResourceState::Error,
    }
}

pub(crate) fn verify_owned_domain(
    inspection: &o3k_libvirt::DomainInspection,
    expected_server_id: &str,
) -> Result<(), AgentError> {
    match o3k_libvirt::discover_domain_xml(&inspection.name, &inspection.xml) {
        o3k_libvirt::DiscoveryResult::Owned { metadata, .. }
            if metadata.server_id == expected_server_id =>
        {
            Ok(())
        }
        _ => Err(AgentError::Protocol(
            "libvirt domain ownership verification failed".to_owned(),
        )),
    }
}

pub(crate) fn agent_error(error: o3k_libvirt::LibvirtError) -> AgentError {
    // Preserve only the finite adapter category on the wire. The exact
    // provider operation/code/message is retained in the host-local warning so
    // a real-host failure can be classified without widening the protocol.
    let category = match error.category {
        ErrorCategory::Unavailable => "unavailable",
        ErrorCategory::ConnectionLost => "connection_lost",
        ErrorCategory::NotFound => "not_found",
        ErrorCategory::InvalidRequest => "invalid_request",
        ErrorCategory::OperationFailed => "operation_failed",
    };
    tracing::warn!(
        libvirt_category = category,
        libvirt_detail = %error.message(),
        "libvirt command failed"
    );
    AgentError::Protocol(format!("libvirt command failed: {category}"))
}

impl LibvirtCommandExecutor {
    /// Polls until the domain is inactive or the bounded wait expires.
    async fn wait_for_domain_inactive(
        &self,
        name: String,
        resource_id: &str,
    ) -> Result<o3k_libvirt::DomainInspection, AgentError> {
        let deadline = std::time::Instant::now() + std::time::Duration::from_secs(5);
        loop {
            let inspection = self
                .adapter
                .inspect(name.clone())
                .await
                .map_err(agent_error)?;
            verify_owned_domain(&inspection, resource_id)?;
            if !inspection.active {
                return Ok(inspection);
            }
            if std::time::Instant::now() >= deadline {
                return Err(AgentError::Protocol(
                    "domain did not stop within the bounded wait".to_owned(),
                ));
            }
            tokio::time::sleep(std::time::Duration::from_millis(100)).await;
        }
    }
}

/// Startup DHCP reconciliation for persisted bindings (issue #87 S3 rerun
/// #5). The caller must treat a failure as a logged, non-fatal condition:
/// the agent has to stay up (control-plane connection, journal replay) even
/// when DHCP cannot start at boot, and DHCP is retried on the next restart
/// or the next create. Create-time DHCP failures stay fail-closed in
/// [`DhcpRuntime::apply`]; only the boot reconciliation may fail softly.
pub(crate) fn reconcile_dhcp_on_startup(
    dhcp: &Arc<Mutex<DhcpRuntime>>,
    network: &o3k_network::HostNetworkManager,
) -> Result<(), String> {
    dhcp.lock()
        .map_err(|_| "DHCP runtime lock is poisoned".to_owned())?
        .start_after_restart(network)
        .map_err(|error| format!("DHCP reconciliation failed: {error}"))
}

/// Bounded window for the startup domain restoration. A host reboot leaves
/// every qemu domain defined but inactive; the restore observes each owned
/// domain, starts the ones whose last lifecycle mutation provably left them
/// running, and retries failed attempts inside this window (libvirtd can
/// still be accepting its first connections when the agent starts). Startup
/// never blocks on the restore: the pass is best-effort and re-runs on the
/// next agent restart.
pub(crate) const STARTUP_DOMAIN_RESTORE_WINDOW: Duration = Duration::from_secs(60);
pub(crate) const STARTUP_DOMAIN_RESTORE_RETRY: Duration = Duration::from_millis(1000);

/// Observe-and-restore port for one O3K-owned domain. The real adapter
/// classifies libvirt outcomes; tests inject fakes without the libvirt
/// feature.
#[async_trait]
pub(crate) trait StartupDomainRestore: Send + Sync {
    /// Observes the owned domain and, when it is defined but inactive,
    /// starts it and confirms the start with a second inspection. Returns
    /// `Ok(true)` when a restore happened, `Ok(false)` when none was needed
    /// (the domain is absent or already active), and `Err` when the outcome
    /// is unknown (retried by the bounded window).
    async fn restore_owned_domain(&self, resource_id: &str) -> Result<bool, AgentError>;
}

#[async_trait]
impl StartupDomainRestore for LibvirtAdapter {
    async fn restore_owned_domain(&self, resource_id: &str) -> Result<bool, AgentError> {
        let name = stable_domain_name(resource_id);
        let inspection = match self.inspect(name.clone()).await {
            Ok(inspection) => inspection,
            Err(error) if error.category == ErrorCategory::NotFound => return Ok(false),
            Err(error) => return Err(agent_error(error)),
        };
        verify_owned_domain(&inspection, resource_id)?;
        if inspection.active {
            return Ok(false);
        }
        self.start_owned(name.clone(), resource_id.to_owned())
            .await
            .map_err(agent_error)?;
        let confirmed = self.inspect(name.clone()).await.map_err(agent_error)?;
        verify_owned_domain(&confirmed, resource_id)?;
        Ok(confirmed.active)
    }
}

/// Observe-and-restore port for the owned TAP devices of one O3K-owned
/// instance (issue #613 blocker A): a host reboot deletes the ephemeral TAP
/// devices while the persisted domain XML still references them, so the
/// domain start would fail. The real implementation reuses the create-time
/// [`o3k_network::HostNetworkManager::ensure_tap`] ownership path; tests
/// inject fakes without touching the host network.
#[async_trait]
pub(crate) trait StartupTapRestore: Send + Sync {
    /// Ensures every TAP recorded as O3K-owned for the instance exists and
    /// is attached to the managed bridge before the domain start. An absent
    /// TAP is re-created under the recorded deterministic name, a present
    /// owned TAP is verified and reused, and a foreign link at the recorded
    /// name fails closed without being touched. `Err` means the outcome is
    /// unknown or foreign: the caller must hold back the instance's domain
    /// start and retries inside the bounded window.
    async fn restore_owned_taps(&self, resource_id: &str) -> Result<(), AgentError>;
}

/// Real TAP restoration driven by the durable network ownership manifest.
/// Each recorded spec is re-verified by `ensure_tap` against both the
/// manifest and the kernel, so a forged or stale record can never create or
/// mutate a foreign interface.
pub(crate) struct NetworkStartupTapRestore {
    pub(crate) network: Arc<o3k_network::HostNetworkManager>,
    pub(crate) external_owner: bool,
}

#[async_trait]
impl StartupTapRestore for NetworkStartupTapRestore {
    async fn restore_owned_taps(&self, resource_id: &str) -> Result<(), AgentError> {
        let specs = self
            .network
            .owned_tap_specs_for_instance(resource_id)
            .map_err(|error| AgentError::Protocol(format!("owned TAP lookup failed: {error}")))?;
        for spec in specs {
            if self.external_owner {
                self.network.resolve_owned_tap(&spec).map_err(|error| {
                    AgentError::Protocol(format!("external network TAP is unavailable: {error}"))
                })?;
                continue;
            }
            let (name, created) = self.network.ensure_tap(&spec).map_err(|error| {
                AgentError::Protocol(format!("owned TAP restoration failed: {error}"))
            })?;
            if created {
                tracing::info!(
                    resource_id = %resource_id,
                    tap = %name,
                    "re-created owned TAP during startup domain restoration"
                );
            }
        }
        Ok(())
    }
}

/// Re-reads the durable command journal at the start of every restore pass
/// (stale-snapshot fence, see [`restore_expected_running_domains`]). The
/// real implementation observes the same journal file the control
/// connection writes; tests inject fakes whose snapshot changes between
/// passes.
pub(crate) trait StartupJournalRefresh: Send + Sync {
    fn latest_lifecycle_states(
        &self,
    ) -> Result<std::collections::HashMap<String, (u64, proto::ResourceState)>, AgentError>;
}

/// Journal re-read driven by the durable command journal file. Read-only:
/// the live journal instance owned by the control connection is opened
/// separately by the agent, and this snapshot only ever observes.
pub(crate) struct CommandJournalStartupRefresh {
    pub(crate) identity_path: PathBuf,
    pub(crate) agent_id: String,
}

impl StartupJournalRefresh for CommandJournalStartupRefresh {
    fn latest_lifecycle_states(
        &self,
    ) -> Result<std::collections::HashMap<String, (u64, proto::ResourceState)>, AgentError> {
        o3k_compute_agent::load_journal_lifecycle_resource_states(
            &self.identity_path,
            &self.agent_id,
        )
    }
}

/// Startup restoration of O3K-owned libvirt domains (one-line TestLab host
/// reboot contract, issue #613 blocker A): a host reboot leaves every qemu
/// domain defined but inactive while the control plane's durable server
/// state stays ACTIVE, and no control-plane operation is left non-terminal
/// to re-drive. The agent's command journal records the last lifecycle
/// mutation it executed per resource, so the domains whose last mutation
/// provably left them running are restored here by starting them again.
///
/// Ordering: a reboot also deletes the ephemeral TAP devices, so the owned
/// TAPs recorded in the network ownership manifest are re-created (or
/// ownership-verified and reused) BEFORE the domain start — the persisted
/// domain XML references them with `managed="no"` and libvirt refuses to
/// start without them. The bridge is guaranteed to exist first: the startup
/// DHCP reconciliation ran before this pass, and `ensure_tap` re-ensures
/// the bridge itself.
///
/// Observe-before-mutate: every TAP restoration is ownership-verified
/// against the manifest and the kernel, every start is preceded by an
/// ownership-verified inspection and confirmed by a second inspection, so a
/// retried attempt can never double-start a domain that came up after an
/// unknown outcome. A failed TAP restoration holds back that instance's
/// domain start (fail closed: an unverified or foreign interface must never
/// be mutated, and a start without its TAP cannot succeed). Absent domains
/// are left alone (their convergence is owned by the control plane), and
/// failures are retried inside the bounded window and logged; the agent
/// never fails startup on a restore.
///
/// Stale-snapshot race: the seed snapshot is taken before the control
/// connection starts, so a lifecycle command accepted afterwards (a fresh
/// user stop or start) is invisible to it. At the start of EVERY retry pass
/// the durable journal is re-read and every still-pending resource whose
/// latest terminal lifecycle state is no longer `Running` is dropped (only
/// the per-resource state is re-snapshotted — the pending set itself is
/// never rebuilt from scratch). The re-read closes the race for commands
/// accepted before the pass begins; a stop accepted after the re-read but
/// before that pass's start of the resource can still be undone, so a
/// residual single-pass window remains (the executor and the restore use
/// separate libvirt connections with no mutual exclusion).
pub(crate) async fn restore_expected_running_domains(
    tap_restorer: &dyn StartupTapRestore,
    restorer: &dyn StartupDomainRestore,
    journal_refresh: &dyn StartupJournalRefresh,
    states: &std::collections::HashMap<String, (u64, proto::ResourceState)>,
) -> Result<(), AgentError> {
    restore_expected_running_domains_with_window(
        tap_restorer,
        restorer,
        journal_refresh,
        states,
        STARTUP_DOMAIN_RESTORE_WINDOW,
        STARTUP_DOMAIN_RESTORE_RETRY,
    )
    .await
}

pub(crate) async fn restore_expected_running_domains_with_window(
    tap_restorer: &dyn StartupTapRestore,
    restorer: &dyn StartupDomainRestore,
    journal_refresh: &dyn StartupJournalRefresh,
    states: &std::collections::HashMap<String, (u64, proto::ResourceState)>,
    window: Duration,
    retry: Duration,
) -> Result<(), AgentError> {
    let mut pending: std::collections::BTreeSet<String> = states
        .iter()
        .filter(|(_, (_, state))| *state == proto::ResourceState::Running)
        .map(|(resource_id, _)| resource_id.clone())
        .collect();
    if pending.is_empty() {
        return Ok(());
    }
    let deadline = std::time::Instant::now() + window;
    let mut first_error = None;
    loop {
        // Stale-snapshot fence: re-read the durable journal before mutating
        // anything this pass. A resource whose fresh last terminal
        // lifecycle state is no longer `Running` was stopped (or deleted)
        // by the control connection since the seed snapshot and must not be
        // re-started. Only the per-resource state is re-snapshotted — the
        // pending set is never rebuilt from scratch, so a resource that
        // already converged or was dropped stays dropped. See the
        // `restore_expected_running_domains` doc comment for the residual
        // single-pass window.
        match journal_refresh.latest_lifecycle_states() {
            Ok(latest) => {
                pending.retain(|resource_id| {
                    latest
                        .get(resource_id)
                        .is_some_and(|(_, state)| *state == proto::ResourceState::Running)
                });
                if pending.is_empty() {
                    return Ok(());
                }
                let mut next = std::collections::BTreeSet::new();
                for resource_id in &pending {
                    if let Err(error) = tap_restorer.restore_owned_taps(resource_id).await {
                        tracing::warn!(
                            resource_id = %resource_id,
                            error = %error,
                            "owned TAP restoration failed; holding back the domain start and \
                             retrying inside the startup window"
                        );
                        next.insert(resource_id.clone());
                        first_error.get_or_insert(error);
                        continue;
                    }
                    match restorer.restore_owned_domain(resource_id).await {
                        Ok(true) => {
                            tracing::info!(
                                resource_id = %resource_id,
                                "restored O3K-owned domain to running"
                            );
                        }
                        Ok(false) => {}
                        Err(error) => {
                            tracing::warn!(
                                resource_id = %resource_id,
                                error = %error,
                                "domain restore attempt failed; retrying inside the startup window"
                            );
                            next.insert(resource_id.clone());
                            first_error.get_or_insert(error);
                        }
                    }
                }
                pending = next;
                if pending.is_empty() {
                    return Ok(());
                }
            }
            Err(error) => {
                // Fail closed: without a fresh journal snapshot the last
                // lifecycle state cannot be proven, so this pass mutates
                // nothing (no TAP restoration, no domain start) and retries
                // inside the window.
                tracing::warn!(
                    error = %error,
                    "command journal could not be re-read before the restore pass; \
                     holding back the pass and retrying inside the startup window"
                );
                first_error.get_or_insert(error);
            }
        }
        if std::time::Instant::now() >= deadline {
            break;
        }
        tokio::time::sleep(retry).await;
    }
    if let Some(error) = first_error {
        tracing::warn!(
            pending = pending.len(),
            error = %error,
            "startup domain restoration did not converge within the startup window; \
             retried on the next agent restart"
        );
        Err(error)
    } else {
        Ok(())
    }
}

/// Startup residue cleanup for crash residue (issue #87 S3 rerun #5 and
/// issue #88 S3/S4 reruns): the stale-network reap removes the persisted
/// DHCP bindings and TAPs of instances whose domains provably do not exist,
/// and the owned-dnsmasq reap stops every owned dnsmasq left behind by a
/// previous agent process. The provisional-link reap removes `o3ktmp-*` TAPs
/// and `o3kbm-*` bridges left by a create that died before its ownership
/// record became durable (issues #602, #608); such links are self-identifying
/// residue — no manifest record or domain ever references a provisional name
/// — so deleting them needs no manifest proof and cannot touch a fenced
/// deterministic `o3ktap-`/`o3k-b*` interface.
/// Ordering invariant: the provisional-link reap runs first (it is independent
/// of instance state), then the stale-network reap MUST run (a crashed create
/// whose DHCP prep completed persists its binding, so the stale binding must
/// not survive to be re-served), then the owned-dnsmasq reap (at startup the
/// supervisor is always None, so every owned dnsmasq is a leftover regardless
/// of bindings), then live bindings get a fresh supervisor in
/// [`reconcile_dhcp_on_startup`]. Errors are logged and never fatal, so
/// residue is retried on the next restart; startup is never blocked by an
/// unreachable or unknown libvirt.
pub(crate) async fn reap_startup_residue(
    network: &o3k_network::HostNetworkManager,
    dhcp: &Arc<Mutex<DhcpRuntime>>,
    presence: &dyn DomainPresence,
) -> Result<(), AgentError> {
    let partial_error = network
        .reap_partial_links()
        .map_err(|error| AgentError::Protocol(format!("provisional link reap failed: {error}")))
        .err();
    let stale_error = reap_stale_instance_networks(network, dhcp, presence)
        .await
        .err();
    let reap_error = dhcp
        .lock()
        .map_err(|_| AgentError::Protocol("DHCP runtime lock is poisoned".to_owned()))
        .and_then(|runtime| runtime.reap_owned_dnsmasq())
        .err();
    match (partial_error, stale_error, reap_error) {
        (Some(error), _, _) | (None, Some(error), _) | (None, None, Some(error)) => Err(error),
        (None, None, None) => Ok(()),
    }
}
