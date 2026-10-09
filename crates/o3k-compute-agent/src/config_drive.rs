use thiserror::Error;

use o3k_provider_contract::compute_proto as proto;

use crate::{MAX_ARTIFACT_BYTES, deterministic_artifact_transfer_id};

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ConfigDriveMaterializationRequest {
    pub transfer_id: String,
    pub command_id: String,
    pub operation_id: String,
    pub resource_id: String,
    pub agent_id: String,
    pub artifact_id: String,
    pub sha256: String,
    pub format: String,
    pub size_bytes: u64,
    pub instance_id: String,
}

#[derive(Debug, Error)]
pub enum ConfigDriveMaterializationError {
    #[error("config-drive command identity is invalid")]
    Ownership,
}

/// Extracts the authenticated config-drive reference without performing host
/// I/O. Media generation and libvirt attachment remain separate boundaries.
pub fn config_drive_materialization_request(
    command: &proto::Command,
) -> Result<Option<ConfigDriveMaterializationRequest>, ConfigDriveMaterializationError> {
    config_drive_materialization_request_inner(command, true)
}

pub(crate) fn validate_config_drive_identity(
    command: &proto::Command,
) -> Result<(), ConfigDriveMaterializationError> {
    config_drive_materialization_request_inner(command, false).map(|_| ())
}

pub fn config_drive_requested(
    command: &proto::Command,
) -> Result<bool, ConfigDriveMaterializationError> {
    config_drive_materialization_request_inner(command, false).map(|request| request.is_some())
}

fn config_drive_materialization_request_inner(
    command: &proto::Command,
    enforce_deadline: bool,
) -> Result<Option<ConfigDriveMaterializationRequest>, ConfigDriveMaterializationError> {
    let Some(proto::command::Action::Create(create)) = command.action.as_ref() else {
        return Err(ConfigDriveMaterializationError::Ownership);
    };
    let Some(resolved) = create.resolved.as_ref() else {
        return Err(ConfigDriveMaterializationError::Ownership);
    };
    let fields_absent = resolved.config_drive_artifact_id.is_empty()
        && resolved.config_drive_sha256.is_empty()
        && resolved.config_drive_transfer.is_none();
    match resolved.config_drive_enabled {
        Some(false) if fields_absent => return Ok(None),
        Some(false) => return Err(ConfigDriveMaterializationError::Ownership),
        Some(true) => {}
        None if fields_absent => return Err(ConfigDriveMaterializationError::Ownership),
        None => {} // legacy commands must carry the complete old representation.
    }
    let Some(reference) = resolved.config_drive_transfer.as_ref() else {
        return Err(ConfigDriveMaterializationError::Ownership);
    };
    let expected_transfer = deterministic_artifact_transfer_id(
        &command.command_id,
        proto::ArtifactKind::ConfigDriveIso,
        &resolved.config_drive_artifact_id,
    );
    if reference.transfer_id != expected_transfer
        || (enforce_deadline && reference.expires_at_unix_ms <= crate::unix_ms())
        || reference.size_bytes > MAX_ARTIFACT_BYTES
        || !crate::valid_reference(&resolved.config_drive_artifact_id)
        || !crate::valid_sha256(&resolved.config_drive_sha256)
    {
        return Err(ConfigDriveMaterializationError::Ownership);
    }
    Ok(Some(ConfigDriveMaterializationRequest {
        transfer_id: reference.transfer_id.clone(),
        command_id: command.command_id.clone(),
        operation_id: command.operation_id.clone(),
        resource_id: command.resource_id.clone(),
        agent_id: command.agent_id.clone(),
        artifact_id: resolved.config_drive_artifact_id.clone(),
        sha256: resolved.config_drive_sha256.clone(),
        format: "iso".to_owned(),
        size_bytes: reference.size_bytes,
        instance_id: command.resource_id.clone(),
    }))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn request_requires_command_bound_iso_transfer() -> Result<(), ConfigDriveMaterializationError>
    {
        let command_id = "command-config";
        let artifact_id = "config-drive-1";
        let command = proto::Command {
            command_id: command_id.to_owned(),
            operation_id: "operation-1".to_owned(),
            agent_id: "agent-1".to_owned(),
            resource_id: "resource-1".to_owned(),
            action: Some(proto::command::Action::Create(proto::CreateCommand {
                resolved: Some(proto::ResolvedCreateInputs {
                    config_drive_artifact_id: artifact_id.to_owned(),
                    config_drive_sha256: "b".repeat(64),
                    config_drive_enabled: Some(true),
                    config_drive_transfer: Some(proto::ArtifactReference {
                        transfer_id: deterministic_artifact_transfer_id(
                            command_id,
                            proto::ArtifactKind::ConfigDriveIso,
                            artifact_id,
                        ),
                        expires_at_unix_ms: crate::unix_ms().saturating_add(10_000),
                        ..Default::default()
                    }),
                    ..Default::default()
                }),
                ..Default::default()
            })),
            ..Default::default()
        };
        let Some(request) = config_drive_materialization_request(&command)? else {
            return Err(ConfigDriveMaterializationError::Ownership);
        };
        assert_eq!(request.artifact_id, artifact_id);
        assert_eq!(request.format, "iso");
        Ok(())
    }

    #[test]
    fn explicitly_disabled_config_drive_has_no_materialization_request()
    -> Result<(), ConfigDriveMaterializationError> {
        let command = proto::Command {
            action: Some(proto::command::Action::Create(proto::CreateCommand {
                resolved: Some(proto::ResolvedCreateInputs {
                    config_drive_enabled: Some(false),
                    ..Default::default()
                }),
                ..Default::default()
            })),
            ..Default::default()
        };

        assert!(matches!(
            config_drive_materialization_request(&command),
            Ok(None)
        ));
        assert!(matches!(config_drive_requested(&command), Ok(false)));
        Ok(())
    }

    #[test]
    fn partial_config_drive_references_and_ambiguous_legacy_absence_fail_closed()
    -> Result<(), ConfigDriveMaterializationError> {
        let mut command = proto::Command {
            action: Some(proto::command::Action::Create(proto::CreateCommand {
                resolved: Some(proto::ResolvedCreateInputs {
                    config_drive_enabled: Some(false),
                    config_drive_artifact_id: "config-drive-1".to_owned(),
                    ..Default::default()
                }),
                ..Default::default()
            })),
            ..Default::default()
        };
        assert!(config_drive_materialization_request(&command).is_err());

        let resolved = match command.action.as_mut() {
            Some(proto::command::Action::Create(create)) => match create.resolved.as_mut() {
                Some(resolved) => resolved,
                None => return Err(ConfigDriveMaterializationError::Ownership),
            },
            _ => return Err(ConfigDriveMaterializationError::Ownership),
        };
        resolved.config_drive_enabled = None;
        assert!(config_drive_materialization_request(&command).is_err());
        Ok(())
    }

    #[test]
    fn requested_config_drive_rejects_every_incomplete_or_mismatched_reference()
    -> Result<(), ConfigDriveMaterializationError> {
        let command_id = "command-config";
        let artifact_id = "config-drive-1";
        let complete = || proto::Command {
            command_id: command_id.to_owned(),
            operation_id: "operation-1".to_owned(),
            agent_id: "agent-1".to_owned(),
            resource_id: "resource-1".to_owned(),
            action: Some(proto::command::Action::Create(proto::CreateCommand {
                resolved: Some(proto::ResolvedCreateInputs {
                    config_drive_enabled: Some(true),
                    config_drive_artifact_id: artifact_id.to_owned(),
                    config_drive_sha256: "b".repeat(64),
                    config_drive_transfer: Some(proto::ArtifactReference {
                        transfer_id: deterministic_artifact_transfer_id(
                            command_id,
                            proto::ArtifactKind::ConfigDriveIso,
                            artifact_id,
                        ),
                        expires_at_unix_ms: crate::unix_ms().saturating_add(10_000),
                        size_bytes: 1,
                    }),
                    ..Default::default()
                }),
                ..Default::default()
            })),
            ..Default::default()
        };

        let mut missing_digest = complete();
        create_resolved_mut(&mut missing_digest)?
            .config_drive_sha256
            .clear();
        assert!(config_drive_materialization_request(&missing_digest).is_err());

        let mut missing_transfer = complete();
        create_resolved_mut(&mut missing_transfer)?.config_drive_transfer = None;
        assert!(config_drive_materialization_request(&missing_transfer).is_err());

        let mut missing_identity = complete();
        create_resolved_mut(&mut missing_identity)?
            .config_drive_artifact_id
            .clear();
        assert!(config_drive_materialization_request(&missing_identity).is_err());

        let mut invalid_digest = complete();
        create_resolved_mut(&mut invalid_digest)?.config_drive_sha256 = "not-a-digest".to_owned();
        assert!(config_drive_materialization_request(&invalid_digest).is_err());

        let mut wrong_transfer = complete();
        let Some(reference) = create_resolved_mut(&mut wrong_transfer)?
            .config_drive_transfer
            .as_mut()
        else {
            return Err(ConfigDriveMaterializationError::Ownership);
        };
        reference.transfer_id = "transfer-from-another-command".to_owned();
        assert!(config_drive_materialization_request(&wrong_transfer).is_err());
        Ok(())
    }

    fn create_resolved_mut(
        command: &mut proto::Command,
    ) -> Result<&mut proto::ResolvedCreateInputs, ConfigDriveMaterializationError> {
        match command.action.as_mut() {
            Some(proto::command::Action::Create(create)) => create
                .resolved
                .as_mut()
                .ok_or(ConfigDriveMaterializationError::Ownership),
            _ => Err(ConfigDriveMaterializationError::Ownership),
        }
    }
}
