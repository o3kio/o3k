//! Canonical native persistent-storage resources.
//!
//! These types deliberately contain technology-independent intent and
//! lifecycle semantics. Provider-native paths, device names, libvirt target
//! names, RBD image/device names, and connection data belong to execution
//! observations, never to these resources.

use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use std::fmt;
use thiserror::Error;
use uuid::Uuid;

macro_rules! typed_id {
    ($name:ident) => {
        #[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
        #[serde(transparent)]
        pub struct $name(Uuid);

        impl $name {
            #[must_use]
            pub fn new() -> Self {
                Self(Uuid::now_v7())
            }

            #[must_use]
            pub const fn from_uuid(id: Uuid) -> Self {
                Self(id)
            }

            #[must_use]
            pub const fn as_uuid(self) -> Uuid {
                self.0
            }
        }

        impl Default for $name {
            fn default() -> Self {
                Self::new()
            }
        }

        impl From<Uuid> for $name {
            fn from(id: Uuid) -> Self {
                Self::from_uuid(id)
            }
        }

        impl From<$name> for Uuid {
            fn from(id: $name) -> Self {
                id.as_uuid()
            }
        }

        impl fmt::Display for $name {
            fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
                self.0.fmt(formatter)
            }
        }
    };
}

typed_id!(VolumeId);
typed_id!(VolumeAttachmentId);
typed_id!(SnapshotId);

/// Placement/execution scope. A host scope is used by local LVM; a backend
/// scope permits shared providers such as Ceph RBD without changing the
/// canonical resource model.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case", tag = "kind", content = "id")]
pub enum StorageExecutionScope {
    Host(String),
    Backend(String),
}

/// Mutations and observations permitted at the bounded storage execution
/// boundary. Provider-native device identity is deliberately absent.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum StorageAction {
    CreateVolume,
    InspectVolume,
    DeleteVolume,
    PrepareAttachment,
    TerminateAttachment,
    CreateSnapshot,
    DeleteSnapshot,
    Reconcile,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct StorageCommandEnvelope {
    pub protocol_version: u16,
    pub command_id: Uuid,
    pub operation_id: Uuid,
    pub idempotency_key: String,
    pub resource_id: String,
    pub resource_generation: u64,
    pub project_id: String,
    /// Controller fencing epoch. Storage agents must reject commands from a
    /// controller that no longer owns the durable work lease.
    pub controller_epoch: u64,
    pub target_agent_id: String,
    pub target_agent_epoch: u64,
    pub deadline: String,
    pub trace_id: String,
    pub action: StorageAction,
    pub canonical_payload_fingerprint: String,
}

/// Typed, provider-neutral command body persisted alongside the envelope.
/// Keeping this body durable makes replay independent of transient controller
/// objects while ensuring provider paths and credentials never cross the
/// canonical boundary.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "kind", content = "value", rename_all = "snake_case")]
pub enum StorageCommandPayload {
    Volume(StorageVolumeCommandPayload),
    Attachment(StorageAttachmentCommandPayload),
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct StorageVolumeCommandPayload {
    pub volume_id: VolumeId,
    pub project_id: String,
    pub size_bytes: u64,
    pub generation: u64,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct StorageAttachmentCommandPayload {
    pub attachment_id: VolumeAttachmentId,
    pub volume_id: VolumeId,
    pub server_id: Uuid,
    pub project_id: String,
    pub access_mode: AttachmentAccessMode,
    pub delete_on_termination: bool,
    pub volume_generation: u64,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct StorageCommandRecord {
    pub envelope: StorageCommandEnvelope,
    pub payload: StorageCommandPayload,
}

impl StorageCommandEnvelope {
    pub fn validate(&self) -> Result<(), StorageValidationError> {
        if self.protocol_version == 0
            || self.idempotency_key.is_empty()
            || self.resource_id.is_empty()
            || self.resource_generation == 0
            || self.project_id.is_empty()
            || self.controller_epoch == 0
            || self.target_agent_id.is_empty()
            || self.target_agent_epoch == 0
            || self.deadline.is_empty()
            || self.trace_id.is_empty()
            || self.canonical_payload_fingerprint.is_empty()
        {
            return Err(StorageValidationError::InvalidCommandEnvelope);
        }
        if self.idempotency_key.len() > 256
            || self.resource_id.len() > 256
            || self.project_id.len() > 256
            || self.target_agent_id.len() > 128
            || self.deadline.len() > 128
            || self.trace_id.len() > 256
            || self.canonical_payload_fingerprint.len() != 64
            || !self
                .canonical_payload_fingerprint
                .chars()
                .all(|character| character.is_ascii_hexdigit() && !character.is_ascii_uppercase())
        {
            return Err(StorageValidationError::InvalidCommandEnvelope);
        }
        Ok(())
    }
}

/// Compute the fingerprint used to bind a wire payload to its command
/// envelope.  Callers must pass the typed payload's serde representation;
/// keeping this helper in the domain crate prevents controller and executor
/// implementations from silently choosing different digest encodings.
pub fn storage_payload_fingerprint<T: Serialize>(payload: &T) -> Result<String, serde_json::Error> {
    let bytes = serde_json::to_vec(payload)?;
    Ok(Sha256::digest(bytes)
        .iter()
        .map(|byte| format!("{byte:02x}"))
        .collect())
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum StorageOperationState {
    Accepted,
    Running,
    Succeeded,
    Failed,
    UnknownOutcome,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct StorageObservation {
    pub agent_id: String,
    pub agent_epoch: u64,
    pub resource_id: String,
    pub provider_resource_id: Option<String>,
    pub operation_id: Uuid,
    pub resource_generation: u64,
    pub observation_sequence: u64,
    pub observed_at: String,
    pub operation_state: StorageOperationState,
    pub resource_state: String,
    pub error_category: Option<StorageErrorCategory>,
    pub redacted_message: Option<String>,
    #[serde(default)]
    pub device_path: Option<String>,
}

impl StorageObservation {
    pub fn validate(&self) -> Result<(), StorageValidationError> {
        if self.agent_id.is_empty()
            || self.agent_id.len() > 128
            || self.agent_epoch == 0
            || self.resource_id.is_empty()
            || self.resource_id.len() > 256
            || self.resource_generation == 0
            || self.observation_sequence == 0
            || self.observed_at.is_empty()
            || self.observed_at.len() > 128
            || self.resource_state.is_empty()
            || self.resource_state.len() > 64
        {
            return Err(StorageValidationError::InvalidObservation);
        }
        if self
            .provider_resource_id
            .as_ref()
            .is_some_and(|value| value.is_empty() || value.len() > 512)
            || self
                .redacted_message
                .as_ref()
                .is_some_and(|value| value.len() > 1024 || value.contains('\0'))
        {
            return Err(StorageValidationError::InvalidObservation);
        }
        Ok(())
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum StorageErrorCategory {
    InvalidRequest,
    AuthorizationBinding,
    UnsupportedCapability,
    Conflict,
    NotFound,
    CapacityExhausted,
    TransientUnavailable,
    Timeout,
    UnknownOutcome,
    TerminalProvider,
    OwnershipAmbiguity,
    Protocol,
}

impl StorageExecutionScope {
    pub fn validate(&self) -> Result<(), StorageValidationError> {
        let id = match self {
            Self::Host(id) | Self::Backend(id) => id,
        };
        if id.is_empty() || id.len() > 128 {
            return Err(StorageValidationError::InvalidScope);
        }
        Ok(())
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum VolumeState {
    Requested,
    Creating,
    Available,
    Attaching,
    InUse,
    Detaching,
    Deleting,
    Deleted,
    Unknown,
    Error,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum VolumeAttachmentState {
    Reserved,
    Preparing,
    Attaching,
    Attached,
    Detaching,
    Detached,
    Unknown,
    Error,
    Deleted,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum SnapshotState {
    Requested,
    Creating,
    Available,
    Deleting,
    Deleted,
    Unknown,
    Error,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum AttachmentAccessMode {
    ReadOnly,
    ReadWrite,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum SnapshotConsistency {
    CrashConsistent,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ProviderReference {
    pub provider: String,
    pub resource_id: String,
}

impl ProviderReference {
    pub fn validate(&self) -> Result<(), StorageValidationError> {
        if self.provider.is_empty()
            || self.provider.len() > 128
            || self.resource_id.is_empty()
            || self.resource_id.len() > 512
        {
            return Err(StorageValidationError::InvalidProviderReference);
        }
        Ok(())
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct StorageCapabilities {
    pub create_volume: bool,
    pub snapshots: bool,
    pub attachment: bool,
    pub capacity_bytes: u64,
    pub allocated_bytes: u64,
    pub allocation_unit_bytes: u64,
}

impl StorageCapabilities {
    pub fn validate(&self) -> Result<(), StorageValidationError> {
        if self.allocation_unit_bytes == 0 || self.allocated_bytes > self.capacity_bytes {
            return Err(StorageValidationError::InvalidCapacity);
        }
        Ok(())
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct StorageBackend {
    pub id: String,
    pub scope: StorageExecutionScope,
    pub capabilities: StorageCapabilities,
    pub generation: u64,
    pub available: bool,
}

impl StorageBackend {
    pub fn validate(&self) -> Result<(), StorageValidationError> {
        if self.id.is_empty() || self.id.len() > 128 {
            return Err(StorageValidationError::InvalidBackendId);
        }
        self.scope.validate()?;
        self.capabilities.validate()?;
        if self.generation == 0 {
            return Err(StorageValidationError::InvalidGeneration);
        }
        Ok(())
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Volume {
    pub id: VolumeId,
    pub project_id: String,
    #[serde(default)]
    pub name: String,
    #[serde(default)]
    pub description: String,
    #[serde(default)]
    pub metadata: std::collections::BTreeMap<String, String>,
    #[serde(default)]
    pub availability_zone: Option<String>,
    pub size_bytes: u64,
    pub volume_type: String,
    pub backend_id: String,
    pub execution_scope: StorageExecutionScope,
    pub state: VolumeState,
    pub generation: u64,
    pub operation_id: Option<Uuid>,
    pub provider_reference: Option<ProviderReference>,
}

impl Volume {
    pub fn validate(&self) -> Result<(), StorageValidationError> {
        if self.project_id.is_empty() || self.project_id.len() > 256 {
            return Err(StorageValidationError::InvalidProject);
        }
        if self.size_bytes == 0
            || self.volume_type.is_empty()
            || self.volume_type.len() > 128
            || self.name.len() > 255
            || self.description.len() > 4096
            || self.metadata.len() > 128
            || self
                .availability_zone
                .as_ref()
                .is_some_and(|zone| zone.is_empty() || zone.len() > 255)
        {
            return Err(StorageValidationError::InvalidVolume);
        }
        if self.backend_id.is_empty() || self.backend_id.len() > 128 {
            return Err(StorageValidationError::InvalidBackendId);
        }
        self.execution_scope.validate()?;
        if self.generation == 0 {
            return Err(StorageValidationError::InvalidGeneration);
        }
        if let Some(reference) = &self.provider_reference {
            reference.validate()?;
        }
        Ok(())
    }

    pub fn transition(self, to: Self) -> Result<Self, StorageTransitionError> {
        let from_state = self.state;
        let to_state = to.state;
        let valid = matches!(
            (from_state, to_state),
            (
                VolumeState::Requested,
                VolumeState::Creating | VolumeState::Error
            ) | (
                VolumeState::Creating,
                VolumeState::Available
                    | VolumeState::Unknown
                    | VolumeState::Error
                    | VolumeState::Deleting
            ) | (
                VolumeState::Available,
                VolumeState::Attaching | VolumeState::Deleting | VolumeState::Error
            ) | (
                VolumeState::Attaching,
                VolumeState::InUse
                    | VolumeState::Unknown
                    | VolumeState::Error
                    | VolumeState::Deleting
            ) | (
                VolumeState::InUse,
                VolumeState::Detaching | VolumeState::Deleting | VolumeState::Error
            ) | (
                VolumeState::Detaching,
                VolumeState::Available
                    | VolumeState::Unknown
                    | VolumeState::Error
                    | VolumeState::Deleting
            ) | (
                VolumeState::Unknown,
                VolumeState::Creating
                    | VolumeState::Available
                    | VolumeState::Attaching
                    | VolumeState::InUse
                    | VolumeState::Deleting
                    | VolumeState::Error
            ) | (VolumeState::Error, VolumeState::Deleting)
                | (
                    VolumeState::Deleting,
                    VolumeState::Deleted | VolumeState::Unknown | VolumeState::Error
                )
        );
        valid
            .then_some(to)
            .ok_or(StorageTransitionError::InvalidVolume {
                from: from_state,
                to: to_state,
            })
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct VolumeAttachment {
    pub id: VolumeAttachmentId,
    pub project_id: String,
    pub volume_id: VolumeId,
    pub server_id: Uuid,
    pub execution_scope: StorageExecutionScope,
    pub access_mode: AttachmentAccessMode,
    pub delete_on_termination: bool,
    pub state: VolumeAttachmentState,
    pub generation: u64,
    pub operation_id: Option<Uuid>,
}

impl VolumeAttachment {
    pub fn validate(&self) -> Result<(), StorageValidationError> {
        if self.project_id.is_empty() || self.project_id.len() > 256 {
            return Err(StorageValidationError::InvalidProject);
        }
        self.execution_scope.validate()?;
        if self.generation == 0 {
            return Err(StorageValidationError::InvalidGeneration);
        }
        Ok(())
    }

    pub fn transition(self, to: Self) -> Result<Self, StorageTransitionError> {
        let from = self.state;
        let target = to.state;
        let valid = matches!(
            (from, target),
            (
                VolumeAttachmentState::Reserved,
                VolumeAttachmentState::Preparing | VolumeAttachmentState::Deleted
            ) | (
                VolumeAttachmentState::Preparing,
                VolumeAttachmentState::Attaching
                    | VolumeAttachmentState::Unknown
                    | VolumeAttachmentState::Error
                    | VolumeAttachmentState::Detaching
            ) | (
                VolumeAttachmentState::Attaching,
                VolumeAttachmentState::Attached
                    | VolumeAttachmentState::Unknown
                    | VolumeAttachmentState::Error
                    | VolumeAttachmentState::Detaching
            ) | (
                VolumeAttachmentState::Attached,
                VolumeAttachmentState::Detaching | VolumeAttachmentState::Error
            ) | (
                VolumeAttachmentState::Detaching,
                VolumeAttachmentState::Detached
                    | VolumeAttachmentState::Unknown
                    | VolumeAttachmentState::Error
                    | VolumeAttachmentState::Deleted
            ) | (
                VolumeAttachmentState::Detached,
                VolumeAttachmentState::Deleted
            ) | (
                VolumeAttachmentState::Unknown,
                VolumeAttachmentState::Preparing
                    | VolumeAttachmentState::Attaching
                    | VolumeAttachmentState::Attached
                    | VolumeAttachmentState::Detaching
                    | VolumeAttachmentState::Detached
                    | VolumeAttachmentState::Deleted
                    | VolumeAttachmentState::Error
            ) | (
                VolumeAttachmentState::Error,
                VolumeAttachmentState::Detaching | VolumeAttachmentState::Deleted
            )
        );
        valid
            .then_some(to)
            .ok_or(StorageTransitionError::InvalidAttachment { from, to: target })
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Snapshot {
    pub id: SnapshotId,
    pub project_id: String,
    pub volume_id: VolumeId,
    pub source_generation: u64,
    pub execution_scope: StorageExecutionScope,
    pub consistency: SnapshotConsistency,
    pub state: SnapshotState,
    pub generation: u64,
    pub operation_id: Option<Uuid>,
    pub provider_reference: Option<ProviderReference>,
}

impl Snapshot {
    pub fn validate(&self) -> Result<(), StorageValidationError> {
        if self.project_id.is_empty() || self.project_id.len() > 256 {
            return Err(StorageValidationError::InvalidProject);
        }
        self.execution_scope.validate()?;
        if self.source_generation == 0 || self.generation == 0 {
            return Err(StorageValidationError::InvalidGeneration);
        }
        if let Some(reference) = &self.provider_reference {
            reference.validate()?;
        }
        Ok(())
    }

    pub fn transition(self, to: Self) -> Result<Self, StorageTransitionError> {
        let from = self.state;
        let target = to.state;
        let valid = matches!(
            (from, target),
            (
                SnapshotState::Requested,
                SnapshotState::Creating | SnapshotState::Deleting | SnapshotState::Error
            ) | (
                SnapshotState::Creating,
                SnapshotState::Available
                    | SnapshotState::Unknown
                    | SnapshotState::Deleting
                    | SnapshotState::Error
            ) | (
                SnapshotState::Available,
                SnapshotState::Deleting | SnapshotState::Error
            ) | (
                SnapshotState::Deleting,
                SnapshotState::Deleted | SnapshotState::Unknown | SnapshotState::Error
            ) | (
                SnapshotState::Unknown,
                SnapshotState::Creating
                    | SnapshotState::Available
                    | SnapshotState::Deleting
                    | SnapshotState::Error
            ) | (SnapshotState::Error, SnapshotState::Deleting)
        );
        valid
            .then_some(to)
            .ok_or(StorageTransitionError::InvalidSnapshot { from, to: target })
    }
}

#[derive(Debug, Error, PartialEq, Eq)]
pub enum StorageValidationError {
    #[error("invalid storage command envelope")]
    InvalidCommandEnvelope,
    #[error("invalid storage observation")]
    InvalidObservation,
    #[error("project identity is invalid")]
    InvalidProject,
    #[error("volume fields are invalid")]
    InvalidVolume,
    #[error("backend identity is invalid")]
    InvalidBackendId,
    #[error("storage scope is invalid")]
    InvalidScope,
    #[error("provider reference is invalid")]
    InvalidProviderReference,
    #[error("capacity or allocation unit is invalid")]
    InvalidCapacity,
    #[error("resource generation must be positive")]
    InvalidGeneration,
}

#[derive(Debug, Error, PartialEq, Eq)]
pub enum StorageTransitionError {
    #[error("invalid volume transition from {from:?} to {to:?}")]
    InvalidVolume { from: VolumeState, to: VolumeState },
    #[error("invalid volume attachment transition from {from:?} to {to:?}")]
    InvalidAttachment {
        from: VolumeAttachmentState,
        to: VolumeAttachmentState,
    },
    #[error("invalid snapshot transition from {from:?} to {to:?}")]
    InvalidSnapshot {
        from: SnapshotState,
        to: SnapshotState,
    },
}

#[cfg(test)]
#[allow(clippy::expect_used)]
mod tests {
    use super::*;

    fn volume(state: VolumeState) -> Volume {
        Volume {
            id: VolumeId::from_uuid(Uuid::from_u128(1)),
            project_id: "project-a".to_owned(),
            name: "volume-a".to_owned(),
            description: String::new(),
            metadata: std::collections::BTreeMap::new(),
            availability_zone: None,
            size_bytes: 4096,
            volume_type: "lvm-thin".to_owned(),
            backend_id: "backend-a".to_owned(),
            execution_scope: StorageExecutionScope::Host("host-a".to_owned()),
            state,
            generation: 1,
            operation_id: None,
            provider_reference: None,
        }
    }

    #[test]
    fn attachment_has_no_provider_device_identity() {
        let attachment = VolumeAttachment {
            id: VolumeAttachmentId::from_uuid(Uuid::from_u128(2)),
            project_id: "project-a".to_owned(),
            volume_id: VolumeId::from_uuid(Uuid::from_u128(1)),
            server_id: Uuid::from_u128(3),
            execution_scope: StorageExecutionScope::Host("host-a".to_owned()),
            access_mode: AttachmentAccessMode::ReadWrite,
            delete_on_termination: false,
            state: VolumeAttachmentState::Reserved,
            generation: 1,
            operation_id: None,
        };
        let encoded = serde_json::to_string(&attachment).expect("domain serialization");
        assert!(!encoded.contains("/dev/"));
        assert!(!encoded.contains("target"));
        assert!(attachment.validate().is_ok());
    }

    #[test]
    fn volume_lifecycle_requires_observation_for_unknown_outcomes() {
        assert!(
            volume(VolumeState::Requested)
                .transition(volume(VolumeState::Available))
                .is_err()
        );
        assert!(
            volume(VolumeState::Creating)
                .transition(volume(VolumeState::Unknown))
                .is_ok()
        );
        assert!(
            volume(VolumeState::Unknown)
                .transition(volume(VolumeState::Available))
                .is_ok()
        );
    }

    #[test]
    fn shared_backend_scope_is_valid_without_local_device_fields() {
        let snapshot = Snapshot {
            id: SnapshotId::from_uuid(Uuid::from_u128(4)),
            project_id: "project-a".to_owned(),
            volume_id: VolumeId::from_uuid(Uuid::from_u128(1)),
            source_generation: 1,
            execution_scope: StorageExecutionScope::Backend("ceph-region-a".to_owned()),
            consistency: SnapshotConsistency::CrashConsistent,
            state: SnapshotState::Requested,
            generation: 1,
            operation_id: None,
            provider_reference: None,
        };
        assert!(snapshot.validate().is_ok());
    }

    #[test]
    fn attachment_and_snapshot_transitions_are_validated() {
        let attachment = VolumeAttachment {
            id: VolumeAttachmentId::from_uuid(Uuid::from_u128(5)),
            project_id: "project-a".to_owned(),
            volume_id: VolumeId::from_uuid(Uuid::from_u128(1)),
            server_id: Uuid::from_u128(6),
            execution_scope: StorageExecutionScope::Host("host-a".to_owned()),
            access_mode: AttachmentAccessMode::ReadWrite,
            delete_on_termination: false,
            state: VolumeAttachmentState::Reserved,
            generation: 1,
            operation_id: None,
        };
        let mut attached = attachment.clone();
        attached.state = VolumeAttachmentState::Preparing;
        assert!(attachment.transition(attached).is_ok());

        let snapshot = Snapshot {
            id: SnapshotId::from_uuid(Uuid::from_u128(7)),
            project_id: "project-a".to_owned(),
            volume_id: VolumeId::from_uuid(Uuid::from_u128(1)),
            source_generation: 1,
            execution_scope: StorageExecutionScope::Host("host-a".to_owned()),
            consistency: SnapshotConsistency::CrashConsistent,
            state: SnapshotState::Available,
            generation: 1,
            operation_id: None,
            provider_reference: None,
        };
        let mut deleted = snapshot.clone();
        deleted.state = SnapshotState::Deleted;
        assert!(snapshot.transition(deleted).is_err());
    }

    #[test]
    fn command_and_observation_validation_is_bounded() {
        let command = StorageCommandEnvelope {
            protocol_version: 1,
            command_id: Uuid::from_u128(8),
            operation_id: Uuid::from_u128(9),
            idempotency_key: "operation-1".to_owned(),
            resource_id: "volume-1".to_owned(),
            resource_generation: 1,
            project_id: "project-a".to_owned(),
            controller_epoch: 1,
            target_agent_id: "storage-a".to_owned(),
            target_agent_epoch: 1,
            deadline: "2026-08-19T00:00:00Z".to_owned(),
            trace_id: "trace-1".to_owned(),
            action: StorageAction::InspectVolume,
            canonical_payload_fingerprint: "a".repeat(64),
        };
        assert!(command.validate().is_ok());

        let observation = StorageObservation {
            agent_id: "storage-a".to_owned(),
            agent_epoch: 1,
            resource_id: "volume-1".to_owned(),
            provider_resource_id: None,
            operation_id: Uuid::from_u128(9),
            resource_generation: 1,
            observation_sequence: 1,
            observed_at: "2026-08-19T00:00:00Z".to_owned(),
            operation_state: StorageOperationState::Succeeded,
            resource_state: "available".to_owned(),
            error_category: None,
            redacted_message: None,
            device_path: None,
        };
        assert!(observation.validate().is_ok());
    }
}
