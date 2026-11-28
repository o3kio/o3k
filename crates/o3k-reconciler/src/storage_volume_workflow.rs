//! Durable command identity for native Volume execution.
//!
//! This module deliberately keeps provider-native paths out of the durable
//! command.  The route/composition layer supplies the already-owned fence and
//! target identity; execution is performed only through the context-bound
//! `StorageProvider` methods.

use o3k_domain::{
    StorageAction, StorageCommandEnvelope, StorageCommandPayload, StorageVolumeCommandPayload,
    VolumeId,
};
use o3k_storage::storage_payload_fingerprint;
use serde::Serialize;
use thiserror::Error;
use uuid::Uuid;

#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct StorageVolumeIntent {
    pub volume_id: VolumeId,
    pub project_id: String,
    pub size_bytes: u64,
    pub generation: u64,
    pub controller_epoch: u64,
    pub target_agent_id: String,
    pub target_agent_epoch: u64,
    pub idempotency_key: String,
    pub trace_id: String,
    pub deadline: String,
}

#[derive(Debug, Error, Clone, Copy, PartialEq, Eq)]
pub enum StorageVolumeIntentError {
    #[error("invalid native volume intent")]
    Invalid,
}

impl StorageVolumeIntent {
    pub fn validate(&self) -> Result<(), StorageVolumeIntentError> {
        if self.project_id.is_empty()
            || self.project_id.len() > 256
            || self.size_bytes == 0
            || self.generation == 0
            || self.controller_epoch == 0
            || self.target_agent_id.is_empty()
            || self.target_agent_id.len() > 128
            || self.target_agent_epoch == 0
            || self.idempotency_key.is_empty()
            || self.idempotency_key.len() > 256
            || self.trace_id.is_empty()
            || self.trace_id.len() > 256
            || self.deadline.is_empty()
            || self.deadline.len() > 128
        {
            return Err(StorageVolumeIntentError::Invalid);
        }
        Ok(())
    }

    pub fn payload(&self) -> StorageCommandPayload {
        StorageCommandPayload::Volume(StorageVolumeCommandPayload {
            volume_id: self.volume_id,
            project_id: self.project_id.clone(),
            size_bytes: self.size_bytes,
            generation: self.generation,
        })
    }

    pub fn deterministic_id(&self, kind: &str, action: StorageAction) -> Uuid {
        let action = format!("{action:?}");
        let mut bytes = Vec::with_capacity(kind.len() + action.len() + self.idempotency_key.len() + 32);
        bytes.extend_from_slice(kind.as_bytes());
        bytes.push(0);
        bytes.extend_from_slice(action.as_bytes());
        bytes.push(0);
        bytes.extend_from_slice(self.volume_id.to_string().as_bytes());
        bytes.push(0);
        bytes.extend_from_slice(self.generation.to_string().as_bytes());
        bytes.push(0);
        bytes.extend_from_slice(self.idempotency_key.as_bytes());
        Uuid::new_v5(&Uuid::NAMESPACE_OID, &bytes)
    }

    pub fn envelope(
        &self,
        action: StorageAction,
    ) -> Result<StorageCommandEnvelope, StorageVolumeIntentError> {
        self.validate()?;
        let payload = self.payload();
        let fingerprint =
            storage_payload_fingerprint(&payload).map_err(|_| StorageVolumeIntentError::Invalid)?;
        Ok(StorageCommandEnvelope {
            protocol_version: 1,
            command_id: self.deterministic_id("command", action),
            operation_id: self.deterministic_id("operation", action),
            idempotency_key: self.idempotency_key.clone(),
            resource_id: self.volume_id.to_string(),
            resource_generation: self.generation,
            project_id: self.project_id.clone(),
            controller_epoch: self.controller_epoch,
            // The provider boundary fills the live WorkLease fence.
            fencing_token: 0,
            target_agent_id: self.target_agent_id.clone(),
            target_agent_epoch: self.target_agent_epoch.to_string(),
            deadline: self.deadline.clone(),
            trace_id: self.trace_id.clone(),
            action,
            canonical_payload_fingerprint: fingerprint,
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn intent() -> StorageVolumeIntent {
        StorageVolumeIntent {
            volume_id: VolumeId::from_uuid(Uuid::from_u128(7)),
            project_id: "p".into(),
            size_bytes: 4096,
            generation: 2,
            controller_epoch: 3,
            target_agent_id: "agent".into(),
            target_agent_epoch: 4,
            idempotency_key: "volume-create-7".into(),
            trace_id: "trace".into(),
            deadline: "2099-01-01T00:00:00Z".into(),
        }
    }

    #[test]
    fn envelope_is_deterministic_and_payload_bound() -> Result<(), StorageVolumeIntentError> {
        let a = intent().envelope(StorageAction::CreateVolume)?;
        let b = intent().envelope(StorageAction::CreateVolume)?;
        assert_eq!(a, b);
        assert!(a.validate().is_ok());
        assert_eq!(a.resource_id, intent().volume_id.to_string());
        Ok(())
    }
}
