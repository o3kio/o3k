//! Durable native-volume execution boundary.
//!
//! This workflow owns replay identity and fencing; provider implementations
//! only receive the persisted, context-bound command envelope.
use async_trait::async_trait;
use o3k_domain::{StorageAction, StorageCommandPayload, StorageCommandRecord, VolumeId};
use o3k_storage::{StorageExecutionContext, StorageProvider, StorageProviderError, StorageVolumeRequest};
use o3k_store::{AgentCommandRecord, AgentCommandState, DurableStore, OperationRecord, OperationState, StoreError};
use std::sync::Arc;
use thiserror::Error;
use crate::storage_volume_workflow::StorageVolumeIntent;
use crate::storage_workflow::StorageControllerFence;

#[derive(Debug, Error)]
pub enum NativeVolumeWorkflowError {
    #[error("invalid volume intent")]
    Invalid,
    #[error("store error")]
    Store(#[from] StoreError),
    #[error("stale controller fence")]
    StaleFence,
    #[error("idempotency conflict")]
    IdempotencyConflict,
    #[error("provider error")]
    Provider(#[from] StorageProviderError),
}

pub struct NativeVolumeWorkflow<S, P: ?Sized, F> {
    store: Arc<S>,
    provider: Arc<P>,
    fence: Arc<F>,
}

impl<S, P, F> NativeVolumeWorkflow<S, P, F>
where
    S: DurableStore + Send + Sync + 'static,
    P: StorageProvider + ?Sized + 'static,
    F: StorageControllerFence + 'static,
{
    pub fn new(store: Arc<S>, provider: Arc<P>, fence: Arc<F>) -> Self { Self { store, provider, fence } }

    pub async fn create(&self, intent: StorageVolumeIntent) -> Result<(), NativeVolumeWorkflowError> {
        self.execute(intent, StorageAction::CreateVolume).await
    }

    pub async fn delete(&self, intent: StorageVolumeIntent) -> Result<(), NativeVolumeWorkflowError> {
        self.execute(intent, StorageAction::DeleteVolume).await
    }

    async fn execute(&self, intent: StorageVolumeIntent, action: StorageAction) -> Result<(), NativeVolumeWorkflowError> {
        intent.validate().map_err(|_| NativeVolumeWorkflowError::Invalid)?;
        self.fence.assert_current(intent.controller_epoch).await.map_err(|_| NativeVolumeWorkflowError::StaleFence)?;
        let envelope = intent.envelope(action).map_err(|_| NativeVolumeWorkflowError::Invalid)?;
        let fingerprint = envelope.canonical_payload_fingerprint.clone();
        if let Ok(existing) = self.store.get_agent_command_by_idempotency_key(&intent.idempotency_key).await {
            if existing.payload_fingerprint_sha256 != fingerprint || existing.command_id != envelope.command_id.to_string() {
                return Err(NativeVolumeWorkflowError::IdempotencyConflict);
            }
            if matches!(existing.state, AgentCommandState::Succeeded) { return Ok(()); }
        }
        let operation_id = envelope.operation_id;
        self.store.insert_operation(&OperationRecord { id: operation_id, resource_id: intent.volume_id.as_uuid(), kind: "storage:volume".into(), state: OperationState::Pending, provider_operation_id: None, error_category: None, error_message: None }).await?;
        let payload = serde_json::to_vec(&StorageCommandRecord { envelope: envelope.clone(), payload: intent.payload() }).map_err(|_| NativeVolumeWorkflowError::Invalid)?;
        let command_id = envelope.command_id.to_string();
        let _ = self.store.insert_agent_command(&AgentCommandRecord { command_id: command_id.clone(), idempotency_key: intent.idempotency_key.clone(), operation_id, resource_id: intent.volume_id.as_uuid(), agent_id: intent.target_agent_id.clone(), agent_epoch: intent.target_agent_epoch.to_string(), payload_fingerprint_sha256: fingerprint, payload, state: AgentCommandState::Pending, accepted_sequence: 0, last_sequence: 0, provider_operation_id: None, provider_resource_id: None }).await?;
        let request = StorageVolumeRequest { volume_id: intent.volume_id, project_id: intent.project_id, size_bytes: intent.size_bytes, generation: intent.generation };
        let context = StorageExecutionContext { envelope };
        let result = match action {
            StorageAction::CreateVolume => self.provider.create_volume_with_context(&request, &context).await.map(|_| ()),
            StorageAction::DeleteVolume => self.provider.delete_volume_with_context(&request, &context).await,
            _ => return Err(NativeVolumeWorkflowError::Invalid),
        };
        match result {
            Ok(()) => { let _ = self.store.update_agent_command(&command_id, AgentCommandState::Succeeded, 0, 0, None, None).await?; let _ = self.store.update_operation(operation_id, OperationState::Succeeded, None, None, None).await?; Ok(()) }
            Err(e) if e.is_unknown_outcome() => { let _ = self.store.update_agent_command(&command_id, AgentCommandState::UnknownOutcome, 0, 0, None, None).await?; let _ = self.store.update_operation(operation_id, OperationState::Running, None, Some("unknown_outcome"), Some("observe before retry")).await?; Err(e.into()) }
            Err(e) => { let _ = self.store.update_agent_command(&command_id, AgentCommandState::Failed, 0, 0, None, None).await?; let _ = self.store.update_operation(operation_id, OperationState::Failed, None, Some("provider"), Some("storage operation failed")).await?; Err(e.into()) }
        }
    }
}
