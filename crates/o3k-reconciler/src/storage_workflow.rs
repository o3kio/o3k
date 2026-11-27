//! Durable native VolumeAttachment coordination.
//!
//! The workflow persists an operation and an authenticated storage command
//! before crossing either execution boundary. The command row is the replay
//! identity: an equivalent retry returns the durable outcome, while a
//! conflicting fingerprint, controller epoch, agent epoch, or generation is
//! rejected. Provider-native device identity remains inside the execution
//! call and is never copied into the canonical attachment.

use async_trait::async_trait;
use o3k_domain::{
    AttachmentAccessMode, StorageAction, StorageAttachmentCommandPayload, StorageCommandEnvelope,
    StorageCommandPayload, StorageCommandRecord, VolumeAttachment, VolumeAttachmentId,
    VolumeAttachmentState, VolumeId, VolumeState, storage_payload_fingerprint,
};
use o3k_storage::{
    PreparedAttachment, StorageAttachmentRequest, StorageProvider, StorageProviderError,
};
use o3k_store::{
    AgentCommandRecord, AgentCommandState, DurableStore, OperationRecord, OperationState,
    StorageRepository, StoreError, VolumeAttachmentRecordV1,
};
use serde::Serialize;
use std::sync::Arc;
use thiserror::Error;
use uuid::Uuid;

#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct StorageAttachmentIntent {
    pub attachment_id: VolumeAttachmentId,
    pub volume_id: VolumeId,
    pub server_id: Uuid,
    pub project_id: String,
    pub access_mode: AttachmentAccessMode,
    pub delete_on_termination: bool,
    pub controller_epoch: u64,
    pub target_agent_id: String,
    pub target_agent_epoch: u64,
    pub idempotency_key: String,
    pub trace_id: String,
    pub deadline: String,
}

impl StorageAttachmentIntent {
    fn validate(&self) -> Result<(), StorageWorkflowError> {
        if self.project_id.is_empty()
            || self.project_id.len() > 256
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
            return Err(StorageWorkflowError::InvalidIntent);
        }
        Ok(())
    }

    fn fingerprint(&self) -> Result<String, StorageWorkflowError> {
        storage_payload_fingerprint(self).map_err(|_| StorageWorkflowError::InvalidIntent)
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct StorageWorkflowResult {
    pub command_id: String,
    pub operation_id: Uuid,
    pub command_state: AgentCommandState,
    pub attachment_state: VolumeAttachmentState,
}

#[derive(Debug, Error)]
pub enum StorageWorkflowError {
    #[error("durable storage workflow store error")]
    Store(#[from] StoreError),
    #[error("storage attachment intent is invalid")]
    InvalidIntent,
    #[error("storage attachment idempotency identity conflicts with durable state")]
    IdempotencyConflict,
    #[error("storage attachment controller fence is stale")]
    StaleControllerFence,
    #[error("storage attachment agent fence is stale")]
    StaleAgentFence,
    #[error("storage attachment generation is stale")]
    StaleGeneration,
    #[error("storage attachment outcome is unknown and requires observation")]
    UnknownOutcome,
    #[error("storage provider rejected attachment")]
    Provider(StorageProviderError),
    #[error("compute attachment outcome is unknown and requires observation")]
    ComputeUnknownOutcome,
    #[error("compute attachment operation failed")]
    ComputeFailed,
}

#[derive(Debug, Error, Clone, Copy, PartialEq, Eq)]
pub enum ComputeAttachmentError {
    #[error("compute attachment outcome is unknown")]
    UnknownOutcome,
    #[error("compute attachment failed")]
    Failed,
}

#[async_trait]
pub trait ComputeAttachmentExecutor: Send + Sync {
    async fn attach(
        &self,
        attachment: &VolumeAttachment,
        prepared: &PreparedAttachment,
    ) -> Result<(), ComputeAttachmentError>;

    async fn inspect(&self, attachment: &VolumeAttachment) -> Result<bool, ComputeAttachmentError>;

    async fn detach(&self, attachment: &VolumeAttachment) -> Result<(), ComputeAttachmentError>;
}

#[async_trait]
pub trait StorageControllerFence: Send + Sync {
    /// Start one execution attempt. Recovery takeover must call this once and
    /// retain the returned implementation's durable fencing identity for the
    /// whole operation; it must not reacquire ownership from an old attempt.
    async fn begin(&self, controller_epoch: u64) -> Result<(), StorageWorkflowError> {
        self.assert_current(controller_epoch).await
    }

    async fn assert_current(&self, controller_epoch: u64) -> Result<(), StorageWorkflowError>;

    /// End the current execution attempt. Implementations release the exact
    /// fencing token they acquired, never an arbitrary current lease.
    async fn end(&self, _controller_epoch: u64) -> Result<(), StorageWorkflowError> {
        Ok(())
    }
}

pub struct StorageAttachmentWorkflow<S, P, C, F> {
    store: Arc<S>,
    provider: Arc<P>,
    compute: Arc<C>,
    fence: Arc<F>,
}

impl<S, P, C, F> StorageAttachmentWorkflow<S, P, C, F>
where
    S: DurableStore + StorageRepository + Send + Sync + 'static,
    P: StorageProvider + 'static,
    C: ComputeAttachmentExecutor + 'static,
    F: StorageControllerFence + 'static,
{
    pub fn new(store: Arc<S>, provider: Arc<P>, compute: Arc<C>, fence: Arc<F>) -> Self {
        Self {
            store,
            provider,
            compute,
            fence,
        }
    }

    /// Persist and execute an attach intent. The first provider/compute side
    /// effect occurs only after both the operation and the replayable command
    /// have been durably recorded.
    pub async fn attach(
        &self,
        intent: StorageAttachmentIntent,
    ) -> Result<StorageWorkflowResult, StorageWorkflowError> {
        self.fence.begin(intent.controller_epoch).await?;
        let controller_epoch = intent.controller_epoch;
        let result = self.attach_inner(intent).await;
        let end = self.fence.end(controller_epoch).await;
        match (result, end) {
            (Err(error), _) => Err(error),
            (Ok(_value), Err(error)) => Err(error),
            (Ok(value), Ok(())) => Ok(value),
        }
    }

    async fn attach_inner(
        &self,
        intent: StorageAttachmentIntent,
    ) -> Result<StorageWorkflowResult, StorageWorkflowError> {
        intent.validate()?;
        self.fence.assert_current(intent.controller_epoch).await?;
        let fingerprint = intent.fingerprint()?;
        match self
            .store
            .get_agent_command_by_idempotency_key(&intent.idempotency_key)
            .await
        {
            Ok(existing) => return self.replay_existing(&existing, &fingerprint).await,
            Err(StoreError::OperationNotFound) => {}
            Err(error) => return Err(StorageWorkflowError::Store(error)),
        }

        let record = self
            .store
            .get_volume_attachment_v1(intent.attachment_id.as_uuid())
            .await?
            .ok_or(StoreError::ResourceNotFound)?;
        let volume = self
            .store
            .get_volume(record.attachment.volume_id.as_uuid())
            .await?
            .ok_or(StoreError::ResourceNotFound)?;
        if record.attachment.project_id != intent.project_id
            || record.attachment.volume_id != intent.volume_id
            || record.attachment.server_id != intent.server_id
            || record.attachment.access_mode != intent.access_mode
            || record.attachment.delete_on_termination != intent.delete_on_termination
            || volume.volume.project_id != intent.project_id
            || volume.volume.state != VolumeState::Available
            || record.attachment.state != VolumeAttachmentState::Reserved
        {
            return Err(StorageWorkflowError::InvalidIntent);
        }
        let volume = self
            .store
            .get_volume(record.attachment.volume_id.as_uuid())
            .await?
            .ok_or(StoreError::ResourceNotFound)?;

        let operation_id = deterministic_storage_id("operation", &intent.idempotency_key);
        let command_id = deterministic_storage_id("command", &intent.idempotency_key);
        let envelope = self.envelope(
            &intent,
            command_id,
            operation_id,
            record.attachment.generation,
            fingerprint.clone(),
            StorageAction::PrepareAttachment,
        )?;
        let payload = serde_json::to_vec(&StorageCommandRecord {
            envelope: envelope.clone(),
            payload: StorageCommandPayload::Attachment(attachment_payload(
                &intent,
                volume.volume.generation,
            )),
        })
        .map_err(|_| StorageWorkflowError::InvalidIntent)?;
        self.store
            .insert_operation(&OperationRecord {
                id: operation_id,
                resource_id: intent.attachment_id.as_uuid(),
                kind: "storage:attach".to_owned(),
                state: OperationState::Pending,
                provider_operation_id: None,
                error_category: None,
                error_message: None,
            })
            .await?;
        let command = self
            .store
            .insert_agent_command(&AgentCommandRecord {
                command_id: command_id.to_string(),
                idempotency_key: intent.idempotency_key.clone(),
                operation_id,
                resource_id: intent.attachment_id.as_uuid(),
                agent_id: intent.target_agent_id.clone(),
                agent_epoch: intent.target_agent_epoch.to_string(),
                payload_fingerprint_sha256: fingerprint,
                payload,
                state: AgentCommandState::Pending,
                accepted_sequence: 0,
                last_sequence: 0,
                provider_operation_id: None,
                provider_resource_id: None,
            })
            .await?;

        let preparing = transition_attachment(&record, VolumeAttachmentState::Preparing)?;
        let record = self
            .store
            .update_volume_attachment_v1(record.attachment.generation, &preparing)
            .await?;
        let controller_epoch = intent.controller_epoch;
        self.execute_attach(
            intent,
            command,
            record,
            volume.volume.generation,
            controller_epoch,
        )
        .await
    }

    /// Persist and execute the detach half of the same durable attachment
    /// workflow. Compute detachment happens before the storage-side terminal
    /// observation, so a timeout never permits a blind retry.
    pub async fn detach(
        &self,
        intent: StorageAttachmentIntent,
    ) -> Result<StorageWorkflowResult, StorageWorkflowError> {
        self.fence.begin(intent.controller_epoch).await?;
        let controller_epoch = intent.controller_epoch;
        let result = self.detach_inner(intent).await;
        let end = self.fence.end(controller_epoch).await;
        match (result, end) {
            (Err(error), _) => Err(error),
            (Ok(_value), Err(error)) => Err(error),
            (Ok(value), Ok(())) => Ok(value),
        }
    }

    async fn detach_inner(
        &self,
        intent: StorageAttachmentIntent,
    ) -> Result<StorageWorkflowResult, StorageWorkflowError> {
        intent.validate()?;
        self.fence.assert_current(intent.controller_epoch).await?;
        let fingerprint = intent.fingerprint()?;
        match self
            .store
            .get_agent_command_by_idempotency_key(&intent.idempotency_key)
            .await
        {
            Ok(existing) => return self.replay_existing(&existing, &fingerprint).await,
            Err(StoreError::OperationNotFound) => {}
            Err(error) => return Err(StorageWorkflowError::Store(error)),
        }
        let record = self
            .store
            .get_volume_attachment_v1(intent.attachment_id.as_uuid())
            .await?
            .ok_or(StoreError::ResourceNotFound)?;
        if record.attachment.project_id != intent.project_id
            || record.attachment.volume_id != intent.volume_id
            || record.attachment.server_id != intent.server_id
            || record.attachment.access_mode != intent.access_mode
            || record.attachment.delete_on_termination != intent.delete_on_termination
            || record.attachment.state != VolumeAttachmentState::Attached
        {
            return Err(StorageWorkflowError::InvalidIntent);
        }
        let volume = self
            .store
            .get_volume(record.attachment.volume_id.as_uuid())
            .await?
            .ok_or(StoreError::ResourceNotFound)?;
        let operation_id = deterministic_storage_id("operation", &intent.idempotency_key);
        let command_id = deterministic_storage_id("command", &intent.idempotency_key);
        let envelope = self.envelope(
            &intent,
            command_id,
            operation_id,
            record.attachment.generation,
            fingerprint.clone(),
            StorageAction::TerminateAttachment,
        )?;
        let payload = serde_json::to_vec(&StorageCommandRecord {
            envelope: envelope.clone(),
            payload: StorageCommandPayload::Attachment(attachment_payload(
                &intent,
                volume.volume.generation,
            )),
        })
        .map_err(|_| StorageWorkflowError::InvalidIntent)?;
        self.store
            .insert_operation(&OperationRecord {
                id: operation_id,
                resource_id: intent.attachment_id.as_uuid(),
                kind: "storage:detach".to_owned(),
                state: OperationState::Pending,
                provider_operation_id: None,
                error_category: None,
                error_message: None,
            })
            .await?;
        let command = self
            .store
            .insert_agent_command(&AgentCommandRecord {
                command_id: command_id.to_string(),
                idempotency_key: intent.idempotency_key,
                operation_id,
                resource_id: intent.attachment_id.as_uuid(),
                agent_id: intent.target_agent_id,
                agent_epoch: intent.target_agent_epoch.to_string(),
                payload_fingerprint_sha256: fingerprint,
                payload,
                state: AgentCommandState::Pending,
                accepted_sequence: 0,
                last_sequence: 0,
                provider_operation_id: None,
                provider_resource_id: None,
            })
            .await?;
        let detaching = transition_attachment(&record, VolumeAttachmentState::Detaching)?;
        let record = self
            .store
            .update_volume_attachment_v1(record.attachment.generation, &detaching)
            .await?;
        self.execute_detach(command, record, envelope, intent.controller_epoch)
            .await
    }

    /// Reconcile a running/unknown command after a controller or process
    /// restart. The supplied epoch is the current durable controller owner;
    /// the epoch in the immutable envelope remains request provenance.
    pub async fn reconcile(
        &self,
        command_id: &str,
        controller_epoch: u64,
    ) -> Result<StorageWorkflowResult, StorageWorkflowError> {
        self.fence.begin(controller_epoch).await?;
        let result = self.reconcile_inner(command_id, controller_epoch).await;
        let end = self.fence.end(controller_epoch).await;
        match (result, end) {
            (Err(error), _) => Err(error),
            (Ok(_value), Err(error)) => Err(error),
            (Ok(value), Ok(())) => Ok(value),
        }
    }

    async fn reconcile_inner(
        &self,
        command_id: &str,
        controller_epoch: u64,
    ) -> Result<StorageWorkflowResult, StorageWorkflowError> {
        if controller_epoch == 0 {
            return Err(StorageWorkflowError::StaleControllerFence);
        }
        self.fence.assert_current(controller_epoch).await?;
        let command = self.store.get_agent_command(command_id).await?;
        let envelope = decode_command_envelope(&command.payload)?;
        envelope
            .validate()
            .map_err(|_| StorageWorkflowError::InvalidIntent)?;
        if command.agent_epoch != envelope.target_agent_epoch.to_string() {
            return Err(StorageWorkflowError::StaleAgentFence);
        }
        let record = self
            .store
            .get_volume_attachment_v1(
                envelope
                    .resource_id
                    .parse::<Uuid>()
                    .map_err(|_| StorageWorkflowError::InvalidIntent)?,
            )
            .await?
            .ok_or(StoreError::ResourceNotFound)?;
        if matches!(
            command.state,
            AgentCommandState::Succeeded | AgentCommandState::Failed
        ) {
            return Ok(StorageWorkflowResult {
                command_id: command.command_id,
                operation_id: command.operation_id,
                command_state: command.state,
                attachment_state: record.attachment.state,
            });
        }
        if envelope.action == StorageAction::TerminateAttachment {
            return self
                .reconcile_detach(command, record, controller_epoch)
                .await;
        }
        let volume = self
            .store
            .get_volume(record.attachment.volume_id.as_uuid())
            .await?
            .ok_or(StoreError::ResourceNotFound)?;
        let request = attachment_request(&record.attachment, volume.volume.generation, &envelope);
        let storage_observation = self.provider.inspect_attachment(&request).await;
        let compute_observation = self.compute.inspect(&record.attachment).await;
        match (storage_observation, compute_observation) {
            (Err(error), _) if error.is_unknown_outcome() => {
                self.fence.assert_current(controller_epoch).await?;
                self.mark_unknown(&command, &record).await?;
                Err(StorageWorkflowError::UnknownOutcome)
            }
            (_, Err(ComputeAttachmentError::UnknownOutcome)) => {
                self.fence.assert_current(controller_epoch).await?;
                self.mark_unknown(&command, &record).await?;
                Err(StorageWorkflowError::ComputeUnknownOutcome)
            }
            (Err(error), _) => Err(StorageWorkflowError::Provider(error)),
            (_, Err(ComputeAttachmentError::Failed)) => Err(StorageWorkflowError::ComputeFailed),
            (Ok(_), Ok(true)) => self.finish_success(command, record, controller_epoch).await,
            (Ok(observation), Ok(false)) if !observation.attached => {
                let preparing = if record.attachment.state == VolumeAttachmentState::Unknown {
                    transition_attachment(&record, VolumeAttachmentState::Preparing)?
                } else {
                    record.clone()
                };
                let record = if preparing.attachment.generation != record.attachment.generation {
                    self.store
                        .update_volume_attachment_v1(record.attachment.generation, &preparing)
                        .await?
                } else {
                    preparing
                };
                let command = self
                    .store
                    .update_agent_command(
                        &command.command_id,
                        AgentCommandState::Retryable,
                        command.accepted_sequence.max(1),
                        command.last_sequence.saturating_add(1).max(3),
                        None,
                        None,
                    )
                    .await?;
                self.execute_attach_from_command(
                    command,
                    record,
                    volume.volume.generation,
                    controller_epoch,
                )
                .await
            }
            (Ok(_), Ok(false)) => Err(StorageWorkflowError::UnknownOutcome),
        }
    }

    async fn execute_attach(
        &self,
        intent: StorageAttachmentIntent,
        command: AgentCommandRecord,
        record: VolumeAttachmentRecordV1,
        volume_generation: u64,
        controller_epoch: u64,
    ) -> Result<StorageWorkflowResult, StorageWorkflowError> {
        let envelope = decode_command_envelope(&command.payload)?;
        self.execute_attach_from_command_with_intent(
            intent,
            envelope,
            command,
            record,
            volume_generation,
            controller_epoch,
        )
        .await
    }

    async fn reconcile_detach(
        &self,
        command: AgentCommandRecord,
        record: VolumeAttachmentRecordV1,
        controller_epoch: u64,
    ) -> Result<StorageWorkflowResult, StorageWorkflowError> {
        let envelope = decode_command_envelope(&command.payload)?;
        let volume = self
            .store
            .get_volume(record.attachment.volume_id.as_uuid())
            .await?
            .ok_or(StoreError::ResourceNotFound)?;
        let request = attachment_request(&record.attachment, volume.volume.generation, &envelope);
        let storage = self.provider.inspect_attachment(&request).await;
        let compute = self.compute.inspect(&record.attachment).await;
        match (storage, compute) {
            (Err(error), _) if error.is_unknown_outcome() => {
                self.fence.assert_current(controller_epoch).await?;
                self.mark_unknown(&command, &record).await?;
                Err(StorageWorkflowError::UnknownOutcome)
            }
            (_, Err(ComputeAttachmentError::UnknownOutcome)) => {
                self.fence.assert_current(controller_epoch).await?;
                self.mark_unknown(&command, &record).await?;
                Err(StorageWorkflowError::ComputeUnknownOutcome)
            }
            (Err(error), _) => Err(StorageWorkflowError::Provider(error)),
            (_, Err(ComputeAttachmentError::Failed)) => Err(StorageWorkflowError::ComputeFailed),
            (Ok(observation), Ok(false)) if !observation.attached => {
                self.finish_detached(command, record, controller_epoch)
                    .await
            }
            (Ok(_), Ok(true)) | (Ok(_), Ok(false)) => {
                let detaching = if record.attachment.state == VolumeAttachmentState::Unknown {
                    transition_attachment(&record, VolumeAttachmentState::Detaching)?
                } else {
                    record
                };
                self.execute_detach(command, detaching, envelope, controller_epoch)
                    .await
            }
        }
    }

    async fn execute_detach(
        &self,
        command: AgentCommandRecord,
        record: VolumeAttachmentRecordV1,
        envelope: StorageCommandEnvelope,
        controller_epoch: u64,
    ) -> Result<StorageWorkflowResult, StorageWorkflowError> {
        self.fence.assert_current(controller_epoch).await?;
        let command = self
            .store
            .update_agent_command(
                &command.command_id,
                AgentCommandState::Running,
                1,
                command.last_sequence.saturating_add(1).max(1),
                None,
                None,
            )
            .await?;
        match self.compute.detach(&record.attachment).await {
            Err(ComputeAttachmentError::UnknownOutcome) => {
                self.fence.assert_current(controller_epoch).await?;
                self.mark_unknown(&command, &record).await?;
                return Err(StorageWorkflowError::ComputeUnknownOutcome);
            }
            Err(ComputeAttachmentError::Failed) => {
                self.fence.assert_current(controller_epoch).await?;
                self.mark_failed(&command, &record).await?;
                return Err(StorageWorkflowError::ComputeFailed);
            }
            Ok(()) => {}
        }
        // A takeover may happen while the compute boundary is in flight.
        // Re-check ownership before crossing into the storage mutation so a
        // superseded controller cannot continue the old attempt.
        self.fence.assert_current(controller_epoch).await?;
        let volume = self
            .store
            .get_volume(record.attachment.volume_id.as_uuid())
            .await?
            .ok_or(StoreError::ResourceNotFound)?;
        let request = attachment_request(&record.attachment, volume.volume.generation, &envelope);
        match self.provider.terminate_attachment(&request).await {
            Err(error) if error.is_unknown_outcome() => {
                self.fence.assert_current(controller_epoch).await?;
                self.mark_unknown(&command, &record).await?;
                Err(StorageWorkflowError::UnknownOutcome)
            }
            Err(error) => {
                self.fence.assert_current(controller_epoch).await?;
                self.mark_failed(&command, &record).await?;
                Err(StorageWorkflowError::Provider(error))
            }
            Ok(observation) if observation.attached => {
                self.fence.assert_current(controller_epoch).await?;
                self.mark_unknown(&command, &record).await?;
                Err(StorageWorkflowError::UnknownOutcome)
            }
            Ok(_) => {
                self.finish_detached(command, record, controller_epoch)
                    .await
            }
        }
    }

    async fn execute_attach_from_command(
        &self,
        command: AgentCommandRecord,
        record: VolumeAttachmentRecordV1,
        volume_generation: u64,
        controller_epoch: u64,
    ) -> Result<StorageWorkflowResult, StorageWorkflowError> {
        let envelope = decode_command_envelope(&command.payload)?;
        let intent = intent_from_attachment(&envelope, &record.attachment);
        self.execute_attach_from_command_with_intent(
            intent,
            envelope,
            command,
            record,
            volume_generation,
            controller_epoch,
        )
        .await
    }

    async fn execute_attach_from_command_with_intent(
        &self,
        _intent: StorageAttachmentIntent,
        envelope: StorageCommandEnvelope,
        command: AgentCommandRecord,
        record: VolumeAttachmentRecordV1,
        volume_generation: u64,
        controller_epoch: u64,
    ) -> Result<StorageWorkflowResult, StorageWorkflowError> {
        self.fence.assert_current(controller_epoch).await?;
        let command = self
            .store
            .update_agent_command(
                &command.command_id,
                AgentCommandState::Running,
                1,
                command.last_sequence.saturating_add(1).max(1),
                None,
                None,
            )
            .await?;
        let request = attachment_request(&record.attachment, volume_generation, &envelope);
        let prepared = match self.provider.prepare_attachment(&request).await {
            Ok(value) => value,
            Err(error) if error.is_unknown_outcome() => {
                self.fence.assert_current(controller_epoch).await?;
                self.mark_unknown(&command, &record).await?;
                return Err(StorageWorkflowError::UnknownOutcome);
            }
            Err(error) => {
                self.fence.assert_current(controller_epoch).await?;
                self.mark_failed(&command, &record).await?;
                return Err(StorageWorkflowError::Provider(error));
            }
        };
        // Preparing a device can cross an external boundary.  Do not allow a
        // worker that lost its durable lease during that call to proceed with
        // the compute-side mutation or canonical finalization.
        self.fence.assert_current(controller_epoch).await?;
        let attaching = transition_attachment(&record, VolumeAttachmentState::Attaching)?;
        let record = self
            .store
            .update_volume_attachment_v1(record.attachment.generation, &attaching)
            .await?;
        match self.compute.attach(&record.attachment, &prepared).await {
            Ok(()) => self.finish_success(command, record, controller_epoch).await,
            Err(ComputeAttachmentError::UnknownOutcome) => {
                self.fence.assert_current(controller_epoch).await?;
                self.mark_unknown(&command, &record).await?;
                Err(StorageWorkflowError::ComputeUnknownOutcome)
            }
            Err(ComputeAttachmentError::Failed) => {
                self.fence.assert_current(controller_epoch).await?;
                self.mark_failed(&command, &record).await?;
                Err(StorageWorkflowError::ComputeFailed)
            }
        }
    }

    async fn finish_success(
        &self,
        command: AgentCommandRecord,
        record: VolumeAttachmentRecordV1,
        controller_epoch: u64,
    ) -> Result<StorageWorkflowResult, StorageWorkflowError> {
        self.fence.assert_current(controller_epoch).await?;
        let record = if record.attachment.state == VolumeAttachmentState::Attached {
            record
        } else {
            let attached = transition_attachment(&record, VolumeAttachmentState::Attached)?;
            self.store
                .update_volume_attachment_v1(record.attachment.generation, &attached)
                .await?
        };
        self.project_volume_state(&record, VolumeState::InUse)
            .await?;
        let command = self
            .store
            .update_agent_command(
                &command.command_id,
                AgentCommandState::Succeeded,
                command.accepted_sequence.max(1),
                command.last_sequence.saturating_add(1).max(2),
                None,
                None,
            )
            .await?;
        self.store
            .update_operation(
                command.operation_id,
                OperationState::Succeeded,
                None,
                None,
                None,
            )
            .await?;
        Ok(StorageWorkflowResult {
            command_id: command.command_id,
            operation_id: command.operation_id,
            command_state: command.state,
            attachment_state: record.attachment.state,
        })
    }

    async fn finish_detached(
        &self,
        command: AgentCommandRecord,
        record: VolumeAttachmentRecordV1,
        controller_epoch: u64,
    ) -> Result<StorageWorkflowResult, StorageWorkflowError> {
        self.fence.assert_current(controller_epoch).await?;
        let record = if matches!(
            record.attachment.state,
            VolumeAttachmentState::Detached | VolumeAttachmentState::Deleted
        ) {
            record
        } else {
            let detached = transition_attachment(&record, VolumeAttachmentState::Detached)?;
            self.store
                .update_volume_attachment_v1(record.attachment.generation, &detached)
                .await?
        };
        self.project_volume_state(&record, VolumeState::Available)
            .await?;
        let record = if record.attachment.state == VolumeAttachmentState::Deleted {
            record
        } else {
            let mut deleted = record.clone();
            deleted.attachment.state = VolumeAttachmentState::Deleted;
            deleted.attachment.generation = deleted
                .attachment
                .generation
                .checked_add(1)
                .ok_or(StorageWorkflowError::StaleGeneration)?;
            self.store
                .update_volume_attachment_v1(record.attachment.generation, &deleted)
                .await?
        };
        let command = self
            .store
            .update_agent_command(
                &command.command_id,
                AgentCommandState::Succeeded,
                command.accepted_sequence.max(1),
                command.last_sequence.saturating_add(1).max(2),
                None,
                None,
            )
            .await?;
        self.store
            .update_operation(
                command.operation_id,
                OperationState::Succeeded,
                None,
                None,
                None,
            )
            .await?;
        Ok(StorageWorkflowResult {
            command_id: command.command_id,
            operation_id: command.operation_id,
            command_state: command.state,
            attachment_state: record.attachment.state,
        })
    }

    async fn project_volume_state(
        &self,
        record: &VolumeAttachmentRecordV1,
        target: VolumeState,
    ) -> Result<(), StorageWorkflowError> {
        let Some(mut volume) = self
            .store
            .get_volume(record.attachment.volume_id.as_uuid())
            .await?
        else {
            return Err(StoreError::ResourceNotFound.into());
        };
        if volume.volume.state == target {
            return Ok(());
        }
        volume.volume.state = target;
        volume.volume.generation = volume
            .volume
            .generation
            .checked_add(1)
            .ok_or(StorageWorkflowError::StaleGeneration)?;
        self.store
            .update_volume(volume.volume.generation - 1, &volume)
            .await?;
        Ok(())
    }

    async fn mark_unknown(
        &self,
        command: &AgentCommandRecord,
        record: &VolumeAttachmentRecordV1,
    ) -> Result<(), StorageWorkflowError> {
        let unknown = match record.attachment.state {
            VolumeAttachmentState::Preparing | VolumeAttachmentState::Attaching => {
                transition_attachment(record, VolumeAttachmentState::Unknown)?
            }
            _ => record.clone(),
        };
        if unknown.attachment.generation != record.attachment.generation {
            self.store
                .update_volume_attachment_v1(record.attachment.generation, &unknown)
                .await?;
        }
        self.store
            .update_agent_command(
                &command.command_id,
                AgentCommandState::UnknownOutcome,
                command.accepted_sequence.max(1),
                command.last_sequence.saturating_add(1).max(2),
                None,
                None,
            )
            .await?;
        self.store
            .update_operation(
                command.operation_id,
                OperationState::UnknownOutcome,
                None,
                Some("unknown_outcome"),
                Some("storage attachment requires observation"),
            )
            .await?;
        Ok(())
    }

    async fn mark_failed(
        &self,
        command: &AgentCommandRecord,
        record: &VolumeAttachmentRecordV1,
    ) -> Result<(), StorageWorkflowError> {
        let mut attachment = record.attachment.clone();
        attachment.state = VolumeAttachmentState::Error;
        attachment.generation = attachment.generation.saturating_add(1);
        let failed = VolumeAttachmentRecordV1 {
            attachment,
            created_at: record.created_at.clone(),
        };
        self.store
            .update_volume_attachment_v1(record.attachment.generation, &failed)
            .await?;
        self.store
            .update_agent_command(
                &command.command_id,
                AgentCommandState::Failed,
                command.accepted_sequence.max(1),
                command.last_sequence.saturating_add(1).max(2),
                None,
                None,
            )
            .await?;
        self.store
            .update_operation(
                command.operation_id,
                OperationState::Failed,
                None,
                Some("provider_failure"),
                Some("storage attachment failed"),
            )
            .await?;
        Ok(())
    }

    async fn replay_existing(
        &self,
        command: &AgentCommandRecord,
        expected_fingerprint: &str,
    ) -> Result<StorageWorkflowResult, StorageWorkflowError> {
        if command.payload_fingerprint_sha256 != expected_fingerprint {
            return Err(StorageWorkflowError::IdempotencyConflict);
        }
        let attachment = self
            .store
            .get_volume_attachment_v1(command.resource_id)
            .await?
            .ok_or(StoreError::ResourceNotFound)?;
        Ok(StorageWorkflowResult {
            command_id: command.command_id.clone(),
            operation_id: command.operation_id,
            command_state: command.state,
            attachment_state: attachment.attachment.state,
        })
    }

    fn envelope(
        &self,
        intent: &StorageAttachmentIntent,
        command_id: Uuid,
        operation_id: Uuid,
        generation: u64,
        fingerprint: String,
        action: StorageAction,
    ) -> Result<StorageCommandEnvelope, StorageWorkflowError> {
        let envelope = StorageCommandEnvelope {
            protocol_version: 1,
            command_id,
            operation_id,
            idempotency_key: intent.idempotency_key.clone(),
            resource_id: intent.attachment_id.to_string(),
            resource_generation: generation,
            project_id: intent.project_id.clone(),
            controller_epoch: intent.controller_epoch,
            target_agent_id: intent.target_agent_id.clone(),
            target_agent_epoch: intent.target_agent_epoch,
            deadline: intent.deadline.clone(),
            trace_id: intent.trace_id.clone(),
            action,
            canonical_payload_fingerprint: fingerprint,
        };
        envelope
            .validate()
            .map_err(|_| StorageWorkflowError::InvalidIntent)?;
        Ok(envelope)
    }
}

fn transition_attachment(
    record: &VolumeAttachmentRecordV1,
    state: VolumeAttachmentState,
) -> Result<VolumeAttachmentRecordV1, StorageWorkflowError> {
    let mut next = record.attachment.clone();
    next.state = state;
    next.generation = record
        .attachment
        .generation
        .checked_add(1)
        .ok_or(StorageWorkflowError::StaleGeneration)?;
    let transitioned = record
        .attachment
        .clone()
        .transition(next)
        .map_err(|_| StorageWorkflowError::InvalidIntent)?;
    Ok(VolumeAttachmentRecordV1 {
        attachment: transitioned,
        created_at: record.created_at.clone(),
    })
}

fn attachment_request(
    attachment: &VolumeAttachment,
    volume_generation: u64,
    envelope: &StorageCommandEnvelope,
) -> StorageAttachmentRequest {
    StorageAttachmentRequest {
        attachment_id: attachment.id,
        volume_id: attachment.volume_id,
        project_id: attachment.project_id.clone(),
        volume_generation,
        host_id: envelope.target_agent_id.clone(),
        access_mode: attachment.access_mode,
    }
}

fn intent_from_attachment(
    envelope: &StorageCommandEnvelope,
    attachment: &VolumeAttachment,
) -> StorageAttachmentIntent {
    StorageAttachmentIntent {
        attachment_id: attachment.id,
        volume_id: attachment.volume_id,
        server_id: attachment.server_id,
        project_id: envelope.project_id.clone(),
        access_mode: attachment.access_mode,
        delete_on_termination: attachment.delete_on_termination,
        controller_epoch: envelope.controller_epoch,
        target_agent_id: envelope.target_agent_id.clone(),
        target_agent_epoch: envelope.target_agent_epoch,
        idempotency_key: envelope.idempotency_key.clone(),
        trace_id: envelope.trace_id.clone(),
        deadline: envelope.deadline.clone(),
    }
}

fn deterministic_storage_id(kind: &str, idempotency_key: &str) -> Uuid {
    let name = format!("o3k-storage:{kind}:{idempotency_key}");
    Uuid::new_v5(&Uuid::NAMESPACE_URL, name.as_bytes())
}

fn decode_command_envelope(bytes: &[u8]) -> Result<StorageCommandEnvelope, StorageWorkflowError> {
    if let Ok(record) = serde_json::from_slice::<StorageCommandRecord>(bytes) {
        return Ok(record.envelope);
    }
    // Read-only compatibility for commands written before typed payloads were
    // introduced. New mutations always use StorageCommandRecord.
    serde_json::from_slice::<StorageCommandEnvelope>(bytes)
        .map_err(|_| StorageWorkflowError::InvalidIntent)
}

fn attachment_payload(
    intent: &StorageAttachmentIntent,
    volume_generation: u64,
) -> StorageAttachmentCommandPayload {
    StorageAttachmentCommandPayload {
        attachment_id: intent.attachment_id,
        volume_id: intent.volume_id,
        server_id: intent.server_id,
        project_id: intent.project_id.clone(),
        access_mode: intent.access_mode,
        delete_on_termination: intent.delete_on_termination,
        volume_generation,
    }
}

#[cfg(test)]
#[allow(clippy::expect_used, clippy::unwrap_used)]
mod tests {
    use super::*;
    use async_trait::async_trait;
    use o3k_domain::{
        AttachmentAccessMode, StorageCapabilities, StorageExecutionScope, Volume, VolumeState,
    };
    use o3k_storage::{
        StorageAttachmentObservation, StorageProviderError, StorageSnapshotObservation,
        StorageSnapshotRequest, StorageVolumeObservation,
    };
    use o3k_store::{O3kStore, ResourceRecord, VolumeRecord};
    use std::sync::{
        Arc,
        atomic::{AtomicBool, AtomicUsize, Ordering},
    };

    struct FakeStorage {
        prepare_unknown: AtomicBool,
        prepare_calls: AtomicUsize,
    }

    #[async_trait]
    impl StorageProvider for FakeStorage {
        async fn capabilities(&self) -> Result<StorageCapabilities, StorageProviderError> {
            Ok(StorageCapabilities {
                create_volume: true,
                snapshots: true,
                attachment: true,
                capacity_bytes: 1_000_000,
                allocated_bytes: 0,
                allocation_unit_bytes: 4096,
            })
        }

        async fn create_volume(
            &self,
            _request: &o3k_storage::StorageVolumeRequest,
        ) -> Result<StorageVolumeObservation, StorageProviderError> {
            unreachable!()
        }

        async fn inspect_volume(
            &self,
            _request: &o3k_storage::StorageVolumeRequest,
        ) -> Result<StorageVolumeObservation, StorageProviderError> {
            unreachable!()
        }

        async fn delete_volume(
            &self,
            _request: &o3k_storage::StorageVolumeRequest,
        ) -> Result<(), StorageProviderError> {
            unreachable!()
        }

        async fn prepare_attachment(
            &self,
            request: &StorageAttachmentRequest,
        ) -> Result<PreparedAttachment, StorageProviderError> {
            self.prepare_calls.fetch_add(1, Ordering::SeqCst);
            if self.prepare_unknown.swap(false, Ordering::SeqCst) {
                return Err(StorageProviderError::UnknownOutcome);
            }
            PreparedAttachment::from_provider(
                o3k_domain::StorageProviderReference {
                    provider: "fake".to_owned(),
                    resource_id: "owned-fake-volume".to_owned(),
                },
                "/dev/fake".to_owned(),
                request.attachment_id,
                request.volume_id,
            )
        }

        async fn inspect_attachment(
            &self,
            request: &StorageAttachmentRequest,
        ) -> Result<StorageAttachmentObservation, StorageProviderError> {
            Ok(StorageAttachmentObservation {
                attachment_id: request.attachment_id,
                volume_id: request.volume_id,
                host_id: request.host_id.clone(),
                attached: false,
                provider_reference: o3k_domain::StorageProviderReference {
                    provider: "fake".to_owned(),
                    resource_id: "owned-fake-volume".to_owned(),
                },
            })
        }

        async fn terminate_attachment(
            &self,
            request: &StorageAttachmentRequest,
        ) -> Result<StorageAttachmentObservation, StorageProviderError> {
            self.inspect_attachment(request).await
        }

        async fn create_snapshot(
            &self,
            _request: &StorageSnapshotRequest,
        ) -> Result<StorageSnapshotObservation, StorageProviderError> {
            unreachable!()
        }

        async fn delete_snapshot(
            &self,
            _request: &StorageSnapshotRequest,
        ) -> Result<(), StorageProviderError> {
            unreachable!()
        }
    }

    struct FakeCompute {
        attach_calls: AtomicUsize,
        attached: AtomicBool,
    }

    struct AcceptFence;

    #[async_trait]
    impl StorageControllerFence for AcceptFence {
        async fn assert_current(&self, controller_epoch: u64) -> Result<(), StorageWorkflowError> {
            (controller_epoch > 0)
                .then_some(())
                .ok_or(StorageWorkflowError::StaleControllerFence)
        }
    }

    struct EpochFence(u64);

    #[async_trait]
    impl StorageControllerFence for EpochFence {
        async fn assert_current(&self, controller_epoch: u64) -> Result<(), StorageWorkflowError> {
            (controller_epoch == self.0)
                .then_some(())
                .ok_or(StorageWorkflowError::StaleControllerFence)
        }
    }

    #[async_trait]
    impl ComputeAttachmentExecutor for FakeCompute {
        async fn attach(
            &self,
            _attachment: &VolumeAttachment,
            _prepared: &PreparedAttachment,
        ) -> Result<(), ComputeAttachmentError> {
            self.attach_calls.fetch_add(1, Ordering::SeqCst);
            self.attached.store(true, Ordering::SeqCst);
            Ok(())
        }

        async fn inspect(
            &self,
            _attachment: &VolumeAttachment,
        ) -> Result<bool, ComputeAttachmentError> {
            Ok(self.attached.load(Ordering::SeqCst))
        }

        async fn detach(
            &self,
            _attachment: &VolumeAttachment,
        ) -> Result<(), ComputeAttachmentError> {
            self.attached.store(false, Ordering::SeqCst);
            Ok(())
        }
    }

    fn intent(attachment: &VolumeAttachment) -> StorageAttachmentIntent {
        StorageAttachmentIntent {
            attachment_id: attachment.id,
            volume_id: attachment.volume_id,
            server_id: attachment.server_id,
            project_id: attachment.project_id.clone(),
            access_mode: attachment.access_mode,
            delete_on_termination: attachment.delete_on_termination,
            controller_epoch: 7,
            target_agent_id: "host-a".to_owned(),
            target_agent_epoch: 3,
            idempotency_key: "attach-once".to_owned(),
            trace_id: "trace-attach".to_owned(),
            deadline: "2026-08-19T00:00:00Z".to_owned(),
        }
    }

    async fn fixture(
        prepare_unknown: bool,
    ) -> (
        Arc<O3kStore>,
        Arc<FakeStorage>,
        Arc<FakeCompute>,
        VolumeAttachment,
    ) {
        let store = Arc::new(O3kStore::connect_sqlite_memory().await.unwrap());
        let volume = Volume {
            id: VolumeId::from_uuid(Uuid::from_u128(10)),
            project_id: "project-a".to_owned(),
            name: "volume-a".to_owned(),
            description: String::new(),
            metadata: std::collections::BTreeMap::new(),
            availability_zone: None,
            size_bytes: 4096,
            volume_type: "lvm-thin".to_owned(),
            backend_id: "backend-a".to_owned(),
            execution_scope: StorageExecutionScope::Host("host-a".to_owned()),
            state: VolumeState::Available,
            generation: 1,
            operation_id: None,
            provider_reference: None,
        };
        store
            .insert_volume(&VolumeRecord {
                volume,
                created_at: "now".to_owned(),
            })
            .await
            .unwrap();
        let attachment = VolumeAttachment {
            id: VolumeAttachmentId::from_uuid(Uuid::from_u128(11)),
            project_id: "project-a".to_owned(),
            volume_id: VolumeId::from_uuid(Uuid::from_u128(10)),
            server_id: Uuid::from_u128(12),
            execution_scope: StorageExecutionScope::Host("host-a".to_owned()),
            access_mode: AttachmentAccessMode::ReadWrite,
            delete_on_termination: false,
            state: VolumeAttachmentState::Reserved,
            generation: 1,
            operation_id: None,
        };
        store
            .insert_resource(&ResourceRecord {
                id: attachment.id.as_uuid(),
                kind: "native_volume_attachment".to_owned(),
                project_id: attachment.project_id.clone(),
                generation: 1,
                observed_generation: 1,
                desired_state: "attached".to_owned(),
                observed_state: "reserved".to_owned(),
                provider_id: None,
            })
            .await
            .unwrap();
        store
            .insert_volume_attachment_v1(&VolumeAttachmentRecordV1 {
                attachment: attachment.clone(),
                created_at: "now".to_owned(),
            })
            .await
            .unwrap();
        (
            store,
            Arc::new(FakeStorage {
                prepare_unknown: AtomicBool::new(prepare_unknown),
                prepare_calls: AtomicUsize::new(0),
            }),
            Arc::new(FakeCompute {
                attach_calls: AtomicUsize::new(0),
                attached: AtomicBool::new(false),
            }),
            attachment,
        )
    }

    #[tokio::test]
    async fn attach_persists_before_side_effect_and_replays_equivalent_request() {
        let (store, provider, compute, attachment) = fixture(false).await;
        let workflow = StorageAttachmentWorkflow::new(
            store.clone(),
            provider.clone(),
            compute.clone(),
            Arc::new(AcceptFence),
        );
        let request = intent(&attachment);
        let first = workflow.attach(request.clone()).await.unwrap();
        assert_eq!(first.command_state, AgentCommandState::Succeeded);
        assert_eq!(first.attachment_state, VolumeAttachmentState::Attached);
        assert_eq!(provider.prepare_calls.load(Ordering::SeqCst), 1);
        assert_eq!(compute.attach_calls.load(Ordering::SeqCst), 1);
        assert_eq!(
            store
                .get_volume(attachment.volume_id.as_uuid())
                .await
                .unwrap()
                .unwrap()
                .volume
                .state,
            VolumeState::InUse
        );

        let replay = workflow.attach(request).await.unwrap();
        assert_eq!(replay.command_id, first.command_id);
        assert_eq!(replay.command_state, AgentCommandState::Succeeded);
        assert_eq!(provider.prepare_calls.load(Ordering::SeqCst), 1);

        let mut conflict = intent(&attachment);
        conflict.access_mode = AttachmentAccessMode::ReadOnly;
        assert!(matches!(
            workflow.attach(conflict).await,
            Err(StorageWorkflowError::IdempotencyConflict)
        ));

        let mut detach_request = intent(&attachment);
        detach_request.idempotency_key = "detach-once".to_owned();
        let detached = workflow.detach(detach_request).await.unwrap();
        assert_eq!(detached.command_state, AgentCommandState::Succeeded);
        assert_eq!(detached.attachment_state, VolumeAttachmentState::Deleted);
        assert_eq!(compute.attach_calls.load(Ordering::SeqCst), 1);
        assert_eq!(
            store
                .get_volume(attachment.volume_id.as_uuid())
                .await
                .unwrap()
                .unwrap()
                .volume
                .state,
            VolumeState::Available
        );
    }

    #[tokio::test]
    async fn unknown_provider_outcome_requires_observe_before_retry() {
        let (store, provider, compute, attachment) = fixture(true).await;
        let workflow = StorageAttachmentWorkflow::new(
            store.clone(),
            provider.clone(),
            compute.clone(),
            Arc::new(AcceptFence),
        );
        let request = intent(&attachment);
        assert!(matches!(
            workflow.attach(request.clone()).await,
            Err(StorageWorkflowError::UnknownOutcome)
        ));
        let command = store
            .get_agent_command_by_idempotency_key("attach-once")
            .await
            .unwrap();
        assert_eq!(command.state, AgentCommandState::UnknownOutcome);
        let durable = store
            .get_volume_attachment_v1(attachment.id.as_uuid())
            .await
            .unwrap()
            .unwrap();
        assert_eq!(durable.attachment.state, VolumeAttachmentState::Unknown);
        assert_eq!(provider.prepare_calls.load(Ordering::SeqCst), 1);

        let result = workflow.reconcile(&command.command_id, 7).await.unwrap();
        assert_eq!(result.command_state, AgentCommandState::Succeeded);
        assert_eq!(result.attachment_state, VolumeAttachmentState::Attached);
        assert_eq!(provider.prepare_calls.load(Ordering::SeqCst), 2);
        assert_eq!(compute.attach_calls.load(Ordering::SeqCst), 1);
    }

    #[tokio::test]
    async fn recovery_takes_over_original_command_epoch_under_current_fence() {
        let (store, provider, compute, attachment) = fixture(true).await;
        let original = StorageAttachmentWorkflow::new(
            store.clone(),
            provider.clone(),
            compute.clone(),
            Arc::new(AcceptFence),
        );
        assert!(matches!(
            original.attach(intent(&attachment)).await,
            Err(StorageWorkflowError::UnknownOutcome)
        ));
        let command = store
            .get_agent_command_by_idempotency_key("attach-once")
            .await
            .unwrap();

        // The immutable request envelope remains owned by controller 7, but
        // controller 8 has acquired the durable recovery lease.  It must be
        // able to recover the operation without impersonating controller 7.
        let takeover = StorageAttachmentWorkflow::new(
            store.clone(),
            provider.clone(),
            compute.clone(),
            Arc::new(EpochFence(8)),
        );
        let result = takeover.reconcile(&command.command_id, 8).await.unwrap();
        assert_eq!(result.command_state, AgentCommandState::Succeeded);
        assert_eq!(result.attachment_state, VolumeAttachmentState::Attached);
        assert_eq!(provider.prepare_calls.load(Ordering::SeqCst), 2);
        let recovered = store.get_agent_command(&command.command_id).await.unwrap();
        let envelope: StorageCommandEnvelope = serde_json::from_slice(&recovered.payload).unwrap();
        assert_eq!(envelope.controller_epoch, 7);
    }
}
