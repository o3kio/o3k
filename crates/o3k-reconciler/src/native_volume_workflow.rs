//! Durable native-volume execution boundary.
//!
//! This workflow owns replay identity and fencing; provider implementations
//! only receive the persisted, context-bound command envelope.
use crate::storage_volume_workflow::StorageVolumeIntent;
use crate::storage_workflow::StorageControllerFence;
use async_trait::async_trait;
use o3k_domain::VolumeState;
use o3k_domain::{
    StorageAction, StorageCommandPayload, StorageCommandRecord, StorageVolumeCommandPayload,
    VolumeId,
};
use o3k_storage::{
    StorageExecutionContext, StorageProvider, StorageProviderError, StorageVolumeRequest,
};
use o3k_store::{
    AgentCommandRecord, AgentCommandState, BootstrapRepository, DurableStore, OperationRecord,
    OperationState, StorageRepository, StoreError, VolumeRecord,
};
use std::sync::Arc;
use thiserror::Error;

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
    #[error("provider reference mismatch")]
    ProviderReferenceMismatch,
    #[error("provider error")]
    Provider(#[from] StorageProviderError),
    #[error("native volume recovery required")]
    RecoveryRequired,
}

#[cfg(test)]
mod tests {
    use super::*;
    use uuid::Uuid;

    #[test]
    fn lvm_reference_is_bound_to_canonical_volume_name() {
        let id = VolumeId::from_uuid(Uuid::from_u128(7));
        let good = o3k_domain::StorageProviderReference {
            provider: "lvm".into(),
            resource_id: format!("o3k-v-{}", id.as_uuid().simple()),
        };
        let foreign = o3k_domain::StorageProviderReference {
            provider: "lvm".into(),
            resource_id: "o3k-v-00000000000000000000000000000008".into(),
        };
        let foreign_provider = o3k_domain::StorageProviderReference {
            provider: "foreign".into(),
            resource_id: format!("o3k-v-{}", id.as_uuid().simple()),
        };
        assert!(provider_reference_matches(id, &good));
        assert!(!provider_reference_matches(id, &foreign));
        assert!(!provider_reference_matches(id, &foreign_provider));
    }
}

pub struct NativeVolumeWorkflow<S, P: ?Sized, F> {
    store: Arc<S>,
    provider: Arc<P>,
    fence: Arc<F>,
}

fn provider_reference_matches(
    volume_id: VolumeId,
    reference: &o3k_domain::StorageProviderReference,
) -> bool {
    reference.validate().is_ok()
        && reference.provider == "lvm"
        && reference.resource_id == format!("o3k-v-{}", volume_id.as_uuid().simple())
}

impl<S, P, F> NativeVolumeWorkflow<S, P, F>
where
    S: DurableStore + StorageRepository + BootstrapRepository + Send + Sync + 'static,
    P: StorageProvider + ?Sized + 'static,
    F: StorageControllerFence + 'static,
{
    pub fn new(store: Arc<S>, provider: Arc<P>, fence: Arc<F>) -> Self {
        Self {
            store,
            provider,
            fence,
        }
    }

    pub async fn create(
        &self,
        intent: StorageVolumeIntent,
    ) -> Result<(), NativeVolumeWorkflowError> {
        self.execute(intent, StorageAction::CreateVolume).await
    }

    pub async fn delete(
        &self,
        intent: StorageVolumeIntent,
    ) -> Result<(), NativeVolumeWorkflowError> {
        self.execute(intent, StorageAction::DeleteVolume).await
    }

    pub async fn recover(&self) -> Result<(), NativeVolumeWorkflowError> {
        for command in self.store.list_recoverable_agent_commands().await? {
            let Ok(record) = serde_json::from_slice::<StorageCommandRecord>(&command.payload)
            else {
                continue;
            };
            let StorageCommandPayload::Volume(payload) = record.payload else {
                continue;
            };
            let request = StorageVolumeRequest {
                volume_id: payload.volume_id,
                project_id: payload.project_id.clone(),
                size_bytes: payload.size_bytes,
                generation: payload.generation,
            };
            let context = StorageExecutionContext {
                envelope: record.envelope.clone(),
            };
            self.assert_agent_epoch(
                &record.envelope.target_agent_id,
                &record.envelope.target_agent_epoch,
            )
            .await?;
            let observed = match self
                .provider
                .inspect_volume_with_context(&request, &context)
                .await
            {
                Ok(observed) => observed,
                Err(StorageProviderError::NotFound)
                    if record.envelope.action == StorageAction::DeleteVolume =>
                {
                    self.converge_recovered_volume(&payload, StorageAction::DeleteVolume, None)
                        .await?;
                    self.store
                        .update_agent_command(
                            &command.command_id,
                            AgentCommandState::Succeeded,
                            command.accepted_sequence.saturating_add(1),
                            command.last_sequence.saturating_add(1),
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
                    continue;
                }
                Err(_) => continue,
            };
            let converged = match record.envelope.action {
                StorageAction::CreateVolume => {
                    observed.owned
                        && observed.available
                        && observed.size_bytes == payload.size_bytes
                        && provider_reference_matches(
                            payload.volume_id,
                            &observed.provider_reference,
                        )
                }
                StorageAction::DeleteVolume => !observed.owned || !observed.available,
                _ => false,
            };
            if converged {
                let reference = if record.envelope.action == StorageAction::CreateVolume {
                    Some(observed.provider_reference.clone())
                } else {
                    None
                };
                self.converge_recovered_volume(&payload, record.envelope.action, reference)
                    .await?;
                self.store
                    .update_agent_command(
                        &command.command_id,
                        AgentCommandState::Succeeded,
                        command.accepted_sequence.saturating_add(1),
                        command.last_sequence.saturating_add(1),
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
            }
        }
        Ok(())
    }

    async fn converge_recovered_volume(
        &self,
        payload: &o3k_domain::StorageVolumeCommandPayload,
        action: StorageAction,
        provider_reference: Option<o3k_domain::StorageProviderReference>,
    ) -> Result<(), NativeVolumeWorkflowError> {
        let current = self
            .store
            .get_volume(payload.volume_id.as_uuid())
            .await?
            .ok_or(StoreError::ResourceNotFound)?;
        if current.volume.project_id != payload.project_id
            || current.volume.size_bytes != payload.size_bytes
        {
            return Err(NativeVolumeWorkflowError::Invalid);
        }
        let target = match action {
            StorageAction::CreateVolume => VolumeState::Available,
            StorageAction::DeleteVolume => VolumeState::Deleted,
            _ => return Err(NativeVolumeWorkflowError::Invalid),
        };
        if current.volume.state == target {
            return Ok(());
        }
        let mut next = current.volume.clone();
        next.state = target;
        next.generation = current.volume.generation.saturating_add(1);
        if let Some(reference) = provider_reference {
            next.provider_reference = Some(reference);
        }
        let next = current
            .volume
            .clone()
            .transition(next)
            .map_err(|_| NativeVolumeWorkflowError::Invalid)?;
        self.store
            .update_volume(
                current.volume.generation,
                &VolumeRecord {
                    volume: next,
                    created_at: current.created_at.clone(),
                },
            )
            .await?;
        Ok(())
    }

    async fn assert_agent_epoch(
        &self,
        agent_id: &str,
        agent_epoch: &str,
    ) -> Result<(), NativeVolumeWorkflowError> {
        let state = self
            .store
            .get_bootstrap_state("default")
            .await?
            .ok_or(NativeVolumeWorkflowError::StaleFence)?;
        let revoked: std::collections::BTreeMap<String, bool> =
            serde_json::from_str(&state.revoked_agents)
                .map_err(|_| NativeVolumeWorkflowError::StaleFence)?;
        if revoked.get(agent_id).copied().unwrap_or(false) {
            return Err(NativeVolumeWorkflowError::StaleFence);
        }
        let enrolled: std::collections::BTreeMap<String, String> =
            serde_json::from_str(&state.enrolled_agents)
                .map_err(|_| NativeVolumeWorkflowError::StaleFence)?;
        if !enrolled.contains_key(agent_id) || state.phase != "ready" {
            return Err(NativeVolumeWorkflowError::StaleFence);
        }
        let epochs: std::collections::BTreeMap<String, String> =
            serde_json::from_str(&state.enrolled_agent_epochs)
                .map_err(|_| NativeVolumeWorkflowError::StaleFence)?;
        if epochs.get(agent_id).map(String::as_str) != Some(agent_epoch) {
            return Err(NativeVolumeWorkflowError::StaleFence);
        }
        Ok(())
    }

    async fn execute(
        &self,
        intent: StorageVolumeIntent,
        action: StorageAction,
    ) -> Result<(), NativeVolumeWorkflowError> {
        intent
            .validate()
            .map_err(|_| NativeVolumeWorkflowError::Invalid)?;
        self.assert_agent_epoch(
            &intent.target_agent_id,
            &intent.target_agent_epoch.to_string(),
        )
        .await?;
        self.fence
            .assert_current(intent.controller_epoch)
            .await
            .map_err(|_| NativeVolumeWorkflowError::StaleFence)?;
        let envelope = intent
            .envelope(action)
            .map_err(|_| NativeVolumeWorkflowError::Invalid)?;
        let fingerprint = envelope.canonical_payload_fingerprint.clone();
        match self
            .store
            .get_agent_command_by_idempotency_key(&intent.idempotency_key)
            .await
        {
            Ok(existing) => {
                if existing.payload_fingerprint_sha256 != fingerprint
                    || existing.command_id != envelope.command_id.to_string()
                {
                    return Err(NativeVolumeWorkflowError::IdempotencyConflict);
                }
                if matches!(existing.state, AgentCommandState::Succeeded) {
                    return Ok(());
                }
            }
            Err(StoreError::ResourceNotFound) => {}
            Err(error) => return Err(error.into()),
        }
        let operation_id = envelope.operation_id;
        self.store
            .insert_operation(&OperationRecord {
                id: operation_id,
                resource_id: intent.volume_id.as_uuid(),
                kind: "storage:volume".into(),
                state: OperationState::Pending,
                provider_operation_id: None,
                error_category: None,
                error_message: None,
            })
            .await?;
        let payload = serde_json::to_vec(&StorageCommandRecord {
            envelope: envelope.clone(),
            payload: intent.payload(),
        })
        .map_err(|_| NativeVolumeWorkflowError::Invalid)?;
        let command_id = envelope.command_id.to_string();
        let command_record = AgentCommandRecord {
            command_id: command_id.clone(),
            idempotency_key: intent.idempotency_key.clone(),
            operation_id,
            resource_id: intent.volume_id.as_uuid(),
            agent_id: intent.target_agent_id.clone(),
            agent_epoch: intent.target_agent_epoch.to_string(),
            payload_fingerprint_sha256: fingerprint,
            payload,
            state: AgentCommandState::Pending,
            accepted_sequence: 0,
            last_sequence: 0,
            provider_operation_id: None,
            provider_resource_id: None,
        };
        match self.store.insert_agent_command(&command_record).await {
            Ok(_) => {}
            Err(StoreError::IdempotencyConflict | StoreError::ResourceAlreadyExists) => {
                let existing = self
                    .store
                    .get_agent_command_by_idempotency_key(&intent.idempotency_key)
                    .await?;
                if existing.command_id != command_id
                    || existing.payload_fingerprint_sha256
                        != command_record.payload_fingerprint_sha256
                {
                    return Err(NativeVolumeWorkflowError::IdempotencyConflict);
                }
                if matches!(existing.state, AgentCommandState::Succeeded) {
                    return Ok(());
                }
            }
            Err(error) => return Err(error.into()),
        }
        let request = StorageVolumeRequest {
            volume_id: intent.volume_id,
            project_id: intent.project_id.clone(),
            size_bytes: intent.size_bytes,
            generation: intent.generation,
        };
        let context = StorageExecutionContext { envelope };
        let current = self
            .store
            .get_volume(intent.volume_id.as_uuid())
            .await?
            .ok_or(StoreError::ResourceNotFound)?;
        if action == StorageAction::DeleteVolume {
            let Some(expected) = current.volume.provider_reference.as_ref() else {
                return Err(NativeVolumeWorkflowError::ProviderReferenceMismatch);
            };
            match self
                .provider
                .inspect_volume_with_context(&request, &context)
                .await
            {
                Ok(observed) if observed.provider_reference == *expected => {}
                _ => return Err(NativeVolumeWorkflowError::ProviderReferenceMismatch),
            }
        }
        if intent.generation != current.volume.generation.saturating_add(1) {
            return Err(NativeVolumeWorkflowError::Invalid);
        }
        {
            let mut next = current.volume.clone();
            next.operation_id = Some(operation_id);
            next.state = match action {
                StorageAction::CreateVolume => VolumeState::Creating,
                StorageAction::DeleteVolume => VolumeState::Deleting,
                _ => current.volume.state,
            };
            next.generation = current.volume.generation.saturating_add(1);
            let next = current
                .volume
                .clone()
                .transition(next)
                .map_err(|_| NativeVolumeWorkflowError::Invalid)?;
            self.store
                .update_volume(
                    current.volume.generation,
                    &VolumeRecord {
                        volume: next,
                        created_at: current.created_at.clone(),
                    },
                )
                .await?;
        }
        self.fence
            .assert_current(intent.controller_epoch)
            .await
            .map_err(|_| NativeVolumeWorkflowError::StaleFence)?;
        let result = match action {
            StorageAction::CreateVolume => self
                .provider
                .create_volume_with_context(&request, &context)
                .await
                .map(|observation| (Some(observation.provider_reference), false)),
            StorageAction::DeleteVolume => self
                .provider
                .delete_volume_with_context(&request, &context)
                .await
                .map(|_| (None, true)),
            _ => return Err(NativeVolumeWorkflowError::Invalid),
        };
        match result {
            Ok((provider_reference, deleted)) => {
                if let Some(reference) = provider_reference.as_ref()
                    && !provider_reference_matches(intent.volume_id, reference)
                {
                    return Err(NativeVolumeWorkflowError::Invalid);
                }
                if let Some(current) = self.store.get_volume(intent.volume_id.as_uuid()).await? {
                    let mut next = current.volume.clone();
                    next.state = if deleted {
                        VolumeState::Deleted
                    } else {
                        VolumeState::Available
                    };
                    next.operation_id = Some(operation_id);
                    if let Some(reference) = provider_reference {
                        next.provider_reference = Some(reference);
                    }
                    next.generation = current.volume.generation.saturating_add(1);
                    let next = current
                        .volume
                        .clone()
                        .transition(next)
                        .map_err(|_| NativeVolumeWorkflowError::Invalid)?;
                    self.store
                        .update_volume(
                            current.volume.generation,
                            &VolumeRecord {
                                volume: next,
                                created_at: current.created_at.clone(),
                            },
                        )
                        .await?;
                }
                self.store
                    .update_agent_command(
                        &command_id,
                        AgentCommandState::Succeeded,
                        1,
                        1,
                        None,
                        None,
                    )
                    .await?;
                self.store
                    .update_operation(operation_id, OperationState::Succeeded, None, None, None)
                    .await?;
                Ok(())
            }
            Err(e) if e.is_unknown_outcome() => {
                self.store
                    .update_agent_command(
                        &command_id,
                        AgentCommandState::UnknownOutcome,
                        1,
                        1,
                        None,
                        None,
                    )
                    .await?;
                self.store
                    .update_operation(
                        operation_id,
                        OperationState::UnknownOutcome,
                        None,
                        Some("unknown_outcome"),
                        Some("observe before retry"),
                    )
                    .await?;
                let observed = self
                    .provider
                    .inspect_volume_with_context(&request, &context)
                    .await;
                let observed_reference = if matches!(action, StorageAction::CreateVolume) {
                    observed
                        .as_ref()
                        .ok()
                        .map(|value| value.provider_reference.clone())
                } else {
                    None
                };
                let converged = match observed {
                    Ok(observed) => match action {
                        StorageAction::CreateVolume => {
                            observed.owned
                                && observed.available
                                && observed.size_bytes == intent.size_bytes
                                && provider_reference_matches(
                                    intent.volume_id,
                                    &observed.provider_reference,
                                )
                        }
                        StorageAction::DeleteVolume => !observed.owned || !observed.available,
                        _ => false,
                    },
                    Err(StorageProviderError::NotFound) => {
                        matches!(action, StorageAction::DeleteVolume)
                    }
                    Err(_) => false,
                };
                if converged {
                    self.converge_recovered_volume(
                        &StorageVolumeCommandPayload {
                            volume_id: intent.volume_id,
                            project_id: intent.project_id.clone(),
                            size_bytes: intent.size_bytes,
                            generation: intent.generation,
                        },
                        action,
                        observed_reference,
                    )
                    .await?;
                    self.store
                        .update_agent_command(
                            &command_id,
                            AgentCommandState::Succeeded,
                            2,
                            2,
                            None,
                            None,
                        )
                        .await?;
                    self.store
                        .update_operation(operation_id, OperationState::Succeeded, None, None, None)
                        .await?;
                    return Ok(());
                }
                Err(e.into())
            }
            Err(e) => {
                self.store
                    .update_agent_command(&command_id, AgentCommandState::Failed, 1, 1, None, None)
                    .await?;
                self.store
                    .update_operation(
                        operation_id,
                        OperationState::Failed,
                        None,
                        Some("provider"),
                        Some("storage operation failed"),
                    )
                    .await?;
                Err(e.into())
            }
        }
    }
}
