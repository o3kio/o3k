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
#[allow(
    clippy::items_after_test_module,
    clippy::unwrap_used,
    clippy::expect_used
)]
mod tests {
    use super::*;
    use crate::storage_workflow::StorageWorkflowError;
    use async_trait::async_trait;
    use o3k_domain::{StorageCapabilities, StorageExecutionScope, Volume, VolumeState};
    use o3k_storage::{
        PreparedAttachment, StorageAttachmentObservation, StorageAttachmentRequest,
        StorageProvider, StorageSnapshotObservation, StorageSnapshotRequest,
    };
    use o3k_store::{
        BootstrapRepository, BootstrapStateRecord, O3kStore, ResourceRecord, StorageRepository,
    };
    use std::sync::{Arc, Mutex};
    use uuid::Uuid;

    struct FakeFence {
        begins: std::sync::atomic::AtomicUsize,
        ends: std::sync::atomic::AtomicUsize,
        fail_begin: std::sync::atomic::AtomicBool,
        current_epoch: std::sync::atomic::AtomicU64,
    }
    #[async_trait]
    impl StorageControllerFence for FakeFence {
        async fn begin(&self, _epoch: u64) -> Result<(), StorageWorkflowError> {
            self.begins
                .fetch_add(1, std::sync::atomic::Ordering::SeqCst);
            if self.fail_begin.load(std::sync::atomic::Ordering::SeqCst)
                || self.current_epoch.load(std::sync::atomic::Ordering::SeqCst) != _epoch
            {
                return Err(StorageWorkflowError::StaleControllerFence);
            }
            Ok(())
        }
        async fn assert_current(&self, epoch: u64) -> Result<(), StorageWorkflowError> {
            if self.current_epoch.load(std::sync::atomic::Ordering::SeqCst) != epoch {
                return Err(StorageWorkflowError::StaleControllerFence);
            }
            Ok(())
        }
        async fn end(&self, _epoch: u64) -> Result<(), StorageWorkflowError> {
            self.ends.fetch_add(1, std::sync::atomic::Ordering::SeqCst);
            Ok(())
        }
    }

    struct FakeProvider {
        observation: Mutex<Option<o3k_storage::StorageVolumeObservation>>,
        creates: std::sync::atomic::AtomicUsize,
        deletes: std::sync::atomic::AtomicUsize,
        foreign: bool,
        unknown_create: bool,
        inspect_unavailable_once: Mutex<bool>,
    }
    #[async_trait]
    impl StorageProvider for FakeProvider {
        async fn capabilities(&self) -> Result<StorageCapabilities, StorageProviderError> {
            Ok(StorageCapabilities {
                create_volume: true,
                snapshots: false,
                attachment: false,
                capacity_bytes: u64::MAX,
                allocated_bytes: 0,
                allocation_unit_bytes: 1,
            })
        }
        async fn create_volume(
            &self,
            request: &StorageVolumeRequest,
        ) -> Result<o3k_storage::StorageVolumeObservation, StorageProviderError> {
            self.creates
                .fetch_add(1, std::sync::atomic::Ordering::SeqCst);
            let o = o3k_storage::StorageVolumeObservation {
                provider_reference: o3k_domain::StorageProviderReference {
                    provider: "lvm".into(),
                    resource_id: format!("o3k-v-{}", request.volume_id.as_uuid().simple()),
                },
                size_bytes: request.size_bytes,
                owned: true,
                available: true,
            };
            *self.observation.lock().unwrap() = Some(o.clone());
            if self.unknown_create {
                Err(StorageProviderError::UnknownOutcome)
            } else {
                Ok(o)
            }
        }
        async fn inspect_volume(
            &self,
            request: &StorageVolumeRequest,
        ) -> Result<o3k_storage::StorageVolumeObservation, StorageProviderError> {
            {
                let mut unavailable = self.inspect_unavailable_once.lock().unwrap();
                if *unavailable {
                    *unavailable = false;
                    return Err(StorageProviderError::Unavailable);
                }
            }
            if self.foreign {
                return Ok(o3k_storage::StorageVolumeObservation {
                    provider_reference: o3k_domain::StorageProviderReference {
                        provider: "lvm".into(),
                        resource_id: "o3k-v-00000000000000000000000000000008".into(),
                    },
                    size_bytes: request.size_bytes,
                    owned: true,
                    available: true,
                });
            }
            self.observation
                .lock()
                .unwrap()
                .clone()
                .ok_or(StorageProviderError::NotFound)
        }
        async fn delete_volume(
            &self,
            _request: &StorageVolumeRequest,
        ) -> Result<(), StorageProviderError> {
            self.deletes
                .fetch_add(1, std::sync::atomic::Ordering::SeqCst);
            self.observation
                .lock()
                .unwrap()
                .take()
                .map(|_| ())
                .ok_or(StorageProviderError::NotFound)
        }
        async fn prepare_attachment(
            &self,
            _request: &StorageAttachmentRequest,
        ) -> Result<PreparedAttachment, StorageProviderError> {
            Err(StorageProviderError::InvalidRequest)
        }
        async fn inspect_attachment(
            &self,
            _request: &StorageAttachmentRequest,
        ) -> Result<StorageAttachmentObservation, StorageProviderError> {
            Err(StorageProviderError::InvalidRequest)
        }
        async fn terminate_attachment(
            &self,
            _request: &StorageAttachmentRequest,
        ) -> Result<StorageAttachmentObservation, StorageProviderError> {
            Err(StorageProviderError::InvalidRequest)
        }
        async fn create_snapshot(
            &self,
            _request: &StorageSnapshotRequest,
        ) -> Result<StorageSnapshotObservation, StorageProviderError> {
            Err(StorageProviderError::InvalidRequest)
        }
        async fn delete_snapshot(
            &self,
            _request: &StorageSnapshotRequest,
        ) -> Result<(), StorageProviderError> {
            Err(StorageProviderError::InvalidRequest)
        }
    }

    async fn workflow_fixture(
        foreign: bool,
        unknown_create: bool,
    ) -> (
        Arc<O3kStore>,
        Arc<FakeProvider>,
        Arc<FakeFence>,
        NativeVolumeWorkflow<O3kStore, FakeProvider, FakeFence>,
        VolumeId,
    ) {
        let store = Arc::new(O3kStore::connect_sqlite_memory().await.unwrap());
        store
            .upsert_bootstrap_state(&BootstrapStateRecord {
                state_id: "default".into(),
                generation: 1,
                phase: "ready".into(),
                cloud_identity_id: "cloud".into(),
                cloud_profile_id: "ea".into(),
                enrolled_agents: r#"{"agent-a":"fp"}"#.into(),
                enrolled_agent_epochs: r#"{"agent-a":"epoch-1"}"#.into(),
                revoked_agents: "{}".into(),
                updated_at: "now".into(),
            })
            .await
            .unwrap();
        let id = VolumeId::from_uuid(Uuid::from_u128(7));
        store
            .insert_resource(&ResourceRecord {
                id: id.as_uuid(),
                kind: "volume".into(),
                project_id: "project".into(),
                generation: 1,
                observed_generation: 1,
                desired_state: "requested".into(),
                observed_state: "requested".into(),
                provider_id: None,
            })
            .await
            .unwrap();
        store
            .insert_volume(&o3k_store::VolumeRecord {
                volume: Volume {
                    id,
                    project_id: "project".into(),
                    name: "volume".into(),
                    description: String::new(),
                    metadata: Default::default(),
                    availability_zone: None,
                    size_bytes: 4096,
                    volume_type: "lvm".into(),
                    backend_id: "local".into(),
                    execution_scope: StorageExecutionScope::Host("agent-a".into()),
                    state: VolumeState::Requested,
                    generation: 1,
                    operation_id: None,
                    provider_reference: None,
                },
                created_at: "now".into(),
            })
            .await
            .unwrap();
        let provider = Arc::new(FakeProvider {
            observation: Mutex::new(None),
            creates: Default::default(),
            deletes: Default::default(),
            foreign,
            unknown_create,
            inspect_unavailable_once: Mutex::new(false),
        });
        let fence = Arc::new(FakeFence {
            begins: Default::default(),
            ends: Default::default(),
            fail_begin: Default::default(),
            current_epoch: std::sync::atomic::AtomicU64::new(1),
        });
        let workflow = NativeVolumeWorkflow::new(store.clone(), provider.clone(), fence.clone());
        (store, provider, fence, workflow, id)
    }
    fn intent(id: VolumeId, key: &str, generation: u64) -> StorageVolumeIntent {
        StorageVolumeIntent {
            volume_id: id,
            project_id: "project".into(),
            size_bytes: 4096,
            generation,
            controller_epoch: 1,
            target_agent_id: "agent-a".into(),
            target_agent_epoch: "epoch-1".into(),
            idempotency_key: key.into(),
            trace_id: "trace".into(),
            deadline: "2099-01-01T00:00:00Z".into(),
        }
    }

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

    #[tokio::test]
    async fn durable_create_and_delete_converge_canonical_state() {
        let (store, provider, fence, workflow, id) = workflow_fixture(false, false).await;
        workflow.create(intent(id, "create", 2)).await.unwrap();
        assert_eq!(
            store
                .get_volume(id.as_uuid())
                .await
                .unwrap()
                .unwrap()
                .volume
                .state,
            VolumeState::Available
        );
        let mut delete = intent(id, "delete", 4);
        delete.generation = 4;
        workflow.delete(delete).await.unwrap();
        assert_eq!(
            store
                .get_volume(id.as_uuid())
                .await
                .unwrap()
                .unwrap()
                .volume
                .state,
            VolumeState::Deleted
        );
        assert_eq!(
            provider.creates.load(std::sync::atomic::Ordering::SeqCst),
            1
        );
        assert_eq!(
            provider.deletes.load(std::sync::atomic::Ordering::SeqCst),
            1
        );
        assert_eq!(fence.begins.load(std::sync::atomic::Ordering::SeqCst), 2);
        assert_eq!(fence.ends.load(std::sync::atomic::Ordering::SeqCst), 2);
    }

    #[tokio::test]
    async fn recovery_rejects_foreign_observation_without_mutation() {
        let (store, provider, fence, workflow, id) = workflow_fixture(true, false).await;
        workflow
            .create(intent(id, "create-foreign", 2))
            .await
            .unwrap();
        let mut delete = intent(id, "delete-foreign", 4);
        delete.generation = 4;
        let result = workflow.delete(delete).await;
        assert!(result.is_err());
        assert_eq!(
            provider.creates.load(std::sync::atomic::Ordering::SeqCst),
            1
        );
        assert_eq!(
            provider.deletes.load(std::sync::atomic::Ordering::SeqCst),
            0
        );
        assert_eq!(
            store
                .get_volume(id.as_uuid())
                .await
                .unwrap()
                .unwrap()
                .volume
                .state,
            VolumeState::Available
        );
        assert_eq!(
            fence.begins.load(std::sync::atomic::Ordering::SeqCst),
            fence.ends.load(std::sync::atomic::Ordering::SeqCst)
        );
    }

    #[tokio::test]
    async fn volume_command_requires_fence_acquisition() {
        let (_store, provider, fence, workflow, id) = workflow_fixture(false, false).await;
        fence
            .fail_begin
            .store(true, std::sync::atomic::Ordering::SeqCst);
        assert!(matches!(
            workflow.create(intent(id, "fence-rejected", 2)).await,
            Err(NativeVolumeWorkflowError::StaleFence)
        ));
        assert_eq!(
            provider.creates.load(std::sync::atomic::Ordering::SeqCst),
            0
        );
        assert_eq!(fence.begins.load(std::sync::atomic::Ordering::SeqCst), 1);
        assert_eq!(fence.ends.load(std::sync::atomic::Ordering::SeqCst), 0);
    }

    #[tokio::test]
    async fn stale_controller_epoch_is_rejected_before_provider_mutation() {
        let (_store, provider, fence, workflow, id) = workflow_fixture(false, false).await;
        fence
            .current_epoch
            .store(2, std::sync::atomic::Ordering::SeqCst);
        assert!(matches!(
            workflow.create(intent(id, "stale-controller", 2)).await,
            Err(NativeVolumeWorkflowError::StaleFence)
        ));
        assert_eq!(
            provider.creates.load(std::sync::atomic::Ordering::SeqCst),
            0
        );
        assert_eq!(fence.begins.load(std::sync::atomic::Ordering::SeqCst), 1);
        assert_eq!(fence.ends.load(std::sync::atomic::Ordering::SeqCst), 0);
    }

    #[tokio::test]
    async fn stale_agent_epoch_is_rejected_before_provider_mutation() {
        let (store, provider, fence, workflow, id) = workflow_fixture(false, false).await;
        let mut bootstrap = store.get_bootstrap_state("default").await.unwrap().unwrap();
        bootstrap.generation += 1;
        bootstrap.enrolled_agent_epochs = r#"{"agent-a":"epoch-2"}"#.into();
        store.upsert_bootstrap_state(&bootstrap).await.unwrap();
        assert!(matches!(
            workflow.create(intent(id, "stale-agent", 2)).await,
            Err(NativeVolumeWorkflowError::StaleFence)
        ));
        assert_eq!(
            provider.creates.load(std::sync::atomic::Ordering::SeqCst),
            0
        );
        assert_eq!(
            fence.begins.load(std::sync::atomic::Ordering::SeqCst),
            fence.ends.load(std::sync::atomic::Ordering::SeqCst)
        );
    }

    #[tokio::test]
    async fn persisted_unknown_create_recovers_after_workflow_reconstruction() {
        let (store, provider, fence, workflow, id) = workflow_fixture(false, true).await;
        *provider.inspect_unavailable_once.lock().unwrap() = true;
        let create_result = workflow.create(intent(id, "restart-replay", 2)).await;
        assert!(
            matches!(
                &create_result,
                Err(NativeVolumeWorkflowError::Provider(
                    StorageProviderError::UnknownOutcome
                ))
            ),
            "expected unknown provider outcome, got {create_result:?}"
        );
        assert_eq!(
            store
                .get_volume(id.as_uuid())
                .await
                .unwrap()
                .unwrap()
                .volume
                .state,
            VolumeState::Creating
        );

        let restarted = NativeVolumeWorkflow::new(store.clone(), provider.clone(), fence.clone());
        restarted.recover().await.unwrap();
        assert_eq!(
            store
                .get_volume(id.as_uuid())
                .await
                .unwrap()
                .unwrap()
                .volume
                .state,
            VolumeState::Available
        );
        assert_eq!(
            provider.creates.load(std::sync::atomic::Ordering::SeqCst),
            1,
            "replay must observe before repeating an uncertain create"
        );
        assert_eq!(
            fence.begins.load(std::sync::atomic::Ordering::SeqCst),
            fence.ends.load(std::sync::atomic::Ordering::SeqCst)
        );
    }

    #[tokio::test]
    async fn concurrent_duplicate_create_dispatches_one_provider_mutation() {
        let (store, provider, fence, workflow, id) = workflow_fixture(false, false).await;
        let second = NativeVolumeWorkflow::new(store.clone(), provider.clone(), fence);
        let intent = intent(id, "concurrent-duplicate", 2);
        let (first_result, second_result) =
            tokio::join!(workflow.create(intent.clone()), second.create(intent));
        assert!(first_result.is_ok() || second_result.is_ok());
        assert_eq!(
            provider.creates.load(std::sync::atomic::Ordering::SeqCst),
            1
        );
        assert_eq!(
            store
                .get_volume(id.as_uuid())
                .await
                .unwrap()
                .unwrap()
                .volume
                .state,
            VolumeState::Available,
            "the concurrent winner must persist the canonical terminal state"
        );
    }

    #[tokio::test]
    async fn delete_rejects_unowned_or_wrong_sized_provider_observation() {
        for mutation in 0..2 {
            let (store, provider, fence, workflow, id) = workflow_fixture(false, false).await;
            workflow
                .create(intent(id, &format!("create-delete-guard-{mutation}"), 2))
                .await
                .unwrap();
            {
                let mut guard = provider.observation.lock().unwrap();
                let observation = guard.as_mut().unwrap();
                if mutation == 0 {
                    observation.owned = false;
                } else {
                    observation.size_bytes += 1;
                }
            }
            let mut delete = intent(id, &format!("delete-guard-{mutation}"), 4);
            delete.generation = 4;
            assert!(matches!(
                workflow.delete(delete).await,
                Err(NativeVolumeWorkflowError::ProviderReferenceMismatch)
            ));
            assert_eq!(
                provider.deletes.load(std::sync::atomic::Ordering::SeqCst),
                0
            );
            assert_eq!(
                fence.begins.load(std::sync::atomic::Ordering::SeqCst),
                fence.ends.load(std::sync::atomic::Ordering::SeqCst)
            );
            assert_eq!(
                store
                    .get_volume(id.as_uuid())
                    .await
                    .unwrap()
                    .unwrap()
                    .volume
                    .state,
                VolumeState::Available
            );
        }
    }

    #[test]
    fn uncertain_delete_is_confirmed_only_by_explicit_absence() {
        let id = VolumeId::from_uuid(Uuid::from_u128(7));
        let foreign = o3k_storage::StorageVolumeObservation {
            provider_reference: o3k_domain::StorageProviderReference {
                provider: "lvm".into(),
                resource_id: "o3k-v-foreign".into(),
            },
            size_bytes: 1024,
            owned: false,
            available: true,
        };
        let unavailable = o3k_storage::StorageVolumeObservation {
            provider_reference: o3k_domain::StorageProviderReference {
                provider: "lvm".into(),
                resource_id: format!("o3k-v-{}", id.as_uuid().simple()),
            },
            size_bytes: 1024,
            owned: true,
            available: false,
        };
        assert!(!delete_outcome_is_confirmed_absent(&Ok(foreign)));
        assert!(!delete_outcome_is_confirmed_absent(&Ok(unavailable)));
        assert!(delete_outcome_is_confirmed_absent(&Err(
            StorageProviderError::NotFound
        )));
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

fn delete_observation_matches(
    volume_id: VolumeId,
    expected_reference: &o3k_domain::StorageProviderReference,
    expected_size_bytes: u64,
    observation: &o3k_storage::StorageVolumeObservation,
) -> bool {
    observation.owned
        && observation.available
        && observation.size_bytes == expected_size_bytes
        && observation.provider_reference == *expected_reference
        && provider_reference_matches(volume_id, &observation.provider_reference)
}

fn delete_outcome_is_confirmed_absent(
    observation: &Result<o3k_storage::StorageVolumeObservation, StorageProviderError>,
) -> bool {
    matches!(observation, Err(StorageProviderError::NotFound))
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
            if !matches!(&record.payload, StorageCommandPayload::Volume(_)) {
                continue;
            }
            let controller_epoch = record.envelope.controller_epoch;
            self.fence
                .begin(controller_epoch)
                .await
                .map_err(|_| NativeVolumeWorkflowError::StaleFence)?;
            let result = self.recover_command(&command, record).await;
            let end = self.fence.end(controller_epoch).await;
            match (result, end) {
                (Err(error), _) => return Err(error),
                (Ok(()), Err(_)) => return Err(NativeVolumeWorkflowError::StaleFence),
                (Ok(()), Ok(())) => {}
            }
        }
        Ok(())
    }

    async fn recover_command(
        &self,
        command: &AgentCommandRecord,
        record: StorageCommandRecord,
    ) -> Result<(), NativeVolumeWorkflowError> {
        let StorageCommandPayload::Volume(payload) = record.payload else {
            return Ok(());
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
        self.fence
            .assert_current(record.envelope.controller_epoch)
            .await
            .map_err(|_| NativeVolumeWorkflowError::StaleFence)?;
        let observed = match self
            .provider
            .inspect_volume_with_context(&request, &context)
            .await
        {
            Ok(observed) => observed,
            Err(StorageProviderError::NotFound)
                if record.envelope.action == StorageAction::CreateVolume =>
            {
                match self
                    .provider
                    .create_volume_with_context(&request, &context)
                    .await
                {
                    Ok(created) => created,
                    Err(_) => return Ok(()),
                }
            }
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
                return Ok(());
            }
            Err(_) => return Ok(()),
        };
        let mut recovered_delete = false;
        let converged = match record.envelope.action {
            StorageAction::CreateVolume => {
                observed.owned
                    && observed.available
                    && observed.size_bytes == payload.size_bytes
                    && provider_reference_matches(payload.volume_id, &observed.provider_reference)
            }
            StorageAction::DeleteVolume => {
                let expected = self
                    .store
                    .get_volume(payload.volume_id.as_uuid())
                    .await?
                    .and_then(|volume| volume.volume.provider_reference);
                if expected.as_ref().is_some_and(|reference| {
                    delete_observation_matches(
                        payload.volume_id,
                        reference,
                        payload.size_bytes,
                        &observed,
                    )
                }) {
                    match self
                        .provider
                        .delete_volume_with_context(&request, &context)
                        .await
                    {
                        Ok(()) | Err(StorageProviderError::NotFound) => recovered_delete = true,
                        Err(_) => return Ok(()),
                    }
                }
                if recovered_delete {
                    matches!(
                        self.provider
                            .inspect_volume_with_context(&request, &context)
                            .await,
                        Err(StorageProviderError::NotFound)
                    )
                } else {
                    false
                }
            }
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
        self.fence
            .begin(intent.controller_epoch)
            .await
            .map_err(|_| NativeVolumeWorkflowError::StaleFence)?;
        let controller_epoch = intent.controller_epoch;
        let result = self.execute_inner(intent, action).await;
        let end = self.fence.end(controller_epoch).await;
        match (result, end) {
            (Err(error), _) => Err(error),
            (Ok(()), Err(_)) => Err(NativeVolumeWorkflowError::StaleFence),
            (Ok(()), Ok(())) => Ok(()),
        }
    }

    async fn execute_inner(
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
                // A pending/unknown command already has an execution owner.
                // Never let a concurrent replay dispatch the same provider
                // mutation; recovery must observe the durable command first.
                return Err(NativeVolumeWorkflowError::RecoveryRequired);
            }
            Err(StoreError::ResourceNotFound | StoreError::OperationNotFound) => {}
            Err(error) => return Err(error.into()),
        }
        let operation_id = envelope.operation_id;
        match self
            .store
            .insert_operation(&OperationRecord {
                id: operation_id,
                resource_id: intent.volume_id.as_uuid(),
                kind: "storage:volume".into(),
                state: OperationState::Pending,
                provider_operation_id: None,
                error_category: None,
                error_message: None,
            })
            .await
        {
            Ok(()) => {}
            Err(StoreError::IdempotencyConflict | StoreError::ResourceAlreadyExists) => {
                let existing = self.store.get_operation(operation_id).await?;
                if existing.resource_id != intent.volume_id.as_uuid()
                    || existing.kind != "storage:volume"
                {
                    return Err(NativeVolumeWorkflowError::IdempotencyConflict);
                }
            }
            Err(error) => return Err(error.into()),
        }
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
                return Err(NativeVolumeWorkflowError::RecoveryRequired);
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
                Ok(observed)
                    if delete_observation_matches(
                        intent.volume_id,
                        expected,
                        intent.size_bytes,
                        &observed,
                    ) => {}
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
            StorageAction::DeleteVolume => {
                match self
                    .provider
                    .delete_volume_with_context(&request, &context)
                    .await
                {
                    Ok(()) | Err(StorageProviderError::NotFound) => {}
                    Err(error) => return Err(error.into()),
                }
                match self
                    .provider
                    .inspect_volume_with_context(&request, &context)
                    .await
                {
                    Err(StorageProviderError::NotFound) => Ok((None, true)),
                    Ok(_) | Err(_) => Err(StorageProviderError::UnknownOutcome),
                }
            }
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
                        // Foreign or unavailable observations do not prove
                        // that an uncertain delete removed the resource.
                        StorageAction::DeleteVolume => {
                            delete_outcome_is_confirmed_absent(&Ok(observed))
                        }
                        _ => false,
                    },
                    Err(StorageProviderError::NotFound) => action == StorageAction::DeleteVolume,
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
