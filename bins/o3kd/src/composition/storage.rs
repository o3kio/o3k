use async_trait::async_trait;
use o3k_provider::BlockDeviceAttachment;
use o3k_reconciler;
use o3k_storage;
use o3k_store;
use o3k_store::{DurableStore, StorageRepository};
use rustix::fs::{FlockOperation, flock};
use std::fs::{File, OpenOptions};
use std::path::PathBuf;
use std::sync::{
    Arc,
    atomic::{AtomicBool, Ordering},
};
use std::time::Duration;
use tracing;
use uuid::Uuid;

#[derive(Clone)]
pub(crate) struct LocalStorageFence {
    pub(crate) coordination: Arc<dyn o3k_store::CoordinationRepository>,
    pub(crate) controller_id: o3k_store::ControllerId,
    pub(crate) controller_epoch: o3k_store::ControllerEpoch,
    pub(crate) intent_epoch: u64,
    pub(crate) execution_lock_path: PathBuf,
    pub(crate) attempt: Arc<tokio::sync::Mutex<Option<StorageLeaseAttempt>>>,
    pub(crate) quiescing: Arc<AtomicBool>,
}

pub(crate) struct StorageLeaseAttempt {
    pub(crate) fencing_token: o3k_store::FencingToken,
    pub(crate) stop: Option<tokio::sync::oneshot::Sender<()>>,
    pub(crate) renewal: Option<tokio::task::JoinHandle<()>>,
    renewal_failed: bool,
    acquisition_pending: bool,
    pub(crate) valid: Arc<AtomicBool>,
    execution_lock: Option<File>,
    release_confirmed: bool,
}

impl Drop for StorageLeaseAttempt {
    fn drop(&mut self) {
        self.valid.store(false, Ordering::Release);
        if let Some(stop) = self.stop.take() {
            let _ = stop.send(());
        }
        if !self.release_confirmed
            && let Some(lock) = self.execution_lock.take()
        {
            // Unexpected owner loss cannot unlock unresolved storage work.
            // No async cleanup is launched from Drop; restart requires exit.
            std::mem::forget(lock);
        }
    }
}

const STORAGE_RENEWAL_STOP_DEADLINE: Duration = Duration::from_secs(5);
const STORAGE_LEASE_TTL: Duration = Duration::from_secs(15);

impl LocalStorageFence {
    /// Permanently closes this process-local fence to new workflow lease
    /// attempts during controller drain. Ordinary attachment begin/end cycles
    /// remain reusable until composition explicitly quiesces the fence.
    pub(crate) async fn quiesce(&self, timeout: Duration) -> Result<(), ()> {
        self.quiescing.store(true, Ordering::Release);
        let Ok(_attempt) = tokio::time::timeout(timeout, self.attempt.lock()).await else {
            return Err(());
        };
        Ok(())
    }
}

#[async_trait]
impl o3k_reconciler::storage_workflow::StorageControllerFence for LocalStorageFence {
    async fn begin(
        &self,
        controller_epoch: u64,
    ) -> Result<(), o3k_reconciler::storage_workflow::StorageWorkflowError> {
        if controller_epoch == 0 || controller_epoch != self.intent_epoch {
            return Err(
                o3k_reconciler::storage_workflow::StorageWorkflowError::StaleControllerFence,
            );
        }
        if self.quiescing.load(Ordering::Acquire) {
            return Err(
                o3k_reconciler::storage_workflow::StorageWorkflowError::StaleControllerFence,
            );
        }
        let mut attempt = self.attempt.lock().await;
        if attempt.is_some() || self.quiescing.load(Ordering::Acquire) {
            return Err(
                o3k_reconciler::storage_workflow::StorageWorkflowError::StaleControllerFence,
            );
        }
        // Own the execution lock before submitting the first database write.
        // A cancelled/unknown acquisition remains recorded and cannot be
        // mistaken for an idle fence by shutdown.
        let execution_lock = OpenOptions::new()
            .create(true)
            .truncate(false)
            .read(true)
            .write(true)
            .open(&self.execution_lock_path)
            .map_err(|_| {
                o3k_reconciler::storage_workflow::StorageWorkflowError::StaleControllerFence
            })?;
        flock(&execution_lock, FlockOperation::NonBlockingLockExclusive).map_err(|_| {
            o3k_reconciler::storage_workflow::StorageWorkflowError::StaleControllerFence
        })?;
        *attempt = Some(StorageLeaseAttempt {
            fencing_token: 0,
            stop: None,
            renewal: None,
            renewal_failed: false,
            acquisition_pending: true,
            valid: Arc::new(AtomicBool::new(false)),
            execution_lock: Some(execution_lock),
            release_confirmed: false,
        });
        let lease = match self
            .coordination
            .acquire_work_lease(
                "o3k-native-storage-controller",
                "storage-attachment",
                &self.controller_id,
                &self.controller_epoch,
                STORAGE_LEASE_TTL,
            )
            .await
            .map_err(|_| {
                o3k_reconciler::storage_workflow::StorageWorkflowError::StaleControllerFence
            })? {
            o3k_store::LeaseAcquireOutcome::Acquired { lease } => lease,
            o3k_store::LeaseAcquireOutcome::Busy { .. } => {
                if let Some(current) = attempt.as_mut() {
                    current.release_confirmed = true;
                }
                attempt.take();
                return Err(
                    o3k_reconciler::storage_workflow::StorageWorkflowError::StaleControllerFence,
                );
            }
        };
        let current = attempt
            .as_mut()
            .ok_or(o3k_reconciler::storage_workflow::StorageWorkflowError::StaleControllerFence)?;
        current.fencing_token = lease.fencing_token;
        current.acquisition_pending = false;
        if self.quiescing.load(Ordering::Acquire) {
            // `end` owns the recorded release; no best-effort release can
            // disappear here if quiescence races acquisition.
            return Err(
                o3k_reconciler::storage_workflow::StorageWorkflowError::StaleControllerFence,
            );
        }
        let (stop, mut stopped) = tokio::sync::oneshot::channel();
        let valid = Arc::new(AtomicBool::new(true));
        let coordination = self.coordination.clone();
        let controller_id = self.controller_id.clone();
        let controller_epoch_value = self.controller_epoch.clone();
        let fencing_token = lease.fencing_token;
        let renewal_valid = valid.clone();
        let renewal = tokio::spawn(async move {
            let mut interval = tokio::time::interval(Duration::from_secs(5));
            interval.tick().await;
            loop {
                tokio::select! {
                    _ = &mut stopped => break,
                    _ = interval.tick() => {
                        match coordination.renew_work_lease(
                            "o3k-native-storage-controller",
                            &controller_id,
                            &controller_epoch_value,
                            fencing_token,
                            STORAGE_LEASE_TTL,
                        ).await {
                            Ok(true) => {}
                            Ok(false) | Err(_) => {
                                renewal_valid.store(false, Ordering::Release);
                                break;
                            }
                        }
                    }
                }
            }
        });
        current.stop = Some(stop);
        current.renewal = Some(renewal);
        current.valid = valid;
        Ok(())
    }

    async fn assert_current(
        &self,
        controller_epoch: u64,
    ) -> Result<(), o3k_reconciler::storage_workflow::StorageWorkflowError> {
        if controller_epoch == 0 || controller_epoch != self.intent_epoch {
            return Err(
                o3k_reconciler::storage_workflow::StorageWorkflowError::StaleControllerFence,
            );
        }
        if self.quiescing.load(Ordering::Acquire) {
            return Err(
                o3k_reconciler::storage_workflow::StorageWorkflowError::StaleControllerFence,
            );
        }
        // Hold the attempt lock until the database renewal finishes. `end`
        // acquires the same lock before stopping the background task, so it
        // cannot release the lease concurrently with this assertion.
        let attempt = self.attempt.lock().await;
        if self.quiescing.load(Ordering::Acquire) {
            return Err(
                o3k_reconciler::storage_workflow::StorageWorkflowError::StaleControllerFence,
            );
        }
        let fencing_token = attempt
            .as_ref()
            .filter(|attempt| attempt.valid.load(Ordering::Acquire) && attempt.stop.is_some())
            .map(|attempt| attempt.fencing_token)
            .ok_or(o3k_reconciler::storage_workflow::StorageWorkflowError::StaleControllerFence)?;
        let renewed = tokio::time::timeout(
            STORAGE_RENEWAL_STOP_DEADLINE,
            self.coordination.renew_work_lease(
                "o3k-native-storage-controller",
                &self.controller_id,
                &self.controller_epoch,
                fencing_token,
                STORAGE_LEASE_TTL,
            ),
        )
        .await;
        match renewed {
            Ok(Ok(true)) => Ok(()),
            Ok(Ok(false)) | Ok(Err(_)) | Err(_) => {
                if let Some(attempt) = attempt.as_ref() {
                    attempt.valid.store(false, Ordering::Release);
                }
                Err(o3k_reconciler::storage_workflow::StorageWorkflowError::StaleControllerFence)
            }
        }
    }

    async fn end(
        &self,
        controller_epoch: u64,
    ) -> Result<(), o3k_reconciler::storage_workflow::StorageWorkflowError> {
        if controller_epoch != self.intent_epoch {
            return Err(
                o3k_reconciler::storage_workflow::StorageWorkflowError::StaleControllerFence,
            );
        }
        let Ok(mut attempt_slot) =
            tokio::time::timeout(STORAGE_RENEWAL_STOP_DEADLINE, self.attempt.lock()).await
        else {
            return Err(
                o3k_reconciler::storage_workflow::StorageWorkflowError::StaleControllerFence,
            );
        };
        let Some(attempt) = attempt_slot.as_mut() else {
            return Ok(());
        };
        if attempt.renewal_failed || attempt.acquisition_pending {
            return Err(
                o3k_reconciler::storage_workflow::StorageWorkflowError::StaleControllerFence,
            );
        }
        attempt.valid.store(false, Ordering::Release);
        if let Some(stop) = attempt.stop.take() {
            let _ = stop.send(());
        }
        if let Some(renewal) = attempt.renewal.as_mut() {
            match tokio::time::timeout(STORAGE_RENEWAL_STOP_DEADLINE, renewal).await {
                Ok(Ok(())) => attempt.renewal = None,
                Ok(Err(_)) => {
                    attempt.renewal = None;
                    attempt.renewal_failed = true;
                    return Err(o3k_reconciler::storage_workflow::StorageWorkflowError::StaleControllerFence);
                }
                Err(_) => {
                    // Keep the join handle in the attempt if this future is
                    // cancelled or times out. Dropping it would detach the
                    // renewal task while releasing the execution lock.
                    return Err(
                        o3k_reconciler::storage_workflow::StorageWorkflowError::StaleControllerFence,
                    );
                }
            }
        }
        let token = attempt.fencing_token;
        let release_result = tokio::time::timeout(
            STORAGE_RENEWAL_STOP_DEADLINE,
            self.coordination.release_work_lease(
                "o3k-native-storage-controller",
                &self.controller_id,
                &self.controller_epoch,
                token,
            ),
        )
        .await;
        match release_result {
            Ok(Ok(true)) => {
                attempt.release_confirmed = true;
                attempt_slot.take();
                Ok(())
            }
            Ok(Ok(false)) | Ok(Err(_)) | Err(_) => {
                // A failed response may follow a committed release. Observe
                // the durable lease before deciding whether the local lock
                // can be dropped. Unknown ownership keeps the attempt and
                // execution lock live, so composition drain fails closed.
                match tokio::time::timeout(
                    STORAGE_RENEWAL_STOP_DEADLINE,
                    self.coordination
                        .inspect_work_lease("o3k-native-storage-controller"),
                )
                .await
                {
                    Ok(Ok(Some(current)))
                        if current.fencing_token != token
                            || current.owner_controller_id != self.controller_id
                            || current.owner_controller_epoch != self.controller_epoch =>
                    {
                        attempt.release_confirmed = true;
                        attempt_slot.take();
                        Ok(())
                    }
                    Ok(Ok(None)) => {
                        attempt.release_confirmed = true;
                        attempt_slot.take();
                        Ok(())
                    }
                    Ok(Ok(Some(_))) | Ok(Err(_)) | Err(_) => Err(
                        o3k_reconciler::storage_workflow::StorageWorkflowError::StaleControllerFence,
                    ),
                }
            }
        }
    }
}

pub(crate) struct LocalComputeAttachmentExecutor {
    pub(crate) compute: Arc<o3k_compute::ComputeService>,
}

#[async_trait]
impl o3k_reconciler::storage_workflow::ComputeAttachmentExecutor
    for LocalComputeAttachmentExecutor
{
    async fn attach(
        &self,
        attachment: &o3k_domain::VolumeAttachment,
        prepared: &o3k_storage::PreparedAttachment,
    ) -> Result<(), o3k_reconciler::storage_workflow::ComputeAttachmentError> {
        let device = BlockDeviceAttachment {
            volume_id: attachment.volume_id.to_string(),
            attachment_id: attachment.id.to_string(),
            driver_volume_type: "local".to_owned(),
            target_iqn: None,
            target_portal: None,
            target_lun: None,
            local_path: Some(prepared.device_path().to_owned()),
            device_path: None,
            multipath: false,
            initiator: None,
            auth_method: None,
            auth_username: None,
            auth_password: None,
        };
        self.compute
            .provider()
            .attach_block_device(attachment.server_id, &device)
            .await
            .map(|_| ())
            .map_err(|error| {
                if error.is_unknown_outcome() {
                    o3k_reconciler::storage_workflow::ComputeAttachmentError::UnknownOutcome
                } else {
                    o3k_reconciler::storage_workflow::ComputeAttachmentError::Failed
                }
            })
    }

    async fn inspect(
        &self,
        attachment: &o3k_domain::VolumeAttachment,
    ) -> Result<bool, o3k_reconciler::storage_workflow::ComputeAttachmentError> {
        self.compute
            .provider()
            .observe_block_device(attachment.server_id, &attachment.volume_id.to_string())
            .await
            .map(|observation| observation.is_some_and(|value| value.attached))
            .map_err(|error| {
                if error.is_unknown_outcome() {
                    o3k_reconciler::storage_workflow::ComputeAttachmentError::UnknownOutcome
                } else {
                    o3k_reconciler::storage_workflow::ComputeAttachmentError::Failed
                }
            })
    }

    async fn detach(
        &self,
        attachment: &o3k_domain::VolumeAttachment,
    ) -> Result<(), o3k_reconciler::storage_workflow::ComputeAttachmentError> {
        let device = BlockDeviceAttachment {
            volume_id: attachment.volume_id.to_string(),
            attachment_id: attachment.id.to_string(),
            driver_volume_type: "local".to_owned(),
            target_iqn: None,
            target_portal: None,
            target_lun: None,
            local_path: None,
            device_path: None,
            multipath: false,
            initiator: None,
            auth_method: None,
            auth_username: None,
            auth_password: None,
        };
        self.compute
            .provider()
            .detach_block_device(attachment.server_id, &device)
            .await
            .map(|_| ())
            .map_err(|error| {
                if error.is_unknown_outcome() {
                    o3k_reconciler::storage_workflow::ComputeAttachmentError::UnknownOutcome
                } else {
                    o3k_reconciler::storage_workflow::ComputeAttachmentError::Failed
                }
            })
    }
}

pub(crate) struct NativeStorageAttachmentWorkflow {
    pub(crate) store: Arc<o3k_store::O3kStore>,
    pub(crate) controller_epoch: u64,
    pub(crate) workflow: o3k_reconciler::storage_workflow::StorageAttachmentWorkflow<
        o3k_store::O3kStore,
        o3k_storage::LvmStorageProvider,
        LocalComputeAttachmentExecutor,
        LocalStorageFence,
    >,
}

// Native LVM execution is intentionally in-process in this bounded profile;
// there is no independently restartable storage-agent session to register.
// The durable controller work lease above is the real storage mutation fence.
// This protocol value is therefore only the required target-agent field and
// must never be treated as storage-agent ownership or restart identity.
const LOCAL_STORAGE_TARGET_AGENT_EPOCH: u64 = 1;

#[async_trait]
impl o3k_api::NativeAttachmentWorkflow for NativeStorageAttachmentWorkflow {
    async fn attach(&self, attachment_id: Uuid) -> Result<(), String> {
        let record = self
            .store
            .get_volume_attachment_v1(attachment_id)
            .await
            .map_err(|error| error.to_string())?
            .ok_or_else(|| "native attachment disappeared".to_owned())?;
        let attachment = record.attachment;
        let intent = native_storage_intent(&attachment, "attach", self.controller_epoch);
        self.workflow
            .attach(intent)
            .await
            .map_err(|error| format!("{error:?}"))?;
        Ok(())
    }

    async fn detach(&self, attachment_id: Uuid) -> Result<(), String> {
        let record = self
            .store
            .get_volume_attachment_v1(attachment_id)
            .await
            .map_err(|error| error.to_string())?
            .ok_or_else(|| "native attachment disappeared".to_owned())?;
        let attachment = record.attachment;
        self.workflow
            .detach(native_storage_intent(
                &attachment,
                "detach",
                self.controller_epoch,
            ))
            .await
            .map_err(|error| format!("{error:?}"))?;
        Ok(())
    }

    async fn recover(&self) -> Result<(), String> {
        let mut first_error = None;
        for command in self
            .store
            .list_recoverable_agent_commands()
            .await
            .map_err(|error| error.to_string())?
        {
            let Ok(_envelope) =
                serde_json::from_slice::<o3k_domain::StorageCommandEnvelope>(&command.payload)
            else {
                continue;
            };
            if self
                .store
                .get_volume_attachment_v1(command.resource_id)
                .await
                .map_err(|error| error.to_string())?
                .is_none()
            {
                continue;
            }
            // The envelope epoch is immutable request provenance.  Recovery
            // is executed by the current controller session after the
            // storage work lease has authorized a takeover.
            if let Err(error) = self
                .workflow
                .reconcile(&command.command_id, self.controller_epoch)
                .await
            {
                // Recovery is per command.  A busy/unknown/provider-failed
                // attachment must not head-of-line block unrelated durable
                // commands in the same startup pass; the next scheduled pass
                // retries the unresolved command automatically.
                tracing::warn!(
                    command_id = %command.command_id,
                    %error,
                    "native storage command recovery deferred"
                );
                if first_error.is_none() {
                    first_error = Some(error.to_string());
                }
            }
        }
        first_error.map_or(Ok(()), Err)
    }
}

pub(crate) fn native_storage_intent(
    attachment: &o3k_domain::VolumeAttachment,
    operation: &str,
    controller_epoch: u64,
) -> o3k_reconciler::storage_workflow::StorageAttachmentIntent {
    o3k_reconciler::storage_workflow::StorageAttachmentIntent {
        attachment_id: attachment.id,
        volume_id: attachment.volume_id,
        server_id: attachment.server_id,
        project_id: attachment.project_id.clone(),
        access_mode: attachment.access_mode,
        delete_on_termination: attachment.delete_on_termination,
        controller_epoch,
        target_agent_id: "local".to_owned(),
        target_agent_epoch: LOCAL_STORAGE_TARGET_AGENT_EPOCH,
        idempotency_key: format!("native-{operation}:{}", attachment.id),
        trace_id: format!("native-{operation}:{}", attachment.id),
        deadline: "2099-01-01T00:00:00.000".to_owned(),
    }
}

pub(crate) fn storage_intent_epoch(epoch: &o3k_store::ControllerEpoch) -> u64 {
    epoch.0.bytes().fold(0xcbf29ce484222325, |hash, byte| {
        hash.wrapping_mul(0x100000001b3)
            .wrapping_add(u64::from(byte))
    })
}

#[cfg(test)]
mod storage_lease_drain_tests {
    use super::*;
    use sqlx::Connection;

    async fn controlled_fence() -> Result<
        (
            LocalStorageFence,
            Arc<super::super::drain_test_support::ControlledCoordination>,
            PathBuf,
        ),
        Box<dyn std::error::Error>,
    > {
        let root = std::env::temp_dir().join(format!("o3kd-storage-controlled-{}", Uuid::now_v7()));
        std::fs::create_dir(&root)?;
        let store = Arc::new(o3k_store::O3kStore::connect_sqlite_memory().await?);
        let coordination = super::super::drain_test_support::ControlledCoordination::new(store);
        let fence = LocalStorageFence {
            coordination: coordination.clone(),
            controller_id: o3k_store::ControllerId::new("controlled-storage"),
            controller_epoch: o3k_store::ControllerEpoch::new("epoch-1"),
            intent_epoch: 1,
            execution_lock_path: root.join("storage.execution.lock"),
            attempt: Arc::new(tokio::sync::Mutex::new(None)),
            quiescing: Arc::new(AtomicBool::new(false)),
        };
        o3k_reconciler::storage_workflow::StorageControllerFence::begin(&fence, 1).await?;
        Ok((fence, coordination, root))
    }

    #[tokio::test]
    async fn storage_end_waits_for_in_flight_database_renewal()
    -> Result<(), Box<dyn std::error::Error>> {
        use o3k_reconciler::storage_workflow::StorageControllerFence;
        let (fence, coordination, root) = controlled_fence().await?;
        coordination.renew.block();
        tokio::time::timeout(
            Duration::from_secs(7),
            coordination.renew.entered.notified(),
        )
        .await?;
        fence
            .quiesce(Duration::from_secs(1))
            .await
            .map_err(|_| "quiesce failed")?;
        let mut end = Box::pin(fence.end(1));
        std::future::poll_fn(|cx| {
            assert!(std::future::Future::poll(end.as_mut(), cx).is_pending());
            std::task::Poll::Ready(())
        })
        .await;
        assert_eq!(coordination.renew.active.load(Ordering::Acquire), 1);
        let contender = OpenOptions::new()
            .read(true)
            .write(true)
            .open(&fence.execution_lock_path)?;
        assert!(flock(&contender, FlockOperation::NonBlockingLockExclusive).is_err());
        coordination.renew.release();
        end.await?;
        assert_eq!(coordination.renew.active.load(Ordering::Acquire), 0);
        assert!(fence.assert_current(1).await.is_err());
        assert!(fence.begin(1).await.is_err());
        assert!(flock(&contender, FlockOperation::NonBlockingLockExclusive).is_ok());
        assert_eq!(coordination.renew.active.load(Ordering::Acquire), 0);
        std::fs::remove_dir_all(root)?;
        Ok(())
    }

    #[tokio::test]
    async fn storage_assert_and_end_serialize_at_the_database_boundary()
    -> Result<(), Box<dyn std::error::Error>> {
        use o3k_reconciler::storage_workflow::StorageControllerFence;
        let (fence, coordination, root) = controlled_fence().await?;
        coordination.renew.block();
        let mut assertion = Box::pin(fence.assert_current(1));
        tokio::select! {
            result = &mut assertion => return Err(format!("assertion escaped gate: {result:?}").into()),
            () = coordination.renew.entered.notified() => {}
        }
        let mut end = Box::pin(fence.end(1));
        std::future::poll_fn(|cx| {
            assert!(std::future::Future::poll(end.as_mut(), cx).is_pending());
            std::task::Poll::Ready(())
        })
        .await;
        assert!(fence.attempt.try_lock().is_err());
        coordination.renew.release();
        assertion.await?;
        end.await?;
        assert_eq!(coordination.renew.active.load(Ordering::Acquire), 0);
        assert!(fence.attempt.lock().await.is_none());
        std::fs::remove_dir_all(root)?;
        Ok(())
    }

    #[tokio::test]
    async fn failed_storage_renewal_is_not_repolled_or_unlocked()
    -> Result<(), Box<dyn std::error::Error>> {
        use o3k_reconciler::storage_workflow::StorageControllerFence;
        let (fence, _coordination, root) = controlled_fence().await?;
        {
            let attempt = fence.attempt.lock().await;
            if let Some(renewal) = attempt
                .as_ref()
                .and_then(|attempt| attempt.renewal.as_ref())
            {
                renewal.abort();
            }
        }
        tokio::time::timeout(Duration::from_secs(2), async {
            loop {
                if fence
                    .attempt
                    .lock()
                    .await
                    .as_ref()
                    .and_then(|attempt| attempt.renewal.as_ref())
                    .is_some_and(|task| task.is_finished())
                {
                    break;
                }
                tokio::task::yield_now().await;
            }
        })
        .await?;
        assert!(fence.end(1).await.is_err());
        assert!(fence.end(1).await.is_err());
        let contender = OpenOptions::new()
            .read(true)
            .write(true)
            .open(&fence.execution_lock_path)?;
        assert!(flock(&contender, FlockOperation::NonBlockingLockExclusive).is_err());
        std::fs::remove_dir_all(root)?;
        Ok(())
    }

    #[tokio::test]
    async fn unknown_storage_release_retains_protection() -> Result<(), Box<dyn std::error::Error>>
    {
        use o3k_reconciler::storage_workflow::StorageControllerFence;
        let (fence, coordination, root) = controlled_fence().await?;
        coordination.unknown_release.store(true, Ordering::Release);
        assert!(fence.end(1).await.is_err());
        assert!(fence.attempt.lock().await.is_some());
        let contender = OpenOptions::new()
            .read(true)
            .write(true)
            .open(&fence.execution_lock_path)?;
        assert!(flock(&contender, FlockOperation::NonBlockingLockExclusive).is_err());
        coordination.unknown_release.store(false, Ordering::Release);
        fence.end(1).await?;
        assert!(flock(&contender, FlockOperation::NonBlockingLockExclusive).is_ok());
        std::fs::remove_dir_all(root)?;
        Ok(())
    }

    #[tokio::test]
    async fn cancelled_acquisition_is_recorded_and_keeps_execution_lock()
    -> Result<(), Box<dyn std::error::Error>> {
        let root = std::env::temp_dir().join(format!("o3kd-storage-acquire-{}", Uuid::now_v7()));
        std::fs::create_dir(&root)?;
        let store = Arc::new(o3k_store::unified::O3kStore::connect_sqlite_memory().await?);
        let lock_path = root.join("storage.execution.lock");
        let fence = LocalStorageFence {
            coordination: store,
            controller_id: o3k_store::ControllerId::new("cancelled-acquire"),
            controller_epoch: o3k_store::ControllerEpoch::new("epoch-1"),
            intent_epoch: 1,
            execution_lock_path: lock_path.clone(),
            attempt: Arc::new(tokio::sync::Mutex::new(None)),
            quiescing: Arc::new(AtomicBool::new(false)),
        };
        let mut begin =
            Box::pin(o3k_reconciler::storage_workflow::StorageControllerFence::begin(&fence, 1));
        std::future::poll_fn(|cx| {
            assert!(std::future::Future::poll(begin.as_mut(), cx).is_pending());
            std::task::Poll::Ready(())
        })
        .await;
        drop(begin);
        assert!(
            fence
                .attempt
                .lock()
                .await
                .as_ref()
                .is_some_and(|attempt| attempt.acquisition_pending)
        );
        assert!(
            o3k_reconciler::storage_workflow::StorageControllerFence::end(&fence, 1)
                .await
                .is_err()
        );
        let contender = OpenOptions::new().read(true).write(true).open(&lock_path)?;
        assert!(flock(&contender, FlockOperation::NonBlockingLockExclusive).is_err());
        drop(fence);
        assert!(flock(&contender, FlockOperation::NonBlockingLockExclusive).is_err());
        std::fs::remove_dir_all(root)?;
        Ok(())
    }

    #[tokio::test]
    async fn end_serializes_with_assert_and_joins_the_renewal_task()
    -> Result<(), Box<dyn std::error::Error>> {
        let store = Arc::new(o3k_store::unified::O3kStore::connect_sqlite_memory().await?);
        let coordination: Arc<dyn o3k_store::CoordinationRepository> = store;
        let root = std::env::temp_dir().join(format!("o3kd-storage-drain-{}", Uuid::now_v7()));
        std::fs::create_dir(&root)?;
        let fence = LocalStorageFence {
            coordination,
            controller_id: o3k_store::ControllerId::new("storage-drain-test"),
            controller_epoch: o3k_store::ControllerEpoch::new("epoch-1"),
            intent_epoch: 1,
            execution_lock_path: root.join("storage.execution.lock"),
            attempt: Arc::new(tokio::sync::Mutex::new(None)),
            quiescing: Arc::new(AtomicBool::new(false)),
        };

        o3k_reconciler::storage_workflow::StorageControllerFence::begin(&fence, 1).await?;
        {
            let attempt = fence.attempt.lock().await;
            let attempt = attempt.as_ref().ok_or("lease attempt missing")?;
            assert!(
                attempt
                    .renewal
                    .as_ref()
                    .is_some_and(|task| !task.is_finished())
            );
        }

        let (_assert_result, end_result) = tokio::join!(
            o3k_reconciler::storage_workflow::StorageControllerFence::assert_current(&fence, 1),
            o3k_reconciler::storage_workflow::StorageControllerFence::end(&fence, 1),
        );
        end_result?;
        assert!(fence.attempt.lock().await.is_none());
        fence
            .quiesce(Duration::from_secs(1))
            .await
            .map_err(|_| "storage fence quiesce timed out")?;
        assert!(
            o3k_reconciler::storage_workflow::StorageControllerFence::begin(&fence, 1)
                .await
                .is_err(),
            "quiesced storage fence must reject a new lease attempt"
        );
        std::fs::remove_dir_all(root)?;
        Ok(())
    }

    #[tokio::test]
    async fn unknown_release_keeps_the_execution_lock_until_observed_safe()
    -> Result<(), Box<dyn std::error::Error>> {
        let root = std::env::temp_dir().join(format!("o3kd-storage-release-{}", Uuid::now_v7()));
        std::fs::create_dir(&root)?;
        let database_path = root.join("state.sqlite");
        let store =
            Arc::new(o3k_store::unified::O3kStore::connect_sqlite_file(&database_path).await?);
        let coordination: Arc<dyn o3k_store::CoordinationRepository> = store;
        let lock_path = root.join("storage.execution.lock");
        let fence = LocalStorageFence {
            coordination,
            controller_id: o3k_store::ControllerId::new("storage-release-test"),
            controller_epoch: o3k_store::ControllerEpoch::new("epoch-1"),
            intent_epoch: 1,
            execution_lock_path: lock_path.clone(),
            attempt: Arc::new(tokio::sync::Mutex::new(None)),
            quiescing: Arc::new(AtomicBool::new(false)),
        };
        o3k_reconciler::storage_workflow::StorageControllerFence::begin(&fence, 1).await?;

        let mut connection =
            sqlx::SqliteConnection::connect(&format!("sqlite://{}", database_path.display()))
                .await?;
        sqlx::query("CREATE TRIGGER block_storage_lease_release BEFORE DELETE ON work_leases WHEN OLD.work_key = 'o3k-native-storage-controller' BEGIN SELECT RAISE(ABORT, 'controlled release failure'); END")
            .execute(&mut connection)
            .await?;
        assert!(
            o3k_reconciler::storage_workflow::StorageControllerFence::end(&fence, 1)
                .await
                .is_err(),
            "a failed release with the same durable lease must fail closed"
        );
        assert!(fence.attempt.lock().await.is_some());
        let probe = OpenOptions::new()
            .create(true)
            .truncate(false)
            .read(true)
            .write(true)
            .open(&lock_path)?;
        assert!(flock(&probe, FlockOperation::NonBlockingLockExclusive).is_err());

        sqlx::query("DROP TRIGGER block_storage_lease_release")
            .execute(&mut connection)
            .await?;
        drop(connection);
        o3k_reconciler::storage_workflow::StorageControllerFence::end(&fence, 1).await?;
        assert!(fence.attempt.lock().await.is_none());
        drop(fence);
        drop(probe);
        std::fs::remove_dir_all(root)?;
        Ok(())
    }
}
