//! Controllable coordination calls over the real disposable SQLite adapter.
use async_trait::async_trait;
use o3k_store::*;
use std::sync::{
    Arc,
    atomic::{AtomicBool, AtomicUsize, Ordering},
};
use std::time::Duration;

#[derive(Default)]
pub(super) struct CallGate {
    blocked: AtomicBool,
    pub entered: tokio::sync::Notify,
    resumed: tokio::sync::Notify,
    pub active: AtomicUsize,
}

pub(super) struct ActiveCall<'a>(&'a AtomicUsize);
impl Drop for ActiveCall<'_> {
    fn drop(&mut self) {
        self.0.fetch_sub(1, Ordering::AcqRel);
    }
}
impl CallGate {
    pub fn block(&self) {
        self.blocked.store(true, Ordering::Release);
    }
    pub fn release(&self) {
        self.blocked.store(false, Ordering::Release);
        self.resumed.notify_waiters();
    }
    async fn enter(&self) -> ActiveCall<'_> {
        self.active.fetch_add(1, Ordering::AcqRel);
        let active = ActiveCall(&self.active);
        self.entered.notify_one();
        loop {
            let resumed = self.resumed.notified();
            tokio::pin!(resumed);
            resumed.as_mut().enable();
            if !self.blocked.load(Ordering::Acquire) {
                break;
            }
            resumed.await;
        }
        active
    }
}

pub(super) struct ControlledCoordination {
    pub inner: Arc<dyn CoordinationRepository>,
    pub renew: CallGate,
    pub relinquish: CallGate,
    pub release: CallGate,
    pub session: CallGate,
    pub unknown_release: AtomicBool,
}
impl ControlledCoordination {
    pub fn new(inner: Arc<dyn CoordinationRepository>) -> Arc<Self> {
        Arc::new(Self {
            inner,
            renew: CallGate::default(),
            relinquish: CallGate::default(),
            release: CallGate::default(),
            session: CallGate::default(),
            unknown_release: AtomicBool::new(false),
        })
    }
}

#[async_trait]
impl CoordinationRepository for ControlledCoordination {
    async fn register_controller_session(
        &self,
        session: &ControllerSession,
        ttl: Duration,
    ) -> Result<(), StoreError> {
        self.inner.register_controller_session(session, ttl).await
    }
    async fn heartbeat_controller_session(
        &self,
        id: &ControllerId,
        epoch: &ControllerEpoch,
        ttl: Duration,
    ) -> Result<bool, StoreError> {
        self.inner
            .heartbeat_controller_session(id, epoch, ttl)
            .await
    }
    async fn drain_controller_session(
        &self,
        id: &ControllerId,
        epoch: &ControllerEpoch,
    ) -> Result<bool, StoreError> {
        let _active = self.session.enter().await;
        self.inner.drain_controller_session(id, epoch).await
    }
    async fn acquire_work_lease_once(
        &self,
        key: &str,
        kind: &str,
        id: &ControllerId,
        epoch: &ControllerEpoch,
        ttl: Duration,
    ) -> Result<LeaseAcquireOutcome, StoreError> {
        self.inner
            .acquire_work_lease_once(key, kind, id, epoch, ttl)
            .await
    }
    async fn renew_work_lease(
        &self,
        key: &str,
        id: &ControllerId,
        epoch: &ControllerEpoch,
        token: FencingToken,
        ttl: Duration,
    ) -> Result<bool, StoreError> {
        let _active = self.renew.enter().await;
        self.inner
            .renew_work_lease(key, id, epoch, token, ttl)
            .await
    }
    async fn release_work_lease(
        &self,
        key: &str,
        id: &ControllerId,
        epoch: &ControllerEpoch,
        token: FencingToken,
    ) -> Result<bool, StoreError> {
        let _active = self.release.enter().await;
        if self.unknown_release.load(Ordering::Acquire) {
            return Err(StoreError::WriterDrainUnavailable);
        }
        self.inner.release_work_lease(key, id, epoch, token).await
    }
    async fn relinquish_work_lease_preserving_fence(
        &self,
        key: &str,
        id: &ControllerId,
        epoch: &ControllerEpoch,
        token: FencingToken,
    ) -> Result<bool, StoreError> {
        let _active = self.relinquish.enter().await;
        self.inner
            .relinquish_work_lease_preserving_fence(key, id, epoch, token)
            .await
    }
    async fn inspect_work_lease(&self, key: &str) -> Result<Option<WorkLease>, StoreError> {
        if self.unknown_release.load(Ordering::Acquire) {
            return Err(StoreError::WriterDrainUnavailable);
        }
        self.inner.inspect_work_lease(key).await
    }
    async fn list_active_controller_sessions(&self) -> Result<Vec<ControllerSession>, StoreError> {
        self.inner.list_active_controller_sessions().await
    }
}
