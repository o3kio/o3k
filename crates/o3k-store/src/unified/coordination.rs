use async_trait::async_trait;

use crate::{
    ControllerEpoch, ControllerId, ControllerSession, CoordinationRepository, FencingToken,
    LeaseAcquireOutcome, StoreError, WorkLease,
};

use super::O3kStore;

#[async_trait]
impl CoordinationRepository for O3kStore {
    async fn register_controller_session(
        &self,
        session: &ControllerSession,
        ttl: std::time::Duration,
    ) -> Result<(), StoreError> {
        match self {
            Self::Sqlite(s) => s.register_controller_session(session, ttl).await,
            Self::Postgres(s) => s.register_controller_session(session, ttl).await,
        }
    }

    async fn heartbeat_controller_session(
        &self,
        controller_id: &ControllerId,
        controller_epoch: &ControllerEpoch,
        ttl: std::time::Duration,
    ) -> Result<bool, StoreError> {
        match self {
            Self::Sqlite(s) => {
                s.heartbeat_controller_session(controller_id, controller_epoch, ttl)
                    .await
            }
            Self::Postgres(s) => {
                s.heartbeat_controller_session(controller_id, controller_epoch, ttl)
                    .await
            }
        }
    }

    async fn drain_controller_session(
        &self,
        controller_id: &ControllerId,
        controller_epoch: &ControllerEpoch,
    ) -> Result<bool, StoreError> {
        match self {
            Self::Sqlite(s) => {
                s.drain_controller_session(controller_id, controller_epoch)
                    .await
            }
            Self::Postgres(s) => {
                s.drain_controller_session(controller_id, controller_epoch)
                    .await
            }
        }
    }

    async fn acquire_work_lease_once(
        &self,
        work_key: &str,
        work_kind: &str,
        controller_id: &ControllerId,
        controller_epoch: &ControllerEpoch,
        ttl: std::time::Duration,
    ) -> Result<LeaseAcquireOutcome, StoreError> {
        match self {
            Self::Sqlite(s) => {
                s.acquire_work_lease(work_key, work_kind, controller_id, controller_epoch, ttl)
                    .await
            }
            Self::Postgres(s) => {
                s.acquire_work_lease(work_key, work_kind, controller_id, controller_epoch, ttl)
                    .await
            }
        }
    }

    async fn renew_work_lease(
        &self,
        work_key: &str,
        controller_id: &ControllerId,
        controller_epoch: &ControllerEpoch,
        fencing_token: FencingToken,
        ttl: std::time::Duration,
    ) -> Result<bool, StoreError> {
        match self {
            Self::Sqlite(s) => {
                s.renew_work_lease(
                    work_key,
                    controller_id,
                    controller_epoch,
                    fencing_token,
                    ttl,
                )
                .await
            }
            Self::Postgres(s) => {
                s.renew_work_lease(
                    work_key,
                    controller_id,
                    controller_epoch,
                    fencing_token,
                    ttl,
                )
                .await
            }
        }
    }

    async fn release_work_lease(
        &self,
        work_key: &str,
        controller_id: &ControllerId,
        controller_epoch: &ControllerEpoch,
        fencing_token: FencingToken,
    ) -> Result<bool, StoreError> {
        match self {
            Self::Sqlite(s) => {
                s.release_work_lease(work_key, controller_id, controller_epoch, fencing_token)
                    .await
            }
            Self::Postgres(s) => {
                s.release_work_lease(work_key, controller_id, controller_epoch, fencing_token)
                    .await
            }
        }
    }

    async fn relinquish_work_lease_preserving_fence(
        &self,
        work_key: &str,
        controller_id: &ControllerId,
        controller_epoch: &ControllerEpoch,
        fencing_token: FencingToken,
    ) -> Result<bool, StoreError> {
        match self {
            Self::Sqlite(s) => {
                s.relinquish_work_lease_preserving_fence(
                    work_key,
                    controller_id,
                    controller_epoch,
                    fencing_token,
                )
                .await
            }
            Self::Postgres(s) => {
                s.relinquish_work_lease_preserving_fence(
                    work_key,
                    controller_id,
                    controller_epoch,
                    fencing_token,
                )
                .await
            }
        }
    }

    async fn inspect_work_lease(&self, work_key: &str) -> Result<Option<WorkLease>, StoreError> {
        match self {
            Self::Sqlite(s) => s.inspect_work_lease(work_key).await,
            Self::Postgres(s) => s.inspect_work_lease(work_key).await,
        }
    }

    async fn list_active_controller_sessions(&self) -> Result<Vec<ControllerSession>, StoreError> {
        match self {
            Self::Sqlite(s) => s.list_active_controller_sessions().await,
            Self::Postgres(s) => s.list_active_controller_sessions().await,
        }
    }
}
