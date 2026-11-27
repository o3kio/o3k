use super::O3kStore;
use crate::{
    BootstrapRepository, BootstrapStateRecord, EnrollmentGrantRecord, EnrollmentResultRecord,
    StoreError,
};
use async_trait::async_trait;

#[async_trait]
impl BootstrapRepository for O3kStore {
    async fn get_bootstrap_state(
        &self,
        id: &str,
    ) -> Result<Option<BootstrapStateRecord>, StoreError> {
        match self {
            Self::Sqlite(s) => s.get_bootstrap_state(id).await,
            Self::Postgres(s) => s.get_bootstrap_state(id).await,
        }
    }
    async fn upsert_bootstrap_state(
        &self,
        s: &BootstrapStateRecord,
    ) -> Result<BootstrapStateRecord, StoreError> {
        match self {
            Self::Sqlite(x) => x.upsert_bootstrap_state(s).await,
            Self::Postgres(x) => x.upsert_bootstrap_state(s).await,
        }
    }
    async fn get_enrollment_grant(
        &self,
        id: &str,
    ) -> Result<Option<EnrollmentGrantRecord>, StoreError> {
        match self {
            Self::Sqlite(s) => s.get_enrollment_grant(id).await,
            Self::Postgres(s) => s.get_enrollment_grant(id).await,
        }
    }
    async fn insert_enrollment_grant(&self, g: &EnrollmentGrantRecord) -> Result<(), StoreError> {
        match self {
            Self::Sqlite(s) => s.insert_enrollment_grant(g).await,
            Self::Postgres(s) => s.insert_enrollment_grant(g).await,
        }
    }
    async fn consume_enrollment_grant(
        &self,
        id: &str,
        epoch: &str,
        d: &str,
        n: u64,
    ) -> Result<EnrollmentGrantRecord, StoreError> {
        match self {
            Self::Sqlite(s) => s.consume_enrollment_grant(id, epoch, d, n).await,
            Self::Postgres(s) => s.consume_enrollment_grant(id, epoch, d, n).await,
        }
    }
    async fn complete_enrollment_issue(
        &self,
        result: &EnrollmentResultRecord,
        now: u64,
    ) -> Result<EnrollmentResultRecord, StoreError> {
        match self {
            Self::Sqlite(s) => s.complete_enrollment_issue(result, now).await,
            Self::Postgres(s) => s.complete_enrollment_issue(result, now).await,
        }
    }
    async fn get_enrollment_result(
        &self,
        grant_id: &str,
    ) -> Result<Option<EnrollmentResultRecord>, StoreError> {
        match self {
            Self::Sqlite(s) => s.get_enrollment_result(grant_id).await,
            Self::Postgres(s) => s.get_enrollment_result(grant_id).await,
        }
    }
    async fn consume_enrollment_result(
        &self,
        grant_id: &str,
        token_digest: &str,
        agent_id: &str,
        epoch: &str,
        fingerprint: &str,
        now: u64,
    ) -> Result<EnrollmentResultRecord, StoreError> {
        match self {
            Self::Sqlite(s) => {
                s.consume_enrollment_result(
                    grant_id,
                    token_digest,
                    agent_id,
                    epoch,
                    fingerprint,
                    now,
                )
                .await
            }
            Self::Postgres(s) => {
                s.consume_enrollment_result(
                    grant_id,
                    token_digest,
                    agent_id,
                    epoch,
                    fingerprint,
                    now,
                )
                .await
            }
        }
    }
}
