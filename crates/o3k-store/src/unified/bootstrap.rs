use super::O3kStore;
use crate::{BootstrapRepository, BootstrapStateRecord, EnrollmentGrantRecord, StoreError};
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
        d: &str,
        n: u64,
    ) -> Result<EnrollmentGrantRecord, StoreError> {
        match self {
            Self::Sqlite(s) => s.consume_enrollment_grant(id, d, n).await,
            Self::Postgres(s) => s.consume_enrollment_grant(id, d, n).await,
        }
    }
}
