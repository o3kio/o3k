use super::O3kStore;
use crate::{CloudProfileRecord, CompositionRepository, StoreError};
use async_trait::async_trait;

#[async_trait]
impl CompositionRepository for O3kStore {
    async fn get_cloud_profile(&self, id: &str) -> Result<Option<CloudProfileRecord>, StoreError> {
        match self {
            Self::Sqlite(s) => s.get_cloud_profile(id).await,
            Self::Postgres(s) => s.get_cloud_profile(id).await,
        }
    }
    async fn list_cloud_profiles(&self) -> Result<Vec<CloudProfileRecord>, StoreError> {
        match self {
            Self::Sqlite(s) => s.list_cloud_profiles().await,
            Self::Postgres(s) => s.list_cloud_profiles().await,
        }
    }
    async fn upsert_cloud_profile(
        &self,
        p: &CloudProfileRecord,
        e: Option<u64>,
    ) -> Result<CloudProfileRecord, StoreError> {
        match self {
            Self::Sqlite(s) => s.upsert_cloud_profile(p, e).await,
            Self::Postgres(s) => s.upsert_cloud_profile(p, e).await,
        }
    }
    async fn upsert_cloud_profile_with_audit(
        &self,
        p: &CloudProfileRecord,
        e: Option<u64>,
        audit: &crate::AuditEventRecord,
    ) -> Result<CloudProfileRecord, StoreError> {
        match self {
            Self::Sqlite(s) => s.upsert_cloud_profile_with_audit(p, e, audit).await,
            Self::Postgres(s) => s.upsert_cloud_profile_with_audit(p, e, audit).await,
        }
    }
    async fn delete_cloud_profile(&self, id: &str, e: u64) -> Result<(), StoreError> {
        match self {
            Self::Sqlite(s) => s.delete_cloud_profile(id, e).await,
            Self::Postgres(s) => s.delete_cloud_profile(id, e).await,
        }
    }
}

impl O3kStore {
    pub async fn get_cloud_profile(
        &self,
        id: &str,
    ) -> Result<Option<CloudProfileRecord>, StoreError> {
        CompositionRepository::get_cloud_profile(self, id).await
    }
    pub async fn list_cloud_profiles(&self) -> Result<Vec<CloudProfileRecord>, StoreError> {
        CompositionRepository::list_cloud_profiles(self).await
    }
    pub async fn upsert_cloud_profile(
        &self,
        p: &CloudProfileRecord,
        e: Option<u64>,
    ) -> Result<CloudProfileRecord, StoreError> {
        CompositionRepository::upsert_cloud_profile(self, p, e).await
    }
    pub async fn delete_cloud_profile(&self, id: &str, e: u64) -> Result<(), StoreError> {
        CompositionRepository::delete_cloud_profile(self, id, e).await
    }
}
