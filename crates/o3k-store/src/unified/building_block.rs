use async_trait::async_trait;

use super::O3kStore;
use crate::{BuildingBlockRecord, BuildingBlockRepository, StoreError};

#[async_trait]
impl BuildingBlockRepository for O3kStore {
    async fn get_building_block(
        &self,
        id: &str,
    ) -> Result<Option<BuildingBlockRecord>, StoreError> {
        match self {
            Self::Sqlite(s) => s.get_building_block(id).await,
            Self::Postgres(s) => s.get_building_block(id).await,
        }
    }

    async fn list_building_blocks(&self) -> Result<Vec<BuildingBlockRecord>, StoreError> {
        match self {
            Self::Sqlite(s) => s.list_building_blocks().await,
            Self::Postgres(s) => s.list_building_blocks().await,
        }
    }

    async fn upsert_building_block(
        &self,
        block: &BuildingBlockRecord,
        expected_generation: Option<u64>,
    ) -> Result<BuildingBlockRecord, StoreError> {
        match self {
            Self::Sqlite(s) => s.upsert_building_block(block, expected_generation).await,
            Self::Postgres(s) => s.upsert_building_block(block, expected_generation).await,
        }
    }

    async fn upsert_building_block_with_audit(
        &self,
        block: &BuildingBlockRecord,
        expected_generation: Option<u64>,
        audit: &crate::AuditEventRecord,
    ) -> Result<BuildingBlockRecord, StoreError> {
        match self {
            Self::Sqlite(s) => {
                s.upsert_building_block_with_audit(block, expected_generation, audit)
                    .await
            }
            Self::Postgres(s) => {
                s.upsert_building_block_with_audit(block, expected_generation, audit)
                    .await
            }
        }
    }
}

impl O3kStore {
    pub async fn get_building_block(
        &self,
        id: &str,
    ) -> Result<Option<BuildingBlockRecord>, StoreError> {
        BuildingBlockRepository::get_building_block(self, id).await
    }
    pub async fn list_building_blocks(&self) -> Result<Vec<BuildingBlockRecord>, StoreError> {
        BuildingBlockRepository::list_building_blocks(self).await
    }
    pub async fn upsert_building_block(
        &self,
        block: &BuildingBlockRecord,
        expected_generation: Option<u64>,
    ) -> Result<BuildingBlockRecord, StoreError> {
        BuildingBlockRepository::upsert_building_block(self, block, expected_generation).await
    }
    pub async fn upsert_building_block_with_audit(
        &self,
        block: &BuildingBlockRecord,
        expected_generation: Option<u64>,
        audit: &crate::AuditEventRecord,
    ) -> Result<BuildingBlockRecord, StoreError> {
        BuildingBlockRepository::upsert_building_block_with_audit(
            self,
            block,
            expected_generation,
            audit,
        )
        .await
    }
}
