use async_trait::async_trait;
use sqlx::Row;

use super::SqliteStore;
use crate::{BuildingBlockRecord, BuildingBlockRepository, StoreError};

fn record(row: &sqlx::sqlite::SqliteRow) -> Result<BuildingBlockRecord, StoreError> {
    Ok(BuildingBlockRecord {
        id: row.try_get("block_id").map_err(StoreError::Database)?,
        generation: row
            .try_get::<i64, _>("generation")
            .map_err(StoreError::Database)?
            .try_into()
            .map_err(|_| StoreError::Corrupt("invalid building block generation".into()))?,
        state: row.try_get("state").map_err(StoreError::Database)?,
        execution_identity: row
            .try_get("execution_identity")
            .map_err(StoreError::Database)?,
        resource_provider_ids: row
            .try_get("resource_provider_ids")
            .map_err(StoreError::Database)?,
        failure_domain_id: row
            .try_get("failure_domain_id")
            .map_err(StoreError::Database)?,
        cloud_profile_id: row
            .try_get("cloud_profile_id")
            .map_err(StoreError::Database)?,
        drain_blockers: row
            .try_get("drain_blockers")
            .map_err(StoreError::Database)?,
        updated_at: row.try_get("updated_at").map_err(StoreError::Database)?,
    })
}

impl SqliteStore {
    pub async fn get_building_block(
        &self,
        id: &str,
    ) -> Result<Option<BuildingBlockRecord>, StoreError> {
        sqlx::query("SELECT * FROM building_blocks WHERE block_id=?")
            .bind(id)
            .fetch_optional(&self.pool)
            .await
            .map_err(StoreError::Database)?
            .as_ref()
            .map(record)
            .transpose()
    }

    pub async fn list_building_blocks(&self) -> Result<Vec<BuildingBlockRecord>, StoreError> {
        sqlx::query("SELECT * FROM building_blocks ORDER BY block_id")
            .fetch_all(&self.pool)
            .await
            .map_err(StoreError::Database)?
            .iter()
            .map(record)
            .collect()
    }

    async fn upsert_block(
        &self,
        block: &BuildingBlockRecord,
        expected: Option<u64>,
        audit: Option<&crate::AuditEventRecord>,
    ) -> Result<BuildingBlockRecord, StoreError> {
        let mut tx = self.pool.begin().await.map_err(StoreError::Database)?;
        let current: Option<i64> =
            sqlx::query_scalar("SELECT generation FROM building_blocks WHERE block_id=?")
                .bind(&block.id)
                .fetch_optional(&mut *tx)
                .await
                .map_err(StoreError::Database)?;
        if current.map(|v| v as u64) != expected && !(current.is_none() && expected.is_none()) {
            return Err(StoreError::StaleGeneration);
        }
        sqlx::query("INSERT INTO building_blocks(block_id,generation,state,execution_identity,resource_provider_ids,failure_domain_id,cloud_profile_id,drain_blockers,updated_at) VALUES(?,?,?,?,?,?,?,?,?) ON CONFLICT(block_id) DO UPDATE SET generation=excluded.generation,state=excluded.state,execution_identity=excluded.execution_identity,resource_provider_ids=excluded.resource_provider_ids,failure_domain_id=excluded.failure_domain_id,cloud_profile_id=excluded.cloud_profile_id,drain_blockers=excluded.drain_blockers,updated_at=excluded.updated_at")
            .bind(&block.id)
            .bind(i64::try_from(block.generation).map_err(|_| StoreError::Corrupt("building block generation overflow".into()))?)
            .bind(&block.state)
            .bind(&block.execution_identity)
            .bind(&block.resource_provider_ids)
            .bind(&block.failure_domain_id)
            .bind(&block.cloud_profile_id)
            .bind(&block.drain_blockers)
            .bind(&block.updated_at)
            .execute(&mut *tx)
            .await
            .map_err(StoreError::Database)?;
        if let Some(audit) = audit {
            super::audit_store::insert_audit_event_tx(&mut tx, audit).await?;
        }
        tx.commit().await.map_err(StoreError::Database)?;
        Ok(block.clone())
    }
}

#[async_trait]
impl BuildingBlockRepository for SqliteStore {
    async fn get_building_block(
        &self,
        id: &str,
    ) -> Result<Option<BuildingBlockRecord>, StoreError> {
        self.get_building_block(id).await
    }
    async fn list_building_blocks(&self) -> Result<Vec<BuildingBlockRecord>, StoreError> {
        self.list_building_blocks().await
    }
    async fn upsert_building_block(
        &self,
        block: &BuildingBlockRecord,
        expected: Option<u64>,
    ) -> Result<BuildingBlockRecord, StoreError> {
        self.upsert_block(block, expected, None).await
    }
    async fn upsert_building_block_with_audit(
        &self,
        block: &BuildingBlockRecord,
        expected: Option<u64>,
        audit: &crate::AuditEventRecord,
    ) -> Result<BuildingBlockRecord, StoreError> {
        self.upsert_block(block, expected, Some(audit)).await
    }
}
