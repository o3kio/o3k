use async_trait::async_trait;
use sqlx::Row;

use super::PostgresStore;
use crate::{CloudProfileRecord, CompositionRepository, StoreError};

impl PostgresStore {
    pub async fn get_cloud_profile(
        &self,
        id: &str,
    ) -> Result<Option<CloudProfileRecord>, StoreError> {
        let row = sqlx::query("SELECT profile_id,generation,payload,updated_at FROM cloud_profiles WHERE profile_id=$1").bind(id).fetch_optional(&self.pool).await.map_err(StoreError::Database)?;
        row.map(|r| {
            Ok(CloudProfileRecord {
                profile_id: r.try_get("profile_id").map_err(StoreError::Database)?,
                generation: r
                    .try_get::<i64, _>("generation")
                    .map_err(StoreError::Database)?
                    .try_into()
                    .map_err(|_| StoreError::Corrupt("invalid cloud profile generation".into()))?,
                payload: r.try_get("payload").map_err(StoreError::Database)?,
                updated_at: r.try_get("updated_at").map_err(StoreError::Database)?,
            })
        })
        .transpose()
    }
    pub async fn list_cloud_profiles(&self) -> Result<Vec<CloudProfileRecord>, StoreError> {
        let rows = sqlx::query("SELECT profile_id,generation,payload,updated_at FROM cloud_profiles ORDER BY profile_id").fetch_all(&self.pool).await.map_err(StoreError::Database)?;
        rows.into_iter()
            .map(|r| {
                Ok(CloudProfileRecord {
                    profile_id: r.try_get("profile_id").map_err(StoreError::Database)?,
                    generation: r
                        .try_get::<i64, _>("generation")
                        .map_err(StoreError::Database)?
                        .try_into()
                        .map_err(|_| {
                            StoreError::Corrupt("invalid cloud profile generation".into())
                        })?,
                    payload: r.try_get("payload").map_err(StoreError::Database)?,
                    updated_at: r.try_get("updated_at").map_err(StoreError::Database)?,
                })
            })
            .collect()
    }
    pub async fn upsert_cloud_profile(
        &self,
        p: &CloudProfileRecord,
        expected: Option<u64>,
    ) -> Result<CloudProfileRecord, StoreError> {
        let mut tx = self.pool.begin().await.map_err(StoreError::Database)?;
        let current: Option<i64> = sqlx::query_scalar(
            "SELECT generation FROM cloud_profiles WHERE profile_id=$1 FOR UPDATE",
        )
        .bind(&p.profile_id)
        .fetch_optional(&mut *tx)
        .await
        .map_err(StoreError::Database)?;
        if current.map(|v| v as u64) != expected && !(current.is_none() && expected.is_none()) {
            return Err(StoreError::StaleGeneration);
        }
        sqlx::query("INSERT INTO cloud_profiles(profile_id,generation,payload,updated_at) VALUES($1,$2,$3,$4) ON CONFLICT(profile_id) DO UPDATE SET generation=EXCLUDED.generation,payload=EXCLUDED.payload,updated_at=EXCLUDED.updated_at").bind(&p.profile_id).bind(i64::try_from(p.generation).map_err(|_| StoreError::Corrupt("profile generation overflow".into()))?).bind(&p.payload).bind(&p.updated_at).execute(&mut *tx).await.map_err(StoreError::Database)?;
        tx.commit().await.map_err(StoreError::Database)?;
        Ok(p.clone())
    }
    pub async fn upsert_cloud_profile_with_audit(
        &self,
        p: &CloudProfileRecord,
        expected: Option<u64>,
        audit: &crate::AuditEventRecord,
    ) -> Result<CloudProfileRecord, StoreError> {
        let mut tx = self.pool.begin().await.map_err(StoreError::Database)?;
        let current: Option<i64> = sqlx::query_scalar(
            "SELECT generation FROM cloud_profiles WHERE profile_id=$1 FOR UPDATE",
        )
        .bind(&p.profile_id)
        .fetch_optional(&mut *tx)
        .await
        .map_err(StoreError::Database)?;
        if current.map(|v| v as u64) != expected && !(current.is_none() && expected.is_none()) {
            return Err(StoreError::StaleGeneration);
        }
        sqlx::query("INSERT INTO cloud_profiles(profile_id,generation,payload,updated_at) VALUES($1,$2,$3,$4) ON CONFLICT(profile_id) DO UPDATE SET generation=EXCLUDED.generation,payload=EXCLUDED.payload,updated_at=EXCLUDED.updated_at").bind(&p.profile_id).bind(i64::try_from(p.generation).map_err(|_| StoreError::Corrupt("profile generation overflow".into()))?).bind(&p.payload).bind(&p.updated_at).execute(&mut *tx).await.map_err(StoreError::Database)?;
        super::audit_store::insert_audit_event_tx(&mut tx, audit).await?;
        tx.commit().await.map_err(StoreError::Database)?;
        Ok(p.clone())
    }
    pub async fn delete_cloud_profile(&self, id: &str, expected: u64) -> Result<(), StoreError> {
        let result =
            sqlx::query("DELETE FROM cloud_profiles WHERE profile_id=$1 AND generation=$2")
                .bind(id)
                .bind(
                    i64::try_from(expected)
                        .map_err(|_| StoreError::Corrupt("profile generation overflow".into()))?,
                )
                .execute(&self.pool)
                .await
                .map_err(StoreError::Database)?;
        if result.rows_affected() == 0 {
            return Err(StoreError::StaleGeneration);
        }
        Ok(())
    }
}
#[async_trait]
impl CompositionRepository for PostgresStore {
    async fn get_cloud_profile(&self, id: &str) -> Result<Option<CloudProfileRecord>, StoreError> {
        self.get_cloud_profile(id).await
    }
    async fn list_cloud_profiles(&self) -> Result<Vec<CloudProfileRecord>, StoreError> {
        self.list_cloud_profiles().await
    }
    async fn upsert_cloud_profile(
        &self,
        p: &CloudProfileRecord,
        e: Option<u64>,
    ) -> Result<CloudProfileRecord, StoreError> {
        self.upsert_cloud_profile(p, e).await
    }
    async fn upsert_cloud_profile_with_audit(
        &self,
        p: &CloudProfileRecord,
        e: Option<u64>,
        audit: &crate::AuditEventRecord,
    ) -> Result<CloudProfileRecord, StoreError> {
        self.upsert_cloud_profile_with_audit(p, e, audit).await
    }
    async fn delete_cloud_profile(&self, id: &str, e: u64) -> Result<(), StoreError> {
        self.delete_cloud_profile(id, e).await
    }
}
