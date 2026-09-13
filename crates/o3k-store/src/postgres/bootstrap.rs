use async_trait::async_trait;
use sqlx::Row;

use super::PostgresStore;
use crate::{BootstrapRepository, BootstrapStateRecord, EnrollmentGrantRecord, StoreError};

fn state(row: sqlx::postgres::PgRow) -> Result<BootstrapStateRecord, StoreError> {
    Ok(BootstrapStateRecord {
        state_id: row.try_get("state_id").map_err(StoreError::Database)?,
        generation: row
            .try_get::<i64, _>("generation")
            .map_err(StoreError::Database)?
            .try_into()
            .map_err(|_| StoreError::Corrupt("bootstrap generation overflow".into()))?,
        phase: row.try_get("phase").map_err(StoreError::Database)?,
        cloud_identity_id: row
            .try_get("cloud_identity_id")
            .map_err(StoreError::Database)?,
        cloud_profile_id: row
            .try_get("cloud_profile_id")
            .map_err(StoreError::Database)?,
        enrolled_agents: row
            .try_get("enrolled_agents")
            .map_err(StoreError::Database)?,
        updated_at: row.try_get("updated_at").map_err(StoreError::Database)?,
    })
}
fn grant(row: sqlx::postgres::PgRow) -> Result<EnrollmentGrantRecord, StoreError> {
    Ok(EnrollmentGrantRecord {
        grant_id: row.try_get("grant_id").map_err(StoreError::Database)?,
        agent_id: row.try_get("agent_id").map_err(StoreError::Database)?,
        token_digest: row.try_get("token_digest").map_err(StoreError::Database)?,
        issued_at_unix_ms: row
            .try_get::<i64, _>("issued_at_unix_ms")
            .map_err(StoreError::Database)?
            .try_into()
            .map_err(|_| StoreError::Corrupt("grant timestamp overflow".into()))?,
        expires_at_unix_ms: row
            .try_get::<i64, _>("expires_at_unix_ms")
            .map_err(StoreError::Database)?
            .try_into()
            .map_err(|_| StoreError::Corrupt("grant timestamp overflow".into()))?,
        used_at_unix_ms: row
            .try_get::<Option<i64>, _>("used_at_unix_ms")
            .map_err(StoreError::Database)?
            .map(|v| {
                v.try_into()
                    .map_err(|_| StoreError::Corrupt("grant timestamp overflow".into()))
            })
            .transpose()?,
    })
}
const STATE_COLUMNS: &str =
    "state_id,generation,phase,cloud_identity_id,cloud_profile_id,enrolled_agents,updated_at";
const GRANT_COLUMNS: &str =
    "grant_id,agent_id,token_digest,issued_at_unix_ms,expires_at_unix_ms,used_at_unix_ms";

impl PostgresStore {
    pub async fn get_bootstrap_state(
        &self,
        id: &str,
    ) -> Result<Option<BootstrapStateRecord>, StoreError> {
        sqlx::query(&format!(
            "SELECT {STATE_COLUMNS} FROM bootstrap_state WHERE state_id=$1"
        ))
        .bind(id)
        .fetch_optional(&self.pool)
        .await
        .map_err(StoreError::Database)?
        .map(state)
        .transpose()
    }
    pub async fn upsert_bootstrap_state(
        &self,
        s: &BootstrapStateRecord,
    ) -> Result<BootstrapStateRecord, StoreError> {
        sqlx::query("INSERT INTO bootstrap_state(state_id,generation,phase,cloud_identity_id,cloud_profile_id,enrolled_agents,updated_at) VALUES($1,$2,$3,$4,$5,$6,$7) ON CONFLICT(state_id) DO UPDATE SET generation=EXCLUDED.generation,phase=EXCLUDED.phase,cloud_identity_id=EXCLUDED.cloud_identity_id,cloud_profile_id=EXCLUDED.cloud_profile_id,enrolled_agents=EXCLUDED.enrolled_agents,updated_at=EXCLUDED.updated_at").bind(&s.state_id).bind(i64::try_from(s.generation).map_err(|_| StoreError::Corrupt("bootstrap generation overflow".into()))?).bind(&s.phase).bind(&s.cloud_identity_id).bind(&s.cloud_profile_id).bind(&s.enrolled_agents).bind(&s.updated_at).execute(&self.pool).await.map_err(StoreError::Database)?;
        Ok(s.clone())
    }
    pub async fn get_enrollment_grant(
        &self,
        id: &str,
    ) -> Result<Option<EnrollmentGrantRecord>, StoreError> {
        sqlx::query(&format!(
            "SELECT {GRANT_COLUMNS} FROM enrollment_grants WHERE grant_id=$1"
        ))
        .bind(id)
        .fetch_optional(&self.pool)
        .await
        .map_err(StoreError::Database)?
        .map(grant)
        .transpose()
    }
    pub async fn insert_enrollment_grant(
        &self,
        g: &EnrollmentGrantRecord,
    ) -> Result<(), StoreError> {
        sqlx::query("INSERT INTO enrollment_grants(grant_id,agent_id,token_digest,issued_at_unix_ms,expires_at_unix_ms,used_at_unix_ms) VALUES($1,$2,$3,$4,$5,$6)").bind(&g.grant_id).bind(&g.agent_id).bind(&g.token_digest).bind(i64::try_from(g.issued_at_unix_ms).map_err(|_| StoreError::Corrupt("grant timestamp overflow".into()))?).bind(i64::try_from(g.expires_at_unix_ms).map_err(|_| StoreError::Corrupt("grant timestamp overflow".into()))?).bind(g.used_at_unix_ms.and_then(|v| i64::try_from(v).ok())).execute(&self.pool).await.map_err(StoreError::Database)?;
        Ok(())
    }
    pub async fn consume_enrollment_grant(
        &self,
        id: &str,
        digest: &str,
        now: u64,
    ) -> Result<EnrollmentGrantRecord, StoreError> {
        let mut tx = self.pool.begin().await.map_err(StoreError::Database)?;
        let row = sqlx::query(&format!(
            "SELECT {GRANT_COLUMNS} FROM enrollment_grants WHERE grant_id=$1 FOR UPDATE"
        ))
        .bind(id)
        .fetch_optional(&mut *tx)
        .await
        .map_err(StoreError::Database)?
        .ok_or(StoreError::ResourceNotFound)?;
        let g = grant(row)?;
        if g.token_digest != digest || g.used_at_unix_ms.is_some() || now >= g.expires_at_unix_ms {
            return Err(StoreError::OwnershipConflict);
        }
        let updated = sqlx::query("UPDATE enrollment_grants SET used_at_unix_ms=$1 WHERE grant_id=$2 AND used_at_unix_ms IS NULL")
            .bind(i64::try_from(now).map_err(|_| StoreError::Corrupt("grant timestamp overflow".into()))?)
            .bind(id)
            .execute(&mut *tx)
            .await
            .map_err(StoreError::Database)?;
        if updated.rows_affected() != 1 {
            return Err(StoreError::OwnershipConflict);
        }
        tx.commit().await.map_err(StoreError::Database)?;
        Ok(EnrollmentGrantRecord {
            used_at_unix_ms: Some(now),
            ..g
        })
    }
}

#[async_trait]
impl BootstrapRepository for PostgresStore {
    async fn get_bootstrap_state(
        &self,
        id: &str,
    ) -> Result<Option<BootstrapStateRecord>, StoreError> {
        self.get_bootstrap_state(id).await
    }
    async fn upsert_bootstrap_state(
        &self,
        s: &BootstrapStateRecord,
    ) -> Result<BootstrapStateRecord, StoreError> {
        self.upsert_bootstrap_state(s).await
    }
    async fn get_enrollment_grant(
        &self,
        id: &str,
    ) -> Result<Option<EnrollmentGrantRecord>, StoreError> {
        self.get_enrollment_grant(id).await
    }
    async fn insert_enrollment_grant(&self, g: &EnrollmentGrantRecord) -> Result<(), StoreError> {
        self.insert_enrollment_grant(g).await
    }
    async fn consume_enrollment_grant(
        &self,
        id: &str,
        d: &str,
        n: u64,
    ) -> Result<EnrollmentGrantRecord, StoreError> {
        self.consume_enrollment_grant(id, d, n).await
    }
}
