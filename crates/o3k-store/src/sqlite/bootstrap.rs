use async_trait::async_trait;
use sqlx::Row;

use super::SqliteStore;
use crate::{
    BootstrapRepository, BootstrapStateRecord, EnrollmentGrantRecord, EnrollmentResultRecord,
    StoreError,
};

fn state(row: sqlx::sqlite::SqliteRow) -> Result<BootstrapStateRecord, StoreError> {
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
        enrolled_agent_epochs: row.try_get("enrolled_agent_epochs").map_err(StoreError::Database)?,
        revoked_agents: row.try_get("revoked_agents").map_err(StoreError::Database)?,
        updated_at: row.try_get("updated_at").map_err(StoreError::Database)?,
    })
}

fn grant(row: sqlx::sqlite::SqliteRow) -> Result<EnrollmentGrantRecord, StoreError> {
    Ok(EnrollmentGrantRecord {
        grant_id: row.try_get("grant_id").map_err(StoreError::Database)?,
        agent_id: row.try_get("agent_id").map_err(StoreError::Database)?,
        agent_epoch: row.try_get("agent_epoch").map_err(StoreError::Database)?,
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

fn enrollment_result(row: sqlx::sqlite::SqliteRow) -> Result<EnrollmentResultRecord, StoreError> {
    let timestamp = |name| -> Result<u64, StoreError> {
        row.try_get::<i64, _>(name)
            .map_err(StoreError::Database)?
            .try_into()
            .map_err(|_| StoreError::Corrupt("enrollment result timestamp overflow".into()))
    };
    Ok(EnrollmentResultRecord {
        grant_id: row.try_get("grant_id").map_err(StoreError::Database)?,
        agent_id: row.try_get("agent_id").map_err(StoreError::Database)?,
        agent_epoch: row.try_get("agent_epoch").map_err(StoreError::Database)?,
        token_digest: row.try_get("token_digest").map_err(StoreError::Database)?,
        csr_sha256: row.try_get("csr_sha256").map_err(StoreError::Database)?,
        certificate_fingerprint_sha256: row
            .try_get("certificate_fingerprint_sha256")
            .map_err(StoreError::Database)?,
        client_certificate_chain_pem: row
            .try_get("client_certificate_chain_pem")
            .map_err(StoreError::Database)?,
        ca_certificate_pem: row
            .try_get("ca_certificate_pem")
            .map_err(StoreError::Database)?,
        ca_fingerprint_sha256: row
            .try_get("ca_fingerprint_sha256")
            .map_err(StoreError::Database)?,
        certificate_expires_at_unix_ms: timestamp("certificate_expires_at_unix_ms")?,
        rotation_deadline_unix_ms: timestamp("rotation_deadline_unix_ms")?,
        issued_at_unix_ms: timestamp("issued_at_unix_ms")?,
        registered_at_unix_ms: row
            .try_get::<Option<i64>, _>("registered_at_unix_ms")
            .map_err(StoreError::Database)?
            .map(|v| {
                v.try_into()
                    .map_err(|_| StoreError::Corrupt("enrollment result timestamp overflow".into()))
            })
            .transpose()?,
    })
}

const ENROLLMENT_RESULT_COLUMNS: &str = "grant_id,agent_id,agent_epoch,token_digest,csr_sha256,certificate_fingerprint_sha256,client_certificate_chain_pem,ca_certificate_pem,ca_fingerprint_sha256,certificate_expires_at_unix_ms,rotation_deadline_unix_ms,issued_at_unix_ms,registered_at_unix_ms";

impl SqliteStore {
    pub async fn get_bootstrap_state(
        &self,
        id: &str,
    ) -> Result<Option<BootstrapStateRecord>, StoreError> {
        sqlx::query("SELECT state_id,generation,phase,cloud_identity_id,cloud_profile_id,enrolled_agents,updated_at FROM bootstrap_state WHERE state_id=?")
            .bind(id).fetch_optional(&self.pool).await.map_err(StoreError::Database)?.map(state).transpose()
    }
    pub async fn upsert_bootstrap_state(
        &self,
        s: &BootstrapStateRecord,
    ) -> Result<BootstrapStateRecord, StoreError> {
        sqlx::query("INSERT INTO bootstrap_state(state_id,generation,phase,cloud_identity_id,cloud_profile_id,enrolled_agents,enrolled_agent_epochs,revoked_agents,updated_at) VALUES(?,?,?,?,?,?,?,?,?) ON CONFLICT(state_id) DO UPDATE SET generation=excluded.generation,phase=excluded.phase,cloud_identity_id=excluded.cloud_identity_id,cloud_profile_id=excluded.cloud_profile_id,enrolled_agents=excluded.enrolled_agents,enrolled_agent_epochs=excluded.enrolled_agent_epochs,revoked_agents=excluded.revoked_agents,updated_at=excluded.updated_at")
            .bind(&s.state_id).bind(i64::try_from(s.generation).map_err(|_| StoreError::Corrupt("bootstrap generation overflow".into()))?).bind(&s.phase).bind(&s.cloud_identity_id).bind(&s.cloud_profile_id).bind(&s.enrolled_agents).bind(&s.enrolled_agent_epochs).bind(&s.revoked_agents).bind(&s.updated_at).execute(&self.pool).await.map_err(StoreError::Database)?;
        Ok(s.clone())
    }
    pub async fn get_enrollment_grant(
        &self,
        id: &str,
    ) -> Result<Option<EnrollmentGrantRecord>, StoreError> {
        sqlx::query("SELECT grant_id,agent_id,agent_epoch,token_digest,issued_at_unix_ms,expires_at_unix_ms,used_at_unix_ms FROM enrollment_grants WHERE grant_id=?").bind(id).fetch_optional(&self.pool).await.map_err(StoreError::Database)?.map(grant).transpose()
    }
    pub async fn insert_enrollment_grant(
        &self,
        g: &EnrollmentGrantRecord,
    ) -> Result<(), StoreError> {
        sqlx::query("INSERT INTO enrollment_grants(grant_id,agent_id,agent_epoch,token_digest,issued_at_unix_ms,expires_at_unix_ms,used_at_unix_ms) VALUES(?,?,?,?,?,?,?)")
            .bind(&g.grant_id).bind(&g.agent_id).bind(&g.agent_epoch).bind(&g.token_digest).bind(i64::try_from(g.issued_at_unix_ms).map_err(|_| StoreError::Corrupt("grant timestamp overflow".into()))?).bind(i64::try_from(g.expires_at_unix_ms).map_err(|_| StoreError::Corrupt("grant timestamp overflow".into()))?).bind(g.used_at_unix_ms.and_then(|v| i64::try_from(v).ok())).execute(&self.pool).await.map_err(StoreError::Database)?;
        Ok(())
    }
    pub async fn consume_enrollment_grant(
        &self,
        id: &str,
        epoch: &str,
        digest: &str,
        now: u64,
    ) -> Result<EnrollmentGrantRecord, StoreError> {
        let mut tx = self.pool.begin().await.map_err(StoreError::Database)?;
        let row = sqlx::query("SELECT grant_id,agent_id,agent_epoch,token_digest,issued_at_unix_ms,expires_at_unix_ms,used_at_unix_ms FROM enrollment_grants WHERE grant_id=?").bind(id).fetch_optional(&mut *tx).await.map_err(StoreError::Database)?.ok_or(StoreError::ResourceNotFound)?;
        let g = grant(row)?;
        if g.agent_epoch.is_empty()
            || g.agent_epoch != epoch
            || g.token_digest != digest
            || g.used_at_unix_ms.is_some()
            || now >= g.expires_at_unix_ms
        {
            return Err(StoreError::OwnershipConflict);
        }
        let updated = sqlx::query("UPDATE enrollment_grants SET used_at_unix_ms=? WHERE grant_id=? AND used_at_unix_ms IS NULL")
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

    pub async fn complete_enrollment_issue(
        &self,
        result: &EnrollmentResultRecord,
        now: u64,
    ) -> Result<EnrollmentResultRecord, StoreError> {
        let mut tx = self.pool.begin().await.map_err(StoreError::Database)?;
        if let Some(row) = sqlx::query(&format!(
            "SELECT {ENROLLMENT_RESULT_COLUMNS} FROM enrollment_results WHERE grant_id=?"
        ))
        .bind(&result.grant_id)
        .fetch_optional(&mut *tx)
        .await
        .map_err(StoreError::Database)?
        {
            let prior = enrollment_result(row)?;
            if prior.agent_id != result.agent_id
                || prior.agent_epoch != result.agent_epoch
                || prior.token_digest != result.token_digest
                || prior.csr_sha256 != result.csr_sha256
            {
                return Err(StoreError::OwnershipConflict);
            }
            tx.commit().await.map_err(StoreError::Database)?;
            return Ok(prior);
        }

        let row = sqlx::query("SELECT grant_id,agent_id,agent_epoch,token_digest,issued_at_unix_ms,expires_at_unix_ms,used_at_unix_ms FROM enrollment_grants WHERE grant_id=?")
            .bind(&result.grant_id).fetch_optional(&mut *tx).await.map_err(StoreError::Database)?.ok_or(StoreError::ResourceNotFound)?;
        let grant = grant(row)?;
        if (grant.agent_id != "*" && grant.agent_id != result.agent_id)
            || (!grant.agent_epoch.is_empty() && grant.agent_epoch != result.agent_epoch)
            || grant.token_digest != result.token_digest
            || grant.used_at_unix_ms.is_some()
            || now >= grant.expires_at_unix_ms
            || result.agent_id.is_empty()
            || result.agent_epoch.is_empty()
        {
            return Err(StoreError::OwnershipConflict);
        }
        let updated = sqlx::query("UPDATE enrollment_grants SET agent_id=?,agent_epoch=?,used_at_unix_ms=? WHERE grant_id=? AND used_at_unix_ms IS NULL")
            .bind(&result.agent_id).bind(&result.agent_epoch).bind(i64::try_from(now).map_err(|_| StoreError::Corrupt("enrollment timestamp overflow".into()))?).bind(&result.grant_id).execute(&mut *tx).await.map_err(StoreError::Database)?;
        if updated.rows_affected() != 1 {
            return Err(StoreError::OwnershipConflict);
        }
        sqlx::query("INSERT INTO enrollment_results(grant_id,agent_id,agent_epoch,token_digest,csr_sha256,certificate_fingerprint_sha256,client_certificate_chain_pem,ca_certificate_pem,ca_fingerprint_sha256,certificate_expires_at_unix_ms,rotation_deadline_unix_ms,issued_at_unix_ms,registered_at_unix_ms) VALUES(?,?,?,?,?,?,?,?,?,?,?,?,NULL)")
            .bind(&result.grant_id).bind(&result.agent_id).bind(&result.agent_epoch).bind(&result.token_digest).bind(&result.csr_sha256).bind(&result.certificate_fingerprint_sha256).bind(&result.client_certificate_chain_pem).bind(&result.ca_certificate_pem).bind(&result.ca_fingerprint_sha256).bind(i64::try_from(result.certificate_expires_at_unix_ms).map_err(|_| StoreError::Corrupt("certificate timestamp overflow".into()))?).bind(i64::try_from(result.rotation_deadline_unix_ms).map_err(|_| StoreError::Corrupt("certificate timestamp overflow".into()))?).bind(i64::try_from(result.issued_at_unix_ms).map_err(|_| StoreError::Corrupt("certificate timestamp overflow".into()))?).execute(&mut *tx).await.map_err(StoreError::Database)?;
        tx.commit().await.map_err(StoreError::Database)?;
        Ok(result.clone())
    }

    pub async fn get_enrollment_result(
        &self,
        grant_id: &str,
    ) -> Result<Option<EnrollmentResultRecord>, StoreError> {
        sqlx::query(&format!(
            "SELECT {ENROLLMENT_RESULT_COLUMNS} FROM enrollment_results WHERE grant_id=?"
        ))
        .bind(grant_id)
        .fetch_optional(&self.pool)
        .await
        .map_err(StoreError::Database)?
        .map(enrollment_result)
        .transpose()
    }

    pub async fn consume_enrollment_result(
        &self,
        grant_id: &str,
        token_digest: &str,
        agent_id: &str,
        agent_epoch: &str,
        certificate_fingerprint: &str,
        now: u64,
    ) -> Result<EnrollmentResultRecord, StoreError> {
        let mut tx = self.pool.begin().await.map_err(StoreError::Database)?;
        let row = sqlx::query(&format!(
            "SELECT {ENROLLMENT_RESULT_COLUMNS} FROM enrollment_results WHERE grant_id=?"
        ))
        .bind(grant_id)
        .fetch_optional(&mut *tx)
        .await
        .map_err(StoreError::Database)?
        .ok_or(StoreError::ResourceNotFound)?;
        let mut result = enrollment_result(row)?;
        if result.token_digest != token_digest
            || result.agent_id != agent_id
            || result.agent_epoch != agent_epoch
            || result.certificate_fingerprint_sha256 != certificate_fingerprint
            || result.certificate_expires_at_unix_ms <= now
        {
            return Err(StoreError::OwnershipConflict);
        }
        if result.registered_at_unix_ms.is_some() {
            tx.commit().await.map_err(StoreError::Database)?;
            return Ok(result);
        }
        let updated = sqlx::query("UPDATE enrollment_results SET registered_at_unix_ms=? WHERE grant_id=? AND registered_at_unix_ms IS NULL AND certificate_fingerprint_sha256=?")
            .bind(i64::try_from(now).map_err(|_| StoreError::Corrupt("enrollment timestamp overflow".into()))?).bind(grant_id).bind(certificate_fingerprint).execute(&mut *tx).await.map_err(StoreError::Database)?;
        if updated.rows_affected() != 1 {
            return Err(StoreError::OwnershipConflict);
        }
        tx.commit().await.map_err(StoreError::Database)?;
        result.registered_at_unix_ms = Some(now);
        Ok(result)
    }
}

#[async_trait]
impl BootstrapRepository for SqliteStore {
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
        epoch: &str,
        d: &str,
        n: u64,
    ) -> Result<EnrollmentGrantRecord, StoreError> {
        self.consume_enrollment_grant(id, epoch, d, n).await
    }
    async fn complete_enrollment_issue(
        &self,
        result: &EnrollmentResultRecord,
        now: u64,
    ) -> Result<EnrollmentResultRecord, StoreError> {
        self.complete_enrollment_issue(result, now).await
    }
    async fn get_enrollment_result(
        &self,
        grant_id: &str,
    ) -> Result<Option<EnrollmentResultRecord>, StoreError> {
        self.get_enrollment_result(grant_id).await
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
        self.consume_enrollment_result(grant_id, token_digest, agent_id, epoch, fingerprint, now)
            .await
    }
}
