use std::{str::FromStr, time::Duration};

use async_trait::async_trait;
use sqlx::Row;
use uuid::Uuid;

use crate::{PostgresStore, SqliteStore, StoreError, is_sqlite_busy};

pub type FencingToken = u64;

#[derive(
    Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Hash, serde::Serialize, serde::Deserialize,
)]
pub struct ControllerId(pub String);

impl ControllerId {
    pub fn new(id: impl Into<String>) -> Self {
        Self(id.into())
    }

    pub fn random() -> Self {
        Self(Uuid::new_v4().to_string())
    }
}

impl std::fmt::Display for ControllerId {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}", self.0)
    }
}

#[derive(
    Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Hash, serde::Serialize, serde::Deserialize,
)]
pub struct ControllerEpoch(pub String);

impl ControllerEpoch {
    pub fn new(epoch: impl Into<String>) -> Self {
        Self(epoch.into())
    }

    pub fn random() -> Self {
        Self(Uuid::new_v4().to_string())
    }
}

impl std::fmt::Display for ControllerEpoch {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}", self.0)
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
pub enum ControllerState {
    Active,
    Draining,
    Expired,
}

impl std::fmt::Display for ControllerState {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Active => write!(f, "Active"),
            Self::Draining => write!(f, "Draining"),
            Self::Expired => write!(f, "Expired"),
        }
    }
}

impl FromStr for ControllerState {
    type Err = StoreError;
    fn from_str(s: &str) -> Result<Self, Self::Err> {
        match s {
            "Active" => Ok(Self::Active),
            "Draining" => Ok(Self::Draining),
            "Expired" => Ok(Self::Expired),
            other => Err(StoreError::Corrupt(format!(
                "unknown controller state: {other}"
            ))),
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
pub struct ControllerSession {
    pub controller_id: ControllerId,
    pub controller_epoch: ControllerEpoch,
    pub started_at: String,
    pub heartbeat_at: String,
    pub lease_until: String,
    pub software_version: String,
    pub source_commit: String,
    pub state: ControllerState,
}

#[derive(Debug, Clone, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
pub struct WorkLease {
    pub work_key: String,
    pub work_kind: String,
    pub owner_controller_id: ControllerId,
    pub owner_controller_epoch: ControllerEpoch,
    pub fencing_token: FencingToken,
    pub lease_until: String,
    pub created_at: String,
    pub updated_at: String,
}

#[derive(Debug, Clone, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
pub enum LeaseAcquireOutcome {
    Acquired {
        lease: WorkLease,
    },
    Busy {
        owner_controller_id: ControllerId,
        owner_controller_epoch: ControllerEpoch,
        fencing_token: FencingToken,
        lease_created_at: String,
        lease_until: String,
    },
}

#[async_trait]
pub trait CoordinationRepository: Send + Sync {
    async fn register_controller_session(
        &self,
        session: &ControllerSession,
        ttl: Duration,
    ) -> Result<(), StoreError>;

    async fn heartbeat_controller_session(
        &self,
        controller_id: &ControllerId,
        controller_epoch: &ControllerEpoch,
        ttl: Duration,
    ) -> Result<bool, StoreError>;

    async fn drain_controller_session(
        &self,
        controller_id: &ControllerId,
        controller_epoch: &ControllerEpoch,
    ) -> Result<bool, StoreError>;

    async fn acquire_work_lease(
        &self,
        work_key: &str,
        work_kind: &str,
        controller_id: &ControllerId,
        controller_epoch: &ControllerEpoch,
        ttl: Duration,
    ) -> Result<LeaseAcquireOutcome, StoreError> {
        const MAX_BUSY_RETRIES: u32 = 5;
        for attempt in 0..=MAX_BUSY_RETRIES {
            match self
                .acquire_work_lease_once(work_key, work_kind, controller_id, controller_epoch, ttl)
                .await
            {
                Err(StoreError::Database(error))
                    if is_sqlite_busy(&error) && attempt < MAX_BUSY_RETRIES =>
                {
                    tokio::time::sleep(Duration::from_millis(50 * u64::from(attempt + 1))).await;
                }
                result => return result,
            }
        }
        unreachable!("work-lease retry loop always returns")
    }

    async fn acquire_work_lease_once(
        &self,
        work_key: &str,
        work_kind: &str,
        controller_id: &ControllerId,
        controller_epoch: &ControllerEpoch,
        ttl: Duration,
    ) -> Result<LeaseAcquireOutcome, StoreError>;

    async fn renew_work_lease(
        &self,
        work_key: &str,
        controller_id: &ControllerId,
        controller_epoch: &ControllerEpoch,
        fencing_token: FencingToken,
        ttl: Duration,
    ) -> Result<bool, StoreError>;

    async fn release_work_lease(
        &self,
        work_key: &str,
        controller_id: &ControllerId,
        controller_epoch: &ControllerEpoch,
        fencing_token: FencingToken,
    ) -> Result<bool, StoreError>;

    async fn inspect_work_lease(&self, work_key: &str) -> Result<Option<WorkLease>, StoreError>;

    async fn list_active_controller_sessions(&self) -> Result<Vec<ControllerSession>, StoreError>;
}

// -----------------------------------------------------------------------------
// PostgreSQL Implementation
// -----------------------------------------------------------------------------

#[async_trait]
impl CoordinationRepository for PostgresStore {
    async fn register_controller_session(
        &self,
        session: &ControllerSession,
        ttl: Duration,
    ) -> Result<(), StoreError> {
        let ttl_secs = ttl.as_secs_f64();
        let interval_str = format!("{ttl_secs} seconds");
        let state_str = session.state.to_string();

        sqlx::query(
            r#"
            INSERT INTO controller_sessions (
                controller_id, controller_epoch, started_at, heartbeat_at, lease_until,
                software_version, source_commit, state
            )
            VALUES (
                $1, $2, NOW(), NOW(), NOW() + $3::interval,
                $4, $5, $6
            )
            ON CONFLICT (controller_id, controller_epoch) DO UPDATE
            SET heartbeat_at = NOW(),
                lease_until = NOW() + $3::interval,
                state = $6,
                software_version = $4,
                source_commit = $5;
            "#,
        )
        .bind(&session.controller_id.0)
        .bind(&session.controller_epoch.0)
        .bind(&interval_str)
        .bind(&session.software_version)
        .bind(&session.source_commit)
        .bind(&state_str)
        .execute(&self.pool)
        .await
        .map_err(StoreError::Database)?;

        Ok(())
    }

    async fn heartbeat_controller_session(
        &self,
        controller_id: &ControllerId,
        controller_epoch: &ControllerEpoch,
        ttl: Duration,
    ) -> Result<bool, StoreError> {
        let ttl_secs = ttl.as_secs_f64();
        let interval_str = format!("{ttl_secs} seconds");

        let result = sqlx::query(
            r#"
            UPDATE controller_sessions
            SET heartbeat_at = NOW(),
                lease_until = NOW() + $3::interval
            WHERE controller_id = $1
              AND controller_epoch = $2
              AND state = 'Active';
            "#,
        )
        .bind(&controller_id.0)
        .bind(&controller_epoch.0)
        .bind(&interval_str)
        .execute(&self.pool)
        .await
        .map_err(StoreError::Database)?;

        Ok(result.rows_affected() > 0)
    }

    async fn drain_controller_session(
        &self,
        controller_id: &ControllerId,
        controller_epoch: &ControllerEpoch,
    ) -> Result<bool, StoreError> {
        let result = sqlx::query(
            r#"
            UPDATE controller_sessions
            SET state = 'Draining',
                heartbeat_at = NOW()
            WHERE controller_id = $1
              AND controller_epoch = $2;
            "#,
        )
        .bind(&controller_id.0)
        .bind(&controller_epoch.0)
        .execute(&self.pool)
        .await
        .map_err(StoreError::Database)?;

        Ok(result.rows_affected() > 0)
    }

    async fn acquire_work_lease_once(
        &self,
        work_key: &str,
        work_kind: &str,
        controller_id: &ControllerId,
        controller_epoch: &ControllerEpoch,
        ttl: Duration,
    ) -> Result<LeaseAcquireOutcome, StoreError> {
        let ttl_secs = ttl.as_secs_f64();
        let interval_str = format!("{ttl_secs} seconds");

        let mut tx = self.pool.begin().await.map_err(StoreError::Database)?;

        let maybe_row = sqlx::query(
            r#"
            SELECT work_key, work_kind, owner_controller_id, owner_controller_epoch,
                   fencing_token, lease_until, created_at, updated_at,
                   (lease_until < NOW()) AS is_expired
            FROM work_leases
            WHERE work_key = $1
            FOR UPDATE;
            "#,
        )
        .bind(work_key)
        .fetch_optional(&mut *tx)
        .await
        .map_err(StoreError::Database)?;

        match maybe_row {
            None => {
                // New lease -> initialize fencing token to 1
                let row = sqlx::query(
                    r#"
                    INSERT INTO work_leases (
                        work_key, work_kind, owner_controller_id, owner_controller_epoch,
                        fencing_token, lease_until, created_at, updated_at
                    )
                    VALUES ($1, $2, $3, $4, 1, NOW() + $5::interval, NOW(), NOW())
                    RETURNING work_key, work_kind, owner_controller_id, owner_controller_epoch,
                              fencing_token, lease_until::text, created_at::text, updated_at::text;
                    "#,
                )
                .bind(work_key)
                .bind(work_kind)
                .bind(&controller_id.0)
                .bind(&controller_epoch.0)
                .bind(&interval_str)
                .fetch_one(&mut *tx)
                .await
                .map_err(StoreError::Database)?;

                let lease = WorkLease {
                    work_key: row.get("work_key"),
                    work_kind: row.get("work_kind"),
                    owner_controller_id: ControllerId(row.get("owner_controller_id")),
                    owner_controller_epoch: ControllerEpoch(row.get("owner_controller_epoch")),
                    fencing_token: row.get::<i64, _>("fencing_token") as u64,
                    lease_until: row.get("lease_until"),
                    created_at: row.get("created_at"),
                    updated_at: row.get("updated_at"),
                };

                tx.commit().await.map_err(StoreError::Database)?;
                Ok(LeaseAcquireOutcome::Acquired { lease })
            }
            Some(existing) => {
                let owner_id: String = existing.get("owner_controller_id");
                let owner_epoch: String = existing.get("owner_controller_epoch");
                let current_token: i64 = existing.get("fencing_token");
                let is_expired: bool = existing.get("is_expired");

                if owner_id == controller_id.0 && owner_epoch == controller_epoch.0 {
                    // Same owner session re-acquiring -> renew lease without bumping fencing token
                    let row = sqlx::query(
                        r#"
                        UPDATE work_leases
                        SET lease_until = NOW() + $2::interval,
                            updated_at = NOW()
                        WHERE work_key = $1
                        RETURNING work_key, work_kind, owner_controller_id, owner_controller_epoch,
                                  fencing_token, lease_until::text, created_at::text, updated_at::text;
                        "#,
                    )
                    .bind(work_key)
                    .bind(&interval_str)
                    .fetch_one(&mut *tx)
                    .await
                    .map_err(StoreError::Database)?;

                    let lease = WorkLease {
                        work_key: row.get("work_key"),
                        work_kind: row.get("work_kind"),
                        owner_controller_id: ControllerId(row.get("owner_controller_id")),
                        owner_controller_epoch: ControllerEpoch(row.get("owner_controller_epoch")),
                        fencing_token: row.get::<i64, _>("fencing_token") as u64,
                        lease_until: row.get("lease_until"),
                        created_at: row.get("created_at"),
                        updated_at: row.get("updated_at"),
                    };

                    tx.commit().await.map_err(StoreError::Database)?;
                    Ok(LeaseAcquireOutcome::Acquired { lease })
                } else if is_expired {
                    // Expired lease -> takeover atomically and increment fencing token!
                    let row = sqlx::query(
                        r#"
                        UPDATE work_leases
                        SET owner_controller_id = $2,
                            owner_controller_epoch = $3,
                            fencing_token = fencing_token + 1,
                            lease_until = NOW() + $4::interval,
                            updated_at = NOW()
                        WHERE work_key = $1
                        RETURNING work_key, work_kind, owner_controller_id, owner_controller_epoch,
                                  fencing_token, lease_until::text, created_at::text, updated_at::text;
                        "#,
                    )
                    .bind(work_key)
                    .bind(&controller_id.0)
                    .bind(&controller_epoch.0)
                    .bind(&interval_str)
                    .fetch_one(&mut *tx)
                    .await
                    .map_err(StoreError::Database)?;

                    let lease = WorkLease {
                        work_key: row.get("work_key"),
                        work_kind: row.get("work_kind"),
                        owner_controller_id: ControllerId(row.get("owner_controller_id")),
                        owner_controller_epoch: ControllerEpoch(row.get("owner_controller_epoch")),
                        fencing_token: row.get::<i64, _>("fencing_token") as u64,
                        lease_until: row.get("lease_until"),
                        created_at: row.get("created_at"),
                        updated_at: row.get("updated_at"),
                    };

                    tx.commit().await.map_err(StoreError::Database)?;
                    Ok(LeaseAcquireOutcome::Acquired { lease })
                } else {
                    // Active lease owned by another controller session
                    let lease_until: String = sqlx::query_scalar(
                        "SELECT lease_until::text FROM work_leases WHERE work_key = $1",
                    )
                    .bind(work_key)
                    .fetch_one(&mut *tx)
                    .await
                    .map_err(StoreError::Database)?;

                    tx.commit().await.map_err(StoreError::Database)?;
                    Ok(LeaseAcquireOutcome::Busy {
                        owner_controller_id: ControllerId(owner_id),
                        owner_controller_epoch: ControllerEpoch(owner_epoch),
                        fencing_token: current_token as u64,
                        lease_created_at: existing.get("created_at"),
                        lease_until,
                    })
                }
            }
        }
    }

    async fn renew_work_lease(
        &self,
        work_key: &str,
        controller_id: &ControllerId,
        controller_epoch: &ControllerEpoch,
        fencing_token: FencingToken,
        ttl: Duration,
    ) -> Result<bool, StoreError> {
        let ttl_secs = ttl.as_secs_f64();
        let interval_str = format!("{ttl_secs} seconds");

        let result = sqlx::query(
            r#"
            UPDATE work_leases
            SET lease_until = NOW() + $5::interval,
                updated_at = NOW()
            WHERE work_key = $1
              AND owner_controller_id = $2
              AND owner_controller_epoch = $3
              AND fencing_token = $4
              AND lease_until >= NOW();
            "#,
        )
        .bind(work_key)
        .bind(&controller_id.0)
        .bind(&controller_epoch.0)
        .bind(fencing_token as i64)
        .bind(&interval_str)
        .execute(&self.pool)
        .await
        .map_err(StoreError::Database)?;

        Ok(result.rows_affected() > 0)
    }

    async fn release_work_lease(
        &self,
        work_key: &str,
        controller_id: &ControllerId,
        controller_epoch: &ControllerEpoch,
        fencing_token: FencingToken,
    ) -> Result<bool, StoreError> {
        let result = sqlx::query(
            r#"
            DELETE FROM work_leases
            WHERE work_key = $1
              AND owner_controller_id = $2
              AND owner_controller_epoch = $3
              AND fencing_token = $4;
            "#,
        )
        .bind(work_key)
        .bind(&controller_id.0)
        .bind(&controller_epoch.0)
        .bind(fencing_token as i64)
        .execute(&self.pool)
        .await
        .map_err(StoreError::Database)?;

        Ok(result.rows_affected() > 0)
    }

    async fn inspect_work_lease(&self, work_key: &str) -> Result<Option<WorkLease>, StoreError> {
        let maybe_row = sqlx::query(
            r#"
            SELECT work_key, work_kind, owner_controller_id, owner_controller_epoch,
                   fencing_token, lease_until::text, created_at::text, updated_at::text
            FROM work_leases
            WHERE work_key = $1;
            "#,
        )
        .bind(work_key)
        .fetch_optional(&self.pool)
        .await
        .map_err(StoreError::Database)?;

        Ok(maybe_row.map(|row| WorkLease {
            work_key: row.get("work_key"),
            work_kind: row.get("work_kind"),
            owner_controller_id: ControllerId(row.get("owner_controller_id")),
            owner_controller_epoch: ControllerEpoch(row.get("owner_controller_epoch")),
            fencing_token: row.get::<i64, _>("fencing_token") as u64,
            lease_until: row.get("lease_until"),
            created_at: row.get("created_at"),
            updated_at: row.get("updated_at"),
        }))
    }

    async fn list_active_controller_sessions(&self) -> Result<Vec<ControllerSession>, StoreError> {
        let rows = sqlx::query(
            r#"
            SELECT controller_id, controller_epoch, started_at::text, heartbeat_at::text,
                   lease_until::text, software_version, source_commit, state
            FROM controller_sessions
            WHERE state = 'Active' AND lease_until >= NOW()
            ORDER BY started_at ASC;
            "#,
        )
        .fetch_all(&self.pool)
        .await
        .map_err(StoreError::Database)?;

        let mut sessions = Vec::with_capacity(rows.len());
        for row in rows {
            let state_str: String = row.get("state");
            sessions.push(ControllerSession {
                controller_id: ControllerId(row.get("controller_id")),
                controller_epoch: ControllerEpoch(row.get("controller_epoch")),
                started_at: row.get("started_at"),
                heartbeat_at: row.get("heartbeat_at"),
                lease_until: row.get("lease_until"),
                software_version: row.get("software_version"),
                source_commit: row.get("source_commit"),
                state: ControllerState::from_str(&state_str)?,
            });
        }

        Ok(sessions)
    }
}

// -----------------------------------------------------------------------------
// SQLite Implementation (Single-Controller / TestLab)
// -----------------------------------------------------------------------------

#[async_trait]
impl CoordinationRepository for SqliteStore {
    async fn register_controller_session(
        &self,
        session: &ControllerSession,
        ttl: Duration,
    ) -> Result<(), StoreError> {
        let ttl_secs = ttl.as_secs();
        let ttl_mod = format!("+{ttl_secs} seconds");
        let state_str = session.state.to_string();

        sqlx::query(
            r#"
            INSERT INTO controller_sessions (
                controller_id, controller_epoch, started_at, heartbeat_at, lease_until,
                software_version, source_commit, state
            )
            VALUES (
                ?1, ?2, datetime('now'), datetime('now'), datetime('now', ?3),
                ?4, ?5, ?6
            )
            ON CONFLICT (controller_id, controller_epoch) DO UPDATE
            SET heartbeat_at = datetime('now'),
                lease_until = datetime('now', ?3),
                state = ?6,
                software_version = ?4,
                source_commit = ?5;
            "#,
        )
        .bind(&session.controller_id.0)
        .bind(&session.controller_epoch.0)
        .bind(&ttl_mod)
        .bind(&session.software_version)
        .bind(&session.source_commit)
        .bind(&state_str)
        .execute(&self.pool)
        .await
        .map_err(StoreError::Database)?;

        Ok(())
    }

    async fn heartbeat_controller_session(
        &self,
        controller_id: &ControllerId,
        controller_epoch: &ControllerEpoch,
        ttl: Duration,
    ) -> Result<bool, StoreError> {
        let ttl_secs = ttl.as_secs();
        let ttl_mod = format!("+{ttl_secs} seconds");

        let result = sqlx::query(
            r#"
            UPDATE controller_sessions
            SET heartbeat_at = datetime('now'),
                lease_until = datetime('now', ?3)
            WHERE controller_id = ?1
              AND controller_epoch = ?2
              AND state = 'Active';
            "#,
        )
        .bind(&controller_id.0)
        .bind(&controller_epoch.0)
        .bind(&ttl_mod)
        .execute(&self.pool)
        .await
        .map_err(StoreError::Database)?;

        Ok(result.rows_affected() > 0)
    }

    async fn drain_controller_session(
        &self,
        controller_id: &ControllerId,
        controller_epoch: &ControllerEpoch,
    ) -> Result<bool, StoreError> {
        let result = sqlx::query(
            r#"
            UPDATE controller_sessions
            SET state = 'Draining',
                heartbeat_at = datetime('now')
            WHERE controller_id = ?1
              AND controller_epoch = ?2;
            "#,
        )
        .bind(&controller_id.0)
        .bind(&controller_epoch.0)
        .execute(&self.pool)
        .await
        .map_err(StoreError::Database)?;

        Ok(result.rows_affected() > 0)
    }

    async fn acquire_work_lease_once(
        &self,
        work_key: &str,
        work_kind: &str,
        controller_id: &ControllerId,
        controller_epoch: &ControllerEpoch,
        ttl: Duration,
    ) -> Result<LeaseAcquireOutcome, StoreError> {
        let ttl_secs = ttl.as_secs();
        let ttl_mod = format!("+{ttl_secs} seconds");

        let mut tx = self.pool.begin().await.map_err(StoreError::Database)?;

        let maybe_row = sqlx::query(
            r#"
            SELECT work_key, work_kind, owner_controller_id, owner_controller_epoch,
                   fencing_token, lease_until, created_at, updated_at,
                   (lease_until < datetime('now')) AS is_expired
            FROM work_leases
            WHERE work_key = ?1;
            "#,
        )
        .bind(work_key)
        .fetch_optional(&mut *tx)
        .await
        .map_err(StoreError::Database)?;

        match maybe_row {
            None => {
                sqlx::query(
                    r#"
                    INSERT INTO work_leases (
                        work_key, work_kind, owner_controller_id, owner_controller_epoch,
                        fencing_token, lease_until, created_at, updated_at
                    )
                    VALUES (?1, ?2, ?3, ?4, 1, datetime('now', ?5), datetime('now'), datetime('now'));
                    "#,
                )
                .bind(work_key)
                .bind(work_kind)
                .bind(&controller_id.0)
                .bind(&controller_epoch.0)
                .bind(&ttl_mod)
                .execute(&mut *tx)
                .await
                .map_err(StoreError::Database)?;

                let row = sqlx::query(
                    r#"
                    SELECT work_key, work_kind, owner_controller_id, owner_controller_epoch,
                           fencing_token, lease_until, created_at, updated_at
                    FROM work_leases
                    WHERE work_key = ?1;
                    "#,
                )
                .bind(work_key)
                .fetch_one(&mut *tx)
                .await
                .map_err(StoreError::Database)?;

                let lease = WorkLease {
                    work_key: row.get("work_key"),
                    work_kind: row.get("work_kind"),
                    owner_controller_id: ControllerId(row.get("owner_controller_id")),
                    owner_controller_epoch: ControllerEpoch(row.get("owner_controller_epoch")),
                    fencing_token: row.get::<i64, _>("fencing_token") as u64,
                    lease_until: row.get("lease_until"),
                    created_at: row.get("created_at"),
                    updated_at: row.get("updated_at"),
                };

                tx.commit().await.map_err(StoreError::Database)?;
                Ok(LeaseAcquireOutcome::Acquired { lease })
            }
            Some(existing) => {
                let owner_id: String = existing.get("owner_controller_id");
                let owner_epoch: String = existing.get("owner_controller_epoch");
                let current_token: i64 = existing.get("fencing_token");
                let is_expired: i64 = existing.get("is_expired");

                if owner_id == controller_id.0 && owner_epoch == controller_epoch.0 {
                    sqlx::query(
                        r#"
                        UPDATE work_leases
                        SET lease_until = datetime('now', ?2),
                            updated_at = datetime('now')
                        WHERE work_key = ?1;
                        "#,
                    )
                    .bind(work_key)
                    .bind(&ttl_mod)
                    .execute(&mut *tx)
                    .await
                    .map_err(StoreError::Database)?;

                    let row = sqlx::query(
                        r#"
                        SELECT work_key, work_kind, owner_controller_id, owner_controller_epoch,
                               fencing_token, lease_until, created_at, updated_at
                        FROM work_leases
                        WHERE work_key = ?1;
                        "#,
                    )
                    .bind(work_key)
                    .fetch_one(&mut *tx)
                    .await
                    .map_err(StoreError::Database)?;

                    let lease = WorkLease {
                        work_key: row.get("work_key"),
                        work_kind: row.get("work_kind"),
                        owner_controller_id: ControllerId(row.get("owner_controller_id")),
                        owner_controller_epoch: ControllerEpoch(row.get("owner_controller_epoch")),
                        fencing_token: row.get::<i64, _>("fencing_token") as u64,
                        lease_until: row.get("lease_until"),
                        created_at: row.get("created_at"),
                        updated_at: row.get("updated_at"),
                    };

                    tx.commit().await.map_err(StoreError::Database)?;
                    Ok(LeaseAcquireOutcome::Acquired { lease })
                } else if is_expired == 1 {
                    sqlx::query(
                        r#"
                        UPDATE work_leases
                        SET owner_controller_id = ?2,
                            owner_controller_epoch = ?3,
                            fencing_token = fencing_token + 1,
                            lease_until = datetime('now', ?4),
                            updated_at = datetime('now')
                        WHERE work_key = ?1;
                        "#,
                    )
                    .bind(work_key)
                    .bind(&controller_id.0)
                    .bind(&controller_epoch.0)
                    .bind(&ttl_mod)
                    .execute(&mut *tx)
                    .await
                    .map_err(StoreError::Database)?;

                    let row = sqlx::query(
                        r#"
                        SELECT work_key, work_kind, owner_controller_id, owner_controller_epoch,
                               fencing_token, lease_until, created_at, updated_at
                        FROM work_leases
                        WHERE work_key = ?1;
                        "#,
                    )
                    .bind(work_key)
                    .fetch_one(&mut *tx)
                    .await
                    .map_err(StoreError::Database)?;

                    let lease = WorkLease {
                        work_key: row.get("work_key"),
                        work_kind: row.get("work_kind"),
                        owner_controller_id: ControllerId(row.get("owner_controller_id")),
                        owner_controller_epoch: ControllerEpoch(row.get("owner_controller_epoch")),
                        fencing_token: row.get::<i64, _>("fencing_token") as u64,
                        lease_until: row.get("lease_until"),
                        created_at: row.get("created_at"),
                        updated_at: row.get("updated_at"),
                    };

                    tx.commit().await.map_err(StoreError::Database)?;
                    Ok(LeaseAcquireOutcome::Acquired { lease })
                } else {
                    let lease_until: String = existing.get("lease_until");
                    tx.commit().await.map_err(StoreError::Database)?;
                    Ok(LeaseAcquireOutcome::Busy {
                        owner_controller_id: ControllerId(owner_id),
                        owner_controller_epoch: ControllerEpoch(owner_epoch),
                        fencing_token: current_token as u64,
                        lease_created_at: existing.get("created_at"),
                        lease_until,
                    })
                }
            }
        }
    }

    async fn renew_work_lease(
        &self,
        work_key: &str,
        controller_id: &ControllerId,
        controller_epoch: &ControllerEpoch,
        fencing_token: FencingToken,
        ttl: Duration,
    ) -> Result<bool, StoreError> {
        let ttl_secs = ttl.as_secs();
        let ttl_mod = format!("+{ttl_secs} seconds");

        let result = sqlx::query(
            r#"
            UPDATE work_leases
            SET lease_until = datetime('now', ?5),
                updated_at = datetime('now')
            WHERE work_key = ?1
              AND owner_controller_id = ?2
              AND owner_controller_epoch = ?3
              AND fencing_token = ?4
              AND lease_until >= datetime('now');
            "#,
        )
        .bind(work_key)
        .bind(&controller_id.0)
        .bind(&controller_epoch.0)
        .bind(fencing_token as i64)
        .bind(&ttl_mod)
        .execute(&self.pool)
        .await
        .map_err(StoreError::Database)?;

        Ok(result.rows_affected() > 0)
    }

    async fn release_work_lease(
        &self,
        work_key: &str,
        controller_id: &ControllerId,
        controller_epoch: &ControllerEpoch,
        fencing_token: FencingToken,
    ) -> Result<bool, StoreError> {
        let result = sqlx::query(
            r#"
            DELETE FROM work_leases
            WHERE work_key = ?1
              AND owner_controller_id = ?2
              AND owner_controller_epoch = ?3
              AND fencing_token = ?4;
            "#,
        )
        .bind(work_key)
        .bind(&controller_id.0)
        .bind(&controller_epoch.0)
        .bind(fencing_token as i64)
        .execute(&self.pool)
        .await
        .map_err(StoreError::Database)?;

        Ok(result.rows_affected() > 0)
    }

    async fn inspect_work_lease(&self, work_key: &str) -> Result<Option<WorkLease>, StoreError> {
        let maybe_row = sqlx::query(
            r#"
            SELECT work_key, work_kind, owner_controller_id, owner_controller_epoch,
                   fencing_token, lease_until, created_at, updated_at
            FROM work_leases
            WHERE work_key = ?1;
            "#,
        )
        .bind(work_key)
        .fetch_optional(&self.pool)
        .await
        .map_err(StoreError::Database)?;

        Ok(maybe_row.map(|row| WorkLease {
            work_key: row.get("work_key"),
            work_kind: row.get("work_kind"),
            owner_controller_id: ControllerId(row.get("owner_controller_id")),
            owner_controller_epoch: ControllerEpoch(row.get("owner_controller_epoch")),
            fencing_token: row.get::<i64, _>("fencing_token") as u64,
            lease_until: row.get("lease_until"),
            created_at: row.get("created_at"),
            updated_at: row.get("updated_at"),
        }))
    }

    async fn list_active_controller_sessions(&self) -> Result<Vec<ControllerSession>, StoreError> {
        let rows = sqlx::query(
            r#"
            SELECT controller_id, controller_epoch, started_at, heartbeat_at,
                   lease_until, software_version, source_commit, state
            FROM controller_sessions
            WHERE state = 'Active' AND lease_until >= datetime('now')
            ORDER BY started_at ASC;
            "#,
        )
        .fetch_all(&self.pool)
        .await
        .map_err(StoreError::Database)?;

        let mut sessions = Vec::with_capacity(rows.len());
        for row in rows {
            let state_str: String = row.get("state");
            sessions.push(ControllerSession {
                controller_id: ControllerId(row.get("controller_id")),
                controller_epoch: ControllerEpoch(row.get("controller_epoch")),
                started_at: row.get("started_at"),
                heartbeat_at: row.get("heartbeat_at"),
                lease_until: row.get("lease_until"),
                software_version: row.get("software_version"),
                source_commit: row.get("source_commit"),
                state: ControllerState::from_str(&state_str)?,
            });
        }

        Ok(sessions)
    }
}
