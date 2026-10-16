//! Row types and the read-only SQLite implementation of the database seam.
//!
//! Table and column names mirror `crates/o3k-store/migrations/*.sql` exactly;
//! doctor never opens the database in a mode that could write to it.

use crate::context::{DoctorDb, sanitize_error};
use async_trait::async_trait;
use sqlx::{Connection, Row};
use std::path::Path;
use std::time::Duration;

/// One `placement_providers` row.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ProviderRow {
    pub id: String,
    pub node_id: String,
    pub state: String,
    pub generation: i64,
}

/// One `placement_inventories` row.
#[derive(Debug, Clone, PartialEq)]
pub struct InventoryRow {
    pub provider_id: String,
    pub resource_class: String,
    pub total: i64,
    pub reserved: i64,
    pub allocation_ratio: f64,
    pub used: i64,
}

/// Summed allocation amount for one (provider, resource class) pair.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct AllocationRow {
    pub provider_id: String,
    pub resource_class: String,
    pub amount: i64,
}

/// Latest persisted agent epoch from one durable source.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct EpochRow {
    pub source: String,
    pub agent_id: String,
    pub agent_epoch: String,
}

/// One compute instance (`resources` row) with its display name extracted
/// from the durable desired-state JSON.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct InstanceRow {
    pub id: String,
    pub name: String,
    pub observed_state: String,
}

/// One `network_ports` row.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PortRow {
    pub id: String,
    pub binding_host: Option<String>,
    pub binding_state: Option<String>,
    pub status: String,
}

/// One currently unexpired durable work lease.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct WorkLeaseRow {
    pub work_key: String,
    pub owner_controller_id: String,
    pub owner_controller_epoch: String,
    pub fencing_token: i64,
    pub owner_session_active: bool,
}

/// Maximum number of leases doctor will materialize for one bounded report.
/// The query fetches one additional row so an overflow fails closed instead
/// of making a truncated prefix appear healthy.
const MAX_ACTIVE_WORK_LEASES: usize = 1_024;

fn bounded_work_leases(rows: Vec<sqlx::sqlite::SqliteRow>) -> Result<Vec<WorkLeaseRow>, String> {
    if rows.len() > MAX_ACTIVE_WORK_LEASES {
        return Err("work fencing authority returned too many active leases".to_owned());
    }
    Ok(rows
        .into_iter()
        .map(|row| WorkLeaseRow {
            work_key: row.get("work_key"),
            owner_controller_id: row.get("owner_controller_id"),
            owner_controller_epoch: row.get("owner_controller_epoch"),
            fencing_token: row.get("fencing_token"),
            owner_session_active: row.get("owner_session_active"),
        })
        .collect())
}

/// Real [`DoctorDb`] implementation: a single-connection read-only SQLite
/// pool opened per query. Any SQL or connection failure becomes a short
/// sanitized error string; SQL parameters are never included in messages.
#[derive(Debug, Clone)]
pub struct SqlxDoctorDb;

impl SqlxDoctorDb {
    /// Opens a read-only connection for one logical query.
    async fn read_only_connection(
        path: &Path,
    ) -> Result<sqlx::pool::PoolConnection<sqlx::Sqlite>, String> {
        let options = sqlx::sqlite::SqliteConnectOptions::new()
            .filename(path)
            .read_only(true)
            .create_if_missing(false);
        let pool = sqlx::sqlite::SqlitePoolOptions::new()
            .max_connections(1)
            .acquire_timeout(Duration::from_secs(10))
            .connect_with(options)
            .await
            .map_err(|error| sanitize_error(&format!("database is not readable: {error}")))?;
        pool.acquire()
            .await
            .map_err(|error| sanitize_error(&format!("database is not readable: {error}")))
    }

    async fn postgres_connection(
        url: &str,
    ) -> Result<sqlx::pool::PoolConnection<sqlx::Postgres>, String> {
        let options = url
            .parse::<sqlx::postgres::PgConnectOptions>()
            .map_err(|_| "PostgreSQL coordination store is not configured".to_owned())?;
        let pool = sqlx::postgres::PgPoolOptions::new()
            .max_connections(1)
            .acquire_timeout(Duration::from_secs(10))
            .connect_with(options)
            .await
            .map_err(|_| "PostgreSQL coordination store is unavailable".to_owned())?;
        pool.acquire()
            .await
            .map_err(|_| "PostgreSQL coordination store is unavailable".to_owned())
    }
}

#[async_trait]
impl DoctorDb for SqlxDoctorDb {
    async fn pragma_journal_mode(&self, path: &Path) -> Result<String, String> {
        let mut connection = Self::read_only_connection(path).await?;
        let row = sqlx::query_scalar::<_, String>("PRAGMA journal_mode")
            .fetch_one(&mut *connection)
            .await
            .map_err(|error| sanitize_error(&format!("journal mode query failed: {error}")))?;
        Ok(row)
    }

    async fn pragma_quick_check(&self, path: &Path) -> Result<String, String> {
        let mut connection = Self::read_only_connection(path).await?;
        let row = sqlx::query_scalar::<_, String>("PRAGMA quick_check")
            .fetch_one(&mut *connection)
            .await
            .map_err(|error| sanitize_error(&format!("integrity check failed: {error}")))?;
        Ok(row)
    }

    async fn placement_providers(&self, path: &Path) -> Result<Vec<ProviderRow>, String> {
        let mut connection = Self::read_only_connection(path).await?;
        let rows = sqlx::query(
            "SELECT id, node_id, state, generation FROM placement_providers ORDER BY id",
        )
        .fetch_all(&mut *connection)
        .await
        .map_err(|error| sanitize_error(&format!("placement provider query failed: {error}")))?;
        Ok(rows
            .into_iter()
            .map(|row| ProviderRow {
                id: row.get("id"),
                node_id: row.get("node_id"),
                state: row.get("state"),
                generation: row.get("generation"),
            })
            .collect())
    }

    async fn placement_inventories(&self, path: &Path) -> Result<Vec<InventoryRow>, String> {
        let mut connection = Self::read_only_connection(path).await?;
        let rows = sqlx::query(
            "SELECT provider_id, resource_class, total, reserved, allocation_ratio, used \
             FROM placement_inventories ORDER BY provider_id, resource_class",
        )
        .fetch_all(&mut *connection)
        .await
        .map_err(|error| sanitize_error(&format!("placement inventory query failed: {error}")))?;
        Ok(rows
            .into_iter()
            .map(|row| InventoryRow {
                provider_id: row.get("provider_id"),
                resource_class: row.get("resource_class"),
                total: row.get("total"),
                reserved: row.get("reserved"),
                allocation_ratio: row.get("allocation_ratio"),
                used: row.get("used"),
            })
            .collect())
    }

    async fn live_allocation_resources(&self, path: &Path) -> Result<Vec<AllocationRow>, String> {
        let mut connection = Self::read_only_connection(path).await?;
        // Mirrors `o3k-store::reconcile_consumers`: the live consumer set is
        // every `compute_instance` resource that is not DELETED.
        let rows = sqlx::query(
            "SELECT a.provider_id, r.resource_class, SUM(r.amount) AS amount \
             FROM placement_allocations a \
             JOIN placement_allocation_resources r ON r.allocation_id = a.id \
             WHERE a.consumer_id IN (\
                 SELECT id FROM resources \
                 WHERE kind = 'compute_instance' AND observed_state != 'DELETED') \
             GROUP BY a.provider_id, r.resource_class \
             ORDER BY a.provider_id, r.resource_class",
        )
        .fetch_all(&mut *connection)
        .await
        .map_err(|error| sanitize_error(&format!("allocation query failed: {error}")))?;
        Ok(rows
            .into_iter()
            .map(|row| AllocationRow {
                provider_id: row.get("provider_id"),
                resource_class: row.get("resource_class"),
                amount: row.get("amount"),
            })
            .collect())
    }

    async fn latest_epochs(&self, path: &Path) -> Result<Vec<EpochRow>, String> {
        let mut connection = Self::read_only_connection(path).await?;
        // MAX() on TEXT is a time-order maximum only because agent epochs
        // are UUIDv7 strings (timestamp-prefixed, lexicographically
        // time-ordered). If the epoch format ever changes to v4 or a
        // counter, this comparison must change with it (see
        // compute.agent_epoch, which relies on the same property).
        let watermark_rows =
            sqlx::query("SELECT MAX(agent_epoch) AS agent_epoch FROM observation_watermarks")
                .fetch_all(&mut *connection)
                .await
                .map_err(|error| {
                    sanitize_error(&format!("watermark epoch query failed: {error}"))
                })?;
        let mut epochs = Vec::new();
        for row in watermark_rows {
            let epoch: Option<String> = row.get("agent_epoch");
            if let Some(agent_epoch) = epoch {
                epochs.push(EpochRow {
                    source: "observation_watermarks".to_owned(),
                    agent_id: String::new(),
                    agent_epoch,
                });
            }
        }
        let command_rows = sqlx::query(
            "SELECT agent_id, MAX(agent_epoch) AS agent_epoch FROM agent_commands GROUP BY agent_id ORDER BY agent_id",
        )
        .fetch_all(&mut *connection)
        .await
        .map_err(|error| sanitize_error(&format!("command epoch query failed: {error}")))?;
        for row in command_rows {
            let epoch: Option<String> = row.get("agent_epoch");
            if let Some(agent_epoch) = epoch {
                epochs.push(EpochRow {
                    source: "agent_commands".to_owned(),
                    agent_id: row.get("agent_id"),
                    agent_epoch,
                });
            }
        }
        Ok(epochs)
    }

    async fn compute_instances(&self, path: &Path) -> Result<Vec<InstanceRow>, String> {
        let mut connection = Self::read_only_connection(path).await?;
        let rows = sqlx::query(
            "SELECT id, \
                    COALESCE(json_extract(desired_state, '$.name'), '') AS name, \
                    observed_state \
             FROM resources WHERE kind = 'compute_instance' ORDER BY id",
        )
        .fetch_all(&mut *connection)
        .await
        .map_err(|error| sanitize_error(&format!("compute instance query failed: {error}")))?;
        Ok(rows
            .into_iter()
            .map(|row| InstanceRow {
                id: row.get("id"),
                name: row.get("name"),
                observed_state: row.get("observed_state"),
            })
            .collect())
    }

    async fn network_ports(&self, path: &Path) -> Result<Vec<PortRow>, String> {
        let mut connection = Self::read_only_connection(path).await?;
        let rows = sqlx::query(
            "SELECT id, binding_host, binding_state, status FROM network_ports ORDER BY id",
        )
        .fetch_all(&mut *connection)
        .await
        .map_err(|error| sanitize_error(&format!("network port query failed: {error}")))?;
        Ok(rows
            .into_iter()
            .map(|row| PortRow {
                id: row.get("id"),
                binding_host: row.get("binding_host"),
                binding_state: row.get("binding_state"),
                status: row.get("status"),
            })
            .collect())
    }

    async fn active_controller_sessions(
        &self,
        path: &Path,
        use_postgres: bool,
        postgres_url: Option<&str>,
    ) -> Result<u64, String> {
        if use_postgres {
            let Some(url) = postgres_url else {
                return Err("PostgreSQL coordination store URL is missing".to_owned());
            };
            let mut connection = Self::postgres_connection(url).await?;
            let mut transaction = connection
                .begin()
                .await
                .map_err(|_| "PostgreSQL coordination store is unavailable".to_owned())?;
            sqlx::query("SET TRANSACTION READ ONLY")
                .execute(&mut *transaction)
                .await
                .map_err(|_| "PostgreSQL coordination store is unavailable".to_owned())?;
            sqlx::query("SET LOCAL statement_timeout = 10000")
                .execute(&mut *transaction)
                .await
                .map_err(|_| "PostgreSQL coordination store is unavailable".to_owned())?;
            let count = sqlx::query_scalar::<_, i64>(
                "SELECT COUNT(*) FROM controller_sessions \
                 WHERE state = 'Active' AND lease_until >= NOW()",
            )
            .fetch_one(&mut *transaction)
            .await
            .map_err(|_| "PostgreSQL controller session query failed".to_owned())?;
            return Ok(count as u64);
        }
        let mut connection = Self::read_only_connection(path).await?;
        let count = sqlx::query_scalar::<_, i64>(
            "SELECT COUNT(*) FROM controller_sessions \
             WHERE state = 'Active' AND lease_until >= datetime('now')",
        )
        .fetch_one(&mut *connection)
        .await
        .map_err(|error| sanitize_error(&format!("controller session query failed: {error}")))?;
        Ok(count as u64)
    }

    async fn active_work_leases(
        &self,
        path: &Path,
        use_postgres: bool,
        postgres_url: Option<&str>,
    ) -> Result<Vec<WorkLeaseRow>, String> {
        if use_postgres {
            let Some(url) = postgres_url else {
                return Err("PostgreSQL coordination store URL is missing".to_owned());
            };
            let mut connection = Self::postgres_connection(url).await?;
            let mut transaction = connection
                .begin()
                .await
                .map_err(|_| "PostgreSQL coordination store is unavailable".to_owned())?;
            sqlx::query("SET TRANSACTION READ ONLY")
                .execute(&mut *transaction)
                .await
                .map_err(|_| "PostgreSQL coordination store is unavailable".to_owned())?;
            sqlx::query("SET LOCAL statement_timeout = 10000")
                .execute(&mut *transaction)
                .await
                .map_err(|_| "PostgreSQL coordination store is unavailable".to_owned())?;
            let rows = sqlx::query(&format!(
                "SELECT l.work_key, l.owner_controller_id, l.owner_controller_epoch, l.fencing_token, \
                        EXISTS (SELECT 1 FROM controller_sessions s WHERE s.controller_id = l.owner_controller_id \
                          AND s.controller_epoch = l.owner_controller_epoch AND s.state = 'Active' AND s.lease_until >= NOW()) AS owner_session_active \
                 FROM work_leases l WHERE l.lease_until >= NOW() ORDER BY l.work_key LIMIT {}",
                MAX_ACTIVE_WORK_LEASES + 1
            ))
            .fetch_all(&mut *transaction)
            .await
            .map_err(|_| "PostgreSQL work lease query failed".to_owned())?;
            if rows.len() > MAX_ACTIVE_WORK_LEASES {
                return Err("work fencing authority returned too many active leases".to_owned());
            }
            return Ok(rows
                .into_iter()
                .map(|row| WorkLeaseRow {
                    work_key: row.get("work_key"),
                    owner_controller_id: row.get("owner_controller_id"),
                    owner_controller_epoch: row.get("owner_controller_epoch"),
                    fencing_token: row.get("fencing_token"),
                    owner_session_active: row.get("owner_session_active"),
                })
                .collect());
        }
        let mut connection = Self::read_only_connection(path).await?;
        let rows = sqlx::query(&format!(
            "SELECT l.work_key, l.owner_controller_id, l.owner_controller_epoch, l.fencing_token, \
                    EXISTS (SELECT 1 FROM controller_sessions s WHERE s.controller_id = l.owner_controller_id \
                      AND s.controller_epoch = l.owner_controller_epoch AND s.state = 'Active' AND s.lease_until >= datetime('now')) AS owner_session_active \
             FROM work_leases l WHERE l.lease_until >= datetime('now') ORDER BY l.work_key LIMIT {}",
            MAX_ACTIVE_WORK_LEASES + 1
        ))
        .fetch_all(&mut *connection)
        .await
        .map_err(|error| sanitize_error(&format!("work lease query failed: {error}")))?;
        bounded_work_leases(rows)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::context::DoctorDb;

    #[tokio::test]
    #[allow(clippy::expect_used, clippy::unwrap_used)]
    async fn coordination_queries_observe_active_and_expired_rows() {
        let path = std::env::temp_dir().join(format!(
            "o3k-doctor-coordination-{}-{}.sqlite",
            std::process::id(),
            std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .expect("clock")
                .as_nanos()
        ));
        let options = sqlx::sqlite::SqliteConnectOptions::new()
            .filename(&path)
            .create_if_missing(true);
        let pool = sqlx::SqlitePool::connect_with(options)
            .await
            .expect("create test db");
        for statement in [
            "CREATE TABLE controller_sessions (controller_id TEXT NOT NULL, controller_epoch TEXT NOT NULL, lease_until TEXT NOT NULL, state TEXT NOT NULL)",
            "CREATE TABLE work_leases (work_key TEXT PRIMARY KEY, owner_controller_id TEXT NOT NULL, owner_controller_epoch TEXT NOT NULL, fencing_token INTEGER NOT NULL, lease_until TEXT NOT NULL)",
            "INSERT INTO controller_sessions VALUES ('active', 'epoch', datetime('now', '+1 hour'), 'Active')",
            "INSERT INTO controller_sessions VALUES ('expired', 'epoch', datetime('now', '-1 hour'), 'Active')",
            "INSERT INTO work_leases VALUES ('active', 'active', 'epoch', 7, datetime('now', '+1 hour'))",
            "INSERT INTO work_leases VALUES ('expired', 'expired', 'epoch', 9, datetime('now', '-1 hour'))",
            "INSERT INTO work_leases VALUES ('invalid', 'active', 'epoch', 0, datetime('now', '+1 hour'))",
        ] {
            sqlx::query(statement)
                .execute(&pool)
                .await
                .expect("seed coordination tables");
        }
        pool.close().await;

        let db = SqlxDoctorDb;
        assert_eq!(
            db.active_controller_sessions(&path, false, None)
                .await
                .unwrap(),
            1
        );
        let leases = db.active_work_leases(&path, false, None).await.unwrap();
        assert_eq!(leases.len(), 2);
        assert_eq!(leases[0].work_key, "active");
        assert_eq!(leases[0].fencing_token, 7);
        assert_eq!(leases[1].work_key, "invalid");
        assert_eq!(leases[1].fencing_token, 0);
        let _ = std::fs::remove_file(path);
    }

    #[tokio::test]
    #[allow(clippy::expect_used, clippy::unwrap_used)]
    async fn active_work_leases_overflow_fails_closed() {
        let path = std::env::temp_dir().join(format!(
            "o3k-doctor-work-lease-overflow-{}-{}.sqlite",
            std::process::id(),
            std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .expect("clock")
                .as_nanos()
        ));
        let options = sqlx::sqlite::SqliteConnectOptions::new()
            .filename(&path)
            .create_if_missing(true);
        let pool = sqlx::SqlitePool::connect_with(options)
            .await
            .expect("create overflow database");
        sqlx::query(
            "CREATE TABLE work_leases (work_key TEXT PRIMARY KEY, owner_controller_id TEXT NOT NULL, owner_controller_epoch TEXT NOT NULL, fencing_token INTEGER NOT NULL, lease_until TEXT NOT NULL)",
        )
        .execute(&pool)
        .await
        .expect("create work leases");
        for index in 0..=MAX_ACTIVE_WORK_LEASES {
            sqlx::query("INSERT INTO work_leases VALUES (?, 'controller', 'epoch', 1, datetime('now', '+1 hour'))")
                .bind(format!("lease-{index}"))
                .execute(&pool)
                .await
                .expect("insert active lease");
        }
        pool.close().await;

        let result = SqlxDoctorDb.active_work_leases(&path, false, None).await;
        assert_eq!(
            result.expect_err("overflow must fail closed"),
            "work fencing authority returned too many active leases"
        );
        let _ = std::fs::remove_file(path);
    }

    #[tokio::test]
    #[allow(clippy::expect_used)]
    async fn postgres_selection_requires_url_and_never_falls_back_to_sqlite() {
        let db = SqlxDoctorDb;
        let path = std::env::temp_dir().join("o3k-doctor-must-not-open-sqlite.sqlite");
        let result = db.active_controller_sessions(&path, true, None).await;
        assert!(result.is_err());
        assert!(
            result
                .expect_err("missing PostgreSQL URL must fail closed")
                .contains("URL is missing")
        );
    }

    /// Run explicitly against a disposable database with:
    /// `O3K_DOCTOR_POSTGRES_URL=postgres://.../o3k_doctor_test cargo test -p o3k
    /// --lib db::tests::postgres_coordination_queries -- --ignored --nocapture`.
    /// The marker in the database name prevents accidental use of a real cloud DB.
    #[tokio::test]
    #[ignore = "requires an explicitly provisioned disposable PostgreSQL database"]
    #[allow(clippy::expect_used, clippy::unwrap_used)]
    async fn postgres_coordination_queries() {
        let url = std::env::var("O3K_DOCTOR_POSTGRES_URL")
            .expect("O3K_DOCTOR_POSTGRES_URL is required for this ignored test");
        let options = url
            .parse::<sqlx::postgres::PgConnectOptions>()
            .expect("valid PostgreSQL URL");
        let database = options.get_database().unwrap_or_default();
        assert!(
            database.contains("o3k_doctor"),
            "refusing PostgreSQL database without o3k_doctor marker"
        );
        let schema = format!(
            "o3k_doctor_{}_{}",
            std::process::id(),
            std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .expect("clock")
                .as_nanos()
        );
        let pool = sqlx::postgres::PgPoolOptions::new()
            .max_connections(1)
            .connect_with(options)
            .await
            .expect("connect to disposable PostgreSQL");
        sqlx::query(&format!("CREATE SCHEMA {schema}"))
            .execute(&pool)
            .await
            .expect("create isolated schema");
        let isolated_url = if url.contains('?') {
            format!("{url}&options=-csearch_path%3D{schema}")
        } else {
            format!("{url}?options=-csearch_path%3D{schema}")
        };
        let isolated_options = isolated_url
            .parse::<sqlx::postgres::PgConnectOptions>()
            .expect("isolated PostgreSQL URL");
        let isolated_pool = sqlx::postgres::PgPoolOptions::new()
            .max_connections(1)
            .connect_with(isolated_options)
            .await
            .expect("connect to isolated schema");
        for statement in [
            "CREATE TABLE controller_sessions (controller_id VARCHAR(64) NOT NULL, controller_epoch VARCHAR(64) NOT NULL, lease_until TIMESTAMPTZ NOT NULL, state VARCHAR(32) NOT NULL)",
            "CREATE TABLE work_leases (work_key VARCHAR(255) PRIMARY KEY, fencing_token BIGINT NOT NULL, lease_until TIMESTAMPTZ NOT NULL)",
            "INSERT INTO controller_sessions VALUES ('active', 'epoch', NOW() + INTERVAL '1 hour', 'Active')",
            "INSERT INTO controller_sessions VALUES ('expired', 'epoch', NOW() - INTERVAL '1 hour', 'Active')",
            "INSERT INTO work_leases VALUES ('active', 7, NOW() + INTERVAL '1 hour')",
            "INSERT INTO work_leases VALUES ('expired', 9, NOW() - INTERVAL '1 hour')",
            "INSERT INTO work_leases VALUES ('invalid', 0, NOW() + INTERVAL '1 hour')",
        ] {
            sqlx::query(statement)
                .execute(&isolated_pool)
                .await
                .expect("seed PostgreSQL");
        }
        isolated_pool.close().await;

        let db = SqlxDoctorDb;
        assert_eq!(
            db.active_controller_sessions(Path::new("unused"), true, Some(&isolated_url))
                .await
                .expect("active session query"),
            1
        );
        let leases = db
            .active_work_leases(Path::new("unused"), true, Some(&isolated_url))
            .await
            .expect("active lease query");
        assert_eq!(leases.len(), 2);
        assert_eq!(leases[0].work_key, "active");
        assert_eq!(leases[0].fencing_token, 7);
        assert_eq!(leases[1].work_key, "invalid");
        assert_eq!(leases[1].fencing_token, 0);

        sqlx::query(&format!("DROP SCHEMA {schema} CASCADE"))
            .execute(&pool)
            .await
            .expect("drop isolated schema");
        pool.close().await;
        let error = db
            .active_controller_sessions(Path::new("unused"), true, Some(&isolated_url))
            .await
            .expect_err("missing schema must fail");
        assert!(error.contains("query failed"));
        assert!(!error.contains("://"));
    }
}
