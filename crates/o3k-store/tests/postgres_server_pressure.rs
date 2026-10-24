//! Real PostgreSQL server connection exhaustion for PP.6.5.
#![allow(clippy::expect_used, clippy::unwrap_used, clippy::panic)]

use o3k_store::{DurableStore, PostgresStore, ResourceRecord};
use sqlx::{Connection, PgConnection, Row};
use std::{
    net::{TcpListener, TcpStream},
    process::Command,
    time::Duration,
};
use tokio::time::{sleep, timeout};
use uuid::Uuid;

/// Bound for a single raw connection, which the server rejects immediately.
const RAW_ADMISSION_TIMEOUT: Duration = Duration::from_secs(5);
/// PostgresStore retries admission until its own 5 s pool acquire timeout, so
/// the outer bound must be longer or the two timers race.
const STORE_ADMISSION_TIMEOUT: Duration = Duration::from_secs(15);
/// Bound for reconnecting once capacity is restored.
const RECOVERY_TIMEOUT: Duration = Duration::from_secs(15);

struct Cluster {
    id: String,
    port: u16,
    removed: bool,
}
impl Cluster {
    async fn start() -> Result<Self, Box<dyn std::error::Error>> {
        let name = format!("o3k-pp6-pg-server-{}", Uuid::now_v7());
        let port = TcpListener::bind(("127.0.0.1", 0))?.local_addr()?.port();
        let publish = format!("127.0.0.1:{port}:5432");
        let out = Command::new("docker")
            .args([
                "run",
                "--detach",
                "--name",
                &name,
                "--env",
                "POSTGRES_USER=admin",
                "--env",
                "POSTGRES_HOST_AUTH_METHOD=trust",
                "--publish",
                &publish,
                "postgres:16.4",
                "-c",
                "max_connections=6",
                "-c",
                "superuser_reserved_connections=1",
            ])
            .output()?;
        if !out.status.success() {
            return Err(format!(
                "docker run failed: {}",
                String::from_utf8_lossy(&out.stderr)
            )
            .into());
        }
        let id = String::from_utf8(out.stdout)?.trim().to_owned();
        let mut cluster = Self {
            id,
            port,
            removed: false,
        };
        let startup: Result<(), Box<dyn std::error::Error>> = async {
            timeout(Duration::from_secs(45), async {
                loop {
                    let ready = Command::new("docker")
                        .args([
                            "exec",
                            &cluster.id,
                            "pg_isready",
                            "-U",
                            "admin",
                            "-d",
                            "postgres",
                        ])
                        .output();
                    if ready.map(|o| o.status.success()).unwrap_or(false) {
                        break;
                    }
                    sleep(Duration::from_millis(250)).await;
                }
            })
            .await
            .map_err(|_| "PostgreSQL in-container readiness timed out")?;
            timeout(Duration::from_secs(10), async {
                loop {
                    if TcpStream::connect(("127.0.0.1", cluster.port)).is_ok() {
                        break;
                    }
                    sleep(Duration::from_millis(250)).await;
                }
            })
            .await
            .map_err(|_| "PostgreSQL host TCP readiness timed out")?;
            timeout(Duration::from_secs(15), async {
                let admin_url = format!(
                    "postgres://admin@127.0.0.1:{}/postgres?connect_timeout=2",
                    cluster.port
                );
                loop {
                    if let Ok(connection) = PgConnection::connect(&admin_url).await {
                        connection.close().await?;
                        break;
                    }
                    sleep(Duration::from_millis(250)).await;
                }
                Ok::<(), sqlx::Error>(())
            })
            .await
            .map_err(|_| "PostgreSQL authenticated host readiness timed out")??;
            let role = Command::new("docker")
                .args([
                    "exec",
                    &cluster.id,
                    "psql",
                    "-U",
                    "admin",
                    "-d",
                    "postgres",
                    "-c",
                    "CREATE ROLE o3k LOGIN; GRANT USAGE, CREATE ON SCHEMA public TO o3k",
                ])
                .output()?;
            if !role.status.success() {
                return Err(format!(
                    "could not create non-superuser test role: {}",
                    String::from_utf8_lossy(&role.stderr)
                )
                .into());
            }
            Ok(())
        }
        .await;
        if let Err(error) = startup {
            cluster
                .remove_checked()
                .map_err(|cleanup| format!("{error}; PostgreSQL cleanup failed: {cleanup}"))?;
            return Err(error);
        }
        Ok(cluster)
    }
    fn url(&self) -> String {
        format!(
            "postgres://o3k@127.0.0.1:{}/postgres?connect_timeout=2",
            self.port
        )
    }

    fn remove_checked(&mut self) -> Result<(), Box<dyn std::error::Error>> {
        if self.removed {
            return Ok(());
        }
        let out = Command::new("docker")
            .args(["rm", "--force", &self.id])
            .output()?;
        if !out.status.success() {
            return Err(format!(
                "owned PostgreSQL cleanup failed: {}",
                String::from_utf8_lossy(&out.stderr)
            )
            .into());
        }
        let inspect = Command::new("docker")
            .args(["inspect", &self.id])
            .output()?;
        if inspect.status.success() {
            return Err("owned PostgreSQL container still exists after cleanup".into());
        }
        self.removed = true;
        Ok(())
    }
}
impl Drop for Cluster {
    fn drop(&mut self) {
        if !self.removed {
            let _ = Command::new("docker")
                .args(["rm", "--force", &self.id])
                .output();
        }
    }
}

#[tokio::test]
#[ignore = "required Docker PostgreSQL server-pressure lane; invoke with --ignored"]
async fn postgres_server_connection_exhaustion_is_bounded_and_recovers()
-> Result<(), Box<dyn std::error::Error>> {
    let cluster = Cluster::start().await?;
    eprintln!("checkpoint:start");
    let url = cluster.url();
    let mut version_connection = PgConnection::connect(&url).await?;
    let version: String = sqlx::query_scalar("SELECT version()")
        .fetch_one(&mut version_connection)
        .await?;
    version_connection.close().await?;
    eprintln!("checkpoint:version");
    let preflight_store = PostgresStore::connect(&url).await?;
    let baseline_id = Uuid::now_v7();
    let baseline = ResourceRecord {
        id: baseline_id,
        kind: "pp6_server_pressure_baseline".into(),
        project_id: "pp6".into(),
        generation: 1,
        observed_generation: 1,
        desired_state: "ACTIVE".into(),
        observed_state: "ACTIVE".into(),
        provider_id: None,
    };
    preflight_store.insert_resource(&baseline).await?;
    preflight_store.pool().close().await;
    eprintln!("checkpoint:store-preflight");
    let mut held = Vec::new();
    for _ in 0..5 {
        held.push(PgConnection::connect(&url).await?);
    }
    eprintln!("checkpoint:held");
    let exhausted = timeout(RAW_ADMISSION_TIMEOUT, PgConnection::connect(&url))
        .await
        .map_err(|_| "raw server admission did not fail within bounded timeout")?
        .expect_err("server must reject beyond max_connections");
    let code = match exhausted {
        sqlx::Error::Database(error) => error.code().map(|value| value.into_owned()),
        _ => None,
    };
    assert_eq!(code.as_deref(), Some("53300"));
    eprintln!("checkpoint:raw");
    let resource_id = Uuid::now_v7();
    let store_attempt = timeout(STORE_ADMISSION_TIMEOUT, PostgresStore::connect(&url)).await;
    assert!(
        store_attempt.is_ok(),
        "store connection admission hung under server pressure"
    );
    let store_error = store_attempt
        .expect("bounded store attempt")
        .expect_err("PostgresStore unexpectedly connected while server slots were exhausted");
    assert_eq!(store_error.to_string(), "database error");
    eprintln!("checkpoint:store-failed");
    // The exhaustion assertion proves server admission failure. Recovery must
    // restore the full non-superuser budget because PostgresStore initializes
    // a larger lazy pool than the single slot left by one released session.
    for connection in held.drain(..) {
        connection.close().await?;
    }
    let store = timeout(RECOVERY_TIMEOUT, PostgresStore::connect(&url))
        .await
        .map_err(|_| "PostgresStore reconnect timed out after capacity recovery")??;
    eprintln!("checkpoint:store-recovered");
    let preserved = store
        .list_resources("pp6", "pp6_server_pressure_baseline")
        .await?;
    assert_eq!(
        preserved,
        vec![baseline],
        "failed admission must preserve canonical state"
    );
    let id = resource_id;
    store
        .insert_resource(&ResourceRecord {
            id,
            kind: "pp6_server_pressure".into(),
            project_id: "pp6".into(),
            generation: 1,
            observed_generation: 1,
            desired_state: "ACTIVE".into(),
            observed_state: "ACTIVE".into(),
            provider_id: None,
        })
        .await?;
    let row = sqlx::query("SELECT COUNT(*) AS count FROM resources WHERE id = $1")
        .bind(id.to_string())
        .fetch_one(store.pool())
        .await?;
    assert_eq!(row.get::<i64, _>("count"), 1);
    let migration_version: i64 =
        sqlx::query_scalar("SELECT COALESCE(MAX(version), 0)::BIGINT FROM _sqlx_migrations")
            .fetch_one(store.pool())
            .await?;
    store.pool().close().await;
    for connection in held {
        connection.close().await?;
    }
    let evidence_path = std::env::var("O3K_PP6_PG_EVIDENCE_PATH")?;
    let source_head = std::env::var("O3K_PP6_SOURCE_HEAD_SHA")?;
    let source_tree = std::env::var("O3K_PP6_SOURCE_TREE_SHA")?;
    let execution_head = std::env::var("O3K_PP6_EXECUTION_HEAD_SHA")?;
    let execution_tree = std::env::var("O3K_PP6_EXECUTION_TREE_SHA")?;
    if source_head.is_empty() || source_tree.is_empty() {
        return Err("source-bound evidence requires non-empty source and tree SHA".into());
    }
    if execution_head.is_empty() || execution_tree.is_empty() {
        return Err("execution-bound evidence requires non-empty execution and tree SHA".into());
    }
    let mut cluster = cluster;
    cluster.remove_checked()?;
    let os_release =
        std::fs::read_to_string("/etc/os-release").unwrap_or_else(|_| "unknown".into());
    let docker_version = String::from_utf8_lossy(
        &Command::new("docker")
            .args(["version", "--format", "{{.Server.Version}}"])
            .output()?
            .stdout,
    )
    .trim()
    .to_owned();
    let artifact = serde_json::json!({
        "schema": "o3k.pp6.postgres-server-pressure.v1",
        "test": "postgres_server_connection_exhaustion_is_bounded_and_recovers",
        "harness": "disposable-docker-postgres-16.4",
        "profile": "o3k-small-edge-v1",
        "schema_migration_identity": format!("o3k-store-sqlx-migrations:{migration_version}"),
        "source_head": source_head,
        "source_tree": source_tree,
        "execution_head": execution_head,
        "execution_tree": execution_tree,
        "server_version": version,
        "container_parameters": ["max_connections=6", "superuser_reserved_connections=1"],
        "os_release": os_release,
        "docker_server_version": docker_version,
        "max_connections": 6,
        "held_session_count": 5,
        "raw_admission_attempts": 1,
        "store_admission_attempts": 1,
        "raw_admission_timeout_seconds": RAW_ADMISSION_TIMEOUT.as_secs(),
        "store_admission_timeout_seconds": STORE_ADMISSION_TIMEOUT.as_secs(),
        "recovery_timeout_seconds": RECOVERY_TIMEOUT.as_secs(),
        "failure": "server_connection_exhaustion",
        "observed_sqlstate": "53300",
        "canonical_retry": "passed",
        "canonical_baseline_preserved": "passed",
        "cleanup": "passed",
        "foreign_state": {
            "status": "not_exercised",
            "reason": "store-only lane invokes no provider or external-state operations"
        },
        "artifact_secret_scan": {
            "status": "passed",
            "scope": "generated_artifact_values_only"
        },
        "disposition": "PASS"
    });
    let artifact_bytes = serde_json::to_vec_pretty(&artifact)?;
    let artifact_text = String::from_utf8_lossy(&artifact_bytes);
    for forbidden in ["postgres://", "password", "private_key", "token"] {
        if artifact_text.to_ascii_lowercase().contains(forbidden) {
            return Err(format!("artifact secret scan found forbidden field: {forbidden}").into());
        }
    }
    std::fs::write(evidence_path, artifact_bytes)?;
    Ok(())
}
