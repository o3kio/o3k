//! Real PostgreSQL outage/reconnect evidence for PP.6.5.
//!
//! The ignored test owns one UUID-named `postgres:16.4` Docker container. It
//! binds only an ephemeral loopback port and never touches the CI PostgreSQL
//! service or any host cluster.

#![allow(clippy::expect_used, clippy::unwrap_used, clippy::panic)]

use o3k_store::{DurableStore, OperationRecord, OperationState, PostgresStore, ResourceRecord};
use serde_json::json;
use std::fs::OpenOptions;
use std::io::Write;
use std::net::{TcpListener, TcpStream};
use std::process::Command;
use std::time::Duration;
use tokio::time::{Instant, sleep, timeout, timeout_at};
use uuid::Uuid;

struct DisposablePostgres {
    id: String,
    name: String,
    port: u16,
    running: bool,
    removed: bool,
}

impl DisposablePostgres {
    async fn start() -> Result<Self, Box<dyn std::error::Error>> {
        let name = format!("o3k-pp6-pg-outage-{}", Uuid::now_v7());
        let port = TcpListener::bind(("127.0.0.1", 0))?.local_addr()?.port();
        let publish = format!("127.0.0.1:{port}:5432");
        let create = Command::new("docker")
            .args([
                "create",
                "--name",
                &name,
                "--env",
                "POSTGRES_HOST_AUTH_METHOD=trust",
                "--publish",
                &publish,
                "postgres:16.4",
            ])
            .output()?;
        if !create.status.success() {
            return Err(format!(
                "docker create failed (no owned container): {}",
                String::from_utf8_lossy(&create.stderr)
            )
            .into());
        }
        // `docker create` succeeded, so the UUID name is now owned even if
        // Docker returns malformed or empty ID output.
        let id = match std::str::from_utf8(&create.stdout)
            .ok()
            .map(str::trim)
            .filter(|id| id.len() == 64 && id.bytes().all(|byte| byte.is_ascii_hexdigit()))
        {
            Some(id) => id.to_owned(),
            None => {
                let cleanup = Self::remove(&name);
                return Err(format!(
                    "docker create returned invalid container ID; cleanup: {}",
                    cleanup
                        .err()
                        .map_or_else(|| "ok".to_owned(), |error| error.to_string())
                )
                .into());
            }
        };
        let mut cluster = Self {
            id,
            name,
            port,
            running: false,
            removed: false,
        };
        let started = Command::new("docker").args(["start", &cluster.id]).output();
        let started = match started {
            Ok(output) => output,
            Err(error) => {
                let cleanup = cluster.stop_and_remove();
                return Err(format!(
                    "docker start could not execute: {error}; cleanup: {}",
                    cleanup
                        .err()
                        .map_or_else(|| "ok".to_owned(), |error| error.to_string())
                )
                .into());
            }
        };
        if !started.status.success() {
            let cleanup = cluster.stop_and_remove();
            return Err(format!(
                "docker start failed: {}; cleanup: {}",
                String::from_utf8_lossy(&started.stderr),
                cleanup
                    .err()
                    .map_or_else(|| "ok".to_owned(), |error| error.to_string())
            )
            .into());
        }
        cluster.running = true;
        if let Err(error) = cluster.wait_ready().await {
            let cleanup = cluster.stop_and_remove();
            return Err(format!(
                "docker PostgreSQL readiness failed: {error}; cleanup: {}",
                cleanup
                    .err()
                    .map_or_else(|| "ok".to_owned(), |error| error.to_string())
            )
            .into());
        }
        Ok(cluster)
    }
    async fn wait_ready(&self) -> Result<(), Box<dyn std::error::Error>> {
        let ready = timeout(Duration::from_secs(30), async {
            loop {
                let result = Command::new("docker")
                    .args([
                        "exec",
                        &self.id,
                        "pg_isready",
                        "-h",
                        "127.0.0.1",
                        "-p",
                        "5432",
                        "-U",
                        "postgres",
                    ])
                    .output();
                if result.map(|r| r.status.success()).unwrap_or(false)
                    && TcpStream::connect(("127.0.0.1", self.port)).is_ok()
                {
                    break;
                }
                sleep(Duration::from_millis(250)).await;
            }
        })
        .await;
        ready.map_err(|_| "docker PostgreSQL readiness timed out".into())
    }
    async fn connect_ready(&self) -> Result<PostgresStore, Box<dyn std::error::Error>> {
        let deadline = Instant::now() + Duration::from_secs(30);
        let mut last_transient_error = String::from("unknown");
        loop {
            let url = format!(
                "postgres://postgres@127.0.0.1:{}/postgres?connect_timeout=2",
                self.port
            );
            let attempt = match timeout_at(deadline, PostgresStore::connect(&url)).await {
                Ok(result) => result,
                Err(_) => {
                    return Err(format!(
                        "PostgreSQL recovery connection timed out; last error: {}",
                        last_transient_error
                    )
                    .into());
                }
            };
            match attempt {
                Ok(store) => return Ok(store),
                Err(error) if is_transient_connect_error(&error) => {
                    last_transient_error = error.to_string();
                    if timeout_at(deadline, sleep(Duration::from_millis(250)))
                        .await
                        .is_err()
                    {
                        return Err(format!(
                            "PostgreSQL recovery connection timed out; last error: {}",
                            last_transient_error
                        )
                        .into());
                    }
                }
                Err(error) => {
                    let sqlstate = safe_sqlstate(&error).unwrap_or_else(|| "none".to_owned());
                    return Err(format!(
                        "PostgreSQL recovery connection failed (sqlstate={sqlstate})"
                    )
                    .into());
                }
            }
        }
    }
    fn server_version(&self) -> Result<String, Box<dyn std::error::Error>> {
        let output = Command::new("docker")
            .args([
                "exec",
                &self.id,
                "psql",
                "-At",
                "-U",
                "postgres",
                "-d",
                "postgres",
                "-c",
                "SHOW server_version",
            ])
            .output()?;
        if !output.status.success() {
            return Err("unable to observe PostgreSQL server version".into());
        }
        Ok(String::from_utf8(output.stdout)?.trim().to_owned())
    }
    fn stop(&mut self) -> Result<(), Box<dyn std::error::Error>> {
        if !self.running {
            return Ok(());
        }
        let out = Command::new("docker").args(["stop", &self.id]).output()?;
        if !out.status.success() {
            return Err(format!(
                "docker stop failed: {}",
                String::from_utf8_lossy(&out.stderr)
            )
            .into());
        }
        self.running = false;
        Ok(())
    }
    async fn start_again(&mut self) -> Result<(), Box<dyn std::error::Error>> {
        let out = Command::new("docker").args(["start", &self.id]).output()?;
        if !out.status.success() {
            return Err(format!(
                "docker start failed: {}",
                String::from_utf8_lossy(&out.stderr)
            )
            .into());
        }
        self.running = true;
        self.wait_ready().await
    }
    fn remove(id: &str) -> Result<(), Box<dyn std::error::Error>> {
        let out = Command::new("docker")
            .args(["rm", "--force", id])
            .output()?;
        if !out.status.success() {
            return Err(
                format!("docker rm failed: {}", String::from_utf8_lossy(&out.stderr)).into(),
            );
        }
        let inspect = Command::new("docker").args(["inspect", id]).output()?;
        if inspect.status.success() {
            return Err(format!("docker container {id} still exists after removal").into());
        }
        Ok(())
    }
    fn stop_and_remove(&mut self) -> Result<(), Box<dyn std::error::Error>> {
        if self.removed {
            return Ok(());
        }
        let stop_error = self.stop().err();
        let remove_result = Self::remove(&self.id);
        match (stop_error, remove_result) {
            (_, Ok(())) => {
                self.removed = true;
                Ok(())
            }
            (Some(stop_error), Err(remove_error)) => Err(format!(
                "docker stop failed: {stop_error}; docker remove failed: {remove_error}"
            )
            .into()),
            (None, Err(remove_error)) => Err(remove_error),
        }
    }
}

fn is_transient_connect_error(error: &o3k_store::StoreError) -> bool {
    matches!(
        error,
        o3k_store::StoreError::Database(sqlx::Error::Io(_))
            | o3k_store::StoreError::Database(sqlx::Error::PoolTimedOut)
    )
}

fn safe_sqlstate(error: &o3k_store::StoreError) -> Option<String> {
    match error {
        o3k_store::StoreError::Database(sqlx::Error::Database(database)) => {
            database.code().map(|code| code.into_owned())
        }
        _ => None,
    }
}

impl Drop for DisposablePostgres {
    fn drop(&mut self) {
        if let Err(error) = self.stop_and_remove() {
            eprintln!("owned Docker cleanup failed for {}: {error}", self.name);
        }
    }
}

#[tokio::test]
#[ignore = "required Docker PostgreSQL outage lane; invoke with --ignored"]
async fn postgres_outage_fails_bounded_and_reconnect_preserves_canonical_state()
-> Result<(), Box<dyn std::error::Error>> {
    let source_commit = git_output(&["rev-parse", "HEAD"])?;
    let source_tree = git_output(&["rev-parse", "HEAD^{tree}"])?;
    let change_head_commit = std::env::var("O3K_PP6_SOURCE_HEAD_SHA")?;
    let change_head_tree = git_output(&["rev-parse", &format!("{change_head_commit}^{{tree}}")])?;
    let evidence_path = std::env::var("O3K_PP6_PG_EVIDENCE_PATH")?;
    let mut cluster = DisposablePostgres::start().await?;
    let store = cluster
        .connect_ready()
        .await
        .map_err(|error| format!("initial PostgreSQL store connection failed: {error}"))?;
    let resource_id = Uuid::now_v7();
    let operation_id = Uuid::now_v7();
    store
        .insert_resource(&ResourceRecord {
            id: resource_id,
            kind: "compute_instance".into(),
            project_id: "pp6-outage".into(),
            generation: 1,
            observed_generation: 1,
            desired_state: "ACTIVE".into(),
            observed_state: "ACTIVE".into(),
            provider_id: None,
        })
        .await?;
    store
        .insert_operation(&OperationRecord {
            id: operation_id,
            resource_id,
            kind: "lifecycle:create".into(),
            state: OperationState::Succeeded,
            provider_operation_id: None,
            error_category: None,
            error_message: None,
        })
        .await?;
    assert_eq!(
        store.get_operation(operation_id).await?.state,
        OperationState::Succeeded
    );
    cluster.stop()?;
    let error = timeout(Duration::from_secs(5), store.get_operation(operation_id))
        .await?
        .expect_err("outage query must fail");
    let rendered = error.to_string();
    let redaction_passed = !rendered.contains("postgres://") && !rendered.contains("127.0.0.1");
    assert!(redaction_passed, "outage error exposed connection details");
    let outage_failure_observed = true;
    cluster.start_again().await?;
    let recovered = cluster.connect_ready().await?;
    assert_eq!(
        recovered.get_operation(operation_id).await?.state,
        OperationState::Succeeded
    );
    assert_eq!(
        recovered.get_resource(resource_id).await?.desired_state,
        "ACTIVE"
    );
    let database_version = cluster.server_version()?;
    cluster.stop_and_remove()?;
    if !cluster.removed {
        return Err("owned PostgreSQL container cleanup was not verified".into());
    }
    let migration_versions = sqlx::migrate!("./migrations_postgres")
        .iter()
        .map(|migration| migration.version)
        .collect::<Vec<_>>();
    let migration_count = migration_versions.len();
    let latest_migration_version = migration_versions.last().copied();
    let evidence = json!({
        "evidence_schema": "o3k.pp6.postgres-outage.v1",
        "disposition": "PASS",
        "source": {
            "repository": std::env::var("GITHUB_REPOSITORY")?,
            "checkout_commit": source_commit,
            "checkout_tree": source_tree,
            "change_head_commit": change_head_commit,
            "change_head_tree": change_head_tree,
            "run_id": std::env::var("GITHUB_RUN_ID")?,
            "run_attempt": std::env::var("GITHUB_RUN_ATTEMPT")?
        },
        "harness": {
            "test": "o3k-store::postgres_outage::postgres_outage_fails_bounded_and_reconnect_preserves_canonical_state",
            "package": "o3k-store",
            "profile": "o3k-small-edge-v1",
            "host_os": std::env::consts::OS,
            "host_arch": std::env::consts::ARCH,
            "backend_image": "postgres:16.4",
            "backend_version": database_version,
            "migration_count": migration_count,
            "latest_migration_version": latest_migration_version
        },
        "fixture": {
            "container_id": cluster.id,
            "resource_id": resource_id,
            "operation_id": operation_id
        },
        "observed": {
            "canonical_resource_persisted_before_outage": true,
            "canonical_operation_persisted_before_outage": true,
            "bounded_outage_failure_observed": outage_failure_observed,
            "connection_details_redacted": redaction_passed,
            "resource_and_operation_preserved_after_reconnect": true,
            "owned_container_removed_and_absence_verified": cluster.removed,
            "foreign_state_mutation_tested": false
        }
    });
    let mut file = OpenOptions::new()
        .write(true)
        .create_new(true)
        .open(evidence_path)?;
    serde_json::to_writer_pretty(&mut file, &evidence)?;
    file.write_all(b"\n")?;
    file.sync_all()?;
    Ok(())
}

fn git_output(args: &[&str]) -> Result<String, Box<dyn std::error::Error>> {
    let output = Command::new("git").args(args).output()?;
    if !output.status.success() {
        return Err(format!("git {:?} failed", args).into());
    }
    Ok(String::from_utf8(output.stdout)?.trim().to_owned())
}
