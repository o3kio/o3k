//! Real PostgreSQL outage/reconnect evidence for PP.6.5.
//!
//! The ignored test owns one UUID-named `postgres:16.4` Docker container. It
//! binds only an ephemeral loopback port and never touches the CI PostgreSQL
//! service or any host cluster.

#![allow(clippy::expect_used, clippy::unwrap_used, clippy::panic)]

use o3k_store::{DurableStore, OperationRecord, OperationState, PostgresStore, ResourceRecord};
use std::net::{TcpListener, TcpStream};
use std::process::Command;
use std::time::Duration;
use tokio::time::{sleep, timeout};
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
                    .args(["exec", &self.id, "pg_isready", "-U", "postgres"])
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
    fn url(&self) -> String {
        format!(
            "postgres://127.0.0.1:{}/postgres?connect_timeout=2",
            self.port
        )
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
    let mut cluster = DisposablePostgres::start().await?;
    let url = cluster.url();
    let store = PostgresStore::connect(&url).await?;
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
    assert!(!rendered.contains("postgres://"));
    assert!(!rendered.contains("127.0.0.1"));
    cluster.start_again().await?;
    let recovered = PostgresStore::connect(&url).await?;
    assert_eq!(
        recovered.get_operation(operation_id).await?.state,
        OperationState::Succeeded
    );
    assert_eq!(
        recovered.get_resource(resource_id).await?.desired_state,
        "ACTIVE"
    );
    cluster.stop_and_remove()?;
    Ok(())
}
