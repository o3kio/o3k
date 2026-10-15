//! Real PostgreSQL outage/reconnect evidence for PP.6.5.
//!
//! This test owns a disposable PostgreSQL cluster under /tmp. It never reads
//! or mutates the configured/default cluster on port 5432.

#![allow(clippy::expect_used, clippy::unwrap_used, clippy::panic)]

use std::net::TcpListener;
use std::path::PathBuf;
use std::process::Command;
use std::time::Duration;

use o3k_store::{DurableStore, OperationRecord, OperationState, PostgresStore, ResourceRecord};
use tokio::time::timeout;
use uuid::Uuid;

const PG_BIN: &str = "/usr/lib/postgresql/16/bin";

struct DisposablePostgres {
    root: PathBuf,
    socket: PathBuf,
    port: u16,
}

impl DisposablePostgres {
    fn start() -> Result<Self, Box<dyn std::error::Error>> {
        let id = Uuid::now_v7();
        let root = std::env::temp_dir().join(format!("o3k-pp6-pg-outage-{id}"));
        let socket = root.join("socket");
        let port = TcpListener::bind((std::net::Ipv4Addr::LOCALHOST, 0))?
            .local_addr()?
            .port();
        let init = Command::new(format!("{PG_BIN}/initdb"))
            .args(["-D", root.to_str().unwrap(), "--auth=trust", "--no-locale"])
            .output()?;
        if !init.status.success() {
            let _ = std::fs::remove_dir_all(&root);
            return Err(format!("initdb failed: {}", String::from_utf8_lossy(&init.stderr)).into());
        }
        std::fs::create_dir_all(&socket)?;
        let mut cluster = Self { root, socket, port };
        cluster.start_server()?;
        Ok(cluster)
    }

    fn start_server(&mut self) -> Result<(), Box<dyn std::error::Error>> {
        let options = format!("-F -p {} -k {}", self.port, self.socket.display());
        let output = Command::new(format!("{PG_BIN}/pg_ctl"))
            .args([
                "-D",
                self.root.to_str().unwrap(),
                "-l",
                self.root.join("server.log").to_str().unwrap(),
                "-o",
                &options,
                "-w",
                "start",
            ])
            .output()?;
        if !output.status.success() {
            return Err(format!(
                "pg_ctl start failed: {}",
                String::from_utf8_lossy(&output.stderr)
            )
            .into());
        }
        Ok(())
    }

    fn stop_server(&self) -> Result<(), Box<dyn std::error::Error>> {
        let output = Command::new(format!("{PG_BIN}/pg_ctl"))
            .args([
                "-D",
                self.root.to_str().unwrap(),
                "-m",
                "fast",
                "-w",
                "stop",
            ])
            .output()?;
        if !output.status.success() {
            return Err(format!(
                "pg_ctl stop failed: {}",
                String::from_utf8_lossy(&output.stderr)
            )
            .into());
        }
        Ok(())
    }

    fn url(&self) -> String {
        format!(
            "postgres://127.0.0.1:{}/postgres?connect_timeout=2",
            self.port
        )
    }
}

impl Drop for DisposablePostgres {
    fn drop(&mut self) {
        let _ = self.stop_server();
        let _ = std::fs::remove_dir_all(&self.root);
    }
}

#[tokio::test]
async fn postgres_outage_fails_bounded_and_reconnect_preserves_canonical_state()
-> Result<(), Box<dyn std::error::Error>> {
    let cluster = DisposablePostgres::start()?;
    let url = cluster.url();
    let store = PostgresStore::connect(&url).await?;
    let resource_id = Uuid::now_v7();
    let operation_id = Uuid::now_v7();
    store
        .insert_resource(&ResourceRecord {
            id: resource_id,
            kind: "compute_instance".to_owned(),
            project_id: "pp6-outage".to_owned(),
            generation: 1,
            observed_generation: 1,
            desired_state: "ACTIVE".to_owned(),
            observed_state: "ACTIVE".to_owned(),
            provider_id: None,
        })
        .await?;
    store
        .insert_operation(&OperationRecord {
            id: operation_id,
            resource_id,
            kind: "lifecycle:create".to_owned(),
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

    cluster.stop_server()?;
    let down = timeout(Duration::from_secs(5), store.get_operation(operation_id)).await;
    let error = down
        .expect("outage query must be bounded")
        .expect_err("outage query must fail closed");
    let rendered = error.to_string();
    assert!(!rendered.contains("postgres://"), "DSN leaked: {rendered}");
    assert!(
        !rendered.contains("127.0.0.1"),
        "connection detail leaked: {rendered}"
    );

    let mut restarted = DisposablePostgres {
        root: cluster.root.clone(),
        socket: cluster.socket.clone(),
        port: cluster.port,
    };
    restarted.start_server()?;
    let recovered = PostgresStore::connect(&url).await?;
    let operation = recovered.get_operation(operation_id).await?;
    assert_eq!(operation.state, OperationState::Succeeded);
    assert_eq!(operation.resource_id, resource_id);
    assert_eq!(
        recovered.get_resource(resource_id).await?.desired_state,
        "ACTIVE"
    );
    std::mem::forget(restarted);
    Ok(())
}
