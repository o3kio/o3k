#![cfg(target_os = "linux")]

use std::os::unix::process::ExitStatusExt;
use std::{error::Error, path::PathBuf, time::Duration};

use o3k_store::{DurableStore, OperationRecord, OperationState, ResourceRecord, testkit};
use uuid::Uuid;

const CHILD: &str = "O3K_MEMORY_PRESSURE_CHILD";
const DB: &str = "O3K_MEMORY_PRESSURE_DB";
const RESOURCE: &str = "O3K_MEMORY_PRESSURE_RESOURCE";
const OPERATION: &str = "O3K_MEMORY_PRESSURE_OPERATION";

#[tokio::test]
#[ignore = "requires a disposable 256 MiB no-swap container"]
async fn sqlite_memory_pressure_kills_only_child_and_replays_operation()
-> Result<(), Box<dyn Error>> {
    let database = std::env::temp_dir().join(format!("o3k-1089-memory-{}.sqlite", Uuid::now_v7()));
    let resource_id = std::env::var(RESOURCE)
        .ok()
        .and_then(|v| Uuid::parse_str(&v).ok())
        .unwrap_or_else(Uuid::now_v7);
    let operation_id = std::env::var(OPERATION)
        .ok()
        .and_then(|v| Uuid::parse_str(&v).ok())
        .unwrap_or_else(Uuid::now_v7);
    if std::env::var_os(CHILD).is_some() {
        return child_case(PathBuf::from(std::env::var(DB)?), resource_id, operation_id).await;
    }
    let store = testkit::open_file(&database).await?;
    store
        .insert_resource(&ResourceRecord {
            id: resource_id,
            kind: "compute:server".into(),
            project_id: "pp6-memory".into(),
            generation: 1,
            observed_generation: 0,
            desired_state: "ACTIVE".into(),
            observed_state: "UNKNOWN".into(),
            provider_id: None,
        })
        .await?;
    store
        .insert_operation(&OperationRecord {
            id: operation_id,
            resource_id,
            kind: "compute:create".into(),
            state: OperationState::Pending,
            provider_operation_id: None,
            error_category: None,
            error_message: None,
        })
        .await?;
    drop(store);
    let mut child = tokio::process::Command::new(std::env::current_exe()?)
        .args([
            "--exact",
            "sqlite_memory_pressure_kills_only_child_and_replays_operation",
            "--nocapture",
        ])
        .env(CHILD, "1")
        .env(DB, &database)
        .env(RESOURCE, resource_id.to_string())
        .env(OPERATION, operation_id.to_string())
        .kill_on_drop(true)
        .spawn()?;
    let status = tokio::time::timeout(Duration::from_secs(60), child.wait()).await??;
    assert_eq!(
        status.signal(),
        Some(9),
        "child must be SIGKILL OOM victim, status={status}"
    );
    let recovered = testkit::open_file(&database).await?;
    let expected_resource = ResourceRecord {
        id: resource_id,
        kind: "compute:server".into(),
        project_id: "pp6-memory".into(),
        generation: 1,
        observed_generation: 0,
        desired_state: "ACTIVE".into(),
        observed_state: "UNKNOWN".into(),
        provider_id: None,
    };
    let expected_operation = OperationRecord {
        id: operation_id,
        resource_id,
        kind: "compute:create".into(),
        state: OperationState::Pending,
        provider_operation_id: None,
        error_category: None,
        error_message: None,
    };
    assert_eq!(
        recovered.get_resource(resource_id).await?,
        expected_resource
    );
    assert_eq!(
        recovered.get_operation(operation_id).await?,
        expected_operation
    );
    let version_pool =
        sqlx::SqlitePool::connect(&format!("sqlite://{}", database.display())).await?;
    let sqlite_version: String = sqlx::query_scalar("SELECT sqlite_version()")
        .fetch_one(&version_pool)
        .await?;
    if let Some(path) = std::env::var_os("O3K_MEMORY_PRESSURE_VERSION_PATH") {
        std::fs::write(path, sqlite_version)?;
    }
    recovered
        .update_operation(operation_id, OperationState::Succeeded, None, None, None)
        .await?;
    assert_eq!(
        recovered.get_operation(operation_id).await?.state,
        OperationState::Succeeded
    );
    drop(recovered);
    for suffix in ["", "-wal", "-shm"] {
        let _ = std::fs::remove_file(format!("{}{}", database.display(), suffix));
    }
    Ok(())
}

async fn child_case(
    database: PathBuf,
    resource_id: Uuid,
    operation_id: Uuid,
) -> Result<(), Box<dyn Error>> {
    let store = testkit::open_file(&database).await?;
    assert_eq!(
        store.get_resource(resource_id).await?.project_id,
        "pp6-memory"
    );
    assert_eq!(
        store.get_operation(operation_id).await?.state,
        OperationState::Pending
    );
    let mut allocations = Vec::new();
    loop {
        allocations.push(vec![0_u8; 16 * 1024 * 1024]);
    }
}
