#![cfg(target_os = "linux")]

use std::{
    error::Error,
    path::{Path, PathBuf},
};

use o3k_store::{DurableStore, OperationRecord, OperationState, ResourceRecord, testkit};
use uuid::Uuid;

const MODE: &str = "O3K_MEMORY_PRESSURE_MODE";
const DB: &str = "O3K_MEMORY_PRESSURE_DB";
const RESOURCE_ID: u128 = 0x1089_0000_0000_0000_0000_0000_0000_0001;
const OPERATION_ID: u128 = 0x1089_0000_0000_0000_0000_0000_0000_0002;

#[tokio::test]
#[ignore = "requires a disposable 256 MiB no-swap container"]
async fn sqlite_memory_pressure_kills_only_child_and_replays_operation()
-> Result<(), Box<dyn Error>> {
    let database = PathBuf::from(std::env::var(DB)?);
    let resource_id = Uuid::from_u128(RESOURCE_ID);
    let operation_id = Uuid::from_u128(OPERATION_ID);
    match std::env::var(MODE)?.as_str() {
        "setup" => setup(&database, resource_id, operation_id).await?,
        "allocate" => allocation_child(database, resource_id, operation_id).await?,
        "recover" => recover(&database, resource_id, operation_id).await?,
        mode => return Err(format!("unknown memory pressure mode: {mode}").into()),
    }
    Ok(())
}

async fn setup(
    database: &Path,
    resource_id: Uuid,
    operation_id: Uuid,
) -> Result<(), Box<dyn Error>> {
    let store = testkit::open_file(database).await?;
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
    Ok(())
}

async fn recover(
    database: &Path,
    resource_id: Uuid,
    operation_id: Uuid,
) -> Result<(), Box<dyn Error>> {
    let recovered = testkit::open_file(database).await?;
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
    std::fs::write(
        std::env::var("O3K_MEMORY_PRESSURE_VERSION_PATH")?,
        sqlite_version,
    )?;
    recovered
        .update_operation(operation_id, OperationState::Succeeded, None, None, None)
        .await?;
    assert_eq!(
        recovered.get_operation(operation_id).await?.state,
        OperationState::Succeeded
    );
    drop(recovered);
    Ok(())
}

async fn allocation_child(
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
    std::fs::write(
        std::env::var("O3K_MEMORY_PRESSURE_PHASE_PATH")?,
        "allocation-phase-ready\n",
    )?;
    let mut allocations = Vec::new();
    loop {
        allocations.push(vec![0_u8; 16 * 1024 * 1024]);
    }
}
