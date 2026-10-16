#![cfg(target_os = "linux")]
#![allow(clippy::expect_used, clippy::unwrap_used)]

use std::{error::Error, fs::File, path::PathBuf, time::Duration};

use o3k_store::{
    DurableStore, OperationRecord, OperationState, ResourceRecord, StoreError, testkit,
};
use uuid::Uuid;

const CHILD_ENV: &str = "O3K_SQLITE_FD_PRESSURE_CHILD";
const DATABASE_ENV: &str = "O3K_SQLITE_FD_PRESSURE_DATABASE";
const OPERATION_ENV: &str = "O3K_SQLITE_FD_PRESSURE_OPERATION";
const RESOURCE_ENV: &str = "O3K_SQLITE_FD_PRESSURE_RESOURCE";

struct DatabaseCleanup(PathBuf);

impl Drop for DatabaseCleanup {
    fn drop(&mut self) {
        let _ = std::fs::remove_file(&self.0);
        let _ = std::fs::remove_file(self.0.with_extension("sqlite-wal"));
        let _ = std::fs::remove_file(self.0.with_extension("sqlite-shm"));
    }
}

#[tokio::test]
async fn sqlite_store_recovers_after_child_file_descriptor_exhaustion() -> Result<(), Box<dyn Error>>
{
    if std::env::var_os(CHILD_ENV).is_some() {
        return child_case().await;
    }

    let database = std::env::temp_dir().join(format!("o3k-1089-fd-{}.sqlite", Uuid::now_v7()));
    let _cleanup = DatabaseCleanup(database.clone());
    let store = testkit::open_file(&database).await?;
    let resource = ResourceRecord {
        id: Uuid::now_v7(),
        kind: "compute:server".to_owned(),
        project_id: "pp6-fd-pressure".to_owned(),
        generation: 1,
        observed_generation: 0,
        desired_state: "ACTIVE".to_owned(),
        observed_state: "UNKNOWN".to_owned(),
        provider_id: None,
    };
    let operation = OperationRecord {
        id: Uuid::now_v7(),
        resource_id: resource.id,
        kind: "compute:create".to_owned(),
        state: OperationState::Pending,
        provider_operation_id: None,
        error_category: None,
        error_message: None,
    };
    store.insert_resource(&resource).await?;
    store.insert_operation(&operation).await?;
    drop(store);

    // `prlimit` is supplied by util-linux on the required Linux test runner.
    // Fail with an actionable setup error if that runner prerequisite is absent.
    let mut child = tokio::process::Command::new("prlimit")
        .args(["--nofile=64:64", "--"])
        .arg(std::env::current_exe()?)
        .args([
            "--exact",
            "sqlite_store_recovers_after_child_file_descriptor_exhaustion",
            "--nocapture",
        ])
        .env(CHILD_ENV, "1")
        .env(DATABASE_ENV, &database)
        .env(OPERATION_ENV, operation.id.to_string())
        .env(RESOURCE_ENV, resource.id.to_string())
        .kill_on_drop(true)
        .spawn()?;
    let status = tokio::time::timeout(Duration::from_secs(30), child.wait()).await??;
    assert!(
        status.success(),
        "low-file-descriptor child failed: {status}"
    );
    Ok(())
}

async fn child_case() -> Result<(), Box<dyn Error>> {
    let database = PathBuf::from(std::env::var(DATABASE_ENV)?);
    let operation_id = Uuid::parse_str(&std::env::var(OPERATION_ENV)?)?;
    let resource_id = Uuid::parse_str(&std::env::var(RESOURCE_ENV)?)?;
    let mut fillers = Vec::new();
    loop {
        match File::open("/dev/null") {
            Ok(file) => fillers.push(file),
            Err(error) if error.raw_os_error() == Some(24) => break,
            Err(error) => return Err(error.into()),
        }
    }
    assert!(
        !fillers.is_empty(),
        "RLIMIT_NOFILE did not create bounded pressure"
    );
    let direct_open_error = File::open(&database)
        .expect_err("database unexpectedly opened while descriptors were exhausted");
    assert_eq!(direct_open_error.raw_os_error(), Some(24));

    let pressure_error = testkit::open_file(&database)
        .await
        .expect_err("SQLite store unexpectedly opened while descriptors were exhausted");
    let database_error = match pressure_error {
        StoreError::Database(sqlx::Error::Database(database_error)) => database_error,
        error => {
            return Err(
                format!("expected SQLite CANTOPEN under EMFILE pressure, got {error:?}").into(),
            );
        }
    };
    assert_eq!(database_error.code().as_deref(), Some("14"));
    drop(fillers);

    let recovered = testkit::open_file(&database).await?;
    let resource = recovered.get_resource(resource_id).await?;
    assert_eq!(resource.generation, 1);
    assert_eq!(resource.observed_generation, 0);
    assert_eq!(resource.desired_state, "ACTIVE");
    assert_eq!(resource.observed_state, "UNKNOWN");
    assert_eq!(resource.provider_id, None);
    let operation = recovered.get_operation(operation_id).await?;
    assert_eq!(operation.state, OperationState::Pending);
    assert_eq!(operation.error_category, None);
    assert_eq!(operation.error_message, None);
    Ok(())
}
