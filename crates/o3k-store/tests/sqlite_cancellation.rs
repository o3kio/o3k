//! Cancelled SQLite writes must not leave a pooled connection holding the
//! writer lock (#1126).
//!
//! The store starts write transactions with a raw `BEGIN IMMEDIATE`, which
//! sqlx does not track. When a caller cancels a write while `BEGIN IMMEDIATE`
//! is still waiting on the busy timeout, the statement keeps running on the
//! connection's worker and can take the writer lock after the caller has given
//! up. Without a rollback on release, that connection returns to the pool
//! inside an open transaction and every other writer fails with
//! `SQLITE_BUSY`. The fixture is adapted from the #1092 pressure test.

use std::time::Duration;

use o3k_store::{
    CanonicalOperationLifecycleUpdate, CanonicalOperationRecord, DurableStore,
    IdempotencyReservationRequest, OperationRecord, OperationState, ResourceRecord, SqliteStore,
    StoreError,
};
use serde_json::json;
use sqlx::sqlite::{SqliteConnectOptions, SqlitePoolOptions};
use uuid::Uuid;

struct DatabaseCleanup(std::path::PathBuf);

impl Drop for DatabaseCleanup {
    fn drop(&mut self) {
        let _ = std::fs::remove_file(&self.0);
        let _ = std::fs::remove_file(self.0.with_extension("sqlite-wal"));
        let _ = std::fs::remove_file(self.0.with_extension("sqlite-shm"));
    }
}

fn running_update() -> Result<CanonicalOperationLifecycleUpdate, StoreError> {
    CanonicalOperationLifecycleUpdate::new(
        o3k_kernel::OperationState::Running,
        1,
        Some("2026-01-01T00:01:00Z".into()),
        None,
        None,
    )
}

/// Opens a separate single-connection writer on the same file and reports
/// whether it can take the SQLite writer lock within `busy_timeout`.
async fn independent_writer_can_lock(
    path: &std::path::Path,
    busy_timeout: Duration,
) -> Result<bool, StoreError> {
    let writer = SqlitePoolOptions::new()
        .max_connections(1)
        .connect_with(
            SqliteConnectOptions::new()
                .filename(path)
                .busy_timeout(busy_timeout),
        )
        .await
        .map_err(StoreError::Database)?;
    let locked = match writer.begin_with("BEGIN IMMEDIATE").await {
        Ok(transaction) => {
            transaction.rollback().await.map_err(StoreError::Database)?;
            true
        }
        // Only SQLite lock contention means "could not lock"; any other error
        // is a fixture failure, not a held writer lock.
        Err(sqlx::Error::Database(error))
            if matches!(error.code().as_deref(), Some("5") | Some("517")) =>
        {
            false
        }
        Err(error) => return Err(StoreError::Database(error)),
    };
    writer.close().await;
    Ok(locked)
}

#[tokio::test]
async fn cancelled_lifecycle_write_releases_the_sqlite_writer_lock() -> Result<(), StoreError> {
    let path = std::env::temp_dir().join(format!("o3k-1126-cancel-{}.sqlite", Uuid::now_v7()));
    let _cleanup = DatabaseCleanup(path.clone());
    let url = format!("sqlite://{}", path.display());
    let operation_id = Uuid::now_v7();
    let resource_id = Uuid::now_v7();
    let operation = OperationRecord {
        id: operation_id,
        resource_id,
        kind: "lifecycle:create".into(),
        state: OperationState::Pending,
        provider_operation_id: None,
        error_category: None,
        error_message: None,
    };
    let canonical = CanonicalOperationRecord {
        id: operation_id,
        service: "compute".into(),
        action: "compute:CreateServer".into(),
        actor: "operator".into(),
        owner_scope: "project-1126".into(),
        resource_type: "compute:server".into(),
        resource_id: Some(resource_id.to_string()),
        state: OperationState::Pending,
        attempt: 0,
        created_at: "2026-01-01T00:00:00Z".into(),
        started_at: None,
        finished_at: None,
        error: None,
        request_id: Some("cancel-request".into()),
    };
    let request = IdempotencyReservationRequest::from_semantics(
        "project-1126",
        "compute:CreateServer",
        "cancel-key",
        "compute:server",
        None,
        &json!({"name":"cancel"}),
        operation_id,
    )?;

    let store = SqliteStore::connect(&url).await?;
    store
        .insert_resource(&ResourceRecord {
            id: resource_id,
            kind: "compute:server".into(),
            project_id: "project-1126".into(),
            generation: 1,
            observed_generation: 0,
            desired_state: "pending".into(),
            observed_state: "unknown".into(),
            provider_id: None,
        })
        .await?;
    store
        .create_or_replay_canonical_idempotent_operation(&operation, &canonical, &request)
        .await?;

    // An external writer holds the lock so the store's BEGIN IMMEDIATE waits
    // on its 5 s busy timeout.
    let locker = SqlitePoolOptions::new()
        .max_connections(1)
        .connect_with(
            SqliteConnectOptions::new()
                .filename(&path)
                .busy_timeout(Duration::from_millis(50)),
        )
        .await
        .map_err(StoreError::Database)?;
    let lock = locker
        .begin_with("BEGIN IMMEDIATE")
        .await
        .map_err(StoreError::Database)?;
    assert!(
        !independent_writer_can_lock(&path, Duration::from_millis(20)).await?,
        "the fixture must hold a real SQLite writer lock"
    );

    // Cancel the write while its BEGIN IMMEDIATE is still blocked.
    let blocked = tokio::time::timeout(
        Duration::from_millis(100),
        store.update_canonical_operation_lifecycle(operation_id, &running_update()?),
    )
    .await;
    assert!(
        blocked.is_err(),
        "the write must still be blocked when cancelled"
    );

    // Release the external lock. The abandoned BEGIN IMMEDIATE now acquires
    // it on the store connection's worker; the pool must roll that back.
    lock.rollback().await.map_err(StoreError::Database)?;
    locker.close().await;
    tokio::time::sleep(Duration::from_secs(1)).await;

    assert!(
        independent_writer_can_lock(&path, Duration::from_secs(2)).await?,
        "a cancelled store write left the SQLite writer lock held"
    );

    // The cancelled write made no change, and a retry succeeds.
    let unchanged = store.get_canonical_operation(operation_id).await?;
    assert_eq!(unchanged.state, OperationState::Pending);
    assert_eq!(unchanged.attempt, 0);
    assert_eq!(unchanged.started_at, None);
    let running = store
        .update_canonical_operation_lifecycle(operation_id, &running_update()?)
        .await?;
    assert_eq!(running.state, OperationState::Running);
    assert_eq!(running.attempt, 1);
    assert_eq!(
        store.get_operation(operation_id).await?.state,
        OperationState::Running
    );
    assert!(
        independent_writer_can_lock(&path, Duration::from_secs(2)).await?,
        "a completed store write left the SQLite writer lock held"
    );

    drop(store);
    Ok(())
}
