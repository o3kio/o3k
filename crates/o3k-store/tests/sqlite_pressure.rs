//! PP.6.5 disposable SQLite pressure coverage.
//!
//! This exercises the public O3K durable lifecycle API while a second real
//! SQLite writer holds the database lock. It deliberately cancels the
//! blocked transition before retrying, proving cancellation happened before
//! mutation without bypassing the Cloud Kernel's canonical projections.

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

#[tokio::test]
async fn sqlite_lock_timeout_cancellation_precedes_mutation_and_retry_is_safe()
-> Result<(), StoreError> {
    let path = std::env::temp_dir().join(format!("o3k-pp6-pressure-{}.sqlite", Uuid::now_v7()));
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
        owner_scope: "project-pressure".into(),
        resource_type: "compute:server".into(),
        resource_id: Some(resource_id.to_string()),
        state: OperationState::Pending,
        attempt: 0,
        created_at: "2026-01-01T00:00:00Z".into(),
        started_at: None,
        finished_at: None,
        error: None,
        request_id: Some("pressure-request".into()),
    };
    let request = IdempotencyReservationRequest::from_semantics(
        "project-pressure",
        "compute:CreateServer",
        "pressure-key",
        "compute:server",
        None,
        &json!({"name":"pressure"}),
        operation_id,
    )?;

    let store = SqliteStore::connect(&url).await?;
    store
        .insert_resource(&ResourceRecord {
            id: resource_id,
            kind: "compute:server".into(),
            project_id: "project-pressure".into(),
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
    let probe = SqlitePoolOptions::new()
        .max_connections(1)
        .connect_with(
            SqliteConnectOptions::new()
                .filename(&path)
                .busy_timeout(Duration::from_millis(20)),
        )
        .await
        .map_err(StoreError::Database)?;
    let probe_result = sqlx::query("BEGIN IMMEDIATE").execute(&probe).await;
    assert!(
        probe_result.is_err(),
        "the pressure fixture must hold a real SQLite writer lock"
    );
    probe.close().await;

    let blocked = tokio::time::timeout(
        Duration::from_millis(100),
        store.update_canonical_operation_lifecycle(
            operation_id,
            &CanonicalOperationLifecycleUpdate::new(
                o3k_kernel::OperationState::Running,
                1,
                Some("2026-01-01T00:01:00Z".into()),
                None,
                None,
            )?,
        ),
    )
    .await;
    assert!(
        blocked.is_err(),
        "the held writer lock must time out before mutation"
    );
    let unchanged = store.get_canonical_operation(operation_id).await?;
    assert_eq!(unchanged.state, OperationState::Pending);
    assert_eq!(unchanged.attempt, 0);
    assert_eq!(unchanged.started_at, None);
    assert_eq!(unchanged.finished_at, None);
    assert_eq!(unchanged.error, None);
    assert_eq!(
        store.get_operation(operation_id).await?.state,
        OperationState::Pending
    );
    drop(lock);

    let running = store
        .update_canonical_operation_lifecycle(
            operation_id,
            &CanonicalOperationLifecycleUpdate::new(
                o3k_kernel::OperationState::Running,
                1,
                Some("2026-01-01T00:01:00Z".into()),
                None,
                None,
            )?,
        )
        .await?;
    assert_eq!(running.state, OperationState::Running);
    assert_eq!(running.attempt, 1);

    let durable = store.get_operation(operation_id).await?;
    assert_eq!(durable.state, OperationState::Running);
    assert_eq!(
        store.get_canonical_operation(operation_id).await?.state,
        OperationState::Running
    );

    drop(locker);
    drop(store);
    Ok(())
}
