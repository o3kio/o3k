use super::drain_test_support::ControlledCoordination;
use super::*;
use o3k_store::{CoordinationRepository, DurableStore};
use std::os::unix::fs::PermissionsExt;

struct Fixture {
    composition: Composition,
    store: Arc<o3k_store::O3kStore>,
    coordination: Arc<ControlledCoordination>,
    root: std::path::PathBuf,
}

async fn fixture() -> Result<Fixture, Box<dyn std::error::Error>> {
    let root = std::env::temp_dir().join(format!("o3kd-drain-fixture-{}", Uuid::now_v7()));
    std::fs::create_dir(&root)?;
    std::fs::set_permissions(&root, std::fs::Permissions::from_mode(0o700))?;
    let lock = o3k_store::StoreAccessLock::acquire(&root)?;
    let store =
        Arc::new(o3k_store::O3kStore::connect_sqlite_file(&root.join("state.sqlite")).await?);
    let coordination = ControlledCoordination::new(store.clone());
    let id = o3k_store::ControllerId::new("drain-fixture");
    let epoch = o3k_store::ControllerEpoch::new("epoch-1");
    coordination
        .register_controller_session(
            &o3k_store::ControllerSession {
                controller_id: id.clone(),
                controller_epoch: epoch.clone(),
                started_at: String::new(),
                heartbeat_at: String::new(),
                lease_until: String::new(),
                software_version: "test".into(),
                source_commit: "test".into(),
                state: o3k_store::ControllerState::Active,
            },
            Duration::from_secs(15),
        )
        .await?;
    let composition = Composition {
        state: o3k_api::AppState::new(),
        controller_id: id,
        controller_epoch: epoch,
        coordination_store: coordination.clone(),
        operation_store: store.clone(),
        network_lease_tasks: network::NetworkLeaseTaskRegistry::default(),
        compute_agent_registry: o3k_compute_agent::NodeRegistry::default(),
        storage_fence: None,
        native_lvm_provider: None,
        session_heartbeat_task: tokio::spawn(async {}),
        event_task: tokio::spawn(async {}),
        console_event_task: tokio::spawn(async {}),
        attachment_reconciler: tokio::spawn(async {}),
        create_convergence_reconciler: tokio::spawn(async {}),
        lifecycle_convergence_reconciler: tokio::spawn(async {}),
        orphan_endpoint_reconciler: tokio::spawn(async {}),
        diagnostics_probe_task: tokio::spawn(async {}),
        fabric_recovery_task: None,
        inventory_task: None,
        composition_task: None,
        native_storage_recovery_task: None,
        control_task: None,
        inspect_probe_task: None,
        external_cinder_probe_task: None,
        _store_access_lock: Some(lock),
    };
    Ok(Fixture {
        composition,
        store,
        coordination,
        root,
    })
}

async fn unresolved_operation(
    store: &o3k_store::O3kStore,
    state: o3k_store::OperationState,
) -> Result<o3k_store::OperationRecord, o3k_store::StoreError> {
    let resource = o3k_store::ResourceRecord {
        id: Uuid::now_v7(),
        kind: "compute_instance".into(),
        project_id: "test".into(),
        generation: 1,
        observed_generation: 0,
        desired_state: "{}".into(),
        observed_state: "BUILD".into(),
        provider_id: None,
    };
    store.insert_resource(&resource).await?;
    let operation = o3k_store::OperationRecord {
        id: Uuid::now_v7(),
        resource_id: resource.id,
        kind: "test-drain".into(),
        state,
        provider_operation_id: Some("observe-before-retry".into()),
        error_category: None,
        error_message: None,
    };
    store.insert_operation(&operation).await?;
    Ok(operation)
}

#[tokio::test]
async fn cancelled_controller_session_drain_retains_lifetime_lock()
-> Result<(), Box<dyn std::error::Error>> {
    let Fixture {
        composition,
        store,
        coordination,
        root,
    } = fixture().await?;
    coordination.session.block();
    let mut shutdown = Box::pin(composition.shutdown());
    tokio::select! {
        result = &mut shutdown => return Err(format!("shutdown escaped session gate: {}", result.is_ok()).into()),
        () = coordination.session.entered.notified() => {}
    }
    assert_eq!(
        coordination
            .session
            .active
            .load(std::sync::atomic::Ordering::Acquire),
        1
    );
    drop(shutdown);
    assert!(o3k_store::StoreAccessLock::acquire(&root).is_err());
    assert_eq!(
        coordination
            .session
            .active
            .load(std::sync::atomic::Ordering::Acquire),
        0
    );
    store.close_for_controller_drain().await?;
    std::fs::remove_dir_all(root)?;
    Ok(())
}

#[tokio::test]
async fn unresolved_operation_without_executor_survives_successful_drain()
-> Result<(), Box<dyn std::error::Error>> {
    let Fixture {
        composition,
        store,
        root,
        ..
    } = fixture().await?;
    let operation = unresolved_operation(&store, o3k_store::OperationState::UnknownOutcome).await?;
    let proof = composition.shutdown().await?;
    assert!(o3k_store::StoreAccessLock::acquire(&root).is_err());
    assert!(
        store.insert_operation(&operation).await.is_err(),
        "closed source pool admitted a writer"
    );
    // Reopening a store may run migrations/backfills. Release the terminal
    // boundary and reacquire ownership before using that mutating opener.
    drop(proof);
    let _reacquired = o3k_store::StoreAccessLock::acquire(&root)?;
    let reopened = o3k_store::O3kStore::connect_sqlite_file(&root.join("state.sqlite")).await?;
    assert_eq!(reopened.get_operation(operation.id).await?, operation);
    reopened.close_for_controller_drain().await?;
    std::fs::remove_dir_all(root)?;
    Ok(())
}

#[tokio::test]
async fn active_executor_that_refuses_cancellation_blocks_drain()
-> Result<(), Box<dyn std::error::Error>> {
    let Fixture {
        mut composition,
        store,
        root,
        ..
    } = fixture().await?;
    let operation = unresolved_operation(&store, o3k_store::OperationState::Running).await?;
    let gate = Arc::new((std::sync::Mutex::new(false), std::sync::Condvar::new()));
    let worker_gate = gate.clone();
    let (entered, started) = tokio::sync::oneshot::channel();
    let (exited, finished) = tokio::sync::oneshot::channel();
    composition.event_task = tokio::task::spawn_blocking(move || {
        let _ = entered.send(());
        let (lock, resumed) = &*worker_gate;
        if let Ok(mut released) = lock.lock() {
            while !*released {
                match resumed.wait(released) {
                    Ok(next) => released = next,
                    Err(_) => break,
                }
            }
        }
        let _ = exited.send(());
    });
    tokio::time::timeout(Duration::from_secs(2), started).await??;
    let result = composition.shutdown().await;
    // Always release the blocking worker before asserting, including on a
    // regression that incorrectly returns success.
    let (lock, resumed) = &*gate;
    *lock
        .lock()
        .map_err(|_| std::io::Error::other("worker gate poisoned"))? = true;
    resumed.notify_all();
    tokio::time::timeout(Duration::from_secs(2), finished).await??;
    assert!(result.is_err());
    assert!(o3k_store::StoreAccessLock::acquire(&root).is_err());
    assert_eq!(store.get_operation(operation.id).await?, operation);
    store.close_for_controller_drain().await?;
    std::fs::remove_dir_all(root)?;
    Ok(())
}
