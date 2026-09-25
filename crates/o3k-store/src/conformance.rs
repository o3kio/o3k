//! Unified Conformance Test Suite for O3K Repositories.
//!
//! Every test in this suite is fully backend-agnostic and executes identical
//! assertions against both `SqliteStore` and `PostgresStore`.

#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]

use std::net::Ipv4Addr;
use std::str::FromStr;
use std::sync::Arc;
use uuid::Uuid;

/// Acquires a session-level advisory lock on the shared PostgreSQL test
/// database, held by the provided connection for as long as the caller keeps
/// it open. Lives in the persistence crate (the approved SQL boundary) so the
/// o3kd endpoint-lifecycle harness and the o3k-store PostgreSQL test suites
/// serialize against each other across separate `cargo test` processes without
/// embedding raw SQL outside this boundary. Test-harness-only; no-op for any
/// non-PostgreSQL caller.
pub async fn acquire_shared_postgres_test_database_lock(
    connection: &mut sqlx::postgres::PgConnection,
) -> Result<(), sqlx::Error> {
    sqlx::query("SELECT pg_advisory_lock(hashtextextended('o3k-shared-test-database', 0))")
        .execute(connection)
        .await
        .map(|_| ())
}

/// Validate a database before any destructive PostgreSQL test operation.
pub fn assert_destructive_postgres_test_database(database_url: &str) -> Result<(), String> {
    let options: sqlx::postgres::PgConnectOptions = database_url
        .parse()
        .map_err(|error| format!("invalid PostgreSQL test URL: {error}"))?;
    let purpose = std::env::var("O3K_TEST_DATABASE_PURPOSE").map_err(|_| {
        "O3K_TEST_DATABASE_PURPOSE must identify the destructive test database".to_owned()
    })?;
    assert_destructive_postgres_test_database_name(options.get_database().unwrap_or(""), &purpose)
}

pub fn assert_destructive_postgres_test_database_name(
    database: &str,
    purpose: &str,
) -> Result<(), String> {
    let expected_prefix = match purpose {
        "workspace" => "o3k_workspace_test_",
        "endpoint" => "o3k_endpoint_test_",
        "p13" => "o3k_p13_test_",
        _ => {
            return Err(format!(
                "unsupported destructive PostgreSQL test purpose {purpose:?}"
            ));
        }
    };
    if !database.starts_with(expected_prefix) || database.len() == expected_prefix.len() {
        return Err(format!(
            "refusing destructive PostgreSQL {purpose} reset for database {database:?}"
        ));
    }
    Ok(())
}

use crate::{
    AgentCommandRecord, AgentCommandState, ArtifactTransferRecord, ArtifactTransferState,
    ArtifactTransferUpdate, CanonicalOperationRecord, ComputeRepository, ControllerEpoch,
    ControllerId, ControllerSession, ControllerState, CoordinationRepository, DurableStore,
    IdempotencyReservationRequest, IdentityRepository, ImageMetadataRecord, ImageOverlayIdentity,
    ImageOverlayOwnershipRecord, ImageOverlayState, ImageOverlayUpdate, ImageRepository,
    KeypairRecord, KeypairRepository, KeystoneDomainRecord, KeystoneEndpointRecord,
    KeystoneProjectRecord, KeystoneRegionRecord, KeystoneRoleAssignmentRecord, KeystoneRoleRecord,
    KeystoneServiceRecord, KeystoneUserRecord, LeaseAcquireOutcome, LifecycleTerminalization,
    NetworkIntentRecord, NetworkRecord, NetworkRepository, ObservationUpdate, OperationRecord,
    OperationState, PlacementAllocationRecord, PlacementIntentRecord, PlacementInventoryRecord,
    PlacementRepository, PlacementResourceRecord, PortRecord, ProviderReference, ResourceRecord,
    StoreError, SubnetRecord, VolumeAttachmentRecord, VolumeAttachmentRepository,
    quota::QuotaRepository,
};
use o3k_kernel::{
    LimitKey, LimitValue, OwnershipScope, ReservationState, ResourceAmount, ScopeId, ScopeKind,
};

pub trait StoreUnderTest:
    DurableStore
    + IdentityRepository
    + KeypairRepository
    + VolumeAttachmentRepository
    + ImageRepository
    + NetworkRepository
    + PlacementRepository
    + QuotaRepository
    + ComputeRepository
    + CoordinationRepository
    + Send
    + Sync
    + 'static
{
}

impl<T> StoreUnderTest for T where
    T: DurableStore
        + IdentityRepository
        + KeypairRepository
        + VolumeAttachmentRepository
        + ImageRepository
        + NetworkRepository
        + PlacementRepository
        + QuotaRepository
        + ComputeRepository
        + CoordinationRepository
        + Send
        + Sync
        + 'static
{
}

pub async fn run_all_conformance_tests<S: StoreUnderTest>(store: Arc<S>) {
    test_durable_store_resources(store.clone()).await;
    test_list_resources_by_kind_includes_deleted_tombstones(store.clone()).await;
    test_durable_store_operations(store.clone()).await;
    test_durable_store_lifecycle_terminalization(store.clone()).await;
    test_durable_store_provider_references(store.clone()).await;
    test_durable_store_agent_commands(store.clone()).await;
    test_durable_store_artifact_transfers(store.clone()).await;
    test_durable_store_image_overlays(store.clone()).await;
    test_identity_repository(store.clone()).await;
    test_keypair_repository(store.clone()).await;
    test_volume_attachment_repository(store.clone()).await;
    test_image_repository(store.clone()).await;
    test_network_repository(store.clone()).await;
    test_placement_repository(store.clone()).await;
    test_quota_repository(store.clone()).await;
    test_coordination_repository(store.clone()).await;
    test_concurrent_finite_quota_limit_1(store.clone()).await;
    test_concurrent_placement_allocation_fencing(store.clone()).await;
    test_duplicate_port_ip_mac_conflict(store.clone()).await;
    test_operation_state_monotonicity(store.clone()).await;
}

pub async fn test_durable_store_resources<S: StoreUnderTest>(store: Arc<S>) {
    let res_id = Uuid::now_v7();
    let proj = format!("proj-{}", Uuid::now_v7());

    let record = ResourceRecord {
        id: res_id,
        kind: "compute_instance".to_owned(),
        project_id: proj.clone(),
        generation: 1,
        observed_generation: 0,
        desired_state: "active".to_owned(),
        observed_state: "building".to_owned(),
        provider_id: None,
    };

    store
        .insert_resource(&record)
        .await
        .expect("insert_resource");

    // Duplicate insert should fail with ResourceAlreadyExists
    let duplicate_err = store.insert_resource(&record).await.unwrap_err();
    assert!(matches!(duplicate_err, StoreError::ResourceAlreadyExists));

    // Get resource
    let fetched = store.get_resource(res_id).await.expect("get_resource");
    assert_eq!(fetched.id, res_id);
    assert_eq!(fetched.generation, 1);
    assert_eq!(fetched.desired_state, "active");
    assert_eq!(fetched.observed_state, "building");

    // List resources
    let list = store
        .list_resources(&proj, "compute_instance")
        .await
        .expect("list_resources");
    assert_eq!(list.len(), 1);
    assert_eq!(list[0].id, res_id);

    // Stale generation update
    let stale_err = store
        .update_resource(res_id, 999, "active", "active", 1, Some("prov-1"))
        .await
        .unwrap_err();
    assert!(matches!(stale_err, StoreError::StaleGeneration));

    // Valid update
    let updated = store
        .update_resource(res_id, 1, "active", "active", 1, Some("prov-1"))
        .await
        .expect("update_resource");
    assert_eq!(updated.generation, 2);
    assert_eq!(updated.observed_state, "active");
    assert_eq!(updated.provider_id.as_deref(), Some("prov-1"));

    // Observation update
    let obs = ObservationUpdate {
        expected_generation: 2,
        desired_state: "active",
        observed_state: "active",
        observed_generation: 2,
        provider_id: Some("prov-1"),
        agent_epoch: "epoch-1",
        observation_sequence: 10,
    };
    let obs_updated = store
        .update_resource_from_observation(res_id, &obs)
        .await
        .expect("update_resource_from_observation");
    assert_eq!(obs_updated.generation, 3);

    // Replaying older observation sequence is a no-op (doesn't fail, returns current)
    let obs_replay = ObservationUpdate {
        expected_generation: 3,
        desired_state: "active",
        observed_state: "active",
        observed_generation: 2,
        provider_id: Some("prov-1"),
        agent_epoch: "epoch-1",
        observation_sequence: 9,
    };
    let replay_res = store
        .update_resource_from_observation(res_id, &obs_replay)
        .await
        .expect("replay observation update");
    assert_eq!(replay_res.generation, 3);
}

/// `list_resources_by_kind` is the restart/repair scan: it must return every
/// resource of a kind across all projects, including `DELETED` tombstones.
/// A backend that filters terminal records here silently hides them from the
/// repair paths that reconcile tombstones, so this pins both adapters to the
/// same set for the same durable state.
pub async fn test_list_resources_by_kind_includes_deleted_tombstones<S: StoreUnderTest>(
    store: Arc<S>,
) {
    let live_id = Uuid::now_v7();
    let deleted_id = Uuid::now_v7();
    let other_kind_id = Uuid::now_v7();
    let proj_a = format!("proj-{}", Uuid::now_v7());
    let proj_b = format!("proj-{}", Uuid::now_v7());

    let record = |id: Uuid, kind: &str, project_id: &str, observed_state: &str| ResourceRecord {
        id,
        kind: kind.to_owned(),
        project_id: project_id.to_owned(),
        generation: 1,
        observed_generation: 1,
        desired_state: "{}".to_owned(),
        observed_state: observed_state.to_owned(),
        provider_id: None,
    };

    store
        .insert_resource(&record(live_id, "compute_instance", &proj_a, "ACTIVE"))
        .await
        .expect("insert live resource");
    store
        .insert_resource(&record(deleted_id, "compute_instance", &proj_b, "DELETED"))
        .await
        .expect("insert deleted tombstone");
    store
        .insert_resource(&record(other_kind_id, "volume", &proj_a, "DELETED"))
        .await
        .expect("insert other-kind resource");

    let listed = store
        .list_resources_by_kind("compute_instance")
        .await
        .expect("list_resources_by_kind");
    let ids: Vec<Uuid> = listed.iter().map(|resource| resource.id).collect();
    assert!(
        ids.contains(&live_id),
        "list_resources_by_kind must return live resources"
    );
    assert!(
        ids.contains(&deleted_id),
        "list_resources_by_kind must return DELETED tombstones: the repair scan \
         reconciles exactly the terminal records a terminal-state filter would hide"
    );
    assert!(
        !ids.contains(&other_kind_id),
        "list_resources_by_kind must be scoped to the requested kind"
    );
    let deleted = listed
        .iter()
        .find(|resource| resource.id == deleted_id)
        .expect("deleted tombstone present");
    assert_eq!(deleted.observed_state, "DELETED");
    assert_eq!(
        deleted.project_id, proj_b,
        "the scan spans projects; callers apply their own authorization scope"
    );

    // The documented ordering is by resource id, so the two adapters agree.
    let mut expected = ids.clone();
    expected.sort();
    assert_eq!(
        ids, expected,
        "list_resources_by_kind must be ordered by id"
    );
}

pub async fn test_durable_store_operations<S: StoreUnderTest>(store: Arc<S>) {
    let res_id = Uuid::now_v7();
    let proj = format!("proj-{}", Uuid::now_v7());

    let res = ResourceRecord {
        id: res_id,
        kind: "compute_instance".to_owned(),
        project_id: proj,
        generation: 1,
        observed_generation: 0,
        desired_state: "active".to_owned(),
        observed_state: "building".to_owned(),
        provider_id: None,
    };
    store.insert_resource(&res).await.expect("insert_resource");

    let op_id = Uuid::now_v7();
    let op = OperationRecord {
        id: op_id,
        resource_id: res_id,
        kind: "lifecycle:create".to_owned(),
        state: OperationState::Pending,
        provider_operation_id: None,
        error_category: None,
        error_message: None,
    };
    store.insert_operation(&op).await.expect("insert_operation");

    let fetched = store.get_operation(op_id).await.expect("get_operation");
    assert_eq!(fetched.id, op_id);
    assert_eq!(fetched.state, OperationState::Pending);

    // Non-terminal list
    let non_terminal = store
        .list_non_terminal_lifecycle_operations()
        .await
        .expect("list_non_terminal_lifecycle_operations");
    assert!(non_terminal.iter().any(|o| o.id == op_id));

    // Update to running
    store
        .update_operation(
            op_id,
            OperationState::Running,
            Some("prov-op-1"),
            None,
            None,
        )
        .await
        .expect("update_operation running");

    // Retry count increment
    let retry = store
        .increment_operation_retry(op_id)
        .await
        .expect("increment_operation_retry");
    assert_eq!(retry, 1);

    // Update to terminal succeeded
    store
        .update_operation(
            op_id,
            OperationState::Succeeded,
            Some("prov-op-1"),
            None,
            None,
        )
        .await
        .expect("update_operation succeeded");

    // Terminal operation should no longer be in non-terminal list
    let non_terminal_after = store
        .list_non_terminal_lifecycle_operations()
        .await
        .expect("list_non_terminal_lifecycle_operations");
    assert!(!non_terminal_after.iter().any(|o| o.id == op_id));
}

/// Issue #1041: lifecycle terminalization must commit the operation row and
/// the resource terminal projection in ONE transaction, reject stale writers
/// without committing anything, and converge (not double-apply) under
/// equivalent replay and concurrency. Both adapters must behave identically.
pub async fn test_durable_store_lifecycle_terminalization<S: StoreUnderTest>(store: Arc<S>) {
    // ── Fixture A: a canonical delete operation with canonical metadata ──
    let res_a = Uuid::now_v7();
    let proj_a = format!("proj-{}", Uuid::now_v7());
    store
        .insert_resource(&ResourceRecord {
            id: res_a,
            kind: "compute_instance".to_owned(),
            project_id: proj_a.clone(),
            generation: 1,
            observed_generation: 0,
            desired_state: "active".to_owned(),
            observed_state: "ACTIVE".to_owned(),
            provider_id: Some("prov-res-a".to_owned()),
        })
        .await
        .expect("insert resource A");
    let op_a = Uuid::now_v7();
    let request_a = IdempotencyReservationRequest::from_semantics(
        proj_a.clone(),
        "compute:DeleteServer",
        format!("terminalization-{op_a}"),
        "compute:server",
        None,
        &serde_json::json!({ "name": "terminalization-a" }),
        op_a,
    )
    .expect("idempotency request A");
    let canonical_a = CanonicalOperationRecord {
        id: op_a,
        service: "compute".to_owned(),
        action: "compute:DeleteServer".to_owned(),
        actor: "user-a".to_owned(),
        owner_scope: proj_a.clone(),
        resource_type: "compute:server".to_owned(),
        resource_id: Some(res_a.to_string()),
        state: OperationState::Pending,
        attempt: 0,
        created_at: "2026-09-23T00:00:00Z".to_owned(),
        started_at: None,
        finished_at: None,
        error: None,
        request_id: Some(format!("request-{op_a}")),
    };
    store
        .create_or_replay_canonical_lifecycle_operation(
            &OperationRecord {
                id: op_a,
                resource_id: res_a,
                kind: "lifecycle:delete".to_owned(),
                state: OperationState::Pending,
                provider_operation_id: None,
                error_category: None,
                error_message: None,
            },
            &canonical_a,
            &request_a,
        )
        .await
        .expect("create canonical lifecycle operation A");

    // ── 1. Atomic terminalization: one call commits the terminal pair ──
    let terminalization_a = LifecycleTerminalization {
        operation_id: op_a,
        terminal_state: OperationState::Succeeded,
        provider_operation_id: Some("prov-op-a"),
        error_category: None,
        error_message: None,
        resource_id: res_a,
        expected_generation: 1,
        desired_state: "active",
        observed_state: "DELETED",
        observed_generation: 1,
        provider_id: Some("prov-res-a"),
    };
    let (op, resource) = store
        .terminalize_lifecycle(&terminalization_a)
        .await
        .expect("terminalize A");
    // Operation and resource identity are preserved on the returned rows.
    assert_eq!(op.id, op_a);
    assert_eq!(op.resource_id, res_a);
    assert_eq!(op.state, OperationState::Succeeded);
    assert_eq!(op.provider_operation_id.as_deref(), Some("prov-op-a"));
    assert_eq!(resource.id, res_a);
    assert_eq!(resource.generation, 2, "exactly one generation advance");
    assert_eq!(resource.observed_state, "DELETED");
    assert_eq!(resource.observed_generation, 1);
    assert_eq!(resource.provider_id.as_deref(), Some("prov-res-a"));
    // `update_operation` parity: the canonical metadata records the finish in
    // the same transaction.
    let canonical_after = store
        .get_canonical_operation(op_a)
        .await
        .expect("canonical metadata after terminalization");
    assert!(
        canonical_after.finished_at.is_some(),
        "terminalization must finish the canonical metadata exactly like update_operation"
    );
    // The #1041 invariant: no observable state has exactly one half terminal.
    let terminal_pair = matches!(op.state, OperationState::Succeeded | OperationState::Failed)
        && resource.observed_state == "DELETED";
    assert!(
        terminal_pair,
        "operation and resource must be terminal together, got op={:?} resource={:?}",
        op.state, resource.observed_state
    );

    // ── 2. Equivalent replay: no error, no double application ──
    let (op_replay, resource_replay) = store
        .terminalize_lifecycle(&terminalization_a)
        .await
        .expect("replay terminalization A");
    assert_eq!(op_replay.state, OperationState::Succeeded);
    assert_eq!(
        resource_replay.generation, 2,
        "replay must not bump the generation again"
    );
    assert_eq!(resource_replay.observed_state, "DELETED");
    assert_eq!(resource_replay.observed_generation, 1);

    // ── 3. A conflicting terminal state is rejected; nothing is rewritten ──
    let conflict = store
        .terminalize_lifecycle(&LifecycleTerminalization {
            terminal_state: OperationState::Failed,
            error_category: Some("terminal"),
            error_message: Some("late failure evidence"),
            ..terminalization_a.clone()
        })
        .await
        .expect_err("a conflicting terminal state must be rejected");
    assert!(matches!(conflict, StoreError::Corrupt(_)), "{conflict:?}");
    let resource_after_conflict = store
        .get_resource(res_a)
        .await
        .expect("resource A after conflict");
    assert_eq!(resource_after_conflict.generation, 2);
    assert_eq!(resource_after_conflict.observed_state, "DELETED");
    let op_after_conflict = store
        .get_operation(op_a)
        .await
        .expect("operation A after conflict");
    assert_eq!(
        op_after_conflict.state,
        OperationState::Succeeded,
        "a rejected conflict must not rewrite the terminal operation"
    );
    assert_eq!(op_after_conflict.error_category, None);

    // ── 4. A conflicting provider identity is rejected ──
    let identity_conflict = store
        .terminalize_lifecycle(&LifecycleTerminalization {
            provider_operation_id: Some("prov-op-other"),
            ..terminalization_a.clone()
        })
        .await
        .expect_err("a conflicting provider identity must be rejected");
    assert!(
        matches!(identity_conflict, StoreError::Corrupt(_)),
        "{identity_conflict:?}"
    );

    // ── 5. A stale replay cannot clobber a newer legitimate write ──
    // (the revive/recreate shape: the resource moved on after the
    // terminalization; replaying the old terminalization must converge
    // without restoring the terminal projection over the newer intent).
    let advanced = store
        .update_resource(res_a, 2, "active", "ACTIVE", 2, Some("prov-res-a"))
        .await
        .expect("advance resource A");
    assert_eq!(advanced.generation, 3);
    let (op_stale, resource_stale) = store
        .terminalize_lifecycle(&terminalization_a)
        .await
        .expect("stale replay still converges without error");
    assert_eq!(op_stale.state, OperationState::Succeeded);
    assert_eq!(
        resource_stale.generation, 3,
        "replay must not clobber the newer write"
    );
    assert_eq!(resource_stale.observed_state, "ACTIVE");

    // ── 6. Stale generation rejection rolls back the WHOLE terminalization ──
    let res_b = Uuid::now_v7();
    let proj_b = format!("proj-{}", Uuid::now_v7());
    store
        .insert_resource(&ResourceRecord {
            id: res_b,
            kind: "compute_instance".to_owned(),
            project_id: proj_b,
            generation: 1,
            observed_generation: 0,
            desired_state: "active".to_owned(),
            observed_state: "ACTIVE".to_owned(),
            provider_id: Some("prov-res-b".to_owned()),
        })
        .await
        .expect("insert resource B");
    let op_b = Uuid::now_v7();
    store
        .insert_operation(&OperationRecord {
            id: op_b,
            resource_id: res_b,
            kind: "lifecycle:delete".to_owned(),
            state: OperationState::Running,
            provider_operation_id: Some("prov-op-b".to_owned()),
            error_category: None,
            error_message: None,
        })
        .await
        .expect("insert operation B");
    let mismatched_resource = store
        .terminalize_lifecycle(&LifecycleTerminalization {
            operation_id: op_b,
            terminal_state: OperationState::Succeeded,
            provider_operation_id: Some("prov-op-b"),
            error_category: None,
            error_message: None,
            // Operation B belongs to resource B. Supplying resource A must
            // not let one transaction terminalize B while projecting A.
            resource_id: res_a,
            expected_generation: 3,
            desired_state: "active",
            observed_state: "DELETED",
            observed_generation: 3,
            provider_id: Some("prov-res-a"),
        })
        .await
        .expect_err("operation/resource identity mismatch must be rejected");
    assert!(
        matches!(mismatched_resource, StoreError::Corrupt(_)),
        "{mismatched_resource:?}"
    );
    assert_eq!(
        store
            .get_operation(op_b)
            .await
            .expect("operation B after identity mismatch")
            .state,
        OperationState::Running,
        "identity mismatch must leave the operation non-terminal"
    );
    let res_a_after_mismatch = store
        .get_resource(res_a)
        .await
        .expect("resource A after identity mismatch");
    assert_eq!(res_a_after_mismatch.generation, 3);
    assert_eq!(res_a_after_mismatch.observed_state, "ACTIVE");

    let stale = store
        .terminalize_lifecycle(&LifecycleTerminalization {
            operation_id: op_b,
            terminal_state: OperationState::Succeeded,
            provider_operation_id: Some("prov-op-b"),
            error_category: None,
            error_message: None,
            resource_id: res_b,
            expected_generation: 999,
            desired_state: "active",
            observed_state: "DELETED",
            observed_generation: 999,
            provider_id: Some("prov-res-b"),
        })
        .await
        .expect_err("stale generation must be rejected");
    assert!(matches!(stale, StoreError::StaleGeneration), "{stale:?}");
    // The crash boundary: the rejected terminalization committed nothing —
    // the operation is NOT terminal and the resource projection is untouched,
    // so no half-committed pair exists and the operation stays re-drivable.
    let op_b_after = store
        .get_operation(op_b)
        .await
        .expect("operation B after stale rejection");
    assert_eq!(
        op_b_after.state,
        OperationState::Running,
        "a rejected terminalization must leave the operation non-terminal"
    );
    assert_eq!(
        op_b_after.provider_operation_id.as_deref(),
        Some("prov-op-b")
    );
    let res_b_after = store
        .get_resource(res_b)
        .await
        .expect("resource B after stale rejection");
    assert_eq!(res_b_after.generation, 1);
    assert_eq!(res_b_after.observed_state, "ACTIVE");
    let non_terminal_b = store
        .list_non_terminal_lifecycle_operations()
        .await
        .expect("non-terminal lifecycle operations");
    assert!(
        non_terminal_b.iter().any(|o| o.id == op_b),
        "the non-terminal operation must remain listed for re-drive"
    );

    // ── 7. Concurrent equivalent terminalizations converge exactly once ──
    let res_c = Uuid::now_v7();
    let proj_c = format!("proj-{}", Uuid::now_v7());
    store
        .insert_resource(&ResourceRecord {
            id: res_c,
            kind: "compute_instance".to_owned(),
            project_id: proj_c.clone(),
            generation: 1,
            observed_generation: 0,
            desired_state: "active".to_owned(),
            observed_state: "ACTIVE".to_owned(),
            provider_id: Some("prov-res-c".to_owned()),
        })
        .await
        .expect("insert resource C");
    let op_c = Uuid::now_v7();
    store
        .insert_operation(&OperationRecord {
            id: op_c,
            resource_id: res_c,
            kind: "lifecycle:delete".to_owned(),
            state: OperationState::Pending,
            provider_operation_id: None,
            error_category: None,
            error_message: None,
        })
        .await
        .expect("insert operation C");
    let mut tasks = Vec::new();
    for _ in 0..8 {
        let store = store.clone();
        tasks.push(tokio::spawn(async move {
            store
                .terminalize_lifecycle(&LifecycleTerminalization {
                    operation_id: op_c,
                    terminal_state: OperationState::Succeeded,
                    provider_operation_id: Some("prov-op-c"),
                    error_category: None,
                    error_message: None,
                    resource_id: res_c,
                    expected_generation: 1,
                    desired_state: "active",
                    observed_state: "DELETED",
                    observed_generation: 1,
                    provider_id: Some("prov-res-c"),
                })
                .await
        }));
    }
    for task in tasks {
        let (op, resource) = task
            .await
            .expect("join concurrent terminalization")
            .expect("concurrent equivalent terminalization converges");
        assert_eq!(op.id, op_c);
        assert_eq!(resource.id, res_c);
    }
    let op_c_final = store
        .get_operation(op_c)
        .await
        .expect("operation C after concurrency");
    assert_eq!(op_c_final.state, OperationState::Succeeded);
    let res_c_final = store
        .get_resource(res_c)
        .await
        .expect("resource C after concurrency");
    assert_eq!(
        res_c_final.generation, 2,
        "exactly one of the concurrent terminalizations may apply"
    );
    assert_eq!(res_c_final.observed_state, "DELETED");
    assert_eq!(res_c_final.observed_generation, 1);

    // ── 8. Tombstone semantics: DELETED resources remain listed ──
    let listed = store
        .list_resources(&proj_a, "compute_instance")
        .await
        .expect("list_resources");
    assert!(
        listed.iter().any(|r| r.id == res_a),
        "the terminal resource must remain visible to list_resources"
    );
    let listed_c = store
        .list_resources(&proj_c, "compute_instance")
        .await
        .expect("list_resources C");
    assert!(
        listed_c
            .iter()
            .any(|r| r.id == res_c && r.observed_state == "DELETED"),
        "the DELETED tombstone must remain visible to list_resources"
    );
    let by_kind = store
        .list_resources_by_kind("compute_instance")
        .await
        .expect("list_resources_by_kind");
    assert!(
        by_kind
            .iter()
            .any(|r| r.id == res_c && r.observed_state == "DELETED"),
        "the DELETED tombstone must remain visible to repair scans"
    );
}

pub async fn test_durable_store_provider_references<S: StoreUnderTest>(store: Arc<S>) {
    let res_id = Uuid::now_v7();
    let proj = format!("proj-{}", Uuid::now_v7());

    let res = ResourceRecord {
        id: res_id,
        kind: "compute_instance".to_owned(),
        project_id: proj,
        generation: 1,
        observed_generation: 0,
        desired_state: "active".to_owned(),
        observed_state: "building".to_owned(),
        provider_id: None,
    };
    store.insert_resource(&res).await.expect("insert_resource");

    let pref = ProviderReference {
        resource_id: res_id,
        provider_name: "libvirt".to_owned(),
        provider_resource_id: "domain-uuid-12345".to_owned(),
    };

    store
        .attach_provider_reference(&pref)
        .await
        .expect("attach_provider_reference");

    // Duplicate provider reference fails with ProviderReferenceAlreadyExists
    let dup_err = store.attach_provider_reference(&pref).await.unwrap_err();
    assert!(matches!(
        dup_err,
        StoreError::ProviderReferenceAlreadyExists
    ));

    let fetched = store
        .get_provider_reference(res_id, "libvirt")
        .await
        .expect("get_provider_reference");
    assert_eq!(fetched.provider_resource_id, "domain-uuid-12345");
}

pub async fn test_durable_store_agent_commands<S: StoreUnderTest>(store: Arc<S>) {
    let res_id = Uuid::now_v7();
    let proj = format!("proj-{}", Uuid::now_v7());

    let res = ResourceRecord {
        id: res_id,
        kind: "compute_instance".to_owned(),
        project_id: proj,
        generation: 1,
        observed_generation: 0,
        desired_state: "active".to_owned(),
        observed_state: "building".to_owned(),
        provider_id: None,
    };
    store.insert_resource(&res).await.expect("insert_resource");

    let op_id = Uuid::now_v7();
    let op = OperationRecord {
        id: op_id,
        resource_id: res_id,
        kind: "lifecycle:create".to_owned(),
        state: OperationState::Pending,
        provider_operation_id: None,
        error_category: None,
        error_message: None,
    };
    store.insert_operation(&op).await.expect("insert_operation");

    let cmd_id = format!("cmd-{}", Uuid::now_v7());
    let idemp_key = format!("idemp-{}", Uuid::now_v7());

    let cmd = AgentCommandRecord {
        command_id: cmd_id.clone(),
        idempotency_key: idemp_key.clone(),
        operation_id: op_id,
        resource_id: res_id,
        agent_id: "agent-1".to_owned(),
        agent_epoch: "epoch-1".to_owned(),
        payload_fingerprint_sha256:
            "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef".to_owned(),
        payload: vec![1, 2, 3, 4],
        state: AgentCommandState::Pending,
        accepted_sequence: 0,
        last_sequence: 0,
        provider_operation_id: None,
        provider_resource_id: None,
    };

    store
        .insert_agent_command(&cmd)
        .await
        .expect("insert_agent_command");

    let by_id = store
        .get_agent_command(&cmd_id)
        .await
        .expect("get_agent_command");
    assert_eq!(by_id.idempotency_key, idemp_key);

    let by_idemp = store
        .get_agent_command_by_idempotency_key(&idemp_key)
        .await
        .expect("get_agent_command_by_idempotency_key");
    assert_eq!(by_idemp.command_id, cmd_id);

    let by_op = store
        .get_agent_command_by_operation(op_id)
        .await
        .expect("get_agent_command_by_operation");
    assert_eq!(by_op.command_id, cmd_id);

    store
        .update_agent_command(
            &cmd_id,
            AgentCommandState::Running,
            1,
            1,
            Some("p-op-1"),
            Some("p-res-1"),
        )
        .await
        .expect("update_agent_command");

    let rec = store
        .list_recoverable_agent_commands()
        .await
        .expect("list_recoverable_agent_commands");
    assert!(rec.iter().any(|c| c.command_id == cmd_id));
}

pub async fn test_durable_store_artifact_transfers<S: StoreUnderTest>(store: Arc<S>) {
    let res_id = Uuid::now_v7();
    let proj = format!("proj-{}", Uuid::now_v7());

    let res = ResourceRecord {
        id: res_id,
        kind: "compute_instance".to_owned(),
        project_id: proj,
        generation: 1,
        observed_generation: 0,
        desired_state: "active".to_owned(),
        observed_state: "building".to_owned(),
        provider_id: None,
    };
    store.insert_resource(&res).await.expect("insert_resource");

    let op_id = Uuid::now_v7();
    let op = OperationRecord {
        id: op_id,
        resource_id: res_id,
        kind: "lifecycle:create".to_owned(),
        state: OperationState::Pending,
        provider_operation_id: None,
        error_category: None,
        error_message: None,
    };
    store.insert_operation(&op).await.expect("insert_operation");

    let cmd_id = format!("cmd-{}", Uuid::now_v7());
    let idemp_key = format!("idemp-{}", Uuid::now_v7());
    let cmd = AgentCommandRecord {
        command_id: cmd_id.clone(),
        idempotency_key: idemp_key,
        operation_id: op_id,
        resource_id: res_id,
        agent_id: "agent-1".to_owned(),
        agent_epoch: "epoch-1".to_owned(),
        payload_fingerprint_sha256:
            "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef".to_owned(),
        payload: vec![1, 2, 3, 4],
        state: AgentCommandState::Pending,
        accepted_sequence: 0,
        last_sequence: 0,
        provider_operation_id: None,
        provider_resource_id: None,
    };
    store
        .insert_agent_command(&cmd)
        .await
        .expect("insert_agent_command");

    let transfer_id = format!("tx-{}", Uuid::now_v7());
    let transfer = ArtifactTransferRecord {
        transfer_id: transfer_id.clone(),
        command_id: cmd_id,
        operation_id: op_id,
        resource_id: res_id,
        agent_id: "agent-1".to_owned(),
        agent_epoch: "epoch-1".to_owned(),
        artifact_id: "art-1".to_owned(),
        artifact_kind: "image".to_owned(),
        sha256: "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef".to_owned(),
        size_bytes: 1024,
        expires_at_unix_ms: 1893456000000,
        format: "qcow2".to_owned(),
        chunk_size_bytes: 512,
        chunk_count: 2,
        state: ArtifactTransferState::Offered,
        contiguous_bytes: 0,
        next_chunk_index: 0,
        retry_count: 0,
        created_at: String::new(),
        updated_at: String::new(),
    };

    store
        .insert_artifact_transfer(&transfer)
        .await
        .expect("insert_artifact_transfer");

    let fetched = store
        .get_artifact_transfer(&transfer_id)
        .await
        .expect("get_artifact_transfer");
    assert_eq!(fetched.state, ArtifactTransferState::Offered);

    // Update transfer
    let update = ArtifactTransferUpdate {
        state: ArtifactTransferState::Receiving,
        contiguous_bytes: 512,
        next_chunk_index: 1,
        retry_count: 0,
    };
    let updated = store
        .update_artifact_transfer(&transfer_id, "epoch-1", update)
        .await
        .expect("update_artifact_transfer");
    assert_eq!(updated.state, ArtifactTransferState::Receiving);
    assert_eq!(updated.contiguous_bytes, 512);

    // List recoverable
    let recoverable = store
        .list_recoverable_artifact_transfers()
        .await
        .expect("list_recoverable_artifact_transfers");
    assert!(recoverable.iter().any(|t| t.transfer_id == transfer_id));

    // Terminalize the operation and expire transfers
    store
        .update_operation(op_id, OperationState::Succeeded, None, None, None)
        .await
        .expect("update_operation to succeeded");

    let expired_count = store
        .expire_transfers_of_terminal_operations()
        .await
        .expect("expire_transfers_of_terminal_operations");
    assert!(expired_count >= 1);

    let expired_tx = store
        .get_artifact_transfer(&transfer_id)
        .await
        .expect("get_artifact_transfer expired");
    assert_eq!(expired_tx.state, ArtifactTransferState::Expired);
}

pub async fn test_durable_store_image_overlays<S: StoreUnderTest>(store: Arc<S>) {
    let res_id = Uuid::now_v7();
    let proj = format!("proj-{}", Uuid::now_v7());

    let res = ResourceRecord {
        id: res_id,
        kind: "compute_instance".to_owned(),
        project_id: proj,
        generation: 1,
        observed_generation: 0,
        desired_state: "active".to_owned(),
        observed_state: "building".to_owned(),
        provider_id: None,
    };
    store.insert_resource(&res).await.expect("insert_resource");

    let op_id = Uuid::now_v7();
    let op = OperationRecord {
        id: op_id,
        resource_id: res_id,
        kind: "lifecycle:create".to_owned(),
        state: OperationState::Pending,
        provider_operation_id: None,
        error_category: None,
        error_message: None,
    };
    store.insert_operation(&op).await.expect("insert_operation");

    let overlay_id = format!("ovl-{}", Uuid::now_v7());
    let identity = ImageOverlayIdentity {
        resource_id: res_id,
        operation_id: op_id,
        command_id: format!("cmd-{}", Uuid::now_v7()),
        agent_id: "agent-1".to_owned(),
        agent_epoch: "epoch-1".to_owned(),
        base_sha256: "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef".to_owned(),
        base_format: "qcow2".to_owned(),
        overlay_format: "qcow2".to_owned(),
    };

    let overlay = ImageOverlayOwnershipRecord {
        overlay_id: overlay_id.clone(),
        identity: identity.clone(),
        state: ImageOverlayState::Materializing,
        created_at: String::new(),
        updated_at: String::new(),
    };

    store
        .insert_image_overlay(&overlay)
        .await
        .expect("insert_image_overlay");

    let fetched = store
        .get_image_overlay(&overlay_id)
        .await
        .expect("get_image_overlay");
    assert_eq!(fetched.state, ImageOverlayState::Materializing);

    let count = store
        .count_image_overlay_references(&identity.base_sha256, &identity.base_format)
        .await
        .expect("count_image_overlay_references");
    assert_eq!(count, 1);

    let list = store
        .list_image_overlays(res_id)
        .await
        .expect("list_image_overlays");
    assert_eq!(list.len(), 1);

    store
        .update_image_overlay(
            &overlay_id,
            &identity,
            ImageOverlayUpdate {
                state: ImageOverlayState::Ready,
            },
        )
        .await
        .expect("update_image_overlay to ready");

    let ready_fetched = store
        .get_image_overlay(&overlay_id)
        .await
        .expect("get ready");
    assert_eq!(ready_fetched.state, ImageOverlayState::Ready);

    let deleted = store
        .delete_image_overlay(&overlay_id, &identity)
        .await
        .expect("delete_image_overlay");
    assert_eq!(deleted.state, ImageOverlayState::Deleted);

    let get_deleted = store
        .get_image_overlay(&overlay_id)
        .await
        .expect("get deleted");
    assert_eq!(get_deleted.state, ImageOverlayState::Deleted);
}

pub async fn test_identity_repository<S: StoreUnderTest>(store: Arc<S>) {
    let domain_id = format!("dom-{}", Uuid::now_v7());
    let domain = KeystoneDomainRecord {
        id: domain_id.clone(),
        name: format!("domain-{}", Uuid::now_v7()),
        description: Some("Test Domain".to_owned()),
        enabled: true,
        created_at: "2026-08-17T00:00:00Z".to_owned(),
    };
    store
        .insert_keystone_domain(&domain)
        .await
        .expect("insert_keystone_domain");
    let domains = store
        .list_keystone_domains()
        .await
        .expect("list_keystone_domains");
    assert!(domains.iter().any(|d| d.id == domain_id));

    let proj_id = format!("proj-{}", Uuid::now_v7());
    let project = KeystoneProjectRecord {
        id: proj_id.clone(),
        domain_id: domain_id.clone(),
        name: format!("proj-{}", Uuid::now_v7()),
        description: Some("Test Project".to_owned()),
        enabled: true,
        created_at: "2026-08-17T00:00:00Z".to_owned(),
    };
    store
        .insert_keystone_project(&project)
        .await
        .expect("insert_keystone_project");
    let projects = store
        .list_keystone_projects()
        .await
        .expect("list_keystone_projects");
    assert!(projects.iter().any(|p| p.id == proj_id));

    let user_id = format!("usr-{}", Uuid::now_v7());
    let user = KeystoneUserRecord {
        id: user_id.clone(),
        domain_id,
        name: format!("user-{}", Uuid::now_v7()),
        password_hash: "hash".to_owned(),
        email: Some("user@test.local".to_owned()),
        enabled: true,
        created_at: "2026-08-17T00:00:00Z".to_owned(),
    };
    store
        .insert_keystone_user(&user)
        .await
        .expect("insert_keystone_user");
    let users = store
        .list_keystone_users()
        .await
        .expect("list_keystone_users");
    assert!(users.iter().any(|u| u.id == user_id));

    let role_id = format!("role-{}", Uuid::now_v7());
    let role = KeystoneRoleRecord {
        id: role_id.clone(),
        name: format!("role-{}", Uuid::now_v7()),
        description: Some("Admin Role".to_owned()),
        created_at: "2026-08-17T00:00:00Z".to_owned(),
    };
    store
        .insert_keystone_role(&role)
        .await
        .expect("insert_keystone_role");
    let roles = store
        .list_keystone_roles()
        .await
        .expect("list_keystone_roles");
    assert!(roles.iter().any(|r| r.id == role_id));

    let assignment = KeystoneRoleAssignmentRecord {
        id: format!("ra-{}", Uuid::now_v7()),
        user_id,
        project_id: proj_id,
        role_id,
        created_at: "2026-08-17T00:00:00Z".to_owned(),
    };
    store
        .insert_keystone_role_assignment(&assignment)
        .await
        .expect("insert_keystone_role_assignment");
    let assignments = store
        .list_keystone_role_assignments()
        .await
        .expect("list_keystone_role_assignments");
    assert!(assignments.iter().any(|a| a.id == assignment.id));

    let service_id = format!("srv-{}", Uuid::now_v7());
    let service = KeystoneServiceRecord {
        id: service_id.clone(),
        name: "compute".to_owned(),
        r#type: "compute".to_owned(),
        description: Some("Nova Compute Service".to_owned()),
        enabled: true,
        created_at: "2026-08-17T00:00:00Z".to_owned(),
    };
    store
        .insert_keystone_service(&service)
        .await
        .expect("insert_keystone_service");
    let services = store
        .list_keystone_services()
        .await
        .expect("list_keystone_services");
    assert!(services.iter().any(|s| s.id == service_id));

    let ep_id = format!("ep-{}", Uuid::now_v7());
    let endpoint = KeystoneEndpointRecord {
        id: ep_id.clone(),
        service_id,
        interface: "public".to_owned(),
        url: "http://127.0.0.1:8774/v2.1".to_owned(),
        region: "RegionOne".to_owned(),
        enabled: true,
        created_at: "2026-08-17T00:00:00Z".to_owned(),
    };
    store
        .insert_keystone_endpoint(&endpoint)
        .await
        .expect("insert_keystone_endpoint");
    let endpoints = store
        .list_keystone_endpoints()
        .await
        .expect("list_keystone_endpoints");
    assert!(endpoints.iter().any(|e| e.id == ep_id));

    let reg_id = format!("reg-{}", Uuid::now_v7());
    let region = KeystoneRegionRecord {
        id: reg_id.clone(),
        description: Some("Primary Region".to_owned()),
        parent_region_id: None,
        enabled: true,
        created_at: "2026-08-17T00:00:00Z".to_owned(),
    };
    store
        .insert_keystone_region(&region)
        .await
        .expect("insert_keystone_region");
    let regions = store
        .list_keystone_regions()
        .await
        .expect("list_keystone_regions");
    assert!(regions.iter().any(|r| r.id == reg_id));
}

pub async fn test_keypair_repository<S: StoreUnderTest>(store: Arc<S>) {
    let keypair_id = Uuid::now_v7();
    let user_id = format!("usr-{}", Uuid::now_v7());
    let proj_id = format!("proj-{}", Uuid::now_v7());
    let name = "my-key";

    let blob = [
        0, 0, 0, 11, b's', b's', b'h', b'-', b'e', b'd', b'2', b'5', b'5', b'1', b'9', 0, 0, 0, 32,
    ]
    .into_iter()
    .chain([9_u8; 32])
    .collect::<Vec<_>>();
    let (key_type, fingerprint, canonical) = crate::validate_public_key(&format!(
        "ssh-ed25519 {}",
        base64::Engine::encode(&base64::engine::general_purpose::STANDARD, &blob)
    ))
    .expect("validate test key");

    let kp = KeypairRecord {
        id: keypair_id,
        user_id: user_id.clone(),
        project_id: proj_id.clone(),
        name: name.to_owned(),
        key_type,
        public_key: canonical,
        fingerprint,
        created_at: "2026-08-17T00:00:00Z".to_owned(),
    };

    store.insert_keypair(&kp).await.expect("insert_keypair");

    let list = store
        .list_keypairs(&user_id, &proj_id)
        .await
        .expect("list_keypairs");
    assert_eq!(list.len(), 1);
    assert_eq!(list[0].id, keypair_id);

    let fetched = store
        .get_keypair(&user_id, &proj_id, name)
        .await
        .expect("get_keypair");
    assert_eq!(fetched.id, keypair_id);

    // Server keypair attachment
    let server_id = Uuid::now_v7();
    let srv_res = ResourceRecord {
        id: server_id,
        kind: "compute_instance".to_owned(),
        project_id: proj_id.clone(),
        generation: 1,
        observed_generation: 0,
        desired_state: r#"{"status":"active"}"#.to_owned(),
        observed_state: "active".to_owned(),
        provider_id: None,
    };
    store
        .insert_resource(&srv_res)
        .await
        .expect("insert srv for keypair");

    store
        .attach_server_keypair(server_id, keypair_id)
        .await
        .expect("attach_server_keypair");
    let attached_name = store
        .get_server_keypair_name(server_id)
        .await
        .expect("get_server_keypair_name");
    assert_eq!(attached_name.as_deref(), Some(name));

    store
        .detach_server_keypair(server_id)
        .await
        .expect("detach_server_keypair");
    let detached_name = store
        .get_server_keypair_name(server_id)
        .await
        .expect("get detached");
    assert!(detached_name.is_none());

    store
        .delete_keypair(&user_id, &proj_id, name)
        .await
        .expect("delete_keypair");
    let del_err = store
        .get_keypair(&user_id, &proj_id, name)
        .await
        .unwrap_err();
    assert!(matches!(del_err, StoreError::KeypairNotFound));
}

pub async fn test_volume_attachment_repository<S: StoreUnderTest>(store: Arc<S>) {
    let server_id = Uuid::now_v7();
    let proj_id = format!("proj-{}", Uuid::now_v7());

    let srv_res = ResourceRecord {
        id: server_id,
        kind: "compute_instance".to_owned(),
        project_id: proj_id,
        generation: 1,
        observed_generation: 0,
        desired_state: "active".to_owned(),
        observed_state: "active".to_owned(),
        provider_id: None,
    };
    store
        .insert_resource(&srv_res)
        .await
        .expect("insert srv for vol attachment");

    let att_id = Uuid::now_v7();
    let vol_id = Uuid::now_v7();

    let record = VolumeAttachmentRecord {
        id: att_id,
        server_id,
        volume_id: vol_id,
        device: "/dev/vdb".to_owned(),
        tag: Some("vol-tag-1".to_owned()),
        delete_on_termination: false,
        created_at: "2026-08-17T00:00:00Z".to_owned(),
        status: "validated".to_owned(),
        operation_id: None,
        idempotency_key: Some(format!("idemp-{}", Uuid::now_v7())),
        cinder_attachment_id: None,
        connector_host: None,
        connector_ip: None,
        connector_initiator: None,
        driver_volume_type: None,
        target_iqn: None,
        target_portal: None,
        target_lun: None,
        connection_info_digest: None,
        error: None,
    };

    store
        .insert_volume_attachment(&record)
        .await
        .expect("insert_volume_attachment");

    let by_id = store
        .get_volume_attachment_by_id(att_id)
        .await
        .expect("get by id")
        .expect("some");
    assert_eq!(by_id.volume_id, vol_id);

    let by_vol = store
        .get_volume_attachment_by_volume(vol_id)
        .await
        .expect("get by vol")
        .expect("some");
    assert_eq!(by_vol.id, att_id);

    let by_srv_vol = store
        .get_volume_attachment_by_volume_for_server(vol_id, server_id)
        .await
        .expect("get by srv vol")
        .expect("some");
    assert_eq!(by_srv_vol.id, att_id);

    let list = store
        .list_volume_attachments(server_id)
        .await
        .expect("list_volume_attachments");
    assert_eq!(list.len(), 1);

    // Update phase
    let phase_updated = store
        .update_volume_attachment_phase(att_id, "attaching", None)
        .await
        .expect("update_volume_attachment_phase");
    assert_eq!(phase_updated.status, "attaching");

    // Update outcome
    let outcome_updated = store
        .update_volume_attachment_outcome(
            att_id,
            "attached",
            Some("cinder-att-1"),
            Some("node-1"),
            Some("10.0.0.1"),
            Some("iqn.initiator"),
            Some("iscsi"),
            Some("iqn.target"),
            Some("10.0.0.2:3260"),
            Some(1),
            Some("digest-123"),
            Some("/dev/vdb"),
        )
        .await
        .expect("update_volume_attachment_outcome");
    assert_eq!(outcome_updated.status, "attached");
    assert_eq!(
        outcome_updated.cinder_attachment_id.as_deref(),
        Some("cinder-att-1")
    );

    store
        .delete_volume_attachment(server_id, att_id)
        .await
        .expect("delete_volume_attachment");
    let after_del = store
        .get_volume_attachment_by_id(att_id)
        .await
        .expect("get after del");
    assert!(after_del.is_none());
}

pub async fn test_image_repository<S: StoreUnderTest>(store: Arc<S>) {
    let img_id = Uuid::now_v7();
    let proj = format!("proj-{}", Uuid::now_v7());

    let img = ImageMetadataRecord {
        id: img_id,
        name: "ubuntu-24.04".to_owned(),
        project_id: proj.clone(),
        status: "queued".to_owned(),
        visibility: "private".to_owned(),
        container_format: "bare".to_owned(),
        disk_format: "qcow2".to_owned(),
        size: None,
        checksum: None,
    };

    store.insert_image(&img).await.expect("insert_image");

    let list = store.list_images(&proj).await.expect("list_images");
    assert!(list.iter().any(|i| i.id == img_id));

    let fetched = store
        .get_image(&proj, &img_id)
        .await
        .expect("get_image")
        .expect("some");
    assert_eq!(fetched.status, "queued");

    let activated = store
        .activate_image(&proj, &img_id, 2_000_000_000, "checksum-abc")
        .await
        .expect("activate_image");
    assert_eq!(activated.status, "active");
    assert_eq!(activated.size, Some(2_000_000_000));

    store
        .delete_image(&proj, &img_id)
        .await
        .expect("delete_image");
    let after_del = store
        .get_image(&proj, &img_id)
        .await
        .expect("get after delete");
    assert!(after_del.is_none());
}

pub async fn test_network_repository<S: StoreUnderTest>(store: Arc<S>) {
    let proj = format!("proj-{}", Uuid::now_v7());
    let other_proj = format!("proj-{}", Uuid::now_v7());

    let realm_id = Uuid::now_v7();
    let endpoint_id = Uuid::now_v7();
    let operation_id = format!("p9-address-op-{}", Uuid::now_v7());
    let allocation = store
        .allocate_network_address(
            &realm_id,
            &proj,
            &endpoint_id,
            &operation_id,
            "192.0.2.0/30",
        )
        .await
        .expect("allocate_network_address");
    assert_eq!(allocation.address, Ipv4Addr::new(192, 0, 2, 1));
    let retry = store
        .allocate_network_address(
            &realm_id,
            &proj,
            &endpoint_id,
            &operation_id,
            "192.0.2.0/30",
        )
        .await
        .expect("idempotent address allocation");
    assert_eq!(retry, allocation);
    assert!(matches!(
        store
            .allocate_network_address(
                &realm_id,
                &other_proj,
                &Uuid::now_v7(),
                &operation_id,
                "192.0.2.0/30",
            )
            .await,
        Err(StoreError::NetworkAddressConflict)
    ));
    store
        .release_network_address(&proj, &endpoint_id)
        .await
        .expect("release_network_address");
    let concurrent_realm = Uuid::now_v7();
    let concurrent_endpoint_a = Uuid::now_v7();
    let concurrent_endpoint_b = Uuid::now_v7();
    let concurrent_operation_a = format!("p9-address-op-a-{}", Uuid::now_v7());
    let concurrent_operation_b = format!("p9-address-op-b-{}", Uuid::now_v7());
    let (first, second) = tokio::join!(
        store.allocate_network_address(
            &concurrent_realm,
            &proj,
            &concurrent_endpoint_a,
            &concurrent_operation_a,
            "198.51.100.0/29",
        ),
        store.allocate_network_address(
            &concurrent_realm,
            &proj,
            &concurrent_endpoint_b,
            &concurrent_operation_b,
            "198.51.100.0/29",
        )
    );
    let first = first.expect("first concurrent allocation");
    let second = second.expect("second concurrent allocation");
    assert_ne!(first.address, second.address);

    let intent = NetworkIntentRecord {
        id: Uuid::now_v7(),
        project_id: proj.clone(),
        generation: 1,
        payload: r#"{"id":"p9-intent","generation":1}"#.to_owned(),
        plan_fingerprint_sha256: Some("abc123".to_owned()),
        status: "requested".to_owned(),
    };
    store
        .insert_network_intent(&intent)
        .await
        .expect("insert_network_intent");
    store
        .insert_network_intent(&intent)
        .await
        .expect("idempotent network intent retry");
    let mut conflicting_intent = intent.clone();
    conflicting_intent.payload = r#"{"id":"p9-intent","generation":99}"#.to_owned();
    assert!(matches!(
        store.insert_network_intent(&conflicting_intent).await,
        Err(StoreError::ResourceAlreadyExists)
    ));
    assert!(
        store
            .get_network_intent(&other_proj, &intent.id)
            .await
            .expect("cross-project intent lookup")
            .is_none()
    );
    let updated_intent = store
        .update_network_intent(
            &proj,
            &intent.id,
            1,
            r#"{"id":"p9-intent","generation":2}"#,
            Some("def456"),
            "active",
        )
        .await
        .expect("update_network_intent");
    assert_eq!(updated_intent.generation, 2);
    assert_eq!(updated_intent.status, "active");
    assert!(matches!(
        store
            .update_network_intent(&proj, &intent.id, 2, "invalid-status", None, "bogus")
            .await,
        Err(StoreError::Corrupt(_))
    ));
    assert!(matches!(
        store
            .update_network_intent(&proj, &intent.id, 2, "backwards", None, "requested")
            .await,
        Err(StoreError::Corrupt(_))
    ));
    assert!(matches!(
        store
            .update_network_intent(&proj, &intent.id, 1, "stale", None, "error")
            .await,
        Err(StoreError::StaleGeneration)
    ));
    assert_eq!(store.list_network_intents(&proj).await.unwrap().len(), 1);

    let net_id = Uuid::now_v7();

    let net = NetworkRecord {
        id: net_id,
        name: "private-net".to_owned(),
        project_id: proj.clone(),
        status: "active".to_owned(),
    };
    store.insert_network(&net).await.expect("insert_network");

    let sub_id = Uuid::now_v7();
    let sub = SubnetRecord {
        id: sub_id,
        network_id: net_id,
        name: "private-subnet".to_owned(),
        project_id: proj.clone(),
        cidr: "192.168.1.0/24".to_owned(),
        gateway_ip: Ipv4Addr::from_str("192.168.1.1").unwrap(),
        allocation_start: Ipv4Addr::from_str("192.168.1.10").unwrap(),
        allocation_end: Ipv4Addr::from_str("192.168.1.200").unwrap(),
        ip_version: 4,
        enable_dhcp: true,
    };
    store.insert_subnet(&sub).await.expect("insert_subnet");

    let port_id = Uuid::now_v7();
    let port = PortRecord {
        id: port_id,
        network_id: net_id,
        subnet_id: Some(sub_id),
        project_id: proj.clone(),
        name: "port-1".to_owned(),
        mac_address: format!(
            "fa:16:3e:{:02x}:{:02x}:{:02x}",
            (sub_id.as_bytes()[0]),
            (sub_id.as_bytes()[1]),
            (sub_id.as_bytes()[2])
        ),
        fixed_ip: Ipv4Addr::from_str("192.168.1.50").unwrap(),
        status: "DOWN".to_owned(),
        binding_host: None,
        binding_state: None,
    };
    store.insert_port(&port).await.expect("insert_port");

    let fetched_port = store
        .get_port(&proj, &port_id)
        .await
        .expect("get_port")
        .expect("some");
    assert_eq!(fetched_port.fixed_ip.to_string(), "192.168.1.50");

    let updated_port = store
        .update_port_binding(&proj, &port_id, Some("compute-node-1"), Some("bound"))
        .await
        .expect("update_port_binding");
    assert_eq!(updated_port.binding_host.as_deref(), Some("compute-node-1"));
    assert_eq!(updated_port.binding_state.as_deref(), Some("bound"));

    // Subnet deletion fails when in-use
    let in_use_sub = store.delete_subnet(&proj, &sub_id).await.unwrap_err();
    assert!(matches!(in_use_sub, StoreError::NetworkInUse));

    store
        .delete_port(&proj, &port_id)
        .await
        .expect("delete_port");
    store
        .delete_subnet(&proj, &sub_id)
        .await
        .expect("delete_subnet");
    store
        .delete_network(&proj, &net_id)
        .await
        .expect("delete_network");
}

pub async fn test_placement_repository<S: StoreUnderTest>(store: Arc<S>) {
    let node_id = format!("node-{}", Uuid::now_v7());

    let inventories = vec![
        PlacementInventoryRecord {
            resource_class: "VCPU".to_owned(),
            total: 32,
            reserved: 0,
            allocation_ratio: 1.0,
            used: 0,
        },
        PlacementInventoryRecord {
            resource_class: "MEMORY_MB".to_owned(),
            total: 65536,
            reserved: 1024,
            allocation_ratio: 1.0,
            used: 0,
        },
    ];

    let provider = store
        .register_provider(&node_id, &inventories)
        .await
        .expect("register_provider");
    assert_eq!(provider.generation, 1);
    assert_eq!(provider.inventories.len(), 2);

    let prov_id = provider.id.clone();

    // Commit allocation
    let alloc_id = format!("alloc-{}", Uuid::now_v7());
    let consumer_id = format!("consumer-{}", Uuid::now_v7());

    let alloc = PlacementAllocationRecord {
        id: alloc_id.clone(),
        provider_id: prov_id.clone(),
        consumer_id: consumer_id.clone(),
        resources: vec![
            PlacementResourceRecord {
                resource_class: "MEMORY_MB".to_owned(),
                amount: 8192,
            },
            PlacementResourceRecord {
                resource_class: "VCPU".to_owned(),
                amount: 4,
            },
        ],
    };

    let committed = store
        .commit_allocation(&prov_id, 1, &alloc)
        .await
        .expect("commit_allocation");
    assert_eq!(committed.id, alloc_id);

    // Idempotent commit of the same allocation succeeds
    let re_committed = store
        .commit_allocation(&prov_id, 1, &alloc)
        .await
        .expect("idempotent commit_allocation");
    assert_eq!(re_committed.id, alloc_id);

    // Commit of a new allocation with stale generation 1 fails (provider generation is now 2)
    let alloc2 = PlacementAllocationRecord {
        id: format!("alloc-{}", Uuid::now_v7()),
        provider_id: prov_id.clone(),
        consumer_id: format!("consumer-{}", Uuid::now_v7()),
        resources: vec![PlacementResourceRecord {
            resource_class: "VCPU".to_owned(),
            amount: 1,
        }],
    };
    let stale_alloc = store
        .commit_allocation(&prov_id, 1, &alloc2)
        .await
        .unwrap_err();
    assert!(matches!(stale_alloc, StoreError::PlacementStaleGeneration));

    // Release allocation
    store
        .release_allocation(&prov_id, &alloc_id)
        .await
        .expect("release_allocation");

    // Upsert and get intent
    let intent_id = format!("intent-{}", Uuid::now_v7());
    let intent = PlacementIntentRecord {
        id: intent_id.clone(),
        provider_id: prov_id.clone(),
        consumer_id: consumer_id.clone(),
        resources: vec![PlacementResourceRecord {
            resource_class: "VCPU".to_owned(),
            amount: 2,
        }],
    };

    store.upsert_intent(&intent).await.expect("upsert_intent");
    let fetched_intent = store
        .get_intent(&intent_id)
        .await
        .expect("get_intent")
        .expect("some");
    assert_eq!(fetched_intent.id, intent_id);

    // Reconcile consumers
    let reconcile = store
        .reconcile_consumers(&[])
        .await
        .expect("reconcile_consumers");
    assert!(
        reconcile
            .abandoned_intents
            .iter()
            .any(|i| i.id == intent_id)
    );
}

pub async fn test_quota_repository<S: StoreUnderTest>(store: Arc<S>) {
    let proj_id = format!("proj-{}", Uuid::now_v7());
    let scope = OwnershipScope::new(
        ScopeId::new_unchecked(proj_id.clone()),
        ScopeKind::Project,
        None,
        None,
    );

    let key_servers = LimitKey::new("compute", "servers").unwrap();
    let key_vcpus = LimitKey::new("compute", "vcpus").unwrap();

    // Default is unlimited
    let initial_limit = store
        .get_limit(&scope, &key_servers)
        .await
        .expect("get_limit default");
    assert_eq!(initial_limit, LimitValue::Unlimited);

    // Set finite limit
    store
        .set_limit(&scope, &key_servers, LimitValue::Maximum(2))
        .await
        .expect("set_limit 2");
    store
        .set_limit(&scope, &key_vcpus, LimitValue::Maximum(8))
        .await
        .expect("set_limit 8");

    let limit_servers = store
        .get_limit(&scope, &key_servers)
        .await
        .expect("get_limit servers");
    assert_eq!(limit_servers, LimitValue::Maximum(2));

    // Reservation 1: request 1 server, 4 vcpus (succeeds)
    let op1 = format!("op-{}", Uuid::now_v7());
    let req1 = vec![
        ResourceAmount::new(key_servers.clone(), 1),
        ResourceAmount::new(key_vcpus.clone(), 4),
    ];
    let res1 = store
        .reserve_quota(&scope, &op1, &req1)
        .await
        .expect("reserve_quota 1");
    assert_eq!(res1.state, ReservationState::Pending);

    // Idempotent retry of reservation 1 succeeds
    let res1_retry = store
        .reserve_quota(&scope, &op1, &req1)
        .await
        .expect("reserve_quota 1 retry");
    assert_eq!(res1_retry.id, res1.id);

    // Check usage
    let usage_servers = store
        .get_usage(&scope, &key_servers)
        .await
        .expect("get_usage servers");
    assert_eq!(usage_servers.in_use, 0);
    assert_eq!(usage_servers.reserved, 1);

    // Reservation 2: request 2 servers (exceeds limit 2 because 1 + 2 > 2) -> QuotaExceeded
    let op2 = format!("op-{}", Uuid::now_v7());
    let req2 = vec![ResourceAmount::new(key_servers.clone(), 2)];
    let quota_err = store.reserve_quota(&scope, &op2, &req2).await.unwrap_err();
    assert!(matches!(quota_err, StoreError::QuotaExceeded { .. }));

    // Commit reservation 1
    store
        .commit_reservation(&res1.id)
        .await
        .expect("commit_reservation");
    let committed_res = store
        .get_reservation_for_operation(&op1)
        .await
        .expect("get op1")
        .expect("some");
    assert_eq!(committed_res.state, ReservationState::Committed);

    // Release reservation 1
    store
        .release_reservation(&res1.id)
        .await
        .expect("release_reservation");
    let released_res = store
        .get_reservation_for_operation(&op1)
        .await
        .expect("get op1")
        .expect("some");
    assert_eq!(released_res.state, ReservationState::Released);

    // Re-reserving an already released operation fails with conflict
    let released_err = store.reserve_quota(&scope, &op1, &req1).await.unwrap_err();
    assert!(matches!(released_err, StoreError::ReservationConflict(_)));
}

pub async fn test_concurrent_finite_quota_limit_1<S: StoreUnderTest>(store: Arc<S>) {
    let proj = format!("proj-race-{}", Uuid::now_v7());
    let scope = OwnershipScope::new(ScopeId::new_unchecked(proj), ScopeKind::Project, None, None);
    let key = LimitKey::compute_servers();

    store
        .set_limit(&scope, &key, LimitValue::Maximum(1))
        .await
        .expect("set_limit 1");

    let num_tasks = 10;
    let mut handles = Vec::new();
    for _ in 0..num_tasks {
        let store = store.clone();
        let scope = scope.clone();
        let key = key.clone();
        let op_id = format!("op-race-{}", Uuid::now_v7());
        handles.push(tokio::spawn(async move {
            let req = vec![ResourceAmount::new(key, 1)];
            store.reserve_quota(&scope, &op_id, &req).await
        }));
    }

    let mut successes = 0;
    let mut quota_exceeded = 0;
    for handle in handles {
        match handle.await.expect("join handle") {
            Ok(_) => successes += 1,
            Err(StoreError::QuotaExceeded { .. }) => quota_exceeded += 1,
            Err(other) => panic!("unexpected error during quota race: {other:?}"),
        }
    }

    assert_eq!(
        successes, 1,
        "Exactly 1 reservation must succeed with limit=1 under race"
    );
    assert_eq!(
        quota_exceeded,
        num_tasks - 1,
        "All other concurrent requests must fail with QuotaExceeded"
    );
}

pub async fn test_concurrent_placement_allocation_fencing<S: StoreUnderTest>(store: Arc<S>) {
    let node_id = format!("node-race-{}", Uuid::now_v7());
    let inventories = vec![PlacementInventoryRecord {
        resource_class: "VCPU".to_owned(),
        total: 4,
        reserved: 0,
        allocation_ratio: 1.0,
        used: 0,
    }];
    let provider = store
        .register_provider(&node_id, &inventories)
        .await
        .expect("register_provider");

    let initial_gen = provider.generation;

    // Concurrently try to commit 2 allocations using the exact same generation
    let alloc1 = PlacementAllocationRecord {
        id: format!("alloc1-{}", Uuid::now_v7()),
        consumer_id: format!("consumer1-{}", Uuid::now_v7()),
        provider_id: provider.id.clone(),
        resources: vec![PlacementResourceRecord {
            resource_class: "VCPU".to_owned(),
            amount: 1,
        }],
    };
    let alloc2 = PlacementAllocationRecord {
        id: format!("alloc2-{}", Uuid::now_v7()),
        consumer_id: format!("consumer2-{}", Uuid::now_v7()),
        provider_id: provider.id.clone(),
        resources: vec![PlacementResourceRecord {
            resource_class: "VCPU".to_owned(),
            amount: 1,
        }],
    };

    let store1 = store.clone();
    let prov_id1 = provider.id.clone();
    let alloc1_clone = alloc1.clone();
    let h1 = tokio::spawn(async move {
        store1
            .commit_allocation(&prov_id1, initial_gen, &alloc1_clone)
            .await
    });

    let store2 = store.clone();
    let prov_id2 = provider.id.clone();
    let alloc2_clone = alloc2.clone();
    let h2 = tokio::spawn(async move {
        store2
            .commit_allocation(&prov_id2, initial_gen, &alloc2_clone)
            .await
    });

    let res1 = h1.await.expect("join h1");
    let res2 = h2.await.expect("join h2");

    let outcomes = [res1, res2];
    let successes = outcomes.iter().filter(|r| r.is_ok()).count();
    let conflicts = outcomes
        .iter()
        .filter(|r| matches!(r, Err(StoreError::PlacementStaleGeneration)))
        .count();

    assert_eq!(
        successes, 1,
        "Exactly 1 allocation must succeed for a given provider generation"
    );
    assert_eq!(
        conflicts, 1,
        "The concurrent competing allocation must fail with PlacementStaleGeneration"
    );

    // Stale generation attempt must fail with PlacementStaleGeneration
    let stale_alloc = PlacementAllocationRecord {
        id: format!("alloc-stale-{}", Uuid::now_v7()),
        consumer_id: format!("consumer-stale-{}", Uuid::now_v7()),
        provider_id: provider.id.clone(),
        resources: vec![PlacementResourceRecord {
            resource_class: "VCPU".to_owned(),
            amount: 1,
        }],
    };
    let stale_res = store.commit_allocation(&provider.id, 0, &stale_alloc).await;
    assert!(
        matches!(stale_res, Err(StoreError::PlacementStaleGeneration)),
        "Stale provider generation must be rejected"
    );
}

pub async fn test_duplicate_port_ip_mac_conflict<S: StoreUnderTest>(store: Arc<S>) {
    let proj = format!("proj-net-{}", Uuid::now_v7());
    let net_id = Uuid::now_v7();
    let net = NetworkRecord {
        id: net_id,
        project_id: proj.clone(),
        name: "test-net".to_owned(),
        status: "ACTIVE".to_owned(),
    };
    store.insert_network(&net).await.expect("insert_network");

    let subnet_id = Uuid::now_v7();
    let subnet = SubnetRecord {
        id: subnet_id,
        network_id: net_id,
        project_id: proj.clone(),
        name: "test-subnet".to_owned(),
        cidr: "192.168.1.0/24".to_owned(),
        gateway_ip: Ipv4Addr::from_str("192.168.1.1").unwrap(),
        allocation_start: Ipv4Addr::from_str("192.168.1.10").unwrap(),
        allocation_end: Ipv4Addr::from_str("192.168.1.200").unwrap(),
        ip_version: 4,
        enable_dhcp: true,
    };
    store.insert_subnet(&subnet).await.expect("insert_subnet");

    let port1_id = Uuid::now_v7();
    let port1 = PortRecord {
        id: port1_id,
        network_id: net_id,
        subnet_id: Some(subnet_id),
        project_id: proj.clone(),
        name: "port-1".to_owned(),
        fixed_ip: Ipv4Addr::from_str("192.168.1.50").unwrap(),
        mac_address: "fa:16:3e:00:11:22".to_owned(),
        binding_host: None,
        binding_state: None,
        status: "ACTIVE".to_owned(),
    };
    store.insert_port(&port1).await.expect("insert port 1");

    // Insert port with duplicate IP
    let port2_id = Uuid::now_v7();
    let port2_dup_ip = PortRecord {
        id: port2_id,
        network_id: net_id,
        subnet_id: Some(subnet_id),
        project_id: proj.clone(),
        name: "port-2".to_owned(),
        fixed_ip: Ipv4Addr::from_str("192.168.1.50").unwrap(),
        mac_address: "fa:16:3e:00:11:33".to_owned(),
        binding_host: None,
        binding_state: None,
        status: "ACTIVE".to_owned(),
    };
    let dup_ip_err = store.insert_port(&port2_dup_ip).await;
    assert!(
        dup_ip_err.is_err(),
        "Duplicate fixed IP on subnet must be rejected"
    );

    // Insert port with duplicate MAC
    let port3_id = Uuid::now_v7();
    let port3_dup_mac = PortRecord {
        id: port3_id,
        network_id: net_id,
        subnet_id: Some(subnet_id),
        project_id: proj.clone(),
        name: "port-3".to_owned(),
        fixed_ip: Ipv4Addr::from_str("192.168.1.51").unwrap(),
        mac_address: "fa:16:3e:00:11:22".to_owned(),
        binding_host: None,
        binding_state: None,
        status: "ACTIVE".to_owned(),
    };
    let dup_mac_err = store.insert_port(&port3_dup_mac).await;
    assert!(
        dup_mac_err.is_err(),
        "Duplicate MAC address must be rejected"
    );
}

pub async fn test_operation_state_monotonicity<S: StoreUnderTest>(store: Arc<S>) {
    let res_id = Uuid::now_v7();
    let proj = format!("proj-{}", Uuid::now_v7());
    let res = ResourceRecord {
        id: res_id,
        kind: "compute_instance".to_owned(),
        project_id: proj,
        generation: 1,
        observed_generation: 0,
        desired_state: "active".to_owned(),
        observed_state: "building".to_owned(),
        provider_id: None,
    };
    store.insert_resource(&res).await.expect("insert_resource");

    let op_id = Uuid::now_v7();
    let op = OperationRecord {
        id: op_id,
        resource_id: res_id,
        kind: "lifecycle:create".to_owned(),
        state: OperationState::Succeeded,
        provider_operation_id: Some("prov-op-1".to_owned()),
        error_category: None,
        error_message: None,
    };
    store.insert_operation(&op).await.expect("insert_operation");

    // Attempting to regress terminal Succeeded state fails
    let regress_res = store
        .update_operation(
            op_id,
            OperationState::Running,
            Some("prov-op-2"),
            None,
            None,
        )
        .await;
    assert!(
        regress_res.is_err(),
        "Updating terminal Succeeded operation to Running must fail"
    );
}

pub async fn test_coordination_repository<S: StoreUnderTest>(store: Arc<S>) {
    let ctrl1 = ControllerId::new(format!("ctrl-{}", Uuid::now_v7()));
    let epoch1 = ControllerEpoch::new(format!("epoch-{}", Uuid::now_v7()));
    let ctrl2 = ControllerId::new(format!("ctrl-{}", Uuid::now_v7()));
    let epoch2 = ControllerEpoch::new(format!("epoch-{}", Uuid::now_v7()));

    // 1. Register controller session
    let session = ControllerSession {
        controller_id: ctrl1.clone(),
        controller_epoch: epoch1.clone(),
        started_at: String::new(),
        heartbeat_at: String::new(),
        lease_until: String::new(),
        software_version: "0.4.0-alpha.1".to_owned(),
        source_commit: "HEAD".to_owned(),
        state: ControllerState::Active,
    };
    store
        .register_controller_session(&session, std::time::Duration::from_secs(30))
        .await
        .expect("register_controller_session");

    let sessions = store
        .list_active_controller_sessions()
        .await
        .expect("list_active_controller_sessions");
    assert!(
        sessions
            .iter()
            .any(|s| s.controller_id == ctrl1 && s.controller_epoch == epoch1),
        "registered session must be in active sessions list"
    );

    // Heartbeat
    let hb = store
        .heartbeat_controller_session(&ctrl1, &epoch1, std::time::Duration::from_secs(30))
        .await
        .expect("heartbeat");
    assert!(hb, "heartbeat on active session must succeed");

    // 2. Initial work lease acquisition
    let work_key = format!("op:{}", Uuid::now_v7());
    let outcome = store
        .acquire_work_lease(
            &work_key,
            "operation",
            &ctrl1,
            &epoch1,
            std::time::Duration::from_secs(30),
        )
        .await
        .expect("acquire_work_lease");

    let lease = match outcome {
        LeaseAcquireOutcome::Acquired { lease } => {
            assert_eq!(lease.work_key, work_key);
            assert_eq!(lease.owner_controller_id, ctrl1);
            assert_eq!(lease.owner_controller_epoch, epoch1);
            assert_eq!(lease.fencing_token, 1);
            lease
        }
        LeaseAcquireOutcome::Busy { .. } => panic!("first acquire must succeed"),
    };

    // Inspect
    let inspected = store
        .inspect_work_lease(&work_key)
        .await
        .expect("inspect_work_lease")
        .expect("lease must exist");
    assert_eq!(inspected, lease);

    // 3. Same owner re-acquisition preserves fencing token
    let reacquired = store
        .acquire_work_lease(
            &work_key,
            "operation",
            &ctrl1,
            &epoch1,
            std::time::Duration::from_secs(30),
        )
        .await
        .expect("reacquire_work_lease");
    match reacquired {
        LeaseAcquireOutcome::Acquired { lease: re_lease } => {
            assert_eq!(
                re_lease.fencing_token, 1,
                "re-acquisition by same owner must not bump fencing token"
            );
        }
        _ => panic!("same owner reacquire must succeed"),
    }

    // 4. Renewal by owner
    let renewed = store
        .renew_work_lease(
            &work_key,
            &ctrl1,
            &epoch1,
            1,
            std::time::Duration::from_secs(30),
        )
        .await
        .expect("renew_work_lease");
    assert!(renewed, "valid renewal must return true");

    // Renewal with stale fencing token fails
    let stale_renew = store
        .renew_work_lease(
            &work_key,
            &ctrl1,
            &epoch1,
            99,
            std::time::Duration::from_secs(30),
        )
        .await
        .expect("stale renew");
    assert!(!stale_renew, "stale fencing token renewal must fail");

    // 5. Competing controller sees Busy
    let busy_outcome = store
        .acquire_work_lease(
            &work_key,
            "operation",
            &ctrl2,
            &epoch2,
            std::time::Duration::from_secs(30),
        )
        .await
        .expect("competing acquire");
    match busy_outcome {
        LeaseAcquireOutcome::Busy {
            owner_controller_id,
            fencing_token,
            ..
        } => {
            assert_eq!(owner_controller_id, ctrl1);
            assert_eq!(fencing_token, 1);
        }
        _ => panic!("competing controller must see Busy on active lease"),
    }

    // 6. Expired lease takeover atomically increments fencing token
    let expire_key = format!("op-expire:{}", Uuid::now_v7());
    let exp_outcome1 = store
        .acquire_work_lease(
            &expire_key,
            "operation",
            &ctrl1,
            &epoch1,
            std::time::Duration::from_millis(500),
        )
        .await
        .expect("acquire expire lease");
    match exp_outcome1 {
        LeaseAcquireOutcome::Acquired { lease } => {
            assert_eq!(lease.fencing_token, 1);
        }
        _ => panic!("acquire expire lease must succeed"),
    }

    // Wait for expiration
    tokio::time::sleep(std::time::Duration::from_millis(1500)).await;

    // Takeover by ctrl2
    let exp_outcome2 = store
        .acquire_work_lease(
            &expire_key,
            "operation",
            &ctrl2,
            &epoch2,
            std::time::Duration::from_secs(30),
        )
        .await
        .expect("takeover expired lease");
    match exp_outcome2 {
        LeaseAcquireOutcome::Acquired { lease } => {
            assert_eq!(lease.owner_controller_id, ctrl2);
            assert_eq!(
                lease.fencing_token, 2,
                "takeover must increment fencing token (1 -> 2)"
            );
        }
        _ => panic!("takeover on expired lease must succeed"),
    }

    // Old owner ctrl1 tries to renew with old fence 1 -> rejected!
    let old_renew = store
        .renew_work_lease(
            &expire_key,
            &ctrl1,
            &epoch1,
            1,
            std::time::Duration::from_secs(30),
        )
        .await
        .expect("old renew");
    assert!(!old_renew, "old owner must be fenced after takeover");

    // Old owner ctrl1 tries to release with old fence 1 -> rejected!
    let old_release = store
        .release_work_lease(&expire_key, &ctrl1, &epoch1, 1)
        .await
        .expect("old release");
    assert!(!old_release, "old owner release must be rejected");

    // Current owner ctrl2 releases cleanly
    let new_release = store
        .release_work_lease(&expire_key, &ctrl2, &epoch2, 2)
        .await
        .expect("new release");
    assert!(new_release, "current owner release must succeed");

    let after_release = store
        .inspect_work_lease(&expire_key)
        .await
        .expect("inspect after release");
    assert!(after_release.is_none(), "released lease must be removed");

    // 7. Drain controller session
    let drain_res = store
        .drain_controller_session(&ctrl1, &epoch1)
        .await
        .expect("drain_controller_session");
    assert!(drain_res, "drain session must succeed");

    let sessions_after_drain = store
        .list_active_controller_sessions()
        .await
        .expect("list active sessions after drain");
    assert!(
        !sessions_after_drain
            .iter()
            .any(|s| s.controller_id == ctrl1 && s.controller_epoch == epoch1),
        "drained session must not appear in active sessions list"
    );
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{PostgresStore, SqliteStore};
    use sqlx::{Connection, postgres::PgConnection};

    async fn prepare_shared_postgres_test_database(database_url: &str) -> Option<PgConnection> {
        super::assert_destructive_postgres_test_database(database_url)
            .expect("destructive PostgreSQL test database must have the expected purpose");
        let mut connection = PgConnection::connect(database_url).await.ok()?;
        super::acquire_shared_postgres_test_database_lock(&mut connection)
            .await
            .ok()?;
        sqlx::query("DROP SCHEMA IF EXISTS public CASCADE")
            .execute(&mut connection)
            .await
            .ok()?;
        sqlx::query("CREATE SCHEMA public")
            .execute(&mut connection)
            .await
            .ok()?;
        Some(connection)
    }

    #[test]
    fn destructive_database_guard_rejects_campaign_and_accepts_distinct_test_purposes() {
        let campaign = "o3k_pp5_s5_990924025";
        let workspace = "o3k_workspace_test_990924025";
        let endpoint = "o3k_endpoint_test_990924025";
        assert_ne!(campaign, workspace);
        assert_ne!(campaign, endpoint);
        assert_ne!(workspace, endpoint);
        assert!(
            super::assert_destructive_postgres_test_database_name(campaign, "workspace").is_err()
        );
        assert!(
            super::assert_destructive_postgres_test_database_name(workspace, "workspace").is_ok()
        );
        assert!(
            super::assert_destructive_postgres_test_database_name(endpoint, "endpoint").is_ok()
        );
        assert!(
            super::assert_destructive_postgres_test_database_name(workspace, "endpoint").is_err()
        );
    }

    #[tokio::test]
    async fn test_sqlite_conformance() {
        let store = Arc::new(SqliteStore::connect("sqlite::memory:").await.unwrap());
        run_all_conformance_tests(store).await;
    }

    #[tokio::test]
    async fn test_postgres_conformance() {
        // A configured backend is a requirement, not a hint. The whole point of
        // this arm is to prove the PostgreSQL adapter, so an unreachable
        // server must fail the suite when the backend was explicitly
        // configured — otherwise `cargo test -p o3k-store` passes without ever
        // exercising PostgreSQL. Only the unconfigured local default may skip.
        let configured = std::env::var("O3K_DATABASE_URL").ok();
        let db_url = configured
            .clone()
            .unwrap_or_else(|| "postgres://o3k:password@127.0.0.1/o3k_test".to_owned());
        let Some(_database_guard) = prepare_shared_postgres_test_database(&db_url).await else {
            assert!(
                configured.is_none(),
                "O3K_DATABASE_URL is configured but the PostgreSQL conformance database \
                 could not be prepared; the PostgreSQL adapter is unproven"
            );
            eprintln!("Skipping test_postgres_conformance: no Postgres instance available");
            return;
        };
        let store = PostgresStore::connect(&db_url)
            .await
            .expect("connect to Postgres");
        store
            .clean_tables_for_testing()
            .await
            .expect("clean tables");
        run_all_conformance_tests(Arc::new(store)).await;
    }

    /// Process-restart shape for the terminalization pair (issue #1041):
    /// terminalize, drop every in-memory handle, reopen the same durable
    /// file, and prove the terminal state is stable and an equivalent replay
    /// stays a no-op. A restarted control plane must see exactly what the
    /// crashed one committed — both halves or neither.
    #[tokio::test]
    async fn test_sqlite_lifecycle_terminalization_survives_store_reopen() {
        let path = std::env::temp_dir().join(format!(
            "o3k-terminalization-reopen-{}-{}.sqlite",
            std::process::id(),
            Uuid::now_v7()
        ));
        let _ = std::fs::remove_file(&path);
        let store = crate::testkit::open_file(&path).await.unwrap();
        let res_id = Uuid::now_v7();
        let proj = format!("proj-{}", Uuid::now_v7());
        store
            .insert_resource(&ResourceRecord {
                id: res_id,
                kind: "compute_instance".to_owned(),
                project_id: proj,
                generation: 1,
                observed_generation: 0,
                desired_state: "active".to_owned(),
                observed_state: "ACTIVE".to_owned(),
                provider_id: Some("prov-res".to_owned()),
            })
            .await
            .unwrap();
        let op_id = Uuid::now_v7();
        store
            .insert_operation(&OperationRecord {
                id: op_id,
                resource_id: res_id,
                kind: "lifecycle:delete".to_owned(),
                state: OperationState::Pending,
                provider_operation_id: None,
                error_category: None,
                error_message: None,
            })
            .await
            .unwrap();
        let terminalization = LifecycleTerminalization {
            operation_id: op_id,
            terminal_state: OperationState::Succeeded,
            provider_operation_id: Some("prov-op"),
            error_category: None,
            error_message: None,
            resource_id: res_id,
            expected_generation: 1,
            desired_state: "active",
            observed_state: "DELETED",
            observed_generation: 1,
            provider_id: Some("prov-res"),
        };
        store
            .terminalize_lifecycle(&terminalization)
            .await
            .expect("terminalize before reopen");
        drop(store);

        // The process restarts: only the durable file survives.
        let reopened = crate::testkit::open_file(&path).await.unwrap();
        let (op, resource) = reopened
            .terminalize_lifecycle(&terminalization)
            .await
            .expect("replay after reopen");
        assert_eq!(op.id, op_id);
        assert_eq!(op.state, OperationState::Succeeded);
        assert_eq!(resource.id, res_id);
        assert_eq!(
            resource.generation, 2,
            "replay after restart must not re-apply"
        );
        assert_eq!(resource.observed_state, "DELETED");
        assert_eq!(resource.observed_generation, 1);
        let _ = std::fs::remove_file(&path);
    }

    /// PostgreSQL lane for the issue-#1041 terminalization semantics: real
    /// concurrency against a real server, proving the atomic pair, the
    /// exactly-once application, and the stale-write rollback hold under the
    /// production engine's locking, not only SQLite's.
    ///
    /// Fails closed: a requested PostgreSQL regression with `O3K_DATABASE_URL`
    /// unset or the host unreachable panics rather than silently skipping
    /// (the `pp4_endpoint_lifecycle` PostgreSQL pattern).
    #[tokio::test]
    #[ignore = "requires O3K_DATABASE_URL (PostgreSQL)"]
    async fn test_postgres_lifecycle_terminalization_regression() {
        let db_url = std::env::var("O3K_DATABASE_URL").unwrap_or_else(|_| {
            panic!("O3K_DATABASE_URL must be set to run the PostgreSQL terminalization regression")
        });
        let Some(_database_guard) = prepare_shared_postgres_test_database(&db_url).await else {
            panic!(
                "O3K_DATABASE_URL is configured but the PostgreSQL conformance database \
                 could not be prepared; the PostgreSQL terminalization regression is unproven"
            );
        };
        let store = PostgresStore::connect(&db_url)
            .await
            .expect("connect to the configured PostgreSQL conformance database");
        store
            .clean_tables_for_testing()
            .await
            .expect("clean the PostgreSQL conformance tables at test start");
        test_durable_store_lifecycle_terminalization(Arc::new(store)).await;
    }
}
