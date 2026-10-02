#![allow(clippy::expect_used, clippy::unwrap_used)]

use o3k_store::ResourceRelationshipRecord;
use o3k_store::{
    CanonicalAcceptanceOutcome, CanonicalOperationLifecycleUpdate, CanonicalOperationRecord,
    DurableStore, IdempotencyReservation, IdempotencyReservationRequest, OperationRecord,
    OperationState, PostgresStore, ResourceRecord, StoreError,
};
use serde_json::json;
use sqlx::Row;
use sqlx::{Connection, postgres::PgConnection};
use std::sync::Arc;
use tokio::sync::Barrier;
use uuid::Uuid;

static TEST_DATABASE_LOCK: tokio::sync::Mutex<()> = tokio::sync::Mutex::const_new(());

fn url() -> String {
    std::env::var("O3K_DATABASE_URL")
        .expect("O3K_DATABASE_URL must be set for PostgreSQL P12.4 conformance")
}

/// Acquires a session-level advisory lock on the shared PostgreSQL test
/// database, held by a dedicated connection for the caller's entire test
/// (issue #1043). The shared `o3k-shared-test-database` key serializes every
/// destructive shared-DB reset (here `clean_tables_for_testing`) against the
/// other shared-DB test groups even across separate `cargo test` processes.
/// The in-process `TEST_DATABASE_LOCK` is kept to serialize intra-process
/// ordering, but it cannot see other processes; this advisory lock can.
/// Matches `o3k_store::conformance::prepare_shared_postgres_test_database`.
async fn acquire_database_guard(url: &str) -> PgConnection {
    let mut connection = PgConnection::connect(url)
        .await
        .expect("connect to the shared PostgreSQL test database");
    sqlx::query("SELECT pg_advisory_lock(hashtextextended('o3k-shared-test-database', 0))")
        .execute(&mut connection)
        .await
        .expect("acquire the shared PostgreSQL test-database advisory lock");
    connection
}

#[tokio::test]
#[ignore = "requires the configured PostgreSQL conformance database"]
async fn postgres_relationship_intent_is_replayable_bindable_and_recoverable() {
    let _database_guard = TEST_DATABASE_LOCK.lock().await;
    let _advisory_guard = acquire_database_guard(&url()).await;
    let store = PostgresStore::connect(&url()).await.expect("connect");
    store.clean_tables_for_testing().await.expect("clean");
    let parent = Uuid::now_v7();
    let operation = Uuid::now_v7();
    let child_operation = Uuid::now_v7();
    let child = Uuid::now_v7();
    store
        .insert_resource(&resource(parent, "p12-6"))
        .await
        .expect("parent resource");
    let record = ResourceRelationshipRecord {
        parent_resource_id: parent,
        parent_resource_type: "database:instance".into(),
        slot: "network-primary".into(),
        expected_child_resource_type: "network:network".into(),
        child_resource_id: None,
        ownership: "exclusive".into(),
        parent_operation_id: operation,
        child_operation_id: None,
        owner_scope: "project:p12-6".into(),
        state: "reserved".into(),
        fingerprint: "same-request".into(),
    };
    let first = store.reserve_relationship(&record).await.expect("reserve");
    assert_eq!(first, record);
    assert_eq!(
        store.reserve_relationship(&record).await.expect("replay"),
        record
    );
    let mut conflict = record.clone();
    conflict.expected_child_resource_type = "volume:volume".into();
    assert!(store.reserve_relationship(&conflict).await.is_err());
    store
        .insert_resource(&resource(child, "p12-6"))
        .await
        .expect("child resource");
    let bound = store
        .bind_relationship(parent, "network-primary", child, child_operation)
        .await
        .expect("bind");
    assert_eq!(bound.state, "bound");
    let listed = store.list_relationships(parent).await.expect("list");
    assert_eq!(listed.len(), 1);
    assert_eq!(listed[0].child_operation_id, Some(child_operation));
}

#[tokio::test]
#[ignore = "requires the mandatory PostgreSQL P12.3/P12.4 CI job"]
async fn postgres_p12_3_canonical_resource_and_lifecycle_acceptance() {
    let _database_guard = TEST_DATABASE_LOCK.lock().await;
    let _advisory_guard = acquire_database_guard(&url()).await;
    let store = PostgresStore::connect(&url()).await.expect("connect");
    store.clean_tables_for_testing().await.expect("clean");
    let rid = Uuid::now_v7();
    let oid = Uuid::now_v7();
    let created_resource = resource(rid, "project-native");
    let created_operation = operation(oid, rid);
    let created_canonical = canonical(oid, rid, "project-native", "user-native");
    let request = request("project-native", "create-native", "same", oid);
    assert!(matches!(
        store
            .create_or_replay_canonical_resource_operation(
                &created_resource,
                &created_operation,
                &created_canonical,
                &request,
                None,
            )
            .await
            .expect("create"),
        CanonicalAcceptanceOutcome::Created { .. }
    ));
    let replay_oid = Uuid::now_v7();
    let replay_resource = resource(Uuid::now_v7(), "project-native");
    let replay_operation = operation(replay_oid, replay_resource.id);
    let replay_canonical = canonical(
        replay_oid,
        replay_resource.id,
        "project-native",
        "user-native",
    );
    let mut replay_request = request.clone();
    replay_request.operation_id = replay_oid;
    assert_eq!(
        store
            .create_or_replay_canonical_resource_operation(
                &replay_resource,
                &replay_operation,
                &replay_canonical,
                &replay_request,
                None
            )
            .await
            .expect("replay"),
        CanonicalAcceptanceOutcome::ExistingEquivalent {
            operation_id: oid,
            resource_id: rid
        }
    );
    assert_eq!(counts(&store).await, (1, 1, 1));

    let delete_id = Uuid::now_v7();
    let delete_operation = OperationRecord {
        id: delete_id,
        resource_id: rid,
        kind: "lifecycle:delete".into(),
        state: OperationState::Pending,
        provider_operation_id: None,
        error_category: None,
        error_message: None,
    };
    let mut delete_canonical = canonical(delete_id, rid, "project-native", "user-native");
    delete_canonical.action = "compute:DeleteServer".into();
    let delete_request = IdempotencyReservationRequest::from_semantics(
        "project-native",
        "compute:DeleteServer",
        "delete-native",
        "compute:server",
        Some(&rid.to_string()),
        &json!({}),
        delete_id,
    )
    .expect("delete request");
    assert!(matches!(
        store
            .create_or_replay_canonical_lifecycle_operation(
                &delete_operation,
                &delete_canonical,
                &delete_request
            )
            .await
            .expect("delete"),
        CanonicalAcceptanceOutcome::Created { .. }
    ));
    assert!(
        o3k_kernel::Operation::try_from(
            store
                .get_canonical_operation(delete_id)
                .await
                .expect("canonical delete")
        )
        .is_ok()
    );
}
fn resource(id: Uuid, project: &str) -> ResourceRecord {
    ResourceRecord {
        id,
        kind: "compute:server".into(),
        project_id: project.into(),
        generation: 1,
        observed_generation: 0,
        desired_state: "pending".into(),
        observed_state: "unknown".into(),
        provider_id: None,
    }
}
fn operation(id: Uuid, resource_id: Uuid) -> OperationRecord {
    OperationRecord {
        id,
        resource_id,
        kind: "lifecycle:create".into(),
        state: OperationState::Pending,
        provider_operation_id: None,
        error_category: None,
        error_message: None,
    }
}
fn canonical(id: Uuid, resource_id: Uuid, project: &str, actor: &str) -> CanonicalOperationRecord {
    CanonicalOperationRecord {
        id,
        service: "compute".into(),
        action: "compute:CreateServer".into(),
        actor: actor.into(),
        owner_scope: project.into(),
        resource_type: "compute:server".into(),
        resource_id: Some(resource_id.to_string()),
        state: OperationState::Pending,
        attempt: 0,
        created_at: "2026-01-01T00:00:00Z".into(),
        started_at: None,
        finished_at: None,
        error: None,
        request_id: Some(format!("request-{actor}")),
    }
}
fn request(
    project: &str,
    key: &str,
    payload: &str,
    operation_id: Uuid,
) -> IdempotencyReservationRequest {
    IdempotencyReservationRequest::from_semantics(
        project,
        "compute:CreateServer",
        key,
        "compute:server",
        None,
        &json!({"name":payload}),
        operation_id,
    )
    .expect("valid reservation")
}

async fn counts(store: &PostgresStore) -> (i64, i64, i64) {
    let row = sqlx::query("SELECT (SELECT count(*) FROM operations) AS operations, (SELECT count(*) FROM canonical_operation_metadata) AS metadata, (SELECT count(*) FROM idempotency_reservations) AS reservations").fetch_one(store.pool()).await.expect("count triplet");
    (
        row.get("operations"),
        row.get("metadata"),
        row.get("reservations"),
    )
}

type Proposal = (
    OperationRecord,
    CanonicalOperationRecord,
    IdempotencyReservationRequest,
);
async fn race(
    store: &PostgresStore,
    a: Proposal,
    b: Proposal,
) -> (IdempotencyReservation, IdempotencyReservation) {
    let barrier = Arc::new(Barrier::new(3));
    let sa = store.clone();
    let ba = barrier.clone();
    let ta = tokio::spawn(async move {
        ba.wait().await;
        sa.create_or_replay_canonical_idempotent_operation(&a.0, &a.1, &a.2)
            .await
            .expect("race caller a")
    });
    let sb = store.clone();
    let bb = barrier.clone();
    let tb = tokio::spawn(async move {
        bb.wait().await;
        sb.create_or_replay_canonical_idempotent_operation(&b.0, &b.1, &b.2)
            .await
            .expect("race caller b")
    });
    barrier.wait().await;
    (ta.await.unwrap(), tb.await.unwrap())
}

#[tokio::test]
#[ignore = "requires the mandatory PostgreSQL P12.4 CI job"]
async fn postgres_p12_4_atomic_triplet_concurrency_recovery_and_cas() {
    let _database_guard = TEST_DATABASE_LOCK.lock().await;
    let _advisory_guard = acquire_database_guard(&url()).await;
    let database_url = url();
    let store = PostgresStore::connect(&database_url)
        .await
        .expect("connect");
    store
        .clean_tables_for_testing()
        .await
        .expect("clean dedicated database");

    let rid = Uuid::now_v7();
    store
        .insert_resource(&resource(rid, "project-equivalent"))
        .await
        .expect("resource");
    let a = Uuid::now_v7();
    let b = Uuid::now_v7();
    let equivalent = race(
        &store,
        (
            operation(a, rid),
            canonical(a, rid, "project-equivalent", "user-a"),
            request("project-equivalent", "equivalent", "same", a),
        ),
        (
            operation(b, rid),
            canonical(b, rid, "project-equivalent", "user-b"),
            request("project-equivalent", "equivalent", "same", b),
        ),
    )
    .await;
    let created: Vec<_> = [&equivalent.0, &equivalent.1]
        .into_iter()
        .filter_map(|outcome| match outcome {
            IdempotencyReservation::Created(id) => Some(*id),
            _ => None,
        })
        .collect();
    let replayed: Vec<_> = [&equivalent.0, &equivalent.1]
        .into_iter()
        .filter_map(|outcome| match outcome {
            IdempotencyReservation::ExistingEquivalent(id) => Some(*id),
            _ => None,
        })
        .collect();
    assert_eq!(created.len(), 1, "one caller must create: {equivalent:?}");
    assert_eq!(replayed, created, "both callers must resolve one identity");
    let winner = created[0];
    let loser = if winner == a { b } else { a };
    assert!(matches!(
        store.get_operation(loser).await,
        Err(StoreError::OperationNotFound)
    ));
    assert!(matches!(
        store.get_canonical_operation(loser).await,
        Err(StoreError::OperationNotFound)
    ));
    assert_eq!(counts(&store).await, (1, 1, 1));

    store
        .clean_tables_for_testing()
        .await
        .expect("clean conflict");
    let rid = Uuid::now_v7();
    store
        .insert_resource(&resource(rid, "project-conflict"))
        .await
        .expect("resource");
    let a = Uuid::now_v7();
    let b = Uuid::now_v7();
    let conflict = race(
        &store,
        (
            operation(a, rid),
            canonical(a, rid, "project-conflict", "user-a"),
            request("project-conflict", "conflict", "first", a),
        ),
        (
            operation(b, rid),
            canonical(b, rid, "project-conflict", "user-b"),
            request("project-conflict", "conflict", "second", b),
        ),
    )
    .await;
    assert!(matches!(
        (&conflict.0, &conflict.1),
        (
            IdempotencyReservation::Created(_),
            IdempotencyReservation::Conflict
        ) | (
            IdempotencyReservation::Conflict,
            IdempotencyReservation::Created(_)
        )
    ));
    let conflict_winner = match (&conflict.0, &conflict.1) {
        (IdempotencyReservation::Created(id), _) | (_, IdempotencyReservation::Created(id)) => *id,
        _ => unreachable!("the assertion above requires one created operation"),
    };
    let conflict_loser = if conflict_winner == a { b } else { a };
    assert!(matches!(
        store.get_operation(conflict_loser).await,
        Err(StoreError::OperationNotFound)
    ));
    assert!(matches!(
        store.get_canonical_operation(conflict_loser).await,
        Err(StoreError::OperationNotFound)
    ));
    assert_eq!(counts(&store).await, (1, 1, 1));

    store
        .clean_tables_for_testing()
        .await
        .expect("clean scopes");
    let ra = Uuid::now_v7();
    let rb = Uuid::now_v7();
    store
        .insert_resource(&resource(ra, "project-a"))
        .await
        .expect("resource a");
    store
        .insert_resource(&resource(rb, "project-b"))
        .await
        .expect("resource b");
    let a = Uuid::now_v7();
    let b = Uuid::now_v7();
    let scopes = race(
        &store,
        (
            operation(a, ra),
            canonical(a, ra, "project-a", "user-a"),
            request("project-a", "shared", "same", a),
        ),
        (
            operation(b, rb),
            canonical(b, rb, "project-b", "user-b"),
            request("project-b", "shared", "same", b),
        ),
    )
    .await;
    assert!(matches!(scopes.0,IdempotencyReservation::Created(id) if id==a));
    assert!(matches!(scopes.1,IdempotencyReservation::Created(id) if id==b));
    assert_eq!(counts(&store).await, (2, 2, 2));

    store
        .clean_tables_for_testing()
        .await
        .expect("clean rollback");
    let rid = Uuid::now_v7();
    store
        .insert_resource(&resource(rid, "project-rollback"))
        .await
        .expect("resource");
    let suffix = Uuid::new_v4().simple().to_string();
    let function = format!("p12_4_reject_reservation_{suffix}");
    let trigger = format!("p12_4_reject_reservation_{suffix}");
    sqlx::query(&format!("CREATE FUNCTION {function}() RETURNS trigger LANGUAGE plpgsql AS $$ BEGIN IF NEW.idempotency_key = 'rollback-sentinel' THEN RAISE EXCEPTION 'p12.4 injected reservation failure'; END IF; RETURN NEW; END $$")).execute(store.pool()).await.expect("create trigger function");
    sqlx::query(&format!("CREATE TRIGGER {trigger} BEFORE INSERT ON idempotency_reservations FOR EACH ROW EXECUTE FUNCTION {function}()")).execute(store.pool()).await.expect("create trigger");
    let id = Uuid::now_v7();
    let rollback = store
        .create_or_replay_canonical_idempotent_operation(
            &operation(id, rid),
            &canonical(id, rid, "project-rollback", "user"),
            &request("project-rollback", "rollback-sentinel", "payload", id),
        )
        .await;
    assert!(rollback.is_err());
    assert_eq!(counts(&store).await, (0, 0, 0));
    sqlx::query(&format!(
        "DROP TRIGGER {trigger} ON idempotency_reservations"
    ))
    .execute(store.pool())
    .await
    .expect("drop trigger");
    sqlx::query(&format!("DROP FUNCTION {function}()"))
        .execute(store.pool())
        .await
        .expect("drop trigger function");

    let id = Uuid::now_v7();
    let req = request("project-rollback", "reload", "payload", id);
    let op = operation(id, rid);
    let meta = canonical(id, rid, "project-rollback", "user-reload");
    assert_eq!(
        store
            .create_or_replay_canonical_idempotent_operation(&op, &meta, &req)
            .await
            .expect("create reload"),
        IdempotencyReservation::Created(id)
    );
    drop(store);
    let reopened = PostgresStore::connect(&database_url)
        .await
        .expect("reconnect");
    let kernel = o3k_kernel::Operation::try_from(
        reopened
            .get_canonical_operation(id)
            .await
            .expect("reload canonical"),
    )
    .expect("kernel conversion");
    assert_eq!(kernel.id, id);
    assert_eq!(kernel.service, "compute");
    assert_eq!(kernel.action.as_str(), "compute:CreateServer");
    assert_eq!(kernel.actor, "user-reload");
    assert_eq!(kernel.owner_scope.id().as_str(), "project-rollback");
    assert_eq!(kernel.resource_type.to_string(), "compute:server");
    assert_eq!(
        kernel.resource_id.as_ref().map(ToString::to_string),
        Some(rid.to_string())
    );
    assert_eq!(kernel.state, o3k_kernel::OperationState::Pending);
    assert_eq!(kernel.attempt, 0);
    assert_eq!(kernel.created_at, "2026-01-01T00:00:00Z");
    assert_eq!(kernel.started_at, None);
    assert_eq!(kernel.finished_at, None);
    assert_eq!(kernel.error, None);
    assert_eq!(kernel.request_id.as_deref(), Some("request-user-reload"));

    let started = "2026-01-01T00:01:00Z".to_owned();
    let running = reopened
        .update_canonical_operation_lifecycle(
            id,
            &CanonicalOperationLifecycleUpdate::new(
                o3k_kernel::OperationState::Running,
                1,
                Some(started.clone()),
                None,
                None,
            )
            .expect("running lifecycle update"),
        )
        .await
        .expect("running lifecycle persistence");
    assert_eq!(running.state, OperationState::Running);
    assert_eq!(running.attempt, 1);
    assert_eq!(running.started_at.as_deref(), Some(started.as_str()));
    assert_eq!(running.finished_at, None);
    let running_kernel = o3k_kernel::Operation::try_from(
        reopened
            .get_canonical_operation(id)
            .await
            .expect("reload running"),
    )
    .expect("running kernel conversion");
    assert_eq!(running_kernel.state, o3k_kernel::OperationState::Running);
    assert_eq!(running_kernel.attempt, 1);
    assert_eq!(running_kernel.started_at.as_deref(), Some(started.as_str()));

    let finished = "2026-01-01T00:02:00Z".to_owned();
    let succeeded = reopened
        .update_canonical_operation_lifecycle(
            id,
            &CanonicalOperationLifecycleUpdate::new(
                o3k_kernel::OperationState::Succeeded,
                1,
                Some(started.clone()),
                Some(finished.clone()),
                None,
            )
            .expect("succeeded lifecycle update"),
        )
        .await
        .expect("succeeded lifecycle persistence");
    assert_eq!(succeeded.state, OperationState::Succeeded);
    assert_eq!(succeeded.attempt, 1);
    assert_eq!(succeeded.finished_at.as_deref(), Some(finished.as_str()));
    let terminal_kernel = o3k_kernel::Operation::try_from(
        reopened
            .get_canonical_operation(id)
            .await
            .expect("reload terminal"),
    )
    .expect("terminal kernel conversion");
    assert_eq!(terminal_kernel.state, o3k_kernel::OperationState::Succeeded);
    assert_eq!(terminal_kernel.attempt, 1);
    assert_eq!(
        terminal_kernel.started_at.as_deref(),
        Some(started.as_str())
    );
    assert_eq!(
        terminal_kernel.finished_at.as_deref(),
        Some(finished.as_str())
    );
    assert_eq!(terminal_kernel.error, None);
    let row = sqlx::query("SELECT state FROM operations WHERE id = $1")
        .bind(id.to_string())
        .fetch_one(reopened.pool())
        .await
        .expect("authoritative operation state");
    assert_eq!(row.get::<String, _>("state"), "succeeded");
    drop(reopened);
    let reopened = PostgresStore::connect(&database_url)
        .await
        .expect("reconnect lifecycle");
    let reconnected_kernel = o3k_kernel::Operation::try_from(
        reopened
            .get_canonical_operation(id)
            .await
            .expect("reload after reconnect"),
    )
    .expect("reconnected kernel conversion");
    assert_eq!(
        reconnected_kernel.state,
        o3k_kernel::OperationState::Succeeded
    );
    assert_eq!(reconnected_kernel.attempt, 1);
    assert_eq!(
        reconnected_kernel.finished_at.as_deref(),
        Some(finished.as_str())
    );

    // A retry resolves the committed scoped identity before considering a
    // newly proposed target. The proposal may use a fresh operation/resource
    // identity after the caller lost the original response.
    let retry_id = Uuid::now_v7();
    let retry_resource = Uuid::now_v7();
    let mut retry_request = req.clone();
    retry_request.operation_id = retry_id;
    assert_eq!(
        reopened
            .create_or_replay_canonical_idempotent_operation(
                &operation(retry_id, retry_resource),
                &canonical(
                    retry_id,
                    retry_resource,
                    "project-rollback",
                    "retrying-user",
                ),
                &retry_request,
            )
            .await
            .expect("replay"),
        IdempotencyReservation::ExistingEquivalent(id)
    );

    let barrier = Arc::new(Barrier::new(3));
    let sa = reopened.clone();
    let ba = barrier.clone();
    let ta = tokio::spawn(async move {
        ba.wait().await;
        sa.update_resource(rid, 1, "first", "unknown", 0, None)
            .await
    });
    let sb = reopened.clone();
    let bb = barrier.clone();
    let tb = tokio::spawn(async move {
        bb.wait().await;
        sb.update_resource(rid, 1, "second", "unknown", 0, None)
            .await
    });
    barrier.wait().await;
    let outcomes = (ta.await.unwrap(), tb.await.unwrap());
    assert!(matches!(
        (&outcomes.0, &outcomes.1),
        (Ok(_), Err(StoreError::StaleGeneration)) | (Err(StoreError::StaleGeneration), Ok(_))
    ));
    assert_eq!(
        reopened
            .get_resource(rid)
            .await
            .expect("final resource")
            .generation,
        2
    );
}

type ResourceProposal = (
    ResourceRecord,
    OperationRecord,
    CanonicalOperationRecord,
    IdempotencyReservationRequest,
);
async fn race_resource_create(
    store: &PostgresStore,
    a: ResourceProposal,
    b: ResourceProposal,
) -> (CanonicalAcceptanceOutcome, CanonicalAcceptanceOutcome) {
    let barrier = Arc::new(Barrier::new(3));
    let sa = store.clone();
    let ba = barrier.clone();
    let ta = tokio::spawn(async move {
        ba.wait().await;
        sa.create_or_replay_canonical_resource_operation(&a.0, &a.1, &a.2, &a.3, None)
            .await
            .expect("race caller a")
    });
    let sb = store.clone();
    let bb = barrier.clone();
    let tb = tokio::spawn(async move {
        bb.wait().await;
        sb.create_or_replay_canonical_resource_operation(&b.0, &b.1, &b.2, &b.3, None)
            .await
            .expect("race caller b")
    });
    barrier.wait().await;
    (ta.await.unwrap(), tb.await.unwrap())
}

#[tokio::test]
#[ignore = "requires the mandatory PostgreSQL P12.4 CI job"]
async fn postgres_p12_4_canonical_resource_create_race() {
    let _database_guard = TEST_DATABASE_LOCK.lock().await;
    let _advisory_guard = acquire_database_guard(&url()).await;
    let store = PostgresStore::connect(&url()).await.expect("connect");
    store.clean_tables_for_testing().await.expect("clean");

    let rid = Uuid::now_v7();
    let oid_a = Uuid::now_v7();
    let oid_b = Uuid::now_v7();
    let res = resource(rid, "project-create-race");

    let (outcome_a, outcome_b) = race_resource_create(
        &store,
        (
            res.clone(),
            operation(oid_a, rid),
            canonical(oid_a, rid, "project-create-race", "user-a"),
            request("project-create-race", "create-race-key", "same", oid_a),
        ),
        (
            res.clone(),
            operation(oid_b, rid),
            canonical(oid_b, rid, "project-create-race", "user-b"),
            request("project-create-race", "create-race-key", "same", oid_b),
        ),
    )
    .await;

    let created: Vec<_> = [&outcome_a, &outcome_b]
        .into_iter()
        .filter_map(|o| match o {
            CanonicalAcceptanceOutcome::Created { .. } => Some(()),
            _ => None,
        })
        .collect();
    let replayed: Vec<_> = [&outcome_a, &outcome_b]
        .into_iter()
        .filter_map(|o| match o {
            CanonicalAcceptanceOutcome::ExistingEquivalent { .. } => Some(()),
            _ => None,
        })
        .collect();
    assert_eq!(created.len(), 1, "exactly one caller must see Created");
    assert_eq!(
        replayed.len(),
        1,
        "the other caller must see ExistingEquivalent"
    );

    let winner_id = match (&outcome_a, &outcome_b) {
        (
            CanonicalAcceptanceOutcome::Created {
                operation_id,
                resource_id,
            },
            _,
        )
        | (
            _,
            CanonicalAcceptanceOutcome::Created {
                operation_id,
                resource_id,
            },
        ) => (*operation_id, *resource_id),
        _ => unreachable!("one outcome must be Created"),
    };
    let loser_oid = if winner_id.0 == oid_a { oid_b } else { oid_a };
    for o in [&outcome_a, &outcome_b] {
        match o {
            CanonicalAcceptanceOutcome::Created {
                operation_id,
                resource_id,
            }
            | CanonicalAcceptanceOutcome::ExistingEquivalent {
                operation_id,
                resource_id,
            } => {
                assert_eq!(*resource_id, rid);
                assert_eq!(*operation_id, winner_id.0);
            }
            _ => {}
        }
    }
    assert!(matches!(
        store.get_operation(loser_oid).await,
        Err(StoreError::OperationNotFound)
    ));
    assert!(matches!(
        store.get_canonical_operation(loser_oid).await,
        Err(StoreError::OperationNotFound)
    ));
    assert_eq!(counts(&store).await, (1, 1, 1));
}

#[tokio::test]
#[ignore = "requires the mandatory PostgreSQL P12.4 CI job"]
async fn postgres_p12_4_canonical_resource_create_conflict_race() {
    let _database_guard = TEST_DATABASE_LOCK.lock().await;
    let _advisory_guard = acquire_database_guard(&url()).await;
    let store = PostgresStore::connect(&url()).await.expect("connect");
    store.clean_tables_for_testing().await.expect("clean");

    let rid = Uuid::now_v7();
    let oid_a = Uuid::now_v7();
    let oid_b = Uuid::now_v7();
    let res = resource(rid, "project-conflict");

    let (outcome_a, outcome_b) = race_resource_create(
        &store,
        (
            res.clone(),
            operation(oid_a, rid),
            canonical(oid_a, rid, "project-conflict", "user-a"),
            request("project-conflict", "conflict-key", "first", oid_a),
        ),
        (
            res.clone(),
            operation(oid_b, rid),
            canonical(oid_b, rid, "project-conflict", "user-b"),
            request("project-conflict", "conflict-key", "second", oid_b),
        ),
    )
    .await;

    assert!(
        matches!(
            (&outcome_a, &outcome_b),
            (
                CanonicalAcceptanceOutcome::Created { .. },
                CanonicalAcceptanceOutcome::Conflict
            ) | (
                CanonicalAcceptanceOutcome::Conflict,
                CanonicalAcceptanceOutcome::Created { .. }
            )
        ),
        "one must be Created, the other Conflict: {outcome_a:?}, {outcome_b:?}"
    );

    let conflict_winner_oid = match (&outcome_a, &outcome_b) {
        (CanonicalAcceptanceOutcome::Created { operation_id, .. }, _) => *operation_id,
        (_, CanonicalAcceptanceOutcome::Created { operation_id, .. }) => *operation_id,
        _ => unreachable!("one outcome must be Created"),
    };
    let loser_oid = if conflict_winner_oid == oid_a {
        oid_b
    } else {
        oid_a
    };
    assert!(matches!(
        store.get_operation(loser_oid).await,
        Err(StoreError::OperationNotFound)
    ));
    assert!(matches!(
        store.get_canonical_operation(loser_oid).await,
        Err(StoreError::OperationNotFound)
    ));
    assert_eq!(counts(&store).await, (1, 1, 1));
}

type LifecycleProposal = (
    OperationRecord,
    CanonicalOperationRecord,
    IdempotencyReservationRequest,
);
async fn race_lifecycle_delete(
    store: &PostgresStore,
    a: LifecycleProposal,
    b: LifecycleProposal,
) -> (CanonicalAcceptanceOutcome, CanonicalAcceptanceOutcome) {
    let barrier = Arc::new(Barrier::new(3));
    let sa = store.clone();
    let ba = barrier.clone();
    let ta = tokio::spawn(async move {
        ba.wait().await;
        sa.create_or_replay_canonical_lifecycle_operation(&a.0, &a.1, &a.2)
            .await
            .expect("race lifecycle caller a")
    });
    let sb = store.clone();
    let bb = barrier.clone();
    let tb = tokio::spawn(async move {
        bb.wait().await;
        sb.create_or_replay_canonical_lifecycle_operation(&b.0, &b.1, &b.2)
            .await
            .expect("race lifecycle caller b")
    });
    barrier.wait().await;
    (ta.await.unwrap(), tb.await.unwrap())
}

#[tokio::test]
#[ignore = "requires the mandatory PostgreSQL P12.4 CI job"]
async fn postgres_p12_4_canonical_lifecycle_delete_race() {
    let _database_guard = TEST_DATABASE_LOCK.lock().await;
    let _advisory_guard = acquire_database_guard(&url()).await;
    let store = PostgresStore::connect(&url()).await.expect("connect");
    store.clean_tables_for_testing().await.expect("clean");

    let rid = Uuid::now_v7();
    store
        .insert_resource(&resource(rid, "project-delete-race"))
        .await
        .expect("pre-insert resource");

    let oid_a = Uuid::now_v7();
    let oid_b = Uuid::now_v7();
    let op_a = OperationRecord {
        id: oid_a,
        resource_id: rid,
        kind: "lifecycle:delete".into(),
        state: OperationState::Pending,
        provider_operation_id: None,
        error_category: None,
        error_message: None,
    };
    let op_b = OperationRecord {
        id: oid_b,
        resource_id: rid,
        kind: "lifecycle:delete".into(),
        state: OperationState::Pending,
        provider_operation_id: None,
        error_category: None,
        error_message: None,
    };

    let mut canonical_a = canonical(oid_a, rid, "project-delete-race", "user-a");
    canonical_a.action = "compute:DeleteServer".into();
    let mut canonical_b = canonical(oid_b, rid, "project-delete-race", "user-b");
    canonical_b.action = "compute:DeleteServer".into();

    let delete_request_a = IdempotencyReservationRequest::from_semantics(
        "project-delete-race",
        "compute:DeleteServer",
        "delete-race-key",
        "compute:server",
        Some(&rid.to_string()),
        &json!({}),
        oid_a,
    )
    .expect("delete request a");

    let delete_request_b = IdempotencyReservationRequest::from_semantics(
        "project-delete-race",
        "compute:DeleteServer",
        "delete-race-key",
        "compute:server",
        Some(&rid.to_string()),
        &json!({}),
        oid_b,
    )
    .expect("delete request b");

    let (outcome_a, outcome_b) = race_lifecycle_delete(
        &store,
        (op_a, canonical_a, delete_request_a),
        (op_b, canonical_b, delete_request_b),
    )
    .await;

    let created: Vec<_> = [&outcome_a, &outcome_b]
        .into_iter()
        .filter_map(|o| match o {
            CanonicalAcceptanceOutcome::Created { .. } => Some(()),
            _ => None,
        })
        .collect();
    let replayed: Vec<_> = [&outcome_a, &outcome_b]
        .into_iter()
        .filter_map(|o| match o {
            CanonicalAcceptanceOutcome::ExistingEquivalent { .. } => Some(()),
            _ => None,
        })
        .collect();
    assert_eq!(created.len(), 1, "exactly one caller must see Created");
    assert_eq!(
        replayed.len(),
        1,
        "the other caller must see ExistingEquivalent"
    );

    let winner_oid = match (&outcome_a, &outcome_b) {
        (CanonicalAcceptanceOutcome::Created { operation_id, .. }, _)
        | (_, CanonicalAcceptanceOutcome::Created { operation_id, .. }) => *operation_id,
        _ => unreachable!("one outcome must be Created"),
    };
    for o in [&outcome_a, &outcome_b] {
        if let CanonicalAcceptanceOutcome::ExistingEquivalent { operation_id, .. }
        | CanonicalAcceptanceOutcome::Created { operation_id, .. } = o
        {
            assert_eq!(
                *operation_id, winner_oid,
                "both must report the same operation_id"
            );
        }
    }
    assert_eq!(counts(&store).await, (1, 1, 1));
}
