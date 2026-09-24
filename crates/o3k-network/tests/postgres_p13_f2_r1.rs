#![allow(clippy::expect_used, clippy::unwrap_used)]

use std::{path::PathBuf, sync::Arc};

use o3k_network::{NetworkService, RealmCleanupObservation, RealmCleanupProgress};
use o3k_store::PostgresStore;
use sqlx::postgres::PgPoolOptions;
use sqlx::{Connection, postgres::PgConnection};
use tokio::sync::Mutex;
use uuid::Uuid;

static DATABASE_LOCK: Mutex<()> = Mutex::const_new(());

fn database_url() -> String {
    std::env::var("O3K_DATABASE_URL")
        .expect("O3K_DATABASE_URL must be set for P13.1F2 PostgreSQL conformance")
}

/// Acquires a session-level advisory lock on the shared PostgreSQL test
/// database, held by a dedicated connection for the caller's entire test
/// (issue #1043). The shared `o3k-shared-test-database` key serializes this
/// file's destructive `DROP SCHEMA public CASCADE` reset against the other
/// shared-DB test groups even across separate `cargo test` processes, unlike
/// the in-process `DATABASE_LOCK`. Matches
/// `o3k_store::conformance::prepare_shared_postgres_test_database`.
async fn acquire_database_guard(url: &str) -> PgConnection {
    o3k_store::conformance::assert_destructive_postgres_test_database(url)
        .expect("destructive PostgreSQL test database must have the expected purpose");
    let mut connection = PgConnection::connect(url)
        .await
        .expect("connect to the shared PostgreSQL test database");
    sqlx::query("SELECT pg_advisory_lock(hashtextextended('o3k-shared-test-database', 0))")
        .execute(&mut connection)
        .await
        .expect("acquire the shared PostgreSQL test-database advisory lock");
    connection
}

fn runtime_root() -> PathBuf {
    std::env::temp_dir().join(format!("o3k-p13-f2-r1-{}", Uuid::new_v4()))
}

#[tokio::test]
#[ignore = "requires the configured PostgreSQL conformance database"]
async fn postgres_p13_f2_r1_reconstructs_and_recovers_realm_cleanup()
-> Result<(), Box<dyn std::error::Error>> {
    let _guard = DATABASE_LOCK.lock().await;
    let url = database_url();
    let _postgres_guard = acquire_database_guard(&url).await;
    let pool = PgPoolOptions::new()
        .max_connections(10)
        .connect(&url)
        .await
        .expect("connect PostgreSQL");
    sqlx::query("DROP SCHEMA IF EXISTS public CASCADE")
        .execute(&pool)
        .await
        .expect("reset schema");
    sqlx::query("CREATE SCHEMA public")
        .execute(&pool)
        .await
        .expect("create schema");

    let store = Arc::new(
        PostgresStore::connect_pool(pool.clone())
            .await
            .expect("connect O3K PostgreSQL store"),
    );
    let root = runtime_root();
    let service = NetworkService::open_for_test(&root, store.clone())
        .await
        .expect("open network service");
    let network = service
        .create_canonical_network_for_project("p13-f2-r1", "network".into())
        .await
        .expect("network");
    let realm_a = service
        .create_canonical_realm_for_project("p13-f2-r1", network.id, "10.40.0.0/24".into(), true)
        .await
        .expect("realm a");
    let realm_b = service
        .create_canonical_realm_for_project("p13-f2-r1", network.id, "10.40.0.0/24".into(), true)
        .await
        .expect("realm b");
    let endpoint_a = service
        .create_canonical_endpoint_for_project(
            "p13-f2-r1",
            realm_a.id,
            "10.40.0.10".parse().unwrap(),
            "02:00:00:40:00:0a".into(),
        )
        .await
        .expect("endpoint a");
    let endpoint_b = service
        .create_canonical_endpoint_for_project(
            "p13-f2-r1",
            realm_b.id,
            "10.40.0.10".parse().unwrap(),
            "02:00:00:40:00:0b".into(),
        )
        .await
        .expect("endpoint b");
    assert_eq!(endpoint_a.fixed_ip, endpoint_b.fixed_ip);
    store
        .delete_canonical_endpoint("p13-f2-r1", &endpoint_b.id)
        .await
        .expect("remove endpoint dependency for cleanup proof");

    let binding = o3k_store::CanonicalRealmBindingRecord {
        fabric_domain_id: "fabric-a".into(),
        realm_id: realm_b.id,
        provider_kind: "geneve".into(),
        provider_segment_id: 404,
        binding_generation: 1,
        state: "active".into(),
    };
    store
        .insert_canonical_realm_binding(&binding)
        .await
        .expect("binding");
    assert!(matches!(
        service
            .reconstruct_canonical_network("p13-f2-r1", network.id)
            .await
            .expect("snapshot")
            .realms
            .as_slice(),
        [_, _]
    ));

    assert!(matches!(
        service
            .delete_canonical_realm_for_project("p13-f2-r1", realm_b.id)
            .await,
        Err(o3k_network::NetworkError::Conflict)
    ));
    let replay = service
        .begin_canonical_realm_deletion_for_project("p13-f2-r1", realm_b.id)
        .await
        .expect("replay deletion");
    let operation_id = match replay {
        RealmCleanupProgress::AwaitingObservation { operation_id, .. } => operation_id,
        _ => {
            return Err("deletion did not remain durable".into());
        }
    };
    service
        .observe_canonical_realm_cleanup_for_project(
            "p13-f2-r1",
            realm_b.id,
            vec![RealmCleanupObservation::Unknown {
                binding: binding.clone(),
                reason: "response lost".into(),
            }],
        )
        .await
        .expect("unknown observation");
    drop(service);

    let reopened = NetworkService::open_for_test(&root, store.clone())
        .await
        .expect("reopen network service");
    let replay_after_restart = reopened
        .begin_canonical_realm_deletion_for_project("p13-f2-r1", realm_b.id)
        .await
        .expect("replay after restart");
    assert!(matches!(
        replay_after_restart,
        RealmCleanupProgress::AwaitingObservation { operation_id: id, .. } if id == operation_id
    ));
    assert_eq!(
        reopened
            .observe_canonical_realm_cleanup_for_project(
                "p13-f2-r1",
                realm_b.id,
                vec![RealmCleanupObservation::Absent(binding)],
            )
            .await
            .expect("absence observation"),
        RealmCleanupProgress::Removed { operation_id }
    );
    let snapshot = reopened
        .reconstruct_canonical_network("p13-f2-r1", network.id)
        .await
        .expect("reconstruct after deletion");
    assert_eq!(snapshot.network.id, network.id);
    assert_eq!(snapshot.realms.len(), 1);
    assert_eq!(snapshot.realms[0].id, realm_a.id);

    let _ = std::fs::remove_dir_all(root);
    Ok(())
}

#[tokio::test]
#[ignore = "requires the configured PostgreSQL conformance database"]
async fn postgres_p13_f3_fresh_runtime_reconstructs_policy_and_zero_realm_network()
-> Result<(), Box<dyn std::error::Error>> {
    let _guard = DATABASE_LOCK.lock().await;
    let url = database_url();
    let _postgres_guard = acquire_database_guard(&url).await;
    let pool = PgPoolOptions::new()
        .max_connections(10)
        .connect(&url)
        .await
        .expect("connect PostgreSQL");
    sqlx::query("DROP SCHEMA IF EXISTS public CASCADE")
        .execute(&pool)
        .await
        .expect("reset schema");
    sqlx::query("CREATE SCHEMA public")
        .execute(&pool)
        .await
        .expect("create schema");

    let store_a = Arc::new(PostgresStore::connect_pool(pool.clone()).await?);
    let root = runtime_root();
    let service_a = NetworkService::open_for_test(&root, store_a.clone()).await?;
    let project = "p13-f3-postgres";
    let network = service_a
        .create_canonical_network_for_project(project, "network".into())
        .await?;
    assert!(
        service_a
            .reconstruct_canonical_network(project, network.id)
            .await?
            .realms
            .is_empty()
    );
    let realm_a = service_a
        .create_canonical_realm_for_project(project, network.id, "10.50.0.0/24".into(), true)
        .await?;
    let realm_b = service_a
        .create_canonical_realm_for_project(project, network.id, "10.50.0.0/24".into(), true)
        .await?;
    let endpoint_a = service_a
        .create_canonical_endpoint_for_project(
            project,
            realm_a.id,
            "10.50.0.10".parse()?,
            "02:00:00:50:00:0a".into(),
        )
        .await?;
    let endpoint_b = service_a
        .create_canonical_endpoint_for_project(
            project,
            realm_b.id,
            "10.50.0.10".parse()?,
            "02:00:00:50:00:0b".into(),
        )
        .await?;
    let policy = o3k_domain::PolicyIntent {
        id: Uuid::now_v7(),
        endpoint_id: endpoint_a.id,
        direction: o3k_domain::PolicyDirection::Ingress,
        protocol: o3k_domain::NetworkProtocol::Tcp,
        ports: Some(o3k_domain::PortRange {
            start: 443,
            end: 443,
        }),
        source: None,
        destination: None,
        action: o3k_domain::PolicyAction::Allow,
    };
    service_a
        .upsert_policy_for_project(project, network.id, policy.clone())
        .await?;
    drop(service_a);
    drop(store_a);

    let store_b = Arc::new(PostgresStore::connect_pool(pool.clone()).await?);
    let service_b = NetworkService::open_for_test(&root, store_b.clone()).await?;
    let snapshot = service_b
        .reconstruct_canonical_network(project, network.id)
        .await?;
    assert_eq!(snapshot.network.id, network.id);
    assert_eq!(snapshot.realms.len(), 2);
    assert_eq!(snapshot.endpoints[&realm_a.id][0].id, endpoint_a.id);
    assert_eq!(snapshot.endpoints[&realm_b.id][0].id, endpoint_b.id);
    assert_eq!(
        service_b
            .list_policies_for_project(project, network.id)
            .await?,
        vec![policy]
    );
    drop(service_b);
    drop(store_b);
    pool.close().await;
    let _ = std::fs::remove_dir_all(root);
    Ok(())
}
