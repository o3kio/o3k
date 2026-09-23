#![allow(clippy::expect_used, clippy::unwrap_used)]

use std::borrow::Cow;
use std::net::Ipv4Addr;

use o3k_store::{
    CanonicalAddressPoolRecord, CanonicalAddressRealmRecord, CanonicalEndpointRecord,
    CanonicalNetworkRecord, NetworkRepository, PortRecord, PostgresStore, StoreError, SubnetRecord,
};
use sqlx::{
    Connection, PgPool, Row,
    postgres::{PgConnection, PgPoolOptions},
};
use uuid::Uuid;

fn database_url() -> String {
    std::env::var("O3K_DATABASE_URL")
        .expect("O3K_DATABASE_URL must be set for P13.1F1 PostgreSQL conformance")
}

/// Acquires a session-level advisory lock on the shared PostgreSQL test
/// database, held by a dedicated connection for the caller's entire test.
/// The shared `o3k-shared-test-database` key serializes every test group that
/// destructively resets the database (this file, `pp4_endpoint_lifecycle`, and
/// group C's conformance/postgres_ops helpers) against each other, even across
/// separate `cargo test` processes. Matches
/// `o3k_store::conformance::prepare_shared_postgres_test_database`.
async fn acquire_database_guard(url: &str) -> PgConnection {
    let mut connection = PgConnection::connect(url)
        .await
        .expect("connect to the shared PostgreSQL conformance database");
    sqlx::query("SELECT pg_advisory_lock(hashtextextended('o3k-shared-test-database', 0))")
        .execute(&mut connection)
        .await
        .expect("acquire the shared PostgreSQL test-database advisory lock");
    connection
}

async fn fresh_pool(url: &str) -> PgPool {
    let pool = PgPoolOptions::new()
        .max_connections(10)
        .connect(url)
        .await
        .expect("connect to PostgreSQL");
    sqlx::query("DROP SCHEMA IF EXISTS public CASCADE")
        .execute(&pool)
        .await
        .expect("drop test schema");
    sqlx::query("CREATE SCHEMA public")
        .execute(&pool)
        .await
        .expect("create test schema");
    pool
}

async fn apply_legacy_migrations(pool: &PgPool) {
    let all = sqlx::migrate!("./migrations_postgres");
    let legacy = sqlx::migrate::Migrator {
        migrations: Cow::Owned(all.migrations.iter().take(9).cloned().collect()),
        ignore_missing: false,
        locking: true,
        no_tx: false,
    };
    legacy.run(pool).await.expect("apply legacy migrations");
}

async fn seed_legacy_state(pool: &PgPool) -> (Uuid, Uuid, Uuid, Uuid) {
    let network_a = Uuid::from_u128(0x1301);
    let network_b = Uuid::from_u128(0x1302);
    let realm_a = Uuid::from_u128(0x1311);
    let realm_b = Uuid::from_u128(0x1312);
    let endpoint_a = Uuid::from_u128(0x1321);
    let policy_a = Uuid::from_u128(0x1323);

    sqlx::query(
        "INSERT INTO network_networks (id, name, project_id, status) VALUES ($1, $2, $3, $4), ($5, $6, $7, $8)",
    )
    .bind(network_a.to_string())
    .bind("network-a")
    .bind("project-a")
    .bind("ACTIVE")
    .bind(network_b.to_string())
    .bind("network-b")
    .bind("project-b")
    .bind("ACTIVE")
    .execute(pool)
    .await
    .expect("legacy networks");

    sqlx::query(
        "INSERT INTO network_intents (id, project_id, generation, payload, status) VALUES ($1, $2, 7, $3, 'active')",
    )
    .bind(network_a.to_string())
    .bind("project-a")
    .bind(format!(r#"{{"id":"{}","project_id":"project-a","realm":{{"id":"{}"}},"policies":[{{"id":"{}","endpoint_id":"{}","direction":"Ingress","protocol":"Tcp","ports":{{"start":443,"end":443}},"source":{{"network":"198.51.100.0","prefix_len":24}},"destination":null,"action":"Deny"}}]}}"#, network_a, realm_a, policy_a, endpoint_a))
    .execute(pool)
    .await
    .expect("legacy network intent");

    sqlx::query(
        "INSERT INTO network_subnets (id, network_id, name, project_id, cidr, gateway_ip, allocation_start, allocation_end) VALUES ($1, $2, $3, $4, $5, $6, $7, $8), ($9, $10, $11, $12, $13, $14, $15, $16)",
    )
    .bind(realm_a.to_string())
    .bind(network_a.to_string())
    .bind("subnet-a")
    .bind("project-a")
    .bind("10.0.0.0/24")
    .bind("10.0.0.1")
    .bind("10.0.0.2")
    .bind("10.0.0.254")
    .bind(realm_b.to_string())
    .bind(network_b.to_string())
    .bind("subnet-b")
    .bind("project-b")
    .bind("10.0.0.0/24")
    .bind("10.0.0.1")
    .bind("10.0.0.2")
    .bind("10.0.0.254")
    .execute(pool)
    .await
    .expect("legacy subnets");

    sqlx::query(
        "INSERT INTO network_ports (id, network_id, subnet_id, project_id, name, mac_address, fixed_ip, status) VALUES ($1, $2, $3, $4, $5, $6, $7, $8)",
    )
    .bind(endpoint_a.to_string())
    .bind(network_a.to_string())
    .bind(realm_a.to_string())
    .bind("project-a")
    .bind("port-a")
    .bind("02:00:00:00:13:21")
    .bind("10.0.0.10")
    .bind("ACTIVE")
    .execute(pool)
    .await
    .expect("legacy endpoint");

    (network_a, network_b, realm_a, endpoint_a)
}

#[tokio::test]
#[ignore = "requires the configured PostgreSQL conformance database"]
async fn postgres_p13_f1_migrates_and_reopens_canonical_network_state() {
    let url = database_url();
    let _database_guard = acquire_database_guard(&url).await;
    let pool = fresh_pool(&url).await;
    apply_legacy_migrations(&pool).await;
    let (network_a, network_b, realm_a, endpoint_a) = seed_legacy_state(&pool).await;

    let store = PostgresStore::connect_pool(pool.clone())
        .await
        .expect("run canonical migration and backfill");
    let network = store
        .get_canonical_network("project-a", &network_a)
        .await
        .expect("get migrated network")
        .expect("network exists");
    assert_eq!(
        network,
        CanonicalNetworkRecord {
            id: network_a,
            project_id: "project-a".into(),
            name: "network-a".into(),
            admin_state_up: true,
            generation: 7,
            state: "active".into(),
        }
    );
    assert!(
        store
            .list_canonical_realms("project-a", &Uuid::from_u128(0x1fff))
            .await
            .expect("empty realm lookup")
            .is_empty()
    );

    let realms_a = store
        .list_canonical_realms("project-a", &network_a)
        .await
        .expect("list migrated realms");
    assert_eq!(realms_a.len(), 1);
    assert_eq!(realms_a[0].id, realm_a);
    assert_eq!(realms_a[0].network_id, network_a);
    assert_eq!(realms_a[0].project_id, "project-a");

    let pools = store
        .list_canonical_pools("project-a", &realm_a)
        .await
        .expect("list migrated pools");
    assert_eq!(pools.len(), 1);
    assert_eq!(pools[0].id, realm_a);
    assert_eq!(pools[0].realm_id, realm_a);

    let endpoints = store
        .list_canonical_endpoints("project-a", &realm_a)
        .await
        .expect("list migrated endpoints");
    assert_eq!(endpoints.len(), 1);
    assert_eq!(endpoints[0].id, endpoint_a);
    assert_eq!(endpoints[0].fixed_ip.to_string(), "10.0.0.10");
    let policies = store
        .list_canonical_policies("project-a", &network_a)
        .await
        .expect("list migrated policies");
    assert_eq!(policies.len(), 1);
    assert_eq!(policies[0].id, Uuid::from_u128(0x1323));
    assert_eq!(policies[0].endpoint_id, endpoint_a);

    let overlap = store
        .list_canonical_realms("project-b", &network_b)
        .await
        .expect("list overlapping realm");
    assert_eq!(overlap.len(), 1);
    let same_ip = o3k_store::CanonicalEndpointRecord {
        id: Uuid::from_u128(0x1322),
        realm_id: overlap[0].id,
        project_id: "project-b".into(),
        fixed_ip: "10.0.0.10".parse().unwrap(),
        mac: "02:00:00:00:13:22".into(),
        generation: 1,
        state: "active".into(),
    };
    store
        .insert_canonical_endpoint(&same_ip)
        .await
        .expect("same IP in another realm");
    let duplicate = o3k_store::CanonicalEndpointRecord {
        id: Uuid::from_u128(0x1323),
        mac: "02:00:00:00:13:23".into(),
        ..same_ip.clone()
    };
    assert!(matches!(
        store.insert_canonical_endpoint(&duplicate).await,
        Err(StoreError::ResourceAlreadyExists)
    ));

    assert!(matches!(
        store
            .insert_canonical_realm(&o3k_store::CanonicalAddressRealmRecord {
                id: Uuid::from_u128(0x1331),
                network_id: network_a,
                project_id: "project-b".into(),
                prefix: "10.2.0.0/24".into(),
                overlapping_prefixes: false,
                generation: 1,
                state: "active".into(),
            })
            .await,
        Err(StoreError::OwnershipConflict)
    ));

    let reopened = PostgresStore::connect(&url).await.expect("reopen store");
    assert_eq!(
        reopened
            .get_canonical_network("project-a", &network_a)
            .await
            .expect("reopened network")
            .expect("reopened network exists")
            .generation,
        7
    );
    reopened
        .delete_canonical_realm("project-a", &realm_a)
        .await
        .expect_err("dependent pool/endpoint blocks realm deletion");
    sqlx::query("DELETE FROM canonical_network_policies WHERE endpoint_id = (SELECT id FROM canonical_endpoints WHERE realm_id = $1)")
        .bind(realm_a.to_string())
        .execute(&pool)
        .await
        .expect("remove canonical policies");
    sqlx::query("DELETE FROM canonical_endpoints WHERE realm_id = $1")
        .bind(realm_a.to_string())
        .execute(reopened.pool())
        .await
        .expect("remove test endpoint");
    sqlx::query("DELETE FROM canonical_address_pools WHERE realm_id = $1")
        .bind(realm_a.to_string())
        .execute(reopened.pool())
        .await
        .expect("remove test pool");
    reopened
        .delete_canonical_realm("project-a", &realm_a)
        .await
        .expect("remove realm");
    assert!(
        reopened
            .list_canonical_realms("project-a", &network_a)
            .await
            .expect("list after realm removal")
            .is_empty()
    );
    assert!(
        reopened
            .get_canonical_network("project-a", &network_a)
            .await
            .expect("network after realm removal")
            .is_some()
    );

    let constraints: Vec<String> = sqlx::query(
        "SELECT conname FROM pg_constraint WHERE conrelid IN ('canonical_networks'::regclass, 'canonical_address_realms'::regclass, 'canonical_address_pools'::regclass, 'canonical_endpoints'::regclass, 'canonical_realm_encapsulation_bindings'::regclass) ORDER BY conname",
    )
    .fetch_all(reopened.pool())
    .await
    .expect("inspect canonical constraints")
    .into_iter()
    .map(|row| row.get("conname"))
    .collect();
    assert!(
        constraints
            .iter()
            .any(|name| name == "canonical_networks_pkey")
    );
    assert!(
        constraints
            .iter()
            .any(|name| name == "canonical_address_realms_network_id_fkey")
    );
    assert!(
        constraints
            .iter()
            .any(|name| name == "canonical_endpoints_realm_id_fixed_ip_key")
    );
    reopened
        .clean_tables_for_testing()
        .await
        .expect("clean conformance database");
}

#[tokio::test]
#[ignore = "requires the configured PostgreSQL conformance database"]
async fn postgres_p13_f1_invalid_legacy_state_fails_closed() {
    let url = database_url();
    let _database_guard = acquire_database_guard(&url).await;
    let pool = fresh_pool(&url).await;
    apply_legacy_migrations(&pool).await;
    let network = Uuid::from_u128(0x1401);
    let subnet = Uuid::from_u128(0x1411);
    sqlx::query(
        "INSERT INTO network_networks (id, name, project_id, status) VALUES ($1, 'network', 'project-a', 'ACTIVE')",
    )
    .bind(network.to_string())
    .execute(&pool)
    .await
    .expect("legacy network");
    sqlx::query(
        "INSERT INTO network_subnets (id, network_id, name, project_id, cidr, gateway_ip, allocation_start, allocation_end) VALUES ($1, $2, 'subnet', 'project-b', 'not-a-cidr', '10.0.0.1', '10.0.0.2', '10.0.0.254')",
    )
    .bind(subnet.to_string())
    .bind(network.to_string())
    .execute(&pool)
    .await
    .expect("invalid legacy subnet fixture");

    let result = PostgresStore::connect_pool(pool.clone()).await;
    assert!(matches!(result, Err(StoreError::OwnershipConflict)));
    let canonical_count: i64 =
        sqlx::query_scalar("SELECT COUNT(*) FROM canonical_networks WHERE id = $1")
            .bind(network.to_string())
            .fetch_one(&pool)
            .await
            .expect("inspect rolled-back backfill");
    assert_eq!(canonical_count, 0);
    sqlx::query("DROP SCHEMA public CASCADE")
        .execute(&pool)
        .await
        .expect("drop invalid fixture schema");
    sqlx::query("CREATE SCHEMA public")
        .execute(&pool)
        .await
        .expect("restore public schema");
}

#[tokio::test]
#[ignore = "requires the configured PostgreSQL conformance database"]
async fn postgres_p13_2a_network_rename_updates_projection_and_reopens() {
    let url = database_url();
    let _database_guard = acquire_database_guard(&url).await;
    let pool = fresh_pool(&url).await;
    let network_id = Uuid::from_u128(0x13a1);

    let store = PostgresStore::connect_pool(pool.clone())
        .await
        .expect("migrate store");
    store
        .insert_network(&o3k_store::NetworkRecord {
            id: network_id,
            name: "before".into(),
            project_id: "project-a".into(),
            status: "ACTIVE".into(),
        })
        .await
        .expect("legacy projection");
    store
        .insert_canonical_network(&CanonicalNetworkRecord {
            id: network_id,
            project_id: "project-a".into(),
            name: "before".into(),
            admin_state_up: true,
            generation: 1,
            state: "active".into(),
        })
        .await
        .expect("canonical network");
    let realm_a = Uuid::from_u128(0x13a2);
    let realm_b = Uuid::from_u128(0x13a3);
    for (id, prefix) in [(realm_a, "198.51.100.0/24"), (realm_b, "198.51.101.0/24")] {
        store
            .insert_canonical_realm(&o3k_store::CanonicalAddressRealmRecord {
                id,
                network_id,
                project_id: "project-a".into(),
                prefix: prefix.into(),
                overlapping_prefixes: false,
                generation: 1,
                state: "active".into(),
            })
            .await
            .expect("canonical realm");
    }

    let renamed = store
        .update_canonical_network("project-a", &network_id, 1, "after", false)
        .await
        .expect("atomic canonical/projection rename");
    assert_eq!(renamed.name, "after");
    assert!(!renamed.admin_state_up);
    assert_eq!(
        store
            .get_network("project-a", &network_id)
            .await
            .unwrap()
            .unwrap()
            .name,
        "after"
    );
    assert_eq!(
        store
            .list_canonical_realms("project-a", &network_id)
            .await
            .unwrap()
            .into_iter()
            .map(|realm| realm.id)
            .collect::<Vec<_>>(),
        vec![realm_a, realm_b]
    );

    drop(store);
    let reopened = PostgresStore::connect(&url).await.expect("reopen store");
    let restored = reopened
        .get_canonical_network("project-a", &network_id)
        .await
        .expect("reopened canonical network")
        .expect("canonical network exists");
    assert_eq!(restored.name, "after");
    assert!(!restored.admin_state_up);
    assert_eq!(
        reopened
            .get_network("project-a", &network_id)
            .await
            .unwrap()
            .unwrap()
            .name,
        "after"
    );
    assert_eq!(
        reopened
            .list_canonical_realms("project-a", &network_id)
            .await
            .unwrap()
            .into_iter()
            .map(|realm| realm.id)
            .collect::<Vec<_>>(),
        vec![realm_a, realm_b]
    );
    reopened
        .clean_tables_for_testing()
        .await
        .expect("clean test database");
}

#[tokio::test]
#[ignore = "requires the configured PostgreSQL conformance database"]
async fn postgres_p13_2b_subnet_bundle_cardinality_and_delete_reopen() {
    let url = database_url();
    let _database_guard = acquire_database_guard(&url).await;
    let pool = fresh_pool(&url).await;
    let network_id = Uuid::from_u128(0x13b1);
    let realm_id = Uuid::from_u128(0x13b2);
    let pool_id = Uuid::from_u128(0x13b3);
    let project_id = "project-p13-2b";
    let store = PostgresStore::connect_pool(pool.clone())
        .await
        .expect("migrate store");

    store
        .insert_network(&o3k_store::NetworkRecord {
            id: network_id,
            name: "p13-2b-network".into(),
            project_id: project_id.into(),
            status: "ACTIVE".into(),
        })
        .await
        .expect("legacy network projection");
    store
        .insert_canonical_network(&CanonicalNetworkRecord {
            id: network_id,
            project_id: project_id.into(),
            name: "p13-2b-network".into(),
            admin_state_up: true,
            generation: 1,
            state: "active".into(),
        })
        .await
        .expect("canonical network");

    let realm = CanonicalAddressRealmRecord {
        id: realm_id,
        network_id,
        project_id: project_id.into(),
        prefix: "198.51.100.0/24".into(),
        overlapping_prefixes: false,
        generation: 1,
        state: "active".into(),
    };
    let pool_record = CanonicalAddressPoolRecord {
        id: pool_id,
        realm_id,
        project_id: project_id.into(),
        prefix: "198.51.100.0/24".into(),
        gateway: Some(Ipv4Addr::new(198, 51, 100, 1)),
        first_usable: Ipv4Addr::new(198, 51, 100, 2),
        last_usable: Ipv4Addr::new(198, 51, 100, 254),
        generation: 1,
        state: "active".into(),
    };
    let subnet = SubnetRecord {
        id: realm_id,
        network_id,
        name: String::new(),
        project_id: project_id.into(),
        cidr: "198.51.100.0/24".into(),
        gateway_ip: Ipv4Addr::new(198, 51, 100, 1),
        allocation_start: Ipv4Addr::new(198, 51, 100, 2),
        allocation_end: Ipv4Addr::new(198, 51, 100, 254),
        ip_version: 4,
        enable_dhcp: true,
    };

    store
        .insert_subnet_bundle(&realm, &pool_record, &subnet)
        .await
        .expect("create subnet bundle");
    assert_eq!(
        store
            .list_canonical_realms(project_id, &network_id)
            .await
            .unwrap()
            .len(),
        1
    );
    assert_eq!(
        store
            .list_canonical_pools(project_id, &realm_id)
            .await
            .unwrap()
            .len(),
        1
    );

    let second = CanonicalAddressRealmRecord {
        id: Uuid::from_u128(0x13b4),
        prefix: "198.51.101.0/24".into(),
        ..realm.clone()
    };
    let second_pool = CanonicalAddressPoolRecord {
        id: Uuid::from_u128(0x13b5),
        realm_id: second.id,
        prefix: second.prefix.clone(),
        ..pool_record.clone()
    };
    let second_subnet = SubnetRecord {
        id: second.id,
        cidr: second.prefix.clone(),
        ..subnet.clone()
    };
    assert!(matches!(
        store
            .insert_subnet_bundle(&second, &second_pool, &second_subnet)
            .await,
        Err(StoreError::NetworkInUse)
    ));

    store
        .delete_subnet_bundle(project_id, &realm_id)
        .await
        .expect("delete subnet bundle");
    drop(store);
    let reopened = PostgresStore::connect(&url).await.expect("reopen store");
    assert!(
        reopened
            .get_canonical_realm(project_id, &realm_id)
            .await
            .unwrap()
            .is_none()
    );
    assert!(
        reopened
            .list_canonical_pools(project_id, &realm_id)
            .await
            .unwrap()
            .is_empty()
    );
    assert!(
        reopened
            .get_canonical_network(project_id, &network_id)
            .await
            .unwrap()
            .is_some()
    );
}

#[tokio::test]
#[ignore = "requires the configured PostgreSQL conformance database"]
async fn postgres_p13_2c_endpoint_port_atomic_lifecycle_and_reopen() {
    let url = database_url();
    let _database_guard = acquire_database_guard(&url).await;
    let pool = fresh_pool(&url).await;
    let network_id = Uuid::from_u128(0x13c1);
    let realm_id = Uuid::from_u128(0x13c2);
    let pool_id = Uuid::from_u128(0x13c3);
    let endpoint_id = Uuid::from_u128(0x13c4);
    let project_id = "project-p13-2c";
    let store = PostgresStore::connect_pool(pool.clone())
        .await
        .expect("migrate store");

    store
        .insert_network(&o3k_store::NetworkRecord {
            id: network_id,
            name: "p13-2c-network".into(),
            project_id: project_id.into(),
            status: "ACTIVE".into(),
        })
        .await
        .expect("legacy network projection");
    store
        .insert_canonical_network(&CanonicalNetworkRecord {
            id: network_id,
            project_id: project_id.into(),
            name: "p13-2c-network".into(),
            admin_state_up: true,
            generation: 1,
            state: "active".into(),
        })
        .await
        .expect("canonical network");
    let realm = CanonicalAddressRealmRecord {
        id: realm_id,
        network_id,
        project_id: project_id.into(),
        prefix: "198.51.102.0/24".into(),
        overlapping_prefixes: false,
        generation: 1,
        state: "active".into(),
    };
    let pool_record = CanonicalAddressPoolRecord {
        id: pool_id,
        realm_id,
        project_id: project_id.into(),
        prefix: realm.prefix.clone(),
        gateway: Some(Ipv4Addr::new(198, 51, 102, 1)),
        first_usable: Ipv4Addr::new(198, 51, 102, 2),
        last_usable: Ipv4Addr::new(198, 51, 102, 254),
        generation: 1,
        state: "active".into(),
    };
    let subnet = SubnetRecord {
        id: realm_id,
        network_id,
        name: String::new(),
        project_id: project_id.into(),
        cidr: realm.prefix.clone(),
        gateway_ip: Ipv4Addr::new(198, 51, 102, 1),
        allocation_start: Ipv4Addr::new(198, 51, 102, 2),
        allocation_end: Ipv4Addr::new(198, 51, 102, 254),
        ip_version: 4,
        enable_dhcp: false,
    };
    store
        .insert_subnet_bundle(&realm, &pool_record, &subnet)
        .await
        .expect("subnet bundle");

    let endpoint = CanonicalEndpointRecord {
        id: endpoint_id,
        realm_id,
        project_id: project_id.into(),
        fixed_ip: Ipv4Addr::new(198, 51, 102, 10),
        mac: "02:00:00:00:13:c4".into(),
        generation: 1,
        state: "active".into(),
    };
    let port = PortRecord {
        id: endpoint_id,
        network_id,
        subnet_id: Some(realm_id),
        project_id: project_id.into(),
        name: "p13-2c-port".into(),
        mac_address: endpoint.mac.clone(),
        fixed_ip: endpoint.fixed_ip,
        status: "ACTIVE".into(),
        binding_host: None,
        binding_state: None,
    };
    store
        .insert_canonical_endpoint_and_port(&endpoint, &port)
        .await
        .expect("atomic endpoint and port create");
    assert_eq!(
        store
            .get_canonical_endpoint(project_id, &endpoint_id)
            .await
            .expect("endpoint read")
            .expect("endpoint exists")
            .fixed_ip,
        endpoint.fixed_ip
    );
    store
        .delete_canonical_endpoint_and_port(project_id, &endpoint_id)
        .await
        .expect("atomic endpoint and port delete");
    drop(store);

    let reopened = PostgresStore::connect(&url).await.expect("reopen store");
    assert!(
        reopened
            .get_canonical_endpoint(project_id, &endpoint_id)
            .await
            .expect("endpoint after reopen")
            .is_none()
    );
    assert!(
        reopened
            .get_port(project_id, &endpoint_id)
            .await
            .expect("projection after reopen")
            .is_none()
    );
    assert!(
        reopened
            .get_canonical_network(project_id, &network_id)
            .await
            .expect("network after reopen")
            .is_some()
    );
}
