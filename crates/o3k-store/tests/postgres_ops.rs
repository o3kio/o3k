#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]

use sqlx::{Connection, postgres::PgConnection};
use std::env;
use std::net::Ipv4Addr;
use std::process::Command;
use std::str::FromStr;
use uuid::Uuid;

use o3k_kernel::{LimitKey, LimitValue, OwnershipScope, ResourceAmount, ScopeId, ScopeKind};
use o3k_store::{
    DurableStore, ImageMetadataRecord, ImageRepository, NetworkRecord, NetworkRepository,
    OperationRecord, OperationState, PlacementAllocationRecord, PlacementInventoryRecord,
    PlacementRepository, PlacementResourceRecord, PortRecord, PostgresStore, QuotaRepository,
    ResourceRecord, StoreError, SubnetRecord,
};

async fn prepare_test_database(database_url: &str) -> Option<PgConnection> {
    let mut database_guard = PgConnection::connect(database_url).await.ok()?;
    sqlx::query("SELECT pg_advisory_lock(hashtextextended('o3k-shared-test-database', 0))")
        .execute(&mut database_guard)
        .await
        .ok()?;
    sqlx::query("DROP SCHEMA IF EXISTS public CASCADE")
        .execute(&mut database_guard)
        .await
        .ok()?;
    sqlx::query("CREATE SCHEMA public")
        .execute(&mut database_guard)
        .await
        .ok()?;
    Some(database_guard)
}

async fn get_test_store() -> Option<(String, PostgresStore, PgConnection)> {
    if let Ok(url) = env::var("O3K_DATABASE_URL") {
        let database_guard = prepare_test_database(&url).await?;
        let store = PostgresStore::connect(&url).await.ok()?;
        return Some((url, store, database_guard));
    }
    let default_url = "postgres://o3k:password@127.0.0.1/o3k_test".to_owned();
    let database_guard = prepare_test_database(&default_url).await?;
    let store = PostgresStore::connect(&default_url).await.ok()?;
    Some((default_url, store, database_guard))
}

#[tokio::test]
async fn test_postgres_backup_and_restore() {
    let (db_url, store, _database_guard) = match get_test_store().await {
        Some(pair) => pair,
        None => {
            eprintln!("Skipping test_postgres_backup_and_restore: no Postgres instance available");
            return;
        }
    };
    store
        .clean_tables_for_testing()
        .await
        .expect("clean tables");

    // 1. Insert records across repositories
    let proj_id = format!("proj-backup-{}", Uuid::now_v7());
    let res_id = Uuid::now_v7();
    let res = ResourceRecord {
        id: res_id,
        kind: "compute_instance".to_owned(),
        project_id: proj_id.clone(),
        generation: 1,
        observed_generation: 1,
        desired_state: "ACTIVE".to_owned(),
        observed_state: "ACTIVE".to_owned(),
        provider_id: Some("prov-backup-1".to_owned()),
    };
    store.insert_resource(&res).await.expect("insert_resource");

    let op_id = Uuid::now_v7();
    let op = OperationRecord {
        id: op_id,
        resource_id: res_id,
        kind: "lifecycle:create".to_owned(),
        state: OperationState::Succeeded,
        provider_operation_id: Some("prov-op-backup".to_owned()),
        error_category: None,
        error_message: None,
    };
    store.insert_operation(&op).await.expect("insert_operation");

    let net_id = Uuid::now_v7();
    let net = NetworkRecord {
        id: net_id,
        project_id: proj_id.clone(),
        name: "backup-net".to_owned(),
        status: "ACTIVE".to_owned(),
    };
    store.insert_network(&net).await.expect("insert_network");

    let sub_id = Uuid::now_v7();
    let sub = SubnetRecord {
        id: sub_id,
        network_id: net_id,
        project_id: proj_id.clone(),
        name: "backup-subnet".to_owned(),
        cidr: "10.0.0.0/24".to_owned(),
        gateway_ip: Ipv4Addr::from_str("10.0.0.1").unwrap(),
        allocation_start: Ipv4Addr::from_str("10.0.0.10").unwrap(),
        allocation_end: Ipv4Addr::from_str("10.0.0.200").unwrap(),
        ip_version: 4,
        enable_dhcp: true,
    };
    store.insert_subnet(&sub).await.expect("insert_subnet");

    let port_id = Uuid::now_v7();
    let port = PortRecord {
        id: port_id,
        network_id: net_id,
        subnet_id: Some(sub_id),
        project_id: proj_id.clone(),
        name: "backup-port".to_owned(),
        fixed_ip: Ipv4Addr::from_str("10.0.0.55").unwrap(),
        mac_address: "fa:16:3e:aa:bb:cc".to_owned(),
        binding_host: None,
        binding_state: None,
        status: "ACTIVE".to_owned(),
    };
    store.insert_port(&port).await.expect("insert_port");

    let img_id = Uuid::now_v7();
    let img = ImageMetadataRecord {
        id: img_id,
        project_id: proj_id.clone(),
        name: "backup-image".to_owned(),
        status: "active".to_owned(),
        visibility: "public".to_owned(),
        disk_format: "raw".to_owned(),
        container_format: "bare".to_owned(),
        size: Some(1048576),
        checksum: Some("abc123hash".to_owned()),
    };
    store.insert_image(&img).await.expect("insert_image");

    let provider = store
        .register_provider(
            "node-backup-1",
            &[PlacementInventoryRecord {
                resource_class: "VCPU".to_owned(),
                total: 16,
                reserved: 0,
                allocation_ratio: 1.0,
                used: 0,
            }],
        )
        .await
        .expect("register_provider");

    let scope = OwnershipScope::new(
        ScopeId::new_unchecked(proj_id.clone()),
        ScopeKind::Project,
        None,
        None,
    );
    let key_servers = LimitKey::compute_servers();
    store
        .set_limit(&scope, &key_servers, LimitValue::Maximum(5))
        .await
        .expect("set_limit");

    let resv = store
        .reserve_quota(
            &scope,
            "op-backup-resv-1",
            &[ResourceAmount::new(key_servers.clone(), 1)],
        )
        .await
        .expect("reserve_quota");
    store
        .commit_reservation(&resv.id)
        .await
        .expect("commit_reservation");

    // 2. Perform pg_dump
    let dump_output = Command::new("pg_dump")
        .arg("-d")
        .arg(&db_url)
        .arg("--clean")
        .arg("--if-exists")
        .output()
        .expect("execute pg_dump");
    assert!(
        dump_output.status.success(),
        "pg_dump failed: {}",
        String::from_utf8_lossy(&dump_output.stderr)
    );
    let sql_dump = dump_output.stdout;

    // 3. Create fresh database for restore test
    let admin_url = "postgres://o3k:password@127.0.0.1/postgres";
    let _ = Command::new("psql")
        .arg("-d")
        .arg(admin_url)
        .arg("-c")
        .arg("DROP DATABASE IF EXISTS o3k_restore_test;")
        .output();
    let create_db = Command::new("psql")
        .arg("-d")
        .arg(admin_url)
        .arg("-c")
        .arg("CREATE DATABASE o3k_restore_test OWNER o3k;")
        .output()
        .expect("create database");
    assert!(create_db.status.success(), "CREATE DATABASE failed");

    // 4. Restore using psql
    let restore_url = "postgres://o3k:password@127.0.0.1/o3k_restore_test";
    let mut psql_child = Command::new("psql")
        .arg("-d")
        .arg(restore_url)
        .stdin(std::process::Stdio::piped())
        .spawn()
        .expect("spawn psql restore");

    {
        use std::io::Write;
        let stdin = psql_child.stdin.as_mut().expect("psql stdin");
        stdin
            .write_all(&sql_dump)
            .expect("write dump to psql stdin");
    }
    let restore_status = psql_child.wait().expect("wait for psql restore");
    assert!(restore_status.success(), "psql restore failed");

    // 5. Connect new PostgresStore to restored database and verify all state
    let restored_store = PostgresStore::connect(restore_url)
        .await
        .expect("connect to restored store");

    let restored_res = restored_store
        .get_resource(res_id)
        .await
        .expect("get resource");
    assert_eq!(restored_res.id, res.id);
    assert_eq!(restored_res.desired_state, "ACTIVE");

    let restored_op = restored_store
        .get_operation(op_id)
        .await
        .expect("get operation");
    assert_eq!(restored_op.state, OperationState::Succeeded);

    let restored_net = restored_store
        .get_network(&proj_id, &net_id)
        .await
        .expect("get network")
        .expect("some");
    assert_eq!(restored_net.name, "backup-net");

    let restored_port = restored_store
        .get_port(&proj_id, &port_id)
        .await
        .expect("get port")
        .expect("some");
    assert_eq!(restored_port.fixed_ip.to_string(), "10.0.0.55");

    let restored_img = restored_store
        .get_image(&proj_id, &img_id)
        .await
        .expect("get image")
        .expect("some");
    assert_eq!(restored_img.name, "backup-image");

    let restored_providers = restored_store
        .list_providers()
        .await
        .expect("list providers");
    assert!(restored_providers.iter().any(|p| p.id == provider.id));

    let restored_limit = restored_store
        .get_limit(&scope, &key_servers)
        .await
        .expect("get limit");
    assert_eq!(restored_limit, LimitValue::Maximum(5));

    let restored_resv = restored_store
        .get_reservation_for_operation("op-backup-resv-1")
        .await
        .expect("get resv")
        .expect("some");
    assert_eq!(restored_resv.id, resv.id);

    // Clean up temporary restore database. Close the store pool first, then
    // terminate leftover backends and force the drop so teardown cannot race
    // server-side session termination (SQLSTATE 55006).
    restored_store.pool().close().await;
    let _ = Command::new("psql")
        .arg("-d")
        .arg(admin_url)
        .arg("-c")
        .arg(
            "SELECT pg_terminate_backend(pid) FROM pg_stat_activity \
             WHERE datname = 'o3k_restore_test' AND pid <> pg_backend_pid();",
        )
        .output();
    let drop_out = Command::new("psql")
        .arg("-d")
        .arg(admin_url)
        .arg("-c")
        .arg("DROP DATABASE IF EXISTS o3k_restore_test;")
        .output()
        .expect("drop restore database");
    assert!(
        drop_out.status.success(),
        "DROP DATABASE o3k_restore_test failed: {}",
        String::from_utf8_lossy(&drop_out.stderr)
    );
}

#[tokio::test]
async fn test_postgres_error_mapping_and_no_leakage() {
    let (_db_url, store, _database_guard) = match get_test_store().await {
        Some(pair) => pair,
        None => {
            eprintln!(
                "Skipping test_postgres_error_mapping_and_no_leakage: no Postgres instance available"
            );
            return;
        }
    };
    store
        .clean_tables_for_testing()
        .await
        .expect("clean tables");

    let res_id = Uuid::now_v7();
    let res = ResourceRecord {
        id: res_id,
        kind: "compute_instance".to_owned(),
        project_id: "proj-1".to_owned(),
        generation: 1,
        observed_generation: 0,
        desired_state: "ACTIVE".to_owned(),
        observed_state: "BUILDING".to_owned(),
        provider_id: None,
    };
    store.insert_resource(&res).await.expect("insert_resource");

    // Duplicate resource insert returns typed StoreError::ResourceAlreadyExists
    let dup_res = store.insert_resource(&res).await;
    match dup_res {
        Err(StoreError::ResourceAlreadyExists) => {}
        other => panic!("expected StoreError::ResourceAlreadyExists, got {other:?}"),
    }
}

#[tokio::test]
async fn test_postgres_placement_hierarchy_conformance() {
    let Some((_db_url, store, _database_guard)) = get_test_store().await else {
        eprintln!(
            "Skipping test_postgres_placement_hierarchy_conformance: no Postgres instance available"
        );
        return;
    };
    let inventory = [PlacementInventoryRecord {
        resource_class: "VCPU".to_owned(),
        total: 8,
        reserved: 0,
        allocation_ratio: 1.0,
        used: 0,
    }];
    let parent = store
        .register_provider("pg-hierarchy-parent", &inventory)
        .await
        .expect("register parent");
    let child = store
        .register_provider_metadata(
            "pg-hierarchy-child",
            &inventory,
            Some(&parent.id),
            &["COMPUTE".to_owned(), "SPECIAL_X".to_owned()],
            &["rack-a".to_owned()],
            Some("az-1"),
        )
        .await
        .expect("register child metadata");
    assert_eq!(
        child.parent_provider_id.as_deref(),
        Some(parent.id.as_str())
    );
    assert_eq!(child.traits, vec!["COMPUTE", "SPECIAL_X"]);
    assert_eq!(child.failure_domains, vec!["rack-a"]);
    assert_eq!(child.location.as_deref(), Some("az-1"));
    assert!(matches!(
        store
            .update_provider_metadata(
                &child.id,
                child.generation - 1,
                Some(&parent.id),
                &child.traits,
                &child.failure_domains,
                child.location.as_deref(),
            )
            .await,
        Err(StoreError::PlacementStaleGeneration)
    ));
    let allocation = PlacementAllocationRecord {
        id: "pg-hierarchy-allocation".to_owned(),
        provider_id: child.id.clone(),
        consumer_id: "pg-consumer".to_owned(),
        resources: vec![PlacementResourceRecord {
            resource_class: "VCPU".to_owned(),
            amount: 2,
        }],
    };
    store
        .commit_allocation(&child.id, child.generation, &allocation)
        .await
        .expect("commit fenced allocation");
    let restored = store
        .get_provider(&child.id)
        .await
        .expect("read child")
        .expect("child exists");
    assert_eq!(restored.allocations, vec![allocation]);
}
