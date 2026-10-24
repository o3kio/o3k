//! PP.6 PostgreSQL 16 barrier/catalog SQL regression.
//!
//! These tests are `#[ignore]` by default because they require a disposable,
//! already-migrated PostgreSQL 16 database. `tests/pp6_pg16_backup.sh` runs
//! them with a real `pg_virtualenv` cluster. They fail closed when run without
//! the environment; they never silently skip.
#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]

use std::env;

use o3k_store::postgres::backup::{
    RolePolicy, apply_writer_barrier, inspect_roles, read_migrations, snapshot_facts,
};
use sqlx::{Connection, postgres::PgConnection};

fn test_url() -> String {
    env::var("O3K_PP6_PG_TEST_URL")
        .expect("O3K_PP6_PG_TEST_URL must point at a disposable migrated PostgreSQL 16 database")
}

fn schema_version() -> u64 {
    env::var("O3K_PP6_SCHEMA_VERSION")
        .expect("O3K_PP6_SCHEMA_VERSION is required")
        .parse()
        .expect("schema version")
}

fn role_policy() -> RolePolicy {
    RolePolicy {
        writer_roles: env::var("O3K_PP6_WRITER_ROLES")
            .unwrap_or_else(|_| "o3k_runtime".to_owned())
            .split(',')
            .map(str::to_owned)
            .collect(),
        dump_role: env::var("O3K_PP6_DUMP_ROLE").unwrap_or_else(|_| "o3k_backup_dump".to_owned()),
        restore_role: env::var("O3K_PP6_RESTORE_ROLE")
            .unwrap_or_else(|_| "o3k_restore_owner".to_owned()),
        control_role: env::var("O3K_PP6_CONTROL_ROLE").unwrap_or_else(|_| "ubuntu".to_owned()),
    }
}

#[tokio::test]
#[ignore = "requires a disposable migrated PostgreSQL 16 database"]
async fn reads_migrations_and_complete_catalog_facts() {
    let mut connection = PgConnection::connect(&test_url()).await.expect("connect");
    let migrations = read_migrations(&mut connection, schema_version())
        .await
        .expect("migrations");
    assert!(!migrations.is_empty());
    assert_eq!(
        migrations.last().map(|(version, _)| *version),
        Some(schema_version())
    );
    assert!(migrations.iter().all(|(_, checksum)| checksum.len() == 48));

    let inventory = o3k_store::state_inventory::baseline_state_inventory().expect("inventory");
    let facts = snapshot_facts(&mut connection, schema_version(), inventory)
        .await
        .expect("snapshot facts");
    assert!(facts.server_version.starts_with("16."));
    assert!(facts.state_inventory.iter().all(|entry| {
        entry
            .get("empty_state_included")
            .and_then(serde_json::Value::as_bool)
            .is_some()
    }));
    assert!(matches!(
        facts.in_flight_operations,
        "drained" | "recorded_unknown"
    ));
}

#[tokio::test]
#[ignore = "requires a disposable migrated PostgreSQL 16 database"]
async fn role_inspection_and_writer_barrier_sql() {
    let mut connection = PgConnection::connect(&test_url()).await.expect("connect");
    let policy = role_policy();
    inspect_roles(&mut connection, &policy)
        .await
        .expect("reviewed role matrix");

    // A new unrelated LOGIN role is rejected before any mutation.
    sqlx::query("CREATE ROLE o3k_pp6_test_unexpected LOGIN NOSUPERUSER NOCREATEDB NOCREATEROLE NOINHERIT NOREPLICATION NOBYPASSRLS")
        .execute(&mut connection)
        .await
        .expect("create unexpected role");
    let error = inspect_roles(&mut connection, &policy)
        .await
        .expect_err("unexpected login role");
    assert_eq!(error.reason(), "unexpected-login-role");
    sqlx::query("DROP ROLE o3k_pp6_test_unexpected")
        .execute(&mut connection)
        .await
        .expect("drop unexpected role");

    apply_writer_barrier(&mut connection, &policy)
        .await
        .expect("writer barrier");
    let modes: (bool, bool) = sqlx::query_as(
        "SELECT (SELECT rolcanlogin FROM pg_roles WHERE rolname = $1), \
                (SELECT rolcanlogin FROM pg_roles WHERE rolname = $2)",
    )
    .bind(&policy.dump_role)
    .bind(&policy.writer_roles[0])
    .fetch_one(&mut connection)
    .await
    .expect("role modes");
    assert!(modes.0, "dump role must be enabled for the capture window");
    assert!(!modes.1, "writer role must be disabled");

    // Restore the disposable fixture's default posture.
    sqlx::query(&format!("ALTER ROLE \"{}\" NOLOGIN", policy.dump_role))
        .execute(&mut connection)
        .await
        .expect("disable dump role");
    sqlx::query(&format!("ALTER ROLE \"{}\" LOGIN", policy.writer_roles[0]))
        .execute(&mut connection)
        .await
        .expect("enable writer role");
}
