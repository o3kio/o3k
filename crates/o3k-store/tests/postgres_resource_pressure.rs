#![allow(clippy::expect_used, clippy::unwrap_used)]

use std::{fs::OpenOptions, io::Write, process::Command, time::Duration};

use o3k_store::{DurableStore, PostgresStore, ResourceRecord, StoreError};
use serde_json::json;
use sqlx::{
    Connection, Row,
    postgres::{PgConnection, PgPoolOptions},
};
use uuid::Uuid;

fn database_url() -> String {
    std::env::var("O3K_DATABASE_URL").expect("O3K_DATABASE_URL must be set")
}

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
#[ignore = "requires the isolated CI PostgreSQL service"]
async fn postgres_pool_exhaustion_preserves_resource_row_state_and_retry() {
    let url = database_url();
    o3k_store::conformance::assert_destructive_postgres_test_database(&url)
        .expect("destructive PostgreSQL test database must have the expected purpose");
    let _database_guard = acquire_database_guard(&url).await;

    let pool = PgPoolOptions::new()
        .max_connections(1)
        .acquire_timeout(Duration::from_millis(100))
        .connect(&url)
        .await
        .expect("connect to PostgreSQL");
    let store = PostgresStore::connect_pool(pool.clone())
        .await
        .expect("apply current migrations");

    store
        .clean_tables_for_testing()
        .await
        .expect("clean the purpose-scoped database");
    let baseline = ResourceRecord {
        id: Uuid::now_v7(),
        kind: "compute_instance".to_owned(),
        project_id: "pp65-pressure".to_owned(),
        generation: 1,
        observed_generation: 1,
        desired_state: "ACTIVE".to_owned(),
        observed_state: "ACTIVE".to_owned(),
        provider_id: None,
    };
    store
        .insert_resource(&baseline)
        .await
        .expect("baseline row");
    let before = store
        .list_resources("pp65-pressure", "compute_instance")
        .await
        .expect("read baseline");

    let held = pool.acquire().await.expect("hold the sole pool connection");
    let candidate = ResourceRecord {
        id: Uuid::now_v7(),
        ..baseline.clone()
    };
    let error = store
        .insert_resource(&candidate)
        .await
        .expect_err("pool exhaustion must fail the write");
    assert!(matches!(
        error,
        StoreError::Database(sqlx::Error::PoolTimedOut)
    ));
    assert_eq!(error.to_string(), "database error");
    drop(held);

    let after_failure = store
        .list_resources("pp65-pressure", "compute_instance")
        .await
        .expect("read state after failed write");
    assert_eq!(after_failure, before);
    store
        .insert_resource(&candidate)
        .await
        .expect("retry after capacity recovery");
    assert_eq!(
        store
            .list_resources("pp65-pressure", "compute_instance")
            .await
            .expect("read state after retry")
            .len(),
        2
    );
    store
        .clean_tables_for_testing()
        .await
        .expect("clean the purpose-scoped database after the retry");
    assert!(
        store
            .list_resources("pp65-pressure", "compute_instance")
            .await
            .expect("verify scoped resource cleanup")
            .is_empty(),
        "purpose-scoped resource rows must be empty after cleanup"
    );

    let metadata = sqlx::query(
        "SELECT current_database() AS database_name, current_schema() AS schema_name, version() AS server_version",
    )
    .fetch_one(store.pool())
    .await
    .expect("read PostgreSQL evidence metadata");
    let source_commit = git_output(&["rev-parse", "HEAD"]);
    let source_tree = git_output(&["rev-parse", "HEAD^{tree}"]);
    let change_head = std::env::var("O3K_PP6_SOURCE_HEAD_SHA")
        .expect("O3K_PP6_SOURCE_HEAD_SHA must bind evidence to the PR head");
    let change_tree = git_output(&["rev-parse", &format!("{change_head}^{{tree}}")]);
    let evidence_path = std::env::var("O3K_PP6_PG_EVIDENCE_PATH")
        .expect("O3K_PP6_PG_EVIDENCE_PATH must identify the evidence output");
    let evidence = json!({
        "evidence_schema": "o3k.pp6.postgres-resource-pressure.v1",
        "disposition": "PASS",
        "source": {
            "repository": std::env::var("GITHUB_REPOSITORY").expect("GITHUB_REPOSITORY"),
            "checkout_commit": source_commit,
            "checkout_tree": source_tree,
            "change_head_commit": change_head,
            "change_head_tree": change_tree,
            "run_id": std::env::var("GITHUB_RUN_ID").expect("GITHUB_RUN_ID"),
            "run_attempt": std::env::var("GITHUB_RUN_ATTEMPT").expect("GITHUB_RUN_ATTEMPT")
        },
        "harness": {
            "test": "postgres_pool_exhaustion_preserves_resource_row_state_and_retry",
            "profile": "SPEC-0024 bounded PostgreSQL",
            "schema": "o3k-store migrations_postgres",
            "server_version": metadata.get::<String, _>("server_version"),
            "database": metadata.get::<String, _>("database_name"),
            "schema_name": metadata.get::<String, _>("schema_name"),
            "pool_max_connections": 1,
            "acquire_timeout_ms": 100
        },
        "observations": {
            "exhaustion_error": "database error / sqlx PoolTimedOut",
            "resource_rows_before": 1,
            "resource_rows_after_retry": 2,
            "resource_rows_after_cleanup": 0,
            "foreign_state": "untouched; only purpose-scoped O3K resource rows were inspected",
            "redaction": "no DSN, credential or secret emitted"
        },
        "cleanup": {"database_rows": "PASS", "advisory_lock_held": true}
    });
    let mut file = OpenOptions::new()
        .write(true)
        .create_new(true)
        .open(evidence_path)
        .expect("create evidence file atomically");
    serde_json::to_writer_pretty(&mut file, &evidence).expect("write evidence JSON");
    file.write_all(b"\n").expect("terminate evidence JSON");
    file.sync_all().expect("sync evidence JSON");
    pool.close().await;
}

fn git_output(args: &[&str]) -> String {
    let output = Command::new("git")
        .args(args)
        .output()
        .expect("run git for evidence identity");
    assert!(
        output.status.success(),
        "git evidence identity command failed"
    );
    String::from_utf8(output.stdout)
        .expect("git evidence identity is UTF-8")
        .trim()
        .to_owned()
}
