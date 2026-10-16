#![allow(clippy::expect_used, clippy::unwrap_used)]

use std::time::Duration;

use o3k_store::{DurableStore, PostgresStore, ResourceRecord, StoreError};
use sqlx::{
    Connection,
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
    pool.close().await;
}
