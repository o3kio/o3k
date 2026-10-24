//! Live PostgreSQL catalog comparison against the committed canonical state
//! inventory.
//!
//! Requires a disposable PostgreSQL 16 database in `O3K_DATABASE_URL`. The
//! test is ignored by default like the other PostgreSQL conformance lanes.

#![allow(clippy::expect_used)]

use o3k_store::PostgresStore;
use o3k_store::state_inventory::{
    baseline_state_inventory, postgres_live_catalog_objects,
    verify_postgres_catalog_against_baseline,
};

#[tokio::test]
#[ignore = "requires O3K_DATABASE_URL (PostgreSQL)"]
async fn postgres_live_catalog_matches_the_committed_baseline() {
    let database_url = std::env::var("O3K_DATABASE_URL")
        .expect("O3K_DATABASE_URL must be set to run the PostgreSQL catalog comparison");
    let store = PostgresStore::connect(&database_url)
        .await
        .expect("connect to the configured PostgreSQL database");
    let live = postgres_live_catalog_objects(store.pool())
        .await
        .expect("read the live PostgreSQL catalog");
    let inventory = baseline_state_inventory().expect("committed baseline inventory");
    verify_postgres_catalog_against_baseline(&inventory, &live)
        .expect("live PostgreSQL catalog must match the committed baseline");
}
