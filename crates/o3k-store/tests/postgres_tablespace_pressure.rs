#![allow(clippy::expect_used, clippy::unwrap_used)]

use o3k_store::{DurableStore, OperationRecord, OperationState, PostgresStore, ResourceRecord};
use serde_json::json;
use sqlx::{Connection, postgres::PgConnection};
use std::{env, fs};
use uuid::Uuid;

fn url() -> String {
    env::var("O3K_DATABASE_URL").expect("O3K_DATABASE_URL")
}

#[tokio::test]
#[ignore = "requires the run-owned constrained PostgreSQL tablespace lane"]
async fn postgres_tablespace_pressure_preserves_canonical_state_and_retries() {
    let url = url();
    let path = env::var("O3K_PG_PRESSURE_TABLESPACE_PATH").expect("tablespace path");
    let artifact = env::var("O3K_PG_PRESSURE_ARTIFACT").expect("artifact path");
    let source_sha = env::var("O3K_SOURCE_SHA").expect("source sha");
    let source_tree = env::var("O3K_SOURCE_TREE").expect("source tree");
    let execution_sha = env::var("O3K_EXECUTION_SHA").expect("execution sha");
    let execution_tree = env::var("O3K_EXECUTION_TREE").expect("execution tree");
    let mut admin = PgConnection::connect(&url).await.expect("connect");
    let db: String = sqlx::query_scalar("SELECT current_database()")
        .fetch_one(&mut admin)
        .await
        .expect("database");
    let ts = format!("o3k_pressure_{}", Uuid::now_v7().simple());
    let filler = format!("o3k_pressure_filler_{}", Uuid::now_v7().simple());
    let ident = |s: &str| format!("\"{}\"", s.replace('"', "\"\""));
    sqlx::query(&format!(
        "CREATE TABLESPACE {} LOCATION '{}'",
        ident(&ts),
        path.replace('\\', "\\\\").replace('\'', "''")
    ))
    .execute(&mut admin)
    .await
    .expect("tablespace");
    sqlx::query(&format!(
        "CREATE TABLE {} (payload bytea) TABLESPACE {}",
        ident(&filler),
        ident(&ts)
    ))
    .execute(&mut admin)
    .await
    .expect("filler table");
    sqlx::query(&format!(
        "ALTER TABLE resources SET TABLESPACE {}",
        ident(&ts)
    ))
    .execute(&mut admin)
    .await
    .expect("resource tablespace");
    let store = PostgresStore::connect(&url).await.expect("store");
    let project = format!("pp6-pressure-{}", Uuid::now_v7());
    let baseline = Uuid::now_v7();
    store
        .insert_resource(&ResourceRecord {
            id: baseline,
            kind: "pressure-baseline".into(),
            project_id: project.clone(),
            generation: 1,
            observed_generation: 1,
            desired_state: "{}".into(),
            observed_state: "ACTIVE".into(),
            provider_id: None,
        })
        .await
        .expect("baseline");
    let baseline_operation = Uuid::now_v7();
    store
        .insert_operation(&OperationRecord {
            id: baseline_operation,
            resource_id: baseline,
            kind: "pressure:baseline".into(),
            state: OperationState::Succeeded,
            provider_operation_id: None,
            error_category: None,
            error_message: None,
        })
        .await
        .expect("baseline operation");

    let mut attempts = 0u32;
    let sqlstate = loop {
        attempts += 1;
        let result = sqlx::query(&format!(
            "INSERT INTO {} VALUES (repeat('x', 32768)::bytea)",
            ident(&filler)
        ))
        .execute(&mut admin)
        .await;
        if let Err(error) = result {
            break error
                .as_database_error()
                .and_then(|e| e.code().map(|c| c.to_string()));
        }
        assert!(
            attempts < 4096,
            "bounded pressure fill did not exhaust tablespace"
        );
    };
    assert_eq!(
        sqlstate.as_deref(),
        Some("53100"),
        "expected disk-full tablespace error"
    );
    let failed = Uuid::now_v7();
    let store_error = store
        .insert_resource(&ResourceRecord {
            id: failed,
            kind: "pressure-failed".into(),
            project_id: project.clone(),
            generation: 1,
            observed_generation: 1,
            desired_state: "{}".into(),
            observed_state: "ACTIVE".into(),
            provider_id: None,
        })
        .await
        .expect_err("canonical write must fail under tablespace pressure");
    let rendered = store_error.to_string();
    assert!(!rendered.contains(&url), "store error leaked database URL");
    assert!(rendered.len() <= 512, "store error is unbounded");
    assert!(
        store
            .list_resources(&project, "pressure-failed")
            .await
            .expect("failed lookup")
            .iter()
            .all(|row| row.id != failed)
    );
    assert!(
        store
            .list_resources(&project, "pressure-baseline")
            .await
            .expect("baseline lookup")
            .iter()
            .any(|row| row.id == baseline)
    );
    let baseline_operation_after = store
        .get_operation(baseline_operation)
        .await
        .expect("baseline operation lookup");
    assert_eq!(baseline_operation_after.resource_id, baseline);
    assert_eq!(baseline_operation_after.state, OperationState::Succeeded);
    assert_eq!(baseline_operation_after.kind, "pressure:baseline");

    sqlx::query(&format!("DROP TABLE {}", ident(&filler)))
        .execute(&mut admin)
        .await
        .expect("drop filler");
    sqlx::query("ALTER TABLE resources SET TABLESPACE pg_default")
        .execute(&mut admin)
        .await
        .expect("restore resource tablespace");
    sqlx::query(&format!("DROP TABLESPACE {}", ident(&ts)))
        .execute(&mut admin)
        .await
        .expect("drop tablespace");
    let recovered = Uuid::now_v7();
    store
        .insert_resource(&ResourceRecord {
            id: recovered,
            kind: "pressure-recovered".into(),
            project_id: project,
            generation: 1,
            observed_generation: 1,
            desired_state: "{}".into(),
            observed_state: "ACTIVE".into(),
            provider_id: None,
        })
        .await
        .expect("retry after pressure recovery");
    let evidence = json!({"schema":"o3k.pp6.postgres-tablespace-pressure.v1","source_sha":source_sha,"source_tree":source_tree,"execution_sha":execution_sha,"execution_tree":execution_tree,"database":db,"tablespace":ts,"attempts":attempts,"sqlstate":sqlstate,"baseline_resource":baseline,"baseline_operation":baseline_operation,"failed_resource_absent":true,"recovered_resource":recovered,"cleanup":"PASS","wal_pressure_claimed":false});
    fs::write(
        artifact,
        serde_json::to_vec_pretty(&evidence).expect("evidence json"),
    )
    .expect("evidence");
}
