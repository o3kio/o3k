#![allow(clippy::expect_used, clippy::panic)]

use std::{env, str::FromStr};

use o3k_store::{
    DurableStore, OperationRecord, OperationState, PostgresStore, ResourceRecord, StoreError,
};
use uuid::Uuid;

fn required_uuid(name: &str) -> Uuid {
    Uuid::from_str(&env::var(name).unwrap_or_else(|_| panic!("{name} is required")))
        .unwrap_or_else(|_| panic!("{name} must be a UUID"))
}

fn baseline_resource(id: Uuid) -> ResourceRecord {
    ResourceRecord {
        id,
        kind: "pp6_wal_pressure_probe".to_owned(),
        project_id: "pp6-wal-pressure-run".to_owned(),
        generation: 1,
        observed_generation: 1,
        desired_state: "ACTIVE".to_owned(),
        observed_state: "ACTIVE".to_owned(),
        provider_id: None,
    }
}

fn bounded_pressure_payload(seed: u32) -> String {
    let mut state = seed.wrapping_add(1);
    let mut payload = String::with_capacity(2_200);
    for _ in 0..2_200 {
        state = state.wrapping_mul(1_664_525).wrapping_add(1_013_904_223);
        payload.push(char::from(b'!' + ((state >> 24) % 94) as u8));
    }
    payload
}

#[tokio::test]
#[ignore = "requires the mandatory disposable PostgreSQL WAL pressure harness"]
async fn postgres_wal_pressure_and_restart_recovery() {
    let phase = env::var("O3K_PG_WAL_PHASE").expect("O3K_PG_WAL_PHASE is required");
    let database_url = env::var("O3K_DATABASE_URL").expect("O3K_DATABASE_URL is required");
    let resource_id = required_uuid("O3K_PG_WAL_RESOURCE_ID");
    let operation_id = required_uuid("O3K_PG_WAL_OPERATION_ID");
    let store = PostgresStore::connect(&database_url)
        .await
        .expect("connect and migrate isolated PostgreSQL store");

    match phase.as_str() {
        "setup" => {
            store
                .insert_resource(&baseline_resource(resource_id))
                .await
                .expect("persist baseline resource before WAL pressure");
            store
                .insert_operation(&OperationRecord {
                    id: operation_id,
                    resource_id,
                    kind: "pp6:wal-pressure-baseline".to_owned(),
                    state: OperationState::Succeeded,
                    provider_operation_id: None,
                    error_category: None,
                    error_message: None,
                })
                .await
                .expect("persist baseline operation before WAL pressure");
        }
        "pressure" => {
            let max_rows = env::var("O3K_PG_WAL_MAX_ROWS")
                .expect("O3K_PG_WAL_MAX_ROWS is required")
                .parse::<u32>()
                .expect("O3K_PG_WAL_MAX_ROWS must be an integer");
            assert!((1..=12_000).contains(&max_rows), "row bound is invalid");
            for index in 0..max_rows {
                let resource = ResourceRecord {
                    id: Uuid::new_v4(),
                    kind: bounded_pressure_payload(index),
                    project_id: "pp6-wal-pressure-run".to_owned(),
                    generation: 1,
                    observed_generation: 1,
                    desired_state: "ACTIVE".to_owned(),
                    observed_state: "ACTIVE".to_owned(),
                    provider_id: None,
                };
                match store.insert_resource(&resource).await {
                    Ok(()) => {}
                    Err(StoreError::Database(sqlx::Error::Database(database_error))) => {
                        let code = database_error.code();
                        assert_eq!(
                            code.as_deref(),
                            Some("53100"),
                            "expected PostgreSQL disk-full SQLSTATE"
                        );
                        eprintln!(
                            "WAL pressure stopped after PostgreSQL SQLSTATE 53100; successful_rows={index}"
                        );
                        return;
                    }
                    Err(error) => panic!("unexpected store error during WAL pressure: {error}"),
                }
            }
            panic!("bounded WAL workload completed without database failure");
        }
        "recovery" => {
            let recovered = store
                .get_resource(resource_id)
                .await
                .expect("read baseline resource after PostgreSQL restart");
            assert_eq!(recovered, baseline_resource(resource_id));
            let operation = store
                .get_operation(operation_id)
                .await
                .expect("read baseline operation after PostgreSQL restart");
            assert_eq!(operation.resource_id, resource_id);
            assert_eq!(operation.state, OperationState::Succeeded);
            let in_recovery: bool = sqlx::query_scalar("SELECT pg_is_in_recovery()")
                .fetch_one(store.pool())
                .await
                .expect("observe PostgreSQL recovery state");
            assert!(!in_recovery, "primary did not leave recovery");

            let after_restart = ResourceRecord {
                id: required_uuid("O3K_PG_WAL_POST_RESTART_RESOURCE_ID"),
                kind: "pp6_wal_pressure_post_restart_probe".to_owned(),
                project_id: "pp6-wal-pressure-run".to_owned(),
                generation: 1,
                observed_generation: 1,
                desired_state: "ACTIVE".to_owned(),
                observed_state: "ACTIVE".to_owned(),
                provider_id: None,
            };
            store
                .insert_resource(&after_restart)
                .await
                .expect("write canonical state after recovery");
            let observed = store
                .get_resource(after_restart.id)
                .await
                .expect("read canonical write after recovery");
            assert_eq!(observed, after_restart);
        }
        _ => panic!("O3K_PG_WAL_PHASE must be setup, pressure, or recovery"),
    }
}
