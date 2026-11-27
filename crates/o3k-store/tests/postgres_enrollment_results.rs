#![allow(clippy::expect_used, clippy::unwrap_used)]

use o3k_store::{EnrollmentGrantRecord, EnrollmentResultRecord, PostgresStore};
use sqlx::postgres::PgPoolOptions;

#[tokio::test]
async fn postgres_enrollment_issue_is_atomic_retryable_and_token_bound() {
    let Some(url) = std::env::var("O3K_DATABASE_URL").ok() else {
        eprintln!("skipping PostgreSQL enrollment result test: O3K_DATABASE_URL unavailable");
        return;
    };
    let mut parsed = url::Url::parse(&url).expect("valid PostgreSQL URL");
    let database = format!("o3k_enrollment_{}", uuid::Uuid::now_v7().simple());
    let mut admin_url = parsed.clone();
    admin_url.set_path("/postgres");
    let admin = PgPoolOptions::new()
        .max_connections(1)
        .connect(admin_url.as_str())
        .await
        .expect("connect to PostgreSQL admin database");
    sqlx::query(&format!("CREATE DATABASE {database}"))
        .execute(&admin)
        .await
        .expect("create isolated enrollment database");
    admin.close().await;
    parsed.set_path(&format!("/{database}"));
    let isolated_url = parsed.to_string();
    let store = PostgresStore::connect(&isolated_url)
        .await
        .expect("migrate isolated PostgreSQL database");

    // Model a database created immediately before the enrollment additions.
    // The workload below then proves the repository's normal startup path
    // applies both additive migrations while keeping the original grant
    // table and its contents available.
    sqlx::query("DROP TABLE enrollment_results")
        .execute(store.pool())
        .await
        .expect("remove the newly added result table from the disposable database");
    sqlx::query("ALTER TABLE enrollment_grants DROP COLUMN agent_epoch")
        .execute(store.pool())
        .await
        .expect("restore the pre-epoch grant schema");
    sqlx::query("DELETE FROM _sqlx_migrations WHERE version IN (37, 38)")
        .execute(store.pool())
        .await
        .expect("restore the pre-enrollment migration ledger");
    store.pool().close().await;
    let store = PostgresStore::connect(&isolated_url)
        .await
        .expect("upgrade the pre-enrollment PostgreSQL database");

    let grant = EnrollmentGrantRecord {
        grant_id: "grant-enrollment-test".into(),
        agent_id: "*".into(),
        agent_epoch: String::new(),
        token_digest: "token-digest".into(),
        issued_at_unix_ms: 10,
        expires_at_unix_ms: 100,
        used_at_unix_ms: None,
    };
    store.insert_enrollment_grant(&grant).await.unwrap();
    let result = EnrollmentResultRecord {
        grant_id: grant.grant_id.clone(),
        agent_id: "node-1".into(),
        agent_epoch: "epoch-1".into(),
        token_digest: grant.token_digest.clone(),
        csr_sha256: "csr-digest".into(),
        certificate_fingerprint_sha256: "cert-fingerprint".into(),
        client_certificate_chain_pem: "public-cert-chain".into(),
        ca_certificate_pem: "public-ca-cert".into(),
        ca_fingerprint_sha256: "ca-fingerprint".into(),
        certificate_expires_at_unix_ms: 1_000,
        rotation_deadline_unix_ms: 900,
        issued_at_unix_ms: 20,
        registered_at_unix_ms: None,
    };
    assert_eq!(
        store.complete_enrollment_issue(&result, 20).await.unwrap(),
        result
    );
    assert_eq!(
        store.complete_enrollment_issue(&result, 21).await.unwrap(),
        result
    );
    assert!(
        store
            .consume_enrollment_result(
                &grant.grant_id,
                "wrong-token",
                "node-1",
                "epoch-1",
                "cert-fingerprint",
                30,
            )
            .await
            .is_err()
    );
    assert_eq!(
        store
            .consume_enrollment_result(
                &grant.grant_id,
                &grant.token_digest,
                "node-1",
                "epoch-1",
                "cert-fingerprint",
                30,
            )
            .await
            .unwrap()
            .registered_at_unix_ms,
        Some(30)
    );

    store.pool().close().await;
    let admin = PgPoolOptions::new()
        .max_connections(1)
        .connect(admin_url.as_str())
        .await
        .expect("reconnect to PostgreSQL admin database");
    sqlx::query(
        "SELECT pg_terminate_backend(pid) FROM pg_stat_activity \
         WHERE datname = $1 AND pid <> pg_backend_pid()",
    )
    .bind(&database)
    .execute(&admin)
    .await
    .expect("terminate isolated database backends");
    sqlx::query(&format!("DROP DATABASE {database}"))
        .execute(&admin)
        .await
        .expect("drop isolated enrollment database");
    admin.close().await;
}
