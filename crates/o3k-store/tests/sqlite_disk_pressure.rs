#![allow(clippy::expect_used, clippy::unwrap_used)]

use std::{
    error::Error,
    fs,
    io::Write,
    path::{Path, PathBuf},
    time::Instant,
};

use o3k_store::{
    DurableStore, OperationRecord, OperationState, ResourceRecord, StoreError, testkit,
};
use sqlx::{sqlite::SqliteConnectOptions, sqlite::SqlitePoolOptions};
use uuid::Uuid;

const MAX_INSERT_ATTEMPTS: usize = 20_000;
const MAX_PRESSURE_SECONDS: u64 = 90;
const STATE_BYTES: usize = 4 * 1024;

#[tokio::test]
#[ignore = "requires the isolated ext4 loopback harness in tests/sqlite-disk-pressure.sh"]
async fn sqlite_store_fails_atomically_when_real_wal_filesystem_is_full()
-> Result<(), Box<dyn Error>> {
    let root = PathBuf::from(std::env::var("O3K_SQLITE_PRESSURE_ROOT")?);
    let evidence_path = PathBuf::from(std::env::var("O3K_SQLITE_PRESSURE_EVIDENCE_PATH")?);
    if !root.is_absolute() || !evidence_path.is_absolute() {
        return Err("pressure and evidence paths must be absolute".into());
    }
    verify_pressure_mount(&root)?;
    verify_evidence_path(&evidence_path)?;

    let database_path = root.join("o3k-pressure.sqlite3");
    let store = testkit::open_file(&database_path).await?;
    assert_eq!(store.journal_mode().await?, "wal");

    let baseline_resource = ResourceRecord {
        id: Uuid::now_v7(),
        kind: "compute:server".to_owned(),
        project_id: "pp6-pressure-project".to_owned(),
        generation: 1,
        observed_generation: 0,
        desired_state: "ACTIVE".to_owned(),
        observed_state: "UNKNOWN".to_owned(),
        provider_id: None,
    };
    let baseline_operation = OperationRecord {
        id: Uuid::now_v7(),
        resource_id: baseline_resource.id,
        kind: "compute:create".to_owned(),
        state: OperationState::Running,
        provider_operation_id: None,
        error_category: None,
        error_message: None,
    };
    store.insert_resource(&baseline_resource).await?;
    store.insert_operation(&baseline_operation).await?;

    // Pin a real WAL snapshot so automatic checkpoints cannot recycle the WAL
    // while the production store performs bounded autocommit writes.
    let reader_options = SqliteConnectOptions::new()
        .filename(&database_path)
        .create_if_missing(false);
    let reader = SqlitePoolOptions::new()
        .max_connections(1)
        .connect_with(reader_options)
        .await?;
    let mut snapshot = reader.begin().await?;
    let _: i64 = sqlx::query_scalar("SELECT COUNT(*) FROM resources")
        .fetch_one(&mut *snapshot)
        .await?;

    let desired_state = format!(
        "{{\"state\":\"requested\",\"bounded_note\":\"{}\"}}",
        "x".repeat(STATE_BYTES)
    );
    let started = Instant::now();
    let mut attempted_id = None;
    let mut pressure_error = None;
    let mut inserts_before_pressure = 0usize;

    for attempt in 0..MAX_INSERT_ATTEMPTS {
        if started.elapsed().as_secs() >= MAX_PRESSURE_SECONDS {
            return Err(format!(
                "filesystem pressure was not reached within {MAX_PRESSURE_SECONDS}s"
            )
            .into());
        }
        let candidate = ResourceRecord {
            id: Uuid::now_v7(),
            kind: "compute:server".to_owned(),
            project_id: "pp6-pressure-project".to_owned(),
            generation: 1,
            observed_generation: 0,
            desired_state: desired_state.clone(),
            observed_state: "UNKNOWN".to_owned(),
            provider_id: None,
        };
        attempted_id = Some(candidate.id);
        match store.insert_resource(&candidate).await {
            Ok(()) => inserts_before_pressure = attempt + 1,
            Err(error) => match sqlite_full_details(&error) {
                Some(details) => {
                    pressure_error = Some(details);
                    break;
                }
                None => return Err(format!("unexpected SQLite pressure error: {error}").into()),
            },
        }
    }

    let attempted_id = attempted_id.ok_or("pressure loop made no writes")?;
    let pressure_error = pressure_error.ok_or_else(|| {
        format!("SQLite did not report SQLITE_FULL in {MAX_INSERT_ATTEMPTS} bounded writes")
    })?;

    assert_eq!(
        store.get_resource(baseline_resource.id).await?,
        baseline_resource
    );
    assert_eq!(
        store.get_operation(baseline_operation.id).await?,
        baseline_operation
    );
    assert!(matches!(
        store.get_resource(attempted_id).await,
        Err(StoreError::ResourceNotFound)
    ));

    snapshot.rollback().await?;
    reader.close().await;
    drop(store);

    // Reopening through the production adapter proves recovery of the actual
    // database/WAL pair and runs the adapter's normal integrity validation.
    let reopened = testkit::open_file(&database_path).await?;
    assert_eq!(
        reopened.get_resource(baseline_resource.id).await?,
        baseline_resource
    );
    assert_eq!(
        reopened.get_operation(baseline_operation.id).await?,
        baseline_operation
    );
    assert!(matches!(
        reopened.get_resource(attempted_id).await,
        Err(StoreError::ResourceNotFound)
    ));
    let diagnostic_pool = SqlitePoolOptions::new()
        .max_connections(1)
        .connect_with(
            SqliteConnectOptions::new()
                .filename(&database_path)
                .read_only(true)
                .create_if_missing(false),
        )
        .await?;
    let integrity: String = sqlx::query_scalar("PRAGMA integrity_check")
        .fetch_one(&diagnostic_pool)
        .await?;
    assert_eq!(integrity, "ok");
    let foreign_key_violations: i64 =
        sqlx::query_scalar("SELECT COUNT(*) FROM pragma_foreign_key_check")
            .fetch_one(&diagnostic_pool)
            .await?;
    assert_eq!(foreign_key_violations, 0);
    let sqlite_version: String = sqlx::query_scalar("SELECT sqlite_version()")
        .fetch_one(&diagnostic_pool)
        .await?;
    let migration_count: i64 = sqlx::query_scalar("SELECT COUNT(*) FROM _sqlx_migrations")
        .fetch_one(&diagnostic_pool)
        .await?;
    let latest_migration: i64 = sqlx::query_scalar("SELECT MAX(version) FROM _sqlx_migrations")
        .fetch_one(&diagnostic_pool)
        .await?;
    diagnostic_pool.close().await;

    let evidence = serde_json::json!({
        "disposition": "PASS",
        "test": "o3k-store::sqlite_store_fails_atomically_when_real_wal_filesystem_is_full",
        "source_commit": std::env::var("O3K_SQLITE_PRESSURE_SOURCE_COMMIT")?,
        "source_tree": std::env::var("O3K_SQLITE_PRESSURE_SOURCE_TREE")?,
        "execution_commit": std::env::var("O3K_SQLITE_PRESSURE_EXECUTION_COMMIT")?,
        "execution_tree": std::env::var("O3K_SQLITE_PRESSURE_EXECUTION_TREE")?,
        "os": std::env::var("O3K_SQLITE_PRESSURE_OS")?,
        "filesystem_type": std::env::var("O3K_SQLITE_PRESSURE_FS_TYPE")?,
        "filesystem_size_bytes": std::env::var("O3K_SQLITE_PRESSURE_FS_SIZE_BYTES")?,
        "filesystem_source": std::env::var("O3K_SQLITE_PRESSURE_FS_SOURCE")?,
        "profile": "SPEC-0024 bounded Small Edge/TestLab SQLite profile",
        "evidence_tier": "real isolated SQLite integration",
        "migration_count": migration_count,
        "latest_migration": latest_migration,
        "sqlite_version": sqlite_version,
        "sqlx_version": std::env::var("O3K_SQLITE_PRESSURE_SQLX_VERSION")?,
        "journal_mode": reopened.journal_mode().await?,
        "injection": "actual ext4 ENOSPC while a second connection pins a WAL snapshot",
        "inserts_before_pressure": inserts_before_pressure,
        "max_insert_attempts": MAX_INSERT_ATTEMPTS,
        "max_pressure_seconds": MAX_PRESSURE_SECONDS,
        "state_bytes_per_insert": STATE_BYTES,
        "failed_resource_id_absent": true,
        "baseline_resource_and_operation_unchanged": true,
        "integrity_check": integrity,
        "observed_error": pressure_error,
        "foreign_state_mutated": false,
        "cleanup": "harness-managed isolated mount and loopback image; awaiting harness confirmation"
    });
    let mut evidence_file = fs::OpenOptions::new()
        .write(true)
        .create_new(true)
        .open(&evidence_path)?;
    evidence_file.write_all(&serde_json::to_vec_pretty(&evidence)?)?;
    println!(
        "PP6_SQLITE_PRESSURE_EVIDENCE={}",
        serde_json::to_string(&evidence)?
    );
    Ok(())
}

fn verify_pressure_mount(root: &Path) -> Result<(), Box<dyn Error>> {
    let canonical_root = fs::canonicalize(root)?;
    if canonical_root != root {
        return Err("pressure root must be the canonical mount directory".into());
    }
    let expected_source = std::env::var("O3K_SQLITE_PRESSURE_FS_SOURCE")?;
    let token = std::env::var("O3K_SQLITE_PRESSURE_HARNESS_TOKEN")?;
    let marker = fs::read_to_string(root.join(".o3k-sqlite-pressure-harness"))?;
    if marker.trim() != token || !expected_source.starts_with("/dev/loop") {
        return Err("pressure root lacks the expected isolated mount marker".into());
    }

    let mountinfo = fs::read_to_string("/proc/self/mountinfo")?;
    let root_text = root.to_string_lossy();
    let matched_mount = mountinfo.lines().any(|line| {
        let Some((before, after)) = line.split_once(" - ") else {
            return false;
        };
        let mount_fields: Vec<_> = before.split_whitespace().collect();
        let filesystem_fields: Vec<_> = after.split_whitespace().collect();
        mount_fields.get(4).is_some_and(|mount_point| {
            mount_point.replace("\\040", " ") == root_text
                && filesystem_fields.first() == Some(&"ext4")
                && filesystem_fields.get(1) == Some(&expected_source.as_str())
        })
    });
    if !matched_mount {
        return Err("pressure root is not the expected mounted ext4 loopback filesystem".into());
    }
    Ok(())
}

fn verify_evidence_path(path: &Path) -> Result<(), Box<dyn Error>> {
    let allowed_directory = fs::canonicalize(std::env::var("RUNNER_TEMP")?)?;
    let parent = path.parent().ok_or("evidence path has no parent")?;
    if fs::canonicalize(parent)? != allowed_directory
        || path.file_name().and_then(|name| name.to_str()) != Some("pp6-sqlite-disk-pressure.json")
        || fs::symlink_metadata(path).is_ok()
    {
        return Err("evidence path must be a new runner-temp file with the expected name".into());
    }
    Ok(())
}

fn sqlite_full_details(error: &StoreError) -> Option<serde_json::Value> {
    match error {
        StoreError::Database(sqlx::Error::Database(database)) => {
            let code = database.code().map(|code| code.into_owned());
            let message = database.message().to_owned();
            if code.as_deref() == Some("13")
                || message
                    .to_ascii_lowercase()
                    .contains("database or disk is full")
            {
                Some(serde_json::json!({
                    "category": "SQLITE_FULL",
                    "code": code,
                    "message": message
                }))
            } else {
                None
            }
        }
        _ => None,
    }
}
