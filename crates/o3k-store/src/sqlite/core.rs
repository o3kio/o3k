use super::{
    SqliteStore,
    helpers::{
        agent_command_from_row, ensure_image_overlay_identity, image_overlay_from_row,
        image_overlay_identity_matches, operation_from_row, parse_uuid, resource_from_row,
        sqlite_sequence, validate_base_identity, validate_image_overlay,
        validate_image_overlay_identity, validate_image_overlay_transition,
    },
};
use async_trait::async_trait;
use chrono::Utc;
use sqlx::{
    Row, SqlitePool,
    sqlite::{
        SqliteConnectOptions, SqliteJournalMode, SqlitePoolOptions, SqliteRow, SqliteSynchronous,
    },
};
#[cfg(unix)]
use std::os::unix::fs::PermissionsExt;
use std::{fs, path::Path, str::FromStr, sync::Arc, time::Duration};
use uuid::Uuid;

use crate::StoredIdempotencyReservation;
use crate::{
    AgentCommandRecord, AgentCommandState, ArtifactTransferRecord, ArtifactTransferUpdate,
    CanonicalAcceptanceOutcome, CanonicalOperationLifecycleUpdate, CanonicalOperationRecord,
    ComputeRepository, DatabaseHealth, DurableStore, IdempotencyReservation,
    IdempotencyReservationRequest, ImageOverlayIdentity, ImageOverlayOwnershipRecord,
    ImageOverlayState, ImageOverlayUpdate, LifecycleTerminalization, ObservationUpdate,
    OperationRecord, OperationState, ProviderReference, RepositoryPage, ResourceRecord,
    SQLITE_BUSY_MAX_ATTEMPTS, StoreError, VolumeAttachmentRecord, WalCheckpointMode,
    is_sqlite_busy, restrict_sqlite_sidecars, validate_canonical_idempotent_operation_identity,
    validate_canonical_lifecycle_update, validate_canonical_operation_read,
    validate_canonical_resource_acceptance, validate_canonical_scoped_operation_read,
};

pub(super) async fn insert_sqlite_canonical_acceptance(
    connection: &mut sqlx::pool::PoolConnection<sqlx::Sqlite>,
    operation: &OperationRecord,
    canonical: &CanonicalOperationRecord,
    request: &IdempotencyReservationRequest,
) -> Result<(), StoreError> {
    sqlx::query("INSERT INTO operations (id,resource_id,kind,state,provider_operation_id,error_category,error_message) VALUES (?,?,?,?,?,?,?)")
        .bind(operation.id.to_string()).bind(operation.resource_id.to_string()).bind(&operation.kind)
        .bind(operation.state.as_str()).bind(&operation.provider_operation_id).bind(&operation.error_category)
        .bind(&operation.error_message).execute(&mut **connection).await.map_err(StoreError::Database)?;
    sqlx::query("INSERT INTO canonical_operation_metadata (operation_id,service,action,actor,owner_scope,resource_type,resource_id,attempt,created_at,started_at,finished_at,error,request_id) VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?)")
        .bind(canonical.id.to_string()).bind(&canonical.service).bind(&canonical.action).bind(&canonical.actor)
        .bind(&canonical.owner_scope).bind(&canonical.resource_type).bind(&canonical.resource_id)
        .bind(i64::from(canonical.attempt)).bind(&canonical.created_at).bind(&canonical.started_at)
        .bind(&canonical.finished_at).bind(&canonical.error).bind(&canonical.request_id)
        .execute(&mut **connection).await.map_err(StoreError::Database)?;
    sqlx::query("INSERT INTO idempotency_reservations (owner_scope,action,idempotency_key,fingerprint,operation_id) VALUES (?,?,?,?,?)")
        .bind(&request.owner_scope).bind(&request.action).bind(&request.key).bind(&request.fingerprint)
        .bind(request.operation_id.to_string()).execute(&mut **connection).await.map_err(StoreError::Database)?;
    Ok(())
}

/// Rebuilds `operations` without the historical generic-resource foreign key.
///
/// SQLx 0.8.6's SQLite migrator always wraps migration SQL in a transaction,
/// including migrations prefixed with `-- no-transaction`. SQLite refuses to
/// change `foreign_keys` while a transaction is active, so this rebuild is
/// coordinated here on one acquired connection. The connection is obtained
/// before the store is exposed to callers, and `BEGIN IMMEDIATE` prevents
/// concurrent writers while the rebuild runs.
pub(super) async fn migrate_operation_resource_scope(pool: &SqlitePool) -> Result<(), StoreError> {
    let mut connection = pool.acquire().await.map_err(StoreError::Database)?;
    let has_operations: i64 = sqlx::query_scalar(
        "SELECT COUNT(*) FROM sqlite_master WHERE type = 'table' AND name = 'operations'",
    )
    .fetch_one(&mut *connection)
    .await
    .map_err(StoreError::Database)?;
    if has_operations == 0 {
        return Ok(());
    }

    let has_resource_fk: i64 = sqlx::query_scalar(
        "SELECT COUNT(*) FROM pragma_foreign_key_list('operations')\
         WHERE \"table\" = 'resources' AND \"from\" = 'resource_id'",
    )
    .fetch_one(&mut *connection)
    .await
    .map_err(StoreError::Database)?;

    if has_resource_fk == 0 {
        sqlx::query(
            r#"CREATE TRIGGER IF NOT EXISTS resources_delete_generic_operations
                AFTER DELETE ON resources
                BEGIN
                    DELETE FROM operations
                    WHERE resource_id = OLD.id
                      AND NOT EXISTS (
                          SELECT 1 FROM canonical_operation_metadata metadata
                          WHERE metadata.operation_id = operations.id
                            AND metadata.resource_type IN ('network:network', 'network:address_realm')
                      );
                END"#,
        )
        .execute(&mut *connection)
        .await
        .map_err(StoreError::Database)?;
        sqlx::query(
            r#"CREATE TRIGGER IF NOT EXISTS operations_validate_resource_reference
                BEFORE INSERT ON operations
                BEGIN
                    SELECT RAISE(ABORT, 'operation resource not found')
                    WHERE NOT EXISTS (SELECT 1 FROM resources WHERE id = NEW.resource_id)
                      AND NOT EXISTS (SELECT 1 FROM canonical_networks WHERE id = NEW.resource_id)
                      AND NOT EXISTS (SELECT 1 FROM canonical_address_realms WHERE id = NEW.resource_id);
                END"#,
        )
        .execute(&mut *connection)
        .await
        .map_err(StoreError::Database)?;
        return Ok(());
    }

    sqlx::query("PRAGMA foreign_keys = OFF")
        .execute(&mut *connection)
        .await
        .map_err(StoreError::Database)?;
    let foreign_keys_off: i64 = sqlx::query_scalar("PRAGMA foreign_keys")
        .fetch_one(&mut *connection)
        .await
        .map_err(StoreError::Database)?;
    if foreign_keys_off != 0 {
        let _ = sqlx::query("PRAGMA foreign_keys = ON")
            .execute(&mut *connection)
            .await;
        return Err(StoreError::Corrupt(
            "SQLite foreign-key enforcement could not be disabled for operation migration"
                .to_owned(),
        ));
    }

    let rebuild = async {
        sqlx::query("BEGIN IMMEDIATE")
            .execute(&mut *connection)
            .await
            .map_err(StoreError::Database)?;
        sqlx::query(
            r#"CREATE TABLE operations_without_resource_fk (
                id TEXT PRIMARY KEY NOT NULL,
                resource_id TEXT NOT NULL,
                kind TEXT NOT NULL DEFAULT 'create',
                state TEXT NOT NULL,
                provider_operation_id TEXT,
                error_category TEXT,
                error_message TEXT,
                created_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP
            )"#,
        )
        .execute(&mut *connection)
        .await
        .map_err(StoreError::Database)?;
        sqlx::query(
            r#"INSERT INTO operations_without_resource_fk
                (id, resource_id, kind, state, provider_operation_id, error_category, error_message, created_at)
                SELECT id, resource_id, kind, state, provider_operation_id, error_category, error_message, created_at
                FROM operations"#,
        )
        .execute(&mut *connection)
        .await
        .map_err(StoreError::Database)?;
        sqlx::query("DROP TABLE operations")
            .execute(&mut *connection)
            .await
            .map_err(StoreError::Database)?;
        sqlx::query("ALTER TABLE operations_without_resource_fk RENAME TO operations")
            .execute(&mut *connection)
            .await
            .map_err(StoreError::Database)?;
        sqlx::query("CREATE INDEX operations_resource_idx ON operations(resource_id)")
            .execute(&mut *connection)
            .await
            .map_err(StoreError::Database)?;
        sqlx::query(
            r#"CREATE TRIGGER resources_delete_generic_operations
                AFTER DELETE ON resources
                BEGIN
                    DELETE FROM operations
                    WHERE resource_id = OLD.id
                      AND NOT EXISTS (
                          SELECT 1 FROM canonical_operation_metadata metadata
                          WHERE metadata.operation_id = operations.id
                            AND metadata.resource_type IN ('network:network', 'network:address_realm')
                      );
                END"#,
        )
        .execute(&mut *connection)
        .await
        .map_err(StoreError::Database)?;
        let foreign_key_violations: i64 =
            sqlx::query_scalar("SELECT COUNT(*) FROM pragma_foreign_key_check")
                .fetch_one(&mut *connection)
                .await
                .map_err(StoreError::Database)?;
        if foreign_key_violations != 0 {
            return Err(StoreError::Corrupt(
                "SQLite foreign-key check failed after operation migration".to_owned(),
            ));
        }
        let integrity: String = sqlx::query_scalar("PRAGMA integrity_check")
            .fetch_one(&mut *connection)
            .await
            .map_err(StoreError::Database)?;
        sqlx::query(
            r#"CREATE TRIGGER operations_validate_resource_reference
                BEFORE INSERT ON operations
                BEGIN
                    SELECT RAISE(ABORT, 'operation resource not found')
                    WHERE NOT EXISTS (SELECT 1 FROM resources WHERE id = NEW.resource_id)
                      AND NOT EXISTS (SELECT 1 FROM canonical_networks WHERE id = NEW.resource_id)
                      AND NOT EXISTS (SELECT 1 FROM canonical_address_realms WHERE id = NEW.resource_id);
                END"#,
        )
        .execute(&mut *connection)
        .await
        .map_err(StoreError::Database)?;
        if !integrity.eq_ignore_ascii_case("ok") {
            return Err(StoreError::Corrupt(format!(
                "SQLite integrity check failed after operation migration: {integrity}"
            )));
        }
        sqlx::query("COMMIT")
            .execute(&mut *connection)
            .await
            .map(|_| ())
            .map_err(StoreError::Database)
    }
    .await;

    if rebuild.is_err() {
        let _ = sqlx::query("ROLLBACK").execute(&mut *connection).await;
    }
    let restore = sqlx::query("PRAGMA foreign_keys = ON")
        .execute(&mut *connection)
        .await
        .map(|_| ())
        .map_err(StoreError::Database);
    match (rebuild, restore) {
        (Err(error), _) => Err(error),
        (Ok(()), Err(error)) => Err(error),
        (Ok(()), Ok(())) => Ok(()),
    }
}

/// Accepts the exact released pre-redesign 0037 checksum so the controlled
/// SQLite rebuild below can migrate that database before normal use. No other
/// checksum is normalized; SQLx remains the authority for all unrelated
/// migration tampering or drift.
async fn normalize_legacy_operation_migration_checksum(
    pool: &SqlitePool,
) -> Result<(), StoreError> {
    const APPROVED_LEGACY_CHECKSUM: [u8; 48] = [
        0x89, 0xe6, 0x76, 0x54, 0xcd, 0x55, 0xd6, 0xc7, 0xaf, 0xbf, 0x46, 0x1c, 0x10, 0x46, 0x82,
        0xa9, 0xda, 0x1a, 0x20, 0xee, 0x6e, 0x56, 0x40, 0x8a, 0x29, 0x37, 0x45, 0xe0, 0x3a, 0xbf,
        0x2a, 0x66, 0x73, 0x24, 0x4f, 0xc2, 0x64, 0xe6, 0x67, 0x40, 0xbb, 0x1d, 0x8e, 0xcf, 0x13,
        0x93, 0x33, 0xd6,
    ];
    let migration_table: i64 = sqlx::query_scalar(
        "SELECT COUNT(*) FROM sqlite_master WHERE type = 'table' AND name = '_sqlx_migrations'",
    )
    .fetch_one(pool)
    .await
    .map_err(StoreError::Database)?;
    if migration_table == 0 {
        return Ok(());
    }
    let Some(expected) = sqlx::migrate!()
        .iter()
        .find(|migration| migration.version == 37)
    else {
        return Ok(());
    };
    let Some(recorded): Option<Vec<u8>> =
        sqlx::query_scalar("SELECT checksum FROM _sqlx_migrations WHERE version = 37")
            .fetch_optional(pool)
            .await
            .map_err(StoreError::Database)?
    else {
        return Ok(());
    };
    if recorded == expected.checksum.as_ref() {
        return Ok(());
    }
    if recorded.as_slice() != APPROVED_LEGACY_CHECKSUM {
        return Ok(());
    }
    sqlx::query("UPDATE _sqlx_migrations SET checksum = ? WHERE version = 37")
        .bind(expected.checksum.as_ref())
        .execute(pool)
        .await
        .map_err(StoreError::Database)?;
    Ok(())
}

pub(super) async fn update_agent_command_once_sqlite(
    store: &SqliteStore,
    command_id: &str,
    state: AgentCommandState,
    accepted_sequence: u64,
    last_sequence: u64,
    provider_operation_id: Option<&str>,
    provider_resource_id: Option<&str>,
) -> Result<AgentCommandRecord, StoreError> {
    let _projection_guard = store.agent_command_projection_lock.lock().await;
    let mut transaction = store.pool.begin().await.map_err(StoreError::Database)?;
    let row = sqlx::query("SELECT command_id, idempotency_key, operation_id, resource_id, agent_id, agent_epoch, payload_fingerprint_sha256, payload, state, accepted_sequence, last_sequence, provider_operation_id, provider_resource_id FROM agent_commands WHERE command_id = ?")
        .bind(command_id)
        .fetch_optional(&mut *transaction)
        .await
        .map_err(StoreError::Database)?
        .ok_or(StoreError::OperationNotFound)?;
    let current = agent_command_from_row(&row)?;
    if last_sequence < current.last_sequence {
        transaction.rollback().await.map_err(StoreError::Database)?;
        return Ok(current);
    }
    if last_sequence == current.last_sequence {
        if current.state == state
            && current.accepted_sequence == accepted_sequence
            && provider_operation_id
                .is_none_or(|value| current.provider_operation_id.as_deref() == Some(value))
            && provider_resource_id
                .is_none_or(|value| current.provider_resource_id.as_deref() == Some(value))
        {
            transaction.rollback().await.map_err(StoreError::Database)?;
            return Ok(current);
        }
        return Err(StoreError::Corrupt(
            "conflicting agent command evidence at one sequence".to_owned(),
        ));
    }
    if matches!(
        current.state,
        AgentCommandState::Succeeded | AgentCommandState::Failed
    ) && current.state != state
    {
        return Err(StoreError::Corrupt(
            "terminal agent command state cannot regress".to_owned(),
        ));
    }
    if current.state == AgentCommandState::UnknownOutcome
        && matches!(
            state,
            AgentCommandState::Accepted | AgentCommandState::Running
        )
    {
        return Err(StoreError::Corrupt(
            "unknown-outcome agent command cannot regress to in-flight".to_owned(),
        ));
    }
    if provider_operation_id.is_some_and(|value| {
        current
            .provider_operation_id
            .as_deref()
            .is_some_and(|existing| existing != value)
    }) || provider_resource_id.is_some_and(|value| {
        current
            .provider_resource_id
            .as_deref()
            .is_some_and(|existing| existing != value)
    }) {
        return Err(StoreError::Corrupt(
            "agent command provider identity conflicts with durable state".to_owned(),
        ));
    }
    let accepted_sequence = accepted_sequence.max(current.accepted_sequence);
    let provider_operation_id = provider_operation_id.or(current.provider_operation_id.as_deref());
    let provider_resource_id = provider_resource_id.or(current.provider_resource_id.as_deref());
    let result = sqlx::query("UPDATE agent_commands SET state = ?, accepted_sequence = ?, last_sequence = ?, provider_operation_id = ?, provider_resource_id = ?, updated_at = CURRENT_TIMESTAMP WHERE command_id = ? AND last_sequence = ?")
        .bind(state.as_str())
        .bind(sqlite_sequence(accepted_sequence)?)
        .bind(sqlite_sequence(last_sequence)?)
        .bind(provider_operation_id)
        .bind(provider_resource_id)
        .bind(command_id)
        .bind(sqlite_sequence(current.last_sequence)?)
        .execute(&mut *transaction)
        .await
        .map_err(StoreError::Database)?;
    if result.rows_affected() != 1 {
        return Err(StoreError::OperationNotFound);
    }
    transaction.commit().await.map_err(StoreError::Database)?;
    store.get_agent_command(command_id).await
}

impl SqliteStore {
    pub async fn connect(database_url: &str) -> Result<Self, StoreError> {
        let is_memory = database_url == "sqlite::memory:" || database_url == "sqlite://:memory:";
        let mut options =
            SqliteConnectOptions::from_str(database_url).map_err(StoreError::Database)?;
        let max_connections = if is_memory { 1 } else { 5 };

        options = options
            .create_if_missing(true)
            .foreign_keys(true)
            .busy_timeout(Duration::from_secs(5));

        if !is_memory {
            options = options
                .journal_mode(SqliteJournalMode::Wal)
                .synchronous(SqliteSynchronous::Normal);
        }

        let pool = SqlitePoolOptions::new()
            .max_connections(max_connections)
            .acquire_timeout(Duration::from_secs(5))
            .connect_with(options)
            .await
            .map_err(StoreError::Database)?;

        normalize_legacy_operation_migration_checksum(&pool).await?;
        sqlx::migrate!()
            .run(&pool)
            .await
            .map_err(StoreError::Migration)?;
        migrate_operation_resource_scope(&pool).await?;

        let store = Self {
            pool,
            agent_command_projection_lock: Arc::new(tokio::sync::Mutex::new(())),
        };
        store.backfill_canonical_network_state().await?;
        store.verify_integrity().await?;
        Ok(store)
    }

    pub async fn connect_file(path: &Path) -> Result<Self, StoreError> {
        if path.as_os_str().is_empty() {
            return Err(StoreError::Database(sqlx::Error::Configuration(
                "database path cannot be empty".into(),
            )));
        }
        if let Some(parent) = path
            .parent()
            .filter(|parent| !parent.as_os_str().is_empty())
        {
            #[cfg(unix)]
            let parent_existed = parent.symlink_metadata().is_ok();
            fs::create_dir_all(parent).map_err(|source| StoreError::CreateDataDirectory {
                path: parent.to_owned(),
                source,
            })?;
            // Restrict the parent directory only when O3K created it. A
            // pre-existing parent (for example /tmp in tests, or a state
            // root already provisioned by the installer) may be a shared
            // system directory or owned by another account; chmod'ing it
            // would either fail with EPERM or change foreign state. The
            // database file and its sidecars are still restricted to 0600
            // below regardless of the parent.
            #[cfg(unix)]
            if !parent_existed {
                fs::set_permissions(parent, fs::Permissions::from_mode(0o700)).map_err(
                    |source| StoreError::CreateDataDirectory {
                        path: parent.to_owned(),
                        source,
                    },
                )?;
            }
        }
        #[cfg(unix)]
        if path.exists() {
            let metadata = fs::symlink_metadata(path)
                .map_err(|source| StoreError::Database(sqlx::Error::Io(source)))?;
            if metadata.file_type().is_symlink() || !metadata.file_type().is_file() {
                return Err(StoreError::Database(sqlx::Error::Configuration(
                    "database path is not a regular file".into(),
                )));
            }
            fs::set_permissions(path, fs::Permissions::from_mode(0o600))
                .map_err(|source| StoreError::Database(sqlx::Error::Io(source)))?;
        }
        #[cfg(unix)]
        restrict_sqlite_sidecars(path)?;
        let url = format!("sqlite://{}", path.display());
        let store = Self::connect(&url).await?;
        #[cfg(unix)]
        fs::set_permissions(path, fs::Permissions::from_mode(0o600))
            .map_err(|source| StoreError::Database(sqlx::Error::Io(source)))?;
        #[cfg(unix)]
        restrict_sqlite_sidecars(path)?;
        Ok(store)
    }

    pub async fn journal_mode(&self) -> Result<String, StoreError> {
        let row = sqlx::query("PRAGMA journal_mode")
            .fetch_one(&self.pool)
            .await
            .map_err(StoreError::Database)?;
        let mode: String = row.get(0);
        Ok(mode)
    }

    pub async fn checkpoint(&self, mode: WalCheckpointMode) -> Result<(), StoreError> {
        let sql = format!("PRAGMA wal_checkpoint({})", mode.as_pragma_str());
        sqlx::query(&sql)
            .execute(&self.pool)
            .await
            .map_err(StoreError::Database)?;
        Ok(())
    }

    pub async fn database_health(&self) -> Result<DatabaseHealth, StoreError> {
        let journal_mode = self.journal_mode().await?;

        let fk_row = sqlx::query("PRAGMA foreign_keys")
            .fetch_one(&self.pool)
            .await
            .map_err(StoreError::Database)?;
        let fk_int: i64 = fk_row.get(0);
        let foreign_keys = fk_int != 0;

        let integrity_row = sqlx::query("PRAGMA quick_check")
            .fetch_one(&self.pool)
            .await
            .map_err(StoreError::Database)?;
        let integrity_check: String = integrity_row.get(0);

        let page_count_row = sqlx::query("PRAGMA page_count")
            .fetch_one(&self.pool)
            .await
            .map_err(StoreError::Database)?;
        let page_count: i64 = page_count_row.get(0);

        let page_size_row = sqlx::query("PRAGMA page_size")
            .fetch_one(&self.pool)
            .await
            .map_err(StoreError::Database)?;
        let page_size: i64 = page_size_row.get(0);

        let wal_status = if journal_mode.eq_ignore_ascii_case("wal") {
            Some("active".to_owned())
        } else {
            None
        };

        let status = if integrity_check.eq_ignore_ascii_case("ok") {
            "ok".to_owned()
        } else {
            "degraded".to_owned()
        };

        Ok(DatabaseHealth {
            status,
            journal_mode,
            foreign_keys,
            integrity_check,
            page_count,
            page_size,
            wal_checkpoint_status: wal_status,
        })
    }

    pub async fn backup_to_file(&self, destination: &Path) -> Result<(), StoreError> {
        if let Some(parent) = destination.parent().filter(|p| !p.as_os_str().is_empty()) {
            fs::create_dir_all(parent).map_err(|source| StoreError::CreateDataDirectory {
                path: parent.to_owned(),
                source,
            })?;
        }
        let dest_str = destination.display().to_string();
        let query_str = format!("VACUUM INTO '{}'", dest_str.replace('\'', "''"));
        sqlx::query(&query_str)
            .execute(&self.pool)
            .await
            .map_err(StoreError::Database)?;
        Ok(())
    }

    /// Lists all resources of one kind across projects for restart
    /// reconciliation. Callers must apply their own authorization checks
    /// before exposing the returned project-scoped records.
    pub async fn list_resources_by_kind(
        &self,
        kind: &str,
    ) -> Result<Vec<ResourceRecord>, StoreError> {
        let rows = sqlx::query(
            "SELECT id, kind, project_id, generation, observed_generation, desired_state, observed_state, provider_id FROM resources WHERE kind = ? ORDER BY id",
        )
        .bind(kind)
        .fetch_all(&self.pool)
        .await
        .map_err(StoreError::Database)?;
        rows.iter().map(resource_from_row).collect()
    }

    pub(super) fn volume_attachment_from_row(
        row: &SqliteRow,
    ) -> Result<VolumeAttachmentRecord, StoreError> {
        let id_str: String = row.try_get("id").map_err(StoreError::Database)?;
        let server_id_str: String = row.try_get("server_id").map_err(StoreError::Database)?;
        let volume_id_str: String = row.try_get("volume_id").map_err(StoreError::Database)?;
        let device: String = row.try_get("device").map_err(StoreError::Database)?;
        let tag: Option<String> = row.try_get("tag").map_err(StoreError::Database)?;
        let delete_on_termination_int: i32 = row
            .try_get("delete_on_termination")
            .map_err(StoreError::Database)?;
        let created_at: String = row.try_get("created_at").map_err(StoreError::Database)?;
        let status: String = row.try_get("status").map_err(StoreError::Database)?;
        let operation_id: Option<String> =
            row.try_get("operation_id").map_err(StoreError::Database)?;
        let idempotency_key: Option<String> = row
            .try_get("idempotency_key")
            .map_err(StoreError::Database)?;
        let cinder_attachment_id: Option<String> = row
            .try_get("cinder_attachment_id")
            .map_err(StoreError::Database)?;
        let connector_host: Option<String> = row
            .try_get("connector_host")
            .map_err(StoreError::Database)?;
        let connector_ip: Option<String> =
            row.try_get("connector_ip").map_err(StoreError::Database)?;
        let connector_initiator: Option<String> = row
            .try_get("connector_initiator")
            .map_err(StoreError::Database)?;
        let driver_volume_type: Option<String> = row
            .try_get("driver_volume_type")
            .map_err(StoreError::Database)?;
        let target_iqn: Option<String> = row.try_get("target_iqn").map_err(StoreError::Database)?;
        let target_portal: Option<String> =
            row.try_get("target_portal").map_err(StoreError::Database)?;
        let target_lun: Option<i64> = row.try_get("target_lun").map_err(StoreError::Database)?;
        let connection_info_digest: Option<String> = row
            .try_get("connection_info_digest")
            .map_err(StoreError::Database)?;
        let error: Option<String> = row.try_get("error").map_err(StoreError::Database)?;

        let id = Uuid::parse_str(&id_str)
            .map_err(|_| StoreError::Corrupt("invalid volume attachment id".to_owned()))?;
        let server_id = Uuid::parse_str(&server_id_str)
            .map_err(|_| StoreError::Corrupt("invalid server id".to_owned()))?;
        let volume_id = Uuid::parse_str(&volume_id_str)
            .map_err(|_| StoreError::Corrupt("invalid volume id".to_owned()))?;

        Ok(VolumeAttachmentRecord {
            id,
            server_id,
            volume_id,
            device,
            tag,
            delete_on_termination: delete_on_termination_int != 0,
            created_at,
            status,
            operation_id: operation_id
                .as_deref()
                .map(Uuid::parse_str)
                .transpose()
                .map_err(|_| StoreError::Corrupt("invalid attachment operation id".to_owned()))?,
            idempotency_key,
            cinder_attachment_id,
            connector_host,
            connector_ip,
            connector_initiator,
            driver_volume_type,
            target_iqn,
            target_portal,
            target_lun: target_lun
                .map(|value| {
                    u32::try_from(value)
                        .map_err(|_| StoreError::Corrupt("invalid attachment lun".to_owned()))
                })
                .transpose()?,
            connection_info_digest,
            error,
        })
    }

    async fn verify_integrity(&self) -> Result<(), StoreError> {
        let result: String = sqlx::query_scalar("PRAGMA integrity_check")
            .fetch_one(&self.pool)
            .await
            .map_err(StoreError::Database)?;
        if result != "ok" {
            return Err(StoreError::Corrupt(result));
        }
        let table_count: i64 = sqlx::query_scalar(
            "SELECT COUNT(*) FROM sqlite_master WHERE type = 'table' AND name IN ('resources', 'operations', 'provider_refs', 'keypairs', 'server_keypairs', 'agent_commands', 'operation_retry_state', 'artifact_transfers', 'image_overlay_ownership', 'volume_attachments', 'keystone_domains', 'keystone_projects', 'keystone_users', 'keystone_roles', 'keystone_role_assignments', 'keystone_services', 'keystone_endpoints', 'keystone_regions', 'image_metadata', 'network_networks', 'network_subnets', 'network_ports', 'canonical_networks', 'canonical_address_realms', 'canonical_address_pools', 'canonical_endpoints', 'canonical_network_policies', 'canonical_realm_encapsulation_bindings', 'placement_providers', 'placement_inventories', 'placement_allocations', 'placement_allocation_resources', 'placement_allocation_intents', 'placement_allocation_intent_resources', 'native_storage_backends', 'native_volumes', 'native_volume_attachments', 'native_snapshots')",
        )
        .fetch_one(&self.pool)
        .await
        .map_err(StoreError::Database)?;
        if table_count != 38 {
            return Err(StoreError::Corrupt("required table is missing".to_owned()));
        }

        Ok(())
    }
}

impl SqliteStore {
    async fn create_or_replay_idempotent_operation(
        &self,
        operation: &OperationRecord,
        request: &IdempotencyReservationRequest,
    ) -> Result<IdempotencyReservation, StoreError> {
        if operation.id != request.operation_id {
            return Err(StoreError::Corrupt(
                "operation and idempotency identities differ".into(),
            ));
        }
        let mut tx = self.pool.begin().await.map_err(StoreError::Database)?;
        let inserted = sqlx::query("INSERT INTO operations (id, resource_id, kind, state, provider_operation_id, error_category, error_message) VALUES (?, ?, ?, ?, ?, ?, ?)")
            .bind(operation.id.to_string()).bind(operation.resource_id.to_string())
            .bind(&operation.kind).bind(operation.state.as_str())
            .bind(&operation.provider_operation_id).bind(&operation.error_category)
            .bind(&operation.error_message).execute(&mut *tx).await;
        let operation_inserted = match inserted {
            Ok(_) => true,
            Err(sqlx::Error::Database(error)) if error.is_unique_violation() => false,
            Err(error) => return Err(StoreError::Database(error)),
        };
        let reservation = sqlx::query("INSERT INTO idempotency_reservations (owner_scope, action, idempotency_key, fingerprint, operation_id) VALUES (?, ?, ?, ?, ?)")
            .bind(&request.owner_scope).bind(&request.action).bind(&request.key)
            .bind(&request.fingerprint).bind(request.operation_id.to_string())
            .execute(&mut *tx).await;
        let outcome = match reservation {
            Ok(_) => IdempotencyReservation::Created(request.operation_id),
            Err(sqlx::Error::Database(error)) if error.is_unique_violation() => {
                let row = sqlx::query("SELECT fingerprint, operation_id FROM idempotency_reservations WHERE owner_scope = ? AND action = ? AND idempotency_key = ?")
                    .bind(&request.owner_scope).bind(&request.action).bind(&request.key)
                    .fetch_optional(&mut *tx).await.map_err(StoreError::Database)?
                    .ok_or(StoreError::IdempotencyConflict)?;
                let fingerprint: String =
                    row.try_get("fingerprint").map_err(StoreError::Database)?;
                let id: String = row.try_get("operation_id").map_err(StoreError::Database)?;
                let existing = Uuid::parse_str(&id).map_err(StoreError::InvalidUuid)?;
                if fingerprint != request.fingerprint {
                    IdempotencyReservation::Conflict
                } else {
                    IdempotencyReservation::ExistingEquivalent(existing)
                }
            }
            Err(error) => return Err(StoreError::Database(error)),
        };
        if operation_inserted
            && (matches!(outcome, IdempotencyReservation::Conflict)
                || matches!(outcome, IdempotencyReservation::ExistingEquivalent(id) if id != operation.id))
        {
            // This transaction may have inserted the losing proposal. Remove
            // it before commit so concurrent losers cannot leave orphan rows.
            sqlx::query("DELETE FROM operations WHERE id = ?")
                .bind(operation.id.to_string())
                .execute(&mut *tx)
                .await
                .map_err(StoreError::Database)?;
        }
        if let IdempotencyReservation::ExistingEquivalent(id) = outcome {
            let exists = sqlx::query("SELECT 1 FROM operations WHERE id = ?")
                .bind(id.to_string())
                .fetch_optional(&mut *tx)
                .await
                .map_err(StoreError::Database)?
                .is_some();
            if !exists {
                return Err(StoreError::Corrupt(
                    "idempotency reservation references missing operation".into(),
                ));
            }
        }
        tx.commit().await.map_err(StoreError::Database)?;
        Ok(outcome)
    }

    async fn create_or_replay_canonical_idempotent_operation(
        &self,
        operation: &OperationRecord,
        canonical: &CanonicalOperationRecord,
        request: &IdempotencyReservationRequest,
    ) -> Result<IdempotencyReservation, StoreError> {
        if request.key.is_empty()
            || request.key.len() > IdempotencyReservationRequest::MAX_KEY_LENGTH
        {
            return Err(StoreError::Corrupt(
                "invalid idempotency key byte length".into(),
            ));
        }
        validate_canonical_idempotent_operation_identity(operation, canonical, request)?;
        let mut connection = self.pool.acquire().await.map_err(StoreError::Database)?;
        sqlx::query("BEGIN IMMEDIATE")
            .execute(&mut *connection)
            .await
            .map_err(StoreError::Database)?;
        let outcome: Result<IdempotencyReservation, StoreError> = async {
            // Idempotency is resolved before inspecting the proposed target.
            // This preserves replay after the accepted resource is removed or
            // advances beyond the request's original precondition.
            let reservation = sqlx::query("SELECT fingerprint, operation_id FROM idempotency_reservations WHERE owner_scope = ? AND action = ? AND idempotency_key = ?")
                .bind(&request.owner_scope).bind(&request.action).bind(&request.key)
                .fetch_optional(&mut *connection).await.map_err(StoreError::Database)?;
            if let Some(reservation) = reservation {
                let fingerprint: String = reservation.try_get("fingerprint").map_err(StoreError::Database)?;
                if fingerprint != request.fingerprint {
                    return Ok(IdempotencyReservation::Conflict);
                }
                let existing = Uuid::parse_str(&reservation.try_get::<String, _>("operation_id").map_err(StoreError::Database)?)
                    .map_err(StoreError::InvalidUuid)?;
                let operation_row = sqlx::query("SELECT id, resource_id, kind, state, provider_operation_id, error_category, error_message FROM operations WHERE id = ?")
                    .bind(existing.to_string()).fetch_optional(&mut *connection).await
                    .map_err(StoreError::Database)?
                    .ok_or_else(|| StoreError::Corrupt("idempotency reservation references missing operation".into()))?;
                let existing_operation = operation_from_row(&operation_row)?;
                let metadata = sqlx::query("SELECT * FROM canonical_operation_metadata WHERE operation_id = ?")
                    .bind(existing.to_string()).fetch_optional(&mut *connection).await
                    .map_err(StoreError::Database)?
                    .ok_or_else(|| StoreError::Corrupt("idempotency reservation references operation without canonical metadata".into()))?;
                let existing_canonical = CanonicalOperationRecord {
                    id: existing,
                    service: metadata.get("service"), action: metadata.get("action"),
                    actor: metadata.get("actor"), owner_scope: metadata.get("owner_scope"),
                    resource_type: metadata.get("resource_type"), resource_id: metadata.get("resource_id"),
                    state: existing_operation.state,
                    attempt: u32::try_from(metadata.get::<i64, _>("attempt"))
                        .map_err(|_| StoreError::Corrupt("invalid operation attempt".into()))?,
                    created_at: metadata.get("created_at"), started_at: metadata.get("started_at"),
                    finished_at: metadata.get("finished_at"), error: metadata.get("error"),
                    request_id: metadata.get("request_id"),
                };
                let mut existing_request = request.clone();
                existing_request.operation_id = existing;
                validate_canonical_idempotent_operation_identity(&existing_operation, &existing_canonical, &existing_request)?;
                let winning_owner: String = sqlx::query("SELECT project_id FROM resources WHERE id = ?")
                    .bind(existing_operation.resource_id.to_string())
                    .fetch_optional(&mut *connection).await.map_err(StoreError::Database)?
                    .ok_or_else(|| StoreError::Corrupt("canonical operation references missing resource".into()))?
                    .try_get("project_id").map_err(StoreError::Database)?;
                if winning_owner != existing_canonical.owner_scope {
                    return Err(StoreError::Corrupt("canonical operation resource and owner scopes differ".into()));
                }
                return Ok(IdempotencyReservation::ExistingEquivalent(existing));
            }

            let resource_owner: String = sqlx::query("SELECT project_id FROM resources WHERE id = ?")
                .bind(operation.resource_id.to_string())
                .fetch_optional(&mut *connection).await.map_err(StoreError::Database)?
                .ok_or(StoreError::ResourceNotFound)?
                .try_get("project_id").map_err(StoreError::Database)?;
            if resource_owner != canonical.owner_scope {
                return Err(StoreError::Corrupt("operation resource does not match canonical owner".into()));
            }
            let inserted = sqlx::query("INSERT OR IGNORE INTO operations (id, resource_id, kind, state, provider_operation_id, error_category, error_message) VALUES (?, ?, ?, ?, ?, ?, ?)")
                .bind(operation.id.to_string()).bind(operation.resource_id.to_string())
                .bind(&operation.kind).bind(operation.state.as_str())
                .bind(&operation.provider_operation_id).bind(&operation.error_category)
                .bind(&operation.error_message).execute(&mut *connection).await.map_err(StoreError::Database)?;
            if inserted.rows_affected() != 1 {
                return Err(StoreError::Corrupt("cannot attach a new idempotency reservation to a pre-existing operation".into()));
            }
            sqlx::query("INSERT INTO canonical_operation_metadata (operation_id,service,action,actor,owner_scope,resource_type,resource_id,attempt,created_at,started_at,finished_at,error,request_id) VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?)")
                .bind(canonical.id.to_string()).bind(&canonical.service).bind(&canonical.action)
                .bind(&canonical.actor).bind(&canonical.owner_scope).bind(&canonical.resource_type)
                .bind(&canonical.resource_id).bind(i64::from(canonical.attempt)).bind(&canonical.created_at)
                .bind(&canonical.started_at).bind(&canonical.finished_at).bind(&canonical.error)
                .bind(&canonical.request_id).execute(&mut *connection).await.map_err(StoreError::Database)?;
            sqlx::query("INSERT INTO idempotency_reservations (owner_scope, action, idempotency_key, fingerprint, operation_id) VALUES (?, ?, ?, ?, ?)")
                .bind(&request.owner_scope).bind(&request.action).bind(&request.key)
                .bind(&request.fingerprint).bind(request.operation_id.to_string())
                .execute(&mut *connection).await.map_err(StoreError::Database)?;
            Ok(IdempotencyReservation::Created(operation.id))
        }.await;
        Self::commit_or_rollback(&mut connection, outcome).await
    }

    async fn create_or_replay_canonical_resource_operation(
        &self,
        resource: &ResourceRecord,
        operation: &OperationRecord,
        canonical: &CanonicalOperationRecord,
        request: &IdempotencyReservationRequest,
        expected_placement_allocation_id: Option<&str>,
    ) -> Result<CanonicalAcceptanceOutcome, StoreError> {
        validate_canonical_resource_acceptance(resource, operation, canonical, request)?;
        let mut connection = self.pool.acquire().await.map_err(StoreError::Database)?;
        sqlx::query("BEGIN IMMEDIATE")
            .execute(&mut *connection)
            .await
            .map_err(StoreError::Database)?;
        let outcome = async {
            if let Some(row) = sqlx::query("SELECT fingerprint, operation_id FROM idempotency_reservations WHERE owner_scope=? AND action=? AND idempotency_key=?")
                .bind(&request.owner_scope).bind(&request.action).bind(&request.key)
                .fetch_optional(&mut *connection).await.map_err(StoreError::Database)? {
                if row.get::<String, _>("fingerprint") != request.fingerprint {
                    return Ok(CanonicalAcceptanceOutcome::Conflict);
                }
                let operation_id = Uuid::parse_str(&row.get::<String, _>("operation_id")).map_err(StoreError::InvalidUuid)?;
                let durable = operation_from_row(&sqlx::query("SELECT * FROM operations WHERE id=?").bind(operation_id.to_string())
                    .fetch_one(&mut *connection).await.map_err(StoreError::Database)?)?;
                let metadata = sqlx::query("SELECT * FROM canonical_operation_metadata WHERE operation_id=?").bind(operation_id.to_string())
                    .fetch_one(&mut *connection).await.map_err(StoreError::Database)?;
                let canonical = CanonicalOperationRecord { id: operation_id, service: metadata.get("service"), action: metadata.get("action"), actor: metadata.get("actor"), owner_scope: metadata.get("owner_scope"), resource_type: metadata.get("resource_type"), resource_id: metadata.get("resource_id"), state: durable.state, attempt: u32::try_from(metadata.get::<i64,_>("attempt")).map_err(|_| StoreError::Corrupt("invalid operation attempt".into()))?, created_at: metadata.get("created_at"), started_at: metadata.get("started_at"), finished_at: metadata.get("finished_at"), error: metadata.get("error"), request_id: metadata.get("request_id") };
                let resource = resource_from_row(&sqlx::query("SELECT * FROM resources WHERE id=?").bind(durable.resource_id.to_string())
                    .fetch_one(&mut *connection).await.map_err(StoreError::Database)?)?;
                let mut replay = request.clone(); replay.operation_id = operation_id;
                validate_canonical_resource_acceptance(&resource, &durable, &canonical, &replay)?;
                return Ok(CanonicalAcceptanceOutcome::ExistingEquivalent { operation_id, resource_id: resource.id });
            }
            if let Some(allocation_id) = expected_placement_allocation_id {
                let exists = sqlx::query("SELECT 1 FROM placement_allocations WHERE id=?").bind(allocation_id)
                    .fetch_optional(&mut *connection).await.map_err(StoreError::Database)?.is_some();
                if !exists { return Err(StoreError::PlacementAllocationNotFound); }
            }
            sqlx::query("INSERT INTO resources (id,kind,project_id,generation,observed_generation,desired_state,observed_state,provider_id) VALUES (?,?,?,?,?,?,?,?)")
                .bind(resource.id.to_string()).bind(&resource.kind).bind(&resource.project_id).bind(resource.generation)
                .bind(resource.observed_generation).bind(&resource.desired_state).bind(&resource.observed_state).bind(&resource.provider_id)
                .execute(&mut *connection).await.map_err(|e| match e {
                    sqlx::Error::Database(ref db) if db.is_unique_violation() => StoreError::ResourceAlreadyExists,
                    _ => StoreError::Database(e),
                })?;
            insert_sqlite_canonical_acceptance(&mut connection, operation, canonical, request).await?;
            Ok(CanonicalAcceptanceOutcome::Created { operation_id: operation.id, resource_id: resource.id })
        }.await;
        Self::commit_or_rollback(&mut connection, outcome).await
    }

    async fn create_or_replay_canonical_lifecycle_operation(
        &self,
        operation: &OperationRecord,
        canonical: &CanonicalOperationRecord,
        request: &IdempotencyReservationRequest,
    ) -> Result<CanonicalAcceptanceOutcome, StoreError> {
        let resource = self.get_resource(operation.resource_id).await?;
        validate_canonical_resource_acceptance(&resource, operation, canonical, request)?;
        let mut connection = self.pool.acquire().await.map_err(StoreError::Database)?;
        sqlx::query("BEGIN IMMEDIATE")
            .execute(&mut *connection)
            .await
            .map_err(StoreError::Database)?;
        let outcome = async {
            if let Some(row) = sqlx::query("SELECT fingerprint, operation_id FROM idempotency_reservations WHERE owner_scope=? AND action=? AND idempotency_key=?")
                .bind(&request.owner_scope).bind(&request.action).bind(&request.key)
                .fetch_optional(&mut *connection).await.map_err(StoreError::Database)? {
                if row.get::<String,_>("fingerprint") != request.fingerprint { return Ok(CanonicalAcceptanceOutcome::Conflict); }
                let operation_id = Uuid::parse_str(&row.get::<String,_>("operation_id")).map_err(StoreError::InvalidUuid)?;
                let durable = operation_from_row(&sqlx::query("SELECT * FROM operations WHERE id=?").bind(operation_id.to_string()).fetch_one(&mut *connection).await.map_err(StoreError::Database)?)?;
                let metadata = sqlx::query("SELECT * FROM canonical_operation_metadata WHERE operation_id=?").bind(operation_id.to_string()).fetch_one(&mut *connection).await.map_err(StoreError::Database)?;
                let existing_canonical = CanonicalOperationRecord { id: operation_id, service: metadata.get("service"), action: metadata.get("action"), actor: metadata.get("actor"), owner_scope: metadata.get("owner_scope"), resource_type: metadata.get("resource_type"), resource_id: metadata.get("resource_id"), state: durable.state, attempt: u32::try_from(metadata.get::<i64,_>("attempt")).map_err(|_| StoreError::Corrupt("invalid operation attempt".into()))?, created_at: metadata.get("created_at"), started_at: metadata.get("started_at"), finished_at: metadata.get("finished_at"), error: metadata.get("error"), request_id: metadata.get("request_id") };
                let existing_resource = resource_from_row(&sqlx::query("SELECT * FROM resources WHERE id=?").bind(durable.resource_id.to_string()).fetch_one(&mut *connection).await.map_err(StoreError::Database)?)?;
                let mut replay = request.clone(); replay.operation_id = operation_id;
                validate_canonical_resource_acceptance(&existing_resource, &durable, &existing_canonical, &replay)?;
                return Ok(CanonicalAcceptanceOutcome::ExistingEquivalent { operation_id, resource_id: durable.resource_id });
            }
            let persisted = resource_from_row(&sqlx::query("SELECT * FROM resources WHERE id=?").bind(operation.resource_id.to_string()).fetch_one(&mut *connection).await.map_err(StoreError::Database)?)?;
            validate_canonical_resource_acceptance(&persisted, operation, canonical, request)?;
            insert_sqlite_canonical_acceptance(&mut connection, operation, canonical, request).await?;
            Ok(CanonicalAcceptanceOutcome::Created { operation_id: operation.id, resource_id: operation.resource_id })
        }.await;
        Self::commit_or_rollback(&mut connection, outcome).await
    }
}

#[async_trait]
impl DurableStore for SqliteStore {
    async fn insert_resource(&self, resource: &ResourceRecord) -> Result<(), StoreError> {
        let result = sqlx::query(
            "INSERT INTO resources (id, kind, project_id, generation, observed_generation, desired_state, observed_state, provider_id) VALUES (?, ?, ?, ?, ?, ?, ?, ?)",
        )
        .bind(resource.id.to_string())
        .bind(&resource.kind)
        .bind(&resource.project_id)
        .bind(resource.generation)
        .bind(resource.observed_generation)
        .bind(&resource.desired_state)
        .bind(&resource.observed_state)
        .bind(&resource.provider_id)
        .execute(&self.pool)
        .await;
        match result {
            Ok(_) => Ok(()),
            Err(sqlx::Error::Database(error)) if error.is_unique_violation() => {
                Err(StoreError::ResourceAlreadyExists)
            }
            Err(error) => Err(StoreError::Database(error)),
        }
    }

    async fn get_resource(&self, id: Uuid) -> Result<ResourceRecord, StoreError> {
        let row = sqlx::query("SELECT id, kind, project_id, generation, observed_generation, desired_state, observed_state, provider_id FROM resources WHERE id = ?")
            .bind(id.to_string())
            .fetch_optional(&self.pool)
            .await
            .map_err(StoreError::Database)?
            .ok_or(StoreError::ResourceNotFound)?;
        resource_from_row(&row)
    }

    async fn list_resources(
        &self,
        project_id: &str,
        kind: &str,
    ) -> Result<Vec<ResourceRecord>, StoreError> {
        let rows = sqlx::query("SELECT id, kind, project_id, generation, observed_generation, desired_state, observed_state, provider_id FROM resources WHERE project_id = ? AND kind = ? ORDER BY id")
            .bind(project_id)
            .bind(kind)
            .fetch_all(&self.pool)
            .await
            .map_err(StoreError::Database)?;
        rows.iter().map(resource_from_row).collect()
    }

    async fn list_resources_page(
        &self,
        project_id: &str,
        kind: &str,
        after_id: Option<&str>,
        limit: usize,
    ) -> Result<RepositoryPage<ResourceRecord>, StoreError> {
        let fetch_limit = crate::port::durable::bounded_fetch_limit(limit)?;
        let rows = if let Some(after_id) = after_id {
            sqlx::query("SELECT id, kind, project_id, generation, observed_generation, desired_state, observed_state, provider_id FROM resources WHERE project_id = ? AND kind = ? AND id > ? ORDER BY id LIMIT ?").bind(project_id).bind(kind).bind(after_id).bind(fetch_limit).fetch_all(&self.pool).await
        } else {
            sqlx::query("SELECT id, kind, project_id, generation, observed_generation, desired_state, observed_state, provider_id FROM resources WHERE project_id = ? AND kind = ? ORDER BY id LIMIT ?").bind(project_id).bind(kind).bind(fetch_limit).fetch_all(&self.pool).await
        }.map_err(StoreError::Database)?;
        let mut items: Vec<_> = rows
            .iter()
            .map(resource_from_row)
            .collect::<Result<_, _>>()?;
        let has_more = items.len() > limit;
        if has_more {
            items.pop();
        }
        let continuation_key = if has_more {
            items.last().map(|r| r.id.to_string())
        } else {
            None
        };
        RepositoryPage::new(items, has_more, continuation_key, limit)
    }

    async fn update_resource(
        &self,
        id: Uuid,
        expected_generation: i64,
        desired_state: &str,
        observed_state: &str,
        observed_generation: i64,
        provider_id: Option<&str>,
    ) -> Result<ResourceRecord, StoreError> {
        let result = sqlx::query("UPDATE resources SET generation = generation + 1, desired_state = ?, observed_state = ?, observed_generation = ?, provider_id = ? WHERE id = ? AND generation = ?")
            .bind(desired_state)
            .bind(observed_state)
            .bind(observed_generation)
            .bind(provider_id)
            .bind(id.to_string())
            .bind(expected_generation)
            .execute(&self.pool)
            .await
            .map_err(StoreError::Database)?;
        if result.rows_affected() == 0 {
            return match self.get_resource(id).await {
                Ok(_) => Err(StoreError::StaleGeneration),
                Err(StoreError::ResourceNotFound) => Err(StoreError::ResourceNotFound),
                Err(error) => Err(error),
            };
        }
        self.get_resource(id).await
    }

    #[allow(clippy::too_many_arguments)]
    async fn update_resource_and_complete_operation(
        &self,
        resource_id: Uuid,
        expected_generation: i64,
        desired_state: &str,
        observed_state: &str,
        observed_generation: i64,
        provider_id: Option<&str>,
        operation_id: Uuid,
        lifecycle: &CanonicalOperationLifecycleUpdate,
    ) -> Result<ResourceRecord, StoreError> {
        validate_canonical_lifecycle_update(lifecycle)?;
        let mut connection = self.pool.acquire().await.map_err(StoreError::Database)?;
        sqlx::query("BEGIN IMMEDIATE")
            .execute(&mut *connection)
            .await
            .map_err(StoreError::Database)?;
        let outcome: Result<(), StoreError> = async {
            let updated = sqlx::query("UPDATE resources SET generation = generation + 1, desired_state = ?, observed_state = ?, observed_generation = ?, provider_id = ? WHERE id = ? AND generation = ?")
                .bind(desired_state).bind(observed_state).bind(observed_generation)
                .bind(provider_id).bind(resource_id.to_string()).bind(expected_generation)
                .execute(&mut *connection).await.map_err(StoreError::Database)?;
            if updated.rows_affected() == 0 {
                return match sqlx::query("SELECT id FROM resources WHERE id = ?")
                    .bind(resource_id.to_string()).fetch_optional(&mut *connection).await
                    .map_err(StoreError::Database)? {
                    Some(_) => Err(StoreError::StaleGeneration),
                    None => Err(StoreError::ResourceNotFound),
                };
            }
            let operation = sqlx::query("SELECT state FROM operations WHERE id = ?")
                .bind(operation_id.to_string()).fetch_optional(&mut *connection).await
                .map_err(StoreError::Database)?.ok_or(StoreError::OperationNotFound)?;
            let state: String = operation.try_get("state").map_err(StoreError::Database)?;
            if state == OperationState::Succeeded.as_str() || state == OperationState::Failed.as_str() {
                return Err(StoreError::Corrupt("operation already terminal".into()));
            }
            sqlx::query("UPDATE operations SET state = ? WHERE id = ?")
                .bind(lifecycle.state.as_str()).bind(operation_id.to_string())
                .execute(&mut *connection).await.map_err(StoreError::Database)?;
            sqlx::query("UPDATE canonical_operation_metadata SET attempt = ?, started_at = ?, finished_at = ?, error = ? WHERE operation_id = ?")
                .bind(lifecycle.attempt as i64).bind(&lifecycle.started_at).bind(&lifecycle.finished_at)
                .bind(&lifecycle.public_error).bind(operation_id.to_string())
                .execute(&mut *connection).await.map_err(StoreError::Database)?;
            Ok(())
        }.await;
        SqliteStore::commit_or_rollback(&mut connection, outcome).await?;
        drop(connection);
        self.get_resource(resource_id).await
    }

    async fn terminalize_lifecycle(
        &self,
        terminalization: &LifecycleTerminalization<'_>,
    ) -> Result<(OperationRecord, ResourceRecord), StoreError> {
        terminalization.validate()?;
        let mut connection = self.pool.acquire().await.map_err(StoreError::Database)?;
        sqlx::query("BEGIN IMMEDIATE")
            .execute(&mut *connection)
            .await
            .map_err(StoreError::Database)?;
        let outcome: Result<(), StoreError> = async {
            let row = sqlx::query(
                "SELECT id, resource_id, kind, state, provider_operation_id, error_category, error_message FROM operations WHERE id = ?",
            )
            .bind(terminalization.operation_id.to_string())
            .fetch_optional(&mut *connection)
            .await
            .map_err(StoreError::Database)?
            .ok_or(StoreError::OperationNotFound)?;
            let current = operation_from_row(&row)?;
            if current.resource_id != terminalization.resource_id {
                return Err(StoreError::Corrupt(
                    "lifecycle operation resource identity does not match terminalization"
                        .to_owned(),
                ));
            }
            if matches!(
                current.state,
                OperationState::Succeeded | OperationState::Failed
            ) {
                // Equivalent replay: the first terminalization committed the
                // resource projection in this same transaction, so
                // re-applying it could only double-bump the generation or
                // clobber a newer legitimate write. Fill in durable evidence
                // the first write lacked (mirroring `update_operation`'s
                // terminal replay arm) and leave the resource row untouched.
                if current
                    .provider_operation_id
                    .as_deref()
                    .is_some_and(|existing| {
                        terminalization
                            .provider_operation_id
                            .is_some_and(|incoming| incoming != existing)
                    })
                {
                    return Err(StoreError::Corrupt(
                        "terminal operation provider identity conflicts with durable state"
                            .to_owned(),
                    ));
                }
                if current.state != terminalization.terminal_state {
                    return Err(StoreError::Corrupt(
                        "terminal operation state cannot conflict with durable state".to_owned(),
                    ));
                }
                sqlx::query("UPDATE operations SET provider_operation_id = COALESCE(?, provider_operation_id), error_category = COALESCE(?, error_category), error_message = COALESCE(?, error_message) WHERE id = ?")
                    .bind(terminalization.provider_operation_id)
                    .bind(terminalization.error_category)
                    .bind(terminalization.error_message)
                    .bind(terminalization.operation_id.to_string())
                    .execute(&mut *connection)
                    .await
                    .map_err(StoreError::Database)?;
                return Ok(());
            }
            sqlx::query("UPDATE operations SET state = ?, provider_operation_id = ?, error_category = ?, error_message = ? WHERE id = ?")
                .bind(terminalization.terminal_state.as_str())
                .bind(terminalization.provider_operation_id)
                .bind(terminalization.error_category)
                .bind(terminalization.error_message)
                .bind(terminalization.operation_id.to_string())
                .execute(&mut *connection)
                .await
                .map_err(StoreError::Database)?;
            let now = Utc::now().to_rfc3339();
            sqlx::query("UPDATE canonical_operation_metadata SET started_at=COALESCE(started_at, ?), finished_at=?, error=? WHERE operation_id=?")
                .bind(Some(now.clone()))
                .bind(Some(now))
                .bind(terminalization.error_category)
                .bind(terminalization.operation_id.to_string())
                .execute(&mut *connection)
                .await
                .map_err(StoreError::Database)?;
            // The terminal resource projection is fenced on the caller's
            // expected generation: a stale writer rolls the whole
            // terminalization back, so no half-committed pair can exist
            // (issue #1041).
            let updated = sqlx::query("UPDATE resources SET generation = generation + 1, desired_state = ?, observed_state = ?, observed_generation = ?, provider_id = ? WHERE id = ? AND generation = ?")
                .bind(terminalization.desired_state)
                .bind(terminalization.observed_state)
                .bind(terminalization.observed_generation)
                .bind(terminalization.provider_id)
                .bind(terminalization.resource_id.to_string())
                .bind(terminalization.expected_generation)
                .execute(&mut *connection)
                .await
                .map_err(StoreError::Database)?;
            if updated.rows_affected() == 0 {
                return match sqlx::query("SELECT id FROM resources WHERE id = ?")
                    .bind(terminalization.resource_id.to_string())
                    .fetch_optional(&mut *connection)
                    .await
                    .map_err(StoreError::Database)?
                {
                    Some(_) => Err(StoreError::StaleGeneration),
                    None => Err(StoreError::ResourceNotFound),
                };
            }
            Ok(())
        }
        .await;
        SqliteStore::commit_or_rollback(&mut connection, outcome).await?;
        drop(connection);
        Ok((
            self.get_operation(terminalization.operation_id).await?,
            self.get_resource(terminalization.resource_id).await?,
        ))
    }

    async fn update_resource_from_observation(
        &self,
        id: Uuid,
        update: &ObservationUpdate<'_>,
    ) -> Result<ResourceRecord, StoreError> {
        // A deferred read-then-write transaction in WAL mode can fail
        // immediately with SQLITE_BUSY when a concurrent connection holds the
        // write lock: SQLite declines to invoke the busy handler when waiting
        // would deadlock a lock promotion (proven by run local-1785957445,
        // issue #487, where the observation update failed 6ms after start and
        // the resource stayed `requested` forever). BEGIN IMMEDIATE acquires
        // the write lock up front so the configured busy_timeout is honoured,
        // and the bounded retry below absorbs any residual busy window. The
        // update is transactional and idempotent (generation check plus
        // watermark dedup), so retrying a failed attempt is safe.
        let mut backoff = Duration::from_millis(10);
        for attempt in 0..SQLITE_BUSY_MAX_ATTEMPTS {
            match self.apply_observation_update(id, update).await {
                Err(StoreError::Database(error))
                    if is_sqlite_busy(&error) && attempt + 1 < SQLITE_BUSY_MAX_ATTEMPTS =>
                {
                    tokio::time::sleep(backoff).await;
                    backoff *= 2;
                }
                outcome => return outcome,
            }
        }
        unreachable!("the loop returns on the final attempt")
    }

    async fn insert_operation(&self, operation: &OperationRecord) -> Result<(), StoreError> {
        let result = sqlx::query("INSERT INTO operations (id, resource_id, kind, state, provider_operation_id, error_category, error_message) VALUES (?, ?, ?, ?, ?, ?, ?)")
            .bind(operation.id.to_string())
            .bind(operation.resource_id.to_string())
            .bind(&operation.kind)
            .bind(operation.state.as_str())
            .bind(&operation.provider_operation_id)
            .bind(&operation.error_category)
            .bind(&operation.error_message)
            .execute(&self.pool)
            .await;
        match result {
            Ok(_) => Ok(()),
            // A duplicate operation identity is the "already exists" contract
            // the lifecycle entry points match on (begin_lifecycle etc.); the
            // raw constraint error would otherwise surface as a 500 on every
            // idempotent lifecycle retry.
            Err(sqlx::Error::Database(error)) if error.is_unique_violation() => {
                Err(StoreError::ResourceAlreadyExists)
            }
            Err(error) => Err(StoreError::Database(error)),
        }
    }

    async fn get_operation(&self, id: Uuid) -> Result<OperationRecord, StoreError> {
        let row = sqlx::query("SELECT id, resource_id, kind, state, provider_operation_id, error_category, error_message FROM operations WHERE id = ?")
            .bind(id.to_string())
            .fetch_optional(&self.pool)
            .await
            .map_err(StoreError::Database)?
            .ok_or(StoreError::OperationNotFound)?;
        operation_from_row(&row)
    }

    async fn get_canonical_operation(
        &self,
        id: Uuid,
    ) -> Result<CanonicalOperationRecord, StoreError> {
        let row = sqlx::query("SELECT * FROM canonical_operation_metadata WHERE operation_id=?")
            .bind(id.to_string())
            .fetch_optional(&self.pool)
            .await
            .map_err(StoreError::Database)?
            .ok_or(StoreError::OperationNotFound)?;
        let operation = self.get_operation(id).await?;
        let canonical = CanonicalOperationRecord {
            id,
            service: row.get("service"),
            action: row.get("action"),
            actor: row.get("actor"),
            owner_scope: row.get("owner_scope"),
            resource_type: row.get("resource_type"),
            resource_id: row.get("resource_id"),
            state: self.get_operation(id).await?.state,
            attempt: u32::try_from(row.get::<i64, _>("attempt"))
                .map_err(|_| StoreError::Corrupt("invalid operation attempt".into()))?,
            created_at: row.get("created_at"),
            started_at: row.get("started_at"),
            finished_at: row.get("finished_at"),
            error: row.get("error"),
            request_id: row.get("request_id"),
        };
        match canonical.resource_type.as_str() {
            "network:network" => {
                let owner = sqlx::query_scalar::<_, String>(
                    "SELECT project_id FROM canonical_networks WHERE id = ?",
                )
                .bind(operation.resource_id.to_string())
                .fetch_optional(&self.pool)
                .await
                .map_err(StoreError::Database)?;
                if let Some(owner) = owner {
                    if owner != canonical.owner_scope {
                        return Err(StoreError::Corrupt(
                            "canonical network operation owner differs from network owner".into(),
                        ));
                    }
                } else if sqlx::query_scalar::<_, String>(
                    "SELECT project_id FROM canonical_address_realms WHERE id = ?",
                )
                .bind(operation.resource_id.to_string())
                .fetch_optional(&self.pool)
                .await
                .map_err(StoreError::Database)?
                .is_some()
                {
                    return Err(StoreError::Corrupt(
                        "canonical network operation references an address realm".into(),
                    ));
                }
            }
            "network:address_realm" => {
                let owner = sqlx::query_scalar::<_, String>(
                    "SELECT project_id FROM canonical_address_realms WHERE id = ?",
                )
                .bind(operation.resource_id.to_string())
                .fetch_optional(&self.pool)
                .await
                .map_err(StoreError::Database)?;
                if let Some(owner) = owner {
                    if owner != canonical.owner_scope {
                        return Err(StoreError::Corrupt(
                            "canonical address realm operation owner differs from realm owner"
                                .into(),
                        ));
                    }
                } else if sqlx::query_scalar::<_, String>(
                    "SELECT project_id FROM canonical_networks WHERE id = ?",
                )
                .bind(operation.resource_id.to_string())
                .fetch_optional(&self.pool)
                .await
                .map_err(StoreError::Database)?
                .is_some()
                {
                    return Err(StoreError::Corrupt(
                        "canonical address realm operation references a network".into(),
                    ));
                }
            }
            _ => {}
        }
        match self.get_resource(operation.resource_id).await {
            Ok(resource) => validate_canonical_operation_read(&operation, &canonical, &resource)?,
            Err(StoreError::ResourceNotFound) => {
                validate_canonical_scoped_operation_read(&operation, &canonical)?;
            }
            Err(error) => return Err(error),
        }
        Ok(canonical)
    }

    async fn get_idempotency_reservation(
        &self,
        owner_scope: &str,
        action: &str,
        key: &str,
    ) -> Result<Option<StoredIdempotencyReservation>, StoreError> {
        let row = sqlx::query(
            "SELECT fingerprint, operation_id FROM idempotency_reservations WHERE owner_scope = ? AND action = ? AND idempotency_key = ?",
        )
        .bind(owner_scope)
        .bind(action)
        .bind(key)
        .fetch_optional(&self.pool)
        .await
        .map_err(StoreError::Database)?;
        row.map(|row| {
            let fingerprint: String = row.try_get("fingerprint").map_err(StoreError::Database)?;
            let operation_id = Uuid::parse_str(
                row.try_get::<String, _>("operation_id")
                    .map_err(StoreError::Database)?
                    .as_str(),
            )
            .map_err(StoreError::InvalidUuid)?;
            Ok(StoredIdempotencyReservation {
                fingerprint,
                operation_id,
            })
        })
        .transpose()
    }

    async fn reserve_idempotent_operation(
        &self,
        request: &IdempotencyReservationRequest,
    ) -> Result<IdempotencyReservation, StoreError> {
        let result = sqlx::query("INSERT INTO idempotency_reservations (owner_scope, action, idempotency_key, fingerprint, operation_id) VALUES (?, ?, ?, ?, ?)").bind(&request.owner_scope).bind(&request.action).bind(&request.key).bind(&request.fingerprint).bind(request.operation_id.to_string()).execute(&self.pool).await;
        match result {
            Ok(_) => Ok(IdempotencyReservation::Created(request.operation_id)),
            Err(sqlx::Error::Database(error)) if error.is_unique_violation() => {
                let row = sqlx::query("SELECT fingerprint, operation_id FROM idempotency_reservations WHERE owner_scope = ? AND action = ? AND idempotency_key = ?").bind(&request.owner_scope).bind(&request.action).bind(&request.key).fetch_optional(&self.pool).await.map_err(StoreError::Database)?.ok_or(StoreError::IdempotencyConflict)?;
                let fingerprint: String =
                    row.try_get("fingerprint").map_err(StoreError::Database)?;
                let id: String = row.try_get("operation_id").map_err(StoreError::Database)?;
                if fingerprint != request.fingerprint {
                    return Ok(IdempotencyReservation::Conflict);
                }
                Ok(IdempotencyReservation::ExistingEquivalent(
                    Uuid::parse_str(&id).map_err(StoreError::InvalidUuid)?,
                ))
            }
            Err(error) => Err(StoreError::Database(error)),
        }
    }

    async fn list_canonical_operations_page(
        &self,
        owner_scope: &str,
        after_id: Option<Uuid>,
        limit: u32,
    ) -> Result<Vec<CanonicalOperationRecord>, StoreError> {
        let limit = i64::from(limit);
        let rows = if let Some(after_id) = after_id {
            sqlx::query("SELECT m.*, o.state FROM canonical_operation_metadata m JOIN operations o ON o.id=m.operation_id WHERE m.owner_scope=? AND m.operation_id>? ORDER BY m.operation_id LIMIT ?")
                .bind(owner_scope).bind(after_id.to_string()).bind(limit).fetch_all(&self.pool).await
        } else {
            sqlx::query("SELECT m.*, o.state FROM canonical_operation_metadata m JOIN operations o ON o.id=m.operation_id WHERE m.owner_scope=? ORDER BY m.operation_id LIMIT ?")
                .bind(owner_scope).bind(limit).fetch_all(&self.pool).await
        }.map_err(StoreError::Database)?;
        rows.into_iter()
            .map(|row| {
                Ok(CanonicalOperationRecord {
                    id: Uuid::parse_str(&row.get::<String, _>("operation_id"))
                        .map_err(StoreError::InvalidUuid)?,
                    service: row.get("service"),
                    action: row.get("action"),
                    actor: row.get("actor"),
                    owner_scope: row.get("owner_scope"),
                    resource_type: row.get("resource_type"),
                    resource_id: row.get("resource_id"),
                    state: OperationState::parse(&row.get::<String, _>("state"))?,
                    attempt: u32::try_from(row.get::<i64, _>("attempt"))
                        .map_err(|_| StoreError::Corrupt("invalid operation attempt".into()))?,
                    created_at: row.get("created_at"),
                    started_at: row.get("started_at"),
                    finished_at: row.get("finished_at"),
                    error: row.get("error"),
                    request_id: row.get("request_id"),
                })
            })
            .collect()
    }

    async fn create_or_replay_idempotent_operation(
        &self,
        operation: &OperationRecord,
        request: &IdempotencyReservationRequest,
    ) -> Result<IdempotencyReservation, StoreError> {
        SqliteStore::create_or_replay_idempotent_operation(self, operation, request).await
    }

    async fn create_or_replay_canonical_idempotent_operation(
        &self,
        operation: &OperationRecord,
        canonical: &CanonicalOperationRecord,
        request: &IdempotencyReservationRequest,
    ) -> Result<IdempotencyReservation, StoreError> {
        SqliteStore::create_or_replay_canonical_idempotent_operation(
            self, operation, canonical, request,
        )
        .await
    }

    async fn create_or_replay_canonical_scoped_operation(
        &self,
        operation: &OperationRecord,
        canonical: &CanonicalOperationRecord,
        request: &IdempotencyReservationRequest,
    ) -> Result<IdempotencyReservation, StoreError> {
        if operation.id != request.operation_id {
            return Err(StoreError::Corrupt(
                "operation and idempotency identities differ".into(),
            ));
        }
        validate_canonical_idempotent_operation_identity(operation, canonical, request)?;
        let mut connection = self.pool.acquire().await.map_err(StoreError::Database)?;
        sqlx::query("BEGIN IMMEDIATE")
            .execute(&mut *connection)
            .await
            .map_err(StoreError::Database)?;
        let result: Result<IdempotencyReservation, StoreError> = async {
            if let Some(row) = sqlx::query("SELECT fingerprint, operation_id FROM idempotency_reservations WHERE owner_scope=? AND action=? AND idempotency_key=?")
                .bind(&request.owner_scope).bind(&request.action).bind(&request.key)
                .fetch_optional(&mut *connection).await.map_err(StoreError::Database)?
            {
                let fingerprint: String = row.try_get("fingerprint").map_err(StoreError::Database)?;
                let existing = Uuid::parse_str(&row.try_get::<String, _>("operation_id").map_err(StoreError::Database)?)
                    .map_err(StoreError::InvalidUuid)?;
                if fingerprint != request.fingerprint {
                    return Ok(IdempotencyReservation::Conflict);
                }
                let op = sqlx::query("SELECT resource_id FROM operations WHERE id=?")
                    .bind(existing.to_string()).fetch_one(&mut *connection).await.map_err(StoreError::Database)?;
                let metadata = sqlx::query("SELECT owner_scope, action, resource_id FROM canonical_operation_metadata WHERE operation_id=?")
                    .bind(existing.to_string()).fetch_one(&mut *connection).await.map_err(StoreError::Database)?;
                if op.get::<String, _>("resource_id") != operation.resource_id.to_string()
                    || metadata.get::<String, _>("owner_scope") != request.owner_scope
                    || metadata.get::<String, _>("action") != request.action
                    || metadata.get::<Option<String>, _>("resource_id") != Some(operation.resource_id.to_string())
                {
                    return Err(StoreError::Corrupt("canonical scoped operation replay identity differs".into()));
                }
                return Ok(IdempotencyReservation::ExistingEquivalent(existing));
            }
            let owner_scope: Option<String> = match canonical.resource_type.as_str() {
                "network:network" => sqlx::query_scalar("SELECT project_id FROM canonical_networks WHERE id=?")
                    .bind(operation.resource_id.to_string()).fetch_optional(&mut *connection).await
                    .map_err(StoreError::Database)?,
                "network:address_realm" => sqlx::query_scalar("SELECT project_id FROM canonical_address_realms WHERE id=?")
                    .bind(operation.resource_id.to_string()).fetch_optional(&mut *connection).await
                    .map_err(StoreError::Database)?,
                _ => return Err(StoreError::Corrupt("unsupported canonical scoped resource type".into())),
            };
            if owner_scope.as_deref() != Some(canonical.owner_scope.as_str()) {
                return Err(StoreError::ResourceNotFound);
            }
            insert_sqlite_canonical_acceptance(&mut connection, operation, canonical, request).await?;
            Ok(IdempotencyReservation::Created(operation.id))
        }.await;
        Self::commit_or_rollback(&mut connection, result).await
    }

    async fn create_or_replay_canonical_resource_operation(
        &self,
        resource: &ResourceRecord,
        operation: &OperationRecord,
        canonical: &CanonicalOperationRecord,
        request: &IdempotencyReservationRequest,
        expected_placement_allocation_id: Option<&str>,
    ) -> Result<CanonicalAcceptanceOutcome, StoreError> {
        SqliteStore::create_or_replay_canonical_resource_operation(
            self,
            resource,
            operation,
            canonical,
            request,
            expected_placement_allocation_id,
        )
        .await
    }

    async fn create_or_replay_canonical_lifecycle_operation(
        &self,
        operation: &OperationRecord,
        canonical: &CanonicalOperationRecord,
        request: &IdempotencyReservationRequest,
    ) -> Result<CanonicalAcceptanceOutcome, StoreError> {
        SqliteStore::create_or_replay_canonical_lifecycle_operation(
            self, operation, canonical, request,
        )
        .await
    }

    async fn list_non_terminal_lifecycle_operations(
        &self,
    ) -> Result<Vec<OperationRecord>, StoreError> {
        let rows = sqlx::query(
            "SELECT id, resource_id, kind, state, provider_operation_id, error_category, error_message FROM operations WHERE kind LIKE 'lifecycle:%' AND state NOT IN ('succeeded', 'failed') ORDER BY id",
        )
        .fetch_all(&self.pool)
        .await
        .map_err(StoreError::Database)?;
        rows.iter().map(operation_from_row).collect()
    }

    async fn update_operation(
        &self,
        id: Uuid,
        state: OperationState,
        provider_operation_id: Option<&str>,
        error_category: Option<&str>,
        error_message: Option<&str>,
    ) -> Result<OperationRecord, StoreError> {
        let mut connection = self.pool.acquire().await.map_err(StoreError::Database)?;
        sqlx::query("BEGIN IMMEDIATE")
            .execute(&mut *connection)
            .await
            .map_err(StoreError::Database)?;
        let outcome: Result<(), StoreError> = async {
            let row = sqlx::query(
                "SELECT id, resource_id, kind, state, provider_operation_id, error_category, error_message FROM operations WHERE id = ?",
            )
            .bind(id.to_string())
            .fetch_optional(&mut *connection)
            .await
            .map_err(StoreError::Database)?
            .ok_or(StoreError::OperationNotFound)?;
            let current = operation_from_row(&row)?;
            if matches!(
                current.state,
                OperationState::Succeeded | OperationState::Failed
            ) {
                if current
                    .provider_operation_id
                    .as_deref()
                    .is_some_and(|existing| {
                        provider_operation_id.is_some_and(|incoming| incoming != existing)
                    })
                {
                    return Err(StoreError::Corrupt(
                        "terminal operation provider identity conflicts with durable state"
                            .to_owned(),
                    ));
                }
                if current.state != state {
                    if matches!(state, OperationState::Succeeded | OperationState::Failed) {
                        return Err(StoreError::Corrupt(
                            "terminal operation state cannot conflict with durable state"
                                .to_owned(),
                        ));
                    }
                    // A stale non-terminal projection may arrive after the
                    // terminal writer. Preserve the terminal truth and let
                    // the caller continue idempotently.
                    return Ok(());
                }

                // An equivalent terminal projection may fill in durable
                // evidence that was absent from the first terminal write,
                // but it can never replace an existing provider identity.
                sqlx::query("UPDATE operations SET provider_operation_id = COALESCE(?, provider_operation_id), error_category = COALESCE(?, error_category), error_message = COALESCE(?, error_message) WHERE id = ?")
                    .bind(provider_operation_id)
                    .bind(error_category)
                    .bind(error_message)
                    .bind(id.to_string())
                    .execute(&mut *connection)
                    .await
                    .map_err(StoreError::Database)?;
                return Ok(());
            }
            sqlx::query("UPDATE operations SET state = ?, provider_operation_id = ?, error_category = ?, error_message = ? WHERE id = ?")
                .bind(state.as_str())
                // `None` intentionally clears a stale provider-operation
                // identity when retry recovery mints a new attempt. A
                // non-None value was checked above for identity consistency.
                .bind(provider_operation_id)
                .bind(error_category)
                .bind(error_message)
                .bind(id.to_string())
                .execute(&mut *connection)
                .await
                .map_err(StoreError::Database)?;
            let now = Utc::now().to_rfc3339();
            let started_at = (!matches!(state, OperationState::Pending)).then_some(now.clone());
            let finished_at = matches!(state, OperationState::Succeeded | OperationState::Failed).then_some(now);
            sqlx::query("UPDATE canonical_operation_metadata SET started_at=COALESCE(started_at, ?), finished_at=?, error=? WHERE operation_id=?")
                .bind(started_at).bind(finished_at).bind(error_category).bind(id.to_string())
                .execute(&mut *connection).await.map_err(StoreError::Database)?;
            Ok(())
        }
        .await;
        SqliteStore::commit_or_rollback(&mut connection, outcome).await?;
        drop(connection);
        self.get_operation(id).await
    }

    async fn update_canonical_operation_lifecycle(
        &self,
        id: Uuid,
        update: &CanonicalOperationLifecycleUpdate,
    ) -> Result<CanonicalOperationRecord, StoreError> {
        validate_canonical_lifecycle_update(update)?;
        let mut connection = self.pool.acquire().await.map_err(StoreError::Database)?;
        sqlx::query("BEGIN IMMEDIATE")
            .execute(&mut *connection)
            .await
            .map_err(StoreError::Database)?;
        let result: Result<(), StoreError> = async {
            let operation = sqlx::query("SELECT state FROM operations WHERE id = ?")
                .bind(id.to_string()).fetch_optional(&mut *connection).await.map_err(StoreError::Database)?
                .ok_or(StoreError::OperationNotFound)?;
            let canonical = sqlx::query("SELECT operation_id FROM canonical_operation_metadata WHERE operation_id = ?")
                .bind(id.to_string()).fetch_optional(&mut *connection).await.map_err(StoreError::Database)?
                .ok_or_else(|| StoreError::Corrupt("canonical lifecycle metadata is missing".into()))?;
            let _ = canonical;
            let current_state: String = operation.try_get("state").map_err(StoreError::Database)?;
            if current_state == OperationState::Succeeded.as_str() && update.state != OperationState::Succeeded
                || current_state == OperationState::Failed.as_str() && update.state != OperationState::Failed {
                return Err(StoreError::Corrupt("terminal operation state cannot regress".into()));
            }
            sqlx::query("UPDATE operations SET state = ? WHERE id = ?")
                .bind(update.state.as_str()).bind(id.to_string()).execute(&mut *connection).await.map_err(StoreError::Database)?;
            sqlx::query("UPDATE canonical_operation_metadata SET attempt = ?, started_at = ?, finished_at = ?, error = ? WHERE operation_id = ?")
                .bind(update.attempt as i64).bind(&update.started_at).bind(&update.finished_at).bind(&update.public_error).bind(id.to_string())
                .execute(&mut *connection).await.map_err(StoreError::Database)?;
            Ok(())
        }.await;
        SqliteStore::commit_or_rollback(&mut connection, result).await?;
        drop(connection);
        self.get_canonical_operation(id).await
    }

    async fn attach_provider_reference(
        &self,
        reference: &ProviderReference,
    ) -> Result<(), StoreError> {
        let result = sqlx::query("INSERT INTO provider_refs (resource_id, provider_name, provider_resource_id) VALUES (?, ?, ?)")
            .bind(reference.resource_id.to_string())
            .bind(&reference.provider_name)
            .bind(&reference.provider_resource_id)
            .execute(&self.pool)
            .await;
        match result {
            Ok(_) => Ok(()),
            Err(sqlx::Error::Database(error)) if error.is_unique_violation() => {
                Err(StoreError::ProviderReferenceAlreadyExists)
            }
            Err(error) => Err(StoreError::Database(error)),
        }
    }

    async fn get_provider_reference(
        &self,
        resource_id: Uuid,
        provider_name: &str,
    ) -> Result<ProviderReference, StoreError> {
        let row = sqlx::query("SELECT resource_id, provider_name, provider_resource_id FROM provider_refs WHERE resource_id = ? AND provider_name = ?")
            .bind(resource_id.to_string())
            .bind(provider_name)
            .fetch_optional(&self.pool)
            .await
            .map_err(StoreError::Database)?
            .ok_or(StoreError::ProviderReferenceNotFound)?;
        Ok(ProviderReference {
            resource_id: parse_uuid(row.get("resource_id"))?,
            provider_name: row.get("provider_name"),
            provider_resource_id: row.get("provider_resource_id"),
        })
    }

    async fn insert_agent_command(
        &self,
        command: &AgentCommandRecord,
    ) -> Result<AgentCommandRecord, StoreError> {
        let result = sqlx::query(
            "INSERT INTO agent_commands (command_id, idempotency_key, operation_id, resource_id, agent_id, agent_epoch, payload_fingerprint_sha256, payload, state, accepted_sequence, last_sequence, provider_operation_id, provider_resource_id) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)",
        )
        .bind(&command.command_id)
        .bind(&command.idempotency_key)
        .bind(command.operation_id.to_string())
        .bind(command.resource_id.to_string())
        .bind(&command.agent_id)
        .bind(&command.agent_epoch)
        .bind(&command.payload_fingerprint_sha256)
        .bind(&command.payload)
        .bind(command.state.as_str())
        .bind(sqlite_sequence(command.accepted_sequence)?)
        .bind(sqlite_sequence(command.last_sequence)?)
        .bind(&command.provider_operation_id)
        .bind(&command.provider_resource_id)
        .execute(&self.pool)
        .await;
        match result {
            Ok(_) => Ok(command.clone()),
            Err(sqlx::Error::Database(error)) if error.is_unique_violation() => {
                let existing = self
                    .get_agent_command_by_idempotency_key(&command.idempotency_key)
                    .await?;
                if existing.command_id == command.command_id
                    && existing.operation_id == command.operation_id
                    && existing.resource_id == command.resource_id
                    && existing.agent_id == command.agent_id
                    && existing.agent_epoch == command.agent_epoch
                    && existing.payload_fingerprint_sha256 == command.payload_fingerprint_sha256
                    && existing.payload == command.payload
                {
                    Ok(existing)
                } else {
                    Err(StoreError::Corrupt(
                        "agent command idempotency identity conflicts with durable state"
                            .to_owned(),
                    ))
                }
            }
            Err(error) => Err(StoreError::Database(error)),
        }
    }

    async fn get_agent_command(&self, command_id: &str) -> Result<AgentCommandRecord, StoreError> {
        let row = sqlx::query("SELECT command_id, idempotency_key, operation_id, resource_id, agent_id, agent_epoch, payload_fingerprint_sha256, payload, state, accepted_sequence, last_sequence, provider_operation_id, provider_resource_id FROM agent_commands WHERE command_id = ?")
            .bind(command_id)
            .fetch_optional(&self.pool)
            .await
            .map_err(StoreError::Database)?
            .ok_or(StoreError::OperationNotFound)?;
        agent_command_from_row(&row)
    }

    async fn get_agent_command_by_idempotency_key(
        &self,
        idempotency_key: &str,
    ) -> Result<AgentCommandRecord, StoreError> {
        let row = sqlx::query("SELECT command_id, idempotency_key, operation_id, resource_id, agent_id, agent_epoch, payload_fingerprint_sha256, payload, state, accepted_sequence, last_sequence, provider_operation_id, provider_resource_id FROM agent_commands WHERE idempotency_key = ?")
            .bind(idempotency_key)
            .fetch_optional(&self.pool)
            .await
            .map_err(StoreError::Database)?
            .ok_or(StoreError::OperationNotFound)?;
        agent_command_from_row(&row)
    }

    async fn get_agent_command_by_operation(
        &self,
        operation_id: Uuid,
    ) -> Result<AgentCommandRecord, StoreError> {
        let row = sqlx::query("SELECT command_id, idempotency_key, operation_id, resource_id, agent_id, agent_epoch, payload_fingerprint_sha256, payload, state, accepted_sequence, last_sequence, provider_operation_id, provider_resource_id FROM agent_commands WHERE operation_id = ? ORDER BY created_at DESC LIMIT 1")
            .bind(operation_id.to_string())
            .fetch_optional(&self.pool)
            .await
            .map_err(StoreError::Database)?
            .ok_or(StoreError::OperationNotFound)?;
        agent_command_from_row(&row)
    }

    async fn update_agent_command(
        &self,
        command_id: &str,
        state: AgentCommandState,
        accepted_sequence: u64,
        last_sequence: u64,
        provider_operation_id: Option<&str>,
        provider_resource_id: Option<&str>,
    ) -> Result<AgentCommandRecord, StoreError> {
        let mut backoff = Duration::from_millis(10);
        for attempt in 0..SQLITE_BUSY_MAX_ATTEMPTS {
            match update_agent_command_once_sqlite(
                self,
                command_id,
                state,
                accepted_sequence,
                last_sequence,
                provider_operation_id,
                provider_resource_id,
            )
            .await
            {
                Err(StoreError::Database(error))
                    if is_sqlite_busy(&error) && attempt + 1 < SQLITE_BUSY_MAX_ATTEMPTS =>
                {
                    tokio::time::sleep(backoff).await;
                    backoff *= 2;
                }
                outcome => return outcome,
            }
        }
        unreachable!("the loop returns on the final attempt")
    }

    async fn list_recoverable_agent_commands(&self) -> Result<Vec<AgentCommandRecord>, StoreError> {
        let rows = sqlx::query("SELECT command_id, idempotency_key, operation_id, resource_id, agent_id, agent_epoch, payload_fingerprint_sha256, payload, state, accepted_sequence, last_sequence, provider_operation_id, provider_resource_id FROM agent_commands WHERE state IN ('pending', 'accepted', 'running', 'retryable', 'unknown_outcome') ORDER BY created_at ASC")
            .fetch_all(&self.pool)
            .await
            .map_err(StoreError::Database)?;
        rows.iter().map(agent_command_from_row).collect()
    }

    async fn insert_artifact_transfer(
        &self,
        transfer: &ArtifactTransferRecord,
    ) -> Result<ArtifactTransferRecord, StoreError> {
        crate::artifact_transfer::insert(&self.pool, transfer).await
    }

    async fn get_artifact_transfer(
        &self,
        transfer_id: &str,
    ) -> Result<ArtifactTransferRecord, StoreError> {
        crate::artifact_transfer::get(&self.pool, transfer_id).await
    }

    async fn rebind_artifact_transfer_epoch(
        &self,
        transfer_id: &str,
        expected_agent_epoch: &str,
        new_agent_epoch: &str,
    ) -> Result<ArtifactTransferRecord, StoreError> {
        crate::artifact_transfer::rebind_epoch(
            &self.pool,
            transfer_id,
            expected_agent_epoch,
            new_agent_epoch,
        )
        .await
    }

    async fn update_artifact_transfer(
        &self,
        transfer_id: &str,
        expected_agent_epoch: &str,
        update: ArtifactTransferUpdate,
    ) -> Result<ArtifactTransferRecord, StoreError> {
        crate::artifact_transfer::update(&self.pool, transfer_id, expected_agent_epoch, update)
            .await
    }

    async fn list_recoverable_artifact_transfers(
        &self,
    ) -> Result<Vec<ArtifactTransferRecord>, StoreError> {
        crate::artifact_transfer::list_recoverable(&self.pool).await
    }

    async fn expire_transfers_of_terminal_operations(&self) -> Result<u64, StoreError> {
        crate::artifact_transfer::expire_transfers_of_terminal_operations(&self.pool).await
    }

    async fn insert_image_overlay(
        &self,
        overlay: &ImageOverlayOwnershipRecord,
    ) -> Result<ImageOverlayOwnershipRecord, StoreError> {
        validate_image_overlay(overlay)?;
        let result = sqlx::query(
            "INSERT INTO image_overlay_ownership (overlay_id, resource_id, operation_id, command_id, agent_id, agent_epoch, base_sha256, base_format, overlay_format, state, created_at, updated_at) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)",
        )
        .bind(&overlay.overlay_id)
        .bind(overlay.identity.resource_id.to_string())
        .bind(overlay.identity.operation_id.to_string())
        .bind(&overlay.identity.command_id)
        .bind(&overlay.identity.agent_id)
        .bind(&overlay.identity.agent_epoch)
        .bind(&overlay.identity.base_sha256)
        .bind(&overlay.identity.base_format)
        .bind(&overlay.identity.overlay_format)
        .bind(overlay.state.as_str())
        .bind(&overlay.created_at)
        .bind(&overlay.updated_at)
        .execute(&self.pool)
        .await;
        match result {
            Ok(_) => self.get_image_overlay(&overlay.overlay_id).await,
            Err(sqlx::Error::Database(error)) if error.is_unique_violation() => {
                let existing = self.get_image_overlay(&overlay.overlay_id).await;
                match existing {
                    Ok(existing) if image_overlay_identity_matches(&existing, overlay) => {
                        Ok(existing)
                    }
                    Ok(_) => Err(StoreError::ImageOverlayConflict(
                        "overlay identity conflicts with durable state".to_owned(),
                    )),
                    Err(StoreError::ImageOverlayNotFound) => {
                        let identity_exists: i64 = sqlx::query_scalar(
                            "SELECT COUNT(*) FROM image_overlay_ownership WHERE resource_id = ? AND operation_id = ? AND command_id = ?",
                        )
                        .bind(overlay.identity.resource_id.to_string())
                        .bind(overlay.identity.operation_id.to_string())
                        .bind(&overlay.identity.command_id)
                        .fetch_one(&self.pool)
                        .await
                        .map_err(StoreError::Database)?;
                        if identity_exists != 0 {
                            Err(StoreError::ImageOverlayConflict(
                                "resource operation already owns an overlay".to_owned(),
                            ))
                        } else {
                            Err(StoreError::ImageOverlayNotFound)
                        }
                    }
                    Err(error) => Err(error),
                }
            }
            Err(error) => Err(StoreError::Database(error)),
        }
    }

    async fn get_image_overlay(
        &self,
        overlay_id: &str,
    ) -> Result<ImageOverlayOwnershipRecord, StoreError> {
        let row = sqlx::query(
            "SELECT overlay_id, resource_id, operation_id, command_id, agent_id, agent_epoch, base_sha256, base_format, overlay_format, state, created_at, updated_at FROM image_overlay_ownership WHERE overlay_id = ?",
        )
        .bind(overlay_id)
        .fetch_optional(&self.pool)
        .await
        .map_err(StoreError::Database)?
        .ok_or(StoreError::ImageOverlayNotFound)?;
        image_overlay_from_row(&row)
    }

    async fn update_image_overlay(
        &self,
        overlay_id: &str,
        expected_identity: &ImageOverlayIdentity,
        update: ImageOverlayUpdate,
    ) -> Result<ImageOverlayOwnershipRecord, StoreError> {
        validate_image_overlay_identity(expected_identity)?;
        let mut transaction = self.pool.begin().await.map_err(StoreError::Database)?;
        let row = sqlx::query(
            "SELECT overlay_id, resource_id, operation_id, command_id, agent_id, agent_epoch, base_sha256, base_format, overlay_format, state, created_at, updated_at FROM image_overlay_ownership WHERE overlay_id = ?",
        )
        .bind(overlay_id)
        .fetch_optional(&mut *transaction)
        .await
        .map_err(StoreError::Database)?
        .ok_or(StoreError::ImageOverlayNotFound)?;
        let current = image_overlay_from_row(&row)?;
        ensure_image_overlay_identity(&current, expected_identity)?;
        validate_image_overlay_transition(current.state, update.state)?;
        if current.state == update.state {
            transaction.rollback().await.map_err(StoreError::Database)?;
            return Ok(current);
        }
        let result = sqlx::query(
            "UPDATE image_overlay_ownership SET state = ?, updated_at = CURRENT_TIMESTAMP WHERE overlay_id = ? AND resource_id = ? AND operation_id = ? AND command_id = ? AND agent_id = ? AND agent_epoch = ? AND base_sha256 = ? AND base_format = ? AND overlay_format = ? AND state = ?",
        )
        .bind(update.state.as_str())
        .bind(overlay_id)
        .bind(expected_identity.resource_id.to_string())
        .bind(expected_identity.operation_id.to_string())
        .bind(&expected_identity.command_id)
        .bind(&expected_identity.agent_id)
        .bind(&expected_identity.agent_epoch)
        .bind(&expected_identity.base_sha256)
        .bind(&expected_identity.base_format)
        .bind(&expected_identity.overlay_format)
        .bind(current.state.as_str())
        .execute(&mut *transaction)
        .await
        .map_err(StoreError::Database)?;
        if result.rows_affected() != 1 {
            return Err(StoreError::ImageOverlayConflict(
                "concurrent overlay state change".to_owned(),
            ));
        }
        transaction.commit().await.map_err(StoreError::Database)?;
        self.get_image_overlay(overlay_id).await
    }

    async fn list_image_overlays(
        &self,
        resource_id: Uuid,
    ) -> Result<Vec<ImageOverlayOwnershipRecord>, StoreError> {
        let rows = sqlx::query(
            "SELECT overlay_id, resource_id, operation_id, command_id, agent_id, agent_epoch, base_sha256, base_format, overlay_format, state, created_at, updated_at FROM image_overlay_ownership WHERE resource_id = ? ORDER BY overlay_id",
        )
        .bind(resource_id.to_string())
        .fetch_all(&self.pool)
        .await
        .map_err(StoreError::Database)?;
        rows.iter().map(image_overlay_from_row).collect()
    }

    async fn count_image_overlay_references(
        &self,
        base_sha256: &str,
        base_format: &str,
    ) -> Result<u64, StoreError> {
        validate_base_identity(base_sha256, base_format)?;
        let count: i64 = sqlx::query_scalar(
            "SELECT COUNT(*) FROM image_overlay_ownership WHERE base_sha256 = ? AND base_format = ? AND state != 'deleted'",
        )
        .bind(base_sha256)
        .bind(base_format)
        .fetch_one(&self.pool)
        .await
        .map_err(StoreError::Database)?;
        u64::try_from(count)
            .map_err(|_| StoreError::Corrupt("negative overlay reference count".to_owned()))
    }

    async fn delete_image_overlay(
        &self,
        overlay_id: &str,
        expected_identity: &ImageOverlayIdentity,
    ) -> Result<ImageOverlayOwnershipRecord, StoreError> {
        let current = self.get_image_overlay(overlay_id).await?;
        if current.state == ImageOverlayState::Deleted {
            ensure_image_overlay_identity(&current, expected_identity)?;
            return Ok(current);
        }
        let deleting = self
            .update_image_overlay(
                overlay_id,
                expected_identity,
                ImageOverlayUpdate {
                    state: ImageOverlayState::Deleting,
                },
            )
            .await?;
        if deleting.state == ImageOverlayState::Deleted {
            return Ok(deleting);
        }
        self.update_image_overlay(
            overlay_id,
            expected_identity,
            ImageOverlayUpdate {
                state: ImageOverlayState::Deleted,
            },
        )
        .await
    }

    async fn increment_operation_retry(&self, operation_id: Uuid) -> Result<u8, StoreError> {
        let mut transaction = self.pool.begin().await.map_err(StoreError::Database)?;
        let current: Option<i64> =
            sqlx::query_scalar("SELECT attempts FROM operation_retry_state WHERE operation_id = ?")
                .bind(operation_id.to_string())
                .fetch_optional(&mut *transaction)
                .await
                .map_err(StoreError::Database)?;
        let attempts = current.unwrap_or(0).saturating_add(1);
        if current.is_some() {
            sqlx::query("UPDATE operation_retry_state SET attempts = ?, updated_at = CURRENT_TIMESTAMP WHERE operation_id = ?")
                .bind(attempts)
                .bind(operation_id.to_string())
                .execute(&mut *transaction)
                .await
                .map_err(StoreError::Database)?;
        } else {
            sqlx::query("INSERT INTO operation_retry_state (operation_id, attempts) VALUES (?, ?)")
                .bind(operation_id.to_string())
                .bind(attempts)
                .execute(&mut *transaction)
                .await
                .map_err(StoreError::Database)?;
        }
        // Synchronise canonical operation attempt when canonical metadata
        // exists; a no-op for legacy operations without metadata.
        sqlx::query("UPDATE canonical_operation_metadata SET attempt = ? WHERE operation_id = ?")
            .bind(attempts)
            .bind(operation_id.to_string())
            .execute(&mut *transaction)
            .await
            .map_err(StoreError::Database)?;

        transaction.commit().await.map_err(StoreError::Database)?;
        u8::try_from(attempts)
            .map_err(|_| StoreError::Corrupt("operation retry count exceeds limit".to_owned()))
    }

    async fn insert_resource_and_operation(
        &self,
        resource: &ResourceRecord,
        operation: &OperationRecord,
        expected_placement_allocation_id: Option<&str>,
    ) -> Result<(), StoreError> {
        let mut transaction = self.pool.begin().await.map_err(StoreError::Database)?;
        let insert_resource = sqlx::query("INSERT INTO resources (id, kind, project_id, generation, observed_generation, desired_state, observed_state, provider_id) VALUES (?, ?, ?, ?, ?, ?, ?, ?)")
            .bind(resource.id.to_string())
            .bind(&resource.kind)
            .bind(&resource.project_id)
            .bind(resource.generation)
            .bind(resource.observed_generation)
            .bind(&resource.desired_state)
            .bind(&resource.observed_state)
            .bind(&resource.provider_id)
            .execute(&mut *transaction)
            .await;
        match insert_resource {
            Ok(_) => {}
            Err(sqlx::Error::Database(error)) if error.is_unique_violation() => {
                return Err(StoreError::ResourceAlreadyExists);
            }
            Err(error) => return Err(StoreError::Database(error)),
        }
        // ASR-018: the consumer intent must not outlive its placement
        // allocation. The resource insert succeeded (or already existed), so
        // the durable create intent is only committed when the allocation it
        // references is still present. A startup orphan reconciliation may
        // have deleted it while this create was between allocation commit and
        // intent persistence; that create must fail closed instead of
        // persisting a consumer without capacity accounting.
        if let Some(allocation_id) = expected_placement_allocation_id {
            let allocation_exists: Option<String> =
                sqlx::query_scalar("SELECT id FROM placement_allocations WHERE id = ?")
                    .bind(allocation_id)
                    .fetch_optional(&mut *transaction)
                    .await
                    .map_err(StoreError::Database)?;
            if allocation_exists.is_none() {
                return Err(StoreError::PlacementAllocationNotFound);
            }
        }
        sqlx::query("INSERT INTO operations (id, resource_id, state, provider_operation_id, error_category, error_message) VALUES (?, ?, ?, ?, ?, ?)")
            .bind(operation.id.to_string())
            .bind(operation.resource_id.to_string())
            .bind(operation.state.as_str())
            .bind(&operation.provider_operation_id)
            .bind(&operation.error_category)
            .bind(&operation.error_message)
            .execute(&mut *transaction)
            .await
            .map_err(StoreError::Database)?;
        transaction.commit().await.map_err(StoreError::Database)
    }

    async fn revive_resource_and_operation(
        &self,
        id: Uuid,
        expected_generation: i64,
        desired_state: &str,
        observed_state: &str,
        observed_generation: i64,
        provider_id: Option<&str>,
        operation: &OperationRecord,
        expected_placement_allocation_id: Option<&str>,
    ) -> Result<ResourceRecord, StoreError> {
        let mut transaction = self.pool.begin().await.map_err(StoreError::Database)?;
        let update = sqlx::query("UPDATE resources SET generation = generation + 1, desired_state = ?, observed_state = ?, observed_generation = ?, provider_id = ? WHERE id = ? AND generation = ?")
            .bind(desired_state)
            .bind(observed_state)
            .bind(observed_generation)
            .bind(provider_id)
            .bind(id.to_string())
            .bind(expected_generation)
            .execute(&mut *transaction)
            .await
            .map_err(StoreError::Database)?;
        if update.rows_affected() == 0 {
            // The generation fence must be evaluated on the SAME transaction
            // connection: the write lock is still held here, and a deferred
            // read on a second connection would hit SQLITE_BUSY instead of
            // classifying the fence miss.
            let exists: Option<String> =
                sqlx::query_scalar("SELECT id FROM resources WHERE id = ?")
                    .bind(id.to_string())
                    .fetch_optional(&mut *transaction)
                    .await
                    .map_err(StoreError::Database)?;
            return if exists.is_some() {
                Err(StoreError::StaleGeneration)
            } else {
                Err(StoreError::ResourceNotFound)
            };
        }
        // ASR-018: the revived consumer intent must not outlive its placement
        // allocation (identical to the `insert_resource_and_operation` fence).
        if let Some(allocation_id) = expected_placement_allocation_id {
            let allocation_exists: Option<String> =
                sqlx::query_scalar("SELECT id FROM placement_allocations WHERE id = ?")
                    .bind(allocation_id)
                    .fetch_optional(&mut *transaction)
                    .await
                    .map_err(StoreError::Database)?;
            if allocation_exists.is_none() {
                return Err(StoreError::PlacementAllocationNotFound);
            }
        }
        let insert = sqlx::query("INSERT INTO operations (id, resource_id, state, provider_operation_id, error_category, error_message) VALUES (?, ?, ?, ?, ?, ?)")
            .bind(operation.id.to_string())
            .bind(operation.resource_id.to_string())
            .bind(operation.state.as_str())
            .bind(&operation.provider_operation_id)
            .bind(&operation.error_category)
            .bind(&operation.error_message)
            .execute(&mut *transaction)
            .await;
        match insert {
            Ok(_) => {}
            Err(sqlx::Error::Database(error)) if error.is_unique_violation() => {
                return Err(StoreError::ResourceAlreadyExists);
            }
            Err(error) => return Err(StoreError::Database(error)),
        }
        transaction.commit().await.map_err(StoreError::Database)?;
        self.get_resource(id).await
    }

    async fn readiness_check(&self) -> Result<(), StoreError> {
        sqlx::query("SELECT 1")
            .execute(&self.pool)
            .await
            .map(|_| ())
            .map_err(StoreError::Database)
    }
}

// The port implementations delegate to the inherent adapter methods, which
// remain the canonical SQL bodies. Inherent methods take name-resolution
// precedence over trait methods, so `self.method(...)` inside these bodies
// resolves to the inherent implementation and does not recurse into the trait.
//
// Hazard: silent infinite recursion (stack exhaustion at runtime, not a
// compile error) is still possible in exactly two cases:
//   1. the inherent method is removed or renamed without deleting its
//      delegation below — the trait method is then the only candidate, and
//      the delegation calls itself (application code calls these methods
//      through the ports, so removal is not guaranteed to error elsewhere);
//   2. the inherent receiver changes from `&self` to `&mut self` — through
//      `&SqliteStore` only the `&self` trait method is applicable, so the
//      delegation resolves to itself.
// An argument or return-type drift, by contrast, is a compile error at the
// delegation site: once name resolution commits to the inherent method there
// is no fallback to the trait. Keep each delegation paired with its inherent
// method; the port conformance tests exercise every method and turn any
// recursion into a loud test failure, but they are the safety net, not the
// primary guard.

#[async_trait]
impl ComputeRepository for SqliteStore {
    async fn list_resources_by_kind(&self, kind: &str) -> Result<Vec<ResourceRecord>, StoreError> {
        self.list_resources_by_kind(kind).await
    }
}
