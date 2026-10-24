//! PP.6 PostgreSQL 16 D4 writer-exclusion barrier and capture facts.
//!
//! SPEC-0050 §3 / ADR-0189 D4 require a database-side admission barrier for
//! the whole `pg_dump` capture: all O3K writer-capable LOGIN roles are
//! disabled, pre-existing sessions are terminated, and a first-match
//! `pg_hba.conf` policy admits only the backup host and the read-only
//! `o3k_backup_dump` role for the O3K database. Every other network path,
//! including `local all all reject`, is rejected. The policy is reloaded with
//! `pg_reload_conf()` and verified through `pg_hba_file_rules`; fresh
//! Unix-socket, application and maintenance reconnects must fail before the
//! dump starts.
//!
//! This module owns the SQL for the barrier. It deliberately does not run host
//! commands and does not decide the operator interface; `bins/o3k` supplies
//! the installation policy and the dump tool boundary.
//!
//! The prior admission file is saved beside `pg_hba.conf` with a SHA-256
//! digest. Restoration happens only after verified publication or a safe
//! abort; an interrupted process leaves the saved file in place so the next
//! invocation can restore admission before doing anything else.

use std::{
    fs,
    io::Write,
    os::unix::fs::{OpenOptionsExt, PermissionsExt},
    path::{Path, PathBuf},
    time::Duration,
};

use rustix::process::{Pid, Signal};
use serde_json::Value;
use sha2::{Digest, Sha256};
use sqlx::{
    Connection, Row,
    postgres::{PgConnectOptions, PgConnection},
};
use thiserror::Error;

/// Suffix of the saved pre-barrier admission file.
pub const SAVED_ADMISSION_SUFFIX: &str = ".o3k-pp6-saved";
/// Suffix of the saved-digest file.
pub const SAVED_DIGEST_SUFFIX: &str = ".o3k-pp6-saved.sha256";
/// Stable marker that identifies an installed barrier block.
pub const BARRIER_MARKER: &str = "O3K-PP6-D4-ADMISSION-BARRIER-V1";
/// Marker that closes the installed barrier block.
pub const BARRIER_END_MARKER: &str = "O3K-PP6-D4-ADMISSION-BARRIER-END-V1";
/// Manifest consistency method for the PostgreSQL custom dump.
pub const POSTGRES_SNAPSHOT_METHOD: &str = "postgresql_native_dump";
/// Database member name for the opaque custom dump.
pub const DATABASE_MEMBER: &str = "database/o3k.dump";
/// Media type of the opaque custom dump.
pub const DATABASE_MEDIA_TYPE: &str = "application/vnd.postgresql.custom";

const RELOAD_POLL_INTERVAL: Duration = Duration::from_millis(50);
const RELOAD_POLL_ATTEMPTS: usize = 100;

/// Stable, secret-free barrier failure.
#[derive(Debug, Clone, PartialEq, Eq, Error)]
#[error("{reason}")]
pub struct BarrierError {
    reason: &'static str,
}

impl BarrierError {
    /// The stable reason code emitted to the operator.
    #[must_use]
    pub const fn reason(&self) -> &'static str {
        self.reason
    }
}

fn fail<T>(reason: &'static str) -> Result<T, BarrierError> {
    Err(BarrierError { reason })
}

/// O3K role policy from trusted installation configuration.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RolePolicy {
    /// Application writer roles; all are disabled during capture.
    pub writer_roles: Vec<String>,
    /// Read-only dump role, enabled only for the capture interval.
    pub dump_role: String,
    /// Restore-owner role; disabled during capture.
    pub restore_role: String,
    /// Distinct administrative control role that owns the control session.
    /// It is the only role allowed to be privileged.
    pub control_role: String,
}

impl RolePolicy {
    fn o3k_roles(&self) -> Vec<String> {
        let mut roles = self.writer_roles.clone();
        roles.push(self.dump_role.clone());
        roles.push(self.restore_role.clone());
        roles.sort();
        roles.dedup();
        roles
    }
}

/// Database-side admission policy derived from `SHOW hba_file` and trusted
/// configuration.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct AdmissionPolicy {
    /// O3K database name.
    pub database: String,
    /// Backup-host source address admitted for the dump role. Must be an IP
    /// literal; hostnames are rejected so the HBA rule cannot be ambiguous.
    pub backup_host: String,
    /// Read-only dump role.
    pub dump_role: String,
    /// `pg_hba` authentication method for the dump rule.
    pub auth_method: String,
}

impl AdmissionPolicy {
    fn dump_address(&self) -> Result<String, BarrierError> {
        let parsed: std::net::IpAddr = self.backup_host.parse().map_err(|_| BarrierError {
            reason: "backup-host-invalid",
        })?;
        Ok(match parsed {
            std::net::IpAddr::V4(_) => format!("{}/32", self.backup_host),
            std::net::IpAddr::V6(_) => format!("{}/128", self.backup_host),
        })
    }

    /// The ordered rules installed at the top of `pg_hba.conf`.
    fn rules(&self) -> Result<Vec<HbaRule>, BarrierError> {
        let address = self.dump_address()?;
        Ok(vec![
            HbaRule {
                kind: "host".to_owned(),
                database: self.database.clone(),
                user: self.dump_role.clone(),
                address: Some(address),
                auth_method: self.auth_method.clone(),
            },
            HbaRule {
                kind: "local".to_owned(),
                database: "all".to_owned(),
                user: "all".to_owned(),
                address: None,
                auth_method: "reject".to_owned(),
            },
            HbaRule {
                kind: "local".to_owned(),
                database: "replication".to_owned(),
                user: "all".to_owned(),
                address: None,
                auth_method: "reject".to_owned(),
            },
            HbaRule {
                kind: "host".to_owned(),
                database: "all".to_owned(),
                user: "all".to_owned(),
                address: Some("0.0.0.0/0".to_owned()),
                auth_method: "reject".to_owned(),
            },
            HbaRule {
                kind: "host".to_owned(),
                database: "all".to_owned(),
                user: "all".to_owned(),
                address: Some("::/0".to_owned()),
                auth_method: "reject".to_owned(),
            },
            HbaRule {
                kind: "host".to_owned(),
                database: "replication".to_owned(),
                user: "all".to_owned(),
                address: Some("0.0.0.0/0".to_owned()),
                auth_method: "reject".to_owned(),
            },
            HbaRule {
                kind: "host".to_owned(),
                database: "replication".to_owned(),
                user: "all".to_owned(),
                address: Some("::/0".to_owned()),
                auth_method: "reject".to_owned(),
            },
        ])
    }

    fn block(&self) -> Result<String, BarrierError> {
        let rules = self.rules()?;
        let mut block = String::new();
        for rule in &rules {
            block.push_str(&rule.line());
            block.push('\n');
        }
        Ok(block)
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
struct HbaRule {
    kind: String,
    database: String,
    user: String,
    address: Option<String>,
    auth_method: String,
}

impl HbaRule {
    fn line(&self) -> String {
        match &self.address {
            Some(address) => format!(
                "{} {} {} {} {}",
                self.kind, self.database, self.user, address, self.auth_method
            ),
            None => format!(
                "{} {} {} {}",
                self.kind, self.database, self.user, self.auth_method
            ),
        }
    }
}

/// A verified installed barrier. Dropping the guard restores the saved
/// admission bytes and signals the postmaster, so early returns and panics do
/// not leave the database unreachable. A hard kill cannot run `Drop`; the
/// saved file makes the next invocation recover admission first.
#[derive(Debug)]
pub struct AdmissionGuard {
    hba_path: PathBuf,
    data_directory: PathBuf,
    saved_path: PathBuf,
    digest_path: PathBuf,
    installed_sha256: String,
    restored: bool,
}

impl AdmissionGuard {
    /// Restores admission synchronously (used by `Drop`) and signals the
    /// postmaster to reload. Best effort: callers that need proof use
    /// [`Self::restore_and_verify`].
    pub fn restore_sync(&mut self) -> Result<(), BarrierError> {
        if self.restored {
            return Ok(());
        }
        restore_saved_admission(&self.hba_path, &self.saved_path, &self.digest_path)?;
        self.restored = true;
        signal_postmaster(&self.data_directory);
        Ok(())
    }

    /// Restores admission, signals the postmaster and waits for the control
    /// role to be admitted again. This is the verified publication/safe-abort
    /// path.
    pub async fn restore_and_verify(&mut self, control_url: &str) -> Result<(), BarrierError> {
        self.restore_sync()?;
        verify_reload_by_control(control_url).await
    }

    /// Whether restoration has already completed.
    #[must_use]
    pub const fn is_restored(&self) -> bool {
        self.restored
    }

    /// SHA-256 of the installed `pg_hba.conf` bytes, recorded as the barrier
    /// generation.
    #[must_use]
    pub fn installed_sha256(&self) -> &str {
        &self.installed_sha256
    }

    /// Re-hashes the admission file and rejects a barrier loss.
    pub fn verify_file_unchanged(&self) -> Result<(), BarrierError> {
        let sha = sha256_file(&self.hba_path).map_err(|_| BarrierError {
            reason: "admission-barrier-unreadable",
        })?;
        if sha != self.installed_sha256 {
            return fail("admission-barrier-lost");
        }
        Ok(())
    }
}

impl Drop for AdmissionGuard {
    fn drop(&mut self) {
        let _ = self.restore_sync();
    }
}

/// Facts read from the control session before the writer barrier closes.
#[derive(Debug, Clone)]
pub struct PgSnapshotFacts {
    /// `SHOW server_version`.
    pub server_version: String,
    /// Applied SQLx migrations as `(version, checksum bytes)`.
    pub migrations: Vec<(u64, Vec<u8>)>,
    /// Baseline state inventory with `empty_state_included` populated.
    pub state_inventory: Vec<Value>,
    /// `drained` or `recorded_unknown`.
    pub in_flight_operations: &'static str,
    /// Stable non-terminal Operation ids.
    pub in_flight_operation_ids: Vec<String>,
    /// `txid_current()` value observed at the capture cut.
    pub capture_xid: i64,
}

fn valid_identifier(name: &str) -> bool {
    !name.is_empty()
        && name.len() <= 63
        && name
            .bytes()
            .all(|byte| byte.is_ascii_lowercase() || byte.is_ascii_digit() || byte == b'_')
        && !name.starts_with(|c: char| c.is_ascii_digit())
}

fn quote_ident(name: &str) -> Result<String, BarrierError> {
    if !valid_identifier(name) {
        return fail("role-or-database-identifier-invalid");
    }
    Ok(format!("\"{name}\""))
}

fn sha256_bytes(bytes: &[u8]) -> String {
    hex_encode(&Sha256::digest(bytes))
}

fn hex_encode(bytes: &[u8]) -> String {
    const HEX: &[u8; 16] = b"0123456789abcdef";
    let mut output = String::with_capacity(bytes.len() * 2);
    for byte in bytes {
        output.push(char::from(HEX[usize::from(byte >> 4)]));
        output.push(char::from(HEX[usize::from(byte & 0x0f)]));
    }
    output
}

fn sha256_file(path: &Path) -> std::io::Result<String> {
    let bytes = fs::read(path)?;
    Ok(sha256_bytes(&bytes))
}

/// Inspects every O3K role and rejects privileged attributes, memberships and
/// unexpected LOGIN roles.
///
/// The control identity is the only explicitly allowed privileged/LOGIN role
/// outside the O3K set. Any other login role must be a system role (`pg_*`),
/// `postgres`, or the configured control role; otherwise the cluster has an
/// unrelated writer whose sessions the barrier cannot reason about.
pub async fn inspect_roles(
    connection: &mut PgConnection,
    policy: &RolePolicy,
) -> Result<(), BarrierError> {
    let expected = policy.o3k_roles();
    let rows = sqlx::query(
        "SELECT rolname, rolsuper, rolcreatedb, rolcreaterole, rolreplication, \
                rolbypassrls, rolinherit, rolcanlogin \
         FROM pg_roles WHERE rolname = ANY($1) ORDER BY rolname",
    )
    .bind(&expected)
    .fetch_all(&mut *connection)
    .await
    .map_err(|_| BarrierError {
        reason: "role-inspection-failed",
    })?;
    if rows.len() != expected.len() {
        return fail("expected-role-missing");
    }
    for row in &rows {
        let name: String = row.get("rolname");
        let privileged: bool = row.get("rolsuper")
            || row.get("rolcreatedb")
            || row.get("rolcreaterole")
            || row.get("rolreplication")
            || row.get("rolbypassrls");
        // The reviewed role matrix requires NOINHERIT for every O3K role.
        let inherits: bool = row.get("rolinherit");
        if privileged || inherits {
            let reason = if name == policy.dump_role {
                "dump-role-privileged"
            } else if name == policy.restore_role {
                "restore-role-privileged"
            } else {
                "writer-role-privileged"
            };
            return fail(reason);
        }
    }

    let memberships = sqlx::query(
        "SELECT member.rolname AS member_name, role.rolname AS role_name \
         FROM pg_auth_members m \
         JOIN pg_roles member ON member.oid = m.member \
         JOIN pg_roles role ON role.oid = m.roleid \
         WHERE member.rolname = ANY($1) OR role.rolname = ANY($1)",
    )
    .bind(&expected)
    .fetch_all(&mut *connection)
    .await
    .map_err(|_| BarrierError {
        reason: "role-membership-inspection-failed",
    })?;
    if !memberships.is_empty() {
        return fail("o3k-role-membership-rejected");
    }

    let unexpected = sqlx::query_scalar::<_, String>(
        "SELECT rolname FROM pg_roles \
         WHERE rolcanlogin \
           AND rolname <> ALL($1) \
           AND rolname NOT LIKE 'pg\\_%' \
           AND rolname <> 'postgres' \
         ORDER BY rolname",
    )
    .bind(&expected)
    .fetch_all(&mut *connection)
    .await
    .map_err(|_| BarrierError {
        reason: "role-inspection-failed",
    })?;
    let unexpected: Vec<String> = unexpected
        .into_iter()
        .filter(|role| role != &policy.control_role)
        .collect();
    if !unexpected.is_empty() {
        return fail("unexpected-login-role");
    }
    Ok(())
}

/// Verifies the dump role has SELECT on every inventoried application table
/// and no write/DDL privilege.
pub async fn verify_dump_role_grants(
    connection: &mut PgConnection,
    policy: &RolePolicy,
    inventory: &[Value],
) -> Result<(), BarrierError> {
    let mut tables = Vec::new();
    for entry in inventory {
        let Some(objects) = entry.get("postgres_objects").and_then(Value::as_array) else {
            return fail("state-inventory-invalid");
        };
        for object in objects {
            if object.get("kind").and_then(Value::as_str) != Some("table") {
                continue;
            }
            let schema = object
                .get("schema")
                .and_then(Value::as_str)
                .unwrap_or_default();
            let name = object
                .get("name")
                .and_then(Value::as_str)
                .unwrap_or_default();
            if schema != "public" || !valid_identifier(name) {
                return fail("state-inventory-invalid");
            }
            tables.push(name.to_owned());
        }
    }
    if tables.is_empty() {
        return fail("state-inventory-empty");
    }
    let missing: i64 = sqlx::query_scalar(
        "SELECT count(*) FROM unnest($1::text[]) AS t(name) \
         WHERE NOT has_table_privilege($2, format('public.%I', t.name), 'SELECT')",
    )
    .bind(&tables)
    .bind(&policy.dump_role)
    .fetch_one(&mut *connection)
    .await
    .map_err(|_| BarrierError {
        reason: "dump-role-grant-inspection-failed",
    })?;
    if missing != 0 {
        return fail("dump-role-missing-select-grant");
    }
    let writable: i64 = sqlx::query_scalar(
        "SELECT count(*) FROM unnest($1::text[]) AS t(name) \
         WHERE has_table_privilege($2, format('public.%I', t.name), 'INSERT,UPDATE,DELETE,TRUNCATE')",
    )
    .bind(&tables)
    .bind(&policy.dump_role)
    .fetch_one(&mut *connection)
    .await
    .map_err(|_| BarrierError {
        reason: "dump-role-grant-inspection-failed",
    })?;
    if writable != 0 {
        return fail("dump-role-write-grant-rejected");
    }
    let schema_create: bool =
        sqlx::query_scalar("SELECT has_schema_privilege($1, 'public', 'CREATE')")
            .bind(&policy.dump_role)
            .fetch_one(&mut *connection)
            .await
            .map_err(|_| BarrierError {
                reason: "dump-role-grant-inspection-failed",
            })?;
    if schema_create {
        return fail("dump-role-schema-create-rejected");
    }
    Ok(())
}

/// Disables every O3K writer role and the restore role, and enables the dump
/// role only for the capture interval.
pub async fn apply_writer_barrier(
    connection: &mut PgConnection,
    policy: &RolePolicy,
) -> Result<(), BarrierError> {
    let dump = quote_ident(&policy.dump_role)?;
    let restore = quote_ident(&policy.restore_role)?;
    let mut statements = vec![
        format!("ALTER ROLE {dump} LOGIN"),
        format!("ALTER ROLE {restore} NOLOGIN"),
    ];
    for writer in &policy.writer_roles {
        statements.push(format!("ALTER ROLE {} NOLOGIN", quote_ident(writer)?));
    }
    for statement in statements {
        sqlx::query(&statement)
            .execute(&mut *connection)
            .await
            .map_err(|_| BarrierError {
                reason: "writer-role-disable-failed",
            })?;
    }
    Ok(())
}

/// Restores the reviewed role login modes after publication, safe abort or
/// crash recovery: the dump role is disabled and every writer is enabled
/// again. Role attributes are never changed.
pub async fn restore_role_modes(
    connection: &mut PgConnection,
    policy: &RolePolicy,
) -> Result<(), BarrierError> {
    let dump = quote_ident(&policy.dump_role)?;
    let restore = quote_ident(&policy.restore_role)?;
    let mut statements = vec![
        format!("ALTER ROLE {dump} NOLOGIN"),
        format!("ALTER ROLE {restore} NOLOGIN"),
    ];
    for writer in &policy.writer_roles {
        statements.push(format!("ALTER ROLE {} LOGIN", quote_ident(writer)?));
    }
    for statement in statements {
        sqlx::query(&statement)
            .execute(&mut *connection)
            .await
            .map_err(|_| BarrierError {
                reason: "role-mode-restore-failed",
            })?;
    }
    Ok(())
}

/// Terminates every other session on the O3K database and verifies that only
/// the control session remains.
pub async fn terminate_other_sessions(
    connection: &mut PgConnection,
    database: &str,
) -> Result<u64, BarrierError> {
    let pids = sqlx::query_scalar::<_, i32>(
        "SELECT pid FROM pg_stat_activity \
         WHERE datname = $1 AND pid <> pg_backend_pid()",
    )
    .bind(database)
    .fetch_all(&mut *connection)
    .await
    .map_err(|_| BarrierError {
        reason: "session-inspection-failed",
    })?;
    for pid in &pids {
        let _: Option<bool> = sqlx::query_scalar("SELECT pg_terminate_backend($1)")
            .bind(pid)
            .fetch_one(&mut *connection)
            .await
            .map_err(|_| BarrierError {
                reason: "session-termination-failed",
            })?;
    }
    // Termination is asynchronous: the backend disappears from
    // `pg_stat_activity` after it observes the signal. Poll briefly instead of
    // racing the first observation.
    for _ in 0..40 {
        let remaining: i64 = sqlx::query_scalar(
            "SELECT count(*) FROM pg_stat_activity \
             WHERE datname = $1 AND pid <> pg_backend_pid()",
        )
        .bind(database)
        .fetch_one(&mut *connection)
        .await
        .map_err(|_| BarrierError {
            reason: "session-inspection-failed",
        })?;
        if remaining == 0 {
            return Ok(u64::try_from(pids.len()).unwrap_or(u64::MAX));
        }
        tokio::time::sleep(Duration::from_millis(50)).await;
    }
    fail("writer-session-retained")
}

/// Installs the first-match admission block and saves the prior file.
pub fn install_admission(
    hba_path: &Path,
    data_directory: &Path,
    policy: &AdmissionPolicy,
) -> Result<AdmissionGuard, BarrierError> {
    validate_hba_path(hba_path)?;
    let original = fs::read(hba_path).map_err(|_| BarrierError {
        reason: "admission-config-unreadable",
    })?;
    let text = std::str::from_utf8(&original).map_err(|_| BarrierError {
        reason: "admission-config-invalid",
    })?;
    if text.contains(BARRIER_MARKER) {
        return fail("admission-barrier-already-installed");
    }

    let block = policy.block()?;
    let mut installed = String::new();
    installed.push_str(&format!(
        "# {BARRIER_MARKER} {} {}\n",
        policy.database, policy.backup_host
    ));
    installed.push_str(&block);
    installed.push_str(&format!("# {BARRIER_END_MARKER}\n"));
    installed.push_str(text);
    let installed_bytes = installed.into_bytes();
    let installed_sha256 = sha256_bytes(&installed_bytes);

    let saved_path = sibling_with_suffix(hba_path, SAVED_ADMISSION_SUFFIX);
    let digest_path = sibling_with_suffix(hba_path, SAVED_DIGEST_SUFFIX);
    atomic_write(&saved_path, &original)?;
    let original_sha256 = sha256_bytes(&original);
    atomic_write(&digest_path, original_sha256.as_bytes())?;
    atomic_write(hba_path, &installed_bytes)?;

    Ok(AdmissionGuard {
        hba_path: hba_path.to_path_buf(),
        data_directory: data_directory.to_path_buf(),
        saved_path,
        digest_path,
        installed_sha256,
        restored: false,
    })
}

fn sibling_with_suffix(path: &Path, suffix: &str) -> PathBuf {
    let mut name = path.as_os_str().to_owned();
    name.push(suffix);
    PathBuf::from(name)
}

fn validate_hba_path(path: &Path) -> Result<(), BarrierError> {
    if !path.is_absolute() {
        return fail("admission-config-path-invalid");
    }
    let metadata = fs::symlink_metadata(path).map_err(|_| BarrierError {
        reason: "admission-config-unreadable",
    })?;
    if metadata.file_type().is_symlink() || !metadata.file_type().is_file() {
        return fail("admission-config-path-invalid");
    }
    if metadata.permissions().mode() & 0o022 != 0 {
        return fail("admission-config-permissions-too-open");
    }
    Ok(())
}

fn atomic_write(path: &Path, bytes: &[u8]) -> Result<(), BarrierError> {
    let parent = path.parent().ok_or(BarrierError {
        reason: "admission-config-path-invalid",
    })?;
    let temporary = parent.join(format!(
        ".o3k-pp6-hba-tmp-{}-{}",
        std::process::id(),
        path.file_name()
            .and_then(|name| name.to_str())
            .unwrap_or("admission")
    ));
    let mut file = fs::OpenOptions::new()
        .create_new(true)
        .write(true)
        .mode(0o600)
        .open(&temporary)
        .map_err(|_| BarrierError {
            reason: "admission-config-write-failed",
        })?;
    file.write_all(bytes)
        .and_then(|()| file.sync_all())
        .map_err(|_| BarrierError {
            reason: "admission-config-write-failed",
        })?;
    drop(file);
    fs::rename(&temporary, path)
        .and_then(|()| fs::File::open(parent).and_then(|directory| directory.sync_all()))
        .map_err(|_| {
            let _ = fs::remove_file(&temporary);
            BarrierError {
                reason: "admission-config-write-failed",
            }
        })
}

fn restore_saved_admission(
    hba_path: &Path,
    saved_path: &Path,
    digest_path: &Path,
) -> Result<(), BarrierError> {
    let saved = match fs::read(saved_path) {
        Ok(bytes) => bytes,
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => return Ok(()),
        Err(_) => return fail("admission-restore-unreadable"),
    };
    let digest = fs::read_to_string(digest_path).map_err(|_| BarrierError {
        reason: "admission-restore-digest-unreadable",
    })?;
    if digest.trim() != sha256_bytes(&saved) {
        return fail("admission-restore-digest-mismatch");
    }
    atomic_write(hba_path, &saved)?;
    let _ = fs::remove_file(saved_path);
    let _ = fs::remove_file(digest_path);
    Ok(())
}

/// Restores admission left behind by an interrupted run, before a new barrier
/// is installed. Returns whether anything was restored.
pub fn recover_saved_admission(
    hba_path: &Path,
    data_directory: &Path,
) -> Result<bool, BarrierError> {
    let saved_path = sibling_with_suffix(hba_path, SAVED_ADMISSION_SUFFIX);
    let digest_path = sibling_with_suffix(hba_path, SAVED_DIGEST_SUFFIX);
    if !saved_path.exists() && !digest_path.exists() {
        return Ok(false);
    }
    validate_hba_path(hba_path)?;
    restore_saved_admission(hba_path, &saved_path, &digest_path)?;
    signal_postmaster(data_directory);
    Ok(true)
}

fn signal_postmaster(data_directory: &Path) {
    let pid_path = data_directory.join("postmaster.pid");
    let Ok(contents) = fs::read_to_string(pid_path) else {
        return;
    };
    let Some(pid) = contents
        .lines()
        .next()
        .and_then(|line| line.trim().parse::<i32>().ok())
    else {
        return;
    };
    let Some(pid) = Pid::from_raw(pid) else {
        return;
    };
    let _ = rustix::process::kill_process(pid, Signal::Hup);
}

/// Reloads `pg_hba.conf` and verifies the ordered first-match policy.
pub async fn reload_and_verify(
    connection: &mut PgConnection,
    policy: &AdmissionPolicy,
    expected_file_sha256: &str,
) -> Result<(), BarrierError> {
    let before: Option<sqlx::types::chrono::DateTime<sqlx::types::chrono::Utc>> =
        sqlx::query_scalar("SELECT pg_conf_load_time()")
            .fetch_one(&mut *connection)
            .await
            .map_err(|_| BarrierError {
                reason: "reload-state-unavailable",
            })?;
    let reloaded: bool = sqlx::query_scalar("SELECT pg_reload_conf()")
        .fetch_one(&mut *connection)
        .await
        .map_err(|_| BarrierError {
            reason: "reload-failed",
        })?;
    if !reloaded {
        return fail("reload-failed");
    }
    let mut observed = false;
    for _ in 0..RELOAD_POLL_ATTEMPTS {
        let after: Option<sqlx::types::chrono::DateTime<sqlx::types::chrono::Utc>> =
            sqlx::query_scalar("SELECT pg_conf_load_time()")
                .fetch_one(&mut *connection)
                .await
                .map_err(|_| BarrierError {
                    reason: "reload-state-unavailable",
                })?;
        if after != before {
            observed = true;
            break;
        }
        tokio::time::sleep(RELOAD_POLL_INTERVAL).await;
    }
    if !observed {
        return fail("reload-incomplete");
    }
    verify_admission(connection, policy, expected_file_sha256).await
}

/// Verifies `pg_hba_file_rules` matches the installed ordered policy and has
/// no error columns.
pub async fn verify_admission(
    connection: &mut PgConnection,
    policy: &AdmissionPolicy,
    expected_file_sha256: &str,
) -> Result<(), BarrierError> {
    let hba_file: String = sqlx::query_scalar("SHOW hba_file")
        .fetch_one(&mut *connection)
        .await
        .map_err(|_| BarrierError {
            reason: "admission-config-unavailable",
        })?;
    let actual_sha = sha256_file(Path::new(&hba_file)).map_err(|_| BarrierError {
        reason: "admission-config-unreadable",
    })?;
    if actual_sha != expected_file_sha256 {
        return fail("admission-barrier-lost");
    }
    let rows = sqlx::query(
        "SELECT rule_number, type, database, user_name, address, auth_method, error \
         FROM pg_hba_file_rules ORDER BY rule_number",
    )
    .fetch_all(&mut *connection)
    .await
    .map_err(|_| BarrierError {
        reason: "admission-rules-unavailable",
    })?;
    if rows.is_empty() {
        return fail("admission-rules-empty");
    }
    for row in &rows {
        let error: Option<String> = row.get("error");
        if error.is_some() {
            return fail("admission-rules-error");
        }
    }
    let expected = policy.rules()?;
    if rows.len() < expected.len() {
        return fail("admission-rule-order-violation");
    }
    for (row, rule) in rows.iter().zip(expected.iter()) {
        let kind: String = row.get("type");
        let databases: Vec<String> = row.get("database");
        let users: Vec<String> = row.get("user_name");
        let address: Option<String> = row.get("address");
        let auth_method: String = row.get("auth_method");
        let matches = kind == rule.kind
            && databases.first() == Some(&rule.database)
            && users.first() == Some(&rule.user)
            && addresses_match(address.as_deref(), rule.address.as_deref())
            && auth_method == rule.auth_method;
        if !matches {
            return fail("admission-rule-order-violation");
        }
    }
    Ok(())
}

/// `pg_hba_file_rules` omits a full-length mask (`/32`, `/128`) from
/// `address`; both spellings describe the same rule.
fn addresses_match(actual: Option<&str>, expected: Option<&str>) -> bool {
    match (actual, expected) {
        (Some(actual), Some(expected)) => {
            actual == expected
                || expected
                    .strip_suffix("/32")
                    .is_some_and(|address| address == actual)
                || expected
                    .strip_suffix("/128")
                    .is_some_and(|address| address == actual)
                || expected
                    .strip_suffix("/0")
                    .is_some_and(|address| address == actual)
        }
        (None, None) => true,
        _ => false,
    }
}

/// Opens a fresh connection with a bounded timeout.
pub async fn connect_probe(url: &str) -> Result<PgConnection, BarrierError> {
    let options = url.parse::<PgConnectOptions>().map_err(|_| BarrierError {
        reason: "probe-url-invalid",
    })?;
    tokio::time::timeout(Duration::from_secs(3), PgConnection::connect_with(&options))
        .await
        .map_err(|_| BarrierError {
            reason: "probe-timeout",
        })?
        .map_err(|_| BarrierError {
            reason: "probe-connect-failed",
        })
}

/// Proves every configured writer/application/maintenance reconnect is denied
/// by the installed barrier.
pub async fn prove_reconnects_denied(probe_urls: &[String]) -> Result<(), BarrierError> {
    if probe_urls.is_empty() {
        return fail("admission-probes-missing");
    }
    for url in probe_urls {
        if connect_probe(url).await.is_ok() {
            return fail("admission-probe-admitted");
        }
    }
    Ok(())
}

/// Verifies that the designated dump session is the only session on the O3K
/// database and that it runs as the dump role.
pub async fn verify_only_dump_session(
    connection: &mut PgConnection,
    dump_role: &str,
) -> Result<(), BarrierError> {
    let current_user: String = sqlx::query_scalar("SELECT current_user")
        .fetch_one(&mut *connection)
        .await
        .map_err(|_| BarrierError {
            reason: "dump-session-inspection-failed",
        })?;
    if current_user != dump_role {
        return fail("dump-session-role-mismatch");
    }
    let others: i64 = sqlx::query_scalar(
        "SELECT count(*) FROM pg_stat_activity \
         WHERE datname = current_database() AND pid <> pg_backend_pid()",
    )
    .fetch_one(&mut *connection)
    .await
    .map_err(|_| BarrierError {
        reason: "dump-session-inspection-failed",
    })?;
    if others != 0 {
        return fail("unexpected-session-during-capture");
    }
    Ok(())
}

/// Waits for the control role to be admitted again after admission restore.
pub async fn verify_reload_by_control(control_url: &str) -> Result<(), BarrierError> {
    for _ in 0..RELOAD_POLL_ATTEMPTS {
        if connect_probe(control_url).await.is_ok() {
            return Ok(());
        }
        tokio::time::sleep(RELOAD_POLL_INTERVAL).await;
    }
    fail("admission-restore-unverified")
}

/// Reads the cluster's `hba_file` and `data_directory` paths.
pub async fn installation_paths(
    connection: &mut PgConnection,
) -> Result<(String, String), BarrierError> {
    let hba_file: String = sqlx::query_scalar("SHOW hba_file")
        .fetch_one(&mut *connection)
        .await
        .map_err(|_| BarrierError {
            reason: "pg-admission-config-unavailable",
        })?;
    let data_directory: String = sqlx::query_scalar("SHOW data_directory")
        .fetch_one(&mut *connection)
        .await
        .map_err(|_| BarrierError {
            reason: "pg-admission-config-unavailable",
        })?;
    Ok((hba_file, data_directory))
}

/// Measures the O3K database source size for the D9 reservation.
pub async fn database_size(
    connection: &mut PgConnection,
    database: &str,
) -> Result<u64, BarrierError> {
    let size: i64 = sqlx::query_scalar("SELECT pg_database_size($1)")
        .bind(database)
        .fetch_one(&mut *connection)
        .await
        .map_err(|_| BarrierError {
            reason: "pg-database-size-unavailable",
        })?;
    u64::try_from(size).map_err(|_| BarrierError {
        reason: "pg-database-size-unavailable",
    })
}

/// Reads the applied SQLx migration identities from the live database.
pub async fn read_migrations(
    connection: &mut PgConnection,
    release_schema_version: u64,
) -> Result<Vec<(u64, Vec<u8>)>, BarrierError> {
    let rows = sqlx::query("SELECT version, checksum FROM _sqlx_migrations ORDER BY version")
        .fetch_all(&mut *connection)
        .await
        .map_err(|_| BarrierError {
            reason: "migration-inventory-unavailable",
        })?;
    let mut migrations = Vec::with_capacity(rows.len());
    let mut previous = None;
    for row in rows {
        let version: i64 = row.get("version");
        let checksum: Vec<u8> = row.get("checksum");
        let version = u64::try_from(version).map_err(|_| BarrierError {
            reason: "migration-version-invalid",
        })?;
        if previous.is_some_and(|prior| prior >= version) || checksum.len() != 48 {
            return fail("migration-inventory-invalid");
        }
        previous = Some(version);
        migrations.push((version, checksum));
    }
    if migrations.is_empty() {
        return fail("migration-inventory-empty");
    }
    if migrations.last().map(|(version, _)| *version) != Some(release_schema_version) {
        return fail("migration-schema-mismatch");
    }
    Ok(migrations)
}

/// Reads the complete catalog/migration/repository facts used by the manifest
/// and by the pre-dump consistency decision.
pub async fn snapshot_facts(
    connection: &mut PgConnection,
    release_schema_version: u64,
    inventory: Vec<Value>,
) -> Result<PgSnapshotFacts, BarrierError> {
    let server_version: String = sqlx::query_scalar("SHOW server_version")
        .fetch_one(&mut *connection)
        .await
        .map_err(|_| BarrierError {
            reason: "server-version-unavailable",
        })?;
    let migrations = read_migrations(connection, release_schema_version).await?;

    let live = live_catalog_objects(connection).await?;
    verify_live_catalog(&inventory, &live)?;

    let mut inventory = inventory;
    for entry in &mut inventory {
        let Some(objects) = entry.get("postgres_objects").and_then(Value::as_array) else {
            return fail("state-inventory-invalid");
        };
        let mut included = true;
        for object in objects {
            if object.get("kind").and_then(Value::as_str) != Some("table") {
                continue;
            }
            let schema = object
                .get("schema")
                .and_then(Value::as_str)
                .unwrap_or_default();
            let name = object
                .get("name")
                .and_then(Value::as_str)
                .unwrap_or_default();
            if schema != "public" || !valid_identifier(name) {
                return fail("state-inventory-invalid");
            }
            let exists: bool = sqlx::query_scalar(&format!(
                "SELECT EXISTS (SELECT 1 FROM \"public\".\"{name}\")"
            ))
            .fetch_one(&mut *connection)
            .await
            .map_err(|_| BarrierError {
                reason: "repository-table-unavailable",
            })?;
            if exists {
                included = false;
                break;
            }
        }
        if let Some(fields) = entry.as_object_mut() {
            fields.insert("empty_state_included".to_owned(), Value::Bool(included));
        }
    }

    let operation_ids = sqlx::query_scalar::<_, String>(
        "SELECT id FROM operations \
         WHERE state NOT IN ('succeeded', 'failed') ORDER BY id",
    )
    .fetch_all(&mut *connection)
    .await
    .map_err(|_| BarrierError {
        reason: "operation-inventory-unavailable",
    })?;
    for id in &operation_ids {
        if uuid::Uuid::parse_str(id).is_err() {
            return fail("operation-inventory-invalid");
        }
    }
    let classification = if operation_ids.is_empty() {
        "drained"
    } else {
        "recorded_unknown"
    };
    let capture_xid: i64 = sqlx::query_scalar("SELECT txid_current()")
        .fetch_one(&mut *connection)
        .await
        .map_err(|_| BarrierError {
            reason: "capture-xid-unavailable",
        })?;
    Ok(PgSnapshotFacts {
        server_version,
        migrations,
        state_inventory: inventory,
        in_flight_operations: classification,
        in_flight_operation_ids: operation_ids,
        capture_xid,
    })
}

#[derive(Debug, Default, PartialEq, Eq)]
struct LiveCatalog {
    tables: Vec<String>,
    indexes: Vec<String>,
    functions: Vec<String>,
    triggers: Vec<String>,
}

async fn live_catalog_objects(connection: &mut PgConnection) -> Result<LiveCatalog, BarrierError> {
    let tables = sqlx::query_scalar::<_, String>(
        "SELECT c.relname FROM pg_class c \
         JOIN pg_namespace n ON n.oid = c.relnamespace \
         WHERE n.nspname = 'public' AND c.relkind IN ('r', 'p') ORDER BY c.relname",
    )
    .fetch_all(&mut *connection)
    .await
    .map_err(|_| BarrierError {
        reason: "catalog-inspection-failed",
    })?;
    let indexes = sqlx::query_scalar::<_, String>(
        "SELECT c.relname FROM pg_class c \
         JOIN pg_namespace n ON n.oid = c.relnamespace \
         WHERE n.nspname = 'public' AND c.relkind = 'i' \
           AND NOT EXISTS (SELECT 1 FROM pg_constraint con \
             WHERE con.conindid = c.oid AND con.contype IN ('p', 'u', 'x')) \
         ORDER BY c.relname",
    )
    .fetch_all(&mut *connection)
    .await
    .map_err(|_| BarrierError {
        reason: "catalog-inspection-failed",
    })?;
    let functions = sqlx::query_scalar::<_, String>(
        "SELECT p.proname || '(' || pg_catalog.pg_get_function_identity_arguments(p.oid) || ')' \
         FROM pg_proc p \
         JOIN pg_namespace n ON n.oid = p.pronamespace \
         WHERE n.nspname = 'public' AND p.prokind IN ('f', 'p') \
         ORDER BY p.proname, pg_catalog.pg_get_function_identity_arguments(p.oid)",
    )
    .fetch_all(&mut *connection)
    .await
    .map_err(|_| BarrierError {
        reason: "catalog-inspection-failed",
    })?;
    let triggers = sqlx::query_scalar::<_, String>(
        "SELECT c.relname || '.' || t.tgname FROM pg_trigger t \
         JOIN pg_class c ON c.oid = t.tgrelid \
         JOIN pg_namespace n ON n.oid = c.relnamespace \
         WHERE n.nspname = 'public' AND NOT t.tgisinternal \
         ORDER BY c.relname, t.tgname",
    )
    .fetch_all(&mut *connection)
    .await
    .map_err(|_| BarrierError {
        reason: "catalog-inspection-failed",
    })?;
    Ok(LiveCatalog {
        tables,
        indexes,
        functions,
        triggers,
    })
}

fn baseline_sets(inventory: &[Value]) -> Result<LiveCatalog, BarrierError> {
    let mut catalog = LiveCatalog::default();
    for entry in inventory {
        let Some(objects) = entry.get("postgres_objects").and_then(Value::as_array) else {
            return fail("state-inventory-invalid");
        };
        for object in objects {
            let kind = object
                .get("kind")
                .and_then(Value::as_str)
                .unwrap_or_default();
            let name = object
                .get("name")
                .and_then(Value::as_str)
                .unwrap_or_default();
            match kind {
                // Tables and indexes are interpolated by later checks, so they
                // must remain plain identifiers.
                "table" => {
                    if !valid_identifier(name) {
                        return fail("state-inventory-invalid");
                    }
                    catalog.tables.push(name.to_owned());
                }
                "index" => {
                    if !valid_identifier(name) {
                        return fail("state-inventory-invalid");
                    }
                    catalog.indexes.push(name.to_owned());
                }
                // D13 keys functions by `name(identity-arguments)` and
                // triggers by `<table>.<name>`. These values are compared,
                // never interpolated.
                "function" => catalog.functions.push(name.to_owned()),
                "trigger" => catalog.triggers.push(name.to_owned()),
                // Explicit constraints/views/sequences are covered by the D13
                // migration-tree drift gate; this live barrier check compares
                // the object identities it can safely classify.
                "constraint" | "view" | "sequence" => continue,
                _ => return fail("state-inventory-invalid"),
            }
        }
    }
    for list in [
        &mut catalog.tables,
        &mut catalog.indexes,
        &mut catalog.functions,
        &mut catalog.triggers,
    ] {
        list.sort();
        list.dedup();
    }
    Ok(catalog)
}

fn verify_live_catalog(inventory: &[Value], live: &LiveCatalog) -> Result<(), BarrierError> {
    let baseline = baseline_sets(inventory)?;
    if baseline.tables != live.tables
        || baseline.indexes != live.indexes
        || baseline.functions != live.functions
        || baseline.triggers != live.triggers
    {
        return fail("store-catalog-mismatch");
    }
    Ok(())
}

#[cfg(test)]
#[allow(clippy::expect_used, clippy::unwrap_used, clippy::panic)]
mod tests {
    use super::*;
    use serde_json::json;

    fn policy() -> AdmissionPolicy {
        AdmissionPolicy {
            database: "o3k".to_owned(),
            backup_host: "127.0.0.1".to_owned(),
            dump_role: "o3k_backup_dump".to_owned(),
            auth_method: "scram-sha-256".to_owned(),
        }
    }

    #[test]
    fn rules_are_first_match_and_cover_every_network_path() {
        let rules = policy().rules().expect("rules");
        assert_eq!(rules[0].kind, "host");
        assert_eq!(rules[0].database, "o3k");
        assert_eq!(rules[0].user, "o3k_backup_dump");
        assert_eq!(rules[0].address.as_deref(), Some("127.0.0.1/32"));
        let lines: Vec<String> = rules.iter().map(HbaRule::line).collect();
        assert!(lines.iter().any(|line| line == "local all all reject"));
        assert!(
            lines
                .iter()
                .any(|line| line == "local replication all reject")
        );
        assert!(
            lines
                .iter()
                .any(|line| line == "host all all 0.0.0.0/0 reject")
        );
        assert!(lines.iter().any(|line| line == "host all all ::/0 reject"));
        assert!(
            lines
                .iter()
                .any(|line| line == "host replication all 0.0.0.0/0 reject")
        );
        assert!(
            lines
                .iter()
                .any(|line| line == "host replication all ::/0 reject")
        );
    }

    #[test]
    fn ipv6_backup_host_is_pinned_to_128_bits() {
        let mut policy = policy();
        policy.backup_host = "::1".to_owned();
        let rules = policy.rules().expect("rules");
        assert_eq!(rules[0].address.as_deref(), Some("::1/128"));
    }

    #[test]
    fn hostname_backup_host_is_rejected() {
        let mut policy = policy();
        policy.backup_host = "db.example".to_owned();
        assert_eq!(
            policy.rules().expect_err("hostname rejected").reason(),
            "backup-host-invalid"
        );
    }

    #[test]
    fn identifiers_are_narrowly_validated() {
        assert!(valid_identifier("o3k_backup_dump"));
        assert!(!valid_identifier("O3K"));
        assert!(!valid_identifier("o3k-dump"));
        assert!(!valid_identifier("1o3k"));
        assert!(!valid_identifier("o3k; DROP ROLE x"));
    }

    #[test]
    fn baseline_sets_cover_expected_kinds_and_reject_unknown() {
        let inventory = vec![json!({
            "postgres_objects": [
                {"kind": "table", "schema": "public", "name": "resources"},
                {"kind": "index", "schema": "public", "name": "idx_resources"},
                {"kind": "function", "schema": "public", "name": "f"},
                {"kind": "trigger", "schema": "public", "name": "t"}
            ]
        })];
        let sets = baseline_sets(&inventory).expect("sets");
        assert_eq!(sets.tables, vec!["resources"]);
        assert_eq!(sets.indexes, vec!["idx_resources"]);
        assert_eq!(sets.functions, vec!["f"]);
        assert_eq!(sets.triggers, vec!["t"]);
        // D13 makes views/constraints/sequences valid inventory kinds; the
        // barrier set comparison safely skips them. A kind it cannot classify
        // must still fail closed.
        let bad = vec![json!({
            "postgres_objects": [{"kind": "extension", "schema": "public", "name": "x"}]
        })];
        assert!(baseline_sets(&bad).is_err());
        let skipped = vec![json!({
            "postgres_objects": [
                {"kind": "view", "schema": "public", "name": "v"},
                {"kind": "constraint", "schema": "public", "name": "c"},
                {"kind": "sequence", "schema": "public", "name": "s"}
            ]
        })];
        assert!(baseline_sets(&skipped).is_ok());
    }

    #[test]
    fn live_catalog_comparison_rejects_extra_and_missing_objects() {
        let inventory = vec![json!({
            "postgres_objects": [
                {"kind": "table", "schema": "public", "name": "resources"},
                {"kind": "index", "schema": "public", "name": "idx_resources"}
            ]
        })];
        let live = LiveCatalog {
            tables: vec!["resources".to_owned()],
            indexes: vec!["idx_resources".to_owned()],
            functions: Vec::new(),
            triggers: Vec::new(),
        };
        assert!(verify_live_catalog(&inventory, &live).is_ok());
        let extra = LiveCatalog {
            functions: vec!["surprise".to_owned()],
            ..live
        };
        assert_eq!(
            verify_live_catalog(&inventory, &extra)
                .expect_err("extra object")
                .reason(),
            "store-catalog-mismatch"
        );
    }
}
