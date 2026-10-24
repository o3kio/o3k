//! PP.6 PostgreSQL 16 capture orchestration.
//!
//! This module joins the D4 database-side admission barrier
//! ([`o3k_store::postgres::backup`]), the argv-only `pg_dump`/`pg_restore`
//! boundary ([`crate::backup_pg_dump`]) and the existing signed-artifact
//! pipeline. It deliberately does not add an HTTP API or a second artifact
//! format: the control-plane backup is still the accepted encrypted,
//! Ed25519-authenticated artifact with one opaque PostgreSQL member.
//!
//! # Signing seam
//!
//! The PostgreSQL profile's selected mode (ADR-0190) is bounded online HSM
//! signing. That service is **blocked**: it requires a contract amendment for
//! the signer protocol/service and an external HSM/custody deployment. This
//! slice therefore reuses the accepted Option A detached-signature seam
//! ([`crate::backup::ArtifactSigner`] / the staged signing request) so a
//! release can plug in the online signer later without forking the artifact
//! flow. No HSM, custody or managed-cluster evidence is claimed here.
//!
//! # Configuration
//!
//! Installation policy is read from a root-owned JSON document
//! (`O3K_PG_BACKUP_CONFIG`, else `<install-prefix>/etc/o3k/backup-postgres.json`).
//! It carries connection URLs and role names, never key material. URLs with
//! embedded passwords are rejected because `pg_dump` argv is not secret.

use std::{
    fs,
    io::Read,
    os::unix::fs::MetadataExt,
    path::{Path, PathBuf},
};

use o3k_store::postgres::backup::{
    self as pg_backup, AdmissionGuard, AdmissionPolicy, BarrierError, PgSnapshotFacts, RolePolicy,
};
use serde::Deserialize;
use serde_json::Value;
use sqlx::{Connection, postgres::PgConnection};

use crate::{
    backup_artifact::SnapshotFacts,
    backup_pg_dump::{self, TocReport},
    upgrade::release_identity::BackupReleaseIdentity,
};

/// Resolves the configured store backend from `o3kd.env` plus process
/// environment overrides. A missing value keeps the historical SQLite default.
#[must_use]
pub fn configured_backend() -> String {
    let config_dir = std::env::var("O3K_CONFIG_DIR").unwrap_or_else(|_| "/etc/o3k".to_owned());
    let env = crate::context::parse_env_file(&Path::new(&config_dir).join("o3kd.env"));
    let backend = std::env::var("O3K_DATABASE_BACKEND")
        .ok()
        .or_else(|| env.get("O3K_DATABASE_BACKEND").cloned())
        .unwrap_or_else(|| crate::backup::BACKEND_SQLITE.to_owned())
        .to_ascii_lowercase();
    match backend.as_str() {
        "postgres" | "postgresql" => crate::backup::BACKEND_POSTGRESQL.to_owned(),
        other => other.to_owned(),
    }
}

/// Environment override for the PostgreSQL installation policy document.
pub const CONFIG_ENV: &str = "O3K_PG_BACKUP_CONFIG";
/// Default policy document below the installation prefix.
pub const CONFIG_RELATIVE_PATH: &str = "etc/o3k/backup-postgres.json";
/// Bound for the policy document.
const MAX_CONFIG_BYTES: u64 = 64 * 1024;

/// Stable PostgreSQL capture failure.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PgBackupError {
    reason: &'static str,
}

impl PgBackupError {
    fn new(reason: &'static str) -> Self {
        Self { reason }
    }

    /// Stable reason code.
    #[must_use]
    pub const fn reason(&self) -> &'static str {
        self.reason
    }
}

impl From<BarrierError> for PgBackupError {
    fn from(error: BarrierError) -> Self {
        Self::new(error.reason())
    }
}

impl From<backup_pg_dump::PgToolError> for PgBackupError {
    fn from(error: backup_pg_dump::PgToolError) -> Self {
        Self::new(error.reason())
    }
}

#[derive(Debug, Deserialize)]
struct RawConfig {
    control_database_url: String,
    dump_database_url: String,
    #[serde(default)]
    probe_database_urls: Vec<String>,
    database: String,
    backup_host: String,
    dump_role: String,
    writer_roles: Vec<String>,
    restore_role: String,
    control_role: String,
    #[serde(default = "default_auth_method")]
    dump_auth_method: String,
    #[serde(default)]
    hba_path: String,
    #[serde(default)]
    data_directory: String,
}

fn default_auth_method() -> String {
    "scram-sha-256".to_owned()
}

/// Validated PostgreSQL installation policy.
#[derive(Debug, Clone)]
pub struct PgBackupConfig {
    pub control_database_url: String,
    pub dump_database_url: String,
    pub probe_database_urls: Vec<String>,
    pub database: String,
    pub backup_host: String,
    pub dump_role: String,
    pub writer_roles: Vec<String>,
    pub restore_role: String,
    pub control_role: String,
    pub dump_auth_method: String,
    pub hba_path: PathBuf,
    pub data_directory: PathBuf,
}

impl PgBackupConfig {
    /// Loads the policy document for an installation prefix.
    pub fn load(install_prefix: &Path) -> Result<Self, PgBackupError> {
        let path = std::env::var_os(CONFIG_ENV)
            .map(PathBuf::from)
            .unwrap_or_else(|| install_prefix.join(CONFIG_RELATIVE_PATH));
        let bytes = read_private(&path)?;
        let raw: RawConfig = serde_json::from_slice(&bytes)
            .map_err(|_| PgBackupError::new("pg-backup-config-invalid"))?;
        Self::from_raw(raw)
    }

    fn from_raw(raw: RawConfig) -> Result<Self, PgBackupError> {
        for role in
            raw.writer_roles
                .iter()
                .chain([&raw.dump_role, &raw.restore_role, &raw.control_role])
        {
            if !valid_identifier(role) {
                return Err(PgBackupError::new("pg-backup-config-invalid"));
            }
        }
        if !valid_identifier(&raw.database) || raw.backup_host.parse::<std::net::IpAddr>().is_err()
        {
            return Err(PgBackupError::new("pg-backup-config-invalid"));
        }
        if raw.writer_roles.is_empty() || raw.probe_database_urls.is_empty() {
            return Err(PgBackupError::new("pg-backup-config-invalid"));
        }
        for url in std::iter::once(&raw.control_database_url)
            .chain(std::iter::once(&raw.dump_database_url))
            .chain(raw.probe_database_urls.iter())
        {
            validate_database_url(url)?;
        }
        let podata = std::env::var_os("PGDATA").map(PathBuf::from);
        let data_directory = if raw.data_directory.is_empty() {
            podata
                .clone()
                .ok_or_else(|| PgBackupError::new("pg-backup-config-invalid"))?
        } else {
            PathBuf::from(raw.data_directory)
        };
        let hba_path = if raw.hba_path.is_empty() {
            data_directory.join("pg_hba.conf")
        } else {
            PathBuf::from(raw.hba_path)
        };
        Ok(Self {
            control_database_url: raw.control_database_url,
            dump_database_url: raw.dump_database_url,
            probe_database_urls: raw.probe_database_urls,
            database: raw.database,
            backup_host: raw.backup_host,
            dump_role: raw.dump_role,
            writer_roles: raw.writer_roles,
            restore_role: raw.restore_role,
            control_role: raw.control_role,
            dump_auth_method: raw.dump_auth_method,
            hba_path,
            data_directory,
        })
    }

    fn role_policy(&self) -> RolePolicy {
        RolePolicy {
            writer_roles: self.writer_roles.clone(),
            dump_role: self.dump_role.clone(),
            restore_role: self.restore_role.clone(),
            control_role: self.control_role.clone(),
        }
    }

    fn admission_policy(&self) -> AdmissionPolicy {
        AdmissionPolicy {
            database: self.database.clone(),
            backup_host: self.backup_host.clone(),
            dump_role: self.dump_role.clone(),
            auth_method: self.dump_auth_method.clone(),
        }
    }
}

fn valid_identifier(name: &str) -> bool {
    !name.is_empty()
        && name.len() <= 63
        && name
            .bytes()
            .all(|byte| byte.is_ascii_lowercase() || byte.is_ascii_digit() || byte == b'_')
        && !name.starts_with(|c: char| c.is_ascii_digit())
}

/// Rejects a URL carrying an embedded password: argv is not secret storage.
fn validate_database_url(url: &str) -> Result<(), PgBackupError> {
    if url.contains(char::is_whitespace) {
        return Err(PgBackupError::new("pg-backup-config-invalid"));
    }
    if !url.starts_with("postgres://") && !url.starts_with("postgresql://") {
        return Err(PgBackupError::new("pg-backup-url-invalid"));
    }
    let Some((_, remainder)) = url.split_once("://") else {
        return Err(PgBackupError::new("pg-backup-url-invalid"));
    };
    let authority = remainder.split('/').next().unwrap_or(remainder);
    if let Some(userinfo) = authority.rsplit_once('@').map(|(userinfo, _)| userinfo)
        && userinfo.contains(':')
    {
        return Err(PgBackupError::new("pg-backup-url-password-rejected"));
    }
    Ok(())
}

fn read_private(path: &Path) -> Result<Vec<u8>, PgBackupError> {
    let metadata = fs::symlink_metadata(path)
        .map_err(|_| PgBackupError::new("pg-backup-config-unavailable"))?;
    if metadata.file_type().is_symlink() || !metadata.file_type().is_file() {
        return Err(PgBackupError::new("pg-backup-config-unsafe"));
    }
    if metadata.mode() & 0o022 != 0 {
        return Err(PgBackupError::new("pg-backup-config-unsafe"));
    }
    let euid = rustix::process::geteuid().as_raw();
    if metadata.uid() != 0 && metadata.uid() != euid {
        return Err(PgBackupError::new("pg-backup-config-owner-untrusted"));
    }
    if metadata.len() > MAX_CONFIG_BYTES {
        return Err(PgBackupError::new("pg-backup-config-too-large"));
    }
    let mut bytes = Vec::new();
    fs::File::open(path)
        .and_then(|mut file| file.read_to_end(&mut bytes))
        .map_err(|_| PgBackupError::new("pg-backup-config-unavailable"))?;
    Ok(bytes)
}

/// Result of one barrier-protected capture.
///
/// The admission guard stays armed until the artifact is published or the
/// operation safely aborts.
pub struct PgCapture {
    /// Manifest facts read before the control session closed.
    pub facts: PgSnapshotFacts,
    /// SHA-256 of the custom dump member bytes.
    pub dump_sha256: String,
    /// Dump member length.
    pub dump_size_bytes: u64,
    /// TOC classification summary.
    pub toc: TocReport,
    /// Verified barrier generation.
    pub admission_sha256: String,
    /// Armed admission barrier.
    pub guard: AdmissionGuard,
}

impl PgCapture {
    /// Converts the PostgreSQL facts to the backend-neutral capture facts.
    #[must_use]
    pub fn artifact_facts(&self) -> SnapshotFacts {
        SnapshotFacts {
            server_version: self.facts.server_version.clone(),
            migrations: self
                .facts
                .migrations
                .iter()
                .map(|(version, checksum)| crate::backup::MigrationIdentity {
                    version: *version,
                    // One documented mapping shared with verification.
                    checksum: crate::backup_verify::migration_checksum(checksum),
                })
                .collect(),
            state_inventory: self.facts.state_inventory.clone(),
            in_flight_operations: self.facts.in_flight_operations,
            in_flight_operation_ids: self.facts.in_flight_operation_ids.clone(),
        }
    }
}

async fn connect_control(url: &str) -> Result<PgConnection, PgBackupError> {
    PgConnection::connect(url)
        .await
        .map_err(|_| PgBackupError::new("pg-control-connect-failed"))
}

async fn connect_control_retry(url: &str) -> Result<PgConnection, PgBackupError> {
    for _ in 0..100 {
        if let Ok(connection) = PgConnection::connect(url).await {
            return Ok(connection);
        }
        tokio::time::sleep(std::time::Duration::from_millis(50)).await;
    }
    Err(PgBackupError::new("pg-control-connect-failed"))
}

fn canonical(path: &Path) -> Result<PathBuf, PgBackupError> {
    fs::canonicalize(path).map_err(|_| PgBackupError::new("pg-admission-config-unavailable"))
}

async fn verify_installation(
    connection: &mut PgConnection,
    config: &PgBackupConfig,
) -> Result<(), PgBackupError> {
    let (hba_file, data_directory) = pg_backup::installation_paths(connection).await?;
    if canonical(Path::new(&hba_file))? != canonical(&config.hba_path)?
        || canonical(Path::new(&data_directory))? != canonical(&config.data_directory)?
    {
        return Err(PgBackupError::new("pg-admission-config-mismatch"));
    }
    Ok(())
}

/// Runs the D4 barrier, the dump, the TOC classification and the catalog /
/// migration / configuration consistency checks.
///
/// On success the returned guard is still installed; the caller must restore
/// admission only after verified publication or a safe abort. On any error the
/// guard restores admission synchronously through `Drop`.
pub async fn capture(
    config: &PgBackupConfig,
    dump_path: &Path,
    release: &BackupReleaseIdentity,
    inventory: &[Value],
) -> Result<PgCapture, PgBackupError> {
    if release.profile_id != "o3k-small-edge-v1" {
        return Err(PgBackupError::new("postgres-profile-unsupported"));
    }
    backup_pg_dump::check_tool_versions()?;

    // A previous interrupted run leaves the saved admission file in place.
    // Restore it before opening a control session: the installed barrier
    // deliberately denies every local control reconnect.
    let recovered = pg_backup::recover_saved_admission(&config.hba_path, &config.data_directory)
        .map_err(PgBackupError::from)?;
    let mut connection = if recovered {
        connect_control_retry(&config.control_database_url).await?
    } else {
        connect_control(&config.control_database_url).await?
    };
    verify_installation(&mut connection, config).await?;

    let roles = config.role_policy();
    let admission = config.admission_policy();
    pg_backup::inspect_roles(&mut connection, &roles).await?;
    pg_backup::verify_dump_role_grants(&mut connection, &roles, inventory).await?;
    let facts =
        pg_backup::snapshot_facts(&mut connection, release.schema_version, inventory.to_vec())
            .await?;

    pg_backup::apply_writer_barrier(&mut connection, &roles).await?;
    pg_backup::terminate_other_sessions(&mut connection, &config.database).await?;
    let guard = pg_backup::install_admission(&config.hba_path, &config.data_directory, &admission)?;
    pg_backup::reload_and_verify(&mut connection, &admission, guard.installed_sha256()).await?;
    pg_backup::prove_reconnects_denied(&config.probe_database_urls).await?;
    barrier_test_pause().await;

    // The control session must be gone before the dump starts.
    connection
        .close()
        .await
        .map_err(|_| PgBackupError::new("pg-control-close-failed"))?;
    let mut dump_probe = pg_backup::connect_probe(&config.dump_database_url)
        .await
        .map_err(|error| PgBackupError::new(error.reason()))?;
    pg_backup::verify_only_dump_session(&mut dump_probe, &config.dump_role).await?;
    dump_probe
        .close()
        .await
        .map_err(|_| PgBackupError::new("pg-dump-session-close-failed"))?;

    let dump_size_bytes = backup_pg_dump::run_pg_dump(&config.dump_database_url, dump_path)?;
    test_exit_after_dump();
    guard.verify_file_unchanged()?;
    let dump_sha256 = sha256_file(dump_path)?;
    let toc =
        backup_pg_dump::classify_toc(&backup_pg_dump::run_pg_restore_list(dump_path)?, inventory)?;

    Ok(PgCapture {
        facts,
        dump_sha256,
        dump_size_bytes,
        toc,
        admission_sha256: guard.installed_sha256().to_owned(),
        guard,
    })
}

#[cfg(feature = "backup-test-hooks")]
async fn barrier_test_pause() {
    let Ok(ready) = std::env::var("O3K_BACKUP_TEST_BARRIER_READY_FILE") else {
        return;
    };
    let _ = fs::write(&ready, b"ready");
    let release = std::env::var("O3K_BACKUP_TEST_BARRIER_RELEASE_FILE").unwrap_or_default();
    while !Path::new(&release).exists() {
        tokio::time::sleep(std::time::Duration::from_millis(50)).await;
    }
}

#[cfg(not(feature = "backup-test-hooks"))]
async fn barrier_test_pause() {}

#[cfg(feature = "backup-test-hooks")]
fn test_exit_after_dump() {
    if std::env::var_os("O3K_BACKUP_TEST_EXIT_AFTER_DUMP").is_some_and(|value| value == "1") {
        std::process::exit(88);
    }
}

#[cfg(not(feature = "backup-test-hooks"))]
fn test_exit_after_dump() {}

fn sha256_file(path: &Path) -> Result<String, PgBackupError> {
    use sha2::{Digest, Sha256};
    let mut file =
        fs::File::open(path).map_err(|_| PgBackupError::new("pg-dump-output-missing"))?;
    let mut hasher = Sha256::new();
    let mut buffer = [0_u8; 64 * 1024];
    loop {
        let read = file
            .read(&mut buffer)
            .map_err(|_| PgBackupError::new("pg-dump-output-unreadable"))?;
        if read == 0 {
            break;
        }
        hasher.update(&buffer[..read]);
    }
    Ok(hex::encode(hasher.finalize()))
}

/// Restores admission after verified publication or a safe abort and proves
/// the control role can connect again.
pub async fn restore_admission(
    capture: &mut PgCapture,
    config: &PgBackupConfig,
) -> Result<(), PgBackupError> {
    capture
        .guard
        .restore_and_verify(&config.control_database_url)
        .await
        .map_err(PgBackupError::from)
}

/// Crash-recovery entry point: restores any saved admission left by an
/// interrupted run and proves the control role can connect again.
///
/// Returns whether a saved admission file was present.
pub async fn ensure_admission_restored(config: &PgBackupConfig) -> Result<bool, PgBackupError> {
    let restored = pg_backup::recover_saved_admission(&config.hba_path, &config.data_directory)
        .map_err(PgBackupError::from)?;
    connect_control_retry(&config.control_database_url).await?;
    Ok(restored)
}

/// Reads the applied migration identities for artifact verification.
pub async fn read_migrations(
    config: &PgBackupConfig,
    release_schema_version: u64,
) -> Result<Vec<crate::backup::MigrationIdentity>, PgBackupError> {
    let mut connection = connect_control(&config.control_database_url).await?;
    let rows = pg_backup::read_migrations(&mut connection, release_schema_version)
        .await
        .map_err(PgBackupError::from)?;
    Ok(rows
        .into_iter()
        .map(|(version, checksum)| crate::backup::MigrationIdentity {
            version,
            checksum: crate::backup_verify::migration_checksum(&checksum),
        })
        .collect())
}

/// Measures the database source size for the D9 reservation before the dump.
pub async fn database_size(config: &PgBackupConfig) -> Result<u64, PgBackupError> {
    let mut connection = connect_control(&config.control_database_url).await?;
    pg_backup::database_size(&mut connection, &config.database)
        .await
        .map_err(PgBackupError::from)
}

#[cfg(test)]
#[allow(clippy::expect_used, clippy::unwrap_used, clippy::panic)]
mod tests {
    use super::*;

    fn raw() -> RawConfig {
        RawConfig {
            control_database_url: "postgres://control@127.0.0.1/o3k".to_owned(),
            dump_database_url: "postgres://o3k_backup_dump@127.0.0.1/o3k".to_owned(),
            probe_database_urls: vec![
                "postgres://o3k_runtime@127.0.0.1/o3k".to_owned(),
                "postgres://o3k_runtime@/o3k".to_owned(),
            ],
            database: "o3k".to_owned(),
            backup_host: "127.0.0.1".to_owned(),
            dump_role: "o3k_backup_dump".to_owned(),
            writer_roles: vec!["o3k_runtime".to_owned()],
            restore_role: "o3k_restore_owner".to_owned(),
            control_role: "control".to_owned(),
            dump_auth_method: "trust".to_owned(),
            hba_path: "/tmp/pg_hba.conf".to_owned(),
            data_directory: "/tmp/pgdata".to_owned(),
        }
    }

    #[test]
    fn password_urls_are_rejected() {
        assert_eq!(
            validate_database_url("postgres://user:secret@127.0.0.1/o3k")
                .expect_err("password")
                .reason(),
            "pg-backup-url-password-rejected"
        );
        assert!(validate_database_url("postgres://user@127.0.0.1/o3k").is_ok());
        assert!(validate_database_url("postgres://user@/o3k").is_ok());
    }

    #[test]
    fn invalid_identifiers_and_hosts_are_rejected() {
        let mut config = raw();
        config.database = "o3k; DROP".to_owned();
        assert_eq!(
            PgBackupConfig::from_raw(config)
                .expect_err("invalid")
                .reason(),
            "pg-backup-config-invalid"
        );
        let mut config = raw();
        config.backup_host = "db.example".to_owned();
        assert_eq!(
            PgBackupConfig::from_raw(config).expect_err("host").reason(),
            "pg-backup-config-invalid"
        );
    }

    #[test]
    fn config_is_accepted_with_all_required_fields() {
        let config = PgBackupConfig::from_raw(raw()).expect("config");
        assert_eq!(config.database, "o3k");
        assert_eq!(config.hba_path, PathBuf::from("/tmp/pg_hba.conf"));
    }
}
