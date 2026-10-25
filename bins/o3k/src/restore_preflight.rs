//! D12 fresh-host preflight. No store is opened or migrated and no selected
//! target file is created. Successful preflight does not authorize restoration
//! or activation. All plaintext is private, disposable recovery-host staging.
use crate::{
    backup::{self, ArtifactVerificationKeys, ExpectedRelease, MigrationIdentity},
    backup_trust::{BackupTrustConfig, default_trust_config_path_for, install_prefix_for},
    upgrade::release_identity::backup_release_identity,
};
use rustix::fs::{FlockOperation, Mode, OFlags, flock, fstat, fstatfs, open, openat};
use serde::Deserialize;
use serde_json::{Value, json};
use sha2::{Digest, Sha256};
use std::{
    fs::{self, File},
    io::{self, Read, Write},
    os::{
        fd::OwnedFd,
        unix::fs::{DirBuilderExt, MetadataExt},
    },
    path::{Component, Path, PathBuf},
    process::ExitCode,
};
use uuid::Uuid;

/// Only the accepted D12 flags. Secrets are loaded through installed handles.
pub struct RestorePreflightArgs {
    pub artifact: PathBuf,
    pub target: PathBuf,
}

/// Denies daemon startup when a configured restore recovery directory contains
/// any state. The journal is not an authority for daemon startup in this
/// implementation: even a valid `PREFLIGHTED` record cannot authorize opening
/// canonical state because the D7 activation and D8 nonce-handoff verifiers
/// are not implemented. Malformed configuration, unsafe paths, and unreadable
/// state also fail closed.
///
/// This check is called while the daemon holds the lifetime store-access lock
/// and before it binds the public API listener.
pub fn deny_startup_if_restore_state(data_dir: &Path) -> std::result::Result<(), &'static str> {
    let prefix = crate::backup_trust::install_prefix_for(
        data_dir,
        std::env::var_os(crate::backup_trust::INSTALL_PREFIX_ENV),
    );
    let config_path = prefix.join("etc/o3k/restore.json");
    match fs::symlink_metadata(&config_path) {
        Err(error) if error.kind() == io::ErrorKind::NotFound => return Ok(()),
        Err(_) => return Err("restore configuration cannot be inspected"),
        Ok(_) => {}
    }

    let bytes = read_root_file(&config_path, 65_536)
        .map_err(|_| "restore configuration is unsafe or unavailable")?;
    let config: RecoveryConfig =
        serde_json::from_slice(&bytes).map_err(|_| "restore configuration is malformed")?;
    let (uid, gid) = o3k_identity().map_err(|_| "o3k account is unavailable")?;
    deny_recovery_state(&config, data_dir, uid, gid, true)
}

fn deny_recovery_state(
    config: &RecoveryConfig,
    data_dir: &Path,
    uid: u32,
    gid: u32,
    require_ext4: bool,
) -> std::result::Result<(), &'static str> {
    if config.format != "o3k-restore-preflight-v1" || config.target_directory != data_dir {
        return Err("restore configuration does not identify this data directory");
    }
    if config.recovery_directory == data_dir
        || config.recovery_directory.starts_with(data_dir)
        || data_dir.starts_with(&config.recovery_directory)
    {
        return Err("restore recovery directory overlaps the data directory");
    }

    if require_ext4 {
        verify_root_ancestors(&config.recovery_directory)
            .map_err(|_| "restore recovery directory has an untrusted ancestor")?;
    }
    let recovery = open_directory(&config.recovery_directory)
        .map_err(|_| "restore recovery directory is unsafe or unavailable")?;
    ensure_same_directory(&config.recovery_directory, &recovery)
        .map_err(|_| "restore recovery directory identity changed")?;
    verify_directory_posture(&recovery, uid, gid, require_ext4)
        .map_err(|_| "restore recovery directory failed its owner or filesystem checks")?;
    let has_state = fs::read_dir(fd_path(&recovery))
        .map_err(|_| "restore recovery directory cannot be inspected")?
        .next()
        .is_some();
    ensure_same_directory(&config.recovery_directory, &recovery)
        .map_err(|_| "restore recovery directory identity changed")?;
    if has_state {
        return Err("restore recovery state is present; daemon startup is quarantined");
    }
    Ok(())
}

/// Root-owned host installation policy, not an artifact or cloud authority.
/// PostgreSQL target is independently provisioned and empty; preflight never
/// creates databases, roles, grants, files, controller epochs or provider work.
#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct RecoveryConfig {
    format: String,
    backend: String,
    target_directory: PathBuf,
    recovery_directory: PathBuf,
    #[serde(default)]
    postgres: Option<PostgresTarget>,
}
#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct PostgresTarget {
    database_url: String,
    validation_image: String,
}

#[derive(Debug)]
struct Failure {
    code: u8,
    reason: &'static str,
}
impl Failure {
    fn rejected(reason: &'static str) -> Self {
        Self { code: 2, reason }
    }
    fn recoverable(reason: &'static str) -> Self {
        Self { code: 3, reason }
    }
    fn unknown(reason: &'static str) -> Self {
        Self { code: 4, reason }
    }
}
type Result<T> = std::result::Result<T, Failure>;

/// Runs only preflight and emits one bounded, redacted JSON result.
pub fn run_restore_preflight(args: &RestorePreflightArgs) -> ExitCode {
    let result = execute(args);
    let (code, output) = match result {
        Ok(value) => (0, value),
        Err(error) => (
            error.code,
            json!({"status": match error.code {
            2 => "rejected", 3 => "recoverable-failure", _ => "quarantined"
        }, "reason": error.reason, "activation_authorized": false}),
        ),
    };
    if let Ok(line) = serde_json::to_string(&output) {
        if writeln!(io::stdout(), "{line}").is_err() {
            return ExitCode::from(3);
        }
    } else {
        return ExitCode::from(3);
    }
    if code != 0 {
        let _ = writeln!(
            io::stderr(),
            "o3k restore preflight: {}",
            output["reason"].as_str().unwrap_or("preflight-failed")
        );
    }
    ExitCode::from(code)
}

fn execute(args: &RestorePreflightArgs) -> Result<Value> {
    absolute_normal(&args.artifact).map_err(|_| Failure::rejected("artifact-path-invalid"))?;
    absolute_normal(&args.target).map_err(|_| Failure::rejected("target-path-invalid"))?;
    // Open and hold every selected directory via no-follow traversal. Locking
    // its inode is the existing startup guard's directory exclusion, without
    // creating its lock file or mutating the selected empty directory.
    let target =
        open_directory(&args.target).map_err(|_| Failure::rejected("target-path-unsafe"))?;
    ensure_empty(&target)?;
    flock(&target, FlockOperation::NonBlockingLockExclusive)
        .map_err(|_| Failure::rejected("controller-or-restore-active"))?;
    let data_dir = crate::backup_data_dir::resolve_data_dir()
        .map_err(|_| Failure::recoverable("recovery-installation-unavailable"))?;
    let prefix = install_prefix_for(
        &data_dir,
        std::env::var_os(crate::backup_trust::INSTALL_PREFIX_ENV),
    );
    let config: RecoveryConfig = serde_json::from_slice(&read_root_file(
        &prefix.join("etc/o3k/restore.json"),
        65536,
    )?)
    .map_err(|_| Failure::rejected("recovery-config-invalid"))?;
    if config.format != "o3k-restore-preflight-v1" || config.target_directory != args.target {
        return Err(Failure::rejected("target-policy-mismatch"));
    }
    if config.backend != "postgresql" {
        // SQLite recovery remains bounded capture/verify until its complete
        // independent catalog validation slice passes. Never accept partially.
        return Err(Failure::rejected("restore-backend-unsupported"));
    }
    let postgres = config
        .postgres
        .as_ref()
        .ok_or_else(|| Failure::rejected("recovery-config-invalid"))?;
    let (uid, gid) = o3k_identity()?;
    if rustix::process::geteuid().as_raw() != 0 && rustix::process::geteuid().as_raw() != uid {
        return Err(Failure::rejected("recovery-operator-unauthorized"));
    }
    verify_directory(&target, uid, gid)?;
    verify_root_ancestors(&args.target)?;
    if config.recovery_directory == args.target
        || config.recovery_directory.starts_with(&args.target)
        || args.target.starts_with(&config.recovery_directory)
    {
        return Err(Failure::rejected("recovery-target-overlap"));
    }
    let recovery = open_directory(&config.recovery_directory)
        .map_err(|_| Failure::rejected("recovery-directory-unsafe"))?;
    verify_directory(&recovery, uid, gid)?;
    verify_root_ancestors(&config.recovery_directory)?;
    flock(&recovery, FlockOperation::NonBlockingLockExclusive)
        .map_err(|_| Failure::rejected("restore-reservation-conflict"))?;
    // A prior journal/pending operation is never implicitly cleared by a
    // preflight. PR B's authenticated disposition will own that recovery.
    if fs::read_dir(fd_path(&recovery))
        .map_err(|_| Failure::recoverable("recovery-directory-unavailable"))?
        .next()
        .is_some()
    {
        return Err(Failure::rejected("recovery-state-present"));
    }
    let trust_path = default_trust_config_path_for(
        &data_dir,
        std::env::var_os(crate::backup_trust::TRUST_CONFIG_ENV),
        std::env::var_os(crate::backup_trust::INSTALL_PREFIX_ENV),
    );
    // Enforce accepted D12 root ownership even on a non-installed test path.
    read_root_file(&trust_path, 65536)?;
    let trust = BackupTrustConfig::load_for_data_dir(&trust_path, &data_dir)
        .map_err(|error| Failure::rejected(error.reason()))?;
    let release_path = prefix.join("share/o3k/release-manifest.json");
    verify_root_ancestors(&release_path)
        .map_err(|_| Failure::rejected("expected-release-untrusted"))?;
    let release_file = open_regular(&release_path)
        .map_err(|_| Failure::rejected("expected-release-unavailable"))?;
    let release_metadata = release_file
        .metadata()
        .map_err(|_| Failure::rejected("expected-release-unavailable"))?;
    if release_metadata.uid() != 0
        || release_metadata.mode() & 0o022 != 0
        || release_metadata.nlink() != 1
    {
        return Err(Failure::rejected("expected-release-untrusted"));
    }
    let identity = backup_release_identity(&prefix)
        .map_err(|_| Failure::rejected("expected-release-unavailable"))?;
    if identity.profile_id != "o3k-small-edge-v1" || identity.profile_id != trust.profile_id() {
        return Err(Failure::rejected("release-profile-mismatch"));
    }
    let migrations = expected_migrations(identity.schema_version)?;
    let inventory = o3k_store::state_inventory::baseline_state_inventory()
        .map_err(|_| Failure::rejected("migration-baseline-unavailable"))?;
    let expected = ExpectedRelease {
        site_id: trust.site_id().to_owned(),
        installation_id: trust.installation_id().to_owned(),
        o3k_version: identity.o3k_version,
        source_sha: identity.source_sha,
        release_artifact_sha256: identity.release_artifact_sha256,
        profile_id: identity.profile_id,
        store_backend: config.backend,
        schema_version: identity.schema_version,
        migrations,
        state_inventory: inventory,
    };
    let signing_key = trust
        .artifact_signing_public_key()
        .map_err(|e| Failure::rejected(e.reason()))?;
    let recipient = trust
        .load_recipient_private_key()
        .map_err(|e| Failure::rejected(e.reason()))?;
    let keys = ArtifactVerificationKeys {
        signing_key_id: trust.artifact_signing_key_id(),
        signer: &signing_key,
        trust: &trust,
        recipient_key_id: trust.recipient_key_id(),
        recipient: &recipient,
    };
    let mut artifact =
        open_regular(&args.artifact).map_err(|_| Failure::rejected("artifact-path-unsafe"))?;
    let length = artifact
        .metadata()
        .map_err(|_| Failure::recoverable("artifact-unavailable"))?
        .len();
    if length > 5 * 1024 * 1024 * 1024 {
        return Err(Failure::rejected("artifact-too-large"));
    }
    // Reserve the complete conservative D9 maximum before plaintext writes.
    // The hold lives outside the target. Space is not borrowed from a foreign
    // path, and there is no fallback to reduced reservations.
    let recovery_path = fd_path(&recovery);
    let capacity = crate::backup_reservation::available_bytes(&recovery_path)
        .map_err(|_| Failure::recoverable("staging-capacity-unavailable"))?;
    let required = crate::backup_reservation::RESERVATION_CAP;
    if capacity < required {
        return Err(Failure::rejected("staging-capacity-insufficient"));
    }
    if crate::backup_reservation::available_bytes(&fd_path(&target))
        .map_err(|_| Failure::recoverable("target-capacity-unavailable"))?
        < required
    {
        return Err(Failure::rejected("target-capacity-insufficient"));
    }
    let staging = recovery_path.join(format!("preflight-{}", Uuid::now_v7()));
    fs::DirBuilder::new()
        .mode(0o700)
        .create(&staging)
        .map_err(|_| Failure::recoverable("staging-unavailable"))?;
    let result = (|| {
        let mut hold =
            crate::backup_reservation::StagingReservation::acquire(&staging, required, 0)
                .map_err(|_| Failure::recoverable("staging-reservation-unavailable"))?;
        hold.prepare_for_write(crate::backup_reservation::SOURCE_PLAINTEXT_BOUND)
            .map_err(|_| Failure::recoverable("staging-reservation-unavailable"))?;
        inspect_staged(&mut artifact, &staging, &expected, &keys, postgres)
    })();
    // A failed/ambiguous cleanup is never reported as a successful preflight.
    if fs::remove_dir_all(&staging).is_err() {
        return Err(Failure::unknown("preflight-cleanup-failed"));
    }
    let report = result?;
    ensure_same_directory(&args.target, &target)?;
    ensure_same_directory(&config.recovery_directory, &recovery)?;
    ensure_empty(&target)?;
    Ok(report)
}

fn inspect_staged(
    artifact: &mut File,
    staging: &Path,
    expected: &ExpectedRelease,
    keys: &ArtifactVerificationKeys<'_>,
    postgres: &PostgresTarget,
) -> Result<Value> {
    let mut digesting = HashReader {
        inner: artifact,
        hasher: Sha256::new(),
    };
    let verified = backup::verify_artifact_stream(&mut digesting, expected, keys, staging)
        .map_err(|e| Failure::rejected(e.class().reason()))?;
    let artifact_sha256 = hex::encode(digesting.hasher.finalize());
    let dump = verified
        .members
        .iter()
        .find(|member| member.record.name == "database/o3k.dump")
        .ok_or_else(|| Failure::rejected("database-member-missing"))?;
    // Complete D10 contains no selected-target connection input.
    let policy = crate::restore_pg_validation::ValidationPolicy {
        image: postgres.validation_image.clone(),
    };
    let report = crate::restore_pg_validation::validate_archive(
        &dump.path,
        &expected.state_inventory,
        &policy,
    )
    .map_err(|e| {
        if e.reason() == "validation-cleanup-unknown" {
            Failure::unknown(e.reason())
        } else {
            Failure::rejected(e.reason())
        }
    })?;
    let runtime = tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()
        .map_err(|_| Failure::recoverable("target-inspection-unavailable"))?;
    runtime
        .block_on(crate::db::inspect_postgres_restore_target(
            &postgres.database_url,
        ))
        .map_err(|error| match error {
            crate::db::RestoreTargetError::Rejected(reason) => Failure::rejected(reason),
            crate::db::RestoreTargetError::Unavailable(reason) => Failure::recoverable(reason),
        })?;
    Ok(
        json!({"status":"preflighted", "artifact_sha256":artifact_sha256,
        "backend":"postgresql", "d10_catalog_sha256": report.catalog_sha256,
        "migration_policy_sha256": report.migration_policy_sha256, "toc_entries":report.toc_entries,
        "activation_authorized":false, "target_mutated":false}),
    )
}

/// Expected checksums are SHA256(SQLx's SHA384(migration bytes)), matching
/// capture. Source database availability is deliberately irrelevant.
fn expected_migrations(schema_version: u64) -> Result<Vec<MigrationIdentity>> {
    let migrator = sqlx::migrate!("../../crates/o3k-store/migrations_postgres");
    let migrations = migrator
        .iter()
        .map(|m| {
            Ok(MigrationIdentity {
                version: u64::try_from(m.version)
                    .map_err(|_| Failure::rejected("migration-baseline-invalid"))?,
                checksum: hex::encode(Sha256::digest(m.checksum.as_ref())),
            })
        })
        .collect::<Result<Vec<_>>>()?;
    if migrations.last().map(|m| m.version) != Some(schema_version) {
        return Err(Failure::rejected("migration-schema-mismatch"));
    }
    Ok(migrations)
}

fn absolute_normal(path: &Path) -> std::result::Result<(), ()> {
    if !path.is_absolute()
        || path == Path::new("/")
        || path
            .components()
            .any(|c| !matches!(c, Component::RootDir | Component::Normal(_)))
    {
        return Err(());
    }
    // Reject redundant separators/dot spelling rather than accepting aliases.
    let rebuilt: PathBuf = path.components().collect();
    if rebuilt.as_os_str() != path.as_os_str() {
        return Err(());
    }
    Ok(())
}
fn open_directory(path: &Path) -> std::result::Result<OwnedFd, ()> {
    if path != Path::new("/") {
        absolute_normal(path)?;
    }
    let mut fd = open(
        "/",
        OFlags::RDONLY | OFlags::DIRECTORY | OFlags::CLOEXEC,
        Mode::empty(),
    )
    .map_err(|_| ())?;
    for component in path.components() {
        if let Component::Normal(name) = component {
            fd = openat(
                &fd,
                name,
                OFlags::RDONLY | OFlags::DIRECTORY | OFlags::CLOEXEC | OFlags::NOFOLLOW,
                Mode::empty(),
            )
            .map_err(|_| ())?;
        }
    }
    Ok(fd)
}
fn fd_path(fd: &OwnedFd) -> PathBuf {
    use std::os::fd::AsRawFd;
    PathBuf::from(format!("/proc/self/fd/{}", fd.as_raw_fd()))
}
fn ensure_empty(fd: &OwnedFd) -> Result<()> {
    if fs::read_dir(fd_path(fd))
        .map_err(|_| Failure::rejected("target-path-unsafe"))?
        .next()
        .is_some()
    {
        return Err(Failure::rejected("target-not-empty"));
    }
    Ok(())
}
fn verify_directory(fd: &OwnedFd, uid: u32, gid: u32) -> Result<()> {
    verify_directory_posture(fd, uid, gid, true)
}
fn verify_directory_posture(fd: &OwnedFd, uid: u32, gid: u32, require_ext4: bool) -> Result<()> {
    let stat = fstat(fd).map_err(|_| Failure::rejected("directory-unverifiable"))?;
    if stat.st_uid != uid || stat.st_gid != gid || stat.st_mode & 0o7777 != 0o700 {
        return Err(Failure::rejected("directory-owner-or-mode-rejected"));
    }
    if !require_ext4 {
        return Ok(());
    }
    let filesystem =
        fstatfs(fd).map_err(|_| Failure::rejected("directory-filesystem-unverifiable"))?;
    if filesystem.f_type != 0xef53 {
        return Err(Failure::rejected("directory-filesystem-unsupported"));
    }
    // ext4 is accepted only on a local block-backed mount, not a matching
    // filesystem magic supplied by a network/overlay/ephemeral namespace.
    let mountinfo = fs::read_to_string("/proc/self/mountinfo")
        .map_err(|_| Failure::rejected("directory-filesystem-unverifiable"))?;
    let major_minor = format!(
        "{}:{}",
        rustix::fs::major(stat.st_dev),
        rustix::fs::minor(stat.st_dev)
    );
    if !mountinfo.lines().any(|line| {
        let fields: Vec<_> = line.split_whitespace().collect();
        fields.get(2) == Some(&major_minor.as_str())
            && line.split_once(" - ").is_some_and(|(_, after)| {
                let parts: Vec<_> = after.split_whitespace().collect();
                parts.first() == Some(&"ext4")
                    && parts
                        .get(1)
                        .is_some_and(|source| source.starts_with("/dev/"))
            })
    }) {
        return Err(Failure::rejected("directory-filesystem-unverifiable"));
    }
    Ok(())
}
fn ensure_same_directory(path: &Path, fd: &OwnedFd) -> Result<()> {
    let current = open_directory(path).map_err(|_| Failure::unknown("target-identity-changed"))?;
    let before = fstat(fd).map_err(|_| Failure::unknown("target-identity-changed"))?;
    let after = fstat(&current).map_err(|_| Failure::unknown("target-identity-changed"))?;
    if (before.st_dev, before.st_ino) != (after.st_dev, after.st_ino) {
        return Err(Failure::unknown("target-identity-changed"));
    }
    Ok(())
}
fn open_regular(path: &Path) -> std::result::Result<File, ()> {
    absolute_normal(path)?;
    let parent = open_directory(path.parent().ok_or(())?)?;
    let fd = openat(
        &parent,
        path.file_name().ok_or(())?,
        OFlags::RDONLY | OFlags::CLOEXEC | OFlags::NOFOLLOW | OFlags::NONBLOCK,
        Mode::empty(),
    )
    .map_err(|_| ())?;
    let file = File::from(fd);
    if !file.metadata().map_err(|_| ())?.is_file() {
        return Err(());
    }
    Ok(file)
}
fn verify_root_ancestors(path: &Path) -> Result<()> {
    // Root-owned configuration is only authoritative below root-protected
    // ancestors. An operator-writable ancestor may replace a whole subtree.
    let mut ancestor = path.parent();
    while let Some(directory) = ancestor {
        let descriptor = if directory == Path::new("/") {
            open(
                "/",
                OFlags::RDONLY | OFlags::DIRECTORY | OFlags::CLOEXEC,
                Mode::empty(),
            )
            .map_err(|_| Failure::rejected("recovery-config-unsafe"))?
        } else {
            open_directory(directory).map_err(|_| Failure::rejected("recovery-config-unsafe"))?
        };
        let metadata =
            fstat(&descriptor).map_err(|_| Failure::rejected("recovery-config-unsafe"))?;
        if metadata.st_uid != 0 || metadata.st_mode & 0o022 != 0 {
            return Err(Failure::rejected("recovery-config-unsafe"));
        }
        ancestor = directory.parent();
    }

    Ok(())
}
fn read_root_file(path: &Path, limit: u64) -> Result<Vec<u8>> {
    verify_root_ancestors(path)?;
    let file = open_regular(path).map_err(|_| Failure::rejected("recovery-config-unsafe"))?;
    let stat = file
        .metadata()
        .map_err(|_| Failure::rejected("recovery-config-unsafe"))?;
    let parent = open_directory(
        path.parent()
            .ok_or_else(|| Failure::rejected("recovery-config-unsafe"))?,
    )
    .map_err(|_| Failure::rejected("recovery-config-unsafe"))?;
    let directory = fstat(&parent).map_err(|_| Failure::rejected("recovery-config-unsafe"))?;
    if stat.uid() != 0
        || stat.mode() & 0o037 != 0
        || stat.nlink() != 1
        || directory.st_uid != 0
        || directory.st_mode & 0o022 != 0
        || stat.len() > limit
    {
        return Err(Failure::rejected("recovery-config-unsafe"));
    }
    let mut bytes = Vec::new();
    file.take(limit + 1)
        .read_to_end(&mut bytes)
        .map_err(|_| Failure::recoverable("recovery-config-unavailable"))?;
    if bytes.len() as u64 > limit {
        return Err(Failure::rejected("recovery-config-unsafe"));
    }
    Ok(bytes)
}

fn o3k_identity() -> Result<(u32, u32)> {
    let passwd = fs::read_to_string("/etc/passwd")
        .map_err(|_| Failure::rejected("recovery-account-unavailable"))?;
    for line in passwd.lines() {
        let parts: Vec<_> = line.split(':').collect();
        if parts.first() == Some(&"o3k") && parts.len() >= 4 {
            let uid = parts[2]
                .parse()
                .map_err(|_| Failure::rejected("recovery-account-unavailable"))?;
            let gid = parts[3]
                .parse()
                .map_err(|_| Failure::rejected("recovery-account-unavailable"))?;
            return Ok((uid, gid));
        }
    }
    Err(Failure::rejected("recovery-account-unavailable"))
}
struct HashReader<R> {
    inner: R,
    hasher: Sha256,
}
impl<R: Read> Read for HashReader<R> {
    fn read(&mut self, buffer: &mut [u8]) -> io::Result<usize> {
        let count = self.inner.read(buffer)?;
        self.hasher.update(&buffer[..count]);
        Ok(count)
    }
}

#[cfg(test)]
mod startup_quarantine_tests {
    use super::{RecoveryConfig, deny_recovery_state};
    use std::{
        fs,
        os::unix::{fs::MetadataExt, fs::PermissionsExt},
        path::PathBuf,
    };
    use uuid::Uuid;

    struct TestDirs(PathBuf);
    impl TestDirs {
        fn new() -> std::io::Result<Self> {
            let root = std::env::temp_dir().join(format!(
                "o3k-restore-startup-{}-{}",
                std::process::id(),
                Uuid::now_v7()
            ));
            fs::create_dir(&root)?;
            fs::set_permissions(&root, fs::Permissions::from_mode(0o700))?;
            Ok(Self(root))
        }
    }
    impl Drop for TestDirs {
        fn drop(&mut self) {
            let _ = fs::remove_dir_all(&self.0);
        }
    }

    fn config(data_dir: PathBuf, recovery_directory: PathBuf) -> RecoveryConfig {
        RecoveryConfig {
            format: "o3k-restore-preflight-v1".to_owned(),
            backend: "postgresql".to_owned(),
            target_directory: data_dir,
            recovery_directory,
            postgres: None,
        }
    }

    #[test]
    fn configured_empty_recovery_directory_allows_startup_gate() -> std::io::Result<()> {
        let dirs = TestDirs::new()?;
        let target = dirs.0.join("target");
        let recovery = dirs.0.join("recovery");
        fs::create_dir(&target)?;
        fs::create_dir(&recovery)?;
        for path in [&target, &recovery] {
            fs::set_permissions(path, fs::Permissions::from_mode(0o700))?;
        }
        let metadata = fs::metadata(&recovery)?;
        deny_recovery_state(
            &config(target.clone(), recovery),
            &target,
            metadata.uid(),
            metadata.gid(),
            false,
        )
        .map_err(std::io::Error::other)
    }

    #[test]
    fn any_restore_journal_state_denies_startup() -> std::io::Result<()> {
        let dirs = TestDirs::new()?;
        let target = dirs.0.join("target");
        let recovery = dirs.0.join("recovery");
        fs::create_dir(&target)?;
        fs::create_dir(&recovery)?;
        for path in [&target, &recovery] {
            fs::set_permissions(path, fs::Permissions::from_mode(0o700))?;
        }
        fs::write(recovery.join("restore-journal.json"), b"not-authoritative")?;
        let metadata = fs::metadata(&recovery)?;
        let error = match deny_recovery_state(
            &config(target.clone(), recovery),
            &target,
            metadata.uid(),
            metadata.gid(),
            false,
        ) {
            Ok(()) => return Err(std::io::Error::other("journal presence allowed startup")),
            Err(error) => error,
        };
        assert!(error.contains("quarantined"));
        Ok(())
    }

    #[test]
    fn unrecognized_recovery_config_format_denies_startup_even_when_empty() -> std::io::Result<()> {
        let dirs = TestDirs::new()?;
        let target = dirs.0.join("target");
        let recovery = dirs.0.join("recovery");
        fs::create_dir(&target)?;
        fs::create_dir(&recovery)?;
        let metadata = fs::metadata(&recovery)?;
        let mut config = config(target.clone(), recovery);
        config.format = "unrecognized-recovery-format".to_owned();
        assert_eq!(
            deny_recovery_state(&config, &target, metadata.uid(), metadata.gid(), false),
            Err("restore configuration does not identify this data directory")
        );
        Ok(())
    }

    #[test]
    fn changed_target_identity_denies_startup() -> std::io::Result<()> {
        let dirs = TestDirs::new()?;
        let target = dirs.0.join("target");
        let other_target = dirs.0.join("other-target");
        let recovery = dirs.0.join("recovery");
        fs::create_dir(&target)?;
        fs::create_dir(&other_target)?;
        fs::create_dir(&recovery)?;
        let metadata = fs::metadata(&recovery)?;
        let error = match deny_recovery_state(
            &config(target, recovery),
            &other_target,
            metadata.uid(),
            metadata.gid(),
            false,
        ) {
            Ok(()) => return Err(std::io::Error::other("target mismatch allowed startup")),
            Err(error) => error,
        };
        assert!(error.contains("does not identify"));
        Ok(())
    }
}
