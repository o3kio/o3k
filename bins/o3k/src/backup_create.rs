//! `o3k backup create` — provisional capture executor for the PP.6
//! authenticated backup handoff (SPEC-0050 §8, ADR-0189 D2/D4/D8).
//!
//! This module implements the `o3k` CLI side of the host-local backup
//! handoff: it requests the authenticated handoff from `o3kd` over the
//! private Unix control socket ([`o3k_store::connect_and_request`]), receives
//! the exclusive store-access lock ([`o3k_store::StoreAccessLock::receive_handoff`]),
//! writes the denial-only interrupted-backup marker, captures an
//! integrity-checked SQLite snapshot through
//! [`o3k_store::SqliteStore::backup_to_file`], proves the source database did
//! not change during capture, and publishes a *provisional* capture directory.
//!
//! # Provisional milestone scope (ADR-0189 D2)
//!
//! This milestone produces a provisional capture only: there is no artifact
//! signing, no trust/publication chain, and no claim of a supported PP.6
//! backup. A partial artifact is never discoverable as a successful backup:
//! the capture is built in a dot-prefixed staging directory and published with
//! a no-replace rename to `provisional-backup-<operation-id>`. The success
//! output says explicitly that this is not a supported PP.6 backup artifact.
//!
//! # Exit-code contract (SPEC-0050 §8)
//!
//! ```text
//! 0  provisional capture completed
//! 2  rejected precondition (unusable destination, controller unavailable or
//!    rejected the handoff request)
//! 3  recoverable failure (lock received; capture or finalization failed and
//!    the interrupted-backup marker is kept so the daemon preflight stays
//!    blocked until an operator clears it)
//! 4  unknown/quarantined outcome (the capture could not prove source
//!    immutability, or the capture outcome is uncertain)
//! ```
//!
//! Stdout carries exactly one line of bounded JSON; stderr carries only the
//! stable reason code and the operation id. Secrets never appear in arguments,
//! environment, or logs; the identity tokens travel only inside the socket
//! request frame.
//!
//! # Data-directory resolution
//!
//! `o3k doctor` and `o3k upgrade` use their own per-command overrides
//! (`O3K_DOCTOR_DATA_DIR`, `O3K_UPGRADE_DATA_DIR`) because they answer
//! different questions. The backup executor must resolve the *same* directory
//! the running `o3kd` was launched with, because both sides independently
//! derive the installation/site identity tokens from the canonical data-dir
//! path and the control socket lives inside that directory. The daemon
//! resolves `O3K_DATA_DIR` with `o3k-config` (environment else the
//! `./data` default), so this executor reuses exactly that precedence —
//! `O3K_DATA_DIR` when set and non-empty, else `./data`
//! ([`DEFAULT_DATA_DIR`], mirroring `o3k-config`'s constant) — and
//! canonicalizes the result. No TOML config file or `--data-dir` flag is read:
//! the executor is a separate process from the daemon and must not guess at a
//! differently-configured installation.
//!
//! # Snapshot verification boundary
//!
//! The post-capture verification is limited to what
//! `SqliteStore::backup_to_file` already proves on the snapshot
//! (`verify_sqlite_snapshot`: `PRAGMA integrity_check`, `PRAGMA
//! foreign_key_check`, and presence of the `_sqlx_migrations` table). There
//! is no public read API for arbitrary queries against the snapshot, and this
//! slice adds none; table-level enumeration of the canonical repository
//! (resources, operations, placement/topology, building blocks, IAM/bootstrap,
//! audit events, and the rest of the migrated schema) is therefore not
//! re-verified here. The source journal mode is recorded in the metadata.
//!
//! Linux-only, mirroring the handoff gating in `o3k-store`.

use std::{
    fs,
    io::{self, Read, Write},
    os::unix::fs::{DirBuilderExt, MetadataExt},
    path::{Path, PathBuf},
    process::ExitCode,
    time::{Duration, Instant},
};

use o3k_store::{
    BackupControlError, BackupHandoffRequest, HandoffRejectReason, SqliteStore, StoreAccessLock,
    StoreError, WalCheckpointMode, connect_and_request, identity_tokens,
};
use rustix::fs::renameat_with;
use rustix::fs::{CWD, Mode, OFlags, RenameFlags, open};
use rustix::process::geteuid;
use serde_json::{Value, json};
use sha2::{Digest, Sha256};
use uuid::Uuid;

use crate::output::now_utc_rfc3339;

/// Default daemon data directory; mirrors `o3k-config`'s `DEFAULT_DATA_DIR`.
const DEFAULT_DATA_DIR: &str = "./data";
/// Default overall deadline for the whole provisional capture.
const OVERALL_DEADLINE: Duration = Duration::from_secs(120);
/// Bound for the authenticated handoff request/response exchange.
const CONTROL_REQUEST_TIMEOUT: Duration = Duration::from_secs(10);
/// Bound for receiving the store-access lock descriptors after acceptance.
const HANDOFF_RECEIVE_TIMEOUT: Duration = Duration::from_secs(30);
/// Denial-only interrupted-backup marker inside the data directory.
const MARKER_FILE_PREFIX: &str = ".o3k-backup-in-progress-";
/// Dot-prefixed staging directory inside the destination (never discoverable
/// as a successful backup while incomplete).
const STAGING_DIR_PREFIX: &str = ".o3k-backup-provisional-";
/// Published provisional capture directory name.
const FINAL_DIR_PREFIX: &str = "provisional-backup-";
/// Snapshot file name inside the capture directory.
const SNAPSHOT_FILE_NAME: &str = "o3k.sqlite";
/// Format tag recorded in `metadata.json`.
const FORMAT_TAG: &str = "o3k-provisional-backup-v1";
/// Bounded human/machine note emitted on success.
const PROVISIONAL_NOTE: &str =
    "not a supported PP.6 backup artifact; signing/publication not integrated";

/// Exit codes defined by SPEC-0050 §8.
const EXIT_REJECTED: u8 = 2;
const EXIT_RECOVERABLE: u8 = 3;
const EXIT_UNKNOWN: u8 = 4;

/// Crash-injection hooks for the concurrency campaign; compiled only with the
/// `backup-test-hooks` feature.
#[cfg(feature = "backup-test-hooks")]
macro_rules! test_hook_exit {
    ($var:literal, $code:expr) => {
        if std::env::var_os($var).is_some_and(|value| value == "1") {
            std::process::exit($code);
        }
    };
}

#[cfg(not(feature = "backup-test-hooks"))]
macro_rules! test_hook_exit {
    ($var:literal, $code:expr) => {{}};
}

/// Two-way file barrier for real-process failure injection (feature
/// `backup-test-hooks`). After the store-lock handoff completes — while this
/// executor owns the lock but before the interrupted-backup marker exists —
/// it creates the `O3K_BACKUP_TEST_BARRIER_READY_FILE` and then polls for
/// `O3K_BACKUP_TEST_BARRIER_WAIT_FILE`, giving a test a deterministic window
/// in which the executor holds the lock (for sender-SIGKILL and competing-
/// opener cases). The wait is bounded; a broken barrier exits 93 instead of
/// hanging the capture.
#[cfg(feature = "backup-test-hooks")]
fn test_barrier_after_receive() {
    let Some(ready) = std::env::var_os("O3K_BACKUP_TEST_BARRIER_READY_FILE") else {
        return;
    };
    let ready_path = PathBuf::from(ready);
    if fs::File::create(&ready_path).is_err() {
        std::process::exit(93);
    }
    let Some(wait) = std::env::var_os("O3K_BACKUP_TEST_BARRIER_WAIT_FILE") else {
        return;
    };
    let wait_path = PathBuf::from(wait);
    let deadline = Instant::now() + Duration::from_secs(30);
    while !wait_path.exists() {
        if Instant::now() >= deadline {
            std::process::exit(93);
        }
        std::thread::sleep(Duration::from_millis(100));
    }
}

#[cfg(not(feature = "backup-test-hooks"))]
fn test_barrier_after_receive() {}

/// Arguments of `o3k backup create`.
pub struct BackupCreateArgs {
    /// Absolute destination directory for the provisional capture.
    pub destination: PathBuf,
    /// Durable identity of this backup operation.
    pub operation_id: Uuid,
}

/// Bounded machine-readable result of one executor run.
struct BackupCreateOutcome {
    exit_code: u8,
    json: Value,
}

impl BackupCreateOutcome {
    fn rejected(operation_id: Uuid, reason: &str) -> Self {
        Self::with_status(EXIT_REJECTED, "rejected", operation_id, reason)
    }

    fn recoverable(operation_id: Uuid, reason: &str) -> Self {
        Self::with_status(
            EXIT_RECOVERABLE,
            "recoverable-failure",
            operation_id,
            reason,
        )
    }

    fn unknown(operation_id: Uuid, reason: &str) -> Self {
        Self::with_status(EXIT_UNKNOWN, "unknown", operation_id, reason)
    }

    fn with_status(exit_code: u8, status: &str, operation_id: Uuid, reason: &str) -> Self {
        Self {
            exit_code,
            json: json!({
                "status": status,
                "reason": reason,
                "operation_id": operation_id,
            }),
        }
    }
}

/// Runs `o3k backup create`, printing the bounded JSON result on stdout and a
/// stable reason line on stderr, and returns the process exit code.
pub fn run_backup_create(args: &BackupCreateArgs) -> ExitCode {
    let outcome = execute(args);
    let line = serde_json::to_string(&outcome.json).unwrap_or_else(|_| {
        format!(
            "{{\"status\":\"recoverable-failure\",\"reason\":\"output-serialization-failed\",\"operation_id\":\"{}\"}}",
            args.operation_id
        )
    });
    println!("{line}");
    if outcome.exit_code == 0 {
        return ExitCode::SUCCESS;
    }
    let reason = outcome
        .json
        .get("reason")
        .and_then(Value::as_str)
        .unwrap_or("unspecified");
    eprintln!("o3k backup create [{}]: {reason}", args.operation_id);
    ExitCode::from(outcome.exit_code)
}

/// Validates the destination and resolves the daemon data directory from the
/// environment, then runs the capture against both.
fn execute(args: &BackupCreateArgs) -> BackupCreateOutcome {
    let started_at = now_utc_rfc3339();
    if let Err(reason) = validate_destination(&args.destination) {
        return BackupCreateOutcome::rejected(args.operation_id, reason);
    }
    let data_dir = match resolve_data_dir() {
        Ok(dir) => dir,
        Err(reason) => return BackupCreateOutcome::rejected(args.operation_id, reason),
    };
    execute_inner(args, args.destination.clone(), data_dir, started_at)
}

/// Validates `--destination`: absolute, existing, a real directory (no symlink
/// substitution), owned by the effective uid, and not group/other-writable.
fn validate_destination(destination: &Path) -> Result<(), &'static str> {
    if !destination.is_absolute() {
        return Err("destination-not-absolute");
    }
    let metadata = match fs::symlink_metadata(destination) {
        Ok(metadata) => metadata,
        Err(error) if error.kind() == io::ErrorKind::NotFound => {
            return Err("destination-missing");
        }
        Err(_) => return Err("destination-unreadable"),
    };
    if metadata.file_type().is_symlink() {
        return Err("destination-symlink");
    }
    if !metadata.file_type().is_dir() {
        return Err("destination-not-directory");
    }
    if metadata.uid() != geteuid().as_raw() {
        return Err("destination-not-euid-owned");
    }
    if metadata.mode() & 0o022 != 0 {
        return Err("destination-group-or-other-writable");
    }
    Ok(())
}

/// Resolves the daemon data directory the way `o3k-config` does for the
/// SQLite default: non-empty `O3K_DATA_DIR`, else `./data`, canonicalized.
fn resolve_data_dir() -> Result<PathBuf, &'static str> {
    let configured = std::env::var("O3K_DATA_DIR")
        .ok()
        .map(|value| value.trim().to_owned())
        .filter(|value| !value.is_empty());
    resolve_data_dir_from(configured.as_deref())
}

fn resolve_data_dir_from(configured: Option<&str>) -> Result<PathBuf, &'static str> {
    fs::canonicalize(data_dir_from(configured)).map_err(|_| "data-dir-unavailable")
}

/// Chooses the configured data directory: non-empty trimmed `O3K_DATA_DIR`,
/// else the `./data` default (mirroring `o3k-config`).
fn data_dir_from(configured: Option<&str>) -> PathBuf {
    configured
        .map(str::trim)
        .filter(|value| !value.is_empty())
        .map(PathBuf::from)
        .unwrap_or_else(|| PathBuf::from(DEFAULT_DATA_DIR))
}

/// Executes the provisional capture once the destination and data directory
/// are known. Post-lock failures keep the interrupted-backup marker unless the
/// capture finalized cleanly.
#[allow(clippy::too_many_lines)]
fn execute_inner(
    args: &BackupCreateArgs,
    destination_dir: PathBuf,
    data_dir: PathBuf,
    started_at: String,
) -> BackupCreateOutcome {
    let operation_id = args.operation_id;
    let deadline = Instant::now()
        .checked_add(OVERALL_DEADLINE)
        .unwrap_or_else(|| Instant::now() + Duration::from_secs(3600));

    let (installation, site) = match identity_tokens(&data_dir) {
        Ok(tokens) => tokens,
        Err(_) => {
            return BackupCreateOutcome::recoverable(operation_id, "identity-derivation-failed");
        }
    };
    let request = BackupHandoffRequest {
        operation_id,
        installation,
        site,
    };
    let stream = match connect_and_request(&data_dir, &request, CONTROL_REQUEST_TIMEOUT) {
        Ok(stream) => stream,
        Err(BackupControlError::Rejected(reason)) => {
            return BackupCreateOutcome::rejected(operation_id, reject_reason_code(reason));
        }
        Err(BackupControlError::AlreadyActive) => {
            return BackupCreateOutcome::rejected(operation_id, "backup-already-active");
        }
        Err(BackupControlError::PeerChanged) | Err(BackupControlError::Unauthorized) => {
            return BackupCreateOutcome::rejected(operation_id, "unauthorized-peer");
        }
        Err(BackupControlError::Timeout) => {
            return BackupCreateOutcome::recoverable(operation_id, "controller-timeout");
        }
        Err(BackupControlError::InvalidInput) => {
            return BackupCreateOutcome::recoverable(operation_id, "internal-invalid-input");
        }
        Err(BackupControlError::Io(_)) => {
            return BackupCreateOutcome::rejected(operation_id, "controller-unavailable");
        }
    };

    test_hook_exit!("O3K_BACKUP_TEST_EXIT_BEFORE_RECEIVE", 95);
    let (_store_lock, _handoff_stream) =
        match StoreAccessLock::receive_handoff(stream, HANDOFF_RECEIVE_TIMEOUT) {
            Ok(pair) => pair,
            Err(_) => {
                return BackupCreateOutcome::recoverable(operation_id, "handoff-receive-failed");
            }
        };
    test_hook_exit!("O3K_BACKUP_TEST_EXIT_AFTER_RECEIVE", 94);
    test_barrier_after_receive();

    // From here on we hold the exclusive store-access lock. Every failure path
    // keeps the denial-only marker so daemon startup stays blocked until an
    // operator inspects the interrupted capture.
    let marker_path = data_dir.join(format!("{MARKER_FILE_PREFIX}{operation_id}"));
    let marker_body = json!({
        "operation_id": operation_id,
        "pid": std::process::id(),
        "started_at": started_at,
    });
    if let Err(error) = write_exclusive_private(&marker_path, &marker_body) {
        let reason = if error.kind() == io::ErrorKind::AlreadyExists {
            "backup-in-progress-marker-present"
        } else {
            "marker-write-failed"
        };
        return BackupCreateOutcome::recoverable(operation_id, reason);
    }
    if sync_dir(&data_dir).is_err() {
        return BackupCreateOutcome::recoverable(operation_id, "marker-sync-failed");
    }

    let runtime = match tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()
    {
        Ok(runtime) => runtime,
        Err(_) => return BackupCreateOutcome::recoverable(operation_id, "runtime-build-failed"),
    };
    let db_path = data_dir.join(SNAPSHOT_FILE_NAME);
    let store = match runtime.block_on(SqliteStore::open_existing_file_for_backup(&db_path)) {
        Ok(store) => store,
        Err(_) => return BackupCreateOutcome::recoverable(operation_id, "store-open-failed"),
    };

    if Instant::now() >= deadline {
        return BackupCreateOutcome::recoverable(operation_id, "deadline-exceeded");
    }
    if runtime
        .block_on(store.checkpoint(WalCheckpointMode::Truncate))
        .is_err()
    {
        return BackupCreateOutcome::recoverable(operation_id, "checkpoint-failed");
    }
    let source_before = match sha256_hex_file(&db_path) {
        Ok(hash) => hash,
        Err(_) => return BackupCreateOutcome::recoverable(operation_id, "source-hash-failed"),
    };

    let staging_dir = destination_dir.join(format!("{STAGING_DIR_PREFIX}{operation_id}"));
    if let Err(error) = fs::DirBuilder::new().mode(0o700).create(&staging_dir) {
        let reason = if error.kind() == io::ErrorKind::AlreadyExists {
            "staging-directory-exists"
        } else {
            "staging-directory-create-failed"
        };
        return BackupCreateOutcome::recoverable(operation_id, reason);
    }
    if Instant::now() >= deadline {
        let _ = fs::remove_dir_all(&staging_dir);
        return BackupCreateOutcome::recoverable(operation_id, "deadline-exceeded");
    }

    let snapshot_path = staging_dir.join(SNAPSHOT_FILE_NAME);
    match runtime.block_on(store.backup_to_file(&snapshot_path)) {
        Ok(()) => {}
        Err(StoreError::BackupPublicationUncertain) => {
            // The snapshot may exist at the destination but its verification
            // or publication step failed; the outcome is unknown, so the
            // staging content is preserved for inspection.
            return BackupCreateOutcome::unknown(operation_id, "capture-outcome-unknown");
        }
        Err(_) => {
            let _ = fs::remove_dir_all(&staging_dir);
            return BackupCreateOutcome::recoverable(operation_id, "capture-failed");
        }
    }

    if Instant::now() >= deadline {
        let _ = fs::remove_dir_all(&staging_dir);
        return BackupCreateOutcome::recoverable(operation_id, "deadline-exceeded");
    }
    let source_after = match sha256_hex_file(&db_path) {
        Ok(hash) => hash,
        Err(_) => {
            let _ = fs::remove_dir_all(&staging_dir);
            return BackupCreateOutcome::unknown(operation_id, "source-rehash-failed");
        }
    };
    if source_before != source_after {
        let _ = fs::remove_dir_all(&staging_dir);
        return BackupCreateOutcome::unknown(operation_id, "source-modified-during-capture");
    }
    let snapshot_hash = match sha256_hex_file(&snapshot_path) {
        Ok(hash) => hash,
        Err(_) => {
            let _ = fs::remove_dir_all(&staging_dir);
            return BackupCreateOutcome::unknown(operation_id, "snapshot-hash-failed");
        }
    };
    let journal_mode = match runtime.block_on(store.journal_mode()) {
        Ok(mode) => mode,
        Err(_) => {
            return BackupCreateOutcome::recoverable(operation_id, "journal-mode-read-failed");
        }
    };

    let metadata = json!({
        "format": FORMAT_TAG,
        "operation_id": operation_id,
        "quiescence_generation": operation_id,
        "started_at": started_at,
        "completed_at": now_utc_rfc3339(),
        "source_db_sha256_before": source_before,
        "source_db_sha256_after": source_after,
        "snapshot_sha256": snapshot_hash,
        "journal_mode": journal_mode,
        "cli_version": env!("CARGO_PKG_VERSION"),
        "provisional": true,
    });
    if write_exclusive_private(&staging_dir.join("metadata.json"), &metadata).is_err() {
        return BackupCreateOutcome::recoverable(operation_id, "metadata-write-failed");
    }

    if sync_dir(&staging_dir).is_err() {
        return BackupCreateOutcome::recoverable(operation_id, "staging-sync-failed");
    }
    let final_path = destination_dir.join(format!("{FINAL_DIR_PREFIX}{operation_id}"));
    if rename_no_replace(&staging_dir, &final_path).is_err() {
        return BackupCreateOutcome::recoverable(operation_id, "finalize-rename-failed");
    }

    #[cfg(feature = "backup-test-hooks")]
    let keep_marker =
        std::env::var_os("O3K_BACKUP_TEST_SKIP_MARKER_CLEANUP").is_some_and(|value| value == "1");
    #[cfg(not(feature = "backup-test-hooks"))]
    let keep_marker = false;
    if !keep_marker && fs::remove_file(&marker_path).is_err() {
        return BackupCreateOutcome::recoverable(operation_id, "marker-removal-failed");
    }
    let _ = sync_dir(&data_dir);

    BackupCreateOutcome {
        exit_code: 0,
        json: json!({
            "status": "provisional-capture-complete",
            "operation_id": operation_id,
            "path": final_path.to_string_lossy(),
            "integrity": "ok",
            "source_unchanged": true,
            "provisional": true,
            "verification": "store-snapshot-guarantees",
            "note": PROVISIONAL_NOTE,
        }),
    }
}

/// Maps an in-band handoff rejection to a stable reason code.
fn reject_reason_code(reason: HandoffRejectReason) -> &'static str {
    match reason {
        HandoffRejectReason::UnauthorizedPeer => "unauthorized-peer",
        HandoffRejectReason::Malformed => "malformed-request",
        HandoffRejectReason::DuplicateOperation => "duplicate-operation",
        HandoffRejectReason::AlreadyActive => "backup-already-active",
        HandoffRejectReason::IdentityMismatch => "identity-mismatch",
        HandoffRejectReason::DrainFailed => "drain-failed",
    }
}

/// Writes `body` as JSON to `path` with `O_CREAT|O_EXCL|O_NOFOLLOW`, mode
/// 0600, fsyncing the file. The exclusive create makes the marker and the
/// metadata denial-only: an existing entry fails instead of being replaced.
fn write_exclusive_private(path: &Path, body: &Value) -> io::Result<()> {
    let fd = open(
        path,
        OFlags::RDWR | OFlags::CREATE | OFlags::EXCL | OFlags::CLOEXEC | OFlags::NOFOLLOW,
        Mode::from_raw_mode(0o600),
    )?;
    let mut file = fs::File::from(fd);
    let bytes = serde_json::to_vec(body).map_err(io::Error::other)?;
    file.write_all(&bytes)?;
    file.sync_all()?;
    Ok(())
}

/// fsyncs a directory through a no-follow descriptor.
fn sync_dir(dir: &Path) -> io::Result<()> {
    let fd = open(
        dir,
        OFlags::RDONLY | OFlags::DIRECTORY | OFlags::CLOEXEC | OFlags::NOFOLLOW,
        Mode::empty(),
    )?;
    fs::File::from(fd).sync_all()
}

/// Publishes the staging directory with a same-filesystem no-replace rename.
fn rename_no_replace(from: &Path, to: &Path) -> io::Result<()> {
    renameat_with(CWD, from, CWD, to, RenameFlags::NOREPLACE).map_err(io::Error::from)
}

/// Streaming SHA-256 of a file, hex-encoded (bounded memory, no secrets).
fn sha256_hex_file(path: &Path) -> io::Result<String> {
    let mut file = fs::File::open(path)?;
    let mut hasher = Sha256::new();
    let mut buffer = [0_u8; 64 * 1024];
    loop {
        let read = file.read(&mut buffer)?;
        if read == 0 {
            break;
        }
        hasher.update(&buffer[..read]);
    }
    Ok(hex::encode(hasher.finalize()))
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::{
        os::unix::fs::{PermissionsExt, symlink},
        sync::atomic::{AtomicU64, Ordering},
        thread,
        time::{Duration, SystemTime},
    };

    static NEXT_ID: AtomicU64 = AtomicU64::new(1);

    struct TempRoot(PathBuf);

    impl TempRoot {
        fn new(tag: &str) -> io::Result<Self> {
            let unique = NEXT_ID.fetch_add(1, Ordering::Relaxed);
            let nanos = SystemTime::now()
                .duration_since(SystemTime::UNIX_EPOCH)
                .map(|elapsed| elapsed.as_nanos())
                .unwrap_or(0);
            let path = std::env::temp_dir().join(format!(
                "o3k-backup-create-{tag}-{}-{unique}-{nanos}",
                std::process::id()
            ));
            fs::create_dir(&path)?;
            fs::set_permissions(&path, fs::Permissions::from_mode(0o700))?;
            Ok(Self(path))
        }

        fn private_dir(&self, name: &str) -> io::Result<PathBuf> {
            let path = self.0.join(name);
            fs::create_dir(&path)?;
            fs::set_permissions(&path, fs::Permissions::from_mode(0o700))?;
            Ok(path)
        }
    }

    impl Drop for TempRoot {
        fn drop(&mut self) {
            let _ = fs::remove_dir_all(&self.0);
        }
    }

    fn outcome_reason(outcome: &BackupCreateOutcome) -> &str {
        outcome
            .json
            .get("reason")
            .and_then(Value::as_str)
            .unwrap_or("")
    }

    fn args_for(destination: PathBuf) -> BackupCreateArgs {
        BackupCreateArgs {
            destination,
            operation_id: Uuid::new_v4(),
        }
    }

    #[test]
    fn relative_destination_is_rejected() {
        let outcome = execute(&args_for(PathBuf::from("relative-dest")));
        assert_eq!(outcome.exit_code, EXIT_REJECTED);
        assert_eq!(outcome_reason(&outcome), "destination-not-absolute");
    }

    #[test]
    fn missing_destination_is_rejected() -> io::Result<()> {
        let root = TempRoot::new("missing")?;
        let outcome = execute(&args_for(root.0.join("absent")));
        assert_eq!(outcome.exit_code, EXIT_REJECTED);
        assert_eq!(outcome_reason(&outcome), "destination-missing");
        Ok(())
    }

    #[test]
    fn regular_file_destination_is_rejected() -> io::Result<()> {
        let root = TempRoot::new("file-dest")?;
        let file = root.0.join("a-file");
        fs::write(&file, b"data")?;
        let outcome = execute(&args_for(file));
        assert_eq!(outcome.exit_code, EXIT_REJECTED);
        assert_eq!(outcome_reason(&outcome), "destination-not-directory");
        Ok(())
    }

    #[test]
    fn symlink_destination_is_rejected() -> io::Result<()> {
        let root = TempRoot::new("symlink-dest")?;
        let real = root.private_dir("real")?;
        let link = root.0.join("link");
        symlink(&real, &link)?;
        let outcome = execute(&args_for(link));
        assert_eq!(outcome.exit_code, EXIT_REJECTED);
        assert_eq!(outcome_reason(&outcome), "destination-symlink");
        Ok(())
    }

    #[test]
    fn group_or_other_writable_destination_is_rejected() -> io::Result<()> {
        let root = TempRoot::new("writable-dest")?;
        let open = root.private_dir("open")?;
        fs::set_permissions(&open, fs::Permissions::from_mode(0o777))?;
        let outcome = execute(&args_for(open));
        assert_eq!(outcome.exit_code, EXIT_REJECTED);
        assert_eq!(
            outcome_reason(&outcome),
            "destination-group-or-other-writable"
        );
        Ok(())
    }

    #[test]
    fn data_dir_selection_matches_config_precedence() {
        assert_eq!(
            data_dir_from(Some("/tmp/o3k-a")),
            PathBuf::from("/tmp/o3k-a")
        );
        assert_eq!(
            data_dir_from(Some("  /tmp/o3k-b ")),
            PathBuf::from("/tmp/o3k-b")
        );
        for empty in [None, Some(""), Some("   ")] {
            assert_eq!(data_dir_from(empty), PathBuf::from(DEFAULT_DATA_DIR));
        }
    }

    #[test]
    fn data_dir_resolution_canonicalizes_existing_directory() -> io::Result<()> {
        let root = TempRoot::new("data-dir")?;
        let utf8_path = root
            .0
            .to_str()
            .ok_or_else(|| io::Error::new(io::ErrorKind::InvalidData, "temp path is not UTF-8"))?;
        let explicit = resolve_data_dir_from(Some(utf8_path)).map_err(io::Error::other)?;
        assert_eq!(explicit, fs::canonicalize(&root.0)?);
        let unresolved = resolve_data_dir_from(Some("/definitely/missing/o3k-path"));
        assert_eq!(unresolved.err(), Some("data-dir-unavailable"));
        Ok(())
    }

    #[test]
    fn missing_controller_socket_is_rejected() -> io::Result<()> {
        let root = TempRoot::new("no-controller")?;
        let data_dir = root.private_dir("data")?;
        let dest = root.private_dir("dest")?;
        let outcome = execute_inner(&args_for(dest.clone()), dest, data_dir, now_utc_rfc3339());
        assert_eq!(outcome.exit_code, EXIT_REJECTED);
        assert_eq!(outcome_reason(&outcome), "controller-unavailable");
        Ok(())
    }

    #[test]
    fn impostor_executor_is_rejected_by_listener() -> io::Result<()> {
        let root = TempRoot::new("impostor")?;
        let data_dir = root.private_dir("data")?;
        let dest = root.private_dir("dest")?;
        let (installation, site) = identity_tokens(&data_dir)?;
        let impostor = [PathBuf::from("/bin/false"), PathBuf::from("/usr/bin/false")]
            .into_iter()
            .find(|path| path.exists())
            .ok_or_else(|| io::Error::other("no impostor executable available"))?;
        let expected = o3k_store::ExpectedExecutor {
            exe: impostor,
            uid: geteuid().as_raw(),
            installation,
            site,
        };
        let listener = o3k_store::BackupControlListener::bind(&data_dir)?;
        let server = thread::spawn(move || {
            let _ = listener.accept_authenticated(&expected, Duration::from_secs(10));
        });
        let outcome = execute_inner(
            &args_for(dest.clone()),
            dest,
            data_dir.clone(),
            now_utc_rfc3339(),
        );
        server
            .join()
            .map_err(|_| io::Error::other("listener thread panicked"))?;
        assert_eq!(outcome.exit_code, EXIT_REJECTED);
        assert_eq!(outcome_reason(&outcome), "unauthorized-peer");
        Ok(())
    }

    #[test]
    fn broken_handoff_is_recoverable() -> io::Result<()> {
        let root = TempRoot::new("broken-handoff")?;
        let data_dir = root.private_dir("data")?;
        let dest = root.private_dir("dest")?;
        let control = data_dir.join(o3k_store::BACKUP_CONTROL_DIR);
        fs::create_dir(&control)?;
        fs::set_permissions(&control, fs::Permissions::from_mode(0o700))?;
        let listener =
            std::os::unix::net::UnixListener::bind(control.join(o3k_store::BACKUP_CONTROL_SOCKET))?;
        let server = thread::spawn(move || -> io::Result<()> {
            let (mut stream, _) = listener.accept()?;
            let mut frame = [0_u8; 64];
            stream.read_exact(&mut frame)?;
            // Answer with the acceptance frame, then close without ever
            // sending the lock-handoff frame.
            stream.write_all(b"O3KBKAC\0")?;
            thread::sleep(Duration::from_millis(100));
            Ok(())
        });
        let outcome = execute_inner(&args_for(dest.clone()), dest, data_dir, now_utc_rfc3339());
        server
            .join()
            .map_err(|_| io::Error::other("fake controller thread panicked"))??;
        assert_eq!(outcome.exit_code, EXIT_RECOVERABLE);
        assert_eq!(outcome_reason(&outcome), "handoff-receive-failed");
        Ok(())
    }

    #[test]
    fn provisional_capture_completes_end_to_end() -> io::Result<()> {
        let root = TempRoot::new("end-to-end")?;
        let data_dir = root.private_dir("data")?;
        let dest = root.private_dir("dest")?;
        let operation_id = Uuid::new_v4();

        // A real migrated database stands in for the daemon-owned store; the
        // daemon side drops it before handing off the lock.
        let runtime = tokio::runtime::Builder::new_current_thread()
            .enable_all()
            .build()?;
        runtime
            .block_on(o3k_store::testkit::open_file(&data_dir.join("o3k.sqlite")))
            .map_err(|error| io::Error::other(error.to_string()))?;
        drop(runtime);

        let (installation, site) = identity_tokens(&data_dir)?;
        let expected = o3k_store::ExpectedExecutor {
            exe: fs::canonicalize(std::env::current_exe()?)?,
            uid: geteuid().as_raw(),
            installation,
            site,
        };
        let listener = o3k_store::BackupControlListener::bind(&data_dir)?;
        let server_data_dir = data_dir.clone();
        let server = thread::spawn(move || -> io::Result<()> {
            let lock = StoreAccessLock::acquire(&server_data_dir)?;
            let mut accepted = listener
                .accept_authenticated(&expected, Duration::from_secs(10))
                .map_err(io::Error::other)?;
            accepted.send_accept()?;
            lock.handoff(&mut accepted.stream, Duration::from_secs(10))
                .map_err(|(_, error)| error)
        });

        let outcome = execute_inner(
            &BackupCreateArgs {
                destination: dest.clone(),
                operation_id,
            },
            dest.clone(),
            data_dir.clone(),
            now_utc_rfc3339(),
        );
        server
            .join()
            .map_err(|_| io::Error::other("handoff server thread panicked"))??;
        assert_eq!(outcome.exit_code, 0, "unexpected outcome: {}", outcome.json);
        assert_eq!(outcome.json["status"], "provisional-capture-complete");
        assert_eq!(outcome.json["operation_id"], operation_id.to_string());
        assert_eq!(outcome.json["source_unchanged"], true);
        assert_eq!(outcome.json["provisional"], true);
        assert_eq!(
            outcome.json["note"],
            "not a supported PP.6 backup artifact; signing/publication not integrated"
        );

        let final_dir = dest.join(format!("{FINAL_DIR_PREFIX}{operation_id}"));
        assert!(final_dir.is_dir());
        assert!(
            !dest
                .join(format!("{STAGING_DIR_PREFIX}{operation_id}"))
                .exists()
        );
        assert!(final_dir.join(SNAPSHOT_FILE_NAME).is_file());
        let metadata: Value = serde_json::from_slice(&fs::read(final_dir.join("metadata.json"))?)?;
        assert_eq!(metadata["format"], FORMAT_TAG);
        assert_eq!(metadata["provisional"], true);
        assert_eq!(metadata["operation_id"], operation_id.to_string());
        assert_eq!(metadata["quiescence_generation"], operation_id.to_string());
        assert_eq!(metadata["cli_version"], env!("CARGO_PKG_VERSION"));
        assert_eq!(metadata["snapshot_sha256"].as_str().map(str::len), Some(64));
        assert_eq!(
            metadata["source_db_sha256_after"],
            sha256_hex_file(&data_dir.join(SNAPSHOT_FILE_NAME))?
        );
        assert_eq!(
            metadata["snapshot_sha256"],
            sha256_hex_file(&final_dir.join(SNAPSHOT_FILE_NAME))?
        );
        assert_eq!(
            fs::metadata(final_dir.join("metadata.json"))?
                .permissions()
                .mode()
                & 0o777,
            0o600
        );
        assert!(
            !data_dir
                .join(format!("{MARKER_FILE_PREFIX}{operation_id}"))
                .exists()
        );
        Ok(())
    }
}
