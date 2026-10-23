//! `o3k backup create` — authenticated capture and offline-signing driver for
//! the PP.6 backup artifact (SPEC-0050 §8, ADR-0189 D2/D4/D8/D9/D12).
//!
//! This module owns the `o3k` CLI side of the host-local backup handoff. It
//! requests the authenticated handoff from `o3kd` over the private Unix control
//! socket ([`o3k_store::connect_and_request`]), receives the exclusive
//! store-access lock ([`o3k_store::StoreAccessLock::receive_handoff`]), writes
//! the denial-only interrupted-backup marker, captures an integrity-checked
//! SQLite snapshot through [`o3k_store::SqliteStore::backup_to_file`], proves
//! the source database did not change during capture, and hands the snapshot to
//! [`crate::backup_artifact`] for manifest assembly and encrypted staging.
//!
//! # Two-phase operator flow (Option A, offline custody)
//!
//! The custody-held Ed25519 key is offline, so one invocation cannot finish the
//! artifact. Instead:
//!
//! ```text
//! $ o3k backup create --destination /var/lib/o3k/backups --operation-id UUID
//! {"status":"signing-required", ... "signing_request":".../signing-request.json", ...}
//! # exit 3 — snapshot captured, artifact staged unsigned, marker removed
//!
//! # offline workstation: sign the D1 signing input under the custody process
//! # (two-of-three custodian confirmation) and place signing-response.json
//! # next to the request.
//!
//! $ o3k backup create --destination /var/lib/o3k/backups --operation-id UUID
//! {"status":"backup-published", ... "path":".../backup-UUID.o3k", ...}
//! # exit 0
//! ```
//!
//! The CLI surface is exactly `--destination` and `--operation-id`: the second
//! phase is the same exact request, detected from the durable operation journal
//! before any controller contact. Phase 2 never needs the store lock because it
//! only reads staged files, verifies a detached signature and publishes.
//!
//! The tool accepts a signature produced under the configured custody process;
//! it does not attest custody, custodian identity, the threshold, or the
//! offline workstation's integrity, and it makes no restore claim.
//!
//! # Interruption semantics
//!
//! * The denial-only marker is written before capture and removed as soon as
//!   the artifact is durably staged (capture complete). Publication pending is
//!   a separate, non-canonical state: a replacement controller may start, and
//!   the staged artifact is not canonical state.
//! * Failures after the marker keep the marker so daemon startup stays blocked
//!   until an operator inspects the partial capture. Failures before the marker
//!   leave canonical state untouched.
//! * The operation journal (`<data_dir>/backup-operations/<operation>.json`)
//!   records `capturing → captured → staged → publishing → published`
//!   (`aborted` on a failed attempt). A *new* capture under an operation id
//!   whose journal already says `published` is refused (exit 2,
//!   `operation-already-published`). The daemon's per-lifetime accepted-id
//!   list still covers genuinely concurrent attempts; the journal only covers
//!   durable operation identity across restarts.
//!
//! # Exit-code contract (SPEC-0050 §8)
//!
//! ```text
//! 0  artifact published (phase 2 only)
//! 2  rejected precondition (unusable or overlapping destination, invalid
//!    trust/release configuration, D9 source/space bound, controller
//!    unavailable or rejected the handoff, already-published operation, or an
//!    invalid signing response)
//! 3  recoverable failure, including `signing-required` (capture staged;
//!    publication pending) and a failed capture/finalization. Once the
//!    interrupted-backup marker is written it is kept on failure so daemon
//!    preflight stays blocked until an operator clears it, and the staging
//!    directory is kept for inspection.
//! 4  unknown/quarantined outcome (source immutability could not be proven, or
//!    the capture/publication outcome is uncertain)
//! ```
//!
//! # Destination integrity
//!
//! The destination is validated up front (absolute, existing, real directory,
//! effective-uid-owned, not group/other-writable, and not equal to or inside
//! the canonical data directory). It is then opened through a retained
//! no-follow descriptor: the staging directory is created with `mkdirat`
//! relative to that descriptor and itself opened as a second no-follow
//! descriptor, so every capture and staging access is dir-fd-anchored through
//! `/proc/self/fd/<staging-fd>` magic links (the artifact builder accepts that
//! form explicitly). Publication is a `renameat(RENAME_NOREPLACE)` inside the
//! retained destination descriptor, and the destination directory is fsynced
//! after the rename.
//!
//! Stdout carries exactly one line of bounded JSON; stderr carries only the
//! stable reason code and the operation id. Secrets never appear in arguments,
//! environment, or logs; identity tokens travel only inside the socket request
//! frame, and signing material is never read by this process.
//!
//! # Data-directory resolution
//!
//! The executor resolves the same directory the running `o3kd` was launched
//! with, because both sides derive the installation/site identity tokens from
//! the canonical path and the control socket lives inside it. It reuses
//! `o3k-config`'s precedence: non-empty `O3K_DATA_DIR`, else `./data`
//! ([`DEFAULT_DATA_DIR`]), canonicalized.
//!
//! Linux-only, mirroring the handoff gating in `o3k-store`.

use std::{
    fs,
    io::{self, Read, Write},
    os::unix::{fs::MetadataExt, io::AsRawFd},
    path::{Path, PathBuf},
    process::ExitCode,
    time::{Duration, Instant},
};

use o3k_store::{
    BackupControlError, BackupHandoffRequest, HandoffRejectReason, SqliteStore, StoreAccessLock,
    StoreError, WalCheckpointMode,
    backup_journal::{self, BackupOperationPhase, BackupOperationRecord},
    connect_and_request, identity_tokens,
};
use rustix::fd::OwnedFd;
use rustix::fs::{Mode, OFlags, fstat, mkdirat, open, openat};
use rustix::process::geteuid;
use serde_json::{Value, json};
use sha2::{Digest, Sha256};
use uuid::Uuid;

use crate::{
    backup_artifact::{
        ArtifactConfig, ArtifactFailure, ArtifactFailureClass, CaptureInputs, CompletionInputs,
        CompletionOutcome, OPERATION_STAGING_PREFIX, complete_staged, install_prefix,
        stage_capture,
    },
    backup_reservation::preflight_reservation,
    backup_trust::default_trust_config_path,
    output::now_utc_rfc3339,
};

/// Default daemon data directory; mirrors `o3k-config`'s `DEFAULT_DATA_DIR`.
const DEFAULT_DATA_DIR: &str = "./data";
/// Default overall deadline for the whole capture.
const OVERALL_DEADLINE: Duration = Duration::from_secs(120);
/// Bound for the authenticated handoff request/response exchange.
const CONTROL_REQUEST_TIMEOUT: Duration = Duration::from_secs(10);
/// Bound for receiving the store-access lock descriptors after acceptance.
/// The daemon's post-acceptance drain is a sequence of 5s-bounded steps
/// (~55-80s worst case) plus the bounded API-serve drain, so the receive
/// must tolerate the full [`OVERALL_DEADLINE`] window; anything shorter
/// would turn a slow-but-correct drain into a spurious receive timeout.
const HANDOFF_RECEIVE_TIMEOUT: Duration = Duration::from_secs(120);
/// Denial-only interrupted-backup marker inside the data directory.
const MARKER_FILE_PREFIX: &str = ".o3k-backup-in-progress-";
/// Snapshot file name inside the operation staging directory (also the
/// `database/o3k.sqlite` member source).
const SNAPSHOT_FILE_NAME: &str = "o3k.sqlite";

/// Bounded human/machine note emitted with `signing-required`.
const SIGNING_REQUIRED_NOTE: &str = "artifact is staged and unsigned; sign the D1 signing input offline under the configured custody process, write signing-response.json next to signing-request.json, and re-run the same command";
/// Bounded human/machine note emitted on publication.
const PUBLISHED_NOTE: &str = "artifact signature was verified against the installed trust document; this tool does not attest the custody process and makes no restore claim";

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
    /// Absolute destination directory for the artifact.
    pub destination: PathBuf,
    /// Durable identity of this backup operation.
    pub operation_id: Uuid,
}

/// Root-owned configuration paths the executor reads. Production resolves them
/// from the process environment; tests pass explicit paths so the derivation is
/// exercised without mutating global state.
pub struct ArtifactEnvironment {
    pub trust_config: PathBuf,
    pub install_prefix: PathBuf,
}

impl ArtifactEnvironment {
    /// Resolves the configuration paths from the process environment.
    #[must_use]
    pub fn from_process() -> Self {
        Self {
            trust_config: default_trust_config_path(),
            install_prefix: install_prefix(),
        }
    }
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

/// Maps an artifact-driver failure to the SPEC-0050 §8 exit contract.
fn failure_outcome(operation_id: Uuid, failure: ArtifactFailure) -> BackupCreateOutcome {
    match failure.class() {
        ArtifactFailureClass::Rejected => {
            BackupCreateOutcome::rejected(operation_id, failure.reason())
        }
        ArtifactFailureClass::Recoverable => {
            BackupCreateOutcome::recoverable(operation_id, failure.reason())
        }
        ArtifactFailureClass::Unknown => {
            BackupCreateOutcome::unknown(operation_id, failure.reason())
        }
    }
}

/// Runs `o3k backup create`, printing the bounded JSON result on stdout and a
/// stable reason line on stderr, and returns the process exit code.
pub fn run_backup_create(args: &BackupCreateArgs) -> ExitCode {
    let outcome = execute(args, &ArtifactEnvironment::from_process());
    let line = serde_json::to_string(&outcome.json).unwrap_or_else(|_| {
        format!(
            "{{\"status\":\"recoverable-failure\",\"reason\":\"output-serialization-failed\",\"operation_id\":\"{}\"}}",
            args.operation_id
        )
    });
    // Write the result manually: `println!` panics (exit 101, outside the
    // SPEC-0050 §8 contract) when stdout is closed, e.g. `| head -0`. A failed
    // write keeps the already-computed contract exit code.
    if writeln!(io::stdout(), "{line}").is_err() {
        return ExitCode::from(outcome.exit_code);
    }
    if outcome.exit_code == 0 {
        return ExitCode::SUCCESS;
    }
    // `signing-required` is a normal, recoverable phase-1 result without a
    // failure reason; the status is the stable line in that case.
    let reason = outcome
        .json
        .get("reason")
        .and_then(Value::as_str)
        .or_else(|| outcome.json.get("status").and_then(Value::as_str))
        .unwrap_or("unspecified");
    // Best effort: stderr carries the stable reason line only.
    let _ = writeln!(
        io::stderr(),
        "o3k backup create [{}]: {reason}",
        args.operation_id
    );
    ExitCode::from(outcome.exit_code)
}

/// Validates the destination, resolves the data directory, and either completes
/// a staged operation or starts a fresh capture.
fn execute(args: &BackupCreateArgs, environment: &ArtifactEnvironment) -> BackupCreateOutcome {
    execute_with_data_dir(args, environment, None)
}

/// [`execute`] with an explicit data directory, so tests exercise the exact
/// command logic without mutating the process-wide `O3K_DATA_DIR`.
fn execute_with_data_dir(
    args: &BackupCreateArgs,
    environment: &ArtifactEnvironment,
    data_dir_override: Option<&Path>,
) -> BackupCreateOutcome {
    let operation_id = args.operation_id;
    if let Err(reason) = validate_destination(&args.destination) {
        return BackupCreateOutcome::rejected(operation_id, reason);
    }
    let data_dir = match data_dir_override {
        Some(path) => match fs::canonicalize(path) {
            Ok(path) => path,
            Err(_) => return BackupCreateOutcome::rejected(operation_id, "data-dir-unavailable"),
        },
        None => match resolve_data_dir() {
            Ok(dir) => dir,
            Err(reason) => return BackupCreateOutcome::rejected(operation_id, reason),
        },
    };
    if destination_overlaps_data_dir(&args.destination, &data_dir) {
        return BackupCreateOutcome::rejected(operation_id, "destination-inside-data-dir");
    }
    let destination_fd = match open_destination_dir(&args.destination) {
        Ok(fd) => fd,
        Err(reason) => return BackupCreateOutcome::rejected(operation_id, reason),
    };

    // Durable operation identity is checked before any controller contact: a
    // published operation id is never captured again, and a staged operation
    // is completed from its staged files without taking the store lock.
    match backup_journal::read_backup_operation(&data_dir, operation_id) {
        Err(error) => return BackupCreateOutcome::rejected(operation_id, error.reason()),
        Ok(Some(record)) => match record.phase {
            BackupOperationPhase::Published => {
                return BackupCreateOutcome::rejected(operation_id, "operation-already-published");
            }
            BackupOperationPhase::Staged | BackupOperationPhase::Publishing => {
                return complete_existing(args, environment, &data_dir, destination_fd, record);
            }
            BackupOperationPhase::Capturing | BackupOperationPhase::Captured => {
                return BackupCreateOutcome::recoverable(
                    operation_id,
                    "backup-operation-incomplete",
                );
            }
            BackupOperationPhase::Aborted => {}
        },
        Ok(None) => {}
    }

    execute_inner(
        args,
        args.destination.clone(),
        destination_fd,
        data_dir,
        now_utc_rfc3339(),
        environment,
    )
}

/// Phase 2: verify the detached signature (or finish a publication replay) and
/// publish. This path never contacts the controller and never opens the store.
fn complete_existing(
    args: &BackupCreateArgs,
    environment: &ArtifactEnvironment,
    data_dir: &Path,
    destination_fd: OwnedFd,
    record: BackupOperationRecord,
) -> BackupCreateOutcome {
    let operation_id = args.operation_id;
    let destination_dir = match fs::canonicalize(&args.destination) {
        Ok(path) => path,
        Err(_) => return BackupCreateOutcome::rejected(operation_id, "destination-unavailable"),
    };
    if record.destination != destination_dir.to_string_lossy().as_ref() {
        return BackupCreateOutcome::rejected(operation_id, "operation-destination-mismatch");
    }
    let config = match ArtifactConfig::load_from(
        data_dir,
        &environment.trust_config,
        &environment.install_prefix,
    ) {
        Ok(config) => config,
        Err(failure) => return failure_outcome(operation_id, failure),
    };
    let inputs = CompletionInputs {
        data_dir,
        config: &config,
        destination_dir: &destination_dir,
        destination_fd: &destination_fd,
        operation_id,
        record: &record,
    };
    match complete_staged(&inputs) {
        Ok(CompletionOutcome::SigningRequired {
            request_path,
            expires_at,
        }) => BackupCreateOutcome {
            exit_code: EXIT_RECOVERABLE,
            json: json!({
                "status": "signing-required",
                "operation_id": operation_id,
                "backup_id": record.backup_id,
                "signing_request": request_path.to_string_lossy(),
                "expires_at": expires_at,
                "note": SIGNING_REQUIRED_NOTE,
            }),
        },
        Ok(CompletionOutcome::Published {
            path,
            sha256,
            size_bytes,
        }) => BackupCreateOutcome {
            exit_code: 0,
            json: json!({
                "status": "backup-published",
                "operation_id": operation_id,
                "backup_id": record.backup_id,
                "path": path.to_string_lossy(),
                "sha256": sha256,
                "size_bytes": size_bytes,
                "signature": "verified",
                "note": PUBLISHED_NOTE,
            }),
        },
        Err(failure) => failure_outcome(operation_id, failure),
    }
}

/// Reports whether the destination is the canonical data directory or a
/// descendant of it: a capture is never written into the directory the
/// handoff just drained (the interrupted-backup marker lives there, and
/// publishing next to canonical state would taint the data directory).
fn destination_overlaps_data_dir(destination: &Path, data_dir: &Path) -> bool {
    let Ok(canonical) = fs::canonicalize(destination) else {
        // `validate_destination` established the destination exists; a fresh
        // resolution failure is transient and the descriptor open below fails
        // closed anyway.
        return false;
    };
    canonical == data_dir || canonical.starts_with(data_dir)
}

/// Opens the validated destination directory through a no-follow descriptor
/// retained for the whole capture. Every later destination access (staging
/// `mkdirat` and the staging-dir `openat` under it, the pre-capture and
/// pre-rename revalidations, and the final `renameat`) is relative to this
/// descriptor, so a path-component symlink swap between validation and use
/// cannot redirect the publication.
fn open_destination_dir(destination: &Path) -> Result<OwnedFd, &'static str> {
    open(
        destination,
        OFlags::RDONLY | OFlags::DIRECTORY | OFlags::CLOEXEC | OFlags::NOFOLLOW,
        Mode::empty(),
    )
    .map_err(|_| "destination-unreadable")
}

/// Re-validates the destination directory against the retained descriptor
/// immediately before a path-based operation on it (`backup_to_file`, the
/// final rename): the fresh `lstat` must still resolve to the held inode and
/// keep the effective-uid-owned, not-group/other-writable posture. A symlink
/// swap or entry replacement between validation and use fails closed here.
fn revalidate_destination(dirfd: &OwnedFd, destination: &Path) -> Result<(), &'static str> {
    let held = fstat(dirfd).map_err(|_| "destination-revalidation-failed")?;
    let current =
        fs::symlink_metadata(destination).map_err(|_| "destination-revalidation-failed")?;
    if current.file_type().is_symlink()
        || !current.file_type().is_dir()
        || current.dev() != held.st_dev
        || current.ino() != held.st_ino
        || current.uid() != held.st_uid
        || current.uid() != geteuid().as_raw()
        || held.st_mode & 0o022 != 0
        || current.mode() & 0o022 != 0
    {
        return Err("destination-changed-after-validation");
    }
    Ok(())
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

/// Executes one capture: handoff, configuration and D9 preflight, snapshot,
/// manifest/staging, offline signing request. Post-lock failures keep the
/// interrupted-backup marker (and the staging directory, once created) so an
/// operator can inspect the interrupted capture; the marker blocks daemon
/// preflight until cleared.
#[allow(clippy::too_many_lines)]
fn execute_inner(
    args: &BackupCreateArgs,
    destination_dir: PathBuf,
    destination_fd: OwnedFd,
    data_dir: PathBuf,
    started_at: String,
    environment: &ArtifactEnvironment,
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

    // From here on we hold the exclusive store-access lock. The destination is
    // resolved once; every later use is descriptor-anchored.
    let destination_dir = match fs::canonicalize(&destination_dir) {
        Ok(path) => path,
        Err(_) => return BackupCreateOutcome::recoverable(operation_id, "destination-unavailable"),
    };

    // Root-owned configuration is read under the lock so the captured members
    // (trust document, release manifest) and the manifest options describe the
    // same quiesced generation. A configuration failure exits 2 before any
    // capture; the controller has already exited by design (SOURCE_EXIT).
    let config = match ArtifactConfig::load_from(
        &data_dir,
        &environment.trust_config,
        &environment.install_prefix,
    ) {
        Ok(config) => config,
        Err(failure) => return failure_outcome(operation_id, failure),
    };

    // D9 preflight: the measured source is the snapshot plus the installation
    // metadata members captured below. The destination must hold the full
    // reservation; a shortfall fails closed instead of truncating it.
    let db_path = data_dir.join(SNAPSHOT_FILE_NAME);
    let source_paths: [&Path; 3] = [
        db_path.as_path(),
        config.release_manifest_path(),
        config.trust_config_path(),
    ];
    let reservation = match preflight_reservation(&source_paths, &destination_dir) {
        Ok(reservation) => reservation,
        Err(error) => {
            let reason = error.measurement_code().unwrap_or_else(|| error.reason());
            return BackupCreateOutcome::rejected(operation_id, reason);
        }
    };

    // Denial-only marker first: its presence is what blocks replacement-
    // controller startup. The journal is written immediately after so a later
    // phase can be recognised, but the marker stays the denial authority.
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

    let staging_leaf = format!("{OPERATION_STAGING_PREFIX}{operation_id}");
    let staging_path = destination_dir.join(&staging_leaf);
    let mut journal = BackupOperationRecord {
        format: o3k_store::backup_journal::BACKUP_OPERATION_FORMAT.to_owned(),
        operation_id,
        phase: BackupOperationPhase::Capturing,
        backup_id: operation_id.to_string(),
        destination: destination_dir.to_string_lossy().into_owned(),
        staging_path: staging_path.to_string_lossy().into_owned(),
        request_sha256: None,
        artifact_sha256: None,
        site_id: config.site_id().to_owned(),
        installation_id: config.installation_id().to_owned(),
        created_at: started_at.clone(),
        updated_at: started_at.clone(),
    };
    if let Err(error) = backup_journal::write_backup_operation(&data_dir, &journal) {
        return BackupCreateOutcome::recoverable(operation_id, error.reason());
    }

    let runtime = match tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()
    {
        Ok(runtime) => runtime,
        Err(_) => return BackupCreateOutcome::recoverable(operation_id, "runtime-build-failed"),
    };
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

    match mkdirat(
        &destination_fd,
        staging_leaf.as_str(),
        Mode::from_raw_mode(0o700),
    ) {
        Ok(()) => {}
        Err(rustix::io::Errno::EXIST) => {
            return BackupCreateOutcome::recoverable(operation_id, "staging-directory-exists");
        }
        Err(_) => {
            return BackupCreateOutcome::recoverable(
                operation_id,
                "staging-directory-create-failed",
            );
        }
    }
    // Open the staging directory itself through the held destination dir-fd;
    // the snapshot write below is addressed through this descriptor via a
    // `/proc/self/fd` magic link, so `backup_to_file`'s internal path
    // re-resolution follows the verified directory instead of the (swappable)
    // destination string path.
    let staging_fd = match openat(
        &destination_fd,
        staging_leaf.as_str(),
        OFlags::RDONLY | OFlags::DIRECTORY | OFlags::CLOEXEC | OFlags::NOFOLLOW,
        Mode::empty(),
    ) {
        Ok(fd) => fd,
        Err(_) => {
            return BackupCreateOutcome::recoverable(operation_id, "staging-directory-open-failed");
        }
    };
    if Instant::now() >= deadline {
        return BackupCreateOutcome::recoverable(operation_id, "deadline-exceeded");
    }

    // The destination is revalidated immediately before the capture; a swap
    // since validation fails closed here.
    if let Err(reason) = revalidate_destination(&destination_fd, &destination_dir) {
        return BackupCreateOutcome::recoverable(operation_id, reason);
    }
    let staging_fd_path = PathBuf::from(format!("/proc/self/fd/{}", staging_fd.as_raw_fd()));
    let staged_snapshot_path = staging_fd_path.join(SNAPSHOT_FILE_NAME);
    match runtime.block_on(store.backup_to_file(&staged_snapshot_path)) {
        Ok(()) => {}
        Err(StoreError::BackupPublicationUncertain) => {
            // The snapshot may exist at the destination but its verification
            // or publication step failed; the outcome is unknown, so the
            // staging content is preserved for inspection.
            mark_operation_aborted(&data_dir, &journal);
            return BackupCreateOutcome::unknown(operation_id, "capture-outcome-unknown");
        }
        Err(_) => {
            mark_operation_aborted(&data_dir, &journal);
            return BackupCreateOutcome::recoverable(operation_id, "capture-failed");
        }
    }

    if Instant::now() >= deadline {
        return BackupCreateOutcome::recoverable(operation_id, "deadline-exceeded");
    }
    let source_after = match sha256_hex_file(&db_path) {
        Ok(hash) => hash,
        Err(_) => return BackupCreateOutcome::unknown(operation_id, "source-rehash-failed"),
    };
    if source_before != source_after {
        return BackupCreateOutcome::unknown(operation_id, "source-modified-during-capture");
    }
    if Instant::now() >= deadline {
        return BackupCreateOutcome::recoverable(operation_id, "deadline-exceeded");
    }
    let snapshot_hash = match sha256_hex_file(&staged_snapshot_path) {
        Ok(hash) => hash,
        Err(_) => return BackupCreateOutcome::unknown(operation_id, "snapshot-hash-failed"),
    };
    let journal_mode = match runtime.block_on(store.journal_mode()) {
        Ok(mode) => mode,
        Err(_) => {
            mark_operation_aborted(&data_dir, &journal);
            return BackupCreateOutcome::recoverable(operation_id, "journal-mode-read-failed");
        }
    };
    let completed_at = now_utc_rfc3339();
    journal.phase = BackupOperationPhase::Captured;
    journal.updated_at = completed_at.clone();
    if let Err(error) = backup_journal::write_backup_operation(&data_dir, &journal) {
        return BackupCreateOutcome::recoverable(operation_id, error.reason());
    }
    // Test-only: crash immediately after the durable `captured` transition,
    // before the artifact is staged. The marker is still present, so a retry
    // must refuse to recapture (`backup-operation-incomplete`).
    test_hook_exit!("O3K_BACKUP_TEST_EXIT_AFTER_JOURNAL_CAPTURED", 86);

    if Instant::now() >= deadline {
        return BackupCreateOutcome::recoverable(operation_id, "deadline-exceeded");
    }
    let capture = CaptureInputs {
        config: &config,
        operation_id,
        reservation,
        staging_dir: &staging_fd_path,
        durable_staging_dir: &staging_path,
        snapshot_path: &staged_snapshot_path,
        snapshot_sha256: &snapshot_hash,
        source_before: &source_before,
        source_after: &source_after,
        journal_mode: &journal_mode,
        snapshot_started_at: &started_at,
        snapshot_completed_at: &completed_at,
        runtime: &runtime,
    };
    let staged = match stage_capture(&capture) {
        Ok(staged) => staged,
        Err(failure) => {
            mark_operation_aborted(&data_dir, &journal);
            return failure_outcome(operation_id, failure);
        }
    };

    journal.phase = BackupOperationPhase::Staged;
    journal.backup_id = staged.backup_id.clone();
    journal.request_sha256 = Some(staged.request_sha256.clone());
    journal.updated_at = now_utc_rfc3339();
    if let Err(error) = backup_journal::write_backup_operation(&data_dir, &journal) {
        // The artifact is staged but the durable transition is missing. Keep
        // the marker: the operator must inspect the operation before the
        // controller may start and before publication can be trusted.
        return BackupCreateOutcome::recoverable(operation_id, error.reason());
    }
    // Test-only: crash after the durable `staged` transition but before the
    // denial-only marker is removed. A later phase-2 invocation must complete
    // from the staged files without recapturing.
    test_hook_exit!("O3K_BACKUP_TEST_EXIT_AFTER_JOURNAL_STAGED", 87);

    #[cfg(feature = "backup-test-hooks")]
    let keep_marker =
        std::env::var_os("O3K_BACKUP_TEST_SKIP_MARKER_CLEANUP").is_some_and(|value| value == "1");
    #[cfg(not(feature = "backup-test-hooks"))]
    let keep_marker = false;
    if !keep_marker && fs::remove_file(&marker_path).is_err() {
        return BackupCreateOutcome::recoverable(operation_id, "marker-removal-failed");
    }
    let _ = sync_dir(&data_dir);
    let _ = sync_dir(&destination_dir);

    BackupCreateOutcome {
        exit_code: EXIT_RECOVERABLE,
        json: json!({
            "status": "signing-required",
            "operation_id": operation_id,
            "backup_id": staged.backup_id,
            "signing_request": staged.request_path.to_string_lossy(),
            "expires_at": staged.expires_at,
            "manifest_digest": staged.manifest_digest,
            "signing_input_sha256": staged.signing_input_sha256,
            "artifact_sha256": staged.payload_sha256,
            "artifact_size_bytes": staged.artifact_size_bytes,
            "source_bytes": staged.source_bytes,
            "reserved_bytes": staged.reserved_bytes,
            "note": SIGNING_REQUIRED_NOTE,
        }),
    }
}

/// Records a failed attempt as `aborted` without touching the marker.
///
/// The marker stays the denial authority: a failure after the marker is
/// written blocks replacement-controller startup until an operator inspects
/// the partial capture. The journal update is best effort because the same
/// failure that aborted the attempt may also prevent the update; a crash
/// simply leaves the last durable phase.
fn mark_operation_aborted(data_dir: &Path, journal: &BackupOperationRecord) {
    let mut record = journal.clone();
    record.phase = BackupOperationPhase::Aborted;
    record.updated_at = now_utc_rfc3339();
    let _ = backup_journal::write_backup_operation(data_dir, &record);
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
/// 0600, fsyncing the file. The exclusive create makes the marker denial-only:
/// an existing entry fails instead of being replaced.
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
#[allow(clippy::expect_used, clippy::unwrap_used)]
mod tests {
    use super::*;
    use crate::backup::{ArtifactVerificationKeys, ExpectedRelease};
    use crate::backup_artifact::{
        SIGNING_REQUEST_FORMAT, SIGNING_RESPONSE_FILE, SIGNING_RESPONSE_FORMAT, snapshot_facts,
    };
    use crate::backup_trust::{BackupTrustConfig, site_and_installation_ids};
    use crate::upgrade::release_identity::BackupReleaseIdentity;
    use base64::{Engine as _, engine::general_purpose::URL_SAFE_NO_PAD};
    use ed25519_dalek::{Signer, SigningKey};
    use hpke::{Kem, Serializable, kem::X25519HkdfSha256};
    use serde_json::Value;
    use std::{
        os::unix::fs::{PermissionsExt, symlink},
        sync::atomic::{AtomicU64, Ordering},
        thread,
        time::{Duration, SystemTime},
    };

    static NEXT_ID: AtomicU64 = AtomicU64::new(1);

    const PROFILE_ID: &str = "o3k-demo-v1";
    const SIGNING_KEY_ID: &str = "signing-1";
    const RECIPIENT_KEY_ID: &str = "recovery-1";

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

    fn write_private(path: &Path, bytes: &[u8]) -> io::Result<()> {
        fs::write(path, bytes)?;
        fs::set_permissions(path, fs::Permissions::from_mode(0o600))
    }

    /// The newest SQLite migration prefix, which the release manifest declares
    /// as `schema_version`. Computed from the migration tree so the fixture
    /// never drifts behind a new migration.
    fn latest_sqlite_schema_version() -> u64 {
        let directory = Path::new(concat!(
            env!("CARGO_MANIFEST_DIR"),
            "/../../crates/o3k-store/migrations"
        ));
        fs::read_dir(directory)
            .expect("migration directory")
            .filter_map(|entry| {
                let name = entry.ok()?.file_name();
                name.to_str()?.split('_').next()?.parse::<u64>().ok()
            })
            .max()
            .expect("at least one migration")
    }

    struct ArtifactFixture {
        signing: SigningKey,
        trust_config: PathBuf,
        install_prefix: PathBuf,
        release: BackupReleaseIdentity,
        site_id: String,
        installation_id: String,
    }

    impl ArtifactFixture {
        fn new(root: &TempRoot, data_dir: &Path, schema_version: u64) -> Self {
            let signing = SigningKey::from_bytes(&[17_u8; 32]);
            let (recipient, _public) = X25519HkdfSha256::gen_keypair();
            let recipient_key = root.0.join("recipient.key");
            write_private(&recipient_key, &recipient.to_bytes()).expect("write recipient key");
            let (site_id, installation_id) =
                site_and_installation_ids(data_dir).expect("identity tokens");
            let public_key = signing.verifying_key().to_bytes();
            let trust_config = root.0.join("backup-trust.json");
            let document = json!({
                "format": "o3k-backup-trust-v1",
                "site_id": site_id,
                "installation_id": installation_id,
                "profile_id": PROFILE_ID,
                "artifact_signing": {
                    "key_id": SIGNING_KEY_ID,
                    "ed25519_public_key": hex::encode(public_key),
                },
                "recipient": {
                    "key_id": RECIPIENT_KEY_ID,
                    "x25519_private_key_file": recipient_key.display().to_string(),
                },
                "revoked_key_ids": [],
                "custody": {
                    "record_id": "custody-1",
                    "purpose": "artifact-signing",
                    "key_fingerprint": hex::encode(Sha256::digest(public_key)),
                    "threshold": "2-of-3",
                    "custodians": ["principal-a", "principal-b", "principal-c"],
                    "storage_class": "offline-safe",
                    "expires_at": "2035-01-01T00:00:00Z",
                },
            });
            write_private(
                &trust_config,
                &serde_json::to_vec_pretty(&document).expect("encode trust document"),
            )
            .expect("write trust document");
            let install_prefix = root.0.join("install");
            let share = install_prefix.join("share/o3k");
            fs::create_dir_all(&share).expect("create install prefix");
            fs::set_permissions(&install_prefix, fs::Permissions::from_mode(0o700))
                .expect("restrict install prefix");
            let release = BackupReleaseIdentity {
                o3k_version: "0.4.0".to_owned(),
                source_sha: "0123456789abcdef0123456789abcdef01234567".to_owned(),
                release_artifact_sha256: "a".repeat(64),
                profile_id: PROFILE_ID.to_owned(),
                schema_version,
            };
            let manifest = json!({
                "version": release.o3k_version,
                "profile": "demo",
                "profile_id": release.profile_id,
                "source_commit": release.source_sha,
                "release_artifact_sha256": release.release_artifact_sha256,
                "schema_version": schema_version.to_string(),
            });
            write_private(
                &share.join("release-manifest.json"),
                &serde_json::to_vec(&manifest).expect("encode release manifest"),
            )
            .expect("write release manifest");
            Self {
                signing,
                trust_config,
                install_prefix,
                release,
                site_id,
                installation_id,
            }
        }

        fn environment(&self) -> ArtifactEnvironment {
            ArtifactEnvironment {
                trust_config: self.trust_config.clone(),
                install_prefix: self.install_prefix.clone(),
            }
        }

        /// Signs the staged request exactly as the offline custodian would and
        /// places the detached response next to it.
        fn respond_to_signing_request(&self, request_path: &Path) -> io::Result<()> {
            let request_bytes = fs::read(request_path)?;
            let request: Value = serde_json::from_slice(&request_bytes)?;
            assert_eq!(request["format"], SIGNING_REQUEST_FORMAT);
            let signing_input = URL_SAFE_NO_PAD
                .decode(
                    request["signing_input_base64url"]
                        .as_str()
                        .expect("signing input"),
                )
                .map_err(io::Error::other)?;
            let signature = self.signing.sign(&signing_input);
            let response = json!({
                "format": SIGNING_RESPONSE_FORMAT,
                "request_sha256": hex::encode(Sha256::digest(&request_bytes)),
                "key_id": SIGNING_KEY_ID,
                "signature": hex::encode(signature.to_bytes()),
                "signed_at": now_utc_rfc3339(),
            });
            write_private(
                &request_path.with_file_name(SIGNING_RESPONSE_FILE),
                &serde_json::to_vec(&response)?,
            )
        }

        fn expected_release(&self, data_dir: &Path) -> ExpectedRelease {
            let runtime = tokio::runtime::Builder::new_current_thread()
                .enable_all()
                .build()
                .expect("runtime");
            let facts = snapshot_facts(&runtime, &data_dir.join(SNAPSHOT_FILE_NAME), &self.release)
                .expect("snapshot facts");
            ExpectedRelease {
                site_id: self.site_id.clone(),
                installation_id: self.installation_id.clone(),
                o3k_version: self.release.o3k_version.clone(),
                source_sha: self.release.source_sha.clone(),
                release_artifact_sha256: self.release.release_artifact_sha256.clone(),
                profile_id: self.release.profile_id.clone(),
                store_backend: "sqlite".to_owned(),
                schema_version: self.release.schema_version,
                migrations: facts.migrations,
                state_inventory: facts.state_inventory,
            }
        }
    }

    fn journal_io<T>(
        result: Result<T, o3k_store::backup_journal::BackupJournalError>,
    ) -> io::Result<T> {
        result.map_err(|error| io::Error::other(error.reason()))
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

    fn absent_environment(root: &TempRoot) -> ArtifactEnvironment {
        ArtifactEnvironment {
            trust_config: root.0.join("absent-backup-trust.json"),
            install_prefix: root.0.join("absent-install"),
        }
    }

    fn create_migrated_store(data_dir: &Path) -> io::Result<()> {
        let runtime = tokio::runtime::Builder::new_current_thread()
            .enable_all()
            .build()?;
        runtime
            .block_on(o3k_store::testkit::open_file(
                &data_dir.join(SNAPSHOT_FILE_NAME),
            ))
            .map_err(|error| io::Error::other(error.to_string()))?;
        Ok(())
    }

    /// Runs the real daemon side of the handoff against `data_dir`.
    fn spawn_handoff(data_dir: PathBuf) -> io::Result<thread::JoinHandle<io::Result<()>>> {
        let (installation, site) = identity_tokens(&data_dir)?;
        let expected = o3k_store::ExpectedExecutor {
            exe: fs::canonicalize(std::env::current_exe()?)?,
            uid: geteuid().as_raw(),
            installation,
            site,
        };
        let listener = o3k_store::BackupControlListener::bind(&data_dir)?;
        Ok(thread::spawn(move || -> io::Result<()> {
            let lock = StoreAccessLock::acquire(&data_dir)?;
            let mut accepted = listener
                .accept_authenticated(&expected, Duration::from_secs(10))
                .map_err(io::Error::other)?;
            accepted.send_accept()?;
            lock.handoff(&mut accepted.stream, Duration::from_secs(10))
                .map_err(|(_, error)| error)
        }))
    }

    #[test]
    fn relative_destination_is_rejected() {
        let root = TempRoot::new("relative").expect("temp root");
        let outcome = execute(
            &args_for(PathBuf::from("relative-dest")),
            &absent_environment(&root),
        );
        assert_eq!(outcome.exit_code, EXIT_REJECTED);
        assert_eq!(outcome_reason(&outcome), "destination-not-absolute");
    }

    #[test]
    fn missing_destination_is_rejected() -> io::Result<()> {
        let root = TempRoot::new("missing")?;
        let outcome = execute(&args_for(root.0.join("absent")), &absent_environment(&root));
        assert_eq!(outcome.exit_code, EXIT_REJECTED);
        assert_eq!(outcome_reason(&outcome), "destination-missing");
        Ok(())
    }

    #[test]
    fn regular_file_destination_is_rejected() -> io::Result<()> {
        let root = TempRoot::new("file-dest")?;
        let file = root.0.join("a-file");
        fs::write(&file, b"data")?;
        let outcome = execute(&args_for(file), &absent_environment(&root));
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
        let outcome = execute(&args_for(link), &absent_environment(&root));
        assert_eq!(outcome.exit_code, EXIT_REJECTED);
        assert_eq!(outcome_reason(&outcome), "destination-symlink");
        Ok(())
    }

    #[test]
    fn group_or_other_writable_destination_is_rejected() -> io::Result<()> {
        let root = TempRoot::new("writable-dest")?;
        let open = root.private_dir("open")?;
        fs::set_permissions(&open, fs::Permissions::from_mode(0o777))?;
        let outcome = execute(&args_for(open), &absent_environment(&root));
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

    fn destination_fd(destination: &Path) -> io::Result<OwnedFd> {
        open_destination_dir(destination).map_err(io::Error::other)
    }

    #[test]
    fn missing_controller_socket_is_rejected() -> io::Result<()> {
        let root = TempRoot::new("no-controller")?;
        let data_dir = root.private_dir("data")?;
        let dest = root.private_dir("dest")?;
        let fd = destination_fd(&dest)?;
        let outcome = execute_inner(
            &args_for(dest.clone()),
            dest,
            fd,
            data_dir,
            now_utc_rfc3339(),
            &absent_environment(&root),
        );
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
            dest.clone(),
            destination_fd(&dest)?,
            data_dir.clone(),
            now_utc_rfc3339(),
            &absent_environment(&root),
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
        let fd = destination_fd(&dest)?;
        let outcome = execute_inner(
            &args_for(dest.clone()),
            dest,
            fd,
            data_dir,
            now_utc_rfc3339(),
            &absent_environment(&root),
        );
        server
            .join()
            .map_err(|_| io::Error::other("fake controller thread panicked"))??;
        assert_eq!(outcome.exit_code, EXIT_RECOVERABLE);
        assert_eq!(outcome_reason(&outcome), "handoff-receive-failed");
        Ok(())
    }

    #[test]
    fn invalid_configuration_fails_before_capture() -> io::Result<()> {
        let root = TempRoot::new("no-config")?;
        let data_dir = root.private_dir("data")?;
        let dest = root.private_dir("dest")?;
        create_migrated_store(&data_dir)?;
        let server = spawn_handoff(data_dir.clone())?;
        let outcome = execute_inner(
            &args_for(dest.clone()),
            dest.clone(),
            destination_fd(&dest)?,
            data_dir.clone(),
            now_utc_rfc3339(),
            &absent_environment(&root),
        );
        server
            .join()
            .map_err(|_| io::Error::other("handoff thread panicked"))??;
        assert_eq!(outcome.exit_code, EXIT_REJECTED);
        assert_eq!(outcome_reason(&outcome), "trust-config-unavailable");
        assert!(
            !data_dir
                .join(format!(
                    "{MARKER_FILE_PREFIX}{}",
                    outcome.json["operation_id"]
                ))
                .exists()
        );
        assert_eq!(fs::read_dir(&dest)?.count(), 0);
        Ok(())
    }

    #[test]
    fn published_operation_is_refused_before_controller_contact() -> io::Result<()> {
        let root = TempRoot::new("published")?;
        let data_dir = root.private_dir("data")?;
        let dest = root.private_dir("dest")?;
        let operation_id = Uuid::new_v4();
        let record = BackupOperationRecord {
            format: o3k_store::backup_journal::BACKUP_OPERATION_FORMAT.to_owned(),
            operation_id,
            phase: BackupOperationPhase::Published,
            backup_id: operation_id.to_string(),
            destination: fs::canonicalize(&dest)?.to_string_lossy().into_owned(),
            staging_path: fs::canonicalize(&dest)?
                .join(format!("{OPERATION_STAGING_PREFIX}{operation_id}"))
                .to_string_lossy()
                .into_owned(),
            request_sha256: Some("a".repeat(64)),
            artifact_sha256: Some("b".repeat(64)),
            site_id: "site-1".to_owned(),
            installation_id: "install-1".to_owned(),
            created_at: "2026-10-23T12:00:00Z".to_owned(),
            updated_at: "2026-10-23T12:01:00Z".to_owned(),
        };
        journal_io(backup_journal::write_backup_operation(&data_dir, &record))?;
        let outcome = execute_with_data_dir(
            &BackupCreateArgs {
                destination: dest,
                operation_id,
            },
            &absent_environment(&root),
            Some(&data_dir),
        );
        assert_eq!(outcome.exit_code, EXIT_REJECTED);
        assert_eq!(outcome_reason(&outcome), "operation-already-published");
        Ok(())
    }

    #[test]
    fn incomplete_operation_is_recoverable_without_a_controller() -> io::Result<()> {
        let root = TempRoot::new("incomplete")?;
        let data_dir = root.private_dir("data")?;
        let dest = root.private_dir("dest")?;
        let operation_id = Uuid::new_v4();
        let record = BackupOperationRecord {
            format: o3k_store::backup_journal::BACKUP_OPERATION_FORMAT.to_owned(),
            operation_id,
            phase: BackupOperationPhase::Captured,
            backup_id: operation_id.to_string(),
            destination: fs::canonicalize(&dest)?.to_string_lossy().into_owned(),
            staging_path: fs::canonicalize(&dest)?
                .join(format!("{OPERATION_STAGING_PREFIX}{operation_id}"))
                .to_string_lossy()
                .into_owned(),
            request_sha256: None,
            artifact_sha256: None,
            site_id: "site-1".to_owned(),
            installation_id: "install-1".to_owned(),
            created_at: "2026-10-23T12:00:00Z".to_owned(),
            updated_at: "2026-10-23T12:01:00Z".to_owned(),
        };
        journal_io(backup_journal::write_backup_operation(&data_dir, &record))?;
        let outcome = execute_with_data_dir(
            &BackupCreateArgs {
                destination: dest,
                operation_id,
            },
            &absent_environment(&root),
            Some(&data_dir),
        );
        assert_eq!(outcome.exit_code, EXIT_RECOVERABLE);
        assert_eq!(outcome_reason(&outcome), "backup-operation-incomplete");
        Ok(())
    }

    /// The full accepted flow: capture and stage (exit 3), sign offline, re-run
    /// the same request (exit 0), verify the published artifact against the
    /// installed release, and refuse a second capture for the same id.
    #[test]
    fn two_phase_flow_publishes_a_verified_artifact() -> io::Result<()> {
        let root = TempRoot::new("two-phase")?;
        let data_dir = root.private_dir("data")?;
        let dest = root.private_dir("dest")?;
        let operation_id = Uuid::new_v4();
        create_migrated_store(&data_dir)?;
        let fixture = ArtifactFixture::new(&root, &data_dir, latest_sqlite_schema_version());
        let environment = fixture.environment();

        // Phase 1: authenticated handoff, capture, staging, signing request.
        let server = spawn_handoff(data_dir.clone())?;
        let phase_one = execute_inner(
            &BackupCreateArgs {
                destination: dest.clone(),
                operation_id,
            },
            dest.clone(),
            destination_fd(&dest)?,
            data_dir.clone(),
            now_utc_rfc3339(),
            &environment,
        );
        server
            .join()
            .map_err(|_| io::Error::other("handoff thread panicked"))??;
        assert_eq!(
            phase_one.exit_code, EXIT_RECOVERABLE,
            "unexpected phase-1 outcome: {}",
            phase_one.json
        );
        assert_eq!(
            phase_one.json["status"], "signing-required",
            "{}",
            phase_one.json
        );
        assert_eq!(phase_one.json["operation_id"], operation_id.to_string());
        assert_eq!(phase_one.json["backup_id"], operation_id.to_string());
        let request_path = PathBuf::from(
            phase_one.json["signing_request"]
                .as_str()
                .expect("signing request path"),
        );
        assert!(request_path.is_file());
        assert_eq!(
            request_path.file_name().and_then(|n| n.to_str()),
            Some("signing-request.json")
        );
        assert!(phase_one.json["expires_at"].as_str().is_some());
        // Capture is complete: the marker is gone, the operation is journaled
        // as staged, and nothing is published.
        assert!(
            !data_dir
                .join(format!("{MARKER_FILE_PREFIX}{operation_id}"))
                .exists()
        );
        let journal = journal_io(backup_journal::read_backup_operation(
            &data_dir,
            operation_id,
        ))?
        .expect("journal record");
        assert_eq!(journal.phase, BackupOperationPhase::Staged);
        assert!(journal.request_sha256.is_some());
        let staging_path = PathBuf::from(&journal.staging_path);
        assert!(staging_path.is_dir());
        assert!(staging_path.join(SNAPSHOT_FILE_NAME).is_file());
        assert!(!dest.join(format!("backup-{operation_id}.o3k")).exists());

        // Phase 2 without a response stays idempotent.
        let pending = execute_with_data_dir(
            &BackupCreateArgs {
                destination: dest.clone(),
                operation_id,
            },
            &environment,
            Some(&data_dir),
        );
        assert_eq!(pending.exit_code, EXIT_RECOVERABLE, "{}", pending.json);
        assert_eq!(
            pending.json["status"], "signing-required",
            "{}",
            pending.json
        );

        // A wrong signature is rejected and nothing is published.
        let request_bytes = fs::read(&request_path)?;
        let request: Value = serde_json::from_slice(&request_bytes)?;
        let signing_input = URL_SAFE_NO_PAD
            .decode(
                request["signing_input_base64url"]
                    .as_str()
                    .expect("signing input"),
            )
            .map_err(io::Error::other)?;
        let foreign = SigningKey::from_bytes(&[18_u8; 32]);
        write_private(
            &request_path.with_file_name(SIGNING_RESPONSE_FILE),
            &serde_json::to_vec(&json!({
                "format": SIGNING_RESPONSE_FORMAT,
                "request_sha256": hex::encode(Sha256::digest(&request_bytes)),
                "key_id": SIGNING_KEY_ID,
                "signature": hex::encode(foreign.sign(&signing_input).to_bytes()),
                "signed_at": now_utc_rfc3339(),
            }))?,
        )?;
        let rejected = execute_with_data_dir(
            &BackupCreateArgs {
                destination: dest.clone(),
                operation_id,
            },
            &environment,
            Some(&data_dir),
        );
        assert_eq!(rejected.exit_code, EXIT_REJECTED);
        assert_eq!(outcome_reason(&rejected), "signature-invalid");
        assert!(!dest.join(format!("backup-{operation_id}.o3k")).exists());
        assert!(staging_path.is_dir());

        // Offline custodian signs the exact D1 input; the same request
        // completes and publishes.
        fixture.respond_to_signing_request(&request_path)?;
        let published = execute_with_data_dir(
            &BackupCreateArgs {
                destination: dest.clone(),
                operation_id,
            },
            &environment,
            Some(&data_dir),
        );
        assert_eq!(
            published.exit_code, 0,
            "unexpected phase-2 outcome: {}",
            published.json
        );
        assert_eq!(published.json["status"], "backup-published");
        let artifact_path = dest.join(format!("backup-{operation_id}.o3k"));
        assert_eq!(
            PathBuf::from(published.json["path"].as_str().expect("path")),
            artifact_path
        );
        assert_eq!(published.json["sha256"].as_str().map(str::len), Some(64));
        assert_eq!(
            published.json["sha256"].as_str(),
            Some(sha256_hex_file(&artifact_path)?.as_str())
        );
        assert!(
            !staging_path.exists(),
            "publication removes private staging"
        );
        assert_eq!(
            journal_io(backup_journal::read_backup_operation(
                &data_dir,
                operation_id
            ))?
            .map(|record| record.phase),
            Some(BackupOperationPhase::Published)
        );

        // Real verification against the installed release identity.
        let trust = BackupTrustConfig::load(&fixture.trust_config).expect("trust document");
        let recipient = trust.load_recipient_private_key().expect("recipient key");
        let verifying_key = fixture.signing.verifying_key();
        let keys = ArtifactVerificationKeys {
            signing_key_id: SIGNING_KEY_ID,
            signer: &verifying_key,
            trust: &trust,
            recipient_key_id: RECIPIENT_KEY_ID,
            recipient: &recipient,
        };
        let expected = fixture.expected_release(&data_dir);
        let verify_root = root.private_dir("verify")?;
        let mut artifact = fs::File::open(&artifact_path)?;
        let verified =
            crate::backup::verify_artifact_stream(&mut artifact, &expected, &keys, &verify_root)
                .expect("published artifact verifies");
        assert_eq!(verified.manifest.backup_id, operation_id.to_string());
        let names = verified
            .members
            .iter()
            .map(|member| member.record.name.as_str())
            .collect::<Vec<_>>();
        assert_eq!(
            names,
            [
                "database/o3k.sqlite",
                "metadata/capture.json",
                "release/release-manifest.json",
                "trust/backup-trust.json",
            ]
        );
        let capture: Value = serde_json::from_slice(&fs::read(&verified.members[1].path)?)?;
        assert_eq!(capture["operation_id"], operation_id.to_string());
        assert_eq!(capture["provisional"], false);
        assert!(capture["reservation"]["reserved_bytes"].as_u64().is_some());
        fs::remove_dir_all(&verified.staging_directory)?;

        // A new capture under a published operation id is refused before the
        // controller is contacted.
        let duplicate = execute_with_data_dir(
            &BackupCreateArgs {
                destination: dest.clone(),
                operation_id,
            },
            &environment,
            Some(&data_dir),
        );
        assert_eq!(duplicate.exit_code, EXIT_REJECTED);
        assert_eq!(outcome_reason(&duplicate), "operation-already-published");
        Ok(())
    }

    #[test]
    fn destination_overlapping_data_dir_is_rejected() -> io::Result<()> {
        let root = TempRoot::new("overlap")?;
        let data_dir = fs::canonicalize(root.private_dir("data")?)?;
        // Exactly the data directory.
        assert!(destination_overlaps_data_dir(&data_dir, &data_dir));
        // A descendant of the data directory.
        let nested = data_dir.join("captures");
        fs::create_dir(&nested)?;
        fs::set_permissions(&nested, fs::Permissions::from_mode(0o700))?;
        assert!(destination_overlaps_data_dir(&nested, &data_dir));
        // A sibling that merely shares the path prefix is allowed.
        let sibling = root.private_dir("data-sibling")?;
        assert!(!destination_overlaps_data_dir(&sibling, &data_dir));
        let outside = root.private_dir("elsewhere")?;
        assert!(!destination_overlaps_data_dir(&outside, &data_dir));
        Ok(())
    }

    #[test]
    fn destination_revalidation_detects_swap_mode_change_and_symlink() -> io::Result<()> {
        // The directory entry is replaced by another directory: the path now
        // resolves to a different inode than the held descriptor.
        let root = TempRoot::new("revalidate")?;
        let original = root.private_dir("original")?;
        let replacement = root.private_dir("replacement")?;
        let fd = destination_fd(&original)?;
        revalidate_destination(&fd, &original).map_err(io::Error::other)?;
        fs::remove_dir(&original)?;
        fs::rename(&replacement, &original)?;
        match revalidate_destination(&fd, &original) {
            Err("destination-changed-after-validation") => {}
            other => {
                return Err(io::Error::other(format!(
                    "swapped destination was not detected: {other:?}"
                )));
            }
        }

        // The directory becomes group/other-writable after validation.
        let open = root.private_dir("opened")?;
        let open_fd = destination_fd(&open)?;
        fs::set_permissions(&open, fs::Permissions::from_mode(0o777))?;
        match revalidate_destination(&open_fd, &open) {
            Err("destination-changed-after-validation") => {}
            other => {
                return Err(io::Error::other(format!(
                    "group/other-writable destination was not detected: {other:?}"
                )));
            }
        }

        // The directory entry is replaced by a symlink: the fresh no-follow
        // lstat catches the swap regardless of the link target.
        let linked = root.private_dir("linked")?;
        let linked_fd = destination_fd(&linked)?;
        fs::remove_dir(&linked)?;
        symlink(root.0.join("linked-target"), &linked)?;
        assert!(fs::symlink_metadata(&linked)?.file_type().is_symlink());
        match revalidate_destination(&linked_fd, &linked) {
            Err("destination-changed-after-validation") => {}
            other => {
                return Err(io::Error::other(format!(
                    "symlink-swapped destination was not detected: {other:?}"
                )));
            }
        }
        Ok(())
    }
}
