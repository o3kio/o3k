//! Durable backup-operation journal for the authenticated PP.6 backup flow.
//!
//! SPEC-0050 §8 (ADR-0189 D2/D8) makes the backup executor a separate process
//! from the controller. The denial-only interrupted-backup marker covers the
//! window in which canonical state may be mid-capture; it deliberately carries
//! no lifecycle and it is removed as soon as capture is complete. The journal
//! in this module is the non-denial record of what happened to one operation,
//! so that a replacement controller can distinguish:
//!
//! * `capturing` — the executor owns the lock and may be mid-capture (the
//!   marker denies startup on its own; this phase is belt-and-braces),
//! * `captured` — the snapshot is durably staged but the artifact is not
//!   complete,
//! * `staged` — the encrypted artifact is staged and an offline signing
//!   request exists; publication is pending and is **not** canonical state,
//! * `publishing` — a signature was accepted and publication was attempted,
//! * `published` — the artifact is durably published; a further capture under
//!   the same operation id must be refused,
//! * `aborted` — the attempt failed; the marker (if it exists) is the
//!   authority for whether startup is denied.
//!
//! Only `published` and `aborted` are terminal. A non-terminal
//! `captured`/`staged`/`publishing` record must never deny controller startup
//! on its own: the staged artifact is not canonical state. Under ADR-0190
//! Option A the *marker* is what denies startup for the whole capture →
//! offline signing → verified publication window; the journal only records
//! which phase the operation reached.
//!
//! # Forward-only transitions
//!
//! [`advance_backup_operation`] compares the on-disk phase with the target and
//! refuses to move backwards or sideways (`captured` → `capturing`,
//! `publishing` → `staged`, anything after a terminal phase). A replayed
//! transition that is already durable is idempotent. The executor holds the
//! store-access lock (and the phase-2 operation lock) for the whole
//! read-compare-write window, so a concurrent writer cannot interleave.
//!
//! Records are private files (`0600`) inside a private directory (`0700`) in
//! the data directory. They carry operation identity, lifecycle, paths and
//! digests only — never credentials, key material or provider payloads. The
//! lifecycle is written atomically (private temporary file, `fsync`, rename,
//! directory `fsync`) so a crash leaves either the previous or the next phase.
//!
//! # Read posture
//!
//! `operation_id`, `backup_id`, `site_id` and `installation_id` use the
//! contract identifier grammar `^[A-Za-z0-9][A-Za-z0-9._:-]*$`; `/`, `..`,
//! empty and other punctuation are rejected so a journal value can never become
//! a path component. Destination and staging paths are validated separately
//! (absolute, bounded) and the executor re-derives the publication name from
//! the operation UUID.
//!
//! Every read validates the journal directory (real directory, root-or-
//! effective-uid owner, no group/other access), opens the record with
//! `O_NOFOLLOW`, validates the descriptor's own `fstat` (regular file, `0600`,
//! trusted owner) and parses at most 256 KiB. A symlink swap between inspection
//! and open therefore cannot redirect the read.

use std::{
    ffi::OsStr,
    fmt, fs,
    io::{self, Read, Write},
    os::fd::AsRawFd,
    path::{Path, PathBuf},
};

use chrono::DateTime;
use rustix::{
    fd::OwnedFd,
    fs::{FileType, Mode, OFlags, fstat, open, openat},
    process::geteuid,
};
use serde::{Deserialize, Serialize};
use uuid::Uuid;

/// Directory inside the data directory that holds the operation journal.
pub const BACKUP_OPERATION_DIR: &str = "backup-operations";

/// Versioned record format marker.
pub const BACKUP_OPERATION_FORMAT: &str = "o3k-backup-operation-v1";

const MAX_OPERATION_RECORD_BYTES: u64 = 256 * 1024;
const MAX_PENDING_ENTRIES: usize = 1024;
const MAX_IDENTIFIER_BYTES: usize = 128;
const MAX_PATH_BYTES: usize = 4096;

/// Lifecycle phase of one backup operation.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum BackupOperationPhase {
    /// The executor holds the lock and may be capturing.
    Capturing,
    /// The snapshot is durably staged; the artifact is not complete.
    Captured,
    /// The encrypted artifact and the offline signing request are staged.
    Staged,
    /// A detached signature was accepted and publication was attempted.
    Publishing,
    /// The artifact is durably published.
    Published,
    /// The attempt failed.
    Aborted,
}

impl BackupOperationPhase {
    /// Stable wire/record spelling.
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Capturing => "capturing",
            Self::Captured => "captured",
            Self::Staged => "staged",
            Self::Publishing => "publishing",
            Self::Published => "published",
            Self::Aborted => "aborted",
        }
    }

    /// A terminal phase never needs operator follow-up for publication.
    #[must_use]
    pub const fn is_terminal(self) -> bool {
        matches!(self, Self::Published | Self::Aborted)
    }

    /// The staged artifact still awaits signature or publication.
    #[must_use]
    pub const fn is_pending_publication(self) -> bool {
        matches!(self, Self::Staged | Self::Publishing)
    }

    /// True when `next` is a legal forward transition from this phase.
    ///
    /// Legal moves are `capturing → captured → staged → publishing →
    /// published`, plus `aborted` from any non-terminal phase. A terminal
    /// phase never advances, and a phase never repeats another earlier phase
    /// (`publishing` can never fall back to `staged`).
    #[must_use]
    pub const fn may_advance_to(self, next: Self) -> bool {
        match (self, next) {
            (Self::Capturing, Self::Captured)
            | (Self::Captured, Self::Staged)
            | (Self::Staged, Self::Publishing)
            | (Self::Publishing, Self::Published) => true,
            (Self::Published | Self::Aborted, _) => false,
            (_, Self::Aborted) => true,
            _ => false,
        }
    }
}

impl fmt::Display for BackupOperationPhase {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str(self.as_str())
    }
}

/// One durable operation record.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct BackupOperationRecord {
    pub format: String,
    pub operation_id: Uuid,
    pub phase: BackupOperationPhase,
    /// Artifact backup identity (`backup-<operation id>` in the accepted flow).
    pub backup_id: String,
    /// Absolute destination directory recorded for the operation.
    pub destination: String,
    /// Absolute private staging directory inside the destination.
    pub staging_path: String,
    /// SHA-256 of the persisted offline signing request once staged.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub request_sha256: Option<String>,
    /// SHA-256 of the signed artifact once publication starts.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub artifact_sha256: Option<String>,
    /// D9 staging reservation accepted by the capture preflight. It is
    /// re-checked against the destination before finalize and publication, so
    /// a resumed phase 2 never has to guess the reservation.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub reserved_bytes: Option<u64>,
    pub site_id: String,
    pub installation_id: String,
    /// First time the operation was journalled.
    pub created_at: String,
    /// Last lifecycle update.
    pub updated_at: String,
}

impl BackupOperationRecord {
    /// Validates every field that a reader relies on. Paths are opaque here:
    /// the executor validates them against the destination it opened.
    pub fn validate(&self) -> Result<(), BackupJournalError> {
        if self.format != BACKUP_OPERATION_FORMAT
            || !is_identifier(&self.backup_id)
            || !is_identifier(&self.site_id)
            || !is_identifier(&self.installation_id)
        {
            return Err(BackupJournalError::InvalidRecord);
        }
        for path in [&self.destination, &self.staging_path] {
            if !path.starts_with('/') || path.len() > MAX_PATH_BYTES {
                return Err(BackupJournalError::InvalidRecord);
            }
        }
        for digest in [&self.request_sha256, &self.artifact_sha256]
            .into_iter()
            .flatten()
        {
            if !is_sha256(digest) {
                return Err(BackupJournalError::InvalidRecord);
            }
        }
        if DateTime::parse_from_rfc3339(&self.created_at).is_err()
            || DateTime::parse_from_rfc3339(&self.updated_at).is_err()
        {
            return Err(BackupJournalError::InvalidRecord);
        }
        Ok(())
    }
}

/// Typed journal failure. [`Self::reason`] is the stable, path-free string a
/// command boundary may emit.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[non_exhaustive]
pub enum BackupJournalError {
    /// The journal directory or file cannot be read.
    Unavailable,
    /// The directory or file is a symlink or not the expected entry type.
    UnsafeEntry,
    /// The record is not valid JSON for this schema or fails validation.
    InvalidRecord,
    /// The requested transition would move the operation backwards.
    InvalidTransition,
    /// The record could not be written durably.
    WriteFailed,
}

impl BackupJournalError {
    /// Stable reason string.
    #[must_use]
    pub const fn reason(self) -> &'static str {
        match self {
            Self::Unavailable => "backup-operation-journal-unavailable",
            Self::UnsafeEntry => "backup-operation-journal-unsafe-entry",
            Self::InvalidRecord => "backup-operation-journal-invalid",
            Self::InvalidTransition => "backup-operation-phase-regression",
            Self::WriteFailed => "backup-operation-journal-write-failed",
        }
    }
}

impl fmt::Display for BackupJournalError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str(self.reason())
    }
}

impl std::error::Error for BackupJournalError {}

/// Journal path for one operation.
#[must_use]
pub fn operation_path(data_dir: &Path, operation_id: Uuid) -> PathBuf {
    data_dir
        .join(BACKUP_OPERATION_DIR)
        .join(format!("{operation_id}.json"))
}

/// Reads one operation record.
///
/// A missing file is `Ok(None)`. A present but unparsable or invalid record
/// fails closed, because a command must never treat a corrupt journal as an
/// absent one: that would silently allow a second capture under a published
/// operation id.
pub fn read_backup_operation(
    data_dir: &Path,
    operation_id: Uuid,
) -> Result<Option<BackupOperationRecord>, BackupJournalError> {
    // The directory posture is part of the trust boundary: a reader must never
    // follow a symlinked or group/other-accessible journal directory. The
    // descriptor is validated and the record is opened relative to it, so a
    // directory swap after validation cannot redirect the read.
    let Some(directory) = open_operation_directory(data_dir)? else {
        return Ok(None);
    };
    let name = format!("{operation_id}.json");
    let Some(record) = read_record_at(&directory, OsStr::new(&name))? else {
        return Ok(None);
    };
    if record.operation_id != operation_id {
        return Err(BackupJournalError::InvalidRecord);
    }
    Ok(Some(record))
}

/// Writes one operation record atomically.
///
/// The directory is created private on first use and re-validated on every
/// write. On any failure the previous record (if any) is left untouched.
pub fn write_backup_operation(
    data_dir: &Path,
    record: &BackupOperationRecord,
) -> Result<(), BackupJournalError> {
    record.validate()?;
    let directory = ensure_operation_directory(data_dir)?;
    let path = directory.join(format!("{}.json", record.operation_id));
    let temporary = directory.join(format!(
        ".{}.json.tmp-{}",
        record.operation_id,
        Uuid::now_v7()
    ));
    let bytes = serde_json::to_vec(record).map_err(|_| BackupJournalError::WriteFailed)?;
    if bytes.len() as u64 > MAX_OPERATION_RECORD_BYTES {
        return Err(BackupJournalError::WriteFailed);
    }
    let result = (|| {
        let descriptor = open(
            &temporary,
            OFlags::RDWR | OFlags::CREATE | OFlags::EXCL | OFlags::CLOEXEC | OFlags::NOFOLLOW,
            Mode::from_raw_mode(0o600),
        )
        .map_err(|_| BackupJournalError::WriteFailed)?;
        let mut file = fs::File::from(descriptor);
        file.write_all(&bytes)
            .map_err(|_| BackupJournalError::WriteFailed)?;
        file.sync_all()
            .map_err(|_| BackupJournalError::WriteFailed)?;
        drop(file);
        fs::rename(&temporary, &path).map_err(|_| BackupJournalError::WriteFailed)?;
        sync_directory(&directory).map_err(|_| BackupJournalError::WriteFailed)
    })();
    if result.is_err() {
        let _ = fs::remove_file(&temporary);
    }
    result
}

/// Advances one operation record, refusing to regress its phase.
///
/// The on-disk record is read first and the transition is validated with
/// [`BackupOperationPhase::may_advance_to`]. Writing the phase that is already
/// durable is idempotent (a replayed step succeeds without a write). A missing
/// record or an illegal transition fails with
/// [`BackupJournalError::InvalidTransition`] instead of overwriting the
/// recorded history; a crash can therefore never make the journal describe a
/// phase the operation never reached.
///
/// Field-only updates are persisted by the next forward transition: phase 1
/// records the accepted D9 reservation while still in `capturing` and it
/// becomes durable with the `captured` write, which always precedes any
/// `staged` record a later invocation can observe.
///
/// The read-compare-write window is serialized by the caller's store-access
/// lock (and, for phase 2, the operation lock in the staging directory). This
/// function is the compare-and-set on the on-disk phase; it does not create a
/// record.
pub fn advance_backup_operation(
    data_dir: &Path,
    record: &BackupOperationRecord,
) -> Result<(), BackupJournalError> {
    let Some(current) = read_backup_operation(data_dir, record.operation_id)? else {
        return Err(BackupJournalError::InvalidTransition);
    };
    if current.phase == record.phase {
        return Ok(());
    }
    if !current.phase.may_advance_to(record.phase) {
        return Err(BackupJournalError::InvalidTransition);
    }
    write_backup_operation(data_dir, record)
}

/// Non-terminal journal records found in a data directory.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct PendingBackupOperations {
    /// `capturing`/`captured`/`staged`/`publishing` records, sorted by id.
    pub pending: Vec<BackupOperationRecord>,
    /// Entry names that could not be read as a record. Names only: contents
    /// are never logged, and an unreadable entry never denies startup.
    pub unreadable: Vec<String>,
}

/// Scans the journal for non-terminal operations.
///
/// This is a diagnostic scan for the controller: an interrupted journal entry
/// is operator follow-up, not a denial condition. A missing journal directory
/// is an empty result.
pub fn pending_backup_operations(
    data_dir: &Path,
) -> Result<PendingBackupOperations, BackupJournalError> {
    let Some(directory) = open_operation_directory(data_dir)? else {
        return Ok(PendingBackupOperations::default());
    };
    let mut pending = Vec::new();
    let mut unreadable = Vec::new();
    // `/proc/self/fd/<n>` resolves against the descriptor this process holds,
    // so the scan cannot be redirected to a replaced directory.
    let directory_path = format!("/proc/self/fd/{}", directory.as_raw_fd());
    let entries = fs::read_dir(&directory_path).map_err(|_| BackupJournalError::Unavailable)?;
    for entry in entries.take(MAX_PENDING_ENTRIES) {
        let Ok(entry) = entry else {
            unreadable.push("<unreadable-entry>".to_owned());
            continue;
        };
        let file_name = entry.file_name();
        let Some(name) = file_name.to_str() else {
            unreadable.push(file_name.to_string_lossy().into_owned());
            continue;
        };
        let Some(stem) = name.strip_suffix(".json") else {
            continue;
        };
        if name.starts_with('.') {
            continue;
        }
        let Ok(operation_id) = Uuid::parse_str(stem) else {
            unreadable.push(name.to_owned());
            continue;
        };
        match read_record_at(&directory, file_name.as_os_str()) {
            Ok(Some(record))
                if record.operation_id == operation_id && !record.phase.is_terminal() =>
            {
                pending.push(record);
            }
            Ok(_) => {}
            Err(_) => unreadable.push(name.to_owned()),
        }
    }
    pending.sort_by_key(|record| record.operation_id);
    Ok(PendingBackupOperations {
        pending,
        unreadable,
    })
}

/// Opens and validates the journal directory as a descriptor.
///
/// `Ok(None)` means the directory does not exist. A symlink, non-directory or
/// untrusted owner/mode fails closed.
fn open_operation_directory(data_dir: &Path) -> Result<Option<OwnedFd>, BackupJournalError> {
    let directory = data_dir.join(BACKUP_OPERATION_DIR);
    let descriptor = match open(
        &directory,
        OFlags::RDONLY | OFlags::DIRECTORY | OFlags::CLOEXEC | OFlags::NOFOLLOW,
        Mode::empty(),
    ) {
        Ok(descriptor) => descriptor,
        Err(rustix::io::Errno::NOENT) => return Ok(None),
        Err(rustix::io::Errno::LOOP | rustix::io::Errno::NOTDIR) => {
            return Err(BackupJournalError::UnsafeEntry);
        }
        Err(_) => return Err(BackupJournalError::Unavailable),
    };
    let metadata = fstat(&descriptor).map_err(|_| BackupJournalError::Unavailable)?;
    validate_directory_stat(&metadata)?;
    Ok(Some(descriptor))
}

/// Reads one record relative to a validated journal directory descriptor,
/// never following a symlink and validating the record descriptor's own
/// metadata (`0600`, root-or-effective-uid owner, regular file) and size
/// bound. `Ok(None)` means the entry does not exist.
fn read_record_at(
    directory: &OwnedFd,
    name: &OsStr,
) -> Result<Option<BackupOperationRecord>, BackupJournalError> {
    let descriptor = match openat(
        directory,
        name,
        OFlags::RDONLY | OFlags::CLOEXEC | OFlags::NOFOLLOW | OFlags::NONBLOCK,
        Mode::empty(),
    ) {
        Ok(descriptor) => descriptor,
        Err(rustix::io::Errno::NOENT) => return Ok(None),
        Err(rustix::io::Errno::LOOP) => return Err(BackupJournalError::UnsafeEntry),
        Err(_) => return Err(BackupJournalError::Unavailable),
    };
    let metadata = fstat(&descriptor).map_err(|_| BackupJournalError::Unavailable)?;
    if FileType::from_raw_mode(metadata.st_mode) != FileType::RegularFile {
        return Err(BackupJournalError::UnsafeEntry);
    }
    if !trusted_owner(metadata.st_uid) {
        return Err(BackupJournalError::UnsafeEntry);
    }
    if metadata.st_mode & 0o077 != 0 {
        return Err(BackupJournalError::UnsafeEntry);
    }
    if u64::try_from(metadata.st_size).unwrap_or(u64::MAX) > MAX_OPERATION_RECORD_BYTES {
        return Err(BackupJournalError::InvalidRecord);
    }
    let mut bytes = Vec::new();
    fs::File::from(descriptor)
        .take(MAX_OPERATION_RECORD_BYTES + 1)
        .read_to_end(&mut bytes)
        .map_err(|_| BackupJournalError::Unavailable)?;
    if bytes.len() as u64 > MAX_OPERATION_RECORD_BYTES {
        return Err(BackupJournalError::InvalidRecord);
    }
    let record: BackupOperationRecord =
        serde_json::from_slice(&bytes).map_err(|_| BackupJournalError::InvalidRecord)?;
    record.validate()?;
    Ok(Some(record))
}

fn ensure_operation_directory(data_dir: &Path) -> Result<PathBuf, BackupJournalError> {
    let directory = data_dir.join(BACKUP_OPERATION_DIR);
    match fs::symlink_metadata(&directory) {
        Ok(metadata) => validate_directory(&metadata)?,
        Err(error) if error.kind() == io::ErrorKind::NotFound => {
            let mut builder = fs::DirBuilder::new();
            #[cfg(unix)]
            {
                use std::os::unix::fs::DirBuilderExt;
                builder.mode(0o700);
            }
            match builder.create(&directory) {
                Ok(()) => {}
                Err(error) if error.kind() == io::ErrorKind::AlreadyExists => {
                    let metadata = fs::symlink_metadata(&directory)
                        .map_err(|_| BackupJournalError::Unavailable)?;
                    validate_directory(&metadata)?;
                }
                Err(_) => return Err(BackupJournalError::WriteFailed),
            }
        }
        Err(_) => return Err(BackupJournalError::Unavailable),
    }
    Ok(directory)
}

fn validate_directory(metadata: &fs::Metadata) -> Result<(), BackupJournalError> {
    if metadata.file_type().is_symlink() || !metadata.is_dir() {
        return Err(BackupJournalError::UnsafeEntry);
    }
    #[cfg(unix)]
    {
        use std::os::unix::fs::{MetadataExt, PermissionsExt};
        if !trusted_owner(metadata.uid()) {
            return Err(BackupJournalError::UnsafeEntry);
        }
        // The journal directory is private (0700): group or other access of
        // any kind is outside the contract.
        if metadata.permissions().mode() & 0o077 != 0 {
            return Err(BackupJournalError::UnsafeEntry);
        }
    }
    Ok(())
}

/// Descriptor-based counterpart of [`validate_directory`], used after `open`
/// so the checks apply to the inode actually traversed.
fn validate_directory_stat(metadata: &rustix::fs::Stat) -> Result<(), BackupJournalError> {
    if FileType::from_raw_mode(metadata.st_mode) != FileType::Directory {
        return Err(BackupJournalError::UnsafeEntry);
    }
    if !trusted_owner(metadata.st_uid) {
        return Err(BackupJournalError::UnsafeEntry);
    }
    if metadata.st_mode & 0o077 != 0 {
        return Err(BackupJournalError::UnsafeEntry);
    }
    Ok(())
}

/// Root, or the effective uid, owns the journal.
fn trusted_owner(uid: u32) -> bool {
    uid == 0 || uid == geteuid().as_raw()
}

fn sync_directory(directory: &Path) -> io::Result<()> {
    let descriptor = open(
        directory,
        OFlags::RDONLY | OFlags::DIRECTORY | OFlags::CLOEXEC | OFlags::NOFOLLOW,
        Mode::empty(),
    )?;
    fs::File::from(descriptor).sync_all()
}

/// Contract identifier grammar `^[A-Za-z0-9][A-Za-z0-9._:-]*$`.
///
/// Journal strings are used to derive paths and identities, so `/`, `..`,
/// whitespace, empty values and any other punctuation are rejected. This is
/// deliberately stricter than the pre-review "ascii graphic" check that
/// allowed `x/../../escaped`.
fn is_identifier(value: &str) -> bool {
    if value.is_empty() || value.len() > MAX_IDENTIFIER_BYTES {
        return false;
    }
    let mut bytes = value.bytes();
    let Some(first) = bytes.next() else {
        return false;
    };
    first.is_ascii_alphanumeric()
        && bytes
            .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'.' | b'_' | b':' | b'-'))
}

fn is_sha256(value: &str) -> bool {
    value.len() == 64
        && value
            .bytes()
            .all(|byte| byte.is_ascii_hexdigit() && !byte.is_ascii_uppercase())
}

#[cfg(test)]
#[allow(clippy::expect_used, clippy::unwrap_used)]
mod tests {
    use super::*;

    struct Fixture(PathBuf);

    impl Fixture {
        fn new(tag: &str) -> Self {
            let path =
                std::env::temp_dir().join(format!("o3k-backup-journal-{tag}-{}", Uuid::now_v7()));
            let mut builder = fs::DirBuilder::new();
            #[cfg(unix)]
            {
                use std::os::unix::fs::DirBuilderExt;
                builder.mode(0o700);
            }
            builder.create(&path).expect("create fixture directory");
            Self(path)
        }
    }

    impl Drop for Fixture {
        fn drop(&mut self) {
            let _ = fs::remove_dir_all(&self.0);
        }
    }

    fn record(operation_id: Uuid, phase: BackupOperationPhase) -> BackupOperationRecord {
        BackupOperationRecord {
            format: BACKUP_OPERATION_FORMAT.to_owned(),
            operation_id,
            phase,
            backup_id: operation_id.to_string(),
            destination: "/var/lib/o3k/backups".to_owned(),
            staging_path: format!("/var/lib/o3k/backups/.o3k-backup-artifact-{operation_id}"),
            request_sha256: Some("a".repeat(64)),
            artifact_sha256: None,
            reserved_bytes: None,
            site_id: "site-1".to_owned(),
            installation_id: "install-1".to_owned(),
            created_at: "2026-10-23T12:00:00Z".to_owned(),
            updated_at: "2026-10-23T12:00:01Z".to_owned(),
        }
    }

    #[test]
    fn records_round_trip_atomically_and_replace_in_place() {
        let fixture = Fixture::new("round-trip");
        let operation_id = Uuid::new_v4();
        assert_eq!(
            read_backup_operation(&fixture.0, operation_id).expect("missing is not an error"),
            None
        );
        let mut first = record(operation_id, BackupOperationPhase::Capturing);
        first.request_sha256 = None;
        write_backup_operation(&fixture.0, &first).expect("write capturing");
        assert_eq!(
            read_backup_operation(&fixture.0, operation_id).expect("read"),
            Some(first)
        );
        let staged = record(operation_id, BackupOperationPhase::Staged);
        write_backup_operation(&fixture.0, &staged).expect("replace with staged");
        assert_eq!(
            read_backup_operation(&fixture.0, operation_id).expect("read"),
            Some(staged.clone())
        );
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            let path = operation_path(&fixture.0, operation_id);
            assert_eq!(
                fs::metadata(&path).expect("record").permissions().mode() & 0o777,
                0o600
            );
            assert_eq!(
                fs::metadata(fixture.0.join(BACKUP_OPERATION_DIR))
                    .expect("directory")
                    .permissions()
                    .mode()
                    & 0o777,
                0o700
            );
        }
        let entries = fs::read_dir(fixture.0.join(BACKUP_OPERATION_DIR))
            .expect("journal directory")
            .count();
        assert_eq!(entries, 1, "temporary records are never left behind");
        assert_eq!(
            staged.phase.as_str(),
            "staged",
            "phase spelling is part of the record format"
        );
    }

    #[test]
    fn pending_scan_reports_only_non_terminal_records() {
        let fixture = Fixture::new("pending");
        let terminal = [
            BackupOperationPhase::Published,
            BackupOperationPhase::Aborted,
        ];
        let non_terminal = [
            BackupOperationPhase::Capturing,
            BackupOperationPhase::Captured,
            BackupOperationPhase::Staged,
            BackupOperationPhase::Publishing,
        ];
        for phase in terminal.into_iter().chain(non_terminal) {
            write_backup_operation(&fixture.0, &record(Uuid::new_v4(), phase))
                .expect("write record");
        }
        let scan = pending_backup_operations(&fixture.0).expect("scan");
        assert_eq!(scan.pending.len(), 4);
        assert!(scan.unreadable.is_empty());
        assert!(
            scan.pending
                .iter()
                .all(|record| !record.phase.is_terminal())
        );
        assert!(
            scan.pending
                .windows(2)
                .all(|pair| pair[0].operation_id < pair[1].operation_id)
        );
    }

    #[test]
    fn pending_scan_tolerates_unreadable_entries_and_missing_directory() {
        let fixture = Fixture::new("tolerate");
        assert_eq!(
            pending_backup_operations(&fixture.0).expect("missing directory"),
            PendingBackupOperations::default()
        );
        let directory = ensure_operation_directory(&fixture.0).expect("create journal directory");
        fs::write(directory.join("not-a-record.json"), b"{}").expect("write malformed name");
        fs::write(
            directory.join(format!("{}.json", Uuid::new_v4())),
            b"not-json",
        )
        .expect("write malformed record");
        let scan = pending_backup_operations(&fixture.0).expect("scan");
        assert!(scan.pending.is_empty());
        assert_eq!(scan.unreadable.len(), 2);
    }

    #[test]
    fn invalid_records_fail_closed() {
        let fixture = Fixture::new("invalid");
        let operation_id = Uuid::new_v4();
        write_backup_operation(
            &fixture.0,
            &record(operation_id, BackupOperationPhase::Staged),
        )
        .expect("write valid record");
        let path = operation_path(&fixture.0, operation_id);
        let mut value: serde_json::Value =
            serde_json::from_slice(&fs::read(&path).expect("read record")).expect("json");
        value["artifact_sha256"] = serde_json::json!("NOT-A-DIGEST");
        fs::write(&path, serde_json::to_vec(&value).expect("encode")).expect("corrupt record");
        assert_eq!(
            read_backup_operation(&fixture.0, operation_id),
            Err(BackupJournalError::InvalidRecord)
        );

        let mut value: serde_json::Value = serde_json::from_slice(
            &fs::read(operation_path(&fixture.0, operation_id)).expect("read record"),
        )
        .expect("json");
        value["phase"] = serde_json::json!("unknown-phase");
        fs::write(&path, serde_json::to_vec(&value).expect("encode")).expect("corrupt phase");
        assert_eq!(
            read_backup_operation(&fixture.0, operation_id),
            Err(BackupJournalError::InvalidRecord)
        );

        // A record whose embedded id disagrees with its file name is never
        // treated as the operation it is filed under.
        let other = Uuid::new_v4();
        write_backup_operation(&fixture.0, &record(other, BackupOperationPhase::Staged))
            .expect("write other record");
        fs::copy(
            operation_path(&fixture.0, other),
            operation_path(&fixture.0, operation_id),
        )
        .expect("copy record");
        assert_eq!(
            read_backup_operation(&fixture.0, operation_id),
            Err(BackupJournalError::InvalidRecord)
        );
    }

    #[cfg(unix)]
    #[test]
    fn symlinked_journal_directory_is_rejected() {
        let fixture = Fixture::new("symlink");
        let target = fixture.0.join("elsewhere");
        fs::create_dir(&target).expect("target directory");
        std::os::unix::fs::symlink(&target, fixture.0.join(BACKUP_OPERATION_DIR))
            .expect("journal symlink");
        assert_eq!(
            write_backup_operation(
                &fixture.0,
                &record(Uuid::new_v4(), BackupOperationPhase::Capturing)
            ),
            Err(BackupJournalError::UnsafeEntry)
        );
        assert_eq!(
            pending_backup_operations(&fixture.0),
            Err(BackupJournalError::UnsafeEntry)
        );
        assert_eq!(
            read_backup_operation(&fixture.0, Uuid::new_v4()),
            Err(BackupJournalError::UnsafeEntry),
            "a replaced journal directory is rejected before any record lookup"
        );
    }

    #[test]
    fn identifiers_reject_path_traversal_and_empty_values() {
        let operation_id = Uuid::new_v4();
        for field in ["backup_id", "site_id", "installation_id"] {
            let mut value = record(operation_id, BackupOperationPhase::Staged);
            match field {
                "backup_id" => value.backup_id = "x/../../escaped".to_owned(),
                "site_id" => value.site_id = "..".to_owned(),
                _ => value.installation_id = "".to_owned(),
            }
            assert_eq!(
                write_backup_operation(&Fixture::new("identifier").0, &value),
                Err(BackupJournalError::InvalidRecord),
                "field {field}"
            );
        }
        assert!(is_identifier("8a1c9e5e-3b2f-4a9a-9df0-4f0e2f1d9c11"));
        assert!(is_identifier("site-1"));
        assert!(is_identifier("a.b_c:d"));
        assert!(!is_identifier(""));
        assert!(!is_identifier(".leading-dot"));
        assert!(!is_identifier("x/../../escaped"));
        assert!(!is_identifier("space id"));
        assert!(!is_identifier("../up"));
    }

    #[cfg(unix)]
    #[test]
    fn symlinked_and_over_permissive_records_are_rejected() {
        use std::os::unix::fs::PermissionsExt;
        let fixture = Fixture::new("record-posture");
        let operation_id = Uuid::new_v4();
        write_backup_operation(
            &fixture.0,
            &record(operation_id, BackupOperationPhase::Staged),
        )
        .expect("write valid record");
        let path = operation_path(&fixture.0, operation_id);
        fs::set_permissions(&path, fs::Permissions::from_mode(0o644)).expect("relax record");
        assert_eq!(
            read_backup_operation(&fixture.0, operation_id),
            Err(BackupJournalError::UnsafeEntry)
        );
        fs::set_permissions(&path, fs::Permissions::from_mode(0o600)).expect("restore record");

        let target = fixture.0.join("elsewhere.json");
        fs::rename(&path, &target).expect("move record");
        std::os::unix::fs::symlink(&target, &path).expect("record symlink");
        assert_eq!(
            read_backup_operation(&fixture.0, operation_id),
            Err(BackupJournalError::UnsafeEntry)
        );

        // A group-accessible journal directory is rejected on every read.
        fs::remove_file(&path).expect("remove symlink");
        fs::rename(&target, &path).expect("restore record");
        fs::set_permissions(
            fixture.0.join(BACKUP_OPERATION_DIR),
            fs::Permissions::from_mode(0o750),
        )
        .expect("relax journal directory");
        assert_eq!(
            read_backup_operation(&fixture.0, operation_id),
            Err(BackupJournalError::UnsafeEntry)
        );
    }

    #[test]
    fn oversized_records_are_rejected_before_parsing() {
        let fixture = Fixture::new("oversized");
        let operation_id = Uuid::new_v4();
        let directory = ensure_operation_directory(&fixture.0).expect("journal directory");
        let path = directory.join(format!("{operation_id}.json"));
        fs::write(&path, vec![b' '; (MAX_OPERATION_RECORD_BYTES + 1) as usize])
            .expect("write oversized record");
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            fs::set_permissions(&path, fs::Permissions::from_mode(0o600))
                .expect("restrict oversized record");
        }
        assert_eq!(
            read_backup_operation(&fixture.0, operation_id),
            Err(BackupJournalError::InvalidRecord)
        );
    }

    #[test]
    fn phases_and_terminality_are_stable() {
        assert!(!BackupOperationPhase::Capturing.is_terminal());
        assert!(!BackupOperationPhase::Captured.is_terminal());
        assert!(BackupOperationPhase::Staged.is_pending_publication());
        assert!(BackupOperationPhase::Publishing.is_pending_publication());
        assert!(!BackupOperationPhase::Staged.is_terminal());
        assert!(BackupOperationPhase::Published.is_terminal());
        assert!(BackupOperationPhase::Aborted.is_terminal());
        assert_eq!(
            serde_json::to_string(&BackupOperationPhase::Staged).expect("encode"),
            "\"staged\""
        );
    }

    #[test]
    fn transitions_only_move_forward() {
        use BackupOperationPhase::{Aborted, Captured, Capturing, Published, Publishing, Staged};
        let forward = [
            (Capturing, Captured),
            (Captured, Staged),
            (Staged, Publishing),
            (Publishing, Published),
            (Capturing, Aborted),
            (Captured, Aborted),
            (Staged, Aborted),
            (Publishing, Aborted),
        ];
        for (from, to) in forward {
            assert!(from.may_advance_to(to), "{from} -> {to} must be allowed");
        }
        let backwards = [
            (Captured, Capturing),
            (Staged, Captured),
            (Publishing, Staged),
            (Published, Publishing),
            (Published, Staged),
            (Aborted, Capturing),
            (Aborted, Published),
            (Published, Aborted),
            (Capturing, Staged),
        ];
        for (from, to) in backwards {
            assert!(!from.may_advance_to(to), "{from} -> {to} must be refused");
        }
    }

    #[test]
    fn advance_is_idempotent_and_refuses_to_regress() {
        let fixture = Fixture::new("advance");
        let operation_id = Uuid::new_v4();
        write_backup_operation(
            &fixture.0,
            &record(operation_id, BackupOperationPhase::Capturing),
        )
        .expect("write capturing");
        advance_backup_operation(
            &fixture.0,
            &record(operation_id, BackupOperationPhase::Captured),
        )
        .expect("capturing -> captured");
        // Replaying the durable transition is a no-op.
        advance_backup_operation(
            &fixture.0,
            &record(operation_id, BackupOperationPhase::Captured),
        )
        .expect("replayed captured transition");
        assert_eq!(
            advance_backup_operation(
                &fixture.0,
                &record(operation_id, BackupOperationPhase::Capturing)
            ),
            Err(BackupJournalError::InvalidTransition)
        );
        assert_eq!(
            read_backup_operation(&fixture.0, operation_id)
                .expect("read")
                .map(|stored| stored.phase),
            Some(BackupOperationPhase::Captured),
            "a refused transition must leave the recorded phase untouched"
        );
        advance_backup_operation(
            &fixture.0,
            &record(operation_id, BackupOperationPhase::Staged),
        )
        .expect("captured -> staged");
        advance_backup_operation(
            &fixture.0,
            &record(operation_id, BackupOperationPhase::Publishing),
        )
        .expect("staged -> publishing");
        assert_eq!(
            advance_backup_operation(
                &fixture.0,
                &record(operation_id, BackupOperationPhase::Staged)
            ),
            Err(BackupJournalError::InvalidTransition)
        );
        advance_backup_operation(
            &fixture.0,
            &record(operation_id, BackupOperationPhase::Published),
        )
        .expect("publishing -> published");
        assert_eq!(
            advance_backup_operation(
                &fixture.0,
                &record(operation_id, BackupOperationPhase::Aborted)
            ),
            Err(BackupJournalError::InvalidTransition),
            "a published operation is terminal"
        );
        // A record that does not exist yet can never be advanced.
        let missing = Uuid::new_v4();
        assert_eq!(
            advance_backup_operation(&fixture.0, &record(missing, BackupOperationPhase::Captured)),
            Err(BackupJournalError::InvalidTransition)
        );
    }
}
