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
//! `captured`/`staged`/`publishing` record must never deny controller startup:
//! the staged artifact is not canonical state, and publication can be
//! completed by a later operator invocation without the store lock.
//!
//! Records are private files (`0600`) inside a private directory (`0700`) in
//! the data directory. They carry operation identity, lifecycle, paths and
//! digests only — never credentials, key material or provider payloads. The
//! lifecycle is written atomically (private temporary file, `fsync`, rename,
//! directory `fsync`) so a crash leaves either the previous or the next phase.

use std::{
    fmt, fs,
    io::{self, Read, Write},
    path::{Path, PathBuf},
};

use chrono::DateTime;
use rustix::{
    fs::{Mode, OFlags, open},
    process::geteuid,
};
use serde::{Deserialize, Serialize};
use uuid::Uuid;

/// Directory inside the data directory that holds the operation journal.
pub const BACKUP_OPERATION_DIR: &str = "backup-operations";

/// Versioned record format marker.
pub const BACKUP_OPERATION_FORMAT: &str = "o3k-backup-operation-v1";

const MAX_OPERATION_RECORD_BYTES: u64 = 64 * 1024;
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
    let path = operation_path(data_dir, operation_id);
    match fs::symlink_metadata(&path) {
        Ok(metadata) => {
            if metadata.file_type().is_symlink() || !metadata.file_type().is_file() {
                return Err(BackupJournalError::UnsafeEntry);
            }
            let record = read_record(&path)?;
            if record.operation_id != operation_id {
                return Err(BackupJournalError::InvalidRecord);
            }
            Ok(Some(record))
        }
        Err(error) if error.kind() == io::ErrorKind::NotFound => Ok(None),
        Err(_) => Err(BackupJournalError::Unavailable),
    }
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
    let directory = data_dir.join(BACKUP_OPERATION_DIR);
    let metadata = match fs::symlink_metadata(&directory) {
        Ok(metadata) => metadata,
        Err(error) if error.kind() == io::ErrorKind::NotFound => {
            return Ok(PendingBackupOperations::default());
        }
        Err(_) => return Err(BackupJournalError::Unavailable),
    };
    if metadata.file_type().is_symlink() || !metadata.is_dir() {
        return Err(BackupJournalError::UnsafeEntry);
    }
    let mut pending = Vec::new();
    let mut unreadable = Vec::new();
    let entries = fs::read_dir(&directory).map_err(|_| BackupJournalError::Unavailable)?;
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
        let Ok(file_type) = entry.file_type() else {
            unreadable.push(name.to_owned());
            continue;
        };
        if !file_type.is_file() {
            unreadable.push(name.to_owned());
            continue;
        }
        match read_record(&entry.path()) {
            Ok(record) if record.operation_id == operation_id && !record.phase.is_terminal() => {
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

fn read_record(path: &Path) -> Result<BackupOperationRecord, BackupJournalError> {
    let metadata = fs::symlink_metadata(path).map_err(|_| BackupJournalError::Unavailable)?;
    if metadata.file_type().is_symlink() || !metadata.file_type().is_file() {
        return Err(BackupJournalError::UnsafeEntry);
    }
    if metadata.len() > MAX_OPERATION_RECORD_BYTES {
        return Err(BackupJournalError::InvalidRecord);
    }
    let mut bytes = Vec::new();
    fs::File::open(path)
        .map_err(|_| BackupJournalError::Unavailable)?
        .take(MAX_OPERATION_RECORD_BYTES + 1)
        .read_to_end(&mut bytes)
        .map_err(|_| BackupJournalError::Unavailable)?;
    if bytes.len() as u64 > MAX_OPERATION_RECORD_BYTES {
        return Err(BackupJournalError::InvalidRecord);
    }
    let record: BackupOperationRecord =
        serde_json::from_slice(&bytes).map_err(|_| BackupJournalError::InvalidRecord)?;
    record.validate()?;
    Ok(record)
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
        let uid = geteuid().as_raw();
        if metadata.uid() != 0 && metadata.uid() != uid {
            return Err(BackupJournalError::UnsafeEntry);
        }
        if metadata.permissions().mode() & 0o022 != 0 {
            return Err(BackupJournalError::UnsafeEntry);
        }
    }
    Ok(())
}

fn sync_directory(directory: &Path) -> io::Result<()> {
    let descriptor = open(
        directory,
        OFlags::RDONLY | OFlags::DIRECTORY | OFlags::CLOEXEC | OFlags::NOFOLLOW,
        Mode::empty(),
    )?;
    fs::File::from(descriptor).sync_all()
}

fn is_identifier(value: &str) -> bool {
    !value.is_empty()
        && value.len() <= MAX_IDENTIFIER_BYTES
        && value
            .bytes()
            .all(|byte| byte.is_ascii_graphic() && !matches!(byte, b'"' | b'\\'))
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
            Ok(None),
            "a missing record inside a replaced directory is not followed"
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
}
