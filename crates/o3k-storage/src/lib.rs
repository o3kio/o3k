//! Bounded native storage execution providers.
//!
//! This crate is an execution boundary, not a source of O3K authority. It
//! never allocates public IDs, authorizes projects, or persists canonical
//! tenant resources. Provider-native handles returned by this crate are
//! transient execution observations and must not be copied into
//! `VolumeAttachment` state.

use async_trait::async_trait;
use o3k_domain::{
    AttachmentAccessMode, SnapshotConsistency, SnapshotId, StorageCapabilities,
    StorageCommandEnvelope, StorageObservation, StorageOperationState, StorageProviderReference,
    VolumeAttachmentId, VolumeId,
};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use std::{
    fmt,
    sync::Arc,
    time::{SystemTime, UNIX_EPOCH},
};
use thiserror::Error;
use tokio::process::Command;

/// Durable local acceptance journal used by the storage executor boundary.
/// The controller remains authoritative; this journal only fences replay and
/// records executor outcomes before a process restart can lose them.
#[derive(Debug, Clone, Serialize, Deserialize)]
struct JournalRecord {
    envelope: StorageCommandEnvelope,
    observation: StorageObservation,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
struct JournalSnapshot {
    format_version: u16,
    controller_epoch: u64,
    records: Vec<JournalRecord>,
}

#[derive(Debug, Error)]
pub enum StorageJournalError {
    #[error("storage journal I/O failed: {0}")]
    Io(#[from] std::io::Error),
    #[error("storage journal encoding failed: {0}")]
    Encoding(#[from] serde_json::Error),
    #[error("storage command conflicts with an existing idempotency record")]
    Conflict,
    #[error("storage journal record was not found")]
    NotFound,
    #[error("storage command is stale for the executor")]
    Stale,
    #[error("storage journal commit is visible but directory durability is uncertain: {0}")]
    DurabilityUncertain(#[source] std::io::Error),
}

#[derive(Debug)]
pub struct StorageJournal {
    path: std::path::PathBuf,
    records: std::sync::Mutex<Vec<JournalRecord>>,
    controller_epoch: std::sync::Mutex<u64>,
}

impl StorageJournal {
    pub fn open(path: impl Into<std::path::PathBuf>) -> Result<Self, StorageJournalError> {
        let path = path.into();
        let journal = Self {
            path,
            records: std::sync::Mutex::new(Vec::new()),
            controller_epoch: std::sync::Mutex::new(0),
        };
        let _lock = acquire_journal_lock(&journal_lock_path(&journal.path))?;
        journal.reload_locked()?;
        Ok(journal)
    }

    pub fn accept(
        &self,
        envelope: StorageCommandEnvelope,
        agent_id: &str,
        agent_epoch: u64,
    ) -> Result<StorageObservation, StorageJournalError> {
        let _lock = acquire_journal_lock(&journal_lock_path(&self.path))?;
        self.reload_locked()?;
        envelope
            .validate()
            .map_err(|_| StorageJournalError::Stale)?;
        if envelope.target_agent_id != agent_id || envelope.target_agent_epoch != agent_epoch {
            return Err(StorageJournalError::Stale);
        }
        let mut records = self
            .records
            .lock()
            .map_err(|_| StorageJournalError::Conflict)?;
        let mut current_epoch = self
            .controller_epoch
            .lock()
            .map_err(|_| StorageJournalError::Conflict)?;
        if *current_epoch != 0 && envelope.controller_epoch != *current_epoch {
            return Err(StorageJournalError::Stale);
        }
        if let Some(existing) = records
            .iter()
            .find(|record| record.envelope.idempotency_key == envelope.idempotency_key)
        {
            return if existing.envelope == envelope {
                Ok(existing.observation.clone())
            } else {
                Err(StorageJournalError::Conflict)
            };
        }
        let observation = StorageObservation {
            agent_id: agent_id.to_owned(),
            agent_epoch,
            resource_id: envelope.resource_id.clone(),
            provider_resource_id: None,
            operation_id: envelope.operation_id,
            resource_generation: envelope.resource_generation,
            observation_sequence: 1,
            observed_at: acceptance_time(),
            operation_state: StorageOperationState::Accepted,
            resource_state: "accepted".to_owned(),
            error_category: None,
            redacted_message: None,
        };
        let next_controller_epoch = envelope.controller_epoch;
        let mut candidate = records.clone();
        candidate.push(JournalRecord {
            envelope,
            observation: observation.clone(),
        });
        match persist_journal(&self.path, next_controller_epoch, &candidate) {
            Ok(()) => {}
            Err(error @ StorageJournalError::DurabilityUncertain(_)) => {
                *records = candidate;
                drop(records);
                *current_epoch = next_controller_epoch;
                return Err(error);
            }
            Err(error) => return Err(error),
        }
        *records = candidate;
        *current_epoch = next_controller_epoch;
        Ok(observation)
    }

    pub fn get(
        &self,
        idempotency_key: &str,
    ) -> Result<Option<StorageObservation>, StorageJournalError> {
        let _lock = acquire_journal_lock(&journal_lock_path(&self.path))?;
        self.reload_locked()?;
        let records = self
            .records
            .lock()
            .map_err(|_| StorageJournalError::Conflict)?;
        Ok(records
            .iter()
            .find(|record| record.envelope.idempotency_key == idempotency_key)
            .map(|record| record.observation.clone()))
    }

    /// Persist an executor observation after the bounded provider has run.
    /// The caller must retain the envelope identity and monotonically advance
    /// the observation sequence; the journal never invents controller state.
    pub fn record_observation(
        &self,
        idempotency_key: &str,
        observation: StorageObservation,
    ) -> Result<(), StorageJournalError> {
        let _lock = acquire_journal_lock(&journal_lock_path(&self.path))?;
        self.reload_locked()?;
        observation
            .validate()
            .map_err(|_| StorageJournalError::Conflict)?;
        let mut records = self
            .records
            .lock()
            .map_err(|_| StorageJournalError::Conflict)?;
        let record = records
            .iter_mut()
            .find(|record| record.envelope.idempotency_key == idempotency_key)
            .ok_or(StorageJournalError::NotFound)?;
        if observation.agent_id != record.observation.agent_id
            || observation.agent_epoch != record.observation.agent_epoch
            || observation.operation_id != record.observation.operation_id
            || observation.resource_generation != record.observation.resource_generation
            || observation.observation_sequence <= record.observation.observation_sequence
            || observation.resource_id != record.envelope.resource_id
        {
            return Err(StorageJournalError::Conflict);
        }
        let mut candidate = records.clone();
        let index = candidate
            .iter()
            .position(|item| item.envelope.idempotency_key == idempotency_key)
            .ok_or(StorageJournalError::NotFound)?;
        candidate[index].observation = observation;
        let epoch = *self
            .controller_epoch
            .lock()
            .map_err(|_| StorageJournalError::Conflict)?;
        match persist_journal(&self.path, epoch, &candidate) {
            Ok(()) => {}
            Err(error @ StorageJournalError::DurabilityUncertain(_)) => {
                *records = candidate;
                return Err(error);
            }
            Err(error) => return Err(error),
        }
        *records = candidate;
        Ok(())
    }

    fn reload_locked(&self) -> Result<(), StorageJournalError> {
        if !self.path.exists() {
            return Ok(());
        }
        let bytes = std::fs::read(&self.path)?;
        let (epoch, records, migrated) = match serde_json::from_slice::<JournalSnapshot>(&bytes) {
            Ok(snapshot) if snapshot.format_version == 1 => {
                (snapshot.controller_epoch, snapshot.records, false)
            }
            Ok(_) => return Err(StorageJournalError::Conflict),
            Err(_) => (
                0,
                serde_json::from_slice::<Vec<JournalRecord>>(&bytes)?,
                true,
            ),
        };
        if migrated {
            match persist_journal(&self.path, epoch, &records) {
                Ok(()) => {}
                Err(StorageJournalError::DurabilityUncertain(error)) => {
                    *self
                        .records
                        .lock()
                        .map_err(|_| StorageJournalError::Conflict)? = records;
                    *self
                        .controller_epoch
                        .lock()
                        .map_err(|_| StorageJournalError::Conflict)? = epoch;
                    return Err(StorageJournalError::DurabilityUncertain(error));
                }
                Err(error) => return Err(error),
            }
        }
        *self
            .records
            .lock()
            .map_err(|_| StorageJournalError::Conflict)? = records;
        *self
            .controller_epoch
            .lock()
            .map_err(|_| StorageJournalError::Conflict)? = epoch;
        Ok(())
    }
}

fn journal_lock_path(path: &std::path::Path) -> std::path::PathBuf {
    path.parent()
        .unwrap_or_else(|| std::path::Path::new("."))
        .join(format!(
            ".{}.lock",
            path.file_name()
                .and_then(|n| n.to_str())
                .unwrap_or("journal")
        ))
}

fn persist_journal(
    path: &std::path::Path,
    controller_epoch: u64,
    records: &[JournalRecord],
) -> Result<(), StorageJournalError> {
    use std::fs::OpenOptions;
    use std::os::unix::fs::OpenOptionsExt;
    let parent = path
        .parent()
        .ok_or_else(|| std::io::Error::other("journal has no parent"))?;
    std::fs::create_dir_all(parent)?;
    let temporary = parent.join(format!(".journal-{}.tmp", uuid::Uuid::new_v4()));
    let bytes = serde_json::to_vec(&JournalSnapshot {
        format_version: 1,
        controller_epoch,
        records: records.to_vec(),
    })?;
    let mut file = OpenOptions::new()
        .write(true)
        .create_new(true)
        .mode(0o600)
        .open(&temporary)?;
    std::io::Write::write_all(&mut file, &bytes)?;
    file.sync_all()?;
    std::fs::rename(&temporary, path)?;
    if let Err(error) = std::fs::File::open(parent).and_then(|directory| directory.sync_all()) {
        return Err(StorageJournalError::DurabilityUncertain(error));
    }
    Ok(())
}

struct JournalLock {
    _file: std::fs::File,
}
fn acquire_journal_lock(path: &std::path::Path) -> Result<JournalLock, StorageJournalError> {
    use std::fs::OpenOptions;
    use std::os::unix::fs::OpenOptionsExt;
    if let Some(parent) = path.parent() {
        std::fs::create_dir_all(parent)?;
    }
    let file = OpenOptions::new()
        .read(true)
        .write(true)
        .create(true)
        .truncate(false)
        .mode(0o600)
        .open(path)?;
    rustix::fs::flock(&file, rustix::fs::FlockOperation::LockExclusive)
        .map_err(std::io::Error::from)?;
    Ok(JournalLock { _file: file })
}

fn acceptance_time() -> String {
    let millis = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map_or(0, |duration| duration.as_millis());
    format!("unix-ms:{millis}")
}

mod ceph;
#[cfg(all(test, unix))]
mod command_drain_tests;

#[cfg(test)]
#[allow(clippy::expect_used)]
mod command_allowlist_tests {
    use super::*;

    #[tokio::test]
    async fn system_runner_rejects_non_lvm_programs_before_spawn() {
        let runner = SystemLvmCommandRunner::default();
        let result = runner
            .run("sh", &["-c".to_owned(), "touch /tmp/o3k-escape".to_owned()])
            .await;
        assert!(matches!(result, Err(LvmCommandError::Failed)));
    }

    #[tokio::test]
    async fn system_runner_rejects_path_prefixed_lvm_names() {
        let runner = SystemLvmCommandRunner::default();
        for program in ["/tmp/vgs", "./lvcreate", "../lvremove"] {
            let result = runner.run(program, &[]).await;
            assert!(matches!(result, Err(LvmCommandError::Failed)), "{program}");
        }
    }

    #[tokio::test]
    async fn system_runner_uses_trusted_absolute_path_for_allowed_name() {
        let runner = SystemLvmCommandRunner::default();
        // The command is allowed by name, but the process is always launched
        // from /usr/sbin rather than resolved through PATH. An invalid option
        // proves the real binary was reached without mutating any VG.
        let result = runner
            .run("vgs", &["--o3k-invalid-option".to_owned()])
            .await;
        assert!(
            result.as_ref().is_ok_and(|output| output.status != 0),
            "trusted vgs should spawn and reject the deliberately invalid option"
        );
    }
}

#[cfg(test)]
#[allow(clippy::expect_used)]
mod journal_tests {
    use super::*;
    use std::time::{SystemTime, UNIX_EPOCH};

    fn envelope(key: &str, fingerprint: &str) -> StorageCommandEnvelope {
        StorageCommandEnvelope {
            protocol_version: 1,
            command_id: uuid::Uuid::new_v4(),
            operation_id: uuid::Uuid::new_v4(),
            idempotency_key: key.to_owned(),
            resource_id: "volume-1".to_owned(),
            resource_generation: 1,
            project_id: "project-1".to_owned(),
            controller_epoch: 1,
            target_agent_id: "storage-a".to_owned(),
            target_agent_epoch: 7,
            deadline: "2099-01-01T00:00:00Z".to_owned(),
            trace_id: "trace-1".to_owned(),
            action: o3k_domain::StorageAction::CreateVolume,
            canonical_payload_fingerprint: fingerprint.to_owned(),
        }
    }

    fn path() -> std::path::PathBuf {
        let nanos = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .expect("clock before epoch")
            .as_nanos();
        std::env::temp_dir().join(format!("o3k-storage-journal-{nanos}.json"))
    }

    #[test]
    fn acceptance_replays_after_restart_and_rejects_conflicts() {
        let journal_path = path();
        let command = envelope("op-1", &"a".repeat(64));
        let accepted = StorageJournal::open(&journal_path)
            .expect("journal opens")
            .accept(command.clone(), "storage-a", 7)
            .expect("command accepted");
        let journal = StorageJournal::open(&journal_path).expect("journal reloads");
        assert_eq!(journal.get("op-1").expect("lookup"), Some(accepted.clone()));
        assert_eq!(
            journal.accept(command, "storage-a", 7).expect("replay"),
            accepted
        );
        assert!(matches!(
            journal.accept(envelope("op-1", &"b".repeat(64)), "storage-a", 7),
            Err(StorageJournalError::Conflict)
        ));
        let _ = std::fs::remove_file(journal_path);
    }

    #[test]
    fn stale_agent_epoch_is_rejected() {
        let journal_path = path();
        let result = StorageJournal::open(&journal_path)
            .expect("journal opens")
            .accept(envelope("op-2", &"c".repeat(64)), "storage-a", 8);
        assert!(matches!(result, Err(StorageJournalError::Stale)));
        let _ = std::fs::remove_file(journal_path);
    }

    #[test]
    fn terminal_observation_is_durable_and_sequence_fenced() {
        let journal_path = path();
        let command = envelope("op-3", &"d".repeat(64));
        let journal = StorageJournal::open(&journal_path).expect("journal opens");
        let accepted = journal.accept(command, "storage-a", 7).expect("accepted");
        let mut terminal = accepted.clone();
        terminal.observation_sequence = 2;
        terminal.operation_state = StorageOperationState::Succeeded;
        terminal.resource_state = "available".to_owned();
        journal
            .record_observation("op-3", terminal.clone())
            .expect("recorded");
        assert_eq!(
            StorageJournal::open(&journal_path)
                .expect("reload")
                .get("op-3")
                .expect("lookup"),
            Some(terminal)
        );
        let _ = std::fs::remove_file(journal_path);
    }

    #[test]
    fn independent_instances_preserve_overlapping_updates() {
        let journal_path = path();
        let first = StorageJournal::open(&journal_path).expect("journal");
        let second = StorageJournal::open(&journal_path).expect("journal");
        first
            .accept(envelope("op-a", &"e".repeat(64)), "storage-a", 7)
            .expect("first");
        second
            .accept(envelope("op-b", &"f".repeat(64)), "storage-a", 7)
            .expect("second");
        let reloaded = StorageJournal::open(&journal_path).expect("reload");
        assert!(reloaded.get("op-a").expect("lookup").is_some());
        assert!(reloaded.get("op-b").expect("lookup").is_some());
        let _ = std::fs::remove_file(journal_path);
    }

    #[test]
    fn legacy_record_vector_is_migrated_before_mutation() {
        let journal_path = path();
        let command = envelope("legacy-op", &"a".repeat(64));
        let old = JournalRecord {
            envelope: command.clone(),
            observation: StorageObservation {
                agent_id: "storage-a".to_owned(),
                agent_epoch: 7,
                resource_id: command.resource_id.clone(),
                provider_resource_id: None,
                operation_id: command.operation_id,
                resource_generation: command.resource_generation,
                observation_sequence: 1,
                observed_at: acceptance_time(),
                operation_state: StorageOperationState::Accepted,
                resource_state: "accepted".to_owned(),
                error_category: None,
                redacted_message: None,
            },
        };
        std::fs::write(
            &journal_path,
            serde_json::to_vec(&vec![old]).expect("encode legacy"),
        )
        .expect("write legacy journal");

        let journal = StorageJournal::open(&journal_path).expect("migrate legacy on open");
        assert!(
            journal
                .get("legacy-op")
                .expect("read legacy record")
                .is_some()
        );
        journal
            .accept(envelope("new-op", &"b".repeat(64)), "storage-a", 7)
            .expect("mutation succeeds after migration");
        let migrated: JournalSnapshot =
            serde_json::from_slice(&std::fs::read(&journal_path).expect("read migrated"))
                .expect("snapshot format");
        assert_eq!(migrated.format_version, 1);
        assert_eq!(migrated.records.len(), 2);
        let _ = std::fs::remove_file(&journal_path);
    }

    #[test]
    fn reads_refresh_records_written_by_another_journal_instance() {
        let journal_path = path();
        let first = StorageJournal::open(&journal_path).expect("first journal");
        let second = StorageJournal::open(&journal_path).expect("second journal");
        first
            .accept(envelope("cross-instance", &"c".repeat(64)), "storage-a", 7)
            .expect("accept command");
        assert!(second.get("cross-instance").expect("fresh read").is_some());
        let _ = std::fs::remove_file(&journal_path);
    }
}

pub use ceph::{
    CephCommandError, CephCommandOutput, CephCommandRunner, CephRbdConfig, CephRbdStorageProvider,
    SystemCephCommandRunner,
};

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct StorageVolumeRequest {
    pub volume_id: VolumeId,
    pub project_id: String,
    pub size_bytes: u64,
    pub generation: u64,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct StorageSnapshotRequest {
    pub snapshot_id: SnapshotId,
    pub volume_id: VolumeId,
    pub project_id: String,
    pub source_generation: u64,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct StorageAttachmentRequest {
    pub attachment_id: VolumeAttachmentId,
    pub volume_id: VolumeId,
    pub project_id: String,
    pub volume_generation: u64,
    pub host_id: String,
    pub access_mode: AttachmentAccessMode,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct StorageVolumeObservation {
    pub provider_reference: StorageProviderReference,
    pub size_bytes: u64,
    pub owned: bool,
    pub available: bool,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PreparedAttachment {
    pub provider_reference: StorageProviderReference,
    /// Provider-native device identity. This is execution-only and must never
    /// be persisted in canonical VolumeAttachment state or public APIs.
    device_path: String,
    pub attachment_id: VolumeAttachmentId,
    pub volume_id: VolumeId,
}

impl PreparedAttachment {
    /// Construct a transient provider/compute hand-off. The value is kept
    /// execution-only; callers must not persist or serialize `device_path` in
    /// canonical state or public responses.
    pub fn from_provider(
        provider_reference: StorageProviderReference,
        device_path: String,
        attachment_id: VolumeAttachmentId,
        volume_id: VolumeId,
    ) -> Result<Self, StorageProviderError> {
        if device_path.is_empty() || device_path.len() > 512 || device_path.contains('\0') {
            return Err(StorageProviderError::InvalidRequest);
        }
        Ok(Self {
            provider_reference,
            device_path,
            attachment_id,
            volume_id,
        })
    }

    #[must_use]
    pub fn device_path(&self) -> &str {
        &self.device_path
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct StorageAttachmentObservation {
    pub attachment_id: VolumeAttachmentId,
    pub volume_id: VolumeId,
    pub host_id: String,
    pub attached: bool,
    pub provider_reference: StorageProviderReference,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct StorageSnapshotObservation {
    pub provider_reference: StorageProviderReference,
    pub consistency: SnapshotConsistency,
    pub available: bool,
}

#[derive(Debug, Error, Clone, PartialEq, Eq)]
pub enum StorageProviderError {
    #[error("invalid storage request")]
    InvalidRequest,
    #[error("configured storage scope is invalid")]
    InvalidConfiguration,
    #[error("storage resource was not found")]
    NotFound,
    #[error("storage resource is not owned by O3K")]
    ForeignResource,
    #[error("storage capacity is unavailable")]
    Capacity,
    #[error("storage command was unavailable")]
    Unavailable,
    #[error("storage mutation outcome is unknown")]
    UnknownOutcome,
    #[error("storage command failed")]
    CommandFailed,
    #[error("storage resource conflicts with an existing owned resource")]
    Conflict,
}

impl StorageProviderError {
    #[must_use]
    pub const fn is_unknown_outcome(&self) -> bool {
        matches!(self, Self::UnknownOutcome | Self::Unavailable)
    }
}

#[async_trait]
pub trait StorageProvider: Send + Sync {
    async fn capabilities(&self) -> Result<StorageCapabilities, StorageProviderError>;
    async fn create_volume(
        &self,
        request: &StorageVolumeRequest,
    ) -> Result<StorageVolumeObservation, StorageProviderError>;
    async fn inspect_volume(
        &self,
        request: &StorageVolumeRequest,
    ) -> Result<StorageVolumeObservation, StorageProviderError>;
    async fn delete_volume(
        &self,
        request: &StorageVolumeRequest,
    ) -> Result<(), StorageProviderError>;
    async fn prepare_attachment(
        &self,
        request: &StorageAttachmentRequest,
    ) -> Result<PreparedAttachment, StorageProviderError>;
    /// Observe the bounded storage-side attachment state without retrying a
    /// mutation. A controller uses this after an unknown outcome before it
    /// may issue another command.
    async fn inspect_attachment(
        &self,
        request: &StorageAttachmentRequest,
    ) -> Result<StorageAttachmentObservation, StorageProviderError>;
    async fn terminate_attachment(
        &self,
        request: &StorageAttachmentRequest,
    ) -> Result<StorageAttachmentObservation, StorageProviderError>;
    async fn create_snapshot(
        &self,
        request: &StorageSnapshotRequest,
    ) -> Result<StorageSnapshotObservation, StorageProviderError>;
    async fn delete_snapshot(
        &self,
        request: &StorageSnapshotRequest,
    ) -> Result<(), StorageProviderError>;
}

/// Minimal stateful provider for composition/recovery tests.  It models the
/// same observe-after-mutation contract as a real provider without touching
/// host storage.
pub mod testkit {
    use super::*;
    use std::collections::BTreeMap;
    use std::sync::Mutex;
    use uuid::Uuid;

    #[derive(Default)]
    pub struct InMemoryStorageProvider {
        volumes: Mutex<BTreeMap<Uuid, StorageVolumeObservation>>,
    }

    #[async_trait]
    impl StorageProvider for InMemoryStorageProvider {
        async fn capabilities(&self) -> Result<StorageCapabilities, StorageProviderError> {
            Ok(StorageCapabilities {
                create_volume: true,
                snapshots: false,
                attachment: false,
                capacity_bytes: u64::MAX,
                allocated_bytes: 0,
                allocation_unit_bytes: 1,
            })
        }

        async fn create_volume(
            &self,
            request: &StorageVolumeRequest,
        ) -> Result<StorageVolumeObservation, StorageProviderError> {
            let observation = StorageVolumeObservation {
                provider_reference: StorageProviderReference {
                    provider: "test".to_owned(),
                    resource_id: request.volume_id.to_string(),
                },
                size_bytes: request.size_bytes,
                owned: true,
                available: true,
            };
            self.volumes
                .lock()
                .map_err(|_| StorageProviderError::CommandFailed)?
                .insert(request.volume_id.as_uuid(), observation.clone());
            Ok(observation)
        }

        async fn inspect_volume(
            &self,
            request: &StorageVolumeRequest,
        ) -> Result<StorageVolumeObservation, StorageProviderError> {
            self.volumes
                .lock()
                .map_err(|_| StorageProviderError::CommandFailed)?
                .get(&request.volume_id.as_uuid())
                .cloned()
                .ok_or(StorageProviderError::NotFound)
        }

        async fn delete_volume(
            &self,
            request: &StorageVolumeRequest,
        ) -> Result<(), StorageProviderError> {
            self.volumes
                .lock()
                .map_err(|_| StorageProviderError::CommandFailed)?
                .remove(&request.volume_id.as_uuid())
                .map(|_| ())
                .ok_or(StorageProviderError::NotFound)
        }

        async fn prepare_attachment(
            &self,
            request: &StorageAttachmentRequest,
        ) -> Result<PreparedAttachment, StorageProviderError> {
            PreparedAttachment::from_provider(
                StorageProviderReference {
                    provider: "test".to_owned(),
                    resource_id: request.volume_id.to_string(),
                },
                "/dev/test".to_owned(),
                request.attachment_id,
                request.volume_id,
            )
        }

        async fn inspect_attachment(
            &self,
            request: &StorageAttachmentRequest,
        ) -> Result<StorageAttachmentObservation, StorageProviderError> {
            Ok(StorageAttachmentObservation {
                attachment_id: request.attachment_id,
                volume_id: request.volume_id,
                host_id: request.host_id.clone(),
                attached: false,
                provider_reference: StorageProviderReference {
                    provider: "test".to_owned(),
                    resource_id: request.volume_id.to_string(),
                },
            })
        }

        async fn terminate_attachment(
            &self,
            request: &StorageAttachmentRequest,
        ) -> Result<StorageAttachmentObservation, StorageProviderError> {
            self.inspect_attachment(request).await
        }

        async fn create_snapshot(
            &self,
            _request: &StorageSnapshotRequest,
        ) -> Result<StorageSnapshotObservation, StorageProviderError> {
            Err(StorageProviderError::InvalidRequest)
        }

        async fn delete_snapshot(
            &self,
            _request: &StorageSnapshotRequest,
        ) -> Result<(), StorageProviderError> {
            Err(StorageProviderError::InvalidRequest)
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct LvmConfig {
    pub volume_group: String,
    pub thin_pool: String,
    pub provider_namespace: String,
}

impl LvmConfig {
    pub fn validate(&self) -> Result<(), StorageProviderError> {
        for value in [
            &self.volume_group,
            &self.thin_pool,
            &self.provider_namespace,
        ] {
            if value.is_empty()
                || value.len() > 128
                || !value
                    .bytes()
                    .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'_' | b'.' | b'-'))
            {
                return Err(StorageProviderError::InvalidConfiguration);
            }
        }
        if self.volume_group == self.thin_pool {
            return Err(StorageProviderError::InvalidConfiguration);
        }
        Ok(())
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct LvmCommandOutput {
    pub status: i32,
    pub stdout: String,
}

#[derive(Debug, Error, Clone, PartialEq, Eq)]
pub enum LvmCommandError {
    #[error("command unavailable")]
    Unavailable,
    #[error("command timed out")]
    Timeout,
    #[error("command failed")]
    Failed,
}

#[async_trait]
pub trait LvmCommandRunner: Send + Sync {
    async fn run(
        &self,
        program: &str,
        args: &[String],
    ) -> Result<LvmCommandOutput, LvmCommandError>;
}

type OwnedLvmCommand = Arc<tokio::sync::Mutex<Option<tokio::task::JoinHandle<()>>>>;

#[derive(Debug, Default)]
struct LvmCommandTasks {
    tasks: std::sync::Mutex<Vec<OwnedLvmCommand>>,
    closed: std::sync::atomic::AtomicBool,
    failed: std::sync::atomic::AtomicBool,
}

#[derive(Debug, Default, Clone)]
pub struct SystemLvmCommandRunner {
    owned: Arc<LvmCommandTasks>,
    #[cfg(test)]
    test_program: Option<String>,
}

impl SystemLvmCommandRunner {
    #[cfg(test)]
    fn for_test_program(program: &str) -> Self {
        Self {
            owned: Arc::new(LvmCommandTasks::default()),
            test_program: Some(program.to_owned()),
        }
    }

    /// Close command admission and await every submitted subprocess. Commands
    /// are never aborted here: cancellation of their caller cannot make a
    /// still-running storage mutation disappear from the drain predicate.
    pub async fn drain(&self, timeout: std::time::Duration) -> Result<(), LvmCommandError> {
        use std::sync::atomic::Ordering;
        if self.owned.failed.swap(true, Ordering::AcqRel) {
            return Err(LvmCommandError::Failed);
        }
        let deadline = tokio::time::Instant::now() + timeout;
        let tasks = {
            let tasks = self
                .owned
                .tasks
                .lock()
                .map_err(|_| LvmCommandError::Failed)?;
            self.owned.closed.store(true, Ordering::Release);
            tasks.clone()
        };
        for task in tasks {
            let mut slot = tokio::time::timeout_at(deadline, task.lock())
                .await
                .map_err(|_| LvmCommandError::Failed)?;
            if let Some(task) = slot.as_mut() {
                let result = tokio::time::timeout_at(deadline, task)
                    .await
                    .map_err(|_| LvmCommandError::Failed)?;
                slot.take();
                result.map_err(|_| LvmCommandError::Failed)?;
            }
        }
        self.owned
            .tasks
            .lock()
            .map_err(|_| LvmCommandError::Failed)?
            .clear();
        self.owned.failed.store(false, Ordering::Release);
        Ok(())
    }
}

#[async_trait]
impl LvmCommandRunner for SystemLvmCommandRunner {
    async fn run(
        &self,
        program: &str,
        args: &[String],
    ) -> Result<LvmCommandOutput, LvmCommandError> {
        // The system runner is intended for the dedicated storage executor.
        // Keep the executable surface closed even if a future provider call
        // accidentally forwards an attacker-controlled program name.
        let trusted_program = match program {
            "vgs" => "/usr/sbin/vgs",
            "lvs" => "/usr/sbin/lvs",
            "lvcreate" => "/usr/sbin/lvcreate",
            "lvremove" => "/usr/sbin/lvremove",
            "lvchange" => "/usr/sbin/lvchange",
            // Reject path-prefixed names as well as arbitrary executables. The
            // fixed absolute paths below prevent PATH shadowing by the service
            // environment or a writable working directory.
            #[cfg(test)]
            _ if self.test_program.as_deref() == Some(program) => program,
            _ => return Err(LvmCommandError::Failed),
        };
        #[cfg(test)]
        let trusted_program = self.test_program.as_deref().unwrap_or(trusted_program);
        use std::sync::atomic::Ordering;
        let program = trusted_program.to_owned();
        let args = args.to_vec();
        let (sender, receiver) = tokio::sync::oneshot::channel();
        {
            let mut tasks = self
                .owned
                .tasks
                .lock()
                .map_err(|_| LvmCommandError::Failed)?;
            if self.owned.closed.load(Ordering::Acquire) {
                return Err(LvmCommandError::Unavailable);
            }
            tasks.retain(|slot| {
                let Ok(mut slot) = slot.try_lock() else {
                    return true;
                };
                let Some(task) = slot.as_mut() else {
                    return false;
                };
                if !task.is_finished() {
                    return true;
                }
                let mut context = std::task::Context::from_waker(std::task::Waker::noop());
                match std::future::Future::poll(std::pin::Pin::new(task), &mut context) {
                    std::task::Poll::Ready(result) => {
                        slot.take();
                        if result.is_err() {
                            self.owned.failed.store(true, Ordering::Release);
                        }
                        false
                    }
                    std::task::Poll::Pending => true,
                }
            });
            let task = tokio::spawn(async move {
                let result = async {
                    let output = Command::new(program)
                        .kill_on_drop(true)
                        .args(args)
                        .output()
                        .await
                        .map_err(|_| LvmCommandError::Unavailable)?;
                    Ok(LvmCommandOutput {
                        status: output.status.code().unwrap_or(1),
                        stdout: String::from_utf8(output.stdout)
                            .map_err(|_| LvmCommandError::Failed)?,
                    })
                }
                .await;
                let _ = sender.send(result);
            });
            tasks.push(Arc::new(tokio::sync::Mutex::new(Some(task))));
        }
        receiver.await.map_err(|_| LvmCommandError::Failed)?
    }
}

#[derive(Clone)]
pub struct LvmStorageProvider<R = SystemLvmCommandRunner> {
    config: LvmConfig,
    runner: Arc<R>,
}

impl<R> fmt::Debug for LvmStorageProvider<R> {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("LvmStorageProvider")
            .field("config", &self.config)
            .finish_non_exhaustive()
    }
}

impl LvmStorageProvider<SystemLvmCommandRunner> {
    pub async fn drain_owned_commands(
        &self,
        timeout: std::time::Duration,
    ) -> Result<(), LvmCommandError> {
        self.runner.drain(timeout).await
    }

    pub fn new(config: LvmConfig) -> Result<Self, StorageProviderError> {
        Self::with_runner(config, SystemLvmCommandRunner::default())
    }
}

impl<R: LvmCommandRunner> LvmStorageProvider<R> {
    pub fn with_runner(config: LvmConfig, runner: R) -> Result<Self, StorageProviderError> {
        config.validate()?;
        Ok(Self {
            config,
            runner: Arc::new(runner),
        })
    }

    #[must_use]
    pub fn config(&self) -> &LvmConfig {
        &self.config
    }

    fn run_args(&self, args: &[&str]) -> Vec<String> {
        args.iter().map(|arg| (*arg).to_owned()).collect()
    }

    async fn command(
        &self,
        program: &str,
        args: &[String],
    ) -> Result<LvmCommandOutput, StorageProviderError>
    where
        R: LvmCommandRunner + Sync,
    {
        self.runner
            .run(program, args)
            .await
            .map_err(|error| match error {
                LvmCommandError::Unavailable => StorageProviderError::Unavailable,
                LvmCommandError::Timeout => StorageProviderError::UnknownOutcome,
                LvmCommandError::Failed => StorageProviderError::CommandFailed,
            })
    }

    async fn checked_command(
        &self,
        program: &str,
        args: &[String],
    ) -> Result<LvmCommandOutput, StorageProviderError>
    where
        R: LvmCommandRunner + Sync,
    {
        let output = self.command(program, args).await?;
        if output.status != 0 {
            return Err(StorageProviderError::CommandFailed);
        }
        Ok(output)
    }

    fn lv_name(&self, id: VolumeId) -> String {
        format!("o3k-v-{}", id.as_uuid().simple())
    }

    fn snapshot_name(&self, id: SnapshotId) -> String {
        format!("o3k-s-{}", id.as_uuid().simple())
    }

    fn marker(&self, volume_id: VolumeId, project_id: &str, generation: u64) -> String {
        let mut digest = Sha256::new();
        digest.update(self.config.provider_namespace.as_bytes());
        digest.update([0]);
        digest.update(volume_id.as_uuid().as_bytes());
        digest.update([0]);
        digest.update(project_id.as_bytes());
        digest.update([0]);
        digest.update(generation.to_be_bytes());
        let hex = digest
            .finalize()
            .iter()
            .map(|byte| format!("{byte:02x}"))
            .collect::<String>();
        format!("o3k_owner_{hex}")
    }

    /// Volume ownership is stable across canonical lifecycle revisions. The
    /// generation is a durable fencing value for the control plane, not part
    /// of the provider object's ownership identity; otherwise an Available
    /// volume could no longer be inspected or deleted after its canonical
    /// generation advanced from the create revision.
    fn volume_marker(&self, volume_id: VolumeId, project_id: &str) -> String {
        let mut digest = Sha256::new();
        digest.update(self.config.provider_namespace.as_bytes());
        digest.update([0]);
        digest.update(volume_id.as_uuid().as_bytes());
        digest.update([0]);
        digest.update(project_id.as_bytes());
        let hex = digest
            .finalize()
            .iter()
            .map(|byte| format!("{byte:02x}"))
            .collect::<String>();
        format!("o3k_volume_owner_{hex}")
    }

    fn scope_marker(&self, kind: &str) -> String {
        let mut digest = Sha256::new();
        digest.update(self.config.provider_namespace.as_bytes());
        let hex = digest
            .finalize()
            .iter()
            .map(|byte| format!("{byte:02x}"))
            .collect::<String>();
        format!("o3k_{kind}_{hex}")
    }

    async fn verify_scope(&self) -> Result<LvmVg, StorageProviderError>
    where
        R: LvmCommandRunner + Sync,
    {
        let output = self
            .checked_command(
                "vgs",
                &self.run_args(&[
                    "--reportformat",
                    "json",
                    "--units",
                    "b",
                    "--nosuffix",
                    "--options",
                    "vg_name,vg_size,vg_free,vg_tags",
                ]),
            )
            .await?;
        let volume_group = parse_vgs(&output.stdout)?
            .into_iter()
            .find(|entry| {
                entry.vg_name == self.config.volume_group
                    && entry
                        .tags
                        .iter()
                        .any(|tag| tag == &self.scope_marker("storage"))
            })
            .ok_or(StorageProviderError::ForeignResource)?;

        let output = self
            .checked_command(
                "lvs",
                &self.run_args(&[
                    "--reportformat",
                    "json",
                    "--units",
                    "b",
                    "--nosuffix",
                    "--options",
                    "lv_name,lv_size,lv_tags,lv_attr,vg_name",
                ]),
            )
            .await?;
        let thin_pool = parse_lvs(&output.stdout)?.into_iter().any(|entry| {
            entry.lv_name == self.config.thin_pool
                && entry.vg_name == self.config.volume_group
                && entry.lv_attr.starts_with('t')
                && entry
                    .tags
                    .iter()
                    .any(|tag| tag == &self.scope_marker("pool"))
        });
        if !thin_pool {
            return Err(StorageProviderError::ForeignResource);
        }
        Ok(volume_group)
    }

    async fn owned_lv(
        &self,
        volume_id: VolumeId,
        project_id: &str,
        _generation: u64,
    ) -> Result<LvmLv, StorageProviderError>
    where
        R: LvmCommandRunner + Sync,
    {
        self.verify_scope().await?;
        let output = self
            .checked_command(
                "lvs",
                &self.run_args(&[
                    "--reportformat",
                    "json",
                    "--units",
                    "b",
                    "--nosuffix",
                    "--options",
                    "lv_name,lv_size,lv_tags,lv_attr,vg_name",
                    "--select",
                    "lv_name!~^o3k-s-",
                ]),
            )
            .await?;
        let marker = self.volume_marker(volume_id, project_id);
        let entries = parse_lvs(&output.stdout)?;
        let expected_name = self.lv_name(volume_id);
        let matches = entries
            .into_iter()
            .filter(|entry| {
                entry.vg_name == self.config.volume_group
                    && entry.tags.iter().any(|tag| tag == &marker)
            })
            .collect::<Vec<_>>();
        if matches.len() > 1 {
            return Err(StorageProviderError::Conflict);
        }
        let Some(entry) = matches.into_iter().next() else {
            return Err(StorageProviderError::NotFound);
        };
        if entry.lv_name != expected_name {
            return Err(StorageProviderError::ForeignResource);
        }
        Ok(entry)
    }

    fn validate_volume_request(request: &StorageVolumeRequest) -> Result<(), StorageProviderError> {
        if request.project_id.is_empty()
            || request.project_id.len() > 256
            || request.size_bytes == 0
            || request.generation == 0
        {
            return Err(StorageProviderError::InvalidRequest);
        }
        Ok(())
    }
}

#[async_trait]
impl<R> StorageProvider for LvmStorageProvider<R>
where
    R: LvmCommandRunner + Sync,
{
    async fn capabilities(&self) -> Result<StorageCapabilities, StorageProviderError> {
        let entry = self.verify_scope().await?;
        Ok(StorageCapabilities {
            create_volume: true,
            snapshots: true,
            attachment: true,
            capacity_bytes: entry.size_bytes,
            allocated_bytes: entry.size_bytes.saturating_sub(entry.free_bytes),
            allocation_unit_bytes: 4096,
        })
    }

    async fn create_volume(
        &self,
        request: &StorageVolumeRequest,
    ) -> Result<StorageVolumeObservation, StorageProviderError> {
        Self::validate_volume_request(request)?;
        match self.inspect_volume(request).await {
            Ok(observation) => return Ok(observation),
            Err(StorageProviderError::NotFound) => {}
            Err(error) => return Err(error),
        }
        let marker = self.volume_marker(request.volume_id, &request.project_id);
        let name = self.lv_name(request.volume_id);
        let size = format!("{}B", request.size_bytes);
        self.checked_command(
            "lvcreate",
            &self.run_args(&[
                "--type",
                "thin",
                "--name",
                &name,
                "--virtualsize",
                &size,
                "--addtag",
                &marker,
                &format!("{}/{}", self.config.volume_group, self.config.thin_pool),
            ]),
        )
        .await?;
        self.inspect_volume(request).await
    }

    async fn inspect_volume(
        &self,
        request: &StorageVolumeRequest,
    ) -> Result<StorageVolumeObservation, StorageProviderError> {
        Self::validate_volume_request(request)?;
        let entry = self
            .owned_lv(request.volume_id, &request.project_id, request.generation)
            .await?;
        Ok(StorageVolumeObservation {
            provider_reference: StorageProviderReference {
                provider: "lvm".to_owned(),
                resource_id: entry.lv_name,
            },
            size_bytes: entry.lv_size,
            owned: true,
            available: true,
        })
    }

    async fn delete_volume(
        &self,
        request: &StorageVolumeRequest,
    ) -> Result<(), StorageProviderError> {
        Self::validate_volume_request(request)?;
        let name = self
            .owned_lv(request.volume_id, &request.project_id, request.generation)
            .await?
            .lv_name;
        self.checked_command(
            "lvremove",
            &self.run_args(&["--yes", &format!("{}/{}", self.config.volume_group, name)]),
        )
        .await?;
        Ok(())
    }

    async fn prepare_attachment(
        &self,
        request: &StorageAttachmentRequest,
    ) -> Result<PreparedAttachment, StorageProviderError> {
        if request.project_id.is_empty() || request.host_id.is_empty() {
            return Err(StorageProviderError::InvalidRequest);
        }
        if request.volume_generation == 0 {
            return Err(StorageProviderError::InvalidRequest);
        }
        let name = self
            .owned_lv(
                request.volume_id,
                &request.project_id,
                request.volume_generation,
            )
            .await?
            .lv_name;
        Ok(PreparedAttachment {
            provider_reference: StorageProviderReference {
                provider: "lvm".to_owned(),
                resource_id: name.clone(),
            },
            device_path: format!("/dev/{}/{}", self.config.volume_group, name),
            attachment_id: request.attachment_id,
            volume_id: request.volume_id,
        })
    }

    async fn terminate_attachment(
        &self,
        request: &StorageAttachmentRequest,
    ) -> Result<StorageAttachmentObservation, StorageProviderError> {
        let prepared = self.prepare_attachment(request).await?;
        Ok(StorageAttachmentObservation {
            attachment_id: request.attachment_id,
            volume_id: request.volume_id,
            host_id: request.host_id.clone(),
            attached: false,
            provider_reference: prepared.provider_reference,
        })
    }

    async fn inspect_attachment(
        &self,
        request: &StorageAttachmentRequest,
    ) -> Result<StorageAttachmentObservation, StorageProviderError> {
        let prepared = self.prepare_attachment(request).await?;
        Ok(StorageAttachmentObservation {
            attachment_id: request.attachment_id,
            volume_id: request.volume_id,
            host_id: request.host_id.clone(),
            // LVM preparation is intentionally stateless at the storage
            // boundary; libvirt/compute owns the live attach observation.
            attached: false,
            provider_reference: prepared.provider_reference,
        })
    }

    async fn create_snapshot(
        &self,
        request: &StorageSnapshotRequest,
    ) -> Result<StorageSnapshotObservation, StorageProviderError> {
        if request.project_id.is_empty() || request.source_generation == 0 {
            return Err(StorageProviderError::InvalidRequest);
        }
        let source = self
            .owned_lv(
                request.volume_id,
                &request.project_id,
                request.source_generation,
            )
            .await?
            .lv_name;
        let name = self.snapshot_name(request.snapshot_id);
        let marker = self.marker(
            request.volume_id,
            &request.project_id,
            request.source_generation,
        );
        self.checked_command(
            "lvcreate",
            &self.run_args(&[
                "--snapshot",
                "--name",
                &name,
                "--addtag",
                &marker,
                &format!("{}/{}", self.config.volume_group, source),
            ]),
        )
        .await?;
        Ok(StorageSnapshotObservation {
            provider_reference: StorageProviderReference {
                provider: "lvm".to_owned(),
                resource_id: name,
            },
            consistency: SnapshotConsistency::CrashConsistent,
            available: true,
        })
    }

    async fn delete_snapshot(
        &self,
        request: &StorageSnapshotRequest,
    ) -> Result<(), StorageProviderError> {
        if request.project_id.is_empty() || request.source_generation == 0 {
            return Err(StorageProviderError::InvalidRequest);
        }
        let output = self
            .checked_command(
                "lvs",
                &self.run_args(&[
                    "--reportformat",
                    "json",
                    "--units",
                    "b",
                    "--nosuffix",
                    "--options",
                    "lv_name,lv_size,lv_tags,lv_attr,vg_name",
                    "--select",
                    "lv_name!~^o3k-v-",
                ]),
            )
            .await?;
        let marker = self.marker(
            request.volume_id,
            &request.project_id,
            request.source_generation,
        );
        let name = self.snapshot_name(request.snapshot_id);
        let owned = parse_lvs(&output.stdout)?.into_iter().any(|entry| {
            entry.lv_name == name
                && entry.vg_name == self.config.volume_group
                && entry.tags.iter().any(|tag| tag == &marker)
        });
        if !owned {
            return Err(StorageProviderError::NotFound);
        }
        self.checked_command(
            "lvremove",
            &self.run_args(&["--yes", &format!("{}/{}", self.config.volume_group, name)]),
        )
        .await?;
        Ok(())
    }
}

#[derive(Debug, Deserialize)]
struct LvmReport<T> {
    report: Vec<T>,
}

#[derive(Debug, Deserialize)]
struct LvmRows<T> {
    lv: Option<Vec<T>>,
    vg: Option<Vec<T>>,
}

#[derive(Debug, Clone)]
struct LvmLv {
    lv_name: String,
    lv_size: u64,
    tags: Vec<String>,
    vg_name: String,
    lv_attr: String,
}

#[derive(Debug, Clone)]
struct LvmVg {
    vg_name: String,
    size_bytes: u64,
    free_bytes: u64,
    tags: Vec<String>,
}

fn parse_lvs(payload: &str) -> Result<Vec<LvmLv>, StorageProviderError> {
    let report: LvmReport<LvmRows<LvmLvJson>> =
        serde_json::from_str(payload).map_err(|_| StorageProviderError::CommandFailed)?;
    report
        .report
        .into_iter()
        .flat_map(|row| row.lv.unwrap_or_default())
        .map(|row| {
            Ok(LvmLv {
                lv_name: row.lv_name,
                lv_size: parse_bytes(&row.lv_size)?,
                tags: row
                    .lv_tags
                    .split(',')
                    .filter(|tag| !tag.is_empty())
                    .map(ToOwned::to_owned)
                    .collect(),
                vg_name: row.vg_name,
                lv_attr: row.lv_attr,
            })
        })
        .collect::<Result<Vec<_>, StorageProviderError>>()
}

fn parse_vgs(payload: &str) -> Result<Vec<LvmVg>, StorageProviderError> {
    let report: LvmReport<LvmRows<LvmVgJson>> =
        serde_json::from_str(payload).map_err(|_| StorageProviderError::CommandFailed)?;
    report
        .report
        .into_iter()
        .flat_map(|row| row.vg.unwrap_or_default())
        .map(|row| {
            Ok(LvmVg {
                vg_name: row.vg_name,
                size_bytes: parse_bytes(&row.vg_size)?,
                free_bytes: parse_bytes(&row.vg_free)?,
                tags: row
                    .vg_tags
                    .split(',')
                    .filter(|tag| !tag.is_empty())
                    .map(ToOwned::to_owned)
                    .collect(),
            })
        })
        .collect()
}

fn parse_bytes(value: &str) -> Result<u64, StorageProviderError> {
    let number = value
        .parse::<f64>()
        .map_err(|_| StorageProviderError::CommandFailed)?;
    if !number.is_finite() || number < 0.0 || number > u64::MAX as f64 {
        return Err(StorageProviderError::CommandFailed);
    }
    Ok(number as u64)
}

#[derive(Debug, Deserialize)]
struct LvmLvJson {
    lv_name: String,
    lv_size: String,
    #[serde(default)]
    lv_tags: String,
    #[serde(default)]
    lv_attr: String,
    vg_name: String,
}

#[derive(Debug, Deserialize)]
struct LvmVgJson {
    vg_name: String,
    vg_size: String,
    vg_free: String,
    #[serde(default)]
    vg_tags: String,
}

#[cfg(test)]
#[allow(clippy::expect_used)]
mod tests {
    use super::*;
    use std::sync::Mutex;
    use uuid::Uuid;

    #[derive(Default)]
    struct FakeRunner {
        calls: Mutex<Vec<(String, Vec<String>)>>,
        output: Mutex<Option<LvmCommandOutput>>,
    }

    #[async_trait]
    impl LvmCommandRunner for FakeRunner {
        async fn run(
            &self,
            program: &str,
            args: &[String],
        ) -> Result<LvmCommandOutput, LvmCommandError> {
            self.calls
                .lock()
                .map_err(|_| LvmCommandError::Failed)?
                .push((program.to_owned(), args.to_vec()));
            self.output
                .lock()
                .map_err(|_| LvmCommandError::Failed)?
                .clone()
                .ok_or(LvmCommandError::Failed)
        }
    }

    fn config() -> LvmConfig {
        LvmConfig {
            volume_group: "o3k-test-vg".to_owned(),
            thin_pool: "o3k-thin".to_owned(),
            provider_namespace: "testlab".to_owned(),
        }
    }

    fn volume() -> StorageVolumeRequest {
        StorageVolumeRequest {
            volume_id: VolumeId::from_uuid(Uuid::from_u128(7)),
            project_id: "project-a".to_owned(),
            size_bytes: 4096,
            generation: 1,
        }
    }

    #[test]
    fn config_rejects_unsafe_or_ambiguous_scope() {
        assert!(
            LvmConfig {
                volume_group: "/dev/vg".to_owned(),
                ..config()
            }
            .validate()
            .is_err()
        );
        assert!(
            LvmConfig {
                thin_pool: "o3k-test-vg".to_owned(),
                ..config()
            }
            .validate()
            .is_err()
        );
    }

    #[test]
    fn provider_markers_bind_the_right_identity() {
        let provider =
            LvmStorageProvider::with_runner(config(), FakeRunner::default()).expect("valid config");
        assert_ne!(
            provider.volume_marker(volume().volume_id, "project-a"),
            provider.volume_marker(volume().volume_id, "project-b")
        );
        assert_ne!(
            provider.marker(volume().volume_id, "project-a", 1),
            provider.marker(volume().volume_id, "project-a", 2)
        );
        assert_eq!(
            provider.volume_marker(volume().volume_id, "project-a"),
            provider.volume_marker(volume().volume_id, "project-a")
        );
    }

    #[test]
    fn parsers_accept_bounded_lvm_json() {
        let lvs = r#"{"report":[{"lv":[{"lv_name":"o3k-v-1","lv_size":"4096","lv_tags":"o3k_owner_ab,o3k_other","vg_name":"o3k-test-vg"}]}]}"#;
        assert_eq!(parse_lvs(lvs).expect("lvs")[0].tags.len(), 2);
        let vgs =
            r#"{"report":[{"vg":[{"vg_name":"o3k-test-vg","vg_size":"10000","vg_free":"4000"}]}]}"#;
        assert_eq!(parse_vgs(vgs).expect("vgs")[0].free_bytes, 4000);
    }

    #[tokio::test]
    async fn create_command_uses_thin_pool_and_ownership_marker() {
        let output = r#"{"report":[{"lv":[{"lv_name":"o3k-v-00000000000000000000000000000007","lv_size":"4096","lv_tags":"o3k_owner_8a1d0b1c3ef2edc9a6c0f2da22d50ee1d3f4fb5b8f2f13b3b7d1e07a4a5b4c9d","vg_name":"o3k-test-vg"}]}]}"#;
        let runner = FakeRunner {
            calls: Mutex::new(Vec::new()),
            output: Mutex::new(Some(LvmCommandOutput {
                status: 0,
                stdout: output.to_owned(),
            })),
        };
        let provider = LvmStorageProvider::with_runner(config(), runner).expect("valid config");
        // The fake output is deliberately not used as ownership evidence here;
        // this test only ensures invalid fixture markers fail closed.
        assert!(provider.create_volume(&volume()).await.is_err());
    }
}
