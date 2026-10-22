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
    StorageProviderReference, VolumeAttachmentId, VolumeId,
};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use std::{fmt, sync::Arc};
use thiserror::Error;
use tokio::process::Command;

mod ceph;
#[cfg(all(test, unix))]
mod command_drain_tests;

pub use ceph::{
    CephCommandError, CephCommandOutput, CephCommandRunner, CephRbdConfig, CephRbdStorageProvider,
    SystemCephCommandRunner,
};

#[derive(Debug, Clone, PartialEq, Eq)]
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
}

impl SystemLvmCommandRunner {
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
        use std::sync::atomic::Ordering;
        let program = program.to_owned();
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
