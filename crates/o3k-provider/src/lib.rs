use std::{
    collections::HashMap,
    sync::{Arc, Mutex},
};

use async_trait::async_trait;
use serde::{Deserialize, Serialize};
use thiserror::Error;
use uuid::Uuid;

pub mod agent;
pub mod attachment;
pub mod node;

pub use agent::{
    AgentArtifactAck, AgentArtifactStatus, AgentCommandAccepted, AgentErrorCategory, AgentEvent,
    AgentObservation, AgentOperationState, AgentOperationUpdate, AgentProtocolError,
    ArtifactTransferState,
};
pub use attachment::{
    AttachmentError, AttachmentObservation, AttachmentTarget, ComputeConnector, ConnectionInfo,
    ConnectionInfoPresence, VolumeAttachmentProvider,
};
pub use node::{
    AgentAdministrativeState, AgentAvailability, AgentCapabilities, AgentCapabilityFlag,
    AgentEpochLease, AgentNodeRegistry, AgentNodeSnapshot, ArtifactKind, CreateArtifactResolver,
    NetworkAttachmentSpec, ResolvedCreateArtifact, ResolvedCreateInputs, ResolvedCreateResolver,
    UnconfiguredCreateArtifactResolver, UnconfiguredResolvedCreateResolver,
};

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Capabilities {
    pub provider_name: String,
    pub provider_version: String,
    pub capabilities: Vec<String>,
}

/// Optional, caller-provided inputs for generating a config-drive image.
///
/// This is part of the durable create intent, but API acceptance and
/// config-drive materialization remain outside this contract for now.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ConfigDriveRequest {
    pub user_data: Vec<u8>,
    #[serde(default)]
    pub vendor_data: Option<Vec<u8>>,
    pub ssh_public_key: String,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct CreateInstanceRequest {
    pub operation_id: Uuid,
    pub o3k_server_id: Uuid,
    #[serde(default)]
    pub project_id: String,
    pub name: String,
    pub vcpus: u32,
    pub memory_mib: u64,
    /// The selected Nova flavor identity is persisted with the create intent.
    /// Providers do not resolve flavor values by dimension because distinct
    /// flavors may legitimately share vCPU and memory values.
    #[serde(default)]
    pub flavor_id: String,
    #[serde(default)]
    pub disk_gib: u64,
    pub image_id: Option<String>,
    #[serde(default)]
    pub key_name: Option<String>,
    #[serde(default)]
    pub keypair_id: Option<Uuid>,
    #[serde(default)]
    pub network_ids: Vec<String>,
    #[serde(default)]
    pub placement_provider_id: Option<String>,
    #[serde(default)]
    pub placement_allocation_id: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub config_drive: Option<ConfigDriveRequest>,
    pub idempotency_key: String,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct DeleteInstanceRequest {
    pub operation_id: Uuid,
    pub provider_instance_id: String,
    pub idempotency_key: String,
}

/// Compute connector description required by the Cinder connector-update flow.
/// Mirrors the os-brick connector shape. The `initiator` is the iSCSI
/// initiator name when the host supports it.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ConnectorInfo {
    pub host: String,
    pub ip: String,
    pub platform: String,
    pub os_type: String,
    pub multipath: bool,
    pub initiator: Option<String>,
}

/// Bounded block-device attachment description dispatched to the compute
/// execution boundary. CHAP credentials are carried only over the
/// authenticated agent control channel; callers must never log or persist
/// these fields outside the run-owned durable journal, and the agent applies
/// them exclusively to the iSCSI node session at login.
#[derive(Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct BlockDeviceAttachment {
    pub volume_id: String,
    pub attachment_id: String,
    pub driver_volume_type: String,
    #[serde(default)]
    pub target_iqn: Option<String>,
    #[serde(default)]
    pub target_portal: Option<String>,
    #[serde(default)]
    pub target_lun: Option<u32>,
    #[serde(default)]
    pub local_path: Option<String>,
    #[serde(default)]
    pub device_path: Option<String>,
    #[serde(default)]
    pub multipath: bool,
    #[serde(default)]
    pub initiator: Option<String>,
    #[serde(default)]
    pub auth_method: Option<String>,
    #[serde(default)]
    pub auth_username: Option<String>,
    #[serde(default)]
    pub auth_password: Option<String>,
}

impl std::fmt::Debug for BlockDeviceAttachment {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter
            .debug_struct("BlockDeviceAttachment")
            .field("volume_id", &self.volume_id)
            .field("attachment_id", &self.attachment_id)
            .field("driver_volume_type", &self.driver_volume_type)
            .field("target_iqn", &self.target_iqn)
            .field("target_portal", &self.target_portal)
            .field("target_lun", &self.target_lun)
            .field("local_path", &self.local_path)
            .field("device_path", &self.device_path)
            .field("multipath", &self.multipath)
            .field("initiator", &self.initiator)
            .field("auth_method", &self.auth_method)
            .field("auth_username", &"<redacted>")
            .field("auth_password", &"<redacted>")
            .finish()
    }
}

/// Observation of a compute-side block device after attach/detach/observe.
/// The optional connector fields are present on observations produced by the
/// collect-connector command; they are never persisted.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct BlockDeviceObservation {
    pub volume_id: String,
    pub attachment_id: String,
    pub driver_volume_type: String,
    #[serde(default)]
    pub device_path: Option<String>,
    #[serde(default)]
    pub host_path: Option<String>,
    pub attached: bool,
    pub found: bool,
    #[serde(default)]
    pub initiator: Option<String>,
    #[serde(default)]
    pub host_name: Option<String>,
    #[serde(default)]
    pub ip_address: Option<String>,
    #[serde(default)]
    pub iscsi_logged_in: bool,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum InstanceAction {
    Start,
    Stop,
    Reboot,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Instance {
    pub provider_instance_id: String,
    pub o3k_server_id: Uuid,
    pub state: InstanceState,
    pub observed_message: Option<String>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum InstanceState {
    Creating,
    Running,
    Stopped,
    Deleting,
    Deleted,
    Error,
}

/// Explicit projection from a provider observation to the canonical O3K
/// server lifecycle state. Provider state is deliberately separate: it
/// describes what the execution boundary observes, while `o3k_domain`
/// owns the durable lifecycle model. This projection is the only sanctioned
/// bridge between the two.
impl From<InstanceState> for o3k_domain::ServerState {
    fn from(state: InstanceState) -> Self {
        match state {
            InstanceState::Creating => o3k_domain::ServerState::Building,
            InstanceState::Running => o3k_domain::ServerState::Active,
            InstanceState::Stopped => o3k_domain::ServerState::Stopped,
            InstanceState::Deleting => o3k_domain::ServerState::Deleting,
            InstanceState::Deleted => o3k_domain::ServerState::Deleted,
            InstanceState::Error => o3k_domain::ServerState::Error,
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Operation {
    pub provider_operation_id: Uuid,
    pub o3k_operation_id: Uuid,
    pub state: OperationState,
    pub error_category: Option<ErrorCategory>,
    pub provider_resource_id: Option<String>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum OperationState {
    Accepted,
    Running,
    Succeeded,
    Retryable,
    UnknownOutcome,
    Failed,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum ErrorCategory {
    InvalidRequest,
    NotFound,
    Conflict,
    Capacity,
    Retryable,
    UnknownOutcome,
    Terminal,
}

#[derive(Debug, Error, Clone, PartialEq, Eq)]
pub enum ProviderError {
    #[error("provider rejected the request")]
    InvalidRequest,
    #[error("provider resource was not found")]
    NotFound,
    #[error("provider operation conflicts with existing state")]
    Conflict,
    #[error("provider capacity is unavailable")]
    Capacity,
    #[error("provider returned a retryable failure")]
    Retryable,
    #[error("provider outcome is unknown; observe operation {operation_id}")]
    UnknownOutcome { operation_id: Uuid },
    #[error("provider returned a terminal failure")]
    Terminal,
    #[error("provider state is unavailable")]
    StaleState,
    #[error("provider fake storage is unavailable")]
    Storage,
    #[error("provider does not support block-device attachment for this connector")]
    UnsupportedBlockDevice(String),
}

impl ProviderError {
    /// Whether the error leaves the provider-side outcome unknown (timeout,
    /// transport, or stale observation). The caller must observe the provider
    /// before retrying or compensating.
    #[must_use]
    pub fn is_unknown_outcome(&self) -> bool {
        matches!(
            self,
            ProviderError::UnknownOutcome { .. }
                | ProviderError::Retryable
                | ProviderError::StaleState
        )
    }

    #[must_use]
    pub fn category(&self) -> ErrorCategory {
        match self {
            Self::InvalidRequest => ErrorCategory::InvalidRequest,
            Self::NotFound => ErrorCategory::NotFound,
            Self::Conflict => ErrorCategory::Conflict,
            Self::Capacity => ErrorCategory::Capacity,
            Self::Retryable => ErrorCategory::Retryable,
            Self::UnknownOutcome { .. } => ErrorCategory::UnknownOutcome,
            Self::Terminal | Self::StaleState | Self::Storage => ErrorCategory::Terminal,
            Self::UnsupportedBlockDevice(_) => ErrorCategory::InvalidRequest,
        }
    }
}

#[async_trait]
pub trait ComputeProvider: Send + Sync {
    async fn capabilities(&self) -> Result<Capabilities, ProviderError>;
    async fn create_instance(
        &self,
        request: CreateInstanceRequest,
    ) -> Result<Operation, ProviderError>;
    async fn get_instance(&self, provider_instance_id: &str) -> Result<Instance, ProviderError>;
    /// Performs a read-only provider inspection. Providers that do not have
    /// an asynchronous host command may satisfy this from their projection;
    /// agent-backed providers override it to dispatch an Inspect command.
    async fn inspect_instance(
        &self,
        _provider_id: &str,
        _resource_id: &str,
        provider_instance_id: &str,
        operation_id: Uuid,
        _idempotency_key: &str,
    ) -> Result<Operation, ProviderError> {
        let instance = self.get_instance(provider_instance_id).await?;
        Ok(Operation {
            provider_operation_id: operation_id,
            o3k_operation_id: operation_id,
            state: OperationState::Succeeded,
            error_category: None,
            provider_resource_id: Some(instance.provider_instance_id),
        })
    }
    async fn delete_instance(
        &self,
        request: DeleteInstanceRequest,
    ) -> Result<Operation, ProviderError>;
    async fn action_instance(
        &self,
        provider_instance_id: &str,
        action: InstanceAction,
        operation_id: Uuid,
        idempotency_key: &str,
    ) -> Result<Operation, ProviderError>;
    async fn get_operation(&self, provider_operation_id: Uuid) -> Result<Operation, ProviderError>;
    /// Collects the compute connector description for the given server.
    async fn collect_connector(&self, _resource_id: Uuid) -> Result<ConnectorInfo, ProviderError> {
        Err(ProviderError::UnsupportedBlockDevice(
            "connector collection".to_owned(),
        ))
    }
    /// Attaches a block device to the given server through the compute
    /// execution boundary.
    async fn attach_block_device(
        &self,
        _resource_id: Uuid,
        _device: &BlockDeviceAttachment,
    ) -> Result<BlockDeviceObservation, ProviderError> {
        Err(ProviderError::UnsupportedBlockDevice(
            "block-device attachment".to_owned(),
        ))
    }
    /// Detaches a block device from the given server.
    async fn detach_block_device(
        &self,
        _resource_id: Uuid,
        _device: &BlockDeviceAttachment,
    ) -> Result<BlockDeviceObservation, ProviderError> {
        Err(ProviderError::UnsupportedBlockDevice(
            "block-device detach".to_owned(),
        ))
    }
    /// Observes whether a block device is currently attached to the server.
    async fn observe_block_device(
        &self,
        _resource_id: Uuid,
        _volume_id: &str,
    ) -> Result<Option<BlockDeviceObservation>, ProviderError> {
        Err(ProviderError::UnsupportedBlockDevice(
            "block-device observation".to_owned(),
        ))
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum FailureInjection {
    None,
    Transient,
    Terminal,
    Timeout,
    StaleState,
    PartialCompletion,
    /// The presence inspection dispatches but stays accepted (in-flight),
    /// so the poll path can be driven without a provider wrapper.
    InspectAccepted,
    /// The first create dispatch behaves normally; every later create
    /// dispatch fails terminally (a re-drive rejection), so the drive's
    /// terminal-failure projection can be tested without a provider wrapper.
    TerminalOnRedrive,
    /// A delete is accepted without changing provider state, modelling the
    /// stale-accepted window from #575 where the original command may have
    /// been lost after acceptance.
    StaleAccepted,
}

#[derive(Clone)]
pub struct FakeComputeProvider {
    inner: Arc<Mutex<FakeState>>,
}

struct FakeState {
    failure: FailureInjection,
    capabilities: Capabilities,
    instances: HashMap<String, Instance>,
    operations: HashMap<Uuid, Operation>,
    idempotency: HashMap<String, (Uuid, String)>,
    block_devices: HashMap<(String, String), BlockDeviceObservation>,
    last_attached_device: Option<BlockDeviceAttachment>,
    last_create_request: Option<CreateInstanceRequest>,
    create_calls: usize,
    inspect_dispatches: usize,
    last_inspect_provider_instance_id: Option<String>,
}

impl Default for FakeComputeProvider {
    fn default() -> Self {
        Self::new()
    }
}

impl FakeComputeProvider {
    #[must_use]
    pub fn new() -> Self {
        Self {
            inner: Arc::new(Mutex::new(FakeState {
                failure: FailureInjection::None,
                capabilities: Capabilities {
                    provider_name: "o3k-fake".to_owned(),
                    provider_version: "0.1".to_owned(),
                    capabilities: vec![
                        "compute.instance.create".to_owned(),
                        "compute.instance.get".to_owned(),
                        "compute.instance.delete".to_owned(),
                    ],
                },
                instances: HashMap::new(),
                operations: HashMap::new(),
                idempotency: HashMap::new(),
                block_devices: HashMap::new(),
                last_attached_device: None,
                last_create_request: None,
                create_calls: 0,
                inspect_dispatches: 0,
                last_inspect_provider_instance_id: None,
            })),
        }
    }

    pub fn set_failure(&self, failure: FailureInjection) -> Result<(), ProviderError> {
        self.inner
            .lock()
            .map(|mut state| state.failure = failure)
            .map_err(|_| ProviderError::Storage)
    }

    /// Advance a recorded provider operation for deterministic recovery tests.
    ///
    /// A real provider may report an operation as still running after the
    /// original transport response was lost. The fake exposes that transition
    /// without pretending to inject a process or host failure.
    pub fn set_operation_state(
        &self,
        operation_id: Uuid,
        operation_state: OperationState,
    ) -> Result<(), ProviderError> {
        self.inner
            .lock()
            .map_err(|_| ProviderError::Storage)?
            .operations
            .get_mut(&operation_id)
            .map(|operation| {
                operation.state = operation_state;
                operation.error_category = (operation_state == OperationState::UnknownOutcome)
                    .then_some(ErrorCategory::UnknownOutcome);
            })
            .ok_or(ProviderError::NotFound)
    }

    /// Clears the provider resource identity of a recorded operation so tests
    /// can model a create whose provider side effect may not exist: the
    /// durable record then carries `UnknownOutcome` without a resource id,
    /// which is exactly the state presence observation must converge.
    pub fn set_operation_provider_resource_id(
        &self,
        operation_id: Uuid,
        provider_resource_id: Option<String>,
    ) -> Result<(), ProviderError> {
        self.inner
            .lock()
            .map_err(|_| ProviderError::Storage)?
            .operations
            .get_mut(&operation_id)
            .map(|operation| operation.provider_resource_id = provider_resource_id)
            .ok_or(ProviderError::NotFound)
    }

    /// Removes a recorded instance so tests can model a create that provably
    /// never took effect (no provider side effect exists to inspect).
    pub fn remove_instance(&self, provider_instance_id: &str) -> Result<(), ProviderError> {
        self.inner
            .lock()
            .map_err(|_| ProviderError::Storage)?
            .instances
            .remove(provider_instance_id)
            .map(|_| ())
            .ok_or(ProviderError::NotFound)
    }

    #[must_use]
    pub fn instance_count(&self) -> usize {
        self.inner
            .lock()
            .map(|state| state.instances.len())
            .unwrap_or_default()
    }

    /// The provider-side instance identities currently materialized by this
    /// fake. Test-support accessor: it lets a process-boundary test assert that
    /// independent runtimes converge on one deterministic provider identity
    /// (`fake-<server id>`) instead of minting competing provider resources.
    #[must_use]
    pub fn instance_ids(&self) -> Vec<String> {
        self.inner
            .lock()
            .map(|state| state.instances.keys().cloned().collect())
            .unwrap_or_default()
    }

    /// Returns the latest create request for boundary tests. The request is
    /// retained only by the in-memory fake and is never logged or serialized.
    #[must_use]
    pub fn last_create_request(&self) -> Option<CreateInstanceRequest> {
        self.inner
            .lock()
            .ok()
            .and_then(|state| state.last_create_request.clone())
    }

    /// The most recent block-device attachment dispatched to the compute
    /// boundary (used by tests to prove CHAP credentials arrive at the
    /// execution boundary without ever being logged).
    #[must_use]
    pub fn last_attached_device(&self) -> Option<BlockDeviceAttachment> {
        self.inner
            .lock()
            .map(|state| state.last_attached_device.clone())
            .unwrap_or_default()
    }

    /// The number of presence inspections dispatched to the fake (used by
    /// tests to prove the poll path converges without duplicate dispatch).
    #[must_use]
    pub fn inspect_dispatch_count(&self) -> usize {
        self.inner
            .lock()
            .map(|state| state.inspect_dispatches)
            .unwrap_or_default()
    }

    /// The provider instance identity the last presence inspection carried
    /// (used by tests to prove a known provider reference is passed through
    /// instead of an empty id).
    #[must_use]
    pub fn last_inspect_provider_instance_id(&self) -> Option<String> {
        self.inner
            .lock()
            .ok()
            .and_then(|state| state.last_inspect_provider_instance_id.clone())
    }

    #[must_use]
    pub fn attached_volume_count(&self, resource_id: Uuid) -> usize {
        self.inner
            .lock()
            .map(|state| {
                state
                    .block_devices
                    .iter()
                    .filter(|((resource, _), observation)| {
                        *resource == resource_id.to_string() && observation.attached
                    })
                    .count()
            })
            .unwrap_or_default()
    }

    fn lock(&self) -> Result<std::sync::MutexGuard<'_, FakeState>, ProviderError> {
        self.inner.lock().map_err(|_| ProviderError::Storage)
    }

    fn operation(
        state: &mut FakeState,
        request: Uuid,
        state_value: OperationState,
        category: Option<ErrorCategory>,
        provider_resource_id: Option<String>,
    ) -> Operation {
        let operation = Operation {
            provider_operation_id: Uuid::now_v7(),
            o3k_operation_id: request,
            state: state_value,
            error_category: category,
            provider_resource_id,
        };
        state
            .operations
            .insert(operation.provider_operation_id, operation.clone());
        operation
    }

    fn create_fingerprint(request: &CreateInstanceRequest) -> String {
        format!(
            "{}:{}:{}:{}:{}:{:?}:{:?}:{:?}:{:?}:{:?}",
            request.o3k_server_id,
            request.project_id,
            request.name,
            request.vcpus,
            request.memory_mib,
            request.image_id,
            request.network_ids,
            request.placement_provider_id,
            request.placement_allocation_id,
            request.config_drive
        )
    }

    fn delete_fingerprint(request: &DeleteInstanceRequest) -> String {
        request.provider_instance_id.clone()
    }

    fn action_fingerprint(provider_instance_id: &str, action: InstanceAction) -> String {
        format!("{provider_instance_id}:{action:?}")
    }
}

#[async_trait]
impl ComputeProvider for FakeComputeProvider {
    async fn capabilities(&self) -> Result<Capabilities, ProviderError> {
        Ok(self.lock()?.capabilities.clone())
    }

    async fn create_instance(
        &self,
        request: CreateInstanceRequest,
    ) -> Result<Operation, ProviderError> {
        let mut state = self.lock()?;
        state.create_calls += 1;
        state.last_create_request = Some(request.clone());
        if matches!(state.failure, FailureInjection::TerminalOnRedrive) && state.create_calls > 1 {
            return Err(ProviderError::Terminal);
        }
        let fingerprint = Self::create_fingerprint(&request);
        // Scope the fake's client-idempotency ledger by project. The default
        // client idempotency key for a server create is the display name,
        // which legitimately repeats across projects; without the scope prefix
        // two projects creating a same-named server would alias on the shared
        // fake provider ledger and surface a false cross-project Conflict
        // (observed for Project A and B both creating "p13-shared-server").
        let ledger_key = format!("create:{}:{}", request.project_id, request.idempotency_key);
        if let Some((operation_id, original)) = state.idempotency.get(&ledger_key) {
            if original != &fingerprint {
                return Err(ProviderError::Conflict);
            }
            return state
                .operations
                .get(operation_id)
                .cloned()
                .ok_or(ProviderError::Storage);
        }
        if request.name.trim().is_empty()
            || request.vcpus == 0
            || request.memory_mib == 0
            || request.idempotency_key.trim().is_empty()
        {
            return Err(ProviderError::InvalidRequest);
        }
        match state.failure {
            FailureInjection::Transient => return Err(ProviderError::Retryable),
            FailureInjection::Terminal => return Err(ProviderError::Terminal),
            FailureInjection::StaleState => return Err(ProviderError::StaleState),
            _ => {}
        }
        // Deterministic per-request provider identity: concurrent creates of
        // the same server converge on one provider id, so the loser's
        // observation matches the winner's attached provider reference
        // instead of racing it (create_race_releases_placement_not_owned_by_
        // winner flaked with ProviderReferenceAlreadyExists because a fresh
        // now_v7 id was minted per call). The idempotency ledger still
        // guards duplicate executions.
        let provider_id = format!("fake-{}", request.o3k_server_id);
        let instance = Instance {
            provider_instance_id: provider_id.clone(),
            o3k_server_id: request.o3k_server_id,
            state: if state.failure == FailureInjection::PartialCompletion {
                InstanceState::Creating
            } else {
                InstanceState::Running
            },
            observed_message: None,
        };
        state.instances.insert(provider_id.clone(), instance);
        let operation_state = match state.failure {
            FailureInjection::Timeout => OperationState::UnknownOutcome,
            FailureInjection::PartialCompletion => OperationState::Running,
            _ => OperationState::Succeeded,
        };
        let operation = Self::operation(
            &mut state,
            request.operation_id,
            operation_state,
            (operation_state == OperationState::UnknownOutcome)
                .then_some(ErrorCategory::UnknownOutcome),
            Some(provider_id),
        );
        state
            .idempotency
            .insert(ledger_key, (operation.provider_operation_id, fingerprint));
        if operation_state == OperationState::UnknownOutcome {
            return Err(ProviderError::UnknownOutcome {
                operation_id: operation.provider_operation_id,
            });
        }
        Ok(operation)
    }

    async fn get_instance(&self, provider_instance_id: &str) -> Result<Instance, ProviderError> {
        let mut state = self.lock()?;
        if state.failure == FailureInjection::StaleState {
            return Err(ProviderError::StaleState);
        }
        if state.failure == FailureInjection::None
            && let Some(instance) = state.instances.get_mut(provider_instance_id)
            && instance.state == InstanceState::Creating
        {
            instance.state = InstanceState::Running;
        }
        state
            .instances
            .get(provider_instance_id)
            .cloned()
            .ok_or(ProviderError::NotFound)
    }

    async fn inspect_instance(
        &self,
        _provider_id: &str,
        resource_id: &str,
        provider_instance_id: &str,
        operation_id: Uuid,
        idempotency_key: &str,
    ) -> Result<Operation, ProviderError> {
        if idempotency_key.trim().is_empty() {
            return Err(ProviderError::InvalidRequest);
        }
        let mut state = self.lock()?;
        state.inspect_dispatches += 1;
        state.last_inspect_provider_instance_id = Some(provider_instance_id.to_owned());
        if state.failure == FailureInjection::InspectAccepted {
            return Ok(Operation {
                provider_operation_id: operation_id,
                o3k_operation_id: operation_id,
                state: OperationState::Accepted,
                error_category: None,
                provider_resource_id: None,
            });
        }
        if state.failure == FailureInjection::Timeout {
            // Dispatch transport loss: the inspection outcome itself is
            // unknown and must not be projected as absence.
            return Err(ProviderError::UnknownOutcome { operation_id });
        }
        // Presence by durable identity when the provider resource id is not
        // yet known (a create in UnknownOutcome with no recorded instance),
        // mirroring the agent's Inspect command keyed on the O3K server id.
        let instance = if provider_instance_id.is_empty() {
            state
                .instances
                .values()
                .find(|instance| instance.o3k_server_id.to_string() == resource_id)
                .cloned()
        } else {
            state.instances.get(provider_instance_id).cloned()
        };
        match instance {
            Some(instance) => Ok(Operation {
                provider_operation_id: operation_id,
                o3k_operation_id: operation_id,
                state: OperationState::Succeeded,
                error_category: None,
                provider_resource_id: Some(instance.provider_instance_id),
            }),
            // An absent owned instance is a terminal classified result (the
            // real executor reports Failed/NotFound the same way), never a
            // transport error.
            None => Ok(Operation {
                provider_operation_id: operation_id,
                o3k_operation_id: operation_id,
                state: OperationState::Failed,
                error_category: Some(ErrorCategory::NotFound),
                provider_resource_id: None,
            }),
        }
    }

    async fn delete_instance(
        &self,
        request: DeleteInstanceRequest,
    ) -> Result<Operation, ProviderError> {
        let mut state = self.lock()?;
        let fingerprint = Self::delete_fingerprint(&request);
        if let Some((operation_id, original)) = state.idempotency.get(&request.idempotency_key) {
            if original != &fingerprint {
                return Err(ProviderError::Conflict);
            }
            return state
                .operations
                .get(operation_id)
                .cloned()
                .ok_or(ProviderError::Storage);
        }
        let absent = !state.instances.contains_key(&request.provider_instance_id);
        if absent {
            let operation = Self::operation(
                &mut state,
                request.operation_id,
                OperationState::Succeeded,
                None,
                None,
            );
            state.idempotency.insert(
                request.idempotency_key,
                (operation.provider_operation_id, fingerprint),
            );
            return Ok(operation);
        }
        match state.failure {
            FailureInjection::Transient => return Err(ProviderError::Retryable),
            FailureInjection::Terminal => return Err(ProviderError::Terminal),
            FailureInjection::StaleState => return Err(ProviderError::StaleState),
            FailureInjection::StaleAccepted => {
                let operation = Self::operation(
                    &mut state,
                    request.operation_id,
                    OperationState::Accepted,
                    None,
                    Some(request.provider_instance_id.clone()),
                );
                state.idempotency.insert(
                    request.idempotency_key,
                    (operation.provider_operation_id, fingerprint),
                );
                return Ok(operation);
            }
            _ => {}
        }
        state.instances.remove(&request.provider_instance_id);
        let operation_state = if state.failure == FailureInjection::Timeout {
            OperationState::UnknownOutcome
        } else {
            OperationState::Succeeded
        };
        let operation = Self::operation(
            &mut state,
            request.operation_id,
            operation_state,
            (operation_state == OperationState::UnknownOutcome)
                .then_some(ErrorCategory::UnknownOutcome),
            None,
        );
        state.idempotency.insert(
            request.idempotency_key,
            (operation.provider_operation_id, fingerprint),
        );
        if operation_state == OperationState::UnknownOutcome {
            return Err(ProviderError::UnknownOutcome {
                operation_id: operation.provider_operation_id,
            });
        }
        Ok(operation)
    }

    async fn action_instance(
        &self,
        provider_instance_id: &str,
        action: InstanceAction,
        operation_id: Uuid,
        idempotency_key: &str,
    ) -> Result<Operation, ProviderError> {
        let mut state = self.lock()?;
        if idempotency_key.trim().is_empty() {
            return Err(ProviderError::InvalidRequest);
        }
        let idempotency_key = format!("action:{idempotency_key}");
        let fingerprint = Self::action_fingerprint(provider_instance_id, action);
        if let Some((operation_id, original)) = state.idempotency.get(&idempotency_key) {
            if original != &fingerprint {
                return Err(ProviderError::Conflict);
            }
            return state
                .operations
                .get(operation_id)
                .cloned()
                .ok_or(ProviderError::Storage);
        }
        match state.failure {
            FailureInjection::Transient => return Err(ProviderError::Retryable),
            FailureInjection::Terminal => return Err(ProviderError::Terminal),
            FailureInjection::StaleState => return Err(ProviderError::StaleState),
            _ => {}
        }
        let current = state
            .instances
            .get(provider_instance_id)
            .ok_or(ProviderError::NotFound)?
            .state;
        let next = match (action, current) {
            (InstanceAction::Start, InstanceState::Stopped) => InstanceState::Running,
            (InstanceAction::Stop, InstanceState::Running) => InstanceState::Stopped,
            (InstanceAction::Reboot, InstanceState::Running | InstanceState::Stopped) => {
                InstanceState::Running
            }
            _ => return Err(ProviderError::Conflict),
        };
        let instance = state
            .instances
            .get_mut(provider_instance_id)
            .ok_or(ProviderError::NotFound)?;
        instance.state = next;
        let operation_state = if state.failure == FailureInjection::Timeout {
            OperationState::UnknownOutcome
        } else {
            OperationState::Succeeded
        };
        let operation = Self::operation(
            &mut state,
            operation_id,
            operation_state,
            (operation_state == OperationState::UnknownOutcome)
                .then_some(ErrorCategory::UnknownOutcome),
            None,
        );
        state.idempotency.insert(
            idempotency_key,
            (operation.provider_operation_id, fingerprint),
        );
        if operation.state == OperationState::UnknownOutcome {
            return Err(ProviderError::UnknownOutcome {
                operation_id: operation.provider_operation_id,
            });
        }
        Ok(operation)
    }

    async fn get_operation(&self, provider_operation_id: Uuid) -> Result<Operation, ProviderError> {
        self.lock()?
            .operations
            .get(&provider_operation_id)
            .cloned()
            .ok_or(ProviderError::NotFound)
    }

    async fn collect_connector(&self, resource_id: Uuid) -> Result<ConnectorInfo, ProviderError> {
        match self.lock()?.failure {
            FailureInjection::Terminal => return Err(ProviderError::Terminal),
            FailureInjection::Transient => return Err(ProviderError::Retryable),
            _ => {}
        }
        let _ = resource_id;
        Ok(ConnectorInfo {
            host: "fake-compute-host".to_owned(),
            ip: "10.0.0.5".to_owned(),
            platform: "x86_64".to_owned(),
            os_type: "linux".to_owned(),
            multipath: false,
            initiator: Some("iqn.1993-08.org.debian:01:o3k-fake".to_owned()),
        })
    }

    async fn attach_block_device(
        &self,
        resource_id: Uuid,
        device: &BlockDeviceAttachment,
    ) -> Result<BlockDeviceObservation, ProviderError> {
        let mut state = self.lock()?;
        match state.failure {
            FailureInjection::Terminal => return Err(ProviderError::Terminal),
            FailureInjection::Transient => return Err(ProviderError::Retryable),
            FailureInjection::StaleState => return Err(ProviderError::StaleState),
            _ => {}
        }
        if device.driver_volume_type != "iscsi" && device.driver_volume_type != "local" {
            return Err(ProviderError::UnsupportedBlockDevice(format!(
                "unsupported driver_volume_type {}",
                device.driver_volume_type
            )));
        }
        let key = (resource_id.to_string(), device.volume_id.clone());
        state.last_attached_device = Some(device.clone());
        // Idempotent: an already-attached device is returned unchanged.
        if let Some(existing) = state.block_devices.get(&key)
            && existing.attached
        {
            return Ok(existing.clone());
        }
        let host_path = if device.driver_volume_type == "iscsi" {
            Some(format!(
                "/dev/sd{}",
                ["b", "c", "d", "e"][device.target_lun.unwrap_or(0) as usize % 4]
            ))
        } else {
            device.local_path.clone()
        };
        let observation = BlockDeviceObservation {
            volume_id: device.volume_id.clone(),
            attachment_id: device.attachment_id.clone(),
            driver_volume_type: device.driver_volume_type.clone(),
            device_path: device.device_path.clone(),
            host_path,
            attached: true,
            found: true,
            initiator: None,
            host_name: None,
            ip_address: None,
            iscsi_logged_in: false,
        };
        state.block_devices.insert(key, observation.clone());
        Ok(observation)
    }

    async fn detach_block_device(
        &self,
        resource_id: Uuid,
        device: &BlockDeviceAttachment,
    ) -> Result<BlockDeviceObservation, ProviderError> {
        let mut state = self.lock()?;
        match state.failure {
            FailureInjection::Terminal => return Err(ProviderError::Terminal),
            FailureInjection::Transient => return Err(ProviderError::Retryable),
            _ => {}
        }
        let key = (resource_id.to_string(), device.volume_id.clone());
        // Repeated detach is idempotent and succeeds with a not-found marker.
        let observation = match state.block_devices.get(&key) {
            Some(existing) => BlockDeviceObservation {
                volume_id: device.volume_id.clone(),
                attachment_id: device.attachment_id.clone(),
                driver_volume_type: device.driver_volume_type.clone(),
                device_path: existing.device_path.clone(),
                host_path: existing.host_path.clone(),
                attached: false,
                found: false,
                initiator: None,
                host_name: None,
                ip_address: None,
                iscsi_logged_in: false,
            },
            None => BlockDeviceObservation {
                volume_id: device.volume_id.clone(),
                attachment_id: device.attachment_id.clone(),
                driver_volume_type: device.driver_volume_type.clone(),
                device_path: device.device_path.clone(),
                host_path: None,
                attached: false,
                found: false,
                initiator: None,
                host_name: None,
                ip_address: None,
                iscsi_logged_in: false,
            },
        };
        state.block_devices.remove(&key);
        Ok(observation)
    }

    async fn observe_block_device(
        &self,
        resource_id: Uuid,
        volume_id: &str,
    ) -> Result<Option<BlockDeviceObservation>, ProviderError> {
        Ok(self
            .lock()?
            .block_devices
            .get(&(resource_id.to_string(), volume_id.to_owned()))
            .cloned())
    }
}

pub async fn run_compute_conformance(provider: &dyn ComputeProvider) -> Result<(), ProviderError> {
    let capabilities = provider.capabilities().await?;
    if !capabilities
        .capabilities
        .iter()
        .any(|value| value == "compute.instance.create")
    {
        return Err(ProviderError::InvalidRequest);
    }
    let request = CreateInstanceRequest {
        operation_id: Uuid::now_v7(),
        o3k_server_id: Uuid::now_v7(),
        project_id: "conformance-project".to_owned(),
        name: "conformance".to_owned(),
        vcpus: 1,
        memory_mib: 128,
        flavor_id: String::new(),
        disk_gib: 0,
        image_id: None,
        key_name: None,
        keypair_id: None,
        network_ids: Vec::new(),
        placement_provider_id: None,
        placement_allocation_id: None,
        config_drive: None,
        idempotency_key: format!("conformance-{}", Uuid::now_v7()),
    };
    let operation = provider.create_instance(request.clone()).await?;
    let observed = provider
        .get_operation(operation.provider_operation_id)
        .await?;
    if observed.state != OperationState::Succeeded {
        return Err(ProviderError::InvalidRequest);
    }
    Ok(())
}

pub async fn run_conformance<P: ComputeProvider>(provider: &P) -> Result<(), ProviderError> {
    run_compute_conformance(provider).await
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn provider_observations_project_to_canonical_server_states() {
        let expected = [
            (InstanceState::Creating, o3k_domain::ServerState::Building),
            (InstanceState::Running, o3k_domain::ServerState::Active),
            (InstanceState::Stopped, o3k_domain::ServerState::Stopped),
            (InstanceState::Deleting, o3k_domain::ServerState::Deleting),
            (InstanceState::Deleted, o3k_domain::ServerState::Deleted),
            (InstanceState::Error, o3k_domain::ServerState::Error),
        ];
        assert_eq!(expected.len(), 6);
        for (observation, canonical) in expected {
            assert_eq!(
                o3k_domain::ServerState::from(observation),
                canonical,
                "{observation:?} must project to {canonical:?}"
            );
        }
    }

    fn request(key: &str) -> CreateInstanceRequest {
        CreateInstanceRequest {
            operation_id: Uuid::now_v7(),
            o3k_server_id: Uuid::now_v7(),
            project_id: "project".to_owned(),
            name: "test".to_owned(),
            vcpus: 1,
            memory_mib: 128,
            flavor_id: String::new(),
            disk_gib: 0,
            image_id: None,
            key_name: None,
            keypair_id: None,
            network_ids: Vec::new(),
            placement_provider_id: None,
            placement_allocation_id: None,
            config_drive: None,
            idempotency_key: key.to_owned(),
        }
    }

    #[tokio::test]
    async fn duplicate_create_is_idempotent_and_delete_is_absent_safe() -> Result<(), ProviderError>
    {
        let provider = FakeComputeProvider::new();
        let create = request("same");
        let first = provider.create_instance(create.clone()).await?;
        let second = provider.create_instance(create).await?;
        assert_eq!(first, second);
        assert_eq!(provider.instance_count(), 1);
        let deleted = provider
            .delete_instance(DeleteInstanceRequest {
                operation_id: Uuid::now_v7(),
                provider_instance_id: "missing".to_owned(),
                idempotency_key: "delete-missing".to_owned(),
            })
            .await?;
        assert_eq!(deleted.state, OperationState::Succeeded);
        Ok(())
    }

    #[tokio::test]
    async fn same_client_key_across_projects_does_not_alias() -> Result<(), ProviderError> {
        // P13.6 scope-bound idempotency regression: a server create uses the
        // display name as its client idempotency key by default, and the name
        // legitimately repeats across projects. The fake provider's idempotency
        // ledger must be project-scoped so two projects creating a same-named
        // server converge independently instead of surfacing a false Conflict.
        let provider = FakeComputeProvider::new();
        let project_a = {
            let mut request = request("p13-shared-server");
            request.project_id = "project-a".to_owned();
            request
        };
        let project_b = {
            let mut request = request("p13-shared-server");
            request.project_id = "project-b".to_owned();
            request
        };
        let a = provider.create_instance(project_a.clone()).await?;
        let b = provider.create_instance(project_b).await?;
        assert_eq!(a.state, OperationState::Succeeded);
        assert_eq!(b.state, OperationState::Succeeded);
        assert_ne!(
            a.provider_resource_id, b.provider_resource_id,
            "distinct projects must get distinct provider realizations"
        );
        assert_eq!(provider.instance_count(), 2);
        // Within one project an equivalent replay still converges (idempotent).
        let replay_a = provider.create_instance(project_a).await?;
        assert_eq!(replay_a, a);
        Ok(())
    }

    #[tokio::test]
    async fn config_drive_changes_idempotency_fingerprint() -> Result<(), ProviderError> {
        let provider = FakeComputeProvider::new();
        let create = request("config-drive");
        provider.create_instance(create.clone()).await?;
        let mut changed = create;
        changed.config_drive = Some(ConfigDriveRequest {
            user_data: b"#cloud-config\n".to_vec(),
            vendor_data: None,
            ssh_public_key: "ssh-ed25519 AAAA test".to_owned(),
        });
        assert_eq!(
            provider.create_instance(changed).await,
            Err(ProviderError::Conflict)
        );
        Ok(())
    }

    #[tokio::test]
    async fn read_retry_is_side_effect_free() -> Result<(), ProviderError> {
        let provider = FakeComputeProvider::new();
        let created = provider.create_instance(request("read-only")).await?;
        let id = created.provider_resource_id.ok_or(ProviderError::Storage)?;
        let before = provider.lock()?.operations.len();
        let first = provider.get_instance(&id).await?;
        let second = provider.get_instance(&id).await?;
        assert_eq!(first, second);
        assert_eq!(provider.lock()?.operations.len(), before);
        assert_eq!(provider.instance_count(), 1);
        Ok(())
    }

    #[tokio::test]
    async fn rejected_update_can_be_retried_once() -> Result<(), ProviderError> {
        let provider = FakeComputeProvider::new();
        let created = provider
            .create_instance(request("update-before-commit"))
            .await?;
        let id = created.provider_resource_id.ok_or(ProviderError::Storage)?;
        provider.set_failure(FailureInjection::Transient)?;
        assert_eq!(
            provider
                .action_instance(
                    &id,
                    InstanceAction::Stop,
                    Uuid::now_v7(),
                    "update-before-commit"
                )
                .await,
            Err(ProviderError::Retryable)
        );
        assert_eq!(
            provider.get_instance(&id).await?.state,
            InstanceState::Running
        );
        provider.set_failure(FailureInjection::None)?;
        let operation = provider
            .action_instance(
                &id,
                InstanceAction::Stop,
                Uuid::now_v7(),
                "update-before-commit",
            )
            .await?;
        assert_eq!(operation.state, OperationState::Succeeded);
        assert_eq!(
            provider.get_instance(&id).await?.state,
            InstanceState::Stopped
        );
        Ok(())
    }

    #[tokio::test]
    async fn committed_update_response_loss_replays_same_operation() -> Result<(), ProviderError> {
        let provider = FakeComputeProvider::new();
        let created = provider
            .create_instance(request("update-response-loss"))
            .await?;
        let id = created.provider_resource_id.ok_or(ProviderError::Storage)?;
        provider.set_failure(FailureInjection::Timeout)?;
        let operation_id = match provider
            .action_instance(
                &id,
                InstanceAction::Stop,
                Uuid::now_v7(),
                "update-response-loss",
            )
            .await
        {
            Err(ProviderError::UnknownOutcome { operation_id }) => operation_id,
            _ => return Err(ProviderError::InvalidRequest),
        };
        assert_eq!(
            provider.get_instance(&id).await?.state,
            InstanceState::Stopped
        );
        provider.set_failure(FailureInjection::None)?;
        let replay = provider
            .action_instance(
                &id,
                InstanceAction::Stop,
                Uuid::now_v7(),
                "update-response-loss",
            )
            .await?;
        assert_eq!(replay.provider_operation_id, operation_id);
        assert_eq!(
            provider.get_instance(&id).await?.state,
            InstanceState::Stopped
        );
        Ok(())
    }

    #[tokio::test]
    async fn committed_delete_response_loss_replays_to_absence() -> Result<(), ProviderError> {
        let provider = FakeComputeProvider::new();
        let created = provider
            .create_instance(request("delete-response-loss"))
            .await?;
        let id = created.provider_resource_id.ok_or(ProviderError::Storage)?;
        provider.set_failure(FailureInjection::Timeout)?;
        let operation_id = match provider
            .delete_instance(DeleteInstanceRequest {
                operation_id: Uuid::now_v7(),
                provider_instance_id: id.clone(),
                idempotency_key: "delete-response-loss-operation".to_owned(),
            })
            .await
        {
            Err(ProviderError::UnknownOutcome { operation_id }) => operation_id,
            _ => return Err(ProviderError::InvalidRequest),
        };
        assert_eq!(provider.instance_count(), 0);
        provider.set_failure(FailureInjection::None)?;
        let replay = provider
            .delete_instance(DeleteInstanceRequest {
                operation_id: Uuid::now_v7(),
                provider_instance_id: id.clone(),
                idempotency_key: "delete-response-loss-operation".to_owned(),
            })
            .await?;
        assert_eq!(replay.provider_operation_id, operation_id);
        assert_eq!(
            provider.get_instance(&id).await,
            Err(ProviderError::NotFound)
        );
        Ok(())
    }

    #[test]
    fn disabled_config_drive_is_omitted_and_legacy_json_defaults_to_none()
    -> Result<(), serde_json::Error> {
        let request = request("serde-config-drive");
        let encoded = serde_json::to_value(&request)?;
        assert!(encoded.get("config_drive").is_none());
        let decoded: CreateInstanceRequest = serde_json::from_value(encoded)?;
        assert_eq!(decoded.config_drive, None);
        Ok(())
    }

    #[tokio::test]
    async fn timeout_is_observable_after_unknown_result() -> Result<(), ProviderError> {
        let provider = FakeComputeProvider::new();
        provider.set_failure(FailureInjection::Timeout)?;
        let error = match provider.create_instance(request("timeout")).await {
            Ok(_) => return Err(ProviderError::InvalidRequest),
            Err(error) => error,
        };
        let ProviderError::UnknownOutcome { operation_id } = error else {
            return Err(ProviderError::InvalidRequest);
        };
        assert_eq!(
            provider.get_operation(operation_id).await?.state,
            OperationState::UnknownOutcome
        );
        assert_eq!(provider.instance_count(), 1);
        Ok(())
    }

    #[tokio::test]
    async fn partial_create_is_running_and_converges_without_duplicate_instance()
    -> Result<(), ProviderError> {
        let provider = FakeComputeProvider::new();
        provider.set_failure(FailureInjection::PartialCompletion)?;
        let create = request("partial");
        let operation = provider.create_instance(create.clone()).await?;
        assert_eq!(operation.state, OperationState::Running);
        let provider_id = operation
            .provider_resource_id
            .clone()
            .ok_or(ProviderError::Storage)?;
        assert_eq!(
            provider.get_instance(&provider_id).await?.state,
            InstanceState::Creating
        );
        provider.set_failure(FailureInjection::None)?;
        assert_eq!(
            provider.get_instance(&provider_id).await?.state,
            InstanceState::Running
        );
        assert_eq!(provider.create_instance(create).await?, operation);
        assert_eq!(provider.instance_count(), 1);
        Ok(())
    }

    #[tokio::test]
    async fn timeout_action_replays_same_operation_without_repeating_mutation()
    -> Result<(), ProviderError> {
        let provider = FakeComputeProvider::new();
        let created = provider.create_instance(request("create-action")).await?;
        let provider_instance_id = created.provider_resource_id.ok_or(ProviderError::Storage)?;
        provider.set_failure(FailureInjection::Timeout)?;
        let first_error = match provider
            .action_instance(
                &provider_instance_id,
                InstanceAction::Stop,
                Uuid::now_v7(),
                "stop-action",
            )
            .await
        {
            Ok(_) => return Err(ProviderError::InvalidRequest),
            Err(error) => error,
        };
        let ProviderError::UnknownOutcome { operation_id } = first_error else {
            return Err(ProviderError::InvalidRequest);
        };
        assert_eq!(
            provider.get_instance(&provider_instance_id).await?.state,
            InstanceState::Stopped
        );

        let replay = provider
            .action_instance(
                &provider_instance_id,
                InstanceAction::Stop,
                Uuid::now_v7(),
                "stop-action",
            )
            .await?;
        assert_eq!(replay.provider_operation_id, operation_id);
        assert_eq!(replay.state, OperationState::UnknownOutcome);
        assert_eq!(
            provider.get_instance(&provider_instance_id).await?.state,
            InstanceState::Stopped
        );
        Ok(())
    }

    #[tokio::test]
    async fn conformance_suite_runs_against_fake() -> Result<(), ProviderError> {
        run_conformance(&FakeComputeProvider::new()).await
    }
}

#[cfg(test)]
mod block_device_tests {
    use super::*;

    fn attachment() -> BlockDeviceAttachment {
        BlockDeviceAttachment {
            volume_id: "volume-1".to_owned(),
            attachment_id: "attachment-1".to_owned(),
            driver_volume_type: "iscsi".to_owned(),
            target_iqn: Some("iqn.2026-01.example.com:volume-1".to_owned()),
            target_portal: Some("10.0.0.10:3260".to_owned()),
            target_lun: Some(1),
            local_path: None,
            device_path: Some("/dev/vdb".to_owned()),
            multipath: false,
            initiator: Some("iqn.1993-08.org.debian:01:o3k-compute".to_owned()),
            auth_method: Some("CHAP".to_owned()),
            auth_username: Some("chap-user".to_owned()),
            auth_password: Some("chap-password".to_owned()),
        }
    }

    #[tokio::test]
    async fn attach_detach_observe_is_idempotent_and_clean() -> Result<(), ProviderError> {
        let provider = FakeComputeProvider::new();
        let resource_id = Uuid::now_v7();
        let device = attachment();

        let connector = provider.collect_connector(resource_id).await?;
        assert_eq!(connector.host, "fake-compute-host");
        assert!(connector.initiator.is_some());

        let attached = provider.attach_block_device(resource_id, &device).await?;
        assert!(attached.attached);
        assert!(attached.host_path.is_some());

        let again = provider.attach_block_device(resource_id, &device).await?;
        assert!(again.attached);

        let observed = provider
            .observe_block_device(resource_id, "volume-1")
            .await?;
        assert!(observed.is_some_and(|observation| observation.attached));

        let detached = provider.detach_block_device(resource_id, &device).await?;
        assert!(!detached.attached);

        // Repeated detach is idempotent.
        let again = provider.detach_block_device(resource_id, &device).await?;
        assert!(!again.attached);

        let observed = provider
            .observe_block_device(resource_id, "volume-1")
            .await?;
        assert!(observed.is_none());
        Ok(())
    }

    #[tokio::test]
    async fn unsupported_connector_is_rejected_explicitly() -> Result<(), ProviderError> {
        let provider = FakeComputeProvider::new();
        let mut device = attachment();
        device.driver_volume_type = "rbd".to_owned();
        let error = match provider.attach_block_device(Uuid::now_v7(), &device).await {
            Err(error) => error,
            Ok(_) => return Err(ProviderError::Terminal),
        };
        assert!(matches!(error, ProviderError::UnsupportedBlockDevice(_)));
        Ok(())
    }

    #[tokio::test]
    async fn missing_device_observation_returns_none() -> Result<(), ProviderError> {
        let provider = FakeComputeProvider::new();
        let observed = provider
            .observe_block_device(Uuid::now_v7(), "volume-missing")
            .await?;
        assert!(observed.is_none());
        Ok(())
    }
}
