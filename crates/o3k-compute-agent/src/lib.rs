//! Secure registration and liveness runtime for the host-local compute agent,
//! plus the control-plane dispatch adapter that drives agent commands and
//! artifact offers over the authenticated control stream (`provider.rs`).
//!
//! This crate deliberately contains no hypervisor or VM lifecycle code.  It
//! owns the authenticated control stream, node state, bounded reconnect
//! behavior described by SPEC-0015, and the wire-to-application conversion
//! for agent events and command dispatch.

use std::{
    collections::HashMap,
    fs,
    io::{self, Write},
    net::SocketAddr,
    path::{Path, PathBuf},
    pin::Pin,
    sync::{Arc, Mutex},
    time::{Duration, SystemTime, UNIX_EPOCH},
};

use async_trait::async_trait;
use base64::{Engine, engine::general_purpose::STANDARD as BASE64};
use hyper_util::rt::TokioIo;
use o3k_provider::AgentEvent as ProviderAgentEvent;
pub use o3k_provider_contract::compute_proto as proto;
pub use prost::Message;
use rustls::{
    ClientConfig, RootCertStore, ServerConfig,
    pki_types::{
        CertificateDer, PrivateKeyDer, PrivatePkcs1KeyDer, PrivatePkcs8KeyDer, PrivateSec1KeyDer,
        ServerName,
    },
    server::WebPkiClientVerifier,
};
use sha2::{Digest, Sha256};
use tokio::{
    sync::{Notify, RwLock, Semaphore, broadcast, mpsc},
    time,
};
use tokio_rustls::{TlsAcceptor, TlsConnector};
use tokio_stream::{
    StreamExt,
    wrappers::{ReceiverStream, TcpListenerStream},
};
use tonic::{
    Request, Response, Status, Streaming,
    transport::{Endpoint, Server},
};
use tower::service_fn;
use tracing::{info, warn};
use uuid::Uuid;

mod artifact;
mod config_drive;
mod events;
mod image;
mod provider;

pub mod types;
pub use artifact::{
    ArtifactCleanup, ArtifactReceipt, ArtifactStore, ArtifactStoreError, CommittedArtifactQuery,
    MAX_ARTIFACT_BYTES, MAX_ARTIFACT_CHUNK_BYTES, MAX_ARTIFACT_CHUNKS,
};
pub use config_drive::{
    ConfigDriveMaterializationError, ConfigDriveMaterializationRequest,
    config_drive_materialization_request,
};
pub use image::{
    ImageMaterialization, ImageMaterializationRequest, ImageMaterializer, ImageMaterializerError,
    image_materialization_request,
};
pub use provider::AgentComputeProvider;
#[cfg(test)]
pub(crate) use provider::{
    AgentProviderState, apply_agent_provider_event, instance_state_from_observed,
};
pub use types::*;

pub const PROTOCOL_VERSION: proto::ProtocolVersion = proto::ProtocolVersion {
    major: 1,
    minor: 0,
    wire_revision: 1,
};
pub const DEFAULT_HEARTBEAT_INTERVAL: Duration = Duration::from_secs(5);
pub const DEFAULT_LEASE: Duration = Duration::from_secs(15);
const MAX_AGENT_ID: usize = 128;
pub const MAX_MESSAGE_SIZE: usize = 1024 * 1024;
pub const MAX_CONCURRENT_ARTIFACT_TRANSFERS_PER_AGENT: usize = 2;
pub const MAX_IN_FLIGHT_ARTIFACT_CHUNKS_PER_TRANSFER: usize = 4;
const ADMINISTRATIVE_STATE_FILE_EXTENSION: &str = "state";
const COMMAND_JOURNAL_FILE_EXTENSION: &str = "commands";
const COMMAND_JOURNAL_TEMP_EXTENSION: &str = "commands.tmp";
const COMMAND_JOURNAL_MAGIC: &[u8] = b"O3KCMDJ1";
const LEGACY_COMMAND_JOURNAL_VERSION: u8 = 1;
const COMMAND_JOURNAL_VERSION: u8 = 2;
const MAX_COMMAND_JOURNAL_ENTRIES: usize = 4096;
const MAX_COMMAND_JOURNAL_BYTES: usize = 16 * 1024 * 1024;
const MAX_REDACTED_RESULT_BYTES: usize = 4096;
// Keep the journal field within the same hard bound as one authenticated wire
// message. The real connector contains only bounded text, but the journal
// must reject any future expansion instead of allowing unbounded local state.
const MAX_BLOCK_DEVICE_RESULT_BYTES: usize = MAX_MESSAGE_SIZE;
const ARTIFACT_STORE_FILE_EXTENSION: &str = "artifacts";
pub(crate) const ARTIFACT_TRANSFER_CAPABILITY: &str = "artifact_transfer";

/// Derives the stable transfer identity shared by the control-plane journal
/// and the agent-local committed-artifact lookup. The artifact kind is part
/// of the identity so resolver ordering cannot alias image and config-drive
/// transfers.
#[must_use]
pub fn deterministic_artifact_transfer_id(
    command_id: &str,
    kind: proto::ArtifactKind,
    artifact_id: &str,
) -> String {
    let kind = match kind {
        proto::ArtifactKind::ImageBase => "image_base",
        proto::ArtifactKind::ConfigDriveIso => "config_drive_iso",
        proto::ArtifactKind::Unspecified => "unspecified",
    };
    Uuid::new_v5(
        &Uuid::NAMESPACE_URL,
        format!("o3k:artifact-transfer:{command_id}:{kind}:{artifact_id}").as_bytes(),
    )
    .to_string()
}

#[derive(Clone)]
struct AgentConnection {
    epoch: String,
    fencing_token: u64,
    sender: mpsc::Sender<Result<proto::ControlResponse, Status>>,
    renewal_abort: Option<Arc<Notify>>,
}

#[derive(Clone)]
pub struct NodeRegistry {
    nodes: Arc<RwLock<HashMap<String, NodeSnapshot>>>,
    epoch_gates: Arc<RwLock<HashMap<String, Arc<RwLock<()>>>>>,
    authorized_agents: Arc<RwLock<HashMap<String, [u8; 32]>>>,
    connections: Arc<RwLock<HashMap<String, AgentConnection>>>,
    artifact_transfer_slots: Arc<RwLock<HashMap<String, Arc<Semaphore>>>>,
    events: broadcast::Sender<ProviderAgentEvent>,
    /// Optional durable agent-command store used to persist dispatch records
    /// before the agent executes a command. Wired by the composition root when
    /// agent control is enabled; a `None` store keeps the transport primitive
    /// functional without durable record-keeping.
    store: Option<Arc<dyn o3k_store::ComputeRepository>>,
    /// Optional coordination repository and controller identity used to lease
    /// stream ownership across multi-controller deployments.
    coordination: Option<(
        Arc<dyn o3k_store::CoordinationRepository>,
        o3k_store::ControllerId,
        o3k_store::ControllerEpoch,
    )>,
    /// Fired on every successful registration so the inventory publisher can
    /// sync the freshly registered agent's capacity immediately instead of
    /// waiting for its next periodic tick (issue #606).
    registration_notify: Arc<Notify>,
}

struct NodeEpochLease {
    _epoch: tokio::sync::OwnedRwLockReadGuard<()>,
}

impl o3k_provider::AgentEpochLease for NodeEpochLease {}

impl Default for NodeRegistry {
    fn default() -> Self {
        let (events, _) = broadcast::channel(256);
        Self {
            nodes: Arc::new(RwLock::new(HashMap::new())),
            epoch_gates: Arc::new(RwLock::new(HashMap::new())),
            authorized_agents: Arc::new(RwLock::new(HashMap::new())),
            connections: Arc::new(RwLock::new(HashMap::new())),
            artifact_transfer_slots: Arc::new(RwLock::new(HashMap::new())),
            events,
            store: None,
            coordination: None,
            registration_notify: Arc::new(Notify::new()),
        }
    }
}

impl NodeRegistry {
    /// Registers a prepared host from the authenticated bootstrap workflow.
    /// The certificate is authorized before the registry epoch is created;
    /// callers cannot manufacture an execution identity without proving the
    /// certificate binding.
    pub async fn register_prepared(
        &self,
        agent_id: &str,
        agent_epoch: &str,
        certificate: &[u8],
        capabilities: proto::Capabilities,
    ) -> Result<proto::RegisterResponse, AgentError> {
        self.authorize_agent(AuthorizedAgent::new(agent_id, certificate))
            .await?;
        self.register(&proto::RegisterRequest {
            agent_id: agent_id.to_owned(),
            agent_epoch: agent_epoch.to_owned(),
            software_version: "o3k-bootstrap".to_owned(),
            host_label: agent_id.to_owned(),
            supported_versions: vec![PROTOCOL_VERSION],
            capabilities: Some(capabilities),
        })
        .await
        .map_err(|status| AgentError::Protocol(status.to_string()))
    }

    async fn epoch_gate(&self, agent_id: &str) -> Arc<RwLock<()>> {
        if let Some(gate) = self.epoch_gates.read().await.get(agent_id).cloned() {
            return gate;
        }
        self.epoch_gates
            .write()
            .await
            .entry(agent_id.to_owned())
            .or_insert_with(|| Arc::new(RwLock::new(())))
            .clone()
    }

    pub async fn snapshot(&self, agent_id: &str) -> Option<NodeSnapshot> {
        self.nodes.read().await.get(agent_id).cloned()
    }

    pub async fn all(&self) -> Vec<NodeSnapshot> {
        self.nodes.read().await.values().cloned().collect()
    }

    pub fn subscribe_events(&self) -> broadcast::Receiver<ProviderAgentEvent> {
        self.events.subscribe()
    }

    /// Wake handle the inventory publisher waits on: every successful
    /// registration notifies it, so a freshly registered agent's capacity is
    /// published to placement without waiting for the next periodic tick
    /// (issue #606).
    pub fn registration_notify(&self) -> Arc<Notify> {
        self.registration_notify.clone()
    }

    /// Attaches the durable agent-command store used by
    /// `persist_pending_command`. Must be called before dispatch when the
    /// console-log path needs durable records.
    #[must_use]
    pub fn with_store(mut self, store: Arc<dyn o3k_store::ComputeRepository>) -> Self {
        self.store = Some(store);
        self
    }

    /// Persists a wire command as a durable pending agent command before the
    /// agent executes it, so a crash cannot lose the dispatched intent. The
    /// payload is the exact encoded wire command: replay rebuilds the same
    /// deadline and fingerprint, preserving the agent journal's idempotent
    /// identity. Returns `None` when no durable store is configured.
    pub async fn persist_pending_command(
        &self,
        command: &proto::Command,
        operation_id: Uuid,
    ) -> Result<Option<o3k_store::AgentCommandRecord>, AgentError> {
        let Some(store) = &self.store else {
            return Ok(None);
        };
        let resource_id = Uuid::parse_str(&command.resource_id).map_err(|_| {
            AgentError::Protocol("command resource identity is not a UUID".to_owned())
        })?;
        persist_command_record(store.as_ref(), command, operation_id, resource_id)
            .await
            .map_err(|_| AgentError::Protocol("agent command record already exists".to_owned()))
    }

    /// Attaches coordination store and controller credentials.
    #[must_use]
    pub fn with_coordination(
        mut self,
        coordination: Arc<dyn o3k_store::CoordinationRepository>,
        controller_id: o3k_store::ControllerId,
        controller_epoch: o3k_store::ControllerEpoch,
    ) -> Self {
        self.coordination = Some((coordination, controller_id, controller_epoch));
        self
    }

    pub async fn abort_stream_renewal(&self, agent_id: &str) {
        if let Some(conn) = self.connections.read().await.get(agent_id)
            && let Some(abort) = &conn.renewal_abort
        {
            abort.notify_waiters();
        }
    }

    pub async fn attach_connection(
        &self,
        agent_id: &str,
        agent_epoch: &str,
        sender: mpsc::Sender<Result<proto::ControlResponse, Status>>,
    ) -> Result<(), Status> {
        let node = self
            .nodes
            .read()
            .await
            .get(agent_id)
            .cloned()
            .ok_or_else(|| Status::unauthenticated("agent is not registered"))?;
        if node.agent_epoch != agent_epoch {
            return Err(Status::permission_denied("agent epoch is fenced"));
        }
        let (fencing_token, renewal_abort) = if let Some((
            coordination,
            controller_id,
            controller_epoch,
        )) = &self.coordination
        {
            let work_key = format!("agent:{}", agent_id);
            let outcome = coordination
                .acquire_work_lease(
                    &work_key,
                    "agent_stream",
                    controller_id,
                    controller_epoch,
                    Duration::from_secs(15),
                )
                .await
                .map_err(|e| {
                    tracing::warn!(agent_id = %agent_id, error = ?e, "failed to acquire agent stream lease");
                    Status::internal(format!("failed to acquire agent stream lease: {e}"))
                })?;
            match outcome {
                o3k_store::LeaseAcquireOutcome::Acquired { lease } => {
                    tracing::info!(
                        agent_id = %agent_id,
                        fencing_token = %lease.fencing_token,
                        "acquired agent stream lease"
                    );
                    let abort_notify = Arc::new(Notify::new());
                    let renew_coord = coordination.clone();
                    let renew_ctrl_id = controller_id.clone();
                    let renew_ctrl_epoch = controller_epoch.clone();
                    let renew_fence = lease.fencing_token;
                    let renew_work_key = work_key.clone();
                    let renew_abort = abort_notify.clone();
                    let renew_agent_id = agent_id.to_owned();
                    let renew_epoch = agent_epoch.to_owned();
                    let registry_conns = self.connections.clone();

                    tokio::spawn(async move {
                        let mut interval = tokio::time::interval(Duration::from_secs(5));
                        interval.tick().await;
                        loop {
                            tokio::select! {
                                _ = renew_abort.notified() => {
                                    tracing::debug!(agent_id = %renew_agent_id, "stream lease renewal task aborted");
                                    break;
                                }
                                _ = interval.tick() => {
                                    match renew_coord.renew_work_lease(&renew_work_key, &renew_ctrl_id, &renew_ctrl_epoch, renew_fence, Duration::from_secs(15)).await {
                                        Ok(true) => {
                                            tracing::trace!(agent_id = %renew_agent_id, "stream lease renewed");
                                        }
                                        Ok(false) => {
                                            tracing::warn!(agent_id = %renew_agent_id, "stream lease renewal rejected (fenced/lost); detaching connection");
                                            let mut conns = registry_conns.write().await;
                                            if conns.get(&renew_agent_id).is_some_and(|c| c.epoch == renew_epoch) {
                                                conns.remove(&renew_agent_id);
                                            }
                                            break;
                                        }
                                        Err(e) => {
                                            tracing::warn!(agent_id = %renew_agent_id, error = %e, "stream lease renewal DB error; detaching connection");
                                            let mut conns = registry_conns.write().await;
                                            if conns.get(&renew_agent_id).is_some_and(|c| c.epoch == renew_epoch) {
                                                conns.remove(&renew_agent_id);
                                            }
                                            break;
                                        }
                                    }
                                }
                            }
                        }
                    });

                    (lease.fencing_token, Some(abort_notify))
                }
                o3k_store::LeaseAcquireOutcome::Busy {
                    owner_controller_id,
                    fencing_token,
                    ..
                } => {
                    tracing::warn!(
                        agent_id = %agent_id,
                        owner_controller_id = %owner_controller_id,
                        fencing_token = %fencing_token,
                        "agent stream lease is currently owned by another controller; rejecting connection"
                    );
                    return Err(Status::permission_denied(
                        "agent stream lease is owned by another controller",
                    ));
                }
            }
        } else {
            (0, None)
        };
        self.connections.write().await.insert(
            agent_id.to_owned(),
            AgentConnection {
                epoch: agent_epoch.to_owned(),
                fencing_token,
                sender,
                renewal_abort,
            },
        );
        Ok(())
    }

    async fn detach_connection(&self, agent_id: &str, agent_epoch: &str) {
        let removed = {
            let mut connections = self.connections.write().await;
            if connections
                .get(agent_id)
                .is_some_and(|connection| connection.epoch == agent_epoch)
            {
                connections.remove(agent_id)
            } else {
                None
            }
        };
        if let Some(conn) = removed
            && let Some(abort) = conn.renewal_abort
        {
            abort.notify_one();
        }
        if let Some((coordination, controller_id, controller_epoch)) = &self.coordination {
            let work_key = format!("agent:{}", agent_id);
            if let Ok(Some(lease)) = coordination.inspect_work_lease(&work_key).await
                && lease.owner_controller_id == *controller_id
                && lease.owner_controller_epoch == *controller_epoch
            {
                let _ = coordination
                    .release_work_lease(
                        &work_key,
                        controller_id,
                        controller_epoch,
                        lease.fencing_token,
                    )
                    .await;
            }
        }
    }

    async fn connection_is_current(&self, agent_id: &str, agent_epoch: &str) -> bool {
        self.connections
            .read()
            .await
            .get(agent_id)
            .is_some_and(|connection| connection.epoch == agent_epoch)
    }

    async fn acquire_artifact_transfer_slot(
        &self,
        agent_id: &str,
    ) -> Result<tokio::sync::OwnedSemaphorePermit, AgentError> {
        let semaphore = if let Some(semaphore) = self
            .artifact_transfer_slots
            .read()
            .await
            .get(agent_id)
            .cloned()
        {
            semaphore
        } else {
            let mut slots = self.artifact_transfer_slots.write().await;
            slots
                .entry(agent_id.to_owned())
                .or_insert_with(|| {
                    Arc::new(Semaphore::new(MAX_CONCURRENT_ARTIFACT_TRANSFERS_PER_AGENT))
                })
                .clone()
        };
        semaphore
            .acquire_owned()
            .await
            .map_err(|_| AgentError::Protocol("artifact transfer limit is closed".to_owned()))
    }

    pub async fn dispatch_command(&self, command: proto::Command) -> Result<(), AgentError> {
        validate_command(&command)?;
        let node = self
            .snapshot(&command.agent_id)
            .await
            .ok_or_else(|| AgentError::Protocol("agent is not registered".to_owned()))?;
        if node.agent_epoch != command.agent_epoch {
            return Err(AgentError::Protocol("agent epoch is fenced".to_owned()));
        }
        if node.availability != Availability::Available
            || node.desired_state != proto::AdministrativeState::Enabled as i32
        {
            return Err(AgentError::Protocol(
                "agent is unavailable or not enabled".to_owned(),
            ));
        }
        let (sender, expected_fence) = {
            let connections = self.connections.read().await;
            let connection = connections
                .get(&command.agent_id)
                .filter(|connection| connection.epoch == command.agent_epoch)
                .ok_or_else(|| {
                    AgentError::Protocol("agent control stream is unavailable".to_owned())
                })?;
            (connection.sender.clone(), connection.fencing_token)
        };

        // FENCE CHECK IMMEDIATELY BEFORE DISPATCH:
        if let Some((coordination, controller_id, controller_epoch)) = &self.coordination {
            let work_key = format!("agent:{}", command.agent_id);
            let lease_opt = coordination
                .inspect_work_lease(&work_key)
                .await
                .map_err(|e| AgentError::Protocol(format!("failed to verify stream lease: {e}")))?;
            let Some(lease) = lease_opt else {
                return Err(AgentError::Protocol(
                    "agent stream lease expired or lost".to_owned(),
                ));
            };
            if lease.owner_controller_id != *controller_id
                || lease.owner_controller_epoch != *controller_epoch
                || (expected_fence > 0 && lease.fencing_token != expected_fence)
            {
                return Err(AgentError::Protocol(
                    "agent stream lease is fenced or owned by another controller".to_owned(),
                ));
            }
        }

        sender
            .send(Ok(proto::ControlResponse {
                body: Some(proto::control_response::Body::Command(command)),
            }))
            .await
            .map_err(|_| AgentError::Protocol("agent control stream is closed".to_owned()))
    }

    /// Sends one validated artifact over the currently fenced agent stream.
    ///
    /// This is intentionally a transport primitive: it does not persist
    /// transfer state or wait for acknowledgements. The caller owns those
    /// coordination concerns.
    pub async fn dispatch_artifact(
        &self,
        offer: proto::ArtifactOffer,
        bytes: impl AsRef<[u8]>,
    ) -> Result<(), AgentError> {
        let _transfer_slot = self.acquire_artifact_transfer_slot(&offer.agent_id).await?;
        self.dispatch_artifact_from(offer, bytes, 0).await
    }

    /// Resumes an artifact transfer at a previously acknowledged contiguous
    /// chunk. The offer and transfer ID remain unchanged; a caller must only
    /// pass a start index obtained from authenticated durable status.
    pub async fn dispatch_artifact_from(
        &self,
        offer: proto::ArtifactOffer,
        bytes: impl AsRef<[u8]>,
        start_chunk_index: u32,
    ) -> Result<(), AgentError> {
        let bytes = bytes.as_ref();
        validate_artifact_dispatch(&offer, bytes)?;
        if start_chunk_index > offer.chunk_count {
            return Err(AgentError::Protocol(
                "artifact resume offset exceeds chunk count".to_owned(),
            ));
        }
        let node = self
            .snapshot(&offer.agent_id)
            .await
            .ok_or_else(|| AgentError::Protocol("agent is not registered".to_owned()))?;
        if !node
            .capabilities
            .flags
            .iter()
            .any(|flag| flag.name == ARTIFACT_TRANSFER_CAPABILITY && flag.supported)
        {
            return Err(AgentError::Protocol(
                "agent has not negotiated artifact transfer capability".to_owned(),
            ));
        }
        if node.agent_epoch.is_empty() {
            return Err(AgentError::Protocol("agent epoch is missing".to_owned()));
        }
        if node.availability != Availability::Available
            || node.desired_state != proto::AdministrativeState::Enabled as i32
        {
            return Err(AgentError::Protocol(
                "agent is unavailable or not enabled".to_owned(),
            ));
        }

        // Keep the connection guard for the complete sequence. A reconnect
        // cannot replace the fenced sender between the offer and its chunks.
        let connections = self.connections.read().await;
        let connection = connections
            .get(&offer.agent_id)
            .filter(|connection| connection.epoch == node.agent_epoch)
            .ok_or_else(|| {
                AgentError::Protocol("agent control stream is unavailable".to_owned())
            })?;
        connection
            .sender
            .send(Ok(proto::ControlResponse {
                body: Some(proto::control_response::Body::ArtifactOffer(offer.clone())),
            }))
            .await
            .map_err(|_| AgentError::Protocol("agent control stream is closed".to_owned()))?;

        let chunk_size = offer.chunk_size_bytes as usize;
        // Chunks are deliberately emitted in index order because the agent
        // commits only contiguous data. The semaphore makes the maximum
        // in-flight chunk budget explicit for future pipelining without
        // allowing an implementation change to exceed the contract.
        let chunk_slots = Arc::new(Semaphore::new(MAX_IN_FLIGHT_ARTIFACT_CHUNKS_PER_TRANSFER));
        for (chunk_index, chunk) in
            bytes
                .chunks(chunk_size)
                .enumerate()
                .skip(usize::try_from(start_chunk_index).map_err(|_| {
                    AgentError::Protocol("artifact resume offset is invalid".to_owned())
                })?)
        {
            let _chunk_slot = chunk_slots
                .acquire()
                .await
                .map_err(|_| AgentError::Protocol("artifact chunk limit is closed".to_owned()))?;
            let chunk_index = u32::try_from(chunk_index)
                .map_err(|_| AgentError::Protocol("artifact chunk index overflow".to_owned()))?;
            connection
                .sender
                .send(Ok(proto::ControlResponse {
                    body: Some(proto::control_response::Body::ArtifactChunk(
                        proto::ArtifactChunk {
                            transfer_id: offer.transfer_id.clone(),
                            chunk_index,
                            offset_bytes: chunk_index as u64 * offer.chunk_size_bytes as u64,
                            data: chunk.to_vec(),
                            chunk_sha256: sha256_hex(chunk),
                        },
                    )),
                }))
                .await
                .map_err(|_| AgentError::Protocol("agent control stream is closed".to_owned()))?;
        }
        connection
            .sender
            .send(Ok(proto::ControlResponse {
                body: Some(proto::control_response::Body::ArtifactEnd(
                    proto::ArtifactEnd {
                        transfer_id: offer.transfer_id,
                        sha256: offer.sha256,
                        size_bytes: offer.size_bytes,
                    },
                )),
            }))
            .await
            .map_err(|_| AgentError::Protocol("agent control stream is closed".to_owned()))
    }

    /// Delivers an artifact and waits for the agent's authenticated commit
    /// acknowledgement. A timeout is deliberately reported as unknown: the
    /// agent may have durably committed the artifact after the stream stopped
    /// carrying responses.
    pub async fn dispatch_artifact_and_wait(
        &self,
        offer: proto::ArtifactOffer,
        bytes: impl AsRef<[u8]>,
        timeout: Duration,
    ) -> Result<o3k_provider::AgentArtifactAck, AgentError> {
        self.dispatch_artifact_and_wait_from(offer, bytes, 0, timeout)
            .await
    }

    /// Resumes an artifact transfer and waits for its authenticated commit
    /// acknowledgement without changing the transfer identity.
    pub async fn dispatch_artifact_and_wait_from(
        &self,
        offer: proto::ArtifactOffer,
        bytes: impl AsRef<[u8]>,
        start_chunk_index: u32,
        timeout: Duration,
    ) -> Result<o3k_provider::AgentArtifactAck, AgentError> {
        let mut events = self.subscribe_events();
        let transfer_id = offer.transfer_id.clone();
        let command_id = offer.command_id.clone();
        let operation_id = offer.operation_id.clone();
        let resource_id = offer.resource_id.clone();
        let agent_id = offer.agent_id.clone();
        let agent_epoch = self
            .snapshot(&agent_id)
            .await
            .ok_or_else(|| AgentError::Protocol("agent is not registered".to_owned()))?
            .agent_epoch;
        // Keep the transfer slot until the authenticated terminal ack. A
        // transfer remains in flight after ArtifactEnd until its outcome is
        // known, including when the outcome later becomes unknown on timeout.
        let _transfer_slot = self.acquire_artifact_transfer_slot(&agent_id).await?;
        // Issue #611 (ASR-021 agent-control-plane-network-interruption): the
        // send phase is bounded exactly like the acknowledgement wait. The
        // chunk sends drain through the agent's response stream; when a
        // control-channel interruption leaves that stream's receiver stalled
        // without being dropped, an unbounded send blocks the caller forever.
        // The create-convergence sweep drives transfers from its single
        // sequential task, so one stalled send froze the entire sweep for
        // minutes in the gate runs (the create stayed Running with no re-drive
        // for ~5 min, and the late re-drive then failed on the never-reoffered
        // artifact). The send timeout fails the drive as a retryable outcome;
        // the durable transfer row stays offered/receiving and the next
        // re-drive re-offers it.
        time::timeout(
            timeout,
            self.dispatch_artifact_from(offer, bytes, start_chunk_index),
        )
        .await
        .map_err(|_| {
            AgentError::Protocol(
                "artifact transfer send timeout; the control stream is stalled".to_owned(),
            )
        })??;
        time::timeout(timeout, async move {
            loop {
                let event = events.recv().await.map_err(|error| match error {
                    broadcast::error::RecvError::Lagged(count) => AgentError::Protocol(format!(
                        "artifact acknowledgement stream lagged by {count} events"
                    )),
                    broadcast::error::RecvError::Closed => {
                        AgentError::Protocol("artifact acknowledgement stream closed".to_owned())
                    }
                })?;
                let ack = match event {
                    ProviderAgentEvent::ArtifactAck(ack)
                        if ack.transfer_id == transfer_id
                            && ack.command_id == command_id
                            && ack.operation_id.to_string() == operation_id
                            && ack.resource_id.to_string() == resource_id
                            && ack.agent_id == agent_id
                            && ack.agent_epoch == agent_epoch =>
                    {
                        ack
                    }
                    _ => continue,
                };
                match ack.state {
                    o3k_provider::ArtifactTransferState::Committed => return Ok(ack),
                    o3k_provider::ArtifactTransferState::Rejected
                    | o3k_provider::ArtifactTransferState::Expired => {
                        return Err(AgentError::Protocol(
                            if let Some(message) = ack.redacted_message {
                                message
                            } else {
                                "agent rejected artifact transfer".to_owned()
                            },
                        ));
                    }
                    _ => {}
                }
            }
        })
        .await
        .map_err(|_| AgentError::Protocol("artifact transfer outcome is unknown".to_owned()))?
    }

    /// Dispatches a fenced command and waits for its matching observation.
    /// The subscription is installed before dispatch so a fast agent response
    /// cannot be missed.
    pub async fn dispatch_command_and_wait(
        &self,
        command: proto::Command,
        timeout: Duration,
    ) -> Result<o3k_provider::AgentObservation, AgentError> {
        let mut events = self.subscribe_events();
        let agent_id = command.agent_id.clone();
        let resource_id = command.resource_id.clone();
        let operation_id = command.operation_id.clone();
        let action = command_action_name(&command);
        info!(
            agent_id = %agent_id,
            operation_id = %operation_id,
            resource_id = %resource_id,
            action,
            timeout_ms = timeout.as_millis(),
            "command dispatch start"
        );
        if let Err(error) = self.dispatch_command(command).await {
            warn!(%error, operation_id = %operation_id, action, "command dispatch failed");
            return Err(error);
        }
        match time::timeout(timeout, async move {
            loop {
                match events.recv().await {
                    Ok(ProviderAgentEvent::Observation(observation))
                        if observation.agent_id == agent_id
                            // The boundary converts identities to canonical
                            // UUIDs; O3K-built commands always carry canonical
                            // lowercase forms, so the round-trip comparison is
                            // exact for every command this control plane
                            // dispatches.
                            && observation.resource_id.to_string() == resource_id
                            && observation.operation_id.to_string() == operation_id =>
                    {
                        // A command may finish after the original control
                        // stream is replaced.  The agent journal then replays
                        // the terminal observation under the new epoch.  The
                        // registry is the authority for which epoch is live:
                        // accept only that current epoch, never merely any
                        // observation with matching operation identities.
                        let current_epoch =
                            self.snapshot(&agent_id).await.map(|node| node.agent_epoch);
                        if current_epoch.as_deref() == Some(observation.agent_epoch.as_str()) {
                            return Ok(*observation);
                        }
                        warn!(
                            agent_id = %observation.agent_id,
                            observation_epoch = %observation.agent_epoch,
                            current_epoch = ?current_epoch,
                            operation_id = %observation.operation_id,
                            resource_id = %observation.resource_id,
                            "ignored observation from a replaced agent epoch while waiting"
                        );
                    }
                    Ok(_) => {}
                    Err(broadcast::error::RecvError::Lagged(count)) => {
                        return Err(AgentError::Protocol(format!(
                            "agent observation stream lagged by {count} events"
                        )));
                    }
                    Err(broadcast::error::RecvError::Closed) => {
                        return Err(AgentError::Protocol(
                            "agent observation stream closed".to_owned(),
                        ));
                    }
                }
            }
        })
        .await
        {
            Ok(Ok(observation)) => {
                info!(
                    operation_id = %observation.operation_id,
                    operation_state = ?observation.operation_state,
                    console_bytes = observation.console_log_bytes.len(),
                    "command observation received"
                );
                Ok(observation)
            }
            Ok(Err(error)) => {
                warn!(%error, "command observation stream failed");
                Err(error)
            }
            Err(_) => {
                warn!("agent observation timed out");
                Err(AgentError::Protocol(
                    "agent observation timed out".to_owned(),
                ))
            }
        }
    }

    pub(crate) fn publish_event(&self, event: ProviderAgentEvent) {
        let _ = self.events.send(event);
    }

    pub async fn authorize_agent(&self, agent: AuthorizedAgent) -> Result<(), AgentError> {
        if agent.agent_id.trim().is_empty() || agent.agent_id.len() > MAX_AGENT_ID {
            return Err(AgentError::InvalidConfiguration(
                "authorized agent identity is invalid",
            ));
        }
        self.authorized_agents
            .write()
            .await
            .insert(agent.agent_id, agent.certificate_sha256);
        Ok(())
    }

    async fn is_authorized(&self, agent_id: &str, certificate: &[u8]) -> bool {
        let digest = Sha256::digest(certificate);
        self.authorized_agents
            .read()
            .await
            .get(agent_id)
            .is_some_and(|expected| expected.as_slice() == digest.as_slice())
    }

    pub async fn register(
        &self,
        request: &proto::RegisterRequest,
    ) -> Result<proto::RegisterResponse, Status> {
        validate_register(request).map_err(|status| *status)?;
        let _epoch_change = self.epoch_gate(&request.agent_id).await.write_owned().await;
        let now = SystemTime::now();
        let mut nodes = self.nodes.write().await;
        let desired = nodes
            .get(&request.agent_id)
            .map_or(proto::AdministrativeState::Enabled as i32, |n| {
                n.desired_state
            });
        let highest = nodes
            .get(&request.agent_id)
            .map_or(0, |n| n.last_heartbeat_sequence);
        let applied = nodes
            .get(&request.agent_id)
            .map_or(proto::AdministrativeState::Unspecified as i32, |n| {
                n.applied_state
            });
        let snapshot = NodeSnapshot {
            agent_id: request.agent_id.clone(),
            agent_epoch: request.agent_epoch.clone(),
            host_label: request.host_label.clone(),
            software_version: request.software_version.clone(),
            capabilities: request.capabilities.clone().unwrap_or_default(),
            desired_state: desired,
            applied_state: applied,
            availability: Availability::Available,
            active_operation_count: 0,
            last_heartbeat_sequence: 0,
            last_heartbeat_at: now,
            transition_sequence: 0,
            last_heartbeat_state: proto::AdministrativeState::Unspecified as i32,
        };
        nodes.insert(request.agent_id.clone(), snapshot);
        info!(agent_id = %request.agent_id, epoch = %request.agent_epoch, "compute agent registered");
        drop(nodes);
        // Wake the inventory publisher so the registered agent's real
        // capacity is visible to placement immediately (issue #606); the
        // publisher keeps its periodic tick as the steady-state sync.
        self.registration_notify.notify_one();
        Ok(proto::RegisterResponse {
            agent_id: request.agent_id.clone(),
            agent_epoch: request.agent_epoch.clone(),
            selected_version: Some(PROTOCOL_VERSION),
            heartbeat_interval_seconds: DEFAULT_HEARTBEAT_INTERVAL.as_secs() as u32,
            max_clock_skew_seconds: 30,
            desired_state: desired,
            highest_observation_sequence: highest,
        })
    }

    pub async fn heartbeat(
        &self,
        heartbeat: &proto::Heartbeat,
    ) -> Result<proto::HeartbeatAck, Status> {
        if heartbeat.agent_id.trim().is_empty() || heartbeat.agent_epoch.trim().is_empty() {
            return Err(Status::invalid_argument("agent identity is required"));
        }
        if !valid_admin_state(heartbeat.state) {
            return Err(Status::invalid_argument("administrative state is invalid"));
        }
        let mut nodes = self.nodes.write().await;
        let node = nodes
            .get_mut(&heartbeat.agent_id)
            .ok_or_else(|| Status::unauthenticated("agent is not registered"))?;
        if node.agent_epoch != heartbeat.agent_epoch {
            return Err(Status::permission_denied("agent epoch is fenced"));
        }
        if heartbeat.sequence <= node.last_heartbeat_sequence {
            return Err(Status::invalid_argument("heartbeat sequence must increase"));
        }
        node.last_heartbeat_sequence = heartbeat.sequence;
        node.last_heartbeat_at = SystemTime::now();
        node.active_operation_count = heartbeat.active_operation_count;
        node.last_heartbeat_state = heartbeat.state;
        node.availability = Availability::Available;
        Ok(proto::HeartbeatAck {
            received_at_unix_ms: unix_ms(),
            desired_state: node.desired_state,
            acknowledged_heartbeat_sequence: heartbeat.sequence,
            highest_observation_sequence: heartbeat.highest_observation_sequence,
            transition_sequence: node.transition_sequence,
        })
    }

    pub async fn set_desired_state(
        &self,
        agent_id: &str,
        state: proto::AdministrativeState,
    ) -> Result<u64, AgentError> {
        if !matches!(
            state,
            proto::AdministrativeState::Enabled
                | proto::AdministrativeState::Draining
                | proto::AdministrativeState::Disabled
        ) {
            return Err(AgentError::InvalidConfiguration(
                "administrative state is unspecified",
            ));
        }
        let mut nodes = self.nodes.write().await;
        let node = nodes
            .get_mut(agent_id)
            .ok_or(AgentError::Protocol("agent is not registered".to_owned()))?;
        node.transition_sequence = node.transition_sequence.saturating_add(1);
        node.desired_state = state as i32;
        let transition_sequence = node.transition_sequence;
        drop(nodes);

        let connection = self.connections.read().await.get(agent_id).cloned();
        if let Some(connection) = connection {
            connection
                .sender
                .send(Ok(proto::ControlResponse {
                    body: Some(proto::control_response::Body::DesiredState(
                        proto::DesiredAgentState {
                            state: state as i32,
                            reason: "administrative state transition".to_owned(),
                            transition_sequence,
                        },
                    )),
                }))
                .await
                .map_err(|_| AgentError::Protocol("agent control stream is closed".to_owned()))?;
        }
        Ok(transition_sequence)
    }

    async fn acknowledge_state(&self, ack: &proto::AgentStateAck) -> Result<(), Status> {
        if !valid_admin_state(ack.applied_state) {
            return Err(Status::invalid_argument("administrative state is invalid"));
        }
        let mut nodes = self.nodes.write().await;
        let node = nodes
            .get_mut(&ack.agent_id)
            .ok_or_else(|| Status::unauthenticated("agent is not registered"))?;
        if node.agent_epoch != ack.agent_epoch {
            return Err(Status::permission_denied("agent epoch is fenced"));
        }
        if ack.transition_sequence != node.transition_sequence {
            return Err(Status::failed_precondition(
                "administrative transition is stale",
            ));
        }
        node.applied_state = ack.applied_state;
        node.active_operation_count = ack.active_operation_count;
        Ok(())
    }

    pub async fn mark_unavailable(&self, lease: Duration) {
        let now = SystemTime::now();
        let mut nodes = self.nodes.write().await;
        for node in nodes.values_mut() {
            if now
                .duration_since(node.last_heartbeat_at)
                .unwrap_or_default()
                > lease
            {
                node.availability = Availability::Unavailable;
            }
        }
    }
}

/// Projects one authenticated wire node snapshot into the application-level
/// node vocabulary used by resolver ports and inventory publication.
#[async_trait]
impl o3k_provider::AgentNodeRegistry for NodeRegistry {
    async fn all(&self) -> Vec<o3k_provider::AgentNodeSnapshot> {
        self.nodes
            .read()
            .await
            .values()
            .map(agent_snapshot)
            .collect()
    }

    async fn snapshot(&self, agent_id: &str) -> Option<o3k_provider::AgentNodeSnapshot> {
        self.nodes.read().await.get(agent_id).map(agent_snapshot)
    }

    async fn observed_at_unix_ms(&self, agent_id: &str) -> Option<i64> {
        let nodes = self.nodes.read().await;
        let node = nodes.get(agent_id)?;
        // Registration seeds `last_heartbeat_at`, and every authenticated
        // heartbeat replaces it, so a present value is a real observation.
        node.last_heartbeat_at
            .duration_since(std::time::UNIX_EPOCH)
            .ok()
            .and_then(|elapsed| i64::try_from(elapsed.as_millis()).ok())
    }

    async fn lease_current_epoch(
        &self,
        agent_id: &str,
        agent_epoch: &str,
    ) -> Option<Box<dyn o3k_provider::AgentEpochLease>> {
        let epoch = self.epoch_gate(agent_id).await.read_owned().await;
        self.nodes
            .read()
            .await
            .get(agent_id)
            .is_some_and(|node| node.agent_epoch == agent_epoch)
            .then(|| Box::new(NodeEpochLease { _epoch: epoch }) as Box<_>)
    }

    fn subscribe_events(&self) -> broadcast::Receiver<o3k_provider::AgentEvent> {
        self.subscribe_events()
    }
}

pub fn agent_snapshot(node: &NodeSnapshot) -> o3k_provider::AgentNodeSnapshot {
    use o3k_provider::{AgentAdministrativeState, AgentAvailability};
    // Unknown administrative-state values fail closed as Disabled: a protocol
    // anomaly must make the node unschedulable, never silently enabled.
    let administrative_state = match node.desired_state {
        value if value == proto::AdministrativeState::Enabled as i32 => {
            AgentAdministrativeState::Enabled
        }
        value if value == proto::AdministrativeState::Draining as i32 => {
            AgentAdministrativeState::Draining
        }
        _ => AgentAdministrativeState::Disabled,
    };
    o3k_provider::AgentNodeSnapshot {
        agent_id: node.agent_id.clone(),
        agent_epoch: node.agent_epoch.clone(),
        availability: if node.availability == Availability::Available {
            AgentAvailability::Available
        } else {
            AgentAvailability::Unavailable
        },
        administrative_state,
        capabilities: o3k_provider::AgentCapabilities {
            agent_provider_name: node.capabilities.agent_provider_name.clone(),
            agent_provider_version: node.capabilities.agent_provider_version.clone(),
            max_vcpus: u64::from(node.capabilities.max_vcpus),
            max_memory_mib: node.capabilities.max_memory_mib,
            max_disk_gb: node.capabilities.max_disk_gb,
            lifecycle_actions: node.capabilities.lifecycle_actions.clone(),
            console_log: node.capabilities.console_log,
            flags: node
                .capabilities
                .flags
                .iter()
                .map(|flag| o3k_provider::AgentCapabilityFlag {
                    name: flag.name.clone(),
                    supported: flag.supported,
                })
                .collect(),
        },
    }
}

/// Builds and persists the durable pending record for a dispatched wire
/// command. The payload is the exact encoded wire command so replay rebuilds
/// the same deadline and fingerprint; the operation record is created when
/// missing. A concurrent dispatch that already inserted the deterministic
/// command identity (issue #88 E3 C3 — the API's synchronous create
/// reconcile races the periodic create-convergence sweep) is adopted rather
/// than reported as a conflict: the surviving row is returned so the caller
/// re-dispatches it and the fresh create is never terminalized. Callers map
/// genuine store errors to their own vocabulary.
pub(crate) async fn persist_command_record(
    store: &dyn o3k_store::ComputeRepository,
    command: &proto::Command,
    operation_id: Uuid,
    resource_id: Uuid,
) -> Result<Option<o3k_store::AgentCommandRecord>, o3k_store::StoreError> {
    let record = o3k_store::AgentCommandRecord {
        command_id: command.command_id.clone(),
        idempotency_key: command.idempotency_key.clone(),
        operation_id,
        resource_id,
        agent_id: command.agent_id.clone(),
        agent_epoch: command.agent_epoch.clone(),
        payload_fingerprint_sha256: command.payload_fingerprint_sha256.clone(),
        payload: command.encode_to_vec(),
        state: o3k_store::AgentCommandState::Pending,
        accepted_sequence: 0,
        last_sequence: 0,
        provider_operation_id: Some(operation_id.to_string()),
        provider_resource_id: None,
    };
    if store.get_operation(operation_id).await.is_err() {
        let _ = store
            .insert_operation(&o3k_store::OperationRecord {
                id: operation_id,
                resource_id: record.resource_id,
                kind: "command".to_owned(),
                state: o3k_store::OperationState::Running,
                provider_operation_id: Some(operation_id.to_string()),
                error_category: None,
                error_message: None,
            })
            .await;
    }
    match store.insert_agent_command(&record).await {
        Ok(existing) => Ok(Some(existing)),
        Err(error) => {
            // A concurrent dispatch for the same operation inserted the
            // durable command between this caller's readiness work and this
            // insert. The command identity is deterministic per operation
            // (agent + operation), so the surviving row IS this command:
            // adopt it and let the caller re-dispatch it instead of failing
            // the fresh create. The agent journal replays by command
            // identity, so the re-dispatch converges on one execution.
            match store.get_agent_command_by_operation(operation_id).await {
                Ok(existing) => Ok(Some(existing)),
                Err(_) => Err(error),
            }
        }
    }
}

fn valid_admin_state(state: i32) -> bool {
    matches!(
        state,
        value if value == proto::AdministrativeState::Enabled as i32
            || value == proto::AdministrativeState::Draining as i32
            || value == proto::AdministrativeState::Disabled as i32
    )
}

fn validate_command(command: &proto::Command) -> Result<(), AgentError> {
    validate_command_with_deadline(command, true, true)
}

fn validate_command_with_deadline(
    command: &proto::Command,
    require_live_deadline: bool,
    require_live_transfers: bool,
) -> Result<(), AgentError> {
    if !valid_reference(&command.command_id)
        || !valid_reference(&command.operation_id)
        || !valid_idempotency_key(&command.idempotency_key)
        || !valid_reference(&command.agent_id)
        || !valid_reference(&command.agent_epoch)
        || !valid_reference(&command.resource_id)
        || command.action.is_none()
    {
        return Err(AgentError::Protocol(
            "command identity, action, and idempotency key are required".to_owned(),
        ));
    }
    let Some(version) = command.protocol_version.as_ref() else {
        return Err(AgentError::Protocol(
            "command protocol version is required".to_owned(),
        ));
    };
    if version != &PROTOCOL_VERSION {
        return Err(AgentError::Protocol(
            "command protocol version is unsupported".to_owned(),
        ));
    }
    if require_live_deadline && command.deadline_unix_ms <= unix_ms() {
        return Err(AgentError::Protocol(
            "command deadline has expired".to_owned(),
        ));
    }
    validate_command_action(command, require_live_transfers)?;
    let expected = command_payload_fingerprint(command)?;
    if command.payload_fingerprint_sha256 != expected {
        return Err(AgentError::Protocol(
            "command payload fingerprint does not match canonical payload".to_owned(),
        ));
    }
    Ok(())
}

fn validate_command_action(
    command: &proto::Command,
    require_live_transfers: bool,
) -> Result<(), AgentError> {
    match command.action.as_ref() {
        Some(proto::command::Action::Create(create)) => {
            if require_live_transfers {
                validate_proto_create(create)
            } else {
                validate_proto_create_identity(create)
            }
        }
        Some(proto::command::Action::ConsoleLog(console))
            if console.max_bytes > 0 && console.max_bytes as usize <= o3k_console_limit() =>
        {
            Ok(())
        }
        Some(proto::command::Action::ConsoleLog(_)) => Err(AgentError::Protocol(
            "console command bounds are invalid".to_owned(),
        )),
        Some(proto::command::Action::Reboot(reboot))
            if matches!(
                proto::reboot_command::RebootType::try_from(reboot.r#type),
                Ok(proto::reboot_command::RebootType::Soft)
                    | Ok(proto::reboot_command::RebootType::Hard)
            ) =>
        {
            Ok(())
        }
        Some(proto::command::Action::Reboot(_)) => {
            Err(AgentError::Protocol("reboot type is invalid".to_owned()))
        }
        Some(
            proto::command::Action::Inspect(_)
            | proto::command::Action::Start(_)
            | proto::command::Action::Stop(_)
            | proto::command::Action::Delete(_),
        ) => Ok(()),
        Some(proto::command::Action::CollectConnector(_)) => Ok(()),
        Some(proto::command::Action::AttachDisk(device)) => validate_attach_disk(device),
        Some(proto::command::Action::DetachDisk(device)) => validate_detach_disk(device),
        Some(proto::command::Action::ObserveDisk(observe)) => {
            if !valid_reference(&observe.volume_id) || !valid_reference(&observe.attachment_id) {
                return Err(AgentError::Protocol(
                    "observe disk command identity is invalid".to_owned(),
                ));
            }
            Ok(())
        }
        None => Err(AgentError::Protocol(
            "command action is required".to_owned(),
        )),
    }
}

fn canonical_action(action: &proto::command::Action) -> proto::canonical_command_payload::Action {
    match action {
        proto::command::Action::Create(value) => {
            proto::canonical_command_payload::Action::Create(value.clone())
        }
        proto::command::Action::Inspect(value) => {
            proto::canonical_command_payload::Action::Inspect(*value)
        }
        proto::command::Action::Start(value) => {
            proto::canonical_command_payload::Action::Start(*value)
        }
        proto::command::Action::Stop(value) => {
            proto::canonical_command_payload::Action::Stop(*value)
        }
        proto::command::Action::Reboot(value) => {
            proto::canonical_command_payload::Action::Reboot(*value)
        }
        proto::command::Action::Delete(value) => {
            proto::canonical_command_payload::Action::Delete(*value)
        }
        proto::command::Action::ConsoleLog(value) => {
            proto::canonical_command_payload::Action::ConsoleLog(*value)
        }
        proto::command::Action::CollectConnector(value) => {
            proto::canonical_command_payload::Action::CollectConnector(*value)
        }
        proto::command::Action::AttachDisk(value) => {
            proto::canonical_command_payload::Action::AttachDisk(value.clone())
        }
        proto::command::Action::DetachDisk(value) => {
            proto::canonical_command_payload::Action::DetachDisk(value.clone())
        }
        proto::command::Action::ObserveDisk(value) => {
            proto::canonical_command_payload::Action::ObserveDisk(value.clone())
        }
    }
}

fn hex_digest(bytes: &[u8]) -> String {
    const HEX: &[u8; 16] = b"0123456789abcdef";
    let mut output = String::with_capacity(bytes.len() * 2);
    for byte in bytes {
        output.push(HEX[usize::from(byte >> 4)] as char);
        output.push(HEX[usize::from(byte & 0x0f)] as char);
    }
    output
}

fn command_payload_fingerprint(command: &proto::Command) -> Result<String, AgentError> {
    let action = command
        .action
        .as_ref()
        .ok_or_else(|| AgentError::Protocol("command action is required".to_owned()))?;
    let canonical = proto::CanonicalCommandPayload {
        operation_id: command.operation_id.clone(),
        resource_id: command.resource_id.clone(),
        action: Some(canonical_action(action)),
    };
    let digest = Sha256::digest(canonical.encode_to_vec());
    Ok(hex_digest(&digest))
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CreateCommandSpec {
    pub agent_id: String,
    pub agent_epoch: String,
    pub project_id: String,
    pub operation_id: String,
    pub resource_id: String,
    pub idempotency_key: String,
    pub deadline_unix_ms: i64,
    pub image_id: String,
    pub flavor_id: String,
    pub image_artifact_id: String,
    pub image_sha256: String,
    pub image_format: String,
    pub vcpus: u32,
    pub memory_mib: u64,
    pub disk_gib: u64,
    pub config_drive_artifact_id: String,
    pub config_drive_sha256: String,
    pub network_attachments: Vec<NetworkAttachmentSpec>,
}

/// The bounded application-level network attachment description; the wire
/// builder converts it into the protocol form at the boundary.
pub use o3k_provider::NetworkAttachmentSpec;

pub fn build_create_command(spec: CreateCommandSpec) -> Result<proto::Command, AgentError> {
    let CreateCommandSpec {
        agent_id,
        agent_epoch,
        project_id,
        operation_id,
        resource_id,
        idempotency_key,
        deadline_unix_ms,
        image_id,
        flavor_id,
        image_artifact_id,
        image_sha256,
        image_format,
        vcpus,
        memory_mib,
        disk_gib,
        config_drive_artifact_id,
        config_drive_sha256,
        network_attachments,
    } = spec;
    if agent_id.trim().is_empty()
        || agent_epoch.trim().is_empty()
        || !valid_reference(&project_id)
        || operation_id.trim().is_empty()
        || resource_id.trim().is_empty()
        || !valid_idempotency_key(&idempotency_key)
        || image_id.trim().is_empty()
        || flavor_id.trim().is_empty()
        || deadline_unix_ms <= unix_ms()
        || !valid_reference(&image_id)
        || !valid_reference(&flavor_id)
        || !valid_reference(&image_artifact_id)
        || !valid_sha256(&image_sha256)
        || !matches!(image_format.as_str(), "raw" | "qcow2")
        || !(1..=256).contains(&vcpus)
        || !(1..=1_048_576).contains(&memory_mib)
        || !(1..=1_048_576).contains(&disk_gib)
        || !valid_reference(&config_drive_artifact_id)
        || !valid_sha256(&config_drive_sha256)
        || network_attachments.is_empty()
        || network_attachments
            .iter()
            .any(|attachment| !valid_network_attachment(attachment))
        || has_duplicate_network_ports(&network_attachments)
    {
        return Err(AgentError::Protocol(
            "create command identity, resolved resources, and deadline are invalid".to_owned(),
        ));
    }
    let command_id = Uuid::new_v5(
        &Uuid::NAMESPACE_URL,
        format!("o3k:command:{agent_id}:{operation_id}").as_bytes(),
    )
    .to_string();
    let image_transfer_id = deterministic_artifact_transfer_id(
        &command_id,
        proto::ArtifactKind::ImageBase,
        &image_artifact_id,
    );
    let config_drive_transfer_id = deterministic_artifact_transfer_id(
        &command_id,
        proto::ArtifactKind::ConfigDriveIso,
        &config_drive_artifact_id,
    );
    let network_port_ids = network_attachments
        .iter()
        .map(|attachment| attachment.port_id.clone())
        .collect();
    let create = proto::CreateCommand {
        image_id,
        flavor_id,
        network_port_ids,
        resolved: Some(proto::ResolvedCreateInputs {
            image_artifact_id,
            image_sha256,
            image_format,
            vcpus,
            memory_mib,
            disk_gib,
            config_drive_artifact_id,
            config_drive_sha256,
            image_transfer: Some(proto::ArtifactReference {
                transfer_id: image_transfer_id,
                size_bytes: 0,
                expires_at_unix_ms: deadline_unix_ms,
            }),
            config_drive_transfer: Some(proto::ArtifactReference {
                transfer_id: config_drive_transfer_id,
                size_bytes: 0,
                expires_at_unix_ms: deadline_unix_ms,
            }),
            network_attachments: network_attachments
                .into_iter()
                .map(|attachment| proto::NetworkAttachment {
                    port_id: attachment.port_id,
                    mac: attachment.mac,
                    fixed_ipv4: attachment.fixed_ipv4,
                    subnet_cidr: attachment.subnet_cidr,
                    gateway_ipv4: attachment.gateway_ipv4,
                })
                .collect(),
            project_id,
        }),
    };
    let canonical = proto::CanonicalCommandPayload {
        operation_id: operation_id.clone(),
        resource_id: resource_id.clone(),
        action: Some(proto::canonical_command_payload::Action::Create(
            create.clone(),
        )),
    };
    let digest = Sha256::digest(canonical.encode_to_vec());
    let payload_fingerprint_sha256 = hex_digest(&digest);
    Ok(proto::Command {
        command_id,
        operation_id,
        idempotency_key,
        agent_id,
        agent_epoch,
        resource_id,
        deadline_unix_ms,
        protocol_version: Some(PROTOCOL_VERSION),
        payload_fingerprint_sha256,
        action: Some(proto::command::Action::Create(create)),
    })
}

/// The lifecycle mutations that can be dispatched after a provider resource
/// has been resolved.  Keeping this list typed prevents callers from turning
/// an arbitrary string into a host command.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum LifecycleCommand {
    Inspect,
    Start,
    Stop,
    HardReboot,
    Delete,
}

/// Builds a deterministic, fenced lifecycle command for the selected agent.
/// The command identity is stable for the operation and resource, so a
/// reconnect or retry cannot silently become a second mutation.
pub fn build_lifecycle_command(
    action: LifecycleCommand,
    agent_id: &str,
    agent_epoch: &str,
    operation_id: &str,
    resource_id: &str,
) -> Result<proto::Command, AgentError> {
    if !valid_reference(agent_id)
        || !valid_reference(agent_epoch)
        || !valid_reference(operation_id)
        || !valid_reference(resource_id)
    {
        return Err(AgentError::Protocol(
            "lifecycle command identity is invalid".to_owned(),
        ));
    }
    let action_name = match action {
        LifecycleCommand::Inspect => "inspect",
        LifecycleCommand::Start => "start",
        LifecycleCommand::Stop => "stop",
        LifecycleCommand::HardReboot => "hard-reboot",
        LifecycleCommand::Delete => "delete",
    };
    let canonical_action = match action {
        LifecycleCommand::Inspect => {
            proto::canonical_command_payload::Action::Inspect(proto::InspectCommand {})
        }
        LifecycleCommand::Start => {
            proto::canonical_command_payload::Action::Start(proto::StartCommand {})
        }
        LifecycleCommand::Stop => {
            proto::canonical_command_payload::Action::Stop(proto::StopCommand {})
        }
        LifecycleCommand::HardReboot => {
            proto::canonical_command_payload::Action::Reboot(proto::RebootCommand {
                r#type: proto::reboot_command::RebootType::Hard as i32,
            })
        }
        LifecycleCommand::Delete => {
            proto::canonical_command_payload::Action::Delete(proto::DeleteCommand {})
        }
    };
    let canonical = proto::CanonicalCommandPayload {
        operation_id: operation_id.to_owned(),
        resource_id: resource_id.to_owned(),
        action: Some(canonical_action.clone()),
    };
    let digest = Sha256::digest(canonical.encode_to_vec());
    let payload_fingerprint_sha256 = hex_digest(&digest);
    let action = match canonical_action {
        proto::canonical_command_payload::Action::Inspect(value) => {
            proto::command::Action::Inspect(value)
        }
        proto::canonical_command_payload::Action::Start(value) => {
            proto::command::Action::Start(value)
        }
        proto::canonical_command_payload::Action::Stop(value) => {
            proto::command::Action::Stop(value)
        }
        proto::canonical_command_payload::Action::Reboot(value) => {
            proto::command::Action::Reboot(value)
        }
        proto::canonical_command_payload::Action::Delete(value) => {
            proto::command::Action::Delete(value)
        }
        proto::canonical_command_payload::Action::Create(_)
        | proto::canonical_command_payload::Action::ConsoleLog(_)
        | proto::canonical_command_payload::Action::CollectConnector(_)
        | proto::canonical_command_payload::Action::AttachDisk(_)
        | proto::canonical_command_payload::Action::DetachDisk(_)
        | proto::canonical_command_payload::Action::ObserveDisk(_) => {
            return Err(AgentError::Protocol(
                "unsupported lifecycle command action".to_owned(),
            ));
        }
    };
    let idempotency_key = format!("{action_name}:{resource_id}:{operation_id}");
    Ok(proto::Command {
        command_id: Uuid::new_v5(
            &Uuid::NAMESPACE_URL,
            format!("o3k:lifecycle-command:{agent_id}:{operation_id}").as_bytes(),
        )
        .to_string(),
        operation_id: operation_id.to_owned(),
        idempotency_key,
        agent_id: agent_id.to_owned(),
        agent_epoch: agent_epoch.to_owned(),
        resource_id: resource_id.to_owned(),
        deadline_unix_ms: unix_ms().saturating_add(10_000),
        protocol_version: Some(PROTOCOL_VERSION),
        payload_fingerprint_sha256,
        action: Some(action),
    })
}

/// Builds a bounded, fenced console-log query using the existing protocol.
pub fn build_console_log_command(
    agent_id: &str,
    agent_epoch: &str,
    operation_id: &str,
    resource_id: &str,
    offset: u64,
    max_bytes: u32,
) -> Result<proto::Command, AgentError> {
    if !valid_reference(agent_id)
        || !valid_reference(agent_epoch)
        || !valid_reference(operation_id)
        || !valid_reference(resource_id)
        || max_bytes == 0
        || max_bytes as usize > o3k_console_limit()
    {
        return Err(AgentError::Protocol(
            "console command identity and bounds are invalid".to_owned(),
        ));
    }
    let action = proto::canonical_command_payload::Action::ConsoleLog(proto::ConsoleLogCommand {
        offset,
        max_bytes,
    });
    let canonical = proto::CanonicalCommandPayload {
        operation_id: operation_id.to_owned(),
        resource_id: resource_id.to_owned(),
        action: Some(action),
    };
    let digest = Sha256::digest(canonical.encode_to_vec());
    let payload_fingerprint_sha256 = hex_digest(&digest);
    // Each console request is its own operation, so the idempotency identity
    // must include the operation id. Sharing a key across operations would
    // make every sequential poll conflict with the durable journal record.
    let idempotency_key = format!("console:{resource_id}:{operation_id}:{offset}:{max_bytes}");
    Ok(proto::Command {
        command_id: Uuid::new_v5(
            &Uuid::NAMESPACE_URL,
            format!("o3k:console-command:{agent_id}:{operation_id}").as_bytes(),
        )
        .to_string(),
        operation_id: operation_id.to_owned(),
        idempotency_key,
        agent_id: agent_id.to_owned(),
        agent_epoch: agent_epoch.to_owned(),
        resource_id: resource_id.to_owned(),
        deadline_unix_ms: unix_ms().saturating_add(10_000),
        protocol_version: Some(PROTOCOL_VERSION),
        payload_fingerprint_sha256,
        action: Some(proto::command::Action::ConsoleLog(
            proto::ConsoleLogCommand { offset, max_bytes },
        )),
    })
}

const fn o3k_console_limit() -> usize {
    64 * 1024
}

/// Block-device commands dispatched to the compute execution boundary.
pub enum BlockDeviceCommand {
    CollectConnector,
    Attach {
        device: proto::AttachDiskCommand,
    },
    Detach {
        device: proto::DetachDiskCommand,
    },
    Observe {
        volume_id: String,
        attachment_id: String,
    },
}

fn valid_disk_reference(value: &str) -> bool {
    !value.is_empty()
        && value.len() <= 256
        && value
            .bytes()
            .all(|byte| byte.is_ascii_graphic() || byte.is_ascii_whitespace() || byte == b'/')
}

fn validate_attach_disk(device: &proto::AttachDiskCommand) -> Result<(), AgentError> {
    if !valid_reference(&device.volume_id)
        || !valid_reference(&device.attachment_id)
        || !valid_disk_reference(&device.driver_volume_type)
    {
        return Err(AgentError::Protocol(
            "attach disk command identity is invalid".to_owned(),
        ));
    }
    match device.driver_volume_type.as_str() {
        "iscsi" => {
            if !valid_disk_reference(&device.target_iqn)
                || !valid_disk_reference(&device.target_portal)
            {
                return Err(AgentError::Protocol(
                    "attach disk iscsi target is incomplete".to_owned(),
                ));
            }
        }
        "local" => {
            if !valid_disk_reference(device.device_path.as_str()) {
                return Err(AgentError::Protocol(
                    "attach disk local path is missing".to_owned(),
                ));
            }
        }
        _ => {
            return Err(AgentError::Protocol(
                "attach disk driver volume type is unsupported".to_owned(),
            ));
        }
    }
    Ok(())
}

fn validate_detach_disk(device: &proto::DetachDiskCommand) -> Result<(), AgentError> {
    if !valid_reference(&device.volume_id)
        || !valid_reference(&device.attachment_id)
        || !valid_disk_reference(&device.driver_volume_type)
    {
        return Err(AgentError::Protocol(
            "detach disk command identity is invalid".to_owned(),
        ));
    }
    Ok(())
}

/// Builds a deterministic, fenced block-device command for the selected agent.
/// Only non-secret bounded connection data crosses the agent boundary.
pub fn build_block_device_command(
    action: BlockDeviceCommand,
    agent_id: &str,
    agent_epoch: &str,
    operation_id: &str,
    resource_id: &str,
) -> Result<proto::Command, AgentError> {
    if !valid_reference(agent_id)
        || !valid_reference(agent_epoch)
        || !valid_reference(operation_id)
        || !valid_reference(resource_id)
    {
        return Err(AgentError::Protocol(
            "block-device command identity is invalid".to_owned(),
        ));
    }
    let (action_name, canonical_action, command_action) = match action {
        BlockDeviceCommand::CollectConnector => (
            "collect-connector",
            proto::canonical_command_payload::Action::CollectConnector(
                proto::CollectConnectorCommand {},
            ),
            proto::command::Action::CollectConnector(proto::CollectConnectorCommand {}),
        ),
        BlockDeviceCommand::Attach { device } => {
            validate_attach_disk(&device)?;
            (
                "attach-disk",
                proto::canonical_command_payload::Action::AttachDisk(device.clone()),
                proto::command::Action::AttachDisk(device),
            )
        }
        BlockDeviceCommand::Detach { device } => {
            validate_detach_disk(&device)?;
            (
                "detach-disk",
                proto::canonical_command_payload::Action::DetachDisk(device.clone()),
                proto::command::Action::DetachDisk(device),
            )
        }
        BlockDeviceCommand::Observe {
            volume_id,
            attachment_id,
        } => {
            if !valid_reference(&volume_id) || !valid_reference(&attachment_id) {
                return Err(AgentError::Protocol(
                    "observe disk command identity is invalid".to_owned(),
                ));
            }
            (
                "observe-disk",
                proto::canonical_command_payload::Action::ObserveDisk(proto::ObserveDiskCommand {
                    volume_id: volume_id.clone(),
                    attachment_id: attachment_id.clone(),
                }),
                proto::command::Action::ObserveDisk(proto::ObserveDiskCommand {
                    volume_id,
                    attachment_id,
                }),
            )
        }
    };
    let canonical = proto::CanonicalCommandPayload {
        operation_id: operation_id.to_owned(),
        resource_id: resource_id.to_owned(),
        action: Some(canonical_action),
    };
    let digest = Sha256::digest(canonical.encode_to_vec());
    let payload_fingerprint_sha256 = hex_digest(&digest);
    let idempotency_key = format!("{action_name}:{resource_id}:{operation_id}");
    Ok(proto::Command {
        command_id: Uuid::new_v5(
            &Uuid::NAMESPACE_URL,
            format!("o3k:block-device-command:{agent_id}:{operation_id}").as_bytes(),
        )
        .to_string(),
        operation_id: operation_id.to_owned(),
        idempotency_key,
        agent_id: agent_id.to_owned(),
        agent_epoch: agent_epoch.to_owned(),
        resource_id: resource_id.to_owned(),
        deadline_unix_ms: unix_ms().saturating_add(60_000),
        protocol_version: Some(PROTOCOL_VERSION),
        payload_fingerprint_sha256,
        action: Some(command_action),
    })
}

fn valid_reference(value: &str) -> bool {
    !value.is_empty()
        && value.len() <= 128
        && value
            .bytes()
            .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'.' | b'_' | b':' | b'-'))
}

fn valid_idempotency_key(value: &str) -> bool {
    !value.is_empty()
        && value.len() <= 128
        && value.bytes().all(|byte| {
            byte.is_ascii_alphanumeric() || matches!(byte, b'.' | b'_' | b':' | b'-' | b'/')
        })
}

fn valid_sha256(value: &str) -> bool {
    value.len() == 64 && value.bytes().all(|byte| byte.is_ascii_hexdigit())
}

fn valid_network_attachment(attachment: &NetworkAttachmentSpec) -> bool {
    valid_reference(&attachment.port_id)
        && attachment.mac.len() == 17
        && attachment.mac.split(':').count() == 6
        && attachment
            .mac
            .split(':')
            .all(|part| part.len() == 2 && part.bytes().all(|byte| byte.is_ascii_hexdigit()))
        && attachment.fixed_ipv4.parse::<std::net::Ipv4Addr>().is_ok()
        && valid_ipv4_cidr(&attachment.subnet_cidr)
        && attachment
            .gateway_ipv4
            .parse::<std::net::Ipv4Addr>()
            .is_ok()
}

fn valid_ipv4_cidr(value: &str) -> bool {
    let Some((address, prefix)) = value.split_once('/') else {
        return false;
    };
    address.parse::<std::net::Ipv4Addr>().is_ok()
        && prefix.parse::<u8>().is_ok_and(|prefix| prefix <= 32)
}

fn has_duplicate_network_ports(attachments: &[NetworkAttachmentSpec]) -> bool {
    attachments.iter().enumerate().any(|(index, attachment)| {
        attachments[..index]
            .iter()
            .any(|prior| prior.port_id == attachment.port_id)
    })
}

/// Validates resolved create identity and shape without the admission expiry
/// fence.
///
/// Expiry fences new transfer admission; it must not prevent replay of an
/// already admitted command: a journaled create was admitted when accepted,
/// and its embedded transfer references expire with the command deadline
/// (seconds after build), so decoding the journal must accept it regardless
/// of age. Rejecting it bricks every later agent restart on the first
/// journaled create (real-host failure at commit 4421013, issue #87: every
/// restart exits "create command resolved inputs are invalid" before any
/// network connect).
fn validate_proto_create_identity(create: &proto::CreateCommand) -> Result<(), AgentError> {
    let Some(resolved) = create.resolved.as_ref() else {
        return Err(AgentError::Protocol(
            "create command resolved inputs are required".to_owned(),
        ));
    };
    if !valid_reference(&create.image_id)
        || !valid_reference(&create.flavor_id)
        || !valid_reference(&resolved.image_artifact_id)
        || !valid_sha256(&resolved.image_sha256)
        || !matches!(resolved.image_format.as_str(), "raw" | "qcow2")
        || !(1..=256).contains(&resolved.vcpus)
        || !(1..=1_048_576).contains(&resolved.memory_mib)
        || !(1..=1_048_576).contains(&resolved.disk_gib)
        || !valid_reference(&resolved.config_drive_artifact_id)
        || !valid_sha256(&resolved.config_drive_sha256)
        || resolved.image_transfer.as_ref().is_none_or(|reference| {
            !valid_reference(&reference.transfer_id) || reference.size_bytes > MAX_ARTIFACT_BYTES
        })
        || resolved
            .config_drive_transfer
            .as_ref()
            .is_none_or(|reference| {
                !valid_reference(&reference.transfer_id)
                    || reference.size_bytes > MAX_ARTIFACT_BYTES
            })
        || resolved.network_attachments.iter().any(|attachment| {
            !valid_network_attachment(&NetworkAttachmentSpec {
                port_id: attachment.port_id.clone(),
                mac: attachment.mac.clone(),
                fixed_ipv4: attachment.fixed_ipv4.clone(),
                subnet_cidr: attachment.subnet_cidr.clone(),
                gateway_ipv4: attachment.gateway_ipv4.clone(),
            })
        })
        || resolved.network_attachments.is_empty()
        || has_duplicate_network_ports(
            &resolved
                .network_attachments
                .iter()
                .map(|attachment| NetworkAttachmentSpec {
                    port_id: attachment.port_id.clone(),
                    mac: attachment.mac.clone(),
                    fixed_ipv4: attachment.fixed_ipv4.clone(),
                    subnet_cidr: attachment.subnet_cidr.clone(),
                    gateway_ipv4: attachment.gateway_ipv4.clone(),
                })
                .collect::<Vec<_>>(),
        )
        || create.network_port_ids.len() != resolved.network_attachments.len()
        || create
            .network_port_ids
            .iter()
            .zip(&resolved.network_attachments)
            .any(|(port_id, attachment)| port_id != &attachment.port_id)
    {
        return Err(AgentError::Protocol(
            "create command resolved inputs are invalid".to_owned(),
        ));
    }
    Ok(())
}

/// Admission-time validation of a create: identity and shape plus the
/// transfer admission expiry fence. The fence must never run on the journal
/// decode/replay path — use `validate_proto_create_identity` there.
fn validate_proto_create(create: &proto::CreateCommand) -> Result<(), AgentError> {
    validate_proto_create_identity(create)?;
    if let Some(reference) = create
        .resolved
        .as_ref()
        .and_then(|resolved| resolved.image_transfer.as_ref())
        && reference.expires_at_unix_ms <= unix_ms()
    {
        return Err(AgentError::Protocol(
            "create command resolved inputs are invalid".to_owned(),
        ));
    }
    if let Some(reference) = create
        .resolved
        .as_ref()
        .and_then(|resolved| resolved.config_drive_transfer.as_ref())
        && reference.expires_at_unix_ms <= unix_ms()
    {
        return Err(AgentError::Protocol(
            "create command resolved inputs are invalid".to_owned(),
        ));
    }
    Ok(())
}

fn matches_stream_identity(
    message_agent_id: &str,
    message_agent_epoch: &str,
    stream_agent_id: &str,
    stream_agent_epoch: &str,
) -> bool {
    message_agent_id == stream_agent_id && message_agent_epoch == stream_agent_epoch
}

fn sha256_hex(bytes: &[u8]) -> String {
    use std::fmt::Write as _;
    let mut digest = String::with_capacity(64);
    for byte in Sha256::digest(bytes) {
        let _ = write!(&mut digest, "{byte:02x}");
    }
    digest
}

fn validate_artifact_dispatch(
    offer: &proto::ArtifactOffer,
    bytes: &[u8],
) -> Result<(), AgentError> {
    let chunk_size = usize::try_from(offer.chunk_size_bytes)
        .map_err(|_| AgentError::Protocol("artifact chunk size is invalid".to_owned()))?;
    let expected_chunks = offer
        .size_bytes
        .div_ceil(u64::from(offer.chunk_size_bytes.max(1)));
    if !valid_reference(&offer.transfer_id)
        || !valid_reference(&offer.command_id)
        || !valid_reference(&offer.operation_id)
        || !valid_reference(&offer.resource_id)
        || !valid_reference(&offer.agent_id)
        || !valid_reference(&offer.artifact_id)
        || !valid_sha256(&offer.sha256)
        || offer.size_bytes == 0
        || offer.size_bytes > MAX_ARTIFACT_BYTES
        || bytes.len() as u64 != offer.size_bytes
        || chunk_size == 0
        || chunk_size > MAX_ARTIFACT_CHUNK_BYTES
        || offer.chunk_count == 0
        || offer.chunk_count > MAX_ARTIFACT_CHUNKS
        || u64::from(offer.chunk_count) != expected_chunks
        || expected_chunks > u64::from(u32::MAX)
        || !matches!(offer.kind, 1 | 2)
        || !matches!(offer.format.as_str(), "raw" | "qcow2" | "iso")
        || (offer.kind == proto::ArtifactKind::ImageBase as i32 && offer.format == "iso")
        || (offer.kind == proto::ArtifactKind::ConfigDriveIso as i32 && offer.format != "iso")
        || offer.expires_at_unix_ms <= unix_ms()
        || sha256_hex(bytes) != offer.sha256
    {
        return Err(AgentError::Protocol(
            "artifact offer or payload is invalid".to_owned(),
        ));
    }
    Ok(())
}

fn validate_register(request: &proto::RegisterRequest) -> Result<(), Box<Status>> {
    if request.agent_id.trim().is_empty()
        || request.agent_id.len() > MAX_AGENT_ID
        || request.agent_epoch.trim().is_empty()
        || request.host_label.len() > crate::types::MAX_HOST_LABEL
        || request.capabilities.is_none()
    {
        return Err(Box::new(Status::invalid_argument(
            "registration is incomplete",
        )));
    }
    let versions = &request.supported_versions;
    if !versions.iter().any(|v| {
        v.major == PROTOCOL_VERSION.major && v.wire_revision == PROTOCOL_VERSION.wire_revision
    }) {
        return Err(Box::new(Status::failed_precondition(
            "no compatible compute-agent protocol version",
        )));
    }
    Ok(())
}

fn unix_ms() -> i64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or_default()
        .as_millis()
        .min(i64::MAX as u128) as i64
}

fn peer_matches_agent(certificate: &[u8], agent_id: &str) -> bool {
    let expected = format!("urn:o3k:compute:agent:{agent_id}");
    certificate_has_uri_san(certificate, expected.as_bytes())
}

/// Finds the URI GeneralName in the Subject Alternative Name extension.
/// TLS has already authenticated the chain and validity period; the strict
/// structural parser performs the protocol's additional identity binding
/// without treating arbitrary certificate bytes as an extension.
fn certificate_has_uri_san(certificate: &[u8], expected: &[u8]) -> bool {
    const SUBJECT_ALT_NAME_OID: &[u8] = &[0x55, 0x1d, 0x11];
    let Some((0x30, certificate, rest)) = der_tlv(certificate) else {
        return false;
    };
    if !rest.is_empty() {
        return false;
    }
    let Some((0x30, tbs, _)) = der_tlv(certificate) else {
        return false;
    };
    let mut fields = tbs;
    while !fields.is_empty() {
        let Some((tag, field, rest)) = der_tlv(fields) else {
            return false;
        };
        fields = rest;
        if tag != 0xa3 {
            continue;
        }
        let Some((0x30, extensions, rest)) = der_tlv(field) else {
            return false;
        };
        if !rest.is_empty() {
            return false;
        }
        let mut extensions = extensions;
        while !extensions.is_empty() {
            let Some((0x30, extension, rest)) = der_tlv(extensions) else {
                return false;
            };
            extensions = rest;
            let Some((0x06, oid, extension)) = der_tlv(extension) else {
                return false;
            };
            let extension_input = extension;
            let Some((tag, _, rest)) = der_tlv(extension_input) else {
                return false;
            };
            let extension = if tag == 0x01 { rest } else { extension_input };
            if oid != SUBJECT_ALT_NAME_OID {
                continue;
            }
            let Some((0x04, value, rest)) = der_tlv(extension) else {
                return false;
            };
            if !rest.is_empty() {
                return false;
            }
            let Some((0x30, names, rest)) = der_tlv(value) else {
                return false;
            };
            if !rest.is_empty() {
                return false;
            }
            let mut names = names;
            while !names.is_empty() {
                let Some((tag, name, rest)) = der_tlv(names) else {
                    return false;
                };
                if tag == 0x86 && name == expected {
                    return true;
                }
                names = rest;
            }
            return false;
        }
    }
    false
}

fn der_tlv(input: &[u8]) -> Option<(u8, &[u8], &[u8])> {
    if input.len() < 2 {
        return None;
    }
    let tag = input[0];
    let length_octet = input[1];
    let (length, header) = if length_octet & 0x80 == 0 {
        (length_octet as usize, 2)
    } else {
        let count = (length_octet & 0x7f) as usize;
        if count == 0 || count > 4 || input.len() < 2 + count {
            return None;
        }
        let mut length = 0_usize;
        for byte in &input[2..2 + count] {
            length = length.checked_mul(256)?.checked_add(*byte as usize)?;
        }
        (length, 2 + count)
    };
    let end = header.checked_add(length)?;
    (end <= input.len()).then(|| (tag, &input[header..end], &input[end..]))
}

fn pem_blocks(input: &[u8], label: &str) -> Result<Vec<Vec<u8>>, AgentError> {
    let text = std::str::from_utf8(input).map_err(|_| AgentError::TlsMaterial)?;
    let begin = format!("-----BEGIN {label}-----");
    let end = format!("-----END {label}-----");
    let mut remaining = text;
    let mut blocks = Vec::new();
    while let Some(start) = remaining.find(&begin) {
        let body = &remaining[start + begin.len()..];
        let finish = body.find(&end).ok_or(AgentError::TlsMaterial)?;
        let encoded: String = body[..finish]
            .chars()
            .filter(|character| !character.is_whitespace())
            .collect();
        blocks.push(
            BASE64
                .decode(encoded)
                .map_err(|_| AgentError::TlsMaterial)?,
        );
        remaining = &body[finish + end.len()..];
    }
    if blocks.is_empty() {
        return Err(AgentError::TlsMaterial);
    }
    Ok(blocks)
}

fn pem_certificates(input: &[u8]) -> Result<Vec<CertificateDer<'static>>, AgentError> {
    pem_blocks(input, "CERTIFICATE")
        .map(|blocks| blocks.into_iter().map(CertificateDer::from).collect())
}

/// Decode the single leaf certificate carried by the bootstrap API. The
/// authorized-agent ledger hashes DER bytes (the same representation exposed
/// by the TLS peer), so hashing the PEM envelope would reject valid joins.
pub fn certificate_der(input: &[u8]) -> Result<Vec<u8>, AgentError> {
    let mut certificates = pem_certificates(input)?;
    if certificates.len() != 1 {
        return Err(AgentError::TlsMaterial);
    }
    Ok(certificates.remove(0).to_vec())
}

fn pem_private_key(input: &[u8]) -> Result<PrivateKeyDer<'static>, AgentError> {
    for (label, constructor) in [
        ("PRIVATE KEY", 0_u8),
        ("RSA PRIVATE KEY", 1_u8),
        ("EC PRIVATE KEY", 2_u8),
    ] {
        if let Ok(mut blocks) = pem_blocks(input, label) {
            let key = blocks.pop().ok_or(AgentError::TlsMaterial)?;
            return Ok(match constructor {
                0 => PrivateKeyDer::Pkcs8(PrivatePkcs8KeyDer::from(key)),
                1 => PrivateKeyDer::Pkcs1(PrivatePkcs1KeyDer::from(key)),
                _ => PrivateKeyDer::Sec1(PrivateSec1KeyDer::from(key)),
            });
        }
    }
    Err(AgentError::TlsMaterial)
}

pub struct ComputeAgentService {
    registry: NodeRegistry,
}

impl ComputeAgentService {
    pub fn new(registry: NodeRegistry) -> Self {
        Self { registry }
    }
}

#[tonic::async_trait]
impl proto::compute_agent_server::ComputeAgent for ComputeAgentService {
    type ControlStream = ReceiverStream<Result<proto::ControlResponse, Status>>;

    async fn control(
        &self,
        request: Request<Streaming<proto::ControlRequest>>,
    ) -> Result<Response<Self::ControlStream>, Status> {
        let mut inbound = request;
        let first = inbound
            .get_mut()
            .message()
            .await?
            .ok_or_else(|| Status::unauthenticated("registration is required"))?;
        let Some(proto::control_request::Body::Register(register)) = first.body else {
            return Err(Status::unauthenticated(
                "registration must be the first message",
            ));
        };
        let Some(certs) = inbound.peer_certs() else {
            return Err(Status::permission_denied("client certificate is required"));
        };
        let Some(certificate) = certs.first() else {
            return Err(Status::permission_denied("client certificate is required"));
        };
        if !peer_matches_agent(certificate.as_ref(), &register.agent_id)
            || !self
                .registry
                .is_authorized(&register.agent_id, certificate.as_ref())
                .await
        {
            return Err(Status::permission_denied(
                "client certificate is not authorized for agent identity",
            ));
        }
        let response = self.registry.register(&register).await?;
        let (tx, rx) = mpsc::channel(32);
        self.registry
            .attach_connection(&register.agent_id, &register.agent_epoch, tx.clone())
            .await?;
        tx.send(Ok(proto::ControlResponse {
            body: Some(proto::control_response::Body::Register(response)),
        }))
        .await
        .map_err(|_| Status::unavailable("response stream closed"))?;
        let registry = self.registry.clone();
        let agent_id = register.agent_id;
        let agent_epoch = register.agent_epoch;
        tokio::spawn(async move {
            while let Ok(Some(message)) = inbound.get_mut().message().await {
                match message.body {
                    Some(proto::control_request::Body::Heartbeat(heartbeat)) => {
                        if !matches_stream_identity(
                            &heartbeat.agent_id,
                            &heartbeat.agent_epoch,
                            &agent_id,
                            &agent_epoch,
                        ) {
                            let _ = tx
                                .send(Err(Status::permission_denied(
                                    "message identity does not match the registered stream",
                                )))
                                .await;
                            break;
                        }
                        match registry.heartbeat(&heartbeat).await {
                            Ok(ack) => {
                                if tx
                                    .send(Ok(proto::ControlResponse {
                                        body: Some(proto::control_response::Body::Heartbeat(ack)),
                                    }))
                                    .await
                                    .is_err()
                                {
                                    break;
                                }
                            }
                            Err(error) => {
                                let _ = tx.send(Err(error)).await;
                                break;
                            }
                        }
                    }
                    Some(proto::control_request::Body::AgentStateAck(ack)) => {
                        if !matches_stream_identity(
                            &ack.agent_id,
                            &ack.agent_epoch,
                            &agent_id,
                            &agent_epoch,
                        ) {
                            let _ = tx
                                .send(Err(Status::permission_denied(
                                    "message identity does not match the registered stream",
                                )))
                                .await;
                            break;
                        }
                        if let Err(error) = registry.acknowledge_state(&ack).await {
                            let _ = tx.send(Err(error)).await;
                            break;
                        }
                    }
                    Some(proto::control_request::Body::Operation(operation)) => {
                        if !matches_stream_identity(
                            &operation.agent_id,
                            &operation.agent_epoch,
                            &agent_id,
                            &agent_epoch,
                        ) {
                            let _ = tx
                                .send(Err(Status::permission_denied(
                                    "message identity does not match the registered stream",
                                )))
                                .await;
                            break;
                        }
                        if !registry
                            .connection_is_current(&agent_id, &agent_epoch)
                            .await
                        {
                            break;
                        }
                        match events::operation_update(operation) {
                            Ok(update) => {
                                registry.publish_event(ProviderAgentEvent::Operation(update))
                            }
                            Err(error) => warn!(
                                %error,
                                "agent operation update rejected at the transport boundary"
                            ),
                        }
                    }
                    Some(proto::control_request::Body::Observation(observation)) => {
                        if !matches_stream_identity(
                            &observation.agent_id,
                            &observation.agent_epoch,
                            &agent_id,
                            &agent_epoch,
                        ) {
                            let _ = tx
                                .send(Err(Status::permission_denied(
                                    "message identity does not match the registered stream",
                                )))
                                .await;
                            break;
                        }
                        if !registry
                            .connection_is_current(&agent_id, &agent_epoch)
                            .await
                        {
                            break;
                        }
                        info!(
                            agent_id = %observation.agent_id,
                            operation_id = %observation.operation_id,
                            resource_id = %observation.resource_id,
                            operation_state = observation.operation_state,
                            console_bytes = observation.console_log_bytes.len(),
                            "agent observation forwarded"
                        );
                        match events::observation(observation) {
                            Ok(observation) => registry.publish_event(
                                ProviderAgentEvent::Observation(Box::new(observation)),
                            ),
                            Err(error) => warn!(
                                %error,
                                "agent observation rejected at the transport boundary"
                            ),
                        }
                    }
                    Some(proto::control_request::Body::CommandAccepted(accepted)) => {
                        if !matches_stream_identity(
                            &accepted.agent_id,
                            &accepted.agent_epoch,
                            &agent_id,
                            &agent_epoch,
                        ) {
                            let _ = tx
                                .send(Err(Status::permission_denied(
                                    "message identity does not match the registered stream",
                                )))
                                .await;
                            break;
                        }
                        if !registry
                            .connection_is_current(&agent_id, &agent_epoch)
                            .await
                        {
                            break;
                        }
                        match events::command_accepted(accepted) {
                            Ok(accepted) => registry
                                .publish_event(ProviderAgentEvent::CommandAccepted(accepted)),
                            Err(error) => warn!(
                                %error,
                                "agent command acceptance rejected at the transport boundary"
                            ),
                        }
                    }
                    Some(proto::control_request::Body::ArtifactAck(ack)) => {
                        if !matches_stream_identity(
                            &ack.agent_id,
                            &ack.agent_epoch,
                            &agent_id,
                            &agent_epoch,
                        ) {
                            let _ = tx
                                .send(Err(Status::permission_denied(
                                    "message identity does not match the registered stream",
                                )))
                                .await;
                            break;
                        }
                        if !registry
                            .connection_is_current(&agent_id, &agent_epoch)
                            .await
                        {
                            break;
                        }
                        match events::artifact_ack(ack) {
                            Ok(ack) => registry.publish_event(ProviderAgentEvent::ArtifactAck(ack)),
                            Err(error) => warn!(
                                %error,
                                "agent artifact acknowledgement rejected at the transport boundary"
                            ),
                        }
                    }
                    Some(proto::control_request::Body::ArtifactStatus(status)) => {
                        if !matches_stream_identity(
                            &status.agent_id,
                            &status.agent_epoch,
                            &agent_id,
                            &agent_epoch,
                        ) {
                            let _ = tx
                                .send(Err(Status::permission_denied(
                                    "message identity does not match the registered stream",
                                )))
                                .await;
                            break;
                        }
                        if !registry
                            .connection_is_current(&agent_id, &agent_epoch)
                            .await
                        {
                            break;
                        }
                        match events::artifact_status(status) {
                            Ok(status) => {
                                registry.publish_event(ProviderAgentEvent::ArtifactStatus(status))
                            }
                            Err(error) => warn!(
                                %error,
                                "agent artifact status rejected at the transport boundary"
                            ),
                        }
                    }
                    Some(proto::control_request::Body::ResyncSnapshot(_)) | None => {}
                    Some(proto::control_request::Body::Error(error)) => {
                        if !registry
                            .connection_is_current(&agent_id, &agent_epoch)
                            .await
                        {
                            break;
                        }
                        match events::protocol_error(error) {
                            Ok(error) => registry.publish_event(ProviderAgentEvent::Error(error)),
                            Err(conversion_error) => warn!(
                                %conversion_error,
                                "agent protocol error rejected at the transport boundary"
                            ),
                        }
                    }
                    Some(proto::control_request::Body::Register(_)) => {
                        let _ = tx
                            .send(Err(Status::invalid_argument("duplicate registration")))
                            .await;
                        break;
                    }
                }
            }
            registry.detach_connection(&agent_id, &agent_epoch).await;
        });
        Ok(Response::new(ReceiverStream::new(rx)))
    }
}

#[derive(Clone)]
pub struct ControlPlaneTls {
    pub server_certificate: PathBuf,
    pub server_private_key: PathBuf,
    pub client_ca_certificate: PathBuf,
}

pub struct ControlPlaneServer {
    pub registry: NodeRegistry,
    pub address: SocketAddr,
    pub tls: ControlPlaneTls,
    pub authorized_agents: Vec<AuthorizedAgent>,
}

impl ControlPlaneServer {
    pub async fn serve(
        self,
        shutdown: impl std::future::Future<Output = ()> + Send + 'static,
    ) -> Result<(), AgentError> {
        let listener = tokio::net::TcpListener::bind(self.address)
            .await
            .map_err(|_| AgentError::InvalidConfiguration("control address cannot be bound"))?;
        self.serve_listener(listener, shutdown).await
    }

    pub async fn serve_listener(
        self,
        listener: tokio::net::TcpListener,
        shutdown: impl std::future::Future<Output = ()> + Send + 'static,
    ) -> Result<(), AgentError> {
        install_crypto_provider();
        for agent in &self.authorized_agents {
            self.registry.authorize_agent(agent.clone()).await?;
        }
        let cert = pem_certificates(
            &fs::read(&self.tls.server_certificate).map_err(|_| AgentError::TlsMaterial)?,
        )?;
        let key = pem_private_key(
            &fs::read(&self.tls.server_private_key).map_err(|_| AgentError::TlsMaterial)?,
        )?;
        let ca = pem_certificates(
            &fs::read(&self.tls.client_ca_certificate).map_err(|_| AgentError::TlsMaterial)?,
        )?;
        let mut roots = RootCertStore::empty();
        for certificate in ca {
            roots
                .add(certificate)
                .map_err(|_| AgentError::TlsMaterial)?;
        }
        let verifier = WebPkiClientVerifier::builder(roots.into())
            .build()
            .map_err(|_| AgentError::TlsMaterial)?;
        let tls = ServerConfig::builder_with_provider(std::sync::Arc::new(
            rustls::crypto::ring::default_provider(),
        ))
        .with_protocol_versions(&[&rustls::version::TLS13])
        .map_err(|_| AgentError::TlsMaterial)?
        .with_client_cert_verifier(verifier)
        .with_single_cert(cert, key)
        .map_err(|_| AgentError::TlsMaterial)?;
        let acceptor = TlsAcceptor::from(std::sync::Arc::new(tls));
        let incoming = TcpListenerStream::new(listener).then(move |connection| {
            let acceptor = acceptor.clone();
            async move {
                match connection {
                    Ok(stream) => acceptor.accept(stream).await.map_err(io::Error::other),
                    Err(error) => Err(error),
                }
            }
        });
        let registry = self.registry.clone();
        let monitor = tokio::spawn(async move {
            let mut tick = time::interval(DEFAULT_HEARTBEAT_INTERVAL);
            loop {
                tick.tick().await;
                registry.mark_unavailable(DEFAULT_LEASE).await;
            }
        });
        let result = Server::builder()
            .add_service(
                proto::compute_agent_server::ComputeAgentServer::new(ComputeAgentService::new(
                    self.registry,
                ))
                .max_decoding_message_size(MAX_MESSAGE_SIZE)
                .max_encoding_message_size(MAX_MESSAGE_SIZE),
            )
            .serve_with_incoming_shutdown(incoming, shutdown)
            .await
            .map_err(AgentError::Transport);
        monitor.abort();
        result
    }
}

#[derive(Clone)]
pub struct AgentClient {
    config: AgentConfig,
    ready: Arc<std::sync::atomic::AtomicBool>,
    /// The agent epoch of the currently live control-plane connection. `None`
    /// before the first successful registration and while reconnecting; set
    /// only after the control plane validated the registration, before
    /// `ready` flips to true (issue #617: the loopback `/readyz` reports it
    /// for stale-epoch diagnosis).
    epoch: Arc<tokio::sync::RwLock<Option<String>>>,
}

#[derive(Debug, Clone, PartialEq)]
pub struct CommandExecutionResult {
    pub state: i32,
    pub error_category: i32,
    /// Provider resource state observed after the command completed.
    /// `UNSPECIFIED` is intentionally invalid for a state-bearing observation.
    pub resource_state: i32,
    pub redacted_message: String,
    pub provider_resource_id: String,
    pub console_log: Option<ConsoleLogResult>,
    pub block_device: Option<proto::BlockDeviceObservation>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ConsoleLogResult {
    pub bytes: Vec<u8>,
    pub offset: u64,
    pub complete: bool,
    pub truncated: bool,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum JournalState {
    Accepted = 1,
    Running = 2,
    Terminal = 3,
    Unknown = 4,
}

impl JournalState {
    fn decode(value: u8) -> Result<Self, AgentError> {
        match value {
            1 => Ok(Self::Accepted),
            2 => Ok(Self::Running),
            3 => Ok(Self::Terminal),
            4 => Ok(Self::Unknown),
            _ => Err(AgentError::Protocol(
                "command journal contains an invalid state".to_owned(),
            )),
        }
    }
}

#[derive(Debug, Clone)]
struct JournalEntry {
    command: proto::Command,
    state: JournalState,
    accepted_sequence: u64,
    last_sequence: u64,
    result: Option<CommandExecutionResult>,
}

#[derive(Debug, Clone)]
enum JournalDecision {
    New { key: String, accepted_sequence: u64 },
    Existing(Box<JournalEntry>),
}

/// A small, bounded, single-writer command journal.
///
/// The journal is a complete snapshot, rewritten to a temporary file and
/// atomically renamed after every state transition. This intentionally keeps
/// recovery independent of SQLite or a second agent-local service while
/// ensuring a torn write can expose only the previous or the next valid
/// snapshot. Records contain the encoded typed command and a bounded terminal
/// result; they never contain host paths, credentials, or arbitrary shell text.
struct CommandJournal {
    path: PathBuf,
    agent_id: String,
    entries: HashMap<String, JournalEntry>,
    next_sequence: u64,
}

impl CommandJournal {
    fn open(identity_path: &Path, agent_id: &str) -> Result<Self, AgentError> {
        let path = command_journal_file(identity_path);
        let (entries, next_sequence) = match fs::read(&path) {
            Ok(bytes) => decode_journal(&bytes, agent_id)?,
            Err(error) if error.kind() == io::ErrorKind::NotFound => (HashMap::new(), 1),
            Err(error) => return Err(AgentError::IdentityStore(error)),
        };
        let mut journal = Self {
            path,
            agent_id: agent_id.to_owned(),
            entries,
            next_sequence,
        };
        let in_flight: Vec<String> = journal
            .entries
            .iter()
            .filter_map(|(key, entry)| {
                matches!(entry.state, JournalState::Accepted | JournalState::Running)
                    .then_some(key.clone())
            })
            .collect();
        for key in &in_flight {
            let entry = journal.entries.get_mut(key).ok_or_else(|| {
                AgentError::Protocol("command journal entry disappeared".to_owned())
            })?;
            entry.state = JournalState::Unknown;
            entry.result = None;
            entry.last_sequence = journal.next_sequence;
            journal.next_sequence = journal.next_sequence.saturating_add(1);
        }
        if !journal.entries.is_empty() && !in_flight.is_empty() {
            journal.persist()?;
        }
        Ok(journal)
    }

    fn accept(&mut self, command: &proto::Command) -> Result<JournalDecision, AgentError> {
        // Admission keeps the transfer expiry fence: a command whose embedded
        // transfer offers already expired must not be admitted.
        validate_command_with_deadline(command, false, true)?;
        let key = journal_key(&command.agent_id, &command.operation_id);
        for entry in self.entries.values() {
            let same_command_id = entry.command.command_id == command.command_id;
            let same_operation = entry.command.operation_id == command.operation_id;
            let same_idempotency = entry.command.idempotency_key == command.idempotency_key;
            if !(same_command_id || same_operation || same_idempotency) {
                continue;
            }
            let equivalent = entry.command.agent_id == command.agent_id
                && entry.command.operation_id == command.operation_id
                && entry.command.resource_id == command.resource_id
                && entry.command.idempotency_key == command.idempotency_key
                && entry.command.payload_fingerprint_sha256 == command.payload_fingerprint_sha256;
            if !equivalent {
                return Err(AgentError::Protocol(
                    "command identity or fingerprint conflicts with durable record".to_owned(),
                ));
            }
            return Ok(JournalDecision::Existing(Box::new(entry.clone())));
        }
        if command.agent_id != self.agent_id {
            return Err(AgentError::Protocol(
                "command agent identity does not match this journal".to_owned(),
            ));
        }
        if command.deadline_unix_ms <= unix_ms() {
            return Err(AgentError::Protocol(
                "command deadline has expired".to_owned(),
            ));
        }
        if self.entries.len() >= MAX_COMMAND_JOURNAL_ENTRIES {
            return Err(AgentError::Protocol(
                "command journal entry limit has been reached".to_owned(),
            ));
        }
        let accepted_sequence = self.next_sequence;
        self.next_sequence = self.next_sequence.saturating_add(1);
        self.entries.insert(
            key.clone(),
            JournalEntry {
                command: command.clone(),
                state: JournalState::Accepted,
                accepted_sequence,
                last_sequence: accepted_sequence,
                result: None,
            },
        );
        if let Err(error) = self.persist() {
            self.entries.remove(&key);
            self.next_sequence = accepted_sequence;
            return Err(error);
        }
        Ok(JournalDecision::New {
            key,
            accepted_sequence,
        })
    }

    fn mark_running(&mut self, key: &str) -> Result<(), AgentError> {
        let entry = self
            .entries
            .get_mut(key)
            .ok_or_else(|| AgentError::Protocol("command journal entry is missing".to_owned()))?;
        if entry.state == JournalState::Accepted {
            entry.state = JournalState::Running;
            self.persist()?;
        }
        Ok(())
    }

    fn complete(
        &mut self,
        key: &str,
        result: CommandExecutionResult,
    ) -> Result<JournalEntry, AgentError> {
        validate_execution_result(&result)?;
        let next_sequence = self.next_sequence;
        let entry = self
            .entries
            .get_mut(key)
            .ok_or_else(|| AgentError::Protocol("command journal entry is missing".to_owned()))?;
        if entry.state == JournalState::Terminal {
            return Ok(entry.clone());
        }
        entry.state = JournalState::Terminal;
        entry.last_sequence = next_sequence;
        entry.result = Some(result);
        self.next_sequence = self.next_sequence.saturating_add(1);
        let completed = entry.clone();
        if let Err(error) = self.persist() {
            self.next_sequence = next_sequence;
            return Err(error);
        }
        Ok(completed)
    }

    fn replay_entries(&self) -> Vec<JournalEntry> {
        let mut entries: Vec<_> = self.entries.values().cloned().collect();
        entries.sort_by_key(|entry| entry.accepted_sequence);
        entries
    }

    /// Returns the last terminal lifecycle-mutation outcome per resource from
    /// the durable journal: for `create`, `start`, `stop`, `reboot`, and
    /// `delete` commands, the recorded provider resource state of the most
    /// recently accepted terminal entry. Resources whose most recent
    /// lifecycle mutation is not terminal are excluded — their convergence is
    /// owned by the control plane's re-drive, never by startup restoration.
    ///
    /// This is the agent-side authority for host-reboot restoration: a host
    /// reboot leaves every qemu domain defined but inactive while the
    /// control plane still reports the durable server state, so the startup
    /// restore starts exactly the domains whose last executed mutation
    /// provably left them running.
    pub fn last_lifecycle_resource_states(&self) -> HashMap<String, (u64, proto::ResourceState)> {
        let mut latest: HashMap<String, (u64, Option<proto::ResourceState>)> = HashMap::new();
        for entry in self.entries.values() {
            if !matches!(
                entry.command.action,
                Some(proto::command::Action::Create(_))
                    | Some(proto::command::Action::Start(_))
                    | Some(proto::command::Action::Stop(_))
                    | Some(proto::command::Action::Reboot(_))
                    | Some(proto::command::Action::Delete(_))
            ) {
                continue;
            }
            let terminal_state = matches!(entry.state, JournalState::Terminal)
                .then(|| entry.result.as_ref())
                .flatten()
                .and_then(|result| proto::ResourceState::try_from(result.resource_state).ok());
            match latest.entry(entry.command.resource_id.clone()) {
                std::collections::hash_map::Entry::Occupied(mut slot) => {
                    if entry.accepted_sequence > slot.get().0 {
                        slot.insert((entry.accepted_sequence, terminal_state));
                    }
                }
                std::collections::hash_map::Entry::Vacant(slot) => {
                    slot.insert((entry.accepted_sequence, terminal_state));
                }
            }
        }
        latest
            .into_iter()
            .filter_map(|(resource_id, (sequence, state))| {
                state.map(|state| (resource_id, (sequence, state)))
            })
            .collect()
    }

    fn persist(&self) -> Result<(), AgentError> {
        let bytes = encode_journal(&self.entries)?;
        atomic_write_command_journal(&self.path, &bytes)
    }
}

/// Opens the durable command journal read-only: the decoded snapshot is
/// returned without the in-flight → unknown mutation that the live journal
/// applies on open. Startup restoration only needs the recorded terminal
/// outcomes, and the live journal is opened separately by the control
/// connection.
fn open_command_journal_read_only(
    identity_path: &Path,
    agent_id: &str,
) -> Result<CommandJournal, AgentError> {
    let path = command_journal_file(identity_path);
    let (entries, next_sequence) = match fs::read(&path) {
        Ok(bytes) => decode_journal(&bytes, agent_id)?,
        Err(error) if error.kind() == io::ErrorKind::NotFound => (HashMap::new(), 1),
        Err(error) => return Err(AgentError::IdentityStore(error)),
    };
    Ok(CommandJournal {
        path,
        agent_id: agent_id.to_owned(),
        entries,
        next_sequence,
    })
}

/// Reads the durable command journal and returns the last terminal
/// lifecycle-mutation resource state per resource for host startup
/// restoration. Read-only: the live journal used by the control connection
/// is opened separately by [`AgentClient::run_with_executor`].
pub fn load_journal_lifecycle_resource_states(
    identity_file: &Path,
    agent_id: &str,
) -> Result<HashMap<String, (u64, proto::ResourceState)>, AgentError> {
    let journal = open_command_journal_read_only(identity_file, agent_id)?;
    Ok(journal.last_lifecycle_resource_states())
}

fn command_journal_file(identity_path: &Path) -> PathBuf {
    identity_path.with_extension(COMMAND_JOURNAL_FILE_EXTENSION)
}

fn journal_key(agent_id: &str, operation_id: &str) -> String {
    format!("{agent_id}\0{operation_id}")
}

fn validate_execution_result(result: &CommandExecutionResult) -> Result<(), AgentError> {
    if !matches!(
        proto::OperationState::try_from(result.state),
        Ok(proto::OperationState::Succeeded)
            | Ok(proto::OperationState::Failed)
            | Ok(proto::OperationState::UnknownOutcome)
    ) || !matches!(
        proto::ResourceState::try_from(result.resource_state),
        Ok(proto::ResourceState::Running)
            | Ok(proto::ResourceState::Stopped)
            | Ok(proto::ResourceState::Deleted)
            | Ok(proto::ResourceState::Error)
    ) || result.redacted_message.len() > MAX_REDACTED_RESULT_BYTES
        || result.provider_resource_id.len() > 128
        || result.console_log.as_ref().is_some_and(|console| {
            console.bytes.len() > o3k_console_limit()
                || console.offset > u64::MAX.saturating_sub(console.bytes.len() as u64)
        })
    {
        return Err(AgentError::Protocol(
            "command execution result exceeds journal bounds".to_owned(),
        ));
    }
    Ok(())
}

fn encode_journal(entries: &HashMap<String, JournalEntry>) -> Result<Vec<u8>, AgentError> {
    if entries.len() > MAX_COMMAND_JOURNAL_ENTRIES {
        return Err(AgentError::Protocol(
            "command journal contains too many entries".to_owned(),
        ));
    }
    let mut sorted: Vec<_> = entries.values().collect();
    sorted.sort_by_key(|entry| entry.accepted_sequence);
    let mut bytes = Vec::new();
    bytes.extend_from_slice(COMMAND_JOURNAL_MAGIC);
    bytes.push(COMMAND_JOURNAL_VERSION);
    push_u32(&mut bytes, sorted.len())?;
    for entry in sorted {
        let record = encode_journal_entry(entry)?;
        if record.len() > MAX_MESSAGE_SIZE + 128 * 1024 {
            return Err(AgentError::Protocol(
                "command journal record is too large".to_owned(),
            ));
        }
        push_u32(&mut bytes, record.len())?;
        bytes.extend_from_slice(&record);
        if bytes.len() > MAX_COMMAND_JOURNAL_BYTES {
            return Err(AgentError::Protocol(
                "command journal exceeds its size limit".to_owned(),
            ));
        }
    }
    Ok(bytes)
}

fn encode_journal_entry(entry: &JournalEntry) -> Result<Vec<u8>, AgentError> {
    let command = entry.command.encode_to_vec();
    if command.is_empty() || command.len() > MAX_MESSAGE_SIZE {
        return Err(AgentError::Protocol(
            "command journal command is too large".to_owned(),
        ));
    }
    if entry.accepted_sequence == 0 || entry.last_sequence < entry.accepted_sequence {
        return Err(AgentError::Protocol(
            "command journal sequence is invalid".to_owned(),
        ));
    }
    if entry.state == JournalState::Terminal && entry.result.is_none() {
        return Err(AgentError::Protocol(
            "terminal command journal record has no result".to_owned(),
        ));
    }
    if entry.state != JournalState::Terminal && entry.result.is_some() {
        return Err(AgentError::Protocol(
            "non-terminal command journal record has a result".to_owned(),
        ));
    }
    let mut record = Vec::new();
    record.push(entry.state as u8);
    push_u64(&mut record, entry.accepted_sequence)?;
    push_u64(&mut record, entry.last_sequence)?;
    push_bytes(&mut record, &command)?;
    match &entry.result {
        Some(result) => {
            record.push(1);
            encode_execution_result(&mut record, result)?;
        }
        None => record.push(0),
    }
    Ok(record)
}

fn encode_execution_result(
    bytes: &mut Vec<u8>,
    result: &CommandExecutionResult,
) -> Result<(), AgentError> {
    validate_execution_result(result)?;
    push_i32(bytes, result.state)?;
    push_i32(bytes, result.error_category)?;
    push_i32(bytes, result.resource_state)?;
    push_bytes(bytes, result.provider_resource_id.as_bytes())?;
    push_bytes(bytes, result.redacted_message.as_bytes())?;
    match &result.console_log {
        Some(console) => {
            bytes.push(1);
            push_u64(bytes, console.offset)?;
            bytes.push(u8::from(console.complete));
            bytes.push(u8::from(console.truncated));
            push_bytes(bytes, &console.bytes)?;
        }
        None => bytes.push(0),
    }
    match &result.block_device {
        Some(block_device) => {
            let encoded = block_device.encode_to_vec();
            if encoded.len() > MAX_BLOCK_DEVICE_RESULT_BYTES {
                return Err(AgentError::Protocol(
                    "command journal block-device result exceeds its bound".to_owned(),
                ));
            }
            bytes.push(1);
            push_bytes(bytes, &encoded)?;
        }
        None => bytes.push(0),
    }
    Ok(())
}

fn push_u32(bytes: &mut Vec<u8>, value: usize) -> Result<(), AgentError> {
    let value = u32::try_from(value).map_err(|_| {
        AgentError::Protocol("command journal length exceeds encoding limit".to_owned())
    })?;
    bytes.extend_from_slice(&value.to_le_bytes());
    Ok(())
}

fn push_u64(bytes: &mut Vec<u8>, value: u64) -> Result<(), AgentError> {
    bytes.extend_from_slice(&value.to_le_bytes());
    Ok(())
}

fn push_i32(bytes: &mut Vec<u8>, value: i32) -> Result<(), AgentError> {
    bytes.extend_from_slice(&value.to_le_bytes());
    Ok(())
}

fn push_bytes(bytes: &mut Vec<u8>, value: &[u8]) -> Result<(), AgentError> {
    push_u32(bytes, value.len())?;
    bytes.extend_from_slice(value);
    Ok(())
}

struct JournalReader<'a> {
    bytes: &'a [u8],
    offset: usize,
}

impl<'a> JournalReader<'a> {
    fn new(bytes: &'a [u8]) -> Self {
        Self { bytes, offset: 0 }
    }

    fn take(&mut self, length: usize) -> Result<&'a [u8], AgentError> {
        let end = self
            .offset
            .checked_add(length)
            .ok_or_else(|| AgentError::Protocol("command journal offset overflow".to_owned()))?;
        let value = self
            .bytes
            .get(self.offset..end)
            .ok_or_else(|| AgentError::Protocol("command journal is truncated".to_owned()))?;
        self.offset = end;
        Ok(value)
    }

    fn u8(&mut self) -> Result<u8, AgentError> {
        Ok(self.take(1)?[0])
    }

    fn u32(&mut self) -> Result<u32, AgentError> {
        Ok(u32::from_le_bytes(self.take(4)?.try_into().map_err(
            |_| AgentError::Protocol("command journal integer is truncated".to_owned()),
        )?))
    }

    fn u64(&mut self) -> Result<u64, AgentError> {
        Ok(u64::from_le_bytes(self.take(8)?.try_into().map_err(
            |_| AgentError::Protocol("command journal integer is truncated".to_owned()),
        )?))
    }

    fn i32(&mut self) -> Result<i32, AgentError> {
        Ok(i32::from_le_bytes(self.take(4)?.try_into().map_err(
            |_| AgentError::Protocol("command journal integer is truncated".to_owned()),
        )?))
    }

    fn bytes(&mut self, maximum: usize) -> Result<Vec<u8>, AgentError> {
        let length = usize::try_from(self.u32()?)
            .map_err(|_| AgentError::Protocol("command journal length is invalid".to_owned()))?;
        if length > maximum {
            return Err(AgentError::Protocol(
                "command journal field exceeds its bound".to_owned(),
            ));
        }
        Ok(self.take(length)?.to_vec())
    }

    fn finished(&self) -> bool {
        self.offset == self.bytes.len()
    }
}

fn decode_journal(
    bytes: &[u8],
    agent_id: &str,
) -> Result<(HashMap<String, JournalEntry>, u64), AgentError> {
    if bytes.len() > MAX_COMMAND_JOURNAL_BYTES || bytes.len() < COMMAND_JOURNAL_MAGIC.len() + 1 + 4
    {
        return Err(AgentError::Protocol(
            "command journal is missing or exceeds its bound".to_owned(),
        ));
    }
    let mut reader = JournalReader::new(bytes);
    if reader.take(COMMAND_JOURNAL_MAGIC.len())? != COMMAND_JOURNAL_MAGIC {
        return Err(AgentError::Protocol(
            "command journal header is invalid".to_owned(),
        ));
    }
    let version = reader.u8()?;
    if !matches!(
        version,
        LEGACY_COMMAND_JOURNAL_VERSION | COMMAND_JOURNAL_VERSION
    ) {
        return Err(AgentError::Protocol(
            "command journal header is invalid".to_owned(),
        ));
    }
    let count = usize::try_from(reader.u32()?)
        .map_err(|_| AgentError::Protocol("command journal entry count is invalid".to_owned()))?;
    if count > MAX_COMMAND_JOURNAL_ENTRIES {
        return Err(AgentError::Protocol(
            "command journal contains too many entries".to_owned(),
        ));
    }
    let mut entries = HashMap::with_capacity(count);
    let mut next_sequence = 1_u64;
    for _ in 0..count {
        let length = usize::try_from(reader.u32()?).map_err(|_| {
            AgentError::Protocol("command journal record length is invalid".to_owned())
        })?;
        if length > MAX_MESSAGE_SIZE + 128 * 1024 {
            return Err(AgentError::Protocol(
                "command journal record exceeds its bound".to_owned(),
            ));
        }
        let record = reader.take(length)?;
        let mut record_reader = JournalReader::new(record);
        let state = JournalState::decode(record_reader.u8()?)?;
        let accepted_sequence = record_reader.u64()?;
        let last_sequence = record_reader.u64()?;
        let command_bytes = record_reader.bytes(MAX_MESSAGE_SIZE)?;
        let command = proto::Command::decode(command_bytes.as_slice()).map_err(|_| {
            AgentError::Protocol("command journal contains an invalid command".to_owned())
        })?;
        // Decode/replay validates identity and integrity without the
        // admission expiry fence: a journaled command was already admitted
        // when accepted, and its embedded transfer offers expire with the
        // command deadline, so rejecting them here would brick every later
        // agent restart on the first journaled create (issue #87, mirror of
        // the #542 artifact-statuses replay fix).
        validate_command_with_deadline(&command, false, false)?;
        if command.agent_id != agent_id
            || accepted_sequence == 0
            || last_sequence < accepted_sequence
        {
            return Err(AgentError::Protocol(
                "command journal identity or sequence is invalid".to_owned(),
            ));
        }
        let result = if record_reader.u8()? == 1 {
            Some(decode_execution_result(
                &mut record_reader,
                version >= COMMAND_JOURNAL_VERSION,
            )?)
        } else {
            None
        };
        if !record_reader.finished()
            || (state == JournalState::Terminal) != result.is_some()
            || (state != JournalState::Terminal && result.is_some())
        {
            return Err(AgentError::Protocol(
                "command journal result state is invalid".to_owned(),
            ));
        }
        let key = journal_key(&command.agent_id, &command.operation_id);
        if entries
            .insert(
                key,
                JournalEntry {
                    command,
                    state,
                    accepted_sequence,
                    last_sequence,
                    result,
                },
            )
            .is_some()
        {
            return Err(AgentError::Protocol(
                "command journal contains duplicate operations".to_owned(),
            ));
        }
        next_sequence = next_sequence.max(last_sequence.saturating_add(1));
    }
    if !reader.finished() {
        return Err(AgentError::Protocol(
            "command journal has trailing bytes".to_owned(),
        ));
    }
    Ok((entries, next_sequence))
}

fn decode_execution_result(
    reader: &mut JournalReader<'_>,
    has_block_device: bool,
) -> Result<CommandExecutionResult, AgentError> {
    let result = CommandExecutionResult {
        state: reader.i32()?,
        error_category: reader.i32()?,
        resource_state: reader.i32()?,
        provider_resource_id: String::from_utf8(reader.bytes(128)?).map_err(|_| {
            AgentError::Protocol("command journal provider identity is invalid".to_owned())
        })?,
        redacted_message: String::from_utf8(reader.bytes(MAX_REDACTED_RESULT_BYTES)?).map_err(
            |_| AgentError::Protocol("command journal result message is invalid".to_owned()),
        )?,
        console_log: if reader.u8()? == 1 {
            let offset = reader.u64()?;
            let complete = reader.u8()? != 0;
            let truncated = reader.u8()? != 0;
            Some(ConsoleLogResult {
                bytes: reader.bytes(o3k_console_limit())?,
                offset,
                complete,
                truncated,
            })
        } else {
            None
        },
        block_device: if has_block_device && reader.u8()? == 1 {
            let encoded = reader.bytes(MAX_BLOCK_DEVICE_RESULT_BYTES)?;
            Some(
                proto::BlockDeviceObservation::decode(encoded.as_slice()).map_err(|_| {
                    AgentError::Protocol(
                        "command journal block-device result is invalid".to_owned(),
                    )
                })?,
            )
        } else {
            None
        },
    };
    validate_execution_result(&result)?;
    Ok(result)
}

fn atomic_write_command_journal(path: &Path, bytes: &[u8]) -> Result<(), AgentError> {
    if bytes.len() > MAX_COMMAND_JOURNAL_BYTES {
        return Err(AgentError::Protocol(
            "command journal exceeds its size limit".to_owned(),
        ));
    }
    if let Some(parent) = path.parent() {
        fs::create_dir_all(parent).map_err(AgentError::IdentityStore)?;
    }
    let temporary = path.with_extension(COMMAND_JOURNAL_TEMP_EXTENSION);
    let mut file = fs::OpenOptions::new();
    file.create(true).truncate(true).write(true);
    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt;
        file.mode(0o600);
    }
    let mut file = file.open(&temporary).map_err(AgentError::IdentityStore)?;
    file.write_all(bytes).map_err(AgentError::IdentityStore)?;
    file.sync_all().map_err(AgentError::IdentityStore)?;
    fs::rename(&temporary, path).map_err(AgentError::IdentityStore)?;
    if let Some(parent) = path.parent() {
        fs::File::open(parent)
            .and_then(|directory| directory.sync_all())
            .map_err(AgentError::IdentityStore)?;
    }
    Ok(())
}

#[async_trait::async_trait]
pub trait CommandExecutor: Send + Sync {
    async fn execute(&self, command: &proto::Command)
    -> Result<CommandExecutionResult, AgentError>;
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum FakeFailureStage {
    Image,
    Network,
    Domain,
}

#[derive(Debug, Clone)]
struct FakeResource {
    fingerprint: String,
    artifacts: Vec<String>,
    active: bool,
    console_log: Vec<u8>,
}

/// Stateful command executor for protocol and failure-recovery tests.
///
/// It models the ownership shape of a host realization without claiming that
/// fake artifacts are libvirt, network, or image evidence. Every successful
/// create owns all staged artifacts; an injected failure removes them in
/// reverse order before returning the generic execution error.
#[derive(Clone, Default)]
pub struct FakeCommandExecutor {
    resources: Arc<Mutex<HashMap<String, FakeResource>>>,
    failure_stage: Arc<Mutex<Option<FakeFailureStage>>>,
    block_devices: Arc<Mutex<HashMap<(String, String), proto::BlockDeviceObservation>>>,
}

impl FakeCommandExecutor {
    pub fn set_failure_stage(&self, stage: Option<FakeFailureStage>) -> Result<(), AgentError> {
        self.failure_stage
            .lock()
            .map_err(|_| AgentError::Protocol("fake executor lock failed".to_owned()))
            .map(|mut value| *value = stage)
    }

    #[must_use]
    pub fn resource_count(&self) -> usize {
        self.resources
            .lock()
            .map(|resources| resources.len())
            .unwrap_or(0)
    }

    #[must_use]
    pub fn artifact_count(&self) -> usize {
        self.resources
            .lock()
            .map(|resources| {
                resources
                    .values()
                    .map(|resource| resource.artifacts.len())
                    .sum()
            })
            .unwrap_or(0)
    }

    fn should_fail(&self, stage: FakeFailureStage) -> Result<bool, AgentError> {
        self.failure_stage
            .lock()
            .map_err(|_| AgentError::Protocol("fake executor lock failed".to_owned()))
            .map(|value| *value == Some(stage))
    }

    fn failure() -> AgentError {
        AgentError::Protocol("fake realization failed".to_owned())
    }
}

#[async_trait::async_trait]
impl CommandExecutor for FakeCommandExecutor {
    async fn execute(
        &self,
        command: &proto::Command,
    ) -> Result<CommandExecutionResult, AgentError> {
        let resource_key = command.resource_id.clone();
        let provider_resource_id = format!("fake-{}", stable_fake_resource_id(&resource_key));
        match command.action.as_ref() {
            Some(proto::command::Action::Create(create)) => {
                validate_proto_create(create)?;
                let mut resources = self
                    .resources
                    .lock()
                    .map_err(|_| AgentError::Protocol("fake executor lock failed".to_owned()))?;
                if let Some(existing) = resources.get(&resource_key) {
                    if existing.fingerprint != command.payload_fingerprint_sha256 {
                        return Err(AgentError::Protocol(
                            "fake create idempotency conflict".to_owned(),
                        ));
                    }
                    return Ok(fake_success(
                        provider_resource_id,
                        proto::ResourceState::Running as i32,
                    ));
                }
                let mut artifacts = Vec::new();
                artifacts.push(format!("image:{}", create.image_id));
                if self.should_fail(FakeFailureStage::Image)? {
                    artifacts.clear();
                    return Err(Self::failure());
                }
                artifacts.extend(
                    create
                        .network_port_ids
                        .iter()
                        .map(|port| format!("network:{port}")),
                );
                if self.should_fail(FakeFailureStage::Network)? {
                    artifacts.clear();
                    return Err(Self::failure());
                }
                artifacts.push(format!("domain:{provider_resource_id}"));
                if self.should_fail(FakeFailureStage::Domain)? {
                    artifacts.clear();
                    return Err(Self::failure());
                }
                resources.insert(
                    resource_key,
                    FakeResource {
                        fingerprint: command.payload_fingerprint_sha256.clone(),
                        artifacts,
                        active: true,
                        console_log: b"fake boot output\n".to_vec(),
                    },
                );
                Ok(fake_success(
                    provider_resource_id,
                    proto::ResourceState::Running as i32,
                ))
            }
            Some(proto::command::Action::Delete(_)) => {
                self.resources
                    .lock()
                    .map_err(|_| AgentError::Protocol("fake executor lock failed".to_owned()))?
                    .remove(&resource_key);
                Ok(fake_success(
                    provider_resource_id,
                    proto::ResourceState::Deleted as i32,
                ))
            }
            Some(proto::command::Action::Inspect(_))
            | Some(proto::command::Action::Start(_))
            | Some(proto::command::Action::Stop(_))
            | Some(proto::command::Action::Reboot(_)) => {
                let mut resources = self
                    .resources
                    .lock()
                    .map_err(|_| AgentError::Protocol("fake executor lock failed".to_owned()))?;
                let resource = resources.get_mut(&resource_key).ok_or_else(Self::failure)?;
                if matches!(
                    command.action.as_ref(),
                    Some(proto::command::Action::Start(_))
                ) {
                    resource.active = true;
                } else if matches!(
                    command.action.as_ref(),
                    Some(proto::command::Action::Stop(_))
                ) {
                    resource.active = false;
                }
                let resource_state = if resource.active {
                    proto::ResourceState::Running as i32
                } else {
                    proto::ResourceState::Stopped as i32
                };
                let mut result = fake_success(provider_resource_id, resource_state);
                if matches!(
                    command.action.as_ref(),
                    Some(proto::command::Action::Inspect(_))
                ) {
                    result.redacted_message = if resource.active {
                        "fake resource is active"
                    } else {
                        "fake resource is stopped"
                    }
                    .to_owned();
                }
                Ok(result)
            }
            Some(proto::command::Action::ConsoleLog(request)) => {
                let resources = self
                    .resources
                    .lock()
                    .map_err(|_| AgentError::Protocol("fake executor lock failed".to_owned()))?;
                let resource = resources.get(&resource_key).ok_or_else(Self::failure)?;
                let start = usize::try_from(request.offset)
                    .unwrap_or(usize::MAX)
                    .min(resource.console_log.len());
                let max_bytes = usize::try_from(request.max_bytes)
                    .unwrap_or(usize::MAX)
                    .min(64 * 1024);
                let end = start
                    .saturating_add(max_bytes)
                    .min(resource.console_log.len());
                Ok(CommandExecutionResult {
                    state: proto::OperationState::Succeeded as i32,
                    error_category: proto::ErrorCategory::Unspecified as i32,
                    resource_state: if resource.active {
                        proto::ResourceState::Running as i32
                    } else {
                        proto::ResourceState::Stopped as i32
                    },
                    redacted_message: "fake console output read".to_owned(),
                    provider_resource_id,
                    console_log: Some(ConsoleLogResult {
                        bytes: resource.console_log[start..end].to_vec(),
                        offset: start as u64,
                        complete: end == resource.console_log.len(),
                        truncated: end < resource.console_log.len(),
                    }),
                    block_device: None,
                })
            }
            Some(proto::command::Action::CollectConnector(_)) => {
                let observation = proto::BlockDeviceObservation {
                    volume_id: String::new(),
                    attachment_id: String::new(),
                    driver_volume_type: String::new(),
                    device_path: String::new(),
                    host_path: String::new(),
                    attached: false,
                    found: true,
                    initiator: "iqn.1993-08.org.debian:01:o3k-fake".to_owned(),
                    host_name: "fake-compute-host".to_owned(),
                    ip_address: "10.0.0.5".to_owned(),
                    iscsi_logged_in: false,
                };
                let mut result =
                    fake_success(provider_resource_id, proto::ResourceState::Running as i32);
                result.block_device = Some(observation);
                Ok(result)
            }
            Some(proto::command::Action::AttachDisk(device)) => {
                if device.driver_volume_type != "iscsi" && device.driver_volume_type != "local" {
                    return Err(AgentError::Protocol(
                        "fake attach disk driver volume type is unsupported".to_owned(),
                    ));
                }
                let key = (resource_key.clone(), device.volume_id.clone());
                let mut block_devices = self
                    .block_devices
                    .lock()
                    .map_err(|_| AgentError::Protocol("fake executor lock failed".to_owned()))?;
                // Idempotent: an already-attached device is returned unchanged.
                if let Some(existing) = block_devices.get(&key) {
                    let mut result =
                        fake_success(provider_resource_id, proto::ResourceState::Running as i32);
                    result.block_device = Some(existing.clone());
                    return Ok(result);
                }
                let host_path = if device.driver_volume_type == "iscsi" {
                    format!(
                        "/dev/sd{}",
                        ["b", "c", "d", "e"][device.target_lun as usize % 4]
                    )
                } else {
                    device.device_path.clone()
                };
                let observation = proto::BlockDeviceObservation {
                    volume_id: device.volume_id.clone(),
                    attachment_id: device.attachment_id.clone(),
                    driver_volume_type: device.driver_volume_type.clone(),
                    device_path: device.device_path.clone(),
                    host_path,
                    attached: true,
                    found: true,
                    initiator: device.initiator.clone(),
                    host_name: String::new(),
                    ip_address: String::new(),
                    iscsi_logged_in: true,
                };
                block_devices.insert(key, observation.clone());
                let mut result =
                    fake_success(provider_resource_id, proto::ResourceState::Running as i32);
                result.block_device = Some(observation);
                Ok(result)
            }
            Some(proto::command::Action::DetachDisk(device)) => {
                let key = (resource_key.clone(), device.volume_id.clone());
                let mut block_devices = self
                    .block_devices
                    .lock()
                    .map_err(|_| AgentError::Protocol("fake executor lock failed".to_owned()))?;
                let previous = block_devices.remove(&key);
                // Repeated detach is idempotent.
                let observation = proto::BlockDeviceObservation {
                    volume_id: device.volume_id.clone(),
                    attachment_id: device.attachment_id.clone(),
                    driver_volume_type: device.driver_volume_type.clone(),
                    device_path: previous
                        .as_ref()
                        .map_or_else(String::new, |value| value.device_path.clone()),
                    host_path: String::new(),
                    attached: false,
                    found: previous.is_some(),
                    initiator: device.initiator.clone(),
                    host_name: String::new(),
                    ip_address: String::new(),
                    iscsi_logged_in: false,
                };
                let mut result =
                    fake_success(provider_resource_id, proto::ResourceState::Running as i32);
                result.block_device = Some(observation);
                Ok(result)
            }
            Some(proto::command::Action::ObserveDisk(observe)) => {
                let key = (resource_key.clone(), observe.volume_id.clone());
                let attached = self
                    .block_devices
                    .lock()
                    .map_err(|_| AgentError::Protocol("fake executor lock failed".to_owned()))?
                    .contains_key(&key);
                let observation = proto::BlockDeviceObservation {
                    volume_id: observe.volume_id.clone(),
                    attachment_id: observe.attachment_id.clone(),
                    driver_volume_type: String::new(),
                    device_path: String::new(),
                    host_path: String::new(),
                    attached,
                    found: attached,
                    initiator: String::new(),
                    host_name: String::new(),
                    ip_address: String::new(),
                    iscsi_logged_in: attached,
                };
                let mut result =
                    fake_success(provider_resource_id, proto::ResourceState::Running as i32);
                result.block_device = Some(observation);
                Ok(result)
            }
            None => Err(Self::failure()),
        }
    }
}

fn stable_fake_resource_id(resource_id: &str) -> String {
    Uuid::new_v5(
        &Uuid::NAMESPACE_URL,
        format!("o3k-fake:{resource_id}").as_bytes(),
    )
    .to_string()
}

fn fake_success(provider_resource_id: String, resource_state: i32) -> CommandExecutionResult {
    CommandExecutionResult {
        state: proto::OperationState::Succeeded as i32,
        error_category: proto::ErrorCategory::Unspecified as i32,
        resource_state,
        redacted_message: "fake operation succeeded".to_owned(),
        provider_resource_id,
        console_log: None,
        block_device: None,
    }
}

/// Returns the stable, payload-free name of a command action for diagnostics.
fn command_action_name(command: &proto::Command) -> &'static str {
    match command.action.as_ref() {
        Some(proto::command::Action::Inspect(_)) => "inspect",
        Some(proto::command::Action::Start(_)) => "start",
        Some(proto::command::Action::Stop(_)) => "stop",
        Some(proto::command::Action::Reboot(_)) => "reboot",
        Some(proto::command::Action::Delete(_)) => "delete",
        Some(proto::command::Action::Create(_)) => "create",
        Some(proto::command::Action::ConsoleLog(_)) => "console_log",
        Some(proto::command::Action::CollectConnector(_)) => "collect_connector",
        Some(proto::command::Action::AttachDisk(_)) => "attach_disk",
        Some(proto::command::Action::DetachDisk(_)) => "detach_disk",
        Some(proto::command::Action::ObserveDisk(_)) => "observe_disk",
        None => "missing",
    }
}

fn observation_from_result(
    agent_id: &str,
    agent_epoch: &str,
    command: &proto::Command,
    result: &CommandExecutionResult,
    observation_sequence: u64,
) -> proto::Observation {
    let console_log = result.console_log.as_ref();
    proto::Observation {
        agent_id: agent_id.to_owned(),
        agent_epoch: agent_epoch.to_owned(),
        resource_id: command.resource_id.clone(),
        provider_resource_id: result.provider_resource_id.clone(),
        operation_id: command.operation_id.clone(),
        operation_state: result.state,
        state: result.resource_state,
        observation_sequence,
        observed_at_unix_ms: unix_ms(),
        redacted_message: result.redacted_message.clone(),
        console_log_bytes: console_log.map_or_else(Vec::new, |value| value.bytes.clone()),
        console_log_offset: console_log.map_or(0, |value| value.offset),
        console_log_complete: console_log.is_some_and(|value| value.complete),
        console_log_truncated: console_log.is_some_and(|value| value.truncated),
        block_device: result.block_device.clone(),
    }
}

struct RejectingCommandExecutor;

#[async_trait::async_trait]
impl CommandExecutor for RejectingCommandExecutor {
    async fn execute(
        &self,
        _command: &proto::Command,
    ) -> Result<CommandExecutionResult, AgentError> {
        Err(AgentError::Protocol(
            "no command executor is configured".to_owned(),
        ))
    }
}

async fn send_command_accepted(
    tx: &mpsc::Sender<proto::ControlRequest>,
    command: &proto::Command,
    agent_id: &str,
    agent_epoch: &str,
    operation_sequence: u64,
) -> Result<(), AgentError> {
    tx.send(proto::ControlRequest {
        body: Some(proto::control_request::Body::CommandAccepted(
            proto::CommandAccepted {
                command_id: command.command_id.clone(),
                operation_id: command.operation_id.clone(),
                state: proto::OperationState::Accepted as i32,
                operation_sequence,
                agent_id: agent_id.to_owned(),
                agent_epoch: agent_epoch.to_owned(),
            },
        )),
    })
    .await
    .map_err(|_| AgentError::Protocol("control stream closed".to_owned()))
}

async fn replay_journal_entries(
    tx: &mpsc::Sender<proto::ControlRequest>,
    journal: &CommandJournal,
    agent_id: &str,
    agent_epoch: &str,
) -> Result<(), AgentError> {
    for entry in journal.replay_entries() {
        replay_journal_entry(tx, &entry, &entry.command, agent_id, agent_epoch).await?;
    }
    Ok(())
}

async fn replay_journal_entry(
    tx: &mpsc::Sender<proto::ControlRequest>,
    entry: &JournalEntry,
    command: &proto::Command,
    agent_id: &str,
    agent_epoch: &str,
) -> Result<(), AgentError> {
    let (state, error_category, provider_resource_id, redacted_message) = match entry.state {
        JournalState::Unknown => (
            proto::OperationState::UnknownOutcome,
            proto::ErrorCategory::UnknownOutcome,
            String::new(),
            "command outcome is unknown after agent restart".to_owned(),
        ),
        JournalState::Terminal => {
            let result = entry.result.as_ref().ok_or_else(|| {
                AgentError::Protocol("terminal command journal result is missing".to_owned())
            })?;
            (
                proto::OperationState::try_from(result.state).map_err(|_| {
                    AgentError::Protocol("journal operation state is invalid".to_owned())
                })?,
                proto::ErrorCategory::try_from(result.error_category).map_err(|_| {
                    AgentError::Protocol("journal error category is invalid".to_owned())
                })?,
                result.provider_resource_id.clone(),
                result.redacted_message.clone(),
            )
        }
        JournalState::Accepted | JournalState::Running => return Ok(()),
    };
    if let Some(result) = entry.result.as_ref() {
        let observation =
            observation_from_result(agent_id, agent_epoch, command, result, entry.last_sequence);
        info!(
            operation_id = %observation.operation_id,
            resource_id = %observation.resource_id,
            operation_state = observation.operation_state,
            console_bytes = observation.console_log_bytes.len(),
            "command observation sent"
        );
        tx.send(proto::ControlRequest {
            body: Some(proto::control_request::Body::Observation(observation)),
        })
        .await
        .map_err(|_| AgentError::Protocol("control stream closed".to_owned()))?;
    }
    tx.send(proto::ControlRequest {
        body: Some(proto::control_request::Body::Operation(
            proto::OperationUpdate {
                operation_id: command.operation_id.clone(),
                resource_id: command.resource_id.clone(),
                state: state as i32,
                error_category: error_category as i32,
                redacted_message,
                operation_sequence: entry.last_sequence,
                provider_resource_id,
                agent_id: agent_id.to_owned(),
                agent_epoch: agent_epoch.to_owned(),
            },
        )),
    })
    .await
    .map_err(|_| AgentError::Protocol("control stream closed".to_owned()))
}

fn protocol_error_for_command(
    command: &proto::Command,
    error: &AgentError,
) -> proto::ProtocolError {
    proto::ProtocolError {
        category: proto::ErrorCategory::InvalidRequest as i32,
        code: "invalid_command".to_owned(),
        redacted_message: error.to_string(),
        operation_id: command.operation_id.clone(),
        retryable: false,
        command_id: command.command_id.clone(),
    }
}

fn artifact_store_root(identity_path: &Path) -> PathBuf {
    identity_path.with_extension(ARTIFACT_STORE_FILE_EXTENSION)
}

fn artifact_store_error() -> AgentError {
    AgentError::Protocol("artifact transfer failed closed".to_owned())
}

fn artifact_offer_is_current(
    offer: &proto::ArtifactOffer,
    agent_id: &str,
) -> Result<(), AgentError> {
    if offer.agent_id != agent_id {
        return Err(AgentError::Protocol(
            "artifact offer identity does not match registration".to_owned(),
        ));
    }
    if offer.expires_at_unix_ms <= unix_ms() {
        return Err(AgentError::Protocol(
            "artifact offer has expired".to_owned(),
        ));
    }
    Ok(())
}

fn artifact_offers_have_same_transfer_identity(
    existing: &proto::ArtifactOffer,
    incoming: &proto::ArtifactOffer,
) -> bool {
    let mut existing = existing.clone();
    let mut incoming = incoming.clone();
    // A retried offer may carry a refreshed command deadline.  The transfer
    // identity and all content/command bindings must remain unchanged; the
    // expiry is the only intentionally mutable field.
    existing.expires_at_unix_ms = 0;
    incoming.expires_at_unix_ms = 0;
    existing == incoming
}

async fn send_artifact_ack(
    tx: &mpsc::Sender<proto::ControlRequest>,
    offer: &proto::ArtifactOffer,
    agent_id: &str,
    agent_epoch: &str,
    receipt: &ArtifactReceipt,
    redacted_message: impl Into<String>,
) -> Result<(), AgentError> {
    tx.send(proto::ControlRequest {
        body: Some(proto::control_request::Body::ArtifactAck(
            proto::ArtifactAck {
                transfer_id: offer.transfer_id.clone(),
                command_id: offer.command_id.clone(),
                operation_id: offer.operation_id.clone(),
                resource_id: offer.resource_id.clone(),
                agent_id: agent_id.to_owned(),
                agent_epoch: agent_epoch.to_owned(),
                contiguous_bytes: receipt.contiguous_bytes,
                next_chunk_index: receipt.next_chunk_index,
                state: receipt.state as i32,
                redacted_message: redacted_message.into(),
            },
        )),
    })
    .await
    .map_err(|_| AgentError::Protocol("control stream closed".to_owned()))
}

async fn reject_artifact(
    tx: &mpsc::Sender<proto::ControlRequest>,
    offer: &proto::ArtifactOffer,
    agent_id: &str,
    agent_epoch: &str,
) -> Result<(), AgentError> {
    if offer.agent_id != agent_id {
        return Ok(());
    }
    let receipt = ArtifactReceipt {
        transfer_id: offer.transfer_id.clone(),
        next_chunk_index: 0,
        contiguous_bytes: 0,
        state: proto::ArtifactTransferState::Rejected,
        path: None,
    };
    send_artifact_ack(
        tx,
        offer,
        agent_id,
        agent_epoch,
        &receipt,
        "artifact transfer rejected",
    )
    .await
}

async fn handle_artifact_response(
    body: proto::control_response::Body,
    store: &ArtifactStore,
    offers: &mut HashMap<String, proto::ArtifactOffer>,
    tx: &mpsc::Sender<proto::ControlRequest>,
    agent_id: &str,
    agent_epoch: &str,
) -> Result<(), AgentError> {
    match body {
        proto::control_response::Body::ArtifactOffer(offer) => {
            if let Err(error) = artifact_offer_is_current(&offer, agent_id) {
                reject_artifact(tx, &offer, agent_id, agent_epoch).await?;
                return Err(error);
            }
            if let Some(existing) = offers.get(&offer.transfer_id)
                && !artifact_offers_have_same_transfer_identity(existing, &offer)
            {
                reject_artifact(tx, &offer, agent_id, agent_epoch).await?;
                return Err(AgentError::Protocol(
                    "artifact offer conflicts with this connection".to_owned(),
                ));
            }
            let receipt = match store.begin(&offer) {
                Ok(receipt) => receipt,
                Err(_) => {
                    reject_artifact(tx, &offer, agent_id, agent_epoch).await?;
                    return Err(artifact_store_error());
                }
            };
            offers.insert(offer.transfer_id.clone(), offer.clone());
            send_artifact_ack(
                tx,
                &offer,
                agent_id,
                agent_epoch,
                &receipt,
                "artifact offer accepted",
            )
            .await
        }
        proto::control_response::Body::ArtifactChunk(chunk) => {
            let offer = offers.get(&chunk.transfer_id).cloned().ok_or_else(|| {
                AgentError::Protocol("artifact chunk has no active offer".to_owned())
            })?;
            if let Err(error) = artifact_offer_is_current(&offer, agent_id) {
                reject_artifact(tx, &offer, agent_id, agent_epoch).await?;
                return Err(error);
            }
            let receipt = match store.accept_chunk(&offer, &chunk) {
                Ok(receipt) => receipt,
                Err(_) => {
                    reject_artifact(tx, &offer, agent_id, agent_epoch).await?;
                    return Err(artifact_store_error());
                }
            };
            send_artifact_ack(
                tx,
                &offer,
                agent_id,
                agent_epoch,
                &receipt,
                "artifact chunk accepted",
            )
            .await
        }
        proto::control_response::Body::ArtifactEnd(end) => {
            let offer = offers.get(&end.transfer_id).cloned().ok_or_else(|| {
                AgentError::Protocol("artifact end has no active offer".to_owned())
            })?;
            if let Err(error) = artifact_offer_is_current(&offer, agent_id) {
                reject_artifact(tx, &offer, agent_id, agent_epoch).await?;
                return Err(error);
            }
            let receipt = match store.finish(&offer, &end) {
                Ok(receipt) => receipt,
                Err(_) => {
                    reject_artifact(tx, &offer, agent_id, agent_epoch).await?;
                    return Err(artifact_store_error());
                }
            };
            send_artifact_ack(
                tx,
                &offer,
                agent_id,
                agent_epoch,
                &receipt,
                "artifact committed",
            )
            .await
        }
        _ => Err(AgentError::Protocol(
            "unexpected artifact response".to_owned(),
        )),
    }
}

impl AgentClient {
    pub fn new(config: AgentConfig) -> Result<Self, AgentError> {
        config.validate()?;
        Ok(Self {
            config,
            ready: Arc::new(std::sync::atomic::AtomicBool::new(false)),
            epoch: Arc::new(tokio::sync::RwLock::new(None)),
        })
    }
    pub fn is_ready(&self) -> bool {
        self.ready.load(std::sync::atomic::Ordering::Acquire)
    }
    /// The agent epoch of the currently live control-plane connection, or
    /// `None` when the agent has not registered yet or is reconnecting.
    pub async fn current_epoch(&self) -> Option<String> {
        self.epoch.read().await.clone()
    }
    pub fn identity_file(&self) -> &Path {
        &self.config.identity_file
    }
    pub fn load_identity(&self) -> Result<String, AgentError> {
        load_or_create_identity(&self.config.identity_file)
    }
    pub async fn run<F>(&self, shutdown: F) -> Result<(), AgentError>
    where
        F: std::future::Future<Output = ()> + Send + 'static,
    {
        self.run_with_executor(shutdown, Arc::new(RejectingCommandExecutor))
            .await
    }

    pub async fn run_with_executor<F>(
        &self,
        shutdown: F,
        executor: Arc<dyn CommandExecutor>,
    ) -> Result<(), AgentError>
    where
        F: std::future::Future<Output = ()> + Send + 'static,
    {
        tokio::pin!(shutdown);
        let agent_id = load_or_create_identity(&self.config.identity_file)?;
        let mut journal = CommandJournal::open(&self.config.identity_file, &agent_id)?;
        let mut delay = Duration::from_millis(250);
        loop {
            self.ready
                .store(false, std::sync::atomic::Ordering::Release);
            *self.epoch.write().await = None;
            let result = self
                .connect_once(&agent_id, shutdown.as_mut(), executor.clone(), &mut journal)
                .await;
            match result {
                Ok(()) => return Ok(()),
                Err(error) => {
                    warn!(error = ?error, "compute-agent control connection lost");
                }
            }
            tokio::select! { () = &mut shutdown => return Ok(()), () = time::sleep(delay) => {} }
            delay = (delay.saturating_mul(2)).min(self.config.max_reconnect_delay);
        }
    }

    async fn connect_once<F>(
        &self,
        agent_id: &str,
        mut shutdown: Pin<&mut F>,
        executor: Arc<dyn CommandExecutor>,
        journal: &mut CommandJournal,
    ) -> Result<(), AgentError>
    where
        F: std::future::Future<Output = ()> + Send,
    {
        let persisted_state =
            load_administrative_state(&administrative_state_file(&self.config.identity_file))?;
        install_crypto_provider();
        let material = self.config.tls.read()?;
        let endpoint_uri = self.config.endpoint.replacen("https://", "http://", 1);
        let endpoint = Endpoint::from_shared(endpoint_uri)
            .map_err(|_| AgentError::InvalidConfiguration("endpoint is invalid"))?
            .connect_timeout(Duration::from_secs(10));
        let mut roots = RootCertStore::empty();
        for certificate in pem_certificates(&material.ca)? {
            roots
                .add(certificate)
                .map_err(|_| AgentError::TlsMaterial)?;
        }
        let client_tls = ClientConfig::builder_with_provider(std::sync::Arc::new(
            rustls::crypto::ring::default_provider(),
        ))
        .with_protocol_versions(&[&rustls::version::TLS13])
        .map_err(|_| AgentError::TlsMaterial)?
        .with_root_certificates(roots)
        .with_client_auth_cert(
            pem_certificates(&material.cert)?,
            pem_private_key(&material.key)?,
        )
        .map_err(|_| AgentError::TlsMaterial)?;
        let connector = TlsConnector::from(std::sync::Arc::new(client_tls));
        let server_name = self.config.server_name.clone();
        let connector_service = service_fn(move |uri: http::Uri| {
            let connector = connector.clone();
            let server_name = server_name.clone();
            async move {
                let authority = uri.authority().ok_or_else(|| {
                    io::Error::new(io::ErrorKind::InvalidInput, "endpoint authority is missing")
                })?;
                let stream = tokio::net::TcpStream::connect(authority.as_str()).await?;
                let name = ServerName::try_from(server_name).map_err(|_| {
                    io::Error::new(io::ErrorKind::InvalidInput, "server name is invalid")
                })?;
                connector
                    .connect(name, stream)
                    .await
                    .map(TokioIo::new)
                    .map_err(io::Error::other)
            }
        });
        let channel = endpoint
            .connect_with_connector(connector_service)
            .await
            .map_err(AgentError::Transport)?;
        let mut client = proto::compute_agent_client::ComputeAgentClient::new(channel)
            .max_decoding_message_size(MAX_MESSAGE_SIZE)
            .max_encoding_message_size(MAX_MESSAGE_SIZE);
        let (tx, rx) = mpsc::channel(32);
        let epoch = Uuid::now_v7().to_string();
        tx.send(proto::ControlRequest {
            body: Some(proto::control_request::Body::Register(
                proto::RegisterRequest {
                    agent_id: agent_id.to_owned(),
                    agent_epoch: epoch.clone(),
                    software_version: self.config.software_version.clone(),
                    host_label: self.config.host_label.clone(),
                    supported_versions: vec![PROTOCOL_VERSION],
                    capabilities: Some(self.config.capabilities.clone()),
                },
            )),
        })
        .await
        .map_err(|_| AgentError::Protocol("control stream closed".to_owned()))?;
        let response = client
            .control(Request::new(ReceiverStream::new(rx)))
            .await
            .map_err(|status| AgentError::Protocol(status.to_string()))?;
        let mut responses = response.into_inner();
        let register = tokio::select! {
            () = &mut shutdown => return Ok(()),
            message = responses.message() => message
                .map_err(|status| AgentError::Protocol(status.to_string()))?
                .ok_or_else(|| AgentError::Protocol("control stream ended before registration".to_owned()))?,
        };
        let register = match register.body {
            Some(proto::control_response::Body::Register(register)) => register,
            _ => {
                return Err(AgentError::Protocol(
                    "registration response is required".to_owned(),
                ));
            }
        };
        validate_register_response(&register, agent_id, &epoch)?;
        // Publish the validated epoch before `ready` flips to true so a
        // concurrent loopback /readyz can never observe ready-without-epoch
        // (issue #617).
        *self.epoch.write().await = Some(epoch.clone());
        let artifact_store =
            ArtifactStore::open(artifact_store_root(&self.config.identity_file), agent_id)
                .map_err(|_| artifact_store_error())?;
        for status in artifact_store
            .artifact_statuses(&epoch)
            .map_err(|_| artifact_store_error())?
        {
            tx.send(proto::ControlRequest {
                body: Some(proto::control_request::Body::ArtifactStatus(status)),
            })
            .await
            .map_err(|_| AgentError::Protocol("control stream closed".to_owned()))?;
        }
        let mut artifact_offers = HashMap::new();
        let state = administrative_state_from_i32(register.desired_state)?;
        persist_administrative_state(
            &administrative_state_file(&self.config.identity_file),
            state,
        )?;
        self.ready.store(true, std::sync::atomic::Ordering::Release);
        let mut sequence = 0_u64;
        // Registration is the fenced control-plane authority for the current
        // epoch; the persisted state is still loaded before transport setup so
        // restart/reconnect rejects corruption and retains the last state until
        // that authoritative response arrives.
        let mut applied_state = if persisted_state == state {
            persisted_state as i32
        } else {
            state as i32
        };
        let mut state_ack_pending = true;
        replay_journal_entries(&tx, journal, agent_id, &epoch).await?;
        let mut interval = time::interval(self.config.heartbeat_interval);
        loop {
            tokio::select! {
                () = &mut shutdown => return Ok(()),
                _ = interval.tick() => { sequence = sequence.saturating_add(1); tx.send(proto::ControlRequest { body: Some(proto::control_request::Body::Heartbeat(proto::Heartbeat { agent_id: agent_id.to_owned(), agent_epoch: epoch.clone(), sequence, sent_at_unix_ms: unix_ms(), state: applied_state, active_operation_count: 0, highest_observation_sequence: 0 })) }).await.map_err(|_| AgentError::Protocol("control stream closed".to_owned()))?; }
                message = responses.message() => match message.map_err(|status| AgentError::Protocol(status.to_string()))? {
                    Some(response) => match response.body {
                        Some(proto::control_response::Body::Register(_)) => {
                            return Err(AgentError::Protocol("duplicate registration".to_owned()));
                        }
                        Some(proto::control_response::Body::Heartbeat(ack)) => {
                            if ack.desired_state != applied_state {
                                let state = administrative_state_from_i32(ack.desired_state)?;
                                persist_administrative_state(
                                    &administrative_state_file(&self.config.identity_file),
                                    state,
                                )?;
                                applied_state = state as i32;
                                state_ack_pending = true;
                            }
                            if state_ack_pending {
                                tx.send(proto::ControlRequest {
                                    body: Some(proto::control_request::Body::AgentStateAck(
                                        proto::AgentStateAck {
                                            agent_id: agent_id.to_owned(),
                                            agent_epoch: epoch.clone(),
                                            applied_state,
                                            transition_sequence: ack.transition_sequence,
                                            active_operation_count: 0,
                                        },
                                    )),
                                })
                                .await
                                .map_err(|_| AgentError::Protocol("control stream closed".to_owned()))?;
                                state_ack_pending = false;
                            }
                        }
                        Some(proto::control_response::Body::Command(command)) => {
                            tracing::warn!(
                                operation_id = %command.operation_id,
                                resource_id = %command.resource_id,
                                action = command_action_name(&command),
                                "agent command received"
                            );
                            if command.agent_id != agent_id || command.agent_epoch != epoch {
                                return Err(AgentError::Protocol(
                                    "command identity does not match registration".to_owned(),
                                ));
                            }
                            let decision = match journal.accept(&command) {
                                Ok(decision) => decision,
                                Err(error @ AgentError::Protocol(_)) => {
                                    warn!(
                                        %error,
                                        operation_id = %command.operation_id,
                                        action = command_action_name(&command),
                                        "command acceptance rejected"
                                    );
                                    tx.send(proto::ControlRequest {
                                        body: Some(proto::control_request::Body::Error(
                                            protocol_error_for_command(&command, &error),
                                        )),
                                    })
                                    .await
                                    .map_err(|_| {
                                        AgentError::Protocol("control stream closed".to_owned())
                                    })?;
                                    continue;
                                }
                                Err(error) => return Err(error),
                            };
                            match decision {
                                JournalDecision::Existing(entry) => {
                                    replay_journal_entry(&tx, &entry, &command, agent_id, &epoch)
                                        .await?;
                                }
                                JournalDecision::New {
                                    key,
                                    accepted_sequence,
                                } => {
                                    info!(
                                        command_id = %command.command_id,
                                        operation_id = %command.operation_id,
                                        resource_id = %command.resource_id,
                                        action = command_action_name(&command),
                                        "command accepted"
                                    );
                                    send_command_accepted(
                                        &tx,
                                        &command,
                                        agent_id,
                                        &epoch,
                                        accepted_sequence,
                                    )
                                    .await?;
                                    journal.mark_running(&key)?;
                                    let result = match executor.execute(&command).await {
                                        Ok(result) => {
                                            info!(
                                                operation_id = %command.operation_id,
                                                action = command_action_name(&command),
                                                state = result.state,
                                                console_bytes = result
                                                    .console_log
                                                    .as_ref()
                                                    .map_or(0, |log| log.bytes.len()),
                                                "command execution completed"
                                            );
                                            result
                                        }
                                        Err(error) => {
                                            tracing::warn!(
                                                %error,
                                                operation_id = %command.operation_id,
                                                action = command_action_name(&command),
                                                "command execution failed"
                                            );
                                            CommandExecutionResult {
                                            state: proto::OperationState::UnknownOutcome as i32,
                                            error_category: proto::ErrorCategory::UnknownOutcome as i32,
                                            resource_state: proto::ResourceState::Error as i32,
                                            redacted_message: "command outcome is unknown".to_owned(),
                                            provider_resource_id: String::new(),
                                            console_log: None,
                                            block_device: None,
                                            }
                                        }
                                    };
                                    let entry = journal.complete(&key, result).inspect_err(
                                        |error| {
                                            tracing::warn!(
                                                %error,
                                                operation_id = %command.operation_id,
                                                "command journal completion persistence failed"
                                            );
                                        },
                                    )?;
                                    replay_journal_entry(
                                        &tx,
                                        &entry,
                                        &command,
                                        agent_id,
                                        &epoch,
                                    )
                                    .await?;
                                }
                            }
                        }
                        Some(proto::control_response::Body::DesiredState(desired)) => {
                            let state = administrative_state_from_i32(desired.state)?;
                            persist_administrative_state(
                                &administrative_state_file(&self.config.identity_file),
                                state,
                            )?;
                            applied_state = state as i32;
                            state_ack_pending = false;
                            tx.send(proto::ControlRequest {
                                body: Some(proto::control_request::Body::AgentStateAck(
                                    proto::AgentStateAck {
                                        agent_id: agent_id.to_owned(),
                                        agent_epoch: epoch.clone(),
                                        applied_state,
                                        transition_sequence: desired.transition_sequence,
                                        active_operation_count: 0,
                                    },
                                )),
                            })
                            .await
                            .map_err(|_| AgentError::Protocol("control stream closed".to_owned()))?;
                        }
                        Some(proto::control_response::Body::ArtifactOffer(offer)) => {
                            handle_artifact_response(
                                proto::control_response::Body::ArtifactOffer(offer),
                                &artifact_store,
                                &mut artifact_offers,
                                &tx,
                                agent_id,
                                &epoch,
                            )
                            .await?;
                        }
                        Some(proto::control_response::Body::ArtifactChunk(chunk)) => {
                            handle_artifact_response(
                                proto::control_response::Body::ArtifactChunk(chunk),
                                &artifact_store,
                                &mut artifact_offers,
                                &tx,
                                agent_id,
                                &epoch,
                            )
                            .await?;
                        }
                        Some(proto::control_response::Body::ArtifactEnd(end)) => {
                            handle_artifact_response(
                                proto::control_response::Body::ArtifactEnd(end),
                                &artifact_store,
                                &mut artifact_offers,
                                &tx,
                                agent_id,
                                &epoch,
                            )
                            .await?;
                        }
                        | Some(proto::control_response::Body::ObservationAck(_))
                        | Some(proto::control_response::Body::Resync(_))
                        | Some(proto::control_response::Body::Error(_)) => {
                            return Err(AgentError::Protocol(
                                "unsupported control response".to_owned(),
                            ));
                        }
                        None => {}
                    },
                    None => return Err(AgentError::Protocol("control stream ended".to_owned())),
                }
            }
        }
    }
}

fn install_crypto_provider() {
    let _ = rustls::crypto::ring::default_provider().install_default();
}

pub fn load_or_create_identity(path: &Path) -> Result<String, AgentError> {
    match fs::read_to_string(path) {
        Ok(value) => {
            let value = value.trim();
            if !value.is_empty()
                && value.len() <= MAX_AGENT_ID
                && !value.chars().any(char::is_whitespace)
            {
                return Ok(value.to_owned());
            }
            return Err(AgentError::InvalidConfiguration(
                "identity file contains an invalid identity",
            ));
        }
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => {}
        Err(error) => return Err(AgentError::IdentityStore(error)),
    }
    if let Some(parent) = path.parent() {
        fs::create_dir_all(parent).map_err(AgentError::IdentityStore)?;
    }
    let value = Uuid::now_v7().to_string();
    let temporary = path.with_extension("tmp");
    fs::write(&temporary, format!("{value}\n")).map_err(AgentError::IdentityStore)?;
    fs::rename(temporary, path).map_err(AgentError::IdentityStore)?;
    Ok(value)
}

pub fn administrative_state_file(identity_path: &Path) -> PathBuf {
    identity_path.with_extension(ADMINISTRATIVE_STATE_FILE_EXTENSION)
}

fn administrative_state_from_i32(value: i32) -> Result<proto::AdministrativeState, AgentError> {
    let state = proto::AdministrativeState::try_from(value)
        .map_err(|_| AgentError::Protocol("administrative state is invalid".to_owned()))?;
    if !valid_admin_state(state as i32) {
        return Err(AgentError::Protocol(
            "administrative state is invalid".to_owned(),
        ));
    }
    Ok(state)
}

fn load_administrative_state(path: &Path) -> Result<proto::AdministrativeState, AgentError> {
    match fs::read_to_string(path) {
        Ok(value) => {
            let value = value.trim();
            let value = value.parse::<i32>().map_err(|_| {
                AgentError::InvalidConfiguration("administrative state file is invalid")
            })?;
            administrative_state_from_i32(value)
        }
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => {
            Ok(proto::AdministrativeState::Enabled)
        }
        Err(error) => Err(AgentError::IdentityStore(error)),
    }
}

fn persist_administrative_state(
    path: &Path,
    state: proto::AdministrativeState,
) -> Result<(), AgentError> {
    if !valid_admin_state(state as i32) {
        return Err(AgentError::InvalidConfiguration(
            "administrative state is invalid",
        ));
    }
    if let Some(parent) = path.parent() {
        fs::create_dir_all(parent).map_err(AgentError::IdentityStore)?;
    }
    let temporary = path.with_extension("state.tmp");
    fs::write(&temporary, format!("{}\n", state as i32)).map_err(AgentError::IdentityStore)?;
    fs::rename(temporary, path).map_err(AgentError::IdentityStore)
}

fn validate_register_response(
    response: &proto::RegisterResponse,
    agent_id: &str,
    agent_epoch: &str,
) -> Result<(), AgentError> {
    if response.agent_id != agent_id || response.agent_epoch != agent_epoch {
        return Err(AgentError::Protocol(
            "registration identity mismatch".to_owned(),
        ));
    }
    if response.selected_version.as_ref() != Some(&PROTOCOL_VERSION) {
        return Err(AgentError::Protocol(
            "registration version mismatch".to_owned(),
        ));
    }
    administrative_state_from_i32(response.desired_state).map(|_| ())
}

#[cfg(test)]
mod tests {
    use super::*;
    use o3k_provider::{
        AgentArtifactStatus, AgentErrorCategory, AgentNodeSnapshot, AgentObservation,
        AgentOperationState, AgentOperationUpdate, ComputeProvider, ConfigDriveRequest,
        CreateInstanceRequest, DeleteInstanceRequest, NetworkAttachmentSpec, Operation,
        ProviderError, ResolvedCreateInputs, ResolvedCreateResolver,
        UnconfiguredCreateArtifactResolver, UnconfiguredResolvedCreateResolver,
    };
    use o3k_store::{ArtifactTransferRecord, ArtifactTransferState, ComputeRepository};
    use std::sync::atomic::Ordering;
    use tokio::sync::RwLock;

    fn capabilities() -> proto::Capabilities {
        proto::Capabilities {
            architecture: "x86_64".to_owned(),
            agent_provider_name: "o3k-compute".to_owned(),
            agent_provider_version: "test".to_owned(),
            flags: vec![proto::CapabilityFlag {
                name: ARTIFACT_TRANSFER_CAPABILITY.to_owned(),
                supported: true,
                bounded_value: String::new(),
            }],
            ..Default::default()
        }
    }
    fn register(id: &str, epoch: &str) -> proto::RegisterRequest {
        proto::RegisterRequest {
            agent_id: id.to_owned(),
            agent_epoch: epoch.to_owned(),
            software_version: "test".to_owned(),
            host_label: "host".to_owned(),
            supported_versions: vec![PROTOCOL_VERSION],
            capabilities: Some(capabilities()),
        }
    }

    #[test]
    fn registration_rejects_protocol_version_without_matching_wire_revision() {
        let mut request = register("node", "epoch");
        request.supported_versions = vec![proto::ProtocolVersion {
            major: PROTOCOL_VERSION.major,
            minor: PROTOCOL_VERSION.minor,
            wire_revision: PROTOCOL_VERSION.wire_revision + 1,
        }];
        assert!(matches!(
            validate_register(&request),
            Err(ref error) if error.code() == tonic::Code::FailedPrecondition
        ));
    }

    #[test]
    fn registration_requires_capabilities_and_identity() {
        let mut request = register("node", "epoch");
        request.capabilities = None;
        assert!(matches!(
            validate_register(&request),
            Err(ref error) if error.code() == tonic::Code::InvalidArgument
        ));

        let request = register("", "epoch");
        assert!(matches!(
            validate_register(&request),
            Err(ref error) if error.code() == tonic::Code::InvalidArgument
        ));
    }

    #[test]
    fn identity_bearing_stream_messages_are_fenced_to_registration() {
        assert!(matches_stream_identity(
            "node-a", "epoch-a", "node-a", "epoch-a"
        ));
        assert!(!matches_stream_identity(
            "node-b", "epoch-a", "node-a", "epoch-a"
        ));
        assert!(!matches_stream_identity(
            "node-a", "epoch-b", "node-a", "epoch-a"
        ));
    }

    #[tokio::test]
    async fn reconnect_reuses_stable_node_and_retains_inventory_on_timeout()
    -> Result<(), Box<dyn std::error::Error>> {
        let registry = NodeRegistry::default();
        registry.register(&register("node", "epoch-1")).await?;
        registry
            .heartbeat(&proto::Heartbeat {
                agent_id: "node".to_owned(),
                agent_epoch: "epoch-1".to_owned(),
                sequence: 1,
                state: proto::AdministrativeState::Enabled as i32,
                ..Default::default()
            })
            .await?;
        registry.register(&register("node", "epoch-2")).await?;
        let nodes = registry.all().await;
        assert_eq!(nodes.len(), 1);
        assert_eq!(nodes[0].agent_epoch, "epoch-2");
        registry.mark_unavailable(Duration::ZERO).await;
        let node = registry.snapshot("node").await.ok_or("node retained")?;
        assert_eq!(node.availability, Availability::Unavailable);
        assert_eq!(node.capabilities.architecture, "x86_64");
        Ok(())
    }

    /// Issue #606: every successful registration must wake the inventory
    /// publisher immediately, so a restarted agent's real capacity is visible
    /// to placement without waiting for the next 5 s tick. A re-registration
    /// (restart) wakes it again.
    #[tokio::test]
    async fn registration_wakes_the_inventory_publisher_notify()
    -> Result<(), Box<dyn std::error::Error>> {
        let registry = NodeRegistry::default();
        let notify = registry.registration_notify();
        registry.register(&register("node", "epoch-1")).await?;
        tokio::time::timeout(Duration::from_millis(100), notify.notified()).await?;
        registry.register(&register("node", "epoch-2")).await?;
        tokio::time::timeout(Duration::from_millis(100), notify.notified()).await?;
        Ok(())
    }

    #[tokio::test]
    async fn replacing_a_connection_fences_the_old_event_stream()
    -> Result<(), Box<dyn std::error::Error>> {
        let registry = NodeRegistry::default();
        registry.register(&register("node", "epoch-1")).await?;
        let (old_sender, _) = mpsc::channel(1);
        registry
            .attach_connection("node", "epoch-1", old_sender)
            .await?;
        assert!(registry.connection_is_current("node", "epoch-1").await);

        registry.register(&register("node", "epoch-2")).await?;
        let (new_sender, _) = mpsc::channel(1);
        registry
            .attach_connection("node", "epoch-2", new_sender)
            .await?;
        assert!(!registry.connection_is_current("node", "epoch-1").await);
        assert!(registry.connection_is_current("node", "epoch-2").await);
        Ok(())
    }

    #[tokio::test]
    async fn current_epoch_lease_blocks_replacement_registration()
    -> Result<(), Box<dyn std::error::Error>> {
        let registry = NodeRegistry::default();
        registry.register(&register("node", "epoch-1")).await?;
        let lease =
            o3k_provider::AgentNodeRegistry::lease_current_epoch(&registry, "node", "epoch-1")
                .await
                .ok_or("current epoch lease")?;

        let replacement_registry = registry.clone();
        let mut replacement = tokio::spawn(async move {
            replacement_registry
                .register(&register("node", "epoch-2"))
                .await
        });
        assert!(
            tokio::time::timeout(Duration::from_millis(50), &mut replacement)
                .await
                .is_err(),
            "replacement epoch became current while the E1 lease was held"
        );
        drop(lease);
        tokio::time::timeout(Duration::from_secs(1), replacement).await???;
        assert_eq!(
            registry
                .snapshot("node")
                .await
                .map(|node| node.agent_epoch)
                .as_deref(),
            Some("epoch-2")
        );
        Ok(())
    }

    #[tokio::test]
    async fn duplicate_or_fenced_heartbeat_is_rejected() -> Result<(), Box<dyn std::error::Error>> {
        let registry = NodeRegistry::default();
        registry.register(&register("node", "epoch")).await?;
        let heartbeat = proto::Heartbeat {
            agent_id: "node".to_owned(),
            agent_epoch: "epoch".to_owned(),
            sequence: 1,
            state: proto::AdministrativeState::Enabled as i32,
            ..Default::default()
        };
        registry.heartbeat(&heartbeat).await?;
        assert!(registry.heartbeat(&heartbeat).await.is_err());
        assert!(
            registry
                .heartbeat(&proto::Heartbeat {
                    agent_id: "node".to_owned(),
                    agent_epoch: "old".to_owned(),
                    sequence: 2,
                    state: proto::AdministrativeState::Enabled as i32,
                    ..Default::default()
                })
                .await
                .is_err()
        );
        Ok(())
    }

    #[tokio::test]
    async fn administrative_state_transition_is_durable_and_acknowledged()
    -> Result<(), Box<dyn std::error::Error>> {
        let registry = NodeRegistry::default();
        registry.register(&register("node", "epoch")).await?;
        let transition = registry
            .set_desired_state("node", proto::AdministrativeState::Draining)
            .await?;
        let ack = registry
            .heartbeat(&proto::Heartbeat {
                agent_id: "node".to_owned(),
                agent_epoch: "epoch".to_owned(),
                sequence: 1,
                state: proto::AdministrativeState::Enabled as i32,
                ..Default::default()
            })
            .await?;
        assert_eq!(
            ack.desired_state,
            proto::AdministrativeState::Draining as i32
        );
        assert_eq!(ack.transition_sequence, transition);
        registry
            .acknowledge_state(&proto::AgentStateAck {
                agent_id: "node".to_owned(),
                agent_epoch: "epoch".to_owned(),
                applied_state: proto::AdministrativeState::Draining as i32,
                transition_sequence: transition,
                active_operation_count: 0,
            })
            .await?;
        assert_eq!(
            registry.snapshot("node").await.ok_or("node")?.applied_state,
            proto::AdministrativeState::Draining as i32
        );
        Ok(())
    }

    #[tokio::test]
    async fn command_dispatch_is_fenced_and_stream_bound() -> Result<(), Box<dyn std::error::Error>>
    {
        let registry = NodeRegistry::default();
        registry.register(&register("node", "epoch")).await?;
        let (sender, mut receiver) = mpsc::channel(1);
        registry.attach_connection("node", "epoch", sender).await?;
        let mut command = build_lifecycle_command(
            LifecycleCommand::Inspect,
            "node",
            "epoch",
            "operation-1",
            "resource-1",
        )?;
        command.command_id = "command-1".to_owned();
        command.idempotency_key = "request-1".to_owned();
        registry.dispatch_command(command.clone()).await?;
        let response = receiver.recv().await.ok_or("command response")??;
        assert!(matches!(
            response.body,
            Some(proto::control_response::Body::Command(received))
                if received.command_id == "command-1"
        ));
        let mut fenced = command;
        fenced.agent_epoch = "old-epoch".to_owned();
        assert!(registry.dispatch_command(fenced).await.is_err());
        Ok(())
    }

    #[tokio::test]
    async fn command_observation_wait_times_out_without_agent_progress()
    -> Result<(), Box<dyn std::error::Error>> {
        let registry = NodeRegistry::default();
        registry.register(&register("node", "epoch")).await?;
        let (sender, _receiver) = mpsc::channel(1);
        registry.attach_connection("node", "epoch", sender).await?;
        let command = build_lifecycle_command(
            LifecycleCommand::Inspect,
            "node",
            "epoch",
            "operation-timeout",
            "resource-1",
        )?;
        let started = std::time::Instant::now();
        let result = registry
            .dispatch_command_and_wait(command, Duration::from_millis(50))
            .await;
        assert!(
            matches!(result, Err(AgentError::Protocol(message)) if message == "agent observation timed out")
        );
        assert!(started.elapsed() >= Duration::from_millis(50));
        Ok(())
    }

    #[tokio::test]
    async fn command_observation_wait_returns_the_matching_observation()
    -> Result<(), Box<dyn std::error::Error>> {
        let registry = NodeRegistry::default();
        registry.register(&register("node", "epoch")).await?;
        let (sender, mut receiver) = mpsc::channel(1);
        registry.attach_connection("node", "epoch", sender).await?;
        let operation_id = "11111111-1111-1111-1111-111111111111";
        let resource_id = "22222222-2222-2222-2222-222222222222";
        let command = build_lifecycle_command(
            LifecycleCommand::Inspect,
            "node",
            "epoch",
            operation_id,
            resource_id,
        )?;
        let waiting = {
            let registry = registry.clone();
            tokio::spawn(async move {
                registry
                    .dispatch_command_and_wait(command, Duration::from_secs(5))
                    .await
            })
        };
        // Receiving the dispatched command proves the waiter subscribed before
        // dispatching, so the observation published now cannot be missed.
        let _dispatched = receiver.recv().await.ok_or("dispatched command")??;
        registry.publish_event(ProviderAgentEvent::Observation(Box::new(
            o3k_provider::AgentObservation {
                agent_id: "node".to_owned(),
                agent_epoch: "epoch".to_owned(),
                resource_id: Uuid::parse_str(resource_id)?,
                provider_resource_id: None,
                operation_id: Uuid::parse_str(operation_id)?,
                state: o3k_provider::InstanceState::Creating,
                operation_state: o3k_provider::AgentOperationState::Succeeded,
                observation_sequence: 1,
                observed_at_unix_ms: 0,
                redacted_message: None,
                console_log_bytes: Vec::new(),
                console_log_offset: 0,
                console_log_complete: false,
                console_log_truncated: false,
                block_device: None,
            },
        )));
        let observation = waiting.await??;
        assert_eq!(observation.operation_id, Uuid::parse_str(operation_id)?);
        Ok(())
    }

    #[tokio::test]
    async fn command_observation_wait_accepts_current_epoch_replay_after_reconnect()
    -> Result<(), Box<dyn std::error::Error>> {
        let registry = NodeRegistry::default();
        registry.register(&register("node", "epoch-1")).await?;
        let (old_sender, mut old_receiver) = mpsc::channel(1);
        registry
            .attach_connection("node", "epoch-1", old_sender)
            .await?;
        let operation_id = "33333333-3333-3333-3333-333333333333";
        let resource_id = "44444444-4444-4444-4444-444444444444";
        let command = build_lifecycle_command(
            LifecycleCommand::Inspect,
            "node",
            "epoch-1",
            operation_id,
            resource_id,
        )?;
        let waiting = {
            let registry = registry.clone();
            tokio::spawn(async move {
                registry
                    .dispatch_command_and_wait(command, Duration::from_secs(5))
                    .await
            })
        };
        let _dispatched = old_receiver.recv().await.ok_or("dispatched command")??;

        // The old stream is replaced before its terminal journal replay is
        // observed. Its evidence must remain fenced even though the command
        // identities match.
        registry.register(&register("node", "epoch-2")).await?;
        let (new_sender, _new_receiver) = mpsc::channel(1);
        registry
            .attach_connection("node", "epoch-2", new_sender)
            .await?;
        let operation_uuid = Uuid::parse_str(operation_id)?;
        let resource_uuid = Uuid::parse_str(resource_id)?;
        let observation = |epoch: &str| o3k_provider::AgentObservation {
            agent_id: "node".to_owned(),
            agent_epoch: epoch.to_owned(),
            resource_id: resource_uuid,
            provider_resource_id: None,
            operation_id: operation_uuid,
            state: o3k_provider::InstanceState::Creating,
            operation_state: o3k_provider::AgentOperationState::Succeeded,
            observation_sequence: 1,
            observed_at_unix_ms: 0,
            redacted_message: None,
            console_log_bytes: Vec::new(),
            console_log_offset: 0,
            console_log_complete: false,
            console_log_truncated: false,
            block_device: None,
        };
        registry.publish_event(ProviderAgentEvent::Observation(Box::new(observation(
            "epoch-1",
        ))));
        tokio::time::sleep(Duration::from_millis(20)).await;
        assert!(!waiting.is_finished(), "stale epoch completed the waiter");

        registry.publish_event(ProviderAgentEvent::Observation(Box::new(observation(
            "epoch-2",
        ))));
        let accepted = waiting.await??;
        assert_eq!(accepted.agent_epoch, "epoch-2");
        Ok(())
    }

    #[test]
    fn command_action_names_are_stable_for_diagnostics() -> Result<(), Box<dyn std::error::Error>> {
        for (action, expected) in [
            (LifecycleCommand::Inspect, "inspect"),
            (LifecycleCommand::Start, "start"),
            (LifecycleCommand::Stop, "stop"),
            (LifecycleCommand::HardReboot, "reboot"),
            (LifecycleCommand::Delete, "delete"),
        ] {
            let command =
                build_lifecycle_command(action, "node", "epoch", "operation-1", "resource-1")?;
            assert_eq!(command_action_name(&command), expected);
        }
        let console =
            build_console_log_command("node", "epoch", "operation-1", "resource-1", 0, 1024)?;
        assert_eq!(command_action_name(&console), "console_log");
        let mut missing = console;
        missing.action = None;
        assert_eq!(command_action_name(&missing), "missing");
        Ok(())
    }

    #[tokio::test]
    async fn artifact_dispatch_sends_bounded_sequential_messages()
    -> Result<(), Box<dyn std::error::Error>> {
        let registry = NodeRegistry::default();
        registry.register(&register("node", "epoch")).await?;
        let (sender, mut receiver) = mpsc::channel(8);
        registry.attach_connection("node", "epoch", sender).await?;
        let (offer, data) = test_artifact_offer("node");

        registry
            .dispatch_artifact(offer.clone(), data.clone())
            .await?;

        let offered = receiver.recv().await.ok_or("artifact offer")??;
        assert!(matches!(
            offered.body,
            Some(proto::control_response::Body::ArtifactOffer(received))
                if received == offer
        ));
        let chunk = receiver.recv().await.ok_or("artifact chunk")??;
        assert!(matches!(
            chunk.body,
            Some(proto::control_response::Body::ArtifactChunk(received))
                if received.transfer_id == offer.transfer_id
                    && received.chunk_index == 0
                    && received.offset_bytes == 0
                    && received.data == data
                    && received.chunk_sha256 == offer.sha256
        ));
        let end = receiver.recv().await.ok_or("artifact end")??;
        assert!(matches!(
            end.body,
            Some(proto::control_response::Body::ArtifactEnd(received))
                if received.transfer_id == offer.transfer_id
                    && received.sha256 == offer.sha256
                    && received.size_bytes == offer.size_bytes
        ));
        Ok(())
    }

    #[tokio::test]
    async fn artifact_dispatch_allows_two_transfers_but_admits_no_third()
    -> Result<(), Box<dyn std::error::Error>> {
        assert_eq!(MAX_CONCURRENT_ARTIFACT_TRANSFERS_PER_AGENT, 2);
        assert_eq!(MAX_IN_FLIGHT_ARTIFACT_CHUNKS_PER_TRANSFER, 4);

        let registry = NodeRegistry::default();
        registry.register(&register("node", "epoch")).await?;
        let (sender, mut receiver) = mpsc::channel(1);
        registry.attach_connection("node", "epoch", sender).await?;
        let (mut first, data) = test_artifact_offer("node");
        first.transfer_id = "transfer-first".to_owned();
        let (mut second, _) = test_artifact_offer("node");
        second.transfer_id = "transfer-second".to_owned();
        let (mut third, _) = test_artifact_offer("node");
        third.transfer_id = "transfer-third".to_owned();

        let first_task = {
            let registry = registry.clone();
            let data = data.clone();
            tokio::spawn(async move { registry.dispatch_artifact(first, data).await })
        };
        let second_task = {
            let registry = registry.clone();
            let data = data.clone();
            tokio::spawn(async move { registry.dispatch_artifact(second, data).await })
        };

        let mut offers = 0;
        while offers < 2 {
            let response = receiver.recv().await.ok_or("artifact response")??;
            if matches!(
                response.body,
                Some(proto::control_response::Body::ArtifactOffer(_))
            ) {
                offers += 1;
            }
        }

        let third_result = tokio::time::timeout(
            Duration::from_millis(100),
            registry.dispatch_artifact(third, data.clone()),
        )
        .await;
        assert!(
            third_result.is_err(),
            "third transfer bypassed the per-agent bound"
        );

        let mut ends = 0;
        while ends < 2 {
            let response = receiver.recv().await.ok_or("artifact response")??;
            if matches!(
                response.body,
                Some(proto::control_response::Body::ArtifactEnd(_))
            ) {
                ends += 1;
            }
        }
        first_task.await??;
        second_task.await??;

        Ok(())
    }

    #[tokio::test]
    async fn artifact_dispatch_resume_skips_authenticated_prefix()
    -> Result<(), Box<dyn std::error::Error>> {
        let registry = NodeRegistry::default();
        registry.register(&register("node", "epoch")).await?;
        let (sender, mut receiver) = mpsc::channel(8);
        registry.attach_connection("node", "epoch", sender).await?;
        let (mut offer, _) = test_artifact_offer("node");
        let data = b"abcdefgh".to_vec();
        offer.size_bytes = data.len() as u64;
        offer.chunk_size_bytes = 4;
        offer.chunk_count = 2;
        offer.sha256 = sha256_hex(&data);

        registry
            .dispatch_artifact_from(offer.clone(), data, 1)
            .await?;
        let _ = receiver.recv().await.ok_or("artifact offer")??;
        let chunk = receiver.recv().await.ok_or("resumed artifact chunk")??;
        assert!(matches!(
            chunk.body,
            Some(proto::control_response::Body::ArtifactChunk(received))
                if received.chunk_index == 1
                    && received.offset_bytes == 4
                    && received.data == b"efgh"
        ));
        let end = receiver.recv().await.ok_or("artifact end")??;
        assert!(matches!(
            end.body,
            Some(proto::control_response::Body::ArtifactEnd(_))
        ));
        Ok(())
    }

    #[tokio::test]
    async fn artifact_dispatch_waits_for_matching_commit_ack()
    -> Result<(), Box<dyn std::error::Error>> {
        let registry = NodeRegistry::default();
        registry.register(&register("node", "epoch")).await?;
        let (sender, mut receiver) = mpsc::channel(8);
        registry.attach_connection("node", "epoch", sender).await?;
        let (offer, data) = test_artifact_offer("node");
        let publisher = registry.clone();
        let expected = offer.clone();
        tokio::spawn(async move {
            for _ in 0..3 {
                receiver.recv().await;
            }
            let operation_id = expected.operation_id.parse::<uuid::Uuid>();
            let resource_id = expected.resource_id.parse::<uuid::Uuid>();
            let (operation_id, resource_id) = match (operation_id, resource_id) {
                (Ok(operation_id), Ok(resource_id)) => (operation_id, resource_id),
                _ => return,
            };
            publisher.publish_event(ProviderAgentEvent::ArtifactAck(
                o3k_provider::AgentArtifactAck {
                    transfer_id: expected.transfer_id,
                    command_id: expected.command_id,
                    operation_id,
                    resource_id,
                    agent_id: expected.agent_id,
                    agent_epoch: "epoch".to_owned(),
                    contiguous_bytes: expected.size_bytes,
                    next_chunk_index: expected.chunk_count,
                    state: o3k_provider::ArtifactTransferState::Committed,
                    redacted_message: None,
                },
            ));
        });

        let ack = registry
            .dispatch_artifact_and_wait(offer, data, Duration::from_secs(1))
            .await?;
        assert_eq!(ack.state, o3k_provider::ArtifactTransferState::Committed);
        Ok(())
    }

    #[tokio::test]
    async fn artifact_dispatch_rejects_payload_and_fenced_offer()
    -> Result<(), Box<dyn std::error::Error>> {
        let registry = NodeRegistry::default();
        registry.register(&register("node", "epoch")).await?;
        let (sender, _receiver) = mpsc::channel(1);
        registry.attach_connection("node", "epoch", sender).await?;
        let (mut offer, data) = test_artifact_offer("node");
        offer.agent_id = "other-node".to_owned();
        assert!(registry.dispatch_artifact(offer, data).await.is_err());

        let (offer, mut data) = test_artifact_offer("node");
        data[0] = b'X';
        assert!(registry.dispatch_artifact(offer, data).await.is_err());
        Ok(())
    }

    #[tokio::test]
    async fn artifact_transfer_requires_negotiated_capability()
    -> Result<(), Box<dyn std::error::Error>> {
        let registry = NodeRegistry::default();
        let mut request = register("node", "epoch");
        if let Some(capabilities) = request.capabilities.as_mut() {
            capabilities.flags.clear();
        }
        registry.register(&request).await?;
        let (sender, _receiver) = mpsc::channel(1);
        registry.attach_connection("node", "epoch", sender).await?;
        let (offer, data) = test_artifact_offer("node");
        let error = registry.dispatch_artifact(offer, data).await;
        assert!(error.is_err());
        if let Err(error) = error {
            assert!(error.to_string().contains("not negotiated"));
        }
        Ok(())
    }

    fn valid_create_spec() -> CreateCommandSpec {
        CreateCommandSpec {
            agent_id: "node".to_owned(),
            agent_epoch: "epoch".to_owned(),
            project_id: "project".to_owned(),
            operation_id: Uuid::new_v5(&Uuid::NAMESPACE_URL, b"fake-operation").to_string(),
            resource_id: Uuid::new_v5(&Uuid::NAMESPACE_URL, b"fake-resource").to_string(),
            idempotency_key: "fake-create".to_owned(),
            deadline_unix_ms: unix_ms().saturating_add(10_000),
            image_id: "image-1".to_owned(),
            flavor_id: "flavor-1".to_owned(),
            image_artifact_id: "image-artifact-1".to_owned(),
            image_sha256: "a".repeat(64),
            image_format: "qcow2".to_owned(),
            vcpus: 1,
            memory_mib: 512,
            disk_gib: 10,
            config_drive_artifact_id: "config-drive-1".to_owned(),
            config_drive_sha256: "b".repeat(64),
            network_attachments: vec![NetworkAttachmentSpec {
                port_id: "port-1".to_owned(),
                mac: "02:00:00:00:00:01".to_owned(),
                fixed_ipv4: "192.0.2.10".to_owned(),
                subnet_cidr: "192.0.2.0/24".to_owned(),
                gateway_ipv4: "192.0.2.1".to_owned(),
            }],
        }
    }

    fn fake_create_command() -> Result<proto::Command, AgentError> {
        build_create_command(valid_create_spec())
    }

    #[test]
    fn resolved_create_inputs_reject_paths_digests_and_duplicate_ports() {
        let mut invalid = valid_create_spec();
        invalid.image_artifact_id = "/var/lib/o3k/image.qcow2".to_owned();
        assert!(build_create_command(invalid).is_err());

        let mut invalid = valid_create_spec();
        invalid.image_sha256 = "not-a-sha256".to_owned();
        assert!(build_create_command(invalid).is_err());

        let mut invalid = valid_create_spec();
        invalid.network_attachments.push(NetworkAttachmentSpec {
            port_id: "port-1".to_owned(),
            mac: "02:00:00:00:00:02".to_owned(),
            fixed_ipv4: "192.0.2.11".to_owned(),
            subnet_cidr: "192.0.2.0/24".to_owned(),
            gateway_ipv4: "192.0.2.1".to_owned(),
        });
        assert!(build_create_command(invalid).is_err());

        let mut invalid = valid_create_spec();
        invalid.network_attachments.clear();
        assert!(build_create_command(invalid).is_err());
    }

    #[test]
    fn create_command_accepts_scoped_idempotency_keys_with_resource_paths() {
        let mut spec = valid_create_spec();
        spec.idempotency_key = "scope:create:server/resource".to_owned();
        assert!(build_create_command(spec).is_ok());

        let mut invalid = valid_create_spec();
        invalid.idempotency_key = "scope:create:server/resource with spaces".to_owned();
        assert!(build_create_command(invalid).is_err());
    }

    #[test]
    fn create_command_carries_deterministic_artifact_transfer_identities() -> Result<(), AgentError>
    {
        let command = fake_create_command()?;
        let Some(proto::command::Action::Create(create)) = command.action.as_ref() else {
            return Err(AgentError::Protocol("expected create action".to_owned()));
        };
        let Some(resolved) = create.resolved.as_ref() else {
            return Err(AgentError::Protocol("expected resolved inputs".to_owned()));
        };
        assert_eq!(
            resolved
                .image_transfer
                .as_ref()
                .map(|reference| reference.transfer_id.clone())
                .unwrap_or_default(),
            deterministic_artifact_transfer_id(
                &command.command_id,
                proto::ArtifactKind::ImageBase,
                "image-artifact-1",
            )
        );
        assert_eq!(
            resolved
                .config_drive_transfer
                .as_ref()
                .map(|reference| reference.transfer_id.clone())
                .unwrap_or_default(),
            deterministic_artifact_transfer_id(
                &command.command_id,
                proto::ArtifactKind::ConfigDriveIso,
                "config-drive-1",
            )
        );
        Ok(())
    }

    #[test]
    fn proto_create_rejects_missing_or_expired_transfer_references() -> Result<(), AgentError> {
        let mut command = fake_create_command()?;
        let Some(proto::command::Action::Create(create)) = command.action.as_mut() else {
            return Err(AgentError::Protocol("expected create action".to_owned()));
        };
        let Some(resolved) = create.resolved.as_mut() else {
            return Err(AgentError::Protocol("expected resolved inputs".to_owned()));
        };
        resolved.image_transfer = None;
        assert!(validate_proto_create(create).is_err());

        let mut command = fake_create_command()?;
        let Some(proto::command::Action::Create(create)) = command.action.as_mut() else {
            return Err(AgentError::Protocol("expected create action".to_owned()));
        };
        let Some(resolved) = create.resolved.as_mut() else {
            return Err(AgentError::Protocol("expected resolved inputs".to_owned()));
        };
        if let Some(reference) = resolved.image_transfer.as_mut() {
            reference.expires_at_unix_ms = unix_ms().saturating_sub(1);
        }
        assert!(validate_proto_create(create).is_err());
        Ok(())
    }

    #[tokio::test]
    async fn fake_create_is_idempotent_and_delete_is_absent_safe()
    -> Result<(), Box<dyn std::error::Error>> {
        let executor = FakeCommandExecutor::default();
        let command = fake_create_command()?;
        let first = executor.execute(&command).await?;
        let second = executor.execute(&command).await?;
        assert_eq!(first, second);
        assert_eq!(executor.resource_count(), 1);
        assert_eq!(executor.artifact_count(), 3);

        let mut changed = command.clone();
        changed.payload_fingerprint_sha256 = "changed-fingerprint".to_owned();
        assert!(executor.execute(&changed).await.is_err());
        let delete = proto::Command {
            action: Some(proto::command::Action::Delete(proto::DeleteCommand {})),
            ..command
        };
        executor.execute(&delete).await?;
        executor.execute(&delete).await?;
        assert_eq!(executor.resource_count(), 0);
        assert_eq!(executor.artifact_count(), 0);
        Ok(())
    }

    #[tokio::test]
    async fn fake_executor_rejects_unresolved_create_commands() -> Result<(), AgentError> {
        let executor = FakeCommandExecutor::default();
        let mut command = fake_create_command()?;
        if let Some(proto::command::Action::Create(create)) = command.action.as_mut() {
            create.resolved = None;
        }
        assert!(executor.execute(&command).await.is_err());
        assert_eq!(executor.resource_count(), 0);
        Ok(())
    }

    #[tokio::test]
    async fn fake_executor_reads_bounded_console_output() -> Result<(), AgentError> {
        let executor = FakeCommandExecutor::default();
        let create = fake_create_command()?;
        executor.execute(&create).await?;
        let mut console = create;
        console.action = Some(proto::command::Action::ConsoleLog(
            proto::ConsoleLogCommand {
                offset: 5,
                max_bytes: 4,
            },
        ));
        let result = executor.execute(&console).await?;
        let output = result.console_log.ok_or_else(|| {
            AgentError::Protocol("fake console output was not returned".to_owned())
        })?;
        assert_eq!(output.bytes, b"boot");
        assert_eq!(output.offset, 5);
        assert!(output.truncated);
        assert!(!output.complete);
        Ok(())
    }

    #[tokio::test]
    async fn successful_command_results_become_complete_observations()
    -> Result<(), Box<dyn std::error::Error>> {
        let executor = FakeCommandExecutor::default();
        let create = fake_create_command()?;
        executor.execute(&create).await?;

        let mut start = create.clone();
        start.operation_id = "start-operation".to_owned();
        start.action = Some(proto::command::Action::Start(proto::StartCommand {}));
        let lifecycle_result = executor.execute(&start).await?;
        let lifecycle_observation =
            observation_from_result("node", "epoch", &start, &lifecycle_result, 7);
        assert_eq!(lifecycle_observation.operation_id, "start-operation");
        assert_eq!(lifecycle_observation.resource_id, start.resource_id);
        assert_eq!(
            lifecycle_observation.provider_resource_id,
            lifecycle_result.provider_resource_id
        );
        assert_eq!(
            lifecycle_observation.operation_state,
            proto::OperationState::Succeeded as i32
        );
        assert_eq!(
            lifecycle_observation.state,
            proto::ResourceState::Running as i32
        );
        assert!(lifecycle_observation.console_log_bytes.is_empty());
        assert_eq!(lifecycle_observation.console_log_offset, 0);
        assert!(!lifecycle_observation.console_log_complete);
        assert!(!lifecycle_observation.console_log_truncated);

        let mut console = create;
        console.operation_id = "console-operation".to_owned();
        console.action = Some(proto::command::Action::ConsoleLog(
            proto::ConsoleLogCommand {
                offset: 5,
                max_bytes: 4,
            },
        ));
        let console_result = executor.execute(&console).await?;
        let console_observation =
            observation_from_result("node", "epoch", &console, &console_result, 8);
        assert_eq!(
            console_observation.state,
            proto::ResourceState::Running as i32
        );
        assert_eq!(console_observation.console_log_bytes, b"boot");
        assert_eq!(console_observation.console_log_offset, 5);
        assert!(!console_observation.console_log_complete);
        assert!(console_observation.console_log_truncated);
        Ok(())
    }

    #[tokio::test]
    async fn terminal_failed_result_is_reported_as_failed_not_unknown()
    -> Result<(), Box<dyn std::error::Error>> {
        let command = fake_create_command()?;
        let result = CommandExecutionResult {
            state: proto::OperationState::Failed as i32,
            error_category: proto::ErrorCategory::Terminal as i32,
            resource_state: proto::ResourceState::Error as i32,
            redacted_message: "definitive pre-definition failure".to_owned(),
            provider_resource_id: String::new(),
            console_log: None,
            block_device: None,
        };
        let entry = JournalEntry {
            command: command.clone(),
            state: JournalState::Terminal,
            accepted_sequence: 1,
            last_sequence: 2,
            result: Some(result),
        };
        let (tx, mut rx) = mpsc::channel(4);
        replay_journal_entry(&tx, &entry, &command, "agent-1", "epoch-1").await?;
        drop(tx);
        let mut bodies = Vec::new();
        while let Some(request) = rx.recv().await {
            bodies.push(request.body.ok_or("control request body is missing")?);
        }
        assert_eq!(bodies.len(), 2);
        match &bodies[0] {
            proto::control_request::Body::Observation(observation) => {
                assert_eq!(
                    observation.operation_state,
                    proto::OperationState::Failed as i32
                );
                assert_eq!(observation.state, proto::ResourceState::Error as i32);
            }
            _ => return Err("expected observation before operation update".into()),
        }
        match &bodies[1] {
            proto::control_request::Body::Operation(update) => {
                assert_eq!(update.state, proto::OperationState::Failed as i32);
                assert_eq!(update.error_category, proto::ErrorCategory::Terminal as i32);
                assert_eq!(update.operation_sequence, 2);
            }
            _ => return Err("expected operation update after observation".into()),
        }
        Ok(())
    }

    #[tokio::test]
    async fn fake_create_failure_cleans_each_owned_stage() -> Result<(), Box<dyn std::error::Error>>
    {
        for stage in [
            FakeFailureStage::Image,
            FakeFailureStage::Network,
            FakeFailureStage::Domain,
        ] {
            let executor = FakeCommandExecutor::default();
            executor.set_failure_stage(Some(stage))?;
            assert!(executor.execute(&fake_create_command()?).await.is_err());
            assert_eq!(executor.resource_count(), 0);
            assert_eq!(executor.artifact_count(), 0);
        }
        Ok(())
    }

    #[test]
    fn create_command_identity_and_fingerprint_are_deterministic() -> Result<(), AgentError> {
        let deadline = unix_ms().saturating_add(10_000);
        let first = build_create_command(CreateCommandSpec {
            agent_id: "node".to_owned(),
            agent_epoch: "epoch".to_owned(),
            project_id: "project".to_owned(),
            operation_id: "operation-1".to_owned(),
            resource_id: "resource-1".to_owned(),
            idempotency_key: "request-1".to_owned(),
            deadline_unix_ms: deadline,
            image_id: "image-1".to_owned(),
            flavor_id: "flavor-1".to_owned(),
            image_artifact_id: "image-artifact-1".to_owned(),
            image_sha256: "a".repeat(64),
            image_format: "qcow2".to_owned(),
            vcpus: 1,
            memory_mib: 512,
            disk_gib: 10,
            config_drive_artifact_id: "config-drive-1".to_owned(),
            config_drive_sha256: "b".repeat(64),
            network_attachments: vec![NetworkAttachmentSpec {
                port_id: "port-1".to_owned(),
                mac: "02:00:00:00:00:01".to_owned(),
                fixed_ipv4: "192.0.2.10".to_owned(),
                subnet_cidr: "192.0.2.0/24".to_owned(),
                gateway_ipv4: "192.0.2.1".to_owned(),
            }],
        })?;
        let second = build_create_command(CreateCommandSpec {
            agent_id: "node".to_owned(),
            agent_epoch: "epoch".to_owned(),
            project_id: "project".to_owned(),
            operation_id: "operation-1".to_owned(),
            resource_id: "resource-1".to_owned(),
            idempotency_key: "request-1".to_owned(),
            deadline_unix_ms: deadline,
            image_id: "image-1".to_owned(),
            flavor_id: "flavor-1".to_owned(),
            image_artifact_id: "image-artifact-1".to_owned(),
            image_sha256: "a".repeat(64),
            image_format: "qcow2".to_owned(),
            vcpus: 1,
            memory_mib: 512,
            disk_gib: 10,
            config_drive_artifact_id: "config-drive-1".to_owned(),
            config_drive_sha256: "b".repeat(64),
            network_attachments: vec![NetworkAttachmentSpec {
                port_id: "port-1".to_owned(),
                mac: "02:00:00:00:00:01".to_owned(),
                fixed_ipv4: "192.0.2.10".to_owned(),
                subnet_cidr: "192.0.2.0/24".to_owned(),
                gateway_ipv4: "192.0.2.1".to_owned(),
            }],
        })?;
        assert_eq!(first, second);
        let changed = build_create_command(CreateCommandSpec {
            agent_id: "node".to_owned(),
            agent_epoch: "epoch".to_owned(),
            project_id: "project".to_owned(),
            operation_id: "operation-1".to_owned(),
            resource_id: "resource-1".to_owned(),
            idempotency_key: "request-1".to_owned(),
            deadline_unix_ms: deadline,
            image_id: "image-1".to_owned(),
            flavor_id: "flavor-1".to_owned(),
            image_artifact_id: "image-artifact-1".to_owned(),
            image_sha256: "a".repeat(64),
            image_format: "qcow2".to_owned(),
            vcpus: 1,
            memory_mib: 512,
            disk_gib: 10,
            config_drive_artifact_id: "config-drive-1".to_owned(),
            config_drive_sha256: "b".repeat(64),
            network_attachments: vec![NetworkAttachmentSpec {
                port_id: "port-2".to_owned(),
                mac: "02:00:00:00:00:02".to_owned(),
                fixed_ipv4: "192.0.2.11".to_owned(),
                subnet_cidr: "192.0.2.0/24".to_owned(),
                gateway_ipv4: "192.0.2.1".to_owned(),
            }],
        })?;
        assert_eq!(first.command_id, changed.command_id);
        assert_ne!(
            first.payload_fingerprint_sha256,
            changed.payload_fingerprint_sha256
        );
        Ok(())
    }

    #[test]
    fn command_journal_deduplicates_and_marks_inflight_unknown() -> Result<(), AgentError> {
        let identity = PathBuf::from(format!("/tmp/o3k-command-journal-{}", std::process::id()));
        let path = command_journal_file(&identity);
        let _ = fs::remove_file(&path);
        let command = fake_create_command()?;
        let mut journal = CommandJournal::open(&identity, "node")?;
        let decision = journal.accept(&command)?;
        let key = match decision {
            JournalDecision::New { key, .. } => key,
            JournalDecision::Existing(_) => {
                return Err(AgentError::Protocol(
                    "journal unexpectedly deduplicated".to_owned(),
                ));
            }
        };
        journal.mark_running(&key)?;
        assert!(matches!(
            journal.accept(&command)?,
            JournalDecision::Existing(_)
        ));
        let mut conflicting = command.clone();
        conflicting.payload_fingerprint_sha256 = "f".repeat(64);
        assert!(journal.accept(&conflicting).is_err());
        drop(journal);

        let reopened = CommandJournal::open(&identity, "node")?;
        assert!(matches!(
            reopened.entries.values().next().map(|entry| entry.state),
            Some(JournalState::Unknown)
        ));
        fs::remove_file(path).map_err(AgentError::IdentityStore)?;
        Ok(())
    }

    /// Host-reboot restoration authority (issue #613 blocker A): the journal
    /// must expose the LAST terminal lifecycle mutation per resource — a
    /// stop after a create wins over the create, an accepted-but-unfinished
    /// mutation excludes the resource (the control plane owns that
    /// convergence), and passive console/inspect entries never count.
    #[test]
    fn journal_last_lifecycle_states_prefer_latest_terminal_mutation() -> Result<(), AgentError> {
        let identity = PathBuf::from(format!(
            "/tmp/o3k-journal-last-states-{}",
            std::process::id()
        ));
        let path = command_journal_file(&identity);
        let _ = fs::remove_file(&path);
        let mut journal = CommandJournal::open(&identity, "node")?;

        let accept_and_complete =
            |journal: &mut CommandJournal, command: &proto::Command, resource_state: i32| {
                let decision = journal
                    .accept(command)
                    .map_err(|error| AgentError::Protocol(format!("accept failed: {error}")))?;
                let key = match decision {
                    JournalDecision::New { key, .. } => key,
                    JournalDecision::Existing(_) => {
                        return Err(AgentError::Protocol(
                            "journal unexpectedly deduplicated".to_owned(),
                        ));
                    }
                };
                journal
                    .complete(&key, fake_success("provider-a".to_owned(), resource_state))
                    .map_err(|error| AgentError::Protocol(format!("complete failed: {error}")))?;
                Ok(())
            };

        // Resource "server-a": create (running) followed by a stop (stopped).
        let create_a = build_create_command(CreateCommandSpec {
            agent_id: "node".to_owned(),
            agent_epoch: "epoch-1".to_owned(),
            project_id: "project-a".to_owned(),
            operation_id: Uuid::now_v7().to_string(),
            resource_id: "server-a".to_owned(),
            idempotency_key: "create-a".to_owned(),
            deadline_unix_ms: unix_ms() + 60_000,
            image_id: "image-1".to_owned(),
            flavor_id: "flavor-1".to_owned(),
            image_artifact_id: "image-artifact-1".to_owned(),
            image_sha256: "a".repeat(64),
            image_format: "qcow2".to_owned(),
            vcpus: 1,
            memory_mib: 512,
            disk_gib: 10,
            config_drive_artifact_id: "config-drive-1".to_owned(),
            config_drive_sha256: "b".repeat(64),
            network_attachments: vec![NetworkAttachmentSpec {
                port_id: "port-1".to_owned(),
                mac: "02:00:00:00:00:01".to_owned(),
                fixed_ipv4: "192.0.2.10".to_owned(),
                subnet_cidr: "192.0.2.0/24".to_owned(),
                gateway_ipv4: "192.0.2.1".to_owned(),
            }],
        })?;
        accept_and_complete(
            &mut journal,
            &create_a,
            proto::ResourceState::Running as i32,
        )?;
        let stop_a = build_lifecycle_command(
            LifecycleCommand::Stop,
            "node",
            "epoch-1",
            &Uuid::now_v7().to_string(),
            "server-a",
        )?;
        accept_and_complete(&mut journal, &stop_a, proto::ResourceState::Stopped as i32)?;

        // Resource "server-b": start (running) only.
        let start_b = build_lifecycle_command(
            LifecycleCommand::Start,
            "node",
            "epoch-1",
            &Uuid::now_v7().to_string(),
            "server-b",
        )?;
        accept_and_complete(&mut journal, &start_b, proto::ResourceState::Running as i32)?;

        // Resource "server-c": an accepted create that never completed; the
        // resource must be excluded (no proof of any executed outcome).
        let create_c = build_create_command(CreateCommandSpec {
            agent_id: "node".to_owned(),
            agent_epoch: "epoch-1".to_owned(),
            project_id: "project-a".to_owned(),
            operation_id: Uuid::now_v7().to_string(),
            resource_id: "server-c".to_owned(),
            idempotency_key: "create-c".to_owned(),
            deadline_unix_ms: unix_ms() + 60_000,
            image_id: "image-1".to_owned(),
            flavor_id: "flavor-1".to_owned(),
            image_artifact_id: "image-artifact-1".to_owned(),
            image_sha256: "a".repeat(64),
            image_format: "qcow2".to_owned(),
            vcpus: 1,
            memory_mib: 512,
            disk_gib: 10,
            config_drive_artifact_id: "config-drive-1".to_owned(),
            config_drive_sha256: "b".repeat(64),
            network_attachments: vec![NetworkAttachmentSpec {
                port_id: "port-2".to_owned(),
                mac: "02:00:00:00:00:02".to_owned(),
                fixed_ipv4: "192.0.2.11".to_owned(),
                subnet_cidr: "192.0.2.0/24".to_owned(),
                gateway_ipv4: "192.0.2.1".to_owned(),
            }],
        })?;
        assert!(matches!(
            journal.accept(&create_c)?,
            JournalDecision::New { .. }
        ));

        let states = journal.last_lifecycle_resource_states();
        assert_eq!(
            states.get("server-a").map(|(_, state)| *state),
            Some(proto::ResourceState::Stopped),
            "the stop after the create must be the last lifecycle state"
        );
        assert_eq!(
            states.get("server-b").map(|(_, state)| *state),
            Some(proto::ResourceState::Running),
            "a terminal start must be the last lifecycle state"
        );
        assert!(
            !states.contains_key("server-c"),
            "an unfinished mutation has no provable outcome and must be excluded"
        );
        fs::remove_file(path).map_err(AgentError::IdentityStore)?;
        Ok(())
    }

    fn expire_create_transfers(command: &mut proto::Command) -> Result<(), AgentError> {
        let Some(proto::command::Action::Create(create)) = command.action.as_mut() else {
            return Err(AgentError::Protocol("expected create action".to_owned()));
        };
        let Some(resolved) = create.resolved.as_mut() else {
            return Err(AgentError::Protocol("expected resolved inputs".to_owned()));
        };
        let expired = unix_ms().saturating_sub(1);
        if let Some(reference) = resolved.image_transfer.as_mut() {
            reference.expires_at_unix_ms = expired;
        }
        if let Some(reference) = resolved.config_drive_transfer.as_mut() {
            reference.expires_at_unix_ms = expired;
        }
        // The command deadline and the embedded transfer expiry are the same
        // value at build time; a restart after the deadline sees both in the
        // past. The transfer fields are part of the canonical payload, so
        // recompute the fingerprint that admission would have recorded.
        command.deadline_unix_ms = expired;
        command.payload_fingerprint_sha256 = command_payload_fingerprint(command)?;
        Ok(())
    }

    #[test]
    fn journal_decode_ignores_transfer_expiry_for_admitted_create() -> Result<(), AgentError> {
        // A journaled create was already admitted when accepted, so decoding
        // the journal on a later restart must accept it regardless of age:
        // the embedded transfer references expire with the command deadline
        // (seconds after build), and rejecting them bricks every subsequent
        // agent restart on the first journaled create (issue #87: SIGKILL
        // 0.11s after accept, then every restart exits
        // "create command resolved inputs are invalid" before any network
        // connect). This mirrors the artifact-statuses replay fix (#78/#542):
        // expiry fences new transfer admission, not replay of admitted work.
        let identity = PathBuf::from(format!(
            "/tmp/o3k-journal-expired-create-{}",
            std::process::id()
        ));
        let path = command_journal_file(&identity);
        let _ = fs::remove_file(&path);
        let command = fake_create_command()?;
        let mut expired_command = command.clone();
        expire_create_transfers(&mut expired_command)?;

        // Admission still rejects the expired command; only decode/replay is
        // exempt from the fence.
        let mut probe = CommandJournal::open(&identity, "node")?;
        assert!(probe.accept(&expired_command).is_err());
        drop(probe);

        let key = journal_key("node", &command.operation_id);
        let mut journal = CommandJournal::open(&identity, "node")?;
        assert!(matches!(
            journal.accept(&command)?,
            JournalDecision::New { .. }
        ));
        journal
            .entries
            .get_mut(&key)
            .ok_or_else(|| AgentError::Protocol("command journal entry is missing".to_owned()))?
            .command = expired_command;
        let expired_fingerprint = journal
            .entries
            .get(&key)
            .ok_or_else(|| AgentError::Protocol("journaled command is missing".to_owned()))?
            .command
            .payload_fingerprint_sha256
            .clone();
        journal.persist()?;
        drop(journal);

        // Restart after the command deadline: decode must succeed and the
        // journaled command must survive for replay.
        let reopened = CommandJournal::open(&identity, "node")?;
        let entry = reopened
            .entries
            .get(&key)
            .ok_or_else(|| AgentError::Protocol("journaled command is missing".to_owned()))?;
        assert_eq!(entry.command.command_id, command.command_id);
        assert_eq!(entry.command.operation_id, command.operation_id);
        assert_eq!(
            entry.command.payload_fingerprint_sha256,
            expired_fingerprint
        );
        fs::remove_file(path).map_err(AgentError::IdentityStore)?;
        Ok(())
    }

    #[test]
    fn journal_decode_keeps_committed_create_past_its_deadline() -> Result<(), AgentError> {
        // The real-host case: the restart bricked on an earlier COMPLETED
        // create whose deadline (and embedded transfer expiry) had passed six
        // minutes before the agent restart; a terminal record must decode and
        // keep its committed result.
        let identity = PathBuf::from(format!(
            "/tmp/o3k-journal-expired-terminal-{}",
            std::process::id()
        ));
        let path = command_journal_file(&identity);
        let _ = fs::remove_file(&path);
        let command = fake_create_command()?;
        let key = journal_key("node", &command.operation_id);
        let mut journal = CommandJournal::open(&identity, "node")?;
        let decision = journal.accept(&command)?;
        let accepted_key = match decision {
            JournalDecision::New { key, .. } => key,
            JournalDecision::Existing(_) => {
                return Err(AgentError::Protocol(
                    "journal unexpectedly deduplicated".to_owned(),
                ));
            }
        };
        assert_eq!(accepted_key, key);
        journal.complete(
            &key,
            fake_success(
                "fake-provider-1".to_owned(),
                proto::ResourceState::Running as i32,
            ),
        )?;
        expire_create_transfers(
            &mut journal
                .entries
                .get_mut(&key)
                .ok_or_else(|| AgentError::Protocol("command journal entry is missing".to_owned()))?
                .command,
        )?;
        journal.persist()?;
        drop(journal);

        let reopened = CommandJournal::open(&identity, "node")?;
        let entry = reopened
            .entries
            .get(&key)
            .ok_or_else(|| AgentError::Protocol("journaled command is missing".to_owned()))?;
        assert!(matches!(entry.state, JournalState::Terminal));
        let result = entry
            .result
            .as_ref()
            .ok_or_else(|| AgentError::Protocol("terminal result is missing".to_owned()))?;
        assert_eq!(result.provider_resource_id, "fake-provider-1");
        fs::remove_file(path).map_err(AgentError::IdentityStore)?;
        Ok(())
    }

    #[test]
    fn command_journal_round_trips_block_device_observations() -> Result<(), AgentError> {
        let identity = PathBuf::from(format!(
            "/tmp/o3k-journal-block-device-{}",
            std::process::id()
        ));
        let path = command_journal_file(&identity);
        let _ = fs::remove_file(&path);
        let command = fake_create_command()?;
        let key = journal_key("node", &command.operation_id);
        let mut journal = CommandJournal::open(&identity, "node")?;
        assert!(matches!(
            journal.accept(&command)?,
            JournalDecision::New { .. }
        ));
        let mut result = fake_success(
            "fake-provider-1".to_owned(),
            proto::ResourceState::Running as i32,
        );
        result.block_device = Some(proto::BlockDeviceObservation {
            volume_id: "volume-1".to_owned(),
            attachment_id: "attachment-1".to_owned(),
            driver_volume_type: "iscsi".to_owned(),
            device_path: "/dev/vdb".to_owned(),
            host_path: "/dev/sdb".to_owned(),
            attached: true,
            found: true,
            initiator: "iqn.1993-08.org.debian:01:o3k".to_owned(),
            host_name: "compute-host".to_owned(),
            ip_address: "192.0.2.10".to_owned(),
            iscsi_logged_in: true,
        });
        journal.complete(&key, result)?;
        drop(journal);

        let reopened = CommandJournal::open(&identity, "node")?;
        let saved = reopened
            .entries
            .get(&key)
            .and_then(|entry| entry.result.as_ref())
            .and_then(|result| result.block_device.as_ref())
            .ok_or_else(|| {
                AgentError::Protocol("block-device journal result was not restored".to_owned())
            })?;
        assert_eq!(saved.volume_id, "volume-1");
        assert_eq!(saved.host_path, "/dev/sdb");
        assert!(saved.attached);
        fs::remove_file(path).map_err(AgentError::IdentityStore)?;
        Ok(())
    }

    #[test]
    fn console_commands_with_distinct_operations_do_not_conflict() -> Result<(), AgentError> {
        // Each console API request is a distinct operation. Two sequential
        // polls for the same server, offset, and bound must both be accepted;
        // sharing a deterministic idempotency key across operations would make
        // the second poll conflict with the durable record and starve the
        // caller of any terminal observation.
        let identity = PathBuf::from(format!(
            "/tmp/o3k-command-journal-console-{}",
            std::process::id()
        ));
        let path = command_journal_file(&identity);
        let _ = fs::remove_file(&path);
        let mut journal = CommandJournal::open(&identity, "node")?;
        let first =
            build_console_log_command("node", "epoch", "operation-1", "resource-1", 0, 1024)?;
        let second =
            build_console_log_command("node", "epoch", "operation-2", "resource-1", 0, 1024)?;
        assert!(matches!(
            journal.accept(&first)?,
            JournalDecision::New { .. }
        ));
        assert!(matches!(
            journal.accept(&second)?,
            JournalDecision::New { .. }
        ));
        drop(journal);
        fs::remove_file(path).map_err(AgentError::IdentityStore)?;
        Ok(())
    }

    #[test]
    fn lifecycle_commands_are_fenced_and_deterministic() -> Result<(), AgentError> {
        let first = build_lifecycle_command(
            LifecycleCommand::HardReboot,
            "agent-1",
            "epoch-1",
            "operation-1",
            "resource-1",
        )?;
        let second = build_lifecycle_command(
            LifecycleCommand::HardReboot,
            "agent-1",
            "epoch-1",
            "operation-1",
            "resource-1",
        )?;
        let first_deadline = first.deadline_unix_ms;
        let second_deadline = second.deadline_unix_ms;
        let mut normalized_second = second.clone();
        normalized_second.deadline_unix_ms = first_deadline;
        assert_eq!(first, normalized_second);
        assert!(first_deadline > unix_ms());
        assert!(second_deadline > unix_ms());
        assert!(first.deadline_unix_ms > unix_ms());
        assert!(first.idempotency_key.starts_with("hard-reboot:resource-1:"));
        assert!(matches!(
            first.action,
            Some(proto::command::Action::Reboot(proto::RebootCommand {
                r#type: value
            })) if value == proto::reboot_command::RebootType::Hard as i32
        ));
        assert!(
            build_lifecycle_command(
                LifecycleCommand::Delete,
                "agent/invalid",
                "epoch-1",
                "operation-1",
                "resource-1",
            )
            .is_err()
        );
        Ok(())
    }

    #[test]
    fn console_query_command_is_bounded_and_fenced() -> Result<(), AgentError> {
        let command =
            build_console_log_command("agent-1", "epoch-1", "operation-1", "resource-1", 12, 128)?;
        assert_eq!(command.agent_id, "agent-1");
        assert_eq!(command.agent_epoch, "epoch-1");
        assert!(command.deadline_unix_ms > unix_ms());
        assert!(matches!(
            command.action,
            Some(proto::command::Action::ConsoleLog(
                proto::ConsoleLogCommand {
                    offset: 12,
                    max_bytes: 128,
                }
            ))
        ));
        assert!(
            build_console_log_command("agent-1", "epoch-1", "operation-1", "resource-1", 0, 0,)
                .is_err()
        );
        Ok(())
    }

    #[test]
    fn identity_is_stable_and_temporary_file_is_not_exposed()
    -> Result<(), Box<dyn std::error::Error>> {
        let path = std::env::temp_dir().join(format!("o3k-agent-identity-{}", Uuid::now_v7()));
        let first = load_or_create_identity(&path)?;
        let second = load_or_create_identity(&path)?;
        assert_eq!(first, second);
        assert!(!format!("{first:?}").contains("private"));
        fs::remove_file(path)?;
        Ok(())
    }

    #[test]
    fn administrative_state_defaults_and_round_trips_atomically()
    -> Result<(), Box<dyn std::error::Error>> {
        let identity = std::env::temp_dir().join(format!("o3k-agent-state-{}", Uuid::now_v7()));
        let state_path = administrative_state_file(&identity);
        assert_eq!(
            load_administrative_state(&state_path)?,
            proto::AdministrativeState::Enabled
        );
        persist_administrative_state(&state_path, proto::AdministrativeState::Draining)?;
        assert_eq!(
            load_administrative_state(&state_path)?,
            proto::AdministrativeState::Draining
        );
        assert!(!state_path.with_extension("state.tmp").exists());
        fs::remove_file(state_path)?;
        Ok(())
    }

    #[test]
    fn administrative_state_rejects_corrupt_and_unspecified_values()
    -> Result<(), Box<dyn std::error::Error>> {
        let identity = std::env::temp_dir().join(format!("o3k-agent-state-{}", Uuid::now_v7()));
        let state_path = administrative_state_file(&identity);
        fs::write(&state_path, "not-a-state\n")?;
        assert!(matches!(
            load_administrative_state(&state_path),
            Err(AgentError::InvalidConfiguration(_))
        ));
        fs::write(
            &state_path,
            format!("{}\n", proto::AdministrativeState::Unspecified as i32),
        )?;
        assert!(load_administrative_state(&state_path).is_err());
        fs::remove_file(state_path)?;
        Ok(())
    }

    #[test]
    fn malformed_tls_material_is_rejected_before_transport_start() {
        assert!(pem_certificates(b"not a certificate").is_err());
        assert!(pem_private_key(b"not a private key").is_err());
    }

    #[test]
    fn bootstrap_certificate_is_normalized_to_one_der_leaf() -> Result<(), AgentError> {
        let pem = include_bytes!("../tests/fixtures/agent.pem");
        let der = certificate_der(pem)?;
        assert!(!der.is_empty());
        assert!(certificate_der(include_bytes!("../tests/fixtures/agent-chain.pem")).is_err());
        Ok(())
    }

    #[test]
    fn protocol_version_is_wire_stable() {
        assert_eq!(PROTOCOL_VERSION.wire_revision, 1);
        assert!(!std::sync::atomic::AtomicBool::new(false).load(Ordering::Relaxed));
    }

    #[test]
    fn authorized_agent_fingerprint_is_strictly_parsed() -> Result<(), Box<dyn std::error::Error>> {
        let fingerprint = "ab".repeat(32);
        let agents = parse_authorized_agents(&format!("node={fingerprint}"))?;
        assert_eq!(agents.len(), 1);
        assert_eq!(agents[0].certificate_sha256, [0xab; 32]);
        assert!(parse_authorized_agents("node=not-hex").is_err());
        Ok(())
    }

    #[test]
    fn certificate_uri_san_binding_is_exact() {
        let uri = b"urn:o3k:compute:agent:node";
        let certificate = normalize_certificate(include_bytes!("../tests/fixtures/agent.pem"));
        assert!(certificate_has_uri_san(
            &certificate,
            b"urn:o3k:compute:agent:node-test"
        ));
        assert!(!certificate_has_uri_san(
            &certificate,
            b"urn:o3k:compute:agent:other"
        ));
        assert!(!certificate_has_uri_san(&certificate, uri));
    }

    fn test_artifact_offer(agent_id: &str) -> (proto::ArtifactOffer, Vec<u8>) {
        let data = b"abc".to_vec();
        let digest = Sha256::digest(&data);
        let mut sha256 = String::with_capacity(64);
        for byte in digest {
            use std::fmt::Write as _;
            let _ = write!(&mut sha256, "{byte:02x}");
        }
        (
            proto::ArtifactOffer {
                transfer_id: "transfer-1".to_owned(),
                command_id: "command-1".to_owned(),
                operation_id: "11111111-1111-1111-1111-111111111111".to_owned(),
                resource_id: "22222222-2222-2222-2222-222222222222".to_owned(),
                agent_id: agent_id.to_owned(),
                artifact_id: "artifact-1".to_owned(),
                kind: proto::ArtifactKind::ImageBase as i32,
                sha256,
                size_bytes: data.len() as u64,
                format: "raw".to_owned(),
                chunk_size_bytes: data.len() as u32,
                chunk_count: 1,
                expires_at_unix_ms: unix_ms().saturating_add(10_000),
            },
            data,
        )
    }

    async fn next_artifact_ack(
        receiver: &mut mpsc::Receiver<proto::ControlRequest>,
    ) -> Result<proto::ArtifactAck, AgentError> {
        let request = receiver
            .recv()
            .await
            .ok_or_else(|| AgentError::Protocol("artifact ack was not emitted".to_owned()))?;
        match request.body {
            Some(proto::control_request::Body::ArtifactAck(ack)) => Ok(ack),
            _ => Err(AgentError::Protocol(
                "unexpected artifact response in test".to_owned(),
            )),
        }
    }

    #[tokio::test]
    async fn artifact_messages_acknowledge_offer_progress_and_commit()
    -> Result<(), Box<dyn std::error::Error>> {
        let root = std::env::temp_dir().join(format!("o3k-agent-artifacts-{}", Uuid::now_v7()));
        let store = ArtifactStore::open(&root, "node")?;
        let (offer, data) = test_artifact_offer("node");
        let chunk = proto::ArtifactChunk {
            transfer_id: offer.transfer_id.clone(),
            chunk_index: 0,
            offset_bytes: 0,
            data: data.clone(),
            chunk_sha256: offer.sha256.clone(),
        };
        let end = proto::ArtifactEnd {
            transfer_id: offer.transfer_id.clone(),
            sha256: offer.sha256.clone(),
            size_bytes: offer.size_bytes,
        };
        let (tx, mut receiver) = mpsc::channel(4);
        let mut offers = HashMap::new();

        handle_artifact_response(
            proto::control_response::Body::ArtifactOffer(offer.clone()),
            &store,
            &mut offers,
            &tx,
            "node",
            "epoch-1",
        )
        .await?;
        let offered = next_artifact_ack(&mut receiver).await?;
        assert_eq!(offered.state, proto::ArtifactTransferState::Offered as i32);
        assert_eq!(offered.agent_epoch, "epoch-1");

        handle_artifact_response(
            proto::control_response::Body::ArtifactChunk(chunk),
            &store,
            &mut offers,
            &tx,
            "node",
            "epoch-1",
        )
        .await?;
        let receiving = next_artifact_ack(&mut receiver).await?;
        assert_eq!(
            receiving.state,
            proto::ArtifactTransferState::Receiving as i32
        );
        assert_eq!(receiving.contiguous_bytes, data.len() as u64);
        assert_eq!(receiving.next_chunk_index, 1);

        handle_artifact_response(
            proto::control_response::Body::ArtifactEnd(end),
            &store,
            &mut offers,
            &tx,
            "node",
            "epoch-1",
        )
        .await?;
        let committed = next_artifact_ack(&mut receiver).await?;
        assert_eq!(
            committed.state,
            proto::ArtifactTransferState::Committed as i32
        );
        assert_eq!(committed.contiguous_bytes, data.len() as u64);
        assert!(store.resolve(&offer).is_ok());
        fs::remove_dir_all(root)?;
        Ok(())
    }

    #[tokio::test]
    async fn retried_artifact_offer_may_refresh_expiry_but_not_identity()
    -> Result<(), Box<dyn std::error::Error>> {
        let root =
            std::env::temp_dir().join(format!("o3k-agent-artifact-retry-{}", Uuid::now_v7()));
        let store = ArtifactStore::open(&root, "node")?;
        let (offer, _) = test_artifact_offer("node");
        let (tx, mut receiver) = mpsc::channel(4);
        let mut offers = HashMap::new();
        handle_artifact_response(
            proto::control_response::Body::ArtifactOffer(offer.clone()),
            &store,
            &mut offers,
            &tx,
            "node",
            "epoch-1",
        )
        .await?;
        let _ = next_artifact_ack(&mut receiver).await?;

        let mut refreshed = offer.clone();
        refreshed.expires_at_unix_ms = offer.expires_at_unix_ms.saturating_add(60_000);
        handle_artifact_response(
            proto::control_response::Body::ArtifactOffer(refreshed),
            &store,
            &mut offers,
            &tx,
            "node",
            "epoch-1",
        )
        .await?;
        let retry_ack = next_artifact_ack(&mut receiver).await?;
        assert_eq!(
            retry_ack.state,
            proto::ArtifactTransferState::Offered as i32
        );

        let mut conflicting = offer;
        conflicting.sha256 = "f".repeat(64);
        assert!(
            handle_artifact_response(
                proto::control_response::Body::ArtifactOffer(conflicting),
                &store,
                &mut offers,
                &tx,
                "node",
                "epoch-1",
            )
            .await
            .is_err()
        );
        let rejected = next_artifact_ack(&mut receiver).await?;
        assert_eq!(
            rejected.state,
            proto::ArtifactTransferState::Rejected as i32
        );
        fs::remove_dir_all(root)?;
        Ok(())
    }

    #[tokio::test]
    async fn artifact_identity_or_chunk_errors_reject_and_fail_closed()
    -> Result<(), Box<dyn std::error::Error>> {
        let root = std::env::temp_dir().join(format!("o3k-agent-artifacts-{}", Uuid::now_v7()));
        let store = ArtifactStore::open(&root, "node")?;
        let (mut offer, data) = test_artifact_offer("other-node");
        let (tx, mut receiver) = mpsc::channel(4);
        let mut offers = HashMap::new();
        assert!(
            handle_artifact_response(
                proto::control_response::Body::ArtifactOffer(offer.clone()),
                &store,
                &mut offers,
                &tx,
                "node",
                "epoch-1",
            )
            .await
            .is_err()
        );
        assert!(receiver.try_recv().is_err());

        offer.agent_id = "node".to_owned();
        handle_artifact_response(
            proto::control_response::Body::ArtifactOffer(offer.clone()),
            &store,
            &mut offers,
            &tx,
            "node",
            "epoch-1",
        )
        .await?;
        let _ = next_artifact_ack(&mut receiver).await?;
        let mut invalid = data;
        invalid[0] = b'X';
        assert!(
            handle_artifact_response(
                proto::control_response::Body::ArtifactChunk(proto::ArtifactChunk {
                    transfer_id: offer.transfer_id.clone(),
                    chunk_index: 0,
                    offset_bytes: 0,
                    data: invalid,
                    chunk_sha256: offer.sha256.clone(),
                }),
                &store,
                &mut offers,
                &tx,
                "node",
                "epoch-1",
            )
            .await
            .is_err()
        );
        let rejected = next_artifact_ack(&mut receiver).await?;
        assert_eq!(
            rejected.state,
            proto::ArtifactTransferState::Rejected as i32
        );
        assert_eq!(rejected.agent_id, "node");
        assert_eq!(rejected.agent_epoch, "epoch-1");
        fs::remove_dir_all(root)?;
        Ok(())
    }
    #[derive(Debug, Default)]
    struct TestResolvedCreateResolver;

    #[async_trait]
    impl ResolvedCreateResolver for TestResolvedCreateResolver {
        async fn resolve(
            &self,
            _request: &CreateInstanceRequest,
            _agent: &AgentNodeSnapshot,
        ) -> Result<ResolvedCreateInputs, ProviderError> {
            Ok(ResolvedCreateInputs {
                flavor_id: "flavor.test".to_owned(),
                image_artifact_id: "artifact.test".to_owned(),
                image_sha256: "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef"
                    .to_owned(),
                image_format: "qcow2".to_owned(),
                disk_gib: 10,
                config_drive_artifact_id: "config-drive.test".to_owned(),
                config_drive_sha256:
                    "abcdef0123456789abcdef0123456789abcdef0123456789abcdef0123456789".to_owned(),
                network_attachments: vec![NetworkAttachmentSpec {
                    port_id: "port.test".to_owned(),
                    mac: "52:54:00:12:34:56".to_owned(),
                    fixed_ipv4: "192.0.2.10".to_owned(),
                    subnet_cidr: "192.0.2.0/24".to_owned(),
                    gateway_ipv4: "192.0.2.1".to_owned(),
                }],
            })
        }
    }

    fn registered_agent(id: &str) -> proto::RegisterRequest {
        proto::RegisterRequest {
            agent_id: id.to_owned(),
            agent_epoch: "epoch-1".to_owned(),
            software_version: "test".to_owned(),
            host_label: id.to_owned(),
            supported_versions: vec![PROTOCOL_VERSION],
            capabilities: Some(proto::Capabilities {
                agent_provider_name: "o3k-compute".to_owned(),
                agent_provider_version: "test".to_owned(),
                max_vcpus: 8,
                max_memory_mib: 16_384,
                max_disk_gb: 100,
                lifecycle_actions: vec!["start".to_owned(), "stop".to_owned()],
                ..Default::default()
            }),
        }
    }

    #[tokio::test]
    async fn agent_provider_reads_capabilities_from_selected_registered_agent()
    -> Result<(), Box<dyn std::error::Error>> {
        let registry = NodeRegistry::default();
        registry.register(&registered_agent("node-a")).await?;
        let provider =
            AgentComputeProvider::new(registry, Arc::new(UnconfiguredResolvedCreateResolver));
        let capabilities = provider.capabilities().await?;
        assert_eq!(capabilities.provider_name, "o3k-compute");
        assert!(
            capabilities
                .capabilities
                .iter()
                .any(|value| value == "start")
        );
        Ok(())
    }

    #[tokio::test]
    async fn agent_provider_rehydrates_instance_binding_from_durable_store()
    -> Result<(), Box<dyn std::error::Error>> {
        let registry = NodeRegistry::default();
        registry.register(&registered_agent("node-a")).await?;
        let store: Arc<dyn ComputeRepository> = Arc::new(o3k_store::testkit::open_memory().await?);
        let server_id = Uuid::now_v7();
        let operation_id = Uuid::now_v7();
        let request = CreateInstanceRequest {
            operation_id,
            o3k_server_id: server_id,
            project_id: "project-a".to_owned(),
            name: "server-a".to_owned(),
            vcpus: 1,
            memory_mib: 512,
            flavor_id: "flavor-1".to_owned(),
            disk_gib: 10,
            image_id: Some("image-a".to_owned()),
            key_name: None,
            keypair_id: None,
            network_ids: vec!["port-a".to_owned()],
            placement_provider_id: Some("node-a".to_owned()),
            placement_allocation_id: Some("allocation-a".to_owned()),
            config_drive: None,
            idempotency_key: "request-a".to_owned(),
        };
        store
            .insert_resource(&o3k_store::ResourceRecord {
                id: server_id,
                kind: "compute_instance".to_owned(),
                project_id: "project-a".to_owned(),
                generation: 1,
                observed_generation: 1,
                desired_state: serde_json::to_string(&request)?,
                observed_state: "ACTIVE".to_owned(),
                provider_id: Some("domain-a".to_owned()),
            })
            .await?;
        store
            .attach_provider_reference(&o3k_store::ProviderReference {
                resource_id: server_id,
                provider_name: "agent".to_owned(),
                provider_resource_id: "domain-a".to_owned(),
            })
            .await?;
        let provider = AgentComputeProvider::new_with_store(
            registry,
            Arc::new(UnconfiguredResolvedCreateResolver),
            Some(store),
        );
        let instance = provider.get_instance("domain-a").await?;
        assert_eq!(instance.o3k_server_id, server_id);
        assert_eq!(instance.state, o3k_provider::InstanceState::Running);
        Ok(())
    }

    #[tokio::test]
    async fn agent_lifecycle_commands_use_the_o3k_server_id_as_resource_identity()
    -> Result<(), Box<dyn std::error::Error>> {
        let registry = NodeRegistry::default();
        registry.register(&registered_agent("node-a")).await?;
        let store: Arc<dyn ComputeRepository> = Arc::new(o3k_store::testkit::open_memory().await?);
        let server_id = Uuid::now_v7();
        let request = CreateInstanceRequest {
            operation_id: Uuid::now_v7(),
            o3k_server_id: server_id,
            project_id: "project-a".to_owned(),
            name: "server-a".to_owned(),
            vcpus: 1,
            memory_mib: 512,
            flavor_id: "flavor-1".to_owned(),
            disk_gib: 10,
            image_id: Some("image-a".to_owned()),
            key_name: None,
            keypair_id: None,
            network_ids: vec!["port-a".to_owned()],
            placement_provider_id: Some("node-a".to_owned()),
            placement_allocation_id: Some("allocation-a".to_owned()),
            config_drive: None,
            idempotency_key: "request-a".to_owned(),
        };
        store
            .insert_resource(&o3k_store::ResourceRecord {
                id: server_id,
                kind: "compute_instance".to_owned(),
                project_id: "project-a".to_owned(),
                generation: 1,
                observed_generation: 1,
                desired_state: serde_json::to_string(&request)?,
                observed_state: "ACTIVE".to_owned(),
                provider_id: Some("domain-a".to_owned()),
            })
            .await?;
        store
            .attach_provider_reference(&o3k_store::ProviderReference {
                resource_id: server_id,
                provider_name: "agent".to_owned(),
                provider_resource_id: "domain-a".to_owned(),
            })
            .await?;
        let provider = AgentComputeProvider::new_with_store(
            registry,
            Arc::new(UnconfiguredResolvedCreateResolver),
            Some(store.clone()),
        );
        // Lifecycle commands must carry the O3K server id, not the provider
        // (libvirt domain) name: the agent derives the domain name from the
        // server id, and the durable command store requires a UUID. Dispatch
        // fails without a live stream, but the durable record proves the
        // command identity that would be sent.
        let stop_operation_id = Uuid::now_v7();
        store
            .insert_operation(&o3k_store::OperationRecord {
                id: stop_operation_id,
                resource_id: server_id,
                kind: "lifecycle:stop".to_owned(),
                state: o3k_store::OperationState::Running,
                provider_operation_id: None,
                error_category: None,
                error_message: None,
            })
            .await?;
        let stop = provider
            .action_instance(
                "domain-a",
                o3k_provider::InstanceAction::Stop,
                stop_operation_id,
                "stop-a",
            )
            .await;
        let stop_error = match stop {
            Err(error) => error,
            Ok(_) => return Err("stop dispatch unexpectedly succeeded without a stream".into()),
        };
        assert!(
            matches!(stop_error, ProviderError::Retryable),
            "stop failed with {stop_error:?}"
        );
        let record = store
            .get_agent_command_by_operation(stop_operation_id)
            .await?;
        let command = proto::Command::decode(record.payload.as_slice())?;
        assert_eq!(command.resource_id, server_id.to_string());
        assert!(matches!(
            command.action,
            Some(proto::command::Action::Stop(_))
        ));
        let delete_operation_id = Uuid::now_v7();
        store
            .insert_operation(&o3k_store::OperationRecord {
                id: delete_operation_id,
                resource_id: server_id,
                kind: "lifecycle:delete".to_owned(),
                state: o3k_store::OperationState::Running,
                provider_operation_id: None,
                error_category: None,
                error_message: None,
            })
            .await?;
        let delete = provider
            .delete_instance(DeleteInstanceRequest {
                operation_id: delete_operation_id,
                provider_instance_id: "domain-a".to_owned(),
                idempotency_key: "delete-a".to_owned(),
            })
            .await;
        let delete_error = match delete {
            Err(error) => error,
            Ok(_) => {
                return Err("delete dispatch unexpectedly succeeded without a stream".into());
            }
        };
        assert!(
            matches!(delete_error, ProviderError::Retryable),
            "delete failed with {delete_error:?}"
        );
        let record = store
            .get_agent_command_by_operation(delete_operation_id)
            .await?;
        let command = proto::Command::decode(record.payload.as_slice())?;
        assert_eq!(command.resource_id, server_id.to_string());
        assert!(matches!(
            command.action,
            Some(proto::command::Action::Delete(_))
        ));
        // A reconcile retry of the same operation must reuse the durable
        // command payload. Rebuilding it would drift the embedded deadline
        // and conflict with the durable record instead of replaying.
        let retry = provider
            .delete_instance(DeleteInstanceRequest {
                operation_id: delete_operation_id,
                provider_instance_id: "domain-a".to_owned(),
                idempotency_key: "delete-a".to_owned(),
            })
            .await;
        let retry_error = match retry {
            Err(error) => error,
            Ok(_) => return Err("delete retry unexpectedly succeeded without a stream".into()),
        };
        assert!(
            matches!(retry_error, ProviderError::Retryable),
            "delete retry failed with {retry_error:?}"
        );
        let replayed = store
            .get_agent_command_by_operation(delete_operation_id)
            .await?;
        assert_eq!(replayed.payload, record.payload);
        Ok(())
    }

    #[tokio::test]
    async fn agent_provider_requires_placement_and_never_invents_resolved_inputs()
    -> Result<(), Box<dyn std::error::Error>> {
        let registry = NodeRegistry::default();
        registry.register(&registered_agent("node-a")).await?;
        let provider =
            AgentComputeProvider::new(registry, Arc::new(UnconfiguredResolvedCreateResolver));
        let request = CreateInstanceRequest {
            operation_id: Uuid::now_v7(),
            o3k_server_id: Uuid::now_v7(),
            project_id: "project-a".to_owned(),
            name: "server-a".to_owned(),
            vcpus: 1,
            memory_mib: 512,
            flavor_id: String::new(),
            disk_gib: 0,
            image_id: Some("image-a".to_owned()),
            key_name: None,
            keypair_id: None,
            network_ids: vec!["port-a".to_owned()],
            placement_provider_id: None,
            placement_allocation_id: None,
            config_drive: None,
            idempotency_key: "request-a".to_owned(),
        };
        assert_eq!(
            provider.create_instance(request).await,
            Err(ProviderError::InvalidRequest)
        );
        Ok(())
    }

    /// The provider contract behind the issue-87 empty-registry defect: with
    /// no agent registered (a preserved agent still in reconnect backoff),
    /// `create_instance` must report NotFound — `selected_agent` fails before
    /// any dispatch, so the command can provably never be delivered — which
    /// lets the reconciler keep the operation re-drivable instead of treating
    /// the dispatch as a terminal failure.
    #[tokio::test]
    async fn agent_provider_create_with_empty_registry_reports_not_found()
    -> Result<(), Box<dyn std::error::Error>> {
        let registry = NodeRegistry::default();
        let provider = AgentComputeProvider::new(registry, Arc::new(TestResolvedCreateResolver));
        let request = CreateInstanceRequest {
            operation_id: Uuid::now_v7(),
            o3k_server_id: Uuid::now_v7(),
            project_id: "project-a".to_owned(),
            name: "server-a".to_owned(),
            vcpus: 1,
            memory_mib: 512,
            flavor_id: String::new(),
            disk_gib: 0,
            image_id: Some("image-a".to_owned()),
            key_name: None,
            keypair_id: None,
            network_ids: vec!["port-a".to_owned()],
            placement_provider_id: Some("node-a".to_owned()),
            placement_allocation_id: Some("allocation-a".to_owned()),
            config_drive: None,
            idempotency_key: "request-a".to_owned(),
        };
        assert!(matches!(
            provider.create_instance(request).await,
            Err(ProviderError::NotFound)
        ));
        Ok(())
    }

    #[tokio::test]
    async fn agent_provider_rejects_create_without_verified_artifacts()
    -> Result<(), Box<dyn std::error::Error>> {
        let registry = NodeRegistry::default();
        registry.register(&registered_agent("node-a")).await?;
        let provider = AgentComputeProvider::new(registry, Arc::new(TestResolvedCreateResolver));
        let operation_id = Uuid::now_v7();
        let request = CreateInstanceRequest {
            operation_id,
            o3k_server_id: Uuid::now_v7(),
            project_id: "project-a".to_owned(),
            name: "server-a".to_owned(),
            vcpus: 1,
            memory_mib: 512,
            flavor_id: String::new(),
            disk_gib: 0,
            image_id: Some("image-a".to_owned()),
            key_name: None,
            keypair_id: None,
            network_ids: vec!["port-a".to_owned()],
            placement_provider_id: Some("node-a".to_owned()),
            placement_allocation_id: Some("allocation-a".to_owned()),
            config_drive: None,
            idempotency_key: "request-a".to_owned(),
        };
        assert_eq!(
            provider.create_instance(request).await,
            Err(ProviderError::InvalidRequest)
        );
        assert_eq!(
            provider.get_operation(operation_id).await,
            Err(ProviderError::NotFound)
        );
        Ok(())
    }

    #[tokio::test]
    async fn agent_provider_rejects_config_drive_without_backend_capability()
    -> Result<(), Box<dyn std::error::Error>> {
        let registry = NodeRegistry::default();
        registry.register(&registered_agent("node-a")).await?;
        let provider = AgentComputeProvider::new(registry, Arc::new(TestResolvedCreateResolver));
        let operation_id = Uuid::now_v7();
        let request = CreateInstanceRequest {
            operation_id,
            o3k_server_id: Uuid::now_v7(),
            project_id: "project-a".to_owned(),
            name: "server-a".to_owned(),
            vcpus: 1,
            memory_mib: 512,
            flavor_id: String::new(),
            disk_gib: 0,
            image_id: Some("image-a".to_owned()),
            key_name: None,
            keypair_id: None,
            network_ids: vec!["port-a".to_owned()],
            placement_provider_id: Some("node-a".to_owned()),
            placement_allocation_id: Some("allocation-a".to_owned()),
            config_drive: Some(ConfigDriveRequest {
                user_data: b"#cloud-config\n".to_vec(),
                vendor_data: None,
                ssh_public_key: "ssh-ed25519 AAAA".to_owned(),
            }),
            idempotency_key: "request-a".to_owned(),
        };
        assert_eq!(
            provider.create_instance(request).await,
            Err(ProviderError::InvalidRequest)
        );
        assert_eq!(
            provider.get_operation(operation_id).await,
            Err(ProviderError::NotFound)
        );
        Ok(())
    }

    #[tokio::test]
    async fn agent_provider_projects_observations_and_agent_errors()
    -> Result<(), Box<dyn std::error::Error>> {
        let state = Arc::new(RwLock::new(AgentProviderState::default()));
        let operation_id = Uuid::now_v7();
        state.write().await.operations.insert(
            operation_id,
            Operation {
                provider_operation_id: operation_id,
                o3k_operation_id: operation_id,
                state: o3k_provider::OperationState::Accepted,
                error_category: None,
                provider_resource_id: None,
            },
        );
        let update = AgentOperationUpdate {
            agent_id: "node-a".to_owned(),
            agent_epoch: "epoch-1".to_owned(),
            operation_sequence: 1,
            operation_id,
            resource_id: Uuid::parse_str("11111111-1111-1111-1111-111111111111")
                .map_err(|_| ProviderError::InvalidRequest)?,
            state: AgentOperationState::Succeeded,
            error_category: None,
            redacted_message: None,
            provider_resource_id: Some("domain-a".to_owned()),
        };
        apply_agent_provider_event(
            &state,
            None,
            None,
            o3k_provider::AgentEvent::Operation(update.clone()),
        )
        .await;
        apply_agent_provider_event(
            &state,
            None,
            None,
            o3k_provider::AgentEvent::Observation(Box::new(AgentObservation {
                agent_id: "node-a".to_owned(),
                agent_epoch: "epoch-1".to_owned(),
                resource_id: update.resource_id,
                provider_resource_id: Some("domain-a".to_owned()),
                state: o3k_provider::InstanceState::Running,
                operation_id,
                operation_state: AgentOperationState::Succeeded,
                observation_sequence: 1,
                observed_at_unix_ms: 1,
                redacted_message: Some("running".to_owned()),
                console_log_bytes: Vec::new(),
                console_log_offset: 0,
                console_log_complete: false,
                console_log_truncated: false,
                block_device: None,
            })),
        )
        .await;
        let provider = AgentComputeProvider {
            registry: NodeRegistry::default(),
            resolver: Arc::new(UnconfiguredResolvedCreateResolver),
            state: state.clone(),
            store: None,
            artifact_resolver: Arc::new(UnconfiguredCreateArtifactResolver),
            command_timeout: Duration::from_secs(30),
        };
        assert_eq!(
            provider.get_instance("domain-a").await?.state,
            o3k_provider::InstanceState::Running
        );
        assert_eq!(
            provider
                .get_operation(operation_id)
                .await?
                .provider_resource_id
                .as_deref(),
            Some("domain-a")
        );
        apply_agent_provider_event(
            &state,
            None,
            None,
            o3k_provider::AgentEvent::Error(o3k_provider::AgentProtocolError {
                category: Some(AgentErrorCategory::Retryable),
                code: "agent-retry".to_owned(),
                redacted_message: Some("retry".to_owned()),
                operation_id: Some(operation_id),
                retryable: true,
                command_id: None,
            }),
        )
        .await;
        assert_eq!(
            provider.get_operation(operation_id).await?.state,
            o3k_provider::OperationState::Retryable
        );
        Ok(())
    }

    #[tokio::test]
    async fn artifact_status_rebinds_epoch_and_rejects_identity_conflicts()
    -> Result<(), Box<dyn std::error::Error>> {
        let store: Arc<dyn ComputeRepository> = Arc::new(o3k_store::testkit::open_memory().await?);
        let operation_id = Uuid::now_v7();
        let resource_id = Uuid::now_v7();
        let sha256 = "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef";
        store
            .insert_resource(&o3k_store::ResourceRecord {
                id: resource_id,
                kind: "compute_instance".to_owned(),
                project_id: "project-a".to_owned(),
                generation: 1,
                observed_generation: 1,
                desired_state: "{}".to_owned(),
                observed_state: "BUILD".to_owned(),
                provider_id: None,
            })
            .await?;
        store
            .insert_operation(&o3k_store::OperationRecord {
                id: operation_id,
                resource_id,
                kind: "compute_create".to_owned(),
                state: o3k_store::OperationState::Running,
                provider_operation_id: None,
                error_category: None,
                error_message: None,
            })
            .await?;
        store
            .insert_artifact_transfer(&ArtifactTransferRecord {
                transfer_id: "transfer-1".to_owned(),
                command_id: "command-1".to_owned(),
                operation_id,
                resource_id,
                agent_id: "agent-1".to_owned(),
                agent_epoch: "epoch-1".to_owned(),
                artifact_id: "artifact-1".to_owned(),
                artifact_kind: "image_base".to_owned(),
                sha256: sha256.to_owned(),
                size_bytes: 8,
                expires_at_unix_ms: i64::MAX,
                format: "raw".to_owned(),
                chunk_size_bytes: 4,
                chunk_count: 2,
                state: ArtifactTransferState::Offered,
                contiguous_bytes: 0,
                next_chunk_index: 0,
                retry_count: 0,
                created_at: String::new(),
                updated_at: String::new(),
            })
            .await?;
        let state = Arc::new(RwLock::new(AgentProviderState::default()));
        apply_agent_provider_event(
            &state,
            Some(store.as_ref()),
            None,
            o3k_provider::AgentEvent::ArtifactStatus(AgentArtifactStatus {
                transfer_id: "transfer-1".to_owned(),
                command_id: "command-1".to_owned(),
                operation_id,
                resource_id,
                agent_id: "agent-1".to_owned(),
                agent_epoch: "epoch-2".to_owned(),
                contiguous_bytes: 4,
                next_chunk_index: 1,
                state: o3k_provider::ArtifactTransferState::Receiving,
            }),
        )
        .await;
        let transfer = store.get_artifact_transfer("transfer-1").await?;
        assert_eq!(transfer.agent_epoch, "epoch-2");
        assert_eq!(transfer.state, ArtifactTransferState::Receiving);
        assert_eq!(transfer.contiguous_bytes, 4);

        apply_agent_provider_event(
            &state,
            Some(store.as_ref()),
            None,
            o3k_provider::AgentEvent::ArtifactStatus(AgentArtifactStatus {
                transfer_id: "transfer-1".to_owned(),
                command_id: "different-command".to_owned(),
                operation_id,
                resource_id,
                agent_id: "agent-1".to_owned(),
                agent_epoch: "epoch-2".to_owned(),
                contiguous_bytes: 8,
                next_chunk_index: 2,
                state: o3k_provider::ArtifactTransferState::Committed,
            }),
        )
        .await;
        let unchanged = store.get_artifact_transfer("transfer-1").await?;
        assert_eq!(unchanged.state, ArtifactTransferState::Receiving);
        assert_eq!(unchanged.contiguous_bytes, 4);
        Ok(())
    }

    #[tokio::test]
    async fn multi_controller_agent_stream_busy_rejection_and_dispatch_fencing()
    -> Result<(), Box<dyn std::error::Error>> {
        let store = Arc::new(o3k_store::O3kStore::connect_sqlite_memory().await?);
        let coord: Arc<dyn o3k_store::CoordinationRepository> = store.clone();

        let ctrl_a = o3k_store::ControllerId::new("ctrl-a");
        let epoch_a = o3k_store::ControllerEpoch::new("epoch-a");
        let ctrl_b = o3k_store::ControllerId::new("ctrl-b");
        let epoch_b = o3k_store::ControllerEpoch::new("epoch-b");

        let agent_id = "test-agent-1";
        let agent_epoch = "agent-epoch-1";

        let registry_a = NodeRegistry::default().with_coordination(
            coord.clone(),
            ctrl_a.clone(),
            epoch_a.clone(),
        );
        let registry_b = NodeRegistry::default().with_coordination(
            coord.clone(),
            ctrl_b.clone(),
            epoch_b.clone(),
        );

        // Register agent on both registries
        registry_a
            .register(&register(agent_id, agent_epoch))
            .await?;
        registry_b
            .register(&register(agent_id, agent_epoch))
            .await?;

        let (tx_a, mut rx_a) = mpsc::channel(16);
        let (tx_b, _rx_b) = mpsc::channel(16);

        // Controller A attaches successfully
        let attach_a = registry_a
            .attach_connection(agent_id, agent_epoch, tx_a)
            .await;
        assert!(attach_a.is_ok(), "Controller A must acquire stream lease");

        // Controller B attempts attach and gets Busy -> PermissionDenied
        let attach_b = registry_b
            .attach_connection(agent_id, agent_epoch, tx_b)
            .await;
        match attach_b {
            Err(e) => assert_eq!(e.code(), tonic::Code::PermissionDenied),
            Ok(_) => {
                return Err(
                    "Controller B must be rejected when stream is owned by Controller A".into(),
                );
            }
        }

        // Controller A can dispatch command
        let mut spec = valid_create_spec();
        spec.agent_id = agent_id.to_owned();
        spec.agent_epoch = agent_epoch.to_owned();
        let command = build_create_command(spec)?;

        let dispatch_a = registry_a.dispatch_command(command.clone()).await;
        assert!(
            dispatch_a.is_ok(),
            "Controller A must be able to dispatch with valid lease"
        );
        let received = rx_a.try_recv();
        assert!(
            received.is_ok(),
            "Agent stream on Controller A must receive the command"
        );

        // Now simulate expired takeover: stop A's background renewal, let lease expire, and B takes over with fence 2
        registry_a.abort_stream_renewal(agent_id).await;
        let work_key = format!("agent:{}", agent_id);
        // Renew with 1s TTL and wait 2.2s for expiry in SQLite
        let _ = coord
            .renew_work_lease(&work_key, &ctrl_a, &epoch_a, 1, Duration::from_secs(1))
            .await;
        tokio::time::sleep(Duration::from_millis(2200)).await;

        let takeover = coord
            .acquire_work_lease(
                &work_key,
                "agent_stream",
                &ctrl_b,
                &epoch_b,
                Duration::from_secs(15),
            )
            .await?;
        match takeover {
            o3k_store::LeaseAcquireOutcome::Acquired { lease } => {
                assert_eq!(lease.fencing_token, 2);
            }
            _ => {
                return Err(
                    "Controller B must acquire expired lease with incremented fence".into(),
                );
            }
        }

        // Stale Controller A attempts dispatch -> strictly rejected and sends ZERO commands
        let mut spec_stale = valid_create_spec();
        spec_stale.idempotency_key = "cmd-stale-2".to_owned();
        spec_stale.agent_id = agent_id.to_owned();
        spec_stale.agent_epoch = agent_epoch.to_owned();
        let command_stale = build_create_command(spec_stale)?;

        let dispatch_stale = registry_a.dispatch_command(command_stale).await;
        assert!(
            dispatch_stale.is_err(),
            "Controller A dispatch must fail when lease is stolen/fenced"
        );
        assert!(
            rx_a.try_recv().is_err(),
            "No command must be dispatched over stale socket"
        );
        Ok(())
    }
}

#[test]
fn durable_server_states_project_to_the_provider_vocabulary() {
    use o3k_provider::InstanceState as ProviderState;
    let expected = [
        ("REQUESTED", ProviderState::Creating),
        ("BUILD", ProviderState::Creating),
        ("ACTIVE", ProviderState::Running),
        ("STOPPING", ProviderState::Creating),
        ("SHUTOFF", ProviderState::Stopped),
        ("STARTING", ProviderState::Creating),
        ("REBOOTING", ProviderState::Creating),
        ("DELETING", ProviderState::Deleting),
        ("DELETED", ProviderState::Deleted),
        ("ERROR", ProviderState::Error),
    ];
    assert_eq!(expected.len(), 10);
    for (stored, provider) in expected {
        assert_eq!(
            instance_state_from_observed(stored),
            Some(provider),
            "{stored} must project to {provider:?}"
        );
    }
    // Legacy lowercase spellings and corrupt values: legacy spellings
    // decode, corrupt values fail closed.
    assert_eq!(
        instance_state_from_observed("active"),
        Some(ProviderState::Running)
    );
    assert_eq!(
        instance_state_from_observed("requested"),
        Some(ProviderState::Creating)
    );
    assert_eq!(instance_state_from_observed("garbage-state"), None);
}

#[cfg(test)]
#[allow(clippy::module_inception)]
mod block_device_tests;
