//! Application-side compute provider that dispatches all host lifecycle
//! commands through a selected, authenticated agent connection.
//!
//! This module is the transport adapter for compute execution: it converts
//! `o3k_provider::ComputeProvider` calls into wire commands, drives artifact
//! offers over the fenced control stream, and projects authenticated agent
//! events back into the provider vocabulary. The durable O3K journal remains
//! the recovery authority; this adapter mirrors volatile state and provides a
//! current-epoch, identity-checked command projection if that journal's
//! broadcast consumer lags.
//!
//! The control plane constructs a `ComputeProvider` from this adapter at the
//! composition root; application services depend only on the
//! `o3k_provider::ComputeProvider` port.

use std::{
    collections::{HashMap, HashSet},
    sync::{
        Arc,
        atomic::{AtomicU64, Ordering},
    },
    time::{Duration, SystemTime, UNIX_EPOCH},
};

use async_trait::async_trait;
use o3k_domain::ServerState;
use o3k_provider::{
    AgentOperationState, BlockDeviceAttachment, BlockDeviceObservation, Capabilities,
    ComputeProvider, ConnectorInfo, CreateArtifactResolver, CreateInstanceRequest,
    DeleteInstanceRequest, Instance, InstanceAction, Operation, ProviderError,
    ResolvedCreateResolver, UnconfiguredCreateArtifactResolver,
};
use o3k_provider_contract::compute_proto as agent_proto;
use o3k_store::{
    AgentCommandRecord, AgentCommandState, ArtifactTransferRecord, ArtifactTransferState,
    ArtifactTransferUpdate, ComputeRepository, StoreError, server_state_from_storage,
};
use prost::Message;
use tokio::sync::RwLock;
use uuid::Uuid;

use crate::{
    AgentError, Availability, BlockDeviceCommand, CreateCommandSpec, LifecycleCommand,
    MAX_ARTIFACT_CHUNK_BYTES, NodeRegistry, NodeSnapshot, agent_snapshot,
    build_block_device_command, build_create_command, build_lifecycle_command,
    deterministic_artifact_transfer_id,
};
#[derive(Debug, Clone)]
pub(crate) struct AgentBinding {
    resource_id: String,
    agent_id: String,
    agent_epoch: String,
    provider_resource_id: Option<String>,
}

#[derive(Default)]
pub(crate) struct AgentProviderState {
    /// In-memory projection of durable agent operations; the journal is the
    /// recovery authority.
    pub(crate) operations: HashMap<Uuid, Operation>,
    instances: HashMap<String, Instance>,
    bindings: HashMap<String, AgentBinding>,
}

/// ComputeProvider adapter that sends all host lifecycle commands through a
/// selected, authenticated NodeRegistry connection.
///
/// The adapter deliberately returns an accepted provider operation after the
/// command is put on the fenced control stream. Later operation and
/// observation events update the adapter's projection; the durable O3K
/// journal remains the recovery authority.
#[derive(Clone)]
pub struct AgentComputeProvider {
    pub(crate) registry: NodeRegistry,
    pub(crate) resolver: Arc<dyn ResolvedCreateResolver>,
    pub(crate) artifact_resolver: Arc<dyn CreateArtifactResolver>,
    pub(crate) state: Arc<RwLock<AgentProviderState>>,
    pub(crate) store: Option<Arc<dyn ComputeRepository>>,
    pub(crate) command_timeout: Duration,
}

/// Test-only fault pause (issue #88 E3 C3): sleeps the configured duration
/// immediately before the durable command insert in `dispatch_recorded` when
/// a test stores a non-zero value here. Zero (the production value) is a
/// no-op; no production path ever writes this static. Mirrors the
/// reconciler's `test_fault_pause_ms` pattern for driving the
/// read-then-insert race deterministically.
pub(crate) static DISPATCH_RECORDED_INSERT_PAUSE_MS: AtomicU64 = AtomicU64::new(0);

impl AgentComputeProvider {
    #[must_use]
    pub fn new(registry: NodeRegistry, resolver: Arc<dyn ResolvedCreateResolver>) -> Self {
        Self::new_with_store(registry, resolver, None)
    }

    #[must_use]
    pub fn new_with_store(
        registry: NodeRegistry,
        resolver: Arc<dyn ResolvedCreateResolver>,
        store: Option<Arc<dyn ComputeRepository>>,
    ) -> Self {
        let state = Arc::new(RwLock::new(AgentProviderState::default()));
        let mut events = registry.subscribe_events();
        let event_state = state.clone();
        let event_store = store.clone();
        let event_registry = registry.clone();
        tokio::spawn(async move {
            loop {
                match events.recv().await {
                    Ok(event) => {
                        apply_agent_provider_event(
                            &event_state,
                            event_store.as_deref(),
                            Some(&event_registry),
                            event,
                        )
                        .await
                    }
                    Err(tokio::sync::broadcast::error::RecvError::Lagged(_)) => {
                        tracing::warn!(
                            "agent provider event projection lagged; durable recovery is required"
                        );
                    }
                    Err(tokio::sync::broadcast::error::RecvError::Closed) => break,
                }
            }
        });
        Self {
            registry,
            resolver,
            artifact_resolver: Arc::new(UnconfiguredCreateArtifactResolver),
            state,
            store,
            command_timeout: Duration::from_secs(30),
        }
    }

    #[must_use]
    pub fn with_command_timeout(mut self, timeout: Duration) -> Self {
        self.command_timeout = timeout;
        self
    }

    /// Resolves the fenced agent bound to a server resource.
    pub async fn agent_for_server(
        &self,
        resource_id: Uuid,
    ) -> Result<(NodeSnapshot, String), ProviderError> {
        let binding = {
            let state = self.state.read().await;
            state
                .bindings
                .values()
                .find(|binding| binding.resource_id == resource_id.to_string())
                .cloned()
        };
        let binding = binding.ok_or(ProviderError::NotFound)?;
        let agent = self.selected_agent(&binding.agent_id).await?;
        if agent.agent_epoch != binding.agent_epoch {
            return Err(ProviderError::StaleState);
        }
        Ok((agent, binding.resource_id))
    }

    /// Persists and dispatches a block-device command, waiting for the bound
    /// observation. A timeout is an unknown outcome requiring observation
    /// before retry.
    pub async fn dispatch_block_device_and_wait(
        &self,
        command: agent_proto::Command,
        operation_id: Uuid,
        timeout: Duration,
    ) -> Result<o3k_provider::BlockDeviceObservation, ProviderError> {
        self.persist_pending_command(&command, operation_id).await?;
        self.registry
            .dispatch_command_and_wait(command, timeout)
            .await
            .map_err(|error| match error {
                AgentError::Protocol(message) if message.contains("observation timed out") => {
                    ProviderError::UnknownOutcome { operation_id }
                }
                other => map_agent_error(other),
            })?
            .block_device
            .ok_or(ProviderError::Terminal)
    }

    #[must_use]
    pub fn with_artifact_resolver(mut self, resolver: Arc<dyn CreateArtifactResolver>) -> Self {
        self.artifact_resolver = resolver.clone();
        if let Some(recovery_store) = self.store.clone() {
            let recovery_registry = self.registry.clone();
            let recovery_resolver = self.resolver.clone();
            let recovery_timeout = self.command_timeout;
            tokio::spawn(async move {
                recover_artifact_transfers(
                    recovery_registry,
                    recovery_resolver,
                    resolver,
                    recovery_store,
                    recovery_timeout,
                )
                .await;
            });
        }
        self
    }

    /// Rebuilds the provider's volatile instance/binding projection from the
    /// durable resource ledger after a daemon restart or agent reconnect.
    /// Provider references and the currently authenticated agent epoch are
    /// both required; stale or conflicting ownership evidence is rejected.
    pub async fn rehydrate(&self) -> Result<(), ProviderError> {
        let Some(store) = &self.store else {
            return Ok(());
        };
        let resources = store
            .list_resources_by_kind("compute_instance")
            .await
            .map_err(|_| ProviderError::Retryable)?;
        // Ids of resources that durably reached a provider definition.
        // Never-defined in-memory bindings (the create dispatch was accepted
        // but no provider object was ever defined — issue #88 S3) have no
        // durable provider reference to rebuild from; they are preserved
        // below exactly while their resource is NOT durably defined (a
        // failed, unknown-outcome, or already-Deleted create — the local
        // reap-delete shape). Once a create durably succeeds, the
        // never-defined entry is stale and is purged as before.
        let defined_resource_ids: HashSet<Uuid> = resources
            .iter()
            .filter(|resource| {
                !matches!(
                    server_state_from_storage(&resource.observed_state),
                    Ok(ServerState::Deleted)
                ) && resource.provider_id.is_some()
            })
            .map(|resource| resource.id)
            .collect();
        let mut instances = HashMap::new();
        let mut bindings = HashMap::new();
        for resource in resources {
            if matches!(
                server_state_from_storage(&resource.observed_state),
                Ok(ServerState::Deleted)
            ) {
                continue;
            }
            let Some(provider_id) = resource.provider_id.clone() else {
                continue;
            };
            let reference = store
                .get_provider_reference(resource.id, "agent")
                .await
                .map_err(|_| ProviderError::Conflict)?;
            if reference.provider_resource_id != provider_id {
                return Err(ProviderError::Conflict);
            }
            let request: CreateInstanceRequest = serde_json::from_str(&resource.desired_state)
                .map_err(|_| ProviderError::Conflict)?;
            let Some(agent_id) = request.placement_provider_id.as_deref() else {
                return Err(ProviderError::Conflict);
            };
            let Some(agent) = self.registry.snapshot(agent_id).await else {
                continue;
            };
            if agent.agent_epoch.trim().is_empty() {
                return Err(ProviderError::Conflict);
            }
            let state = instance_state_from_observed(&resource.observed_state)
                .ok_or(ProviderError::Conflict)?;
            instances.insert(
                provider_id.clone(),
                Instance {
                    provider_instance_id: provider_id.clone(),
                    o3k_server_id: resource.id,
                    state,
                    observed_message: None,
                },
            );
            bindings.insert(
                provider_id,
                AgentBinding {
                    resource_id: resource.id.to_string(),
                    agent_id: agent.agent_id,
                    agent_epoch: agent.agent_epoch,
                    provider_resource_id: resource.provider_id,
                },
            );
        }
        let mut state = self.state.write().await;
        state
            .instances
            .retain(|provider_id, _| instances.contains_key(provider_id));
        state.bindings.retain(|key, binding| {
            if bindings.contains_key(key) {
                return true;
            }
            // A never-defined binding (no provider object ever defined)
            // is preserved while its resource is durably present but not
            // provider-defined — the reap delete (issue #88 S3) needs it
            // to reach the agent that accepted the create. Once the
            // resource is durably defined, the never-defined entry is
            // stale and is purged.
            !(binding.provider_resource_id.is_none()
                && Uuid::parse_str(key).is_ok_and(|id| defined_resource_ids.contains(&id)))
        });
        state.instances.extend(instances);
        state.bindings.extend(bindings);
        Ok(())
    }

    async fn selected_agent(&self, provider_id: &str) -> Result<NodeSnapshot, ProviderError> {
        let snapshot = self
            .registry
            .snapshot(provider_id)
            .await
            .ok_or(ProviderError::NotFound)?;
        if snapshot.availability != Availability::Available {
            return Err(ProviderError::Retryable);
        }
        if snapshot.desired_state != agent_proto::AdministrativeState::Enabled as i32 {
            return Err(ProviderError::Retryable);
        }
        Ok(snapshot)
    }

    async fn dispatch(
        &self,
        command: agent_proto::Command,
        operation_id: Uuid,
    ) -> Result<(), ProviderError> {
        self.registry
            .dispatch_command(command)
            .await
            .map_err(|error| match error {
                AgentError::Protocol(message)
                    if message
                        .to_ascii_lowercase()
                        .contains("deadline has expired") =>
                {
                    // A durably recorded command whose embedded deadline
                    // expired during a re-dispatch may already have been
                    // delivered and executed while the control stream was
                    // stalled: the outcome is unknown, never a rejected
                    // request (issue #87 B2 — the agent accepted and
                    // executed the reboot while the acceptance and terminal
                    // observation were dropped). The reconciler's
                    // UnknownOutcome path observes the operation before
                    // retrying and adopts the re-delivered terminal evidence
                    // instead of terminalizing the operation.
                    ProviderError::UnknownOutcome { operation_id }
                }
                other => map_agent_error(other),
            })
    }

    async fn accepted_operation(&self, operation_id: Uuid) -> Result<Operation, ProviderError> {
        let operation = Operation {
            provider_operation_id: operation_id,
            o3k_operation_id: operation_id,
            state: o3k_provider::OperationState::Accepted,
            error_category: None,
            provider_resource_id: None,
        };
        self.state
            .write()
            .await
            .operations
            .insert(operation_id, operation.clone());
        Ok(operation)
    }

    async fn dispatch_recorded(
        &self,
        command: agent_proto::Command,
        operation_id: Uuid,
    ) -> Result<Operation, ProviderError> {
        if let Some(store) = &self.store {
            if let Ok(existing) = store.get_agent_command_by_operation(operation_id).await {
                if self.recorded_command_can_be_redelivered(&existing).await {
                    return self.reuse_recorded_command(existing, operation_id).await;
                }
                // Issue #610 (ASR-021 agent-control-plane-network-interruption):
                // the durable command is still `pending` but its recorded
                // payload can no longer be delivered — the agent re-registered
                // under a fresh epoch (the registry fences the recorded epoch),
                // or the embedded deadline expired (`validate_command` rejects
                // it). Re-dispatching the recorded payload verbatim could never
                // reach the agent again, so the freshly built command (current
                // epoch, fresh deadline) is dispatched instead. The
                // deterministic command identity (command id, operation,
                // resource, idempotency key) is unchanged; the agent journal
                // dedups by that identity, so a command that was never accepted
                // executes exactly once and an accepted one rejects the rebuilt
                // fingerprint instead of re-executing.
                tracing::warn!(
                    operation_id = %operation_id,
                    command_id = %existing.command_id,
                    recorded_epoch = %existing.agent_epoch,
                    "re-dispatching an undeliverable recorded command with a freshly built command"
                );
                return self.dispatch_accepted(command, operation_id).await;
            }
            let pause_ms = DISPATCH_RECORDED_INSERT_PAUSE_MS.load(Ordering::Relaxed);
            if pause_ms > 0 {
                std::thread::sleep(Duration::from_millis(pause_ms));
            }
            let record = AgentCommandRecord {
                command_id: command.command_id.clone(),
                idempotency_key: command.idempotency_key.clone(),
                operation_id,
                resource_id: Uuid::parse_str(&command.resource_id)
                    .map_err(|_| ProviderError::InvalidRequest)?,
                agent_id: command.agent_id.clone(),
                agent_epoch: command.agent_epoch.clone(),
                payload_fingerprint_sha256: command.payload_fingerprint_sha256.clone(),
                payload: command.encode_to_vec(),
                state: AgentCommandState::Pending,
                accepted_sequence: 0,
                last_sequence: 0,
                provider_operation_id: Some(operation_id.to_string()),
                provider_resource_id: None,
            };
            if store.insert_agent_command(&record).await.is_err() {
                // The read above saw no row, but this insert conflicted: a
                // concurrent dispatch for the same operation inserted its
                // durable command in between (issue #88 E3 C3 — the API's
                // synchronous create reconcile races the periodic
                // create-convergence sweep, and both read "no row" before
                // either inserts). The command identity is deterministic per
                // operation, so the surviving row IS this command: adopt it
                // and re-dispatch the recorded payload instead of failing.
                // The agent journal replays by command identity, so the
                // re-dispatch converges on one execution.
                if let Ok(existing) = store.get_agent_command_by_operation(operation_id).await {
                    return self.reuse_recorded_command(existing, operation_id).await;
                }
                return Err(ProviderError::Conflict);
            }
        }
        self.dispatch_accepted(command, operation_id).await
    }

    /// Re-dispatches a durable command record for the operation: terminal
    /// rows return the recorded operation; Pending/Accepted rows are
    /// re-dispatched with their RECORDED payload (rebuilding would drift the
    /// embedded deadline and break the agent journal's idempotent replay
    /// with an identity conflict).
    async fn reuse_recorded_command(
        &self,
        existing: AgentCommandRecord,
        operation_id: Uuid,
    ) -> Result<Operation, ProviderError> {
        if matches!(
            existing.state,
            AgentCommandState::Succeeded | AgentCommandState::Failed
        ) {
            return self.get_operation(operation_id).await;
        }
        let recorded = agent_proto::Command::decode(existing.payload.as_slice())
            .map_err(|_| ProviderError::Storage)?;
        self.dispatch_accepted(recorded, operation_id).await
    }

    /// Issue #610: decides whether a durable Pending command's RECORDED
    /// payload can still be delivered over the control plane. A Pending
    /// create or inspect command whose agent epoch no longer matches the
    /// registered node (the agent re-registered after a control-channel
    /// interruption) or whose embedded deadline has expired can never be
    /// dispatched again — `dispatch_command` fences the stale epoch and
    /// `validate_command` rejects the expired deadline — so the caller must
    /// rebuild the command instead of reusing the recorded payload. The
    /// deterministic command identity keeps the agent journal idempotent: a
    /// command that was never accepted executes exactly once, an accepted one
    /// rejects the rebuilt fingerprint (create) or replays the entry
    /// (inspect) instead of re-executing.
    ///
    /// Other lifecycle actions are deliberately excluded: their re-drives
    /// keep the recorded-payload semantics (issue #87 B2), where a
    /// deadline-expired re-dispatch is classified as an unknown outcome and
    /// the reconciler observes the operation — the agent journal replays the
    /// terminal evidence after the stream recovers. Accepted/Running/Terminal
    /// rows are always redeliverable: the agent journal replays or returns
    /// them by identity. A node absent from the registry (a control-plane
    /// restart while the agent is still in reconnect backoff) keeps the
    /// recorded payload: the dispatch fails `not registered`/`StaleState` and
    /// the next re-drive re-decides once the agent's fresh registration
    /// lands.
    async fn recorded_command_can_be_redelivered(
        &self,
        record: &o3k_store::AgentCommandRecord,
    ) -> bool {
        if record.state != AgentCommandState::Pending {
            return true;
        }
        let Ok(recorded) = agent_proto::Command::decode(record.payload.as_slice()) else {
            return true;
        };
        if !matches!(
            recorded.action,
            Some(agent_proto::command::Action::Create(_))
                | Some(agent_proto::command::Action::Inspect(_))
        ) {
            return true;
        }
        if recorded.deadline_unix_ms <= unix_ms() {
            return false;
        }
        match self.registry.snapshot(&record.agent_id).await {
            Some(node) => node.agent_epoch == recorded.agent_epoch,
            None => true,
        }
    }

    async fn dispatch_accepted(
        &self,
        command: agent_proto::Command,
        operation_id: Uuid,
    ) -> Result<Operation, ProviderError> {
        let operation = self.accepted_operation(operation_id).await?;
        if let Err(error) = self.dispatch(command, operation_id).await {
            self.state.write().await.operations.remove(&operation_id);
            return Err(error);
        }
        Ok(operation)
    }

    pub async fn persist_pending_command(
        &self,
        command: &agent_proto::Command,
        operation_id: Uuid,
    ) -> Result<Option<AgentCommandRecord>, ProviderError> {
        let Some(store) = &self.store else {
            return Ok(None);
        };
        let resource_id =
            Uuid::parse_str(&command.resource_id).map_err(|_| ProviderError::InvalidRequest)?;
        crate::persist_command_record(store.as_ref(), command, operation_id, resource_id)
            .await
            .map_err(|_| ProviderError::Conflict)
    }

    /// Issue #88 S5 fallback: reap a NEVER-ACCEPTED create through its
    /// durable command row — the only residue evidence the control plane
    /// has when no binding exists. `provider_instance_id` is the O3K server
    /// id (the local-completion reap shape): resolve the create intent from
    /// the resource's desired state (the same JSON the reconciler parses),
    /// take the create command's agent, and dispatch the Delete with the
    /// REGISTRY's current epoch — the row's epoch is stale after a
    /// control-plane restart, and the registry is authoritative for the
    /// agent's current epoch (the #568 never-defined relaxation rationale;
    /// the wire dispatch additionally fences the command by the current
    /// registered epoch). Missing or unparseable residue evidence falls
    /// through to `NotFound`: the local completion is unaffected and the
    /// residue verifier catches leftovers.
    async fn reap_never_accepted_create(
        &self,
        request: DeleteInstanceRequest,
    ) -> Result<Operation, ProviderError> {
        let Some(store) = &self.store else {
            return Err(ProviderError::NotFound);
        };
        let Ok(server_id) = Uuid::parse_str(&request.provider_instance_id) else {
            return Err(ProviderError::NotFound);
        };
        let Ok(resource) = store.get_resource(server_id).await else {
            return Err(ProviderError::NotFound);
        };
        let Ok(create) = serde_json::from_str::<CreateInstanceRequest>(&resource.desired_state)
        else {
            return Err(ProviderError::NotFound);
        };
        let Ok(command) = store
            .get_agent_command_by_operation(create.operation_id)
            .await
        else {
            return Err(ProviderError::NotFound);
        };
        let agent = self.selected_agent(&command.agent_id).await?;
        let mut delete = build_lifecycle_command(
            LifecycleCommand::Delete,
            &agent.agent_id,
            &agent.agent_epoch,
            &request.operation_id.to_string(),
            &server_id.to_string(),
        )
        .map_err(map_agent_error)?;
        delete.idempotency_key = request.idempotency_key.clone();
        self.dispatch_recorded(delete, request.operation_id).await
    }
}

async fn recover_artifact_transfers(
    registry: NodeRegistry,
    resolver: Arc<dyn ResolvedCreateResolver>,
    artifact_resolver: Arc<dyn CreateArtifactResolver>,
    store: Arc<dyn ComputeRepository>,
    timeout: Duration,
) {
    let transfers = match store.list_recoverable_artifact_transfers().await {
        Ok(transfers) => transfers,
        Err(error) => {
            tracing::warn!(%error, "artifact transfer recovery listing failed");
            return;
        }
    };
    for transfer in transfers {
        if transfer.expires_at_unix_ms <= unix_ms() {
            if let Err(error) = store
                .update_artifact_transfer(
                    &transfer.transfer_id,
                    &transfer.agent_epoch,
                    ArtifactTransferUpdate {
                        state: ArtifactTransferState::Expired,
                        contiguous_bytes: transfer.contiguous_bytes,
                        next_chunk_index: transfer.next_chunk_index,
                        retry_count: transfer.retry_count,
                    },
                )
                .await
            {
                tracing::warn!(
                    transfer_id = %transfer.transfer_id,
                    %error,
                    "expired artifact transfer could not be fenced"
                );
            }
            continue;
        }
        let Some(agent) = registry.snapshot(&transfer.agent_id).await else {
            continue;
        };
        let transfer = if agent.agent_epoch != transfer.agent_epoch {
            match store
                .rebind_artifact_transfer_epoch(
                    &transfer.transfer_id,
                    &transfer.agent_epoch,
                    &agent.agent_epoch,
                )
                .await
            {
                Ok(transfer) => transfer,
                Err(error) => {
                    tracing::warn!(
                        transfer_id = %transfer.transfer_id,
                        %error,
                        "artifact transfer recovery could not rebind agent epoch"
                    );
                    continue;
                }
            }
        } else {
            transfer
        };
        let resource = match store.get_resource(transfer.resource_id).await {
            Ok(resource) => resource,
            Err(error) => {
                tracing::warn!(transfer_id = %transfer.transfer_id, %error, "artifact transfer intent missing");
                continue;
            }
        };
        let request: CreateInstanceRequest = match serde_json::from_str(&resource.desired_state) {
            Ok(request) => request,
            Err(error) => {
                tracing::warn!(transfer_id = %transfer.transfer_id, %error, "artifact transfer intent is invalid");
                continue;
            }
        };
        let app_agent = agent_snapshot(&agent);
        let inputs = match resolver.resolve(&request, &app_agent).await {
            Ok(inputs) => inputs,
            Err(error) => {
                tracing::warn!(transfer_id = %transfer.transfer_id, %error, "artifact transfer source recovery failed");
                continue;
            }
        };
        let artifacts = match artifact_resolver
            .resolve_artifacts(&request, &app_agent, &inputs)
            .await
        {
            Ok(artifacts) => artifacts,
            Err(error) => {
                tracing::warn!(transfer_id = %transfer.transfer_id, %error, "artifact transfer bytes recovery failed");
                continue;
            }
        };
        let Some(artifact) = artifacts.into_iter().find(|artifact| {
            artifact.artifact_id == transfer.artifact_id
                && artifact.sha256 == transfer.sha256
                && artifact.format == transfer.format
                && artifact_kind_name(artifact.kind) == transfer.artifact_kind
        }) else {
            tracing::warn!(transfer_id = %transfer.transfer_id, "artifact transfer identity has no matching source");
            continue;
        };
        let kind = match transfer.artifact_kind.as_str() {
            "image_base" => agent_proto::ArtifactKind::ImageBase,
            "config_drive_iso" => agent_proto::ArtifactKind::ConfigDriveIso,
            _ => continue,
        };
        let offer = agent_proto::ArtifactOffer {
            transfer_id: transfer.transfer_id.clone(),
            command_id: transfer.command_id.clone(),
            operation_id: transfer.operation_id.to_string(),
            resource_id: transfer.resource_id.to_string(),
            agent_id: transfer.agent_id.clone(),
            artifact_id: transfer.artifact_id.clone(),
            kind: kind as i32,
            sha256: transfer.sha256.clone(),
            size_bytes: transfer.size_bytes,
            format: transfer.format.clone(),
            chunk_size_bytes: transfer.chunk_size_bytes as u32,
            chunk_count: transfer.chunk_count as u32,
            expires_at_unix_ms: transfer.expires_at_unix_ms,
        };
        let Ok(start_chunk_index) = u32::try_from(transfer.next_chunk_index) else {
            tracing::warn!(transfer_id = %transfer.transfer_id, "artifact transfer resume index is invalid");
            continue;
        };
        match registry
            .dispatch_artifact_and_wait_from(offer, artifact.bytes, start_chunk_index, timeout)
            .await
        {
            Ok(_) => {
                let _ = store
                    .update_artifact_transfer(
                        &transfer.transfer_id,
                        &transfer.agent_epoch,
                        ArtifactTransferUpdate {
                            state: ArtifactTransferState::Committed,
                            contiguous_bytes: transfer.size_bytes,
                            next_chunk_index: transfer.chunk_count,
                            retry_count: transfer.retry_count,
                        },
                    )
                    .await;
            }
            Err(error) => {
                tracing::warn!(transfer_id = %transfer.transfer_id, %error, "artifact transfer recovery dispatch failed")
            }
        }
    }
}

fn map_agent_error(error: AgentError) -> ProviderError {
    match error {
        AgentError::Protocol(message) => {
            let message = message.to_ascii_lowercase();
            if message.contains("unavailable")
                || message.contains("closed")
                || message.contains("timeout")
            {
                ProviderError::Retryable
            } else if message.contains("fenced") || message.contains("not registered") {
                ProviderError::StaleState
            } else {
                ProviderError::InvalidRequest
            }
        }
        AgentError::Transport(_)
        | AgentError::IdentityStore(_)
        | AgentError::TlsMaterial
        | AgentError::InvalidConfiguration(_) => ProviderError::Retryable,
    }
}

/// A transfer that ended without a definitive acknowledgement is an unknown
/// outcome, never a terminal failure (issue #603; ASR-021 matrix scenario
/// agent-control-plane-network-interruption): the operation engine must
/// observe and re-drive it, and the transfer resume path
/// (`dispatch_artifact_and_wait_from`) makes that re-drive idempotent.
/// Mapping it terminal stranded an interrupted create in `failed` even though
/// no provider-side rejection ever occurred.
fn map_artifact_transfer_error(error: AgentError, operation_id: Uuid) -> ProviderError {
    match error {
        AgentError::Protocol(message) if message.contains("outcome is unknown") => {
            ProviderError::UnknownOutcome { operation_id }
        }
        other => map_agent_error(other),
    }
}

fn artifact_kind_name(kind: o3k_provider::ArtifactKind) -> &'static str {
    match kind {
        o3k_provider::ArtifactKind::ImageBase => "image_base",
        o3k_provider::ArtifactKind::ConfigDriveIso => "config_drive_iso",
    }
}

fn equivalent_committed_transfer(
    current: &ArtifactTransferRecord,
    offer: &agent_proto::ArtifactOffer,
    operation_id: Uuid,
    resource_id: Uuid,
    artifact_kind: &str,
    agent_epoch: &str,
) -> bool {
    current.transfer_id == offer.transfer_id
        && current.command_id == offer.command_id
        && current.operation_id == operation_id
        && current.resource_id == resource_id
        && current.agent_id == offer.agent_id
        && current.agent_epoch == agent_epoch
        && current.artifact_id == offer.artifact_id
        && current.artifact_kind == artifact_kind
        && current.sha256 == offer.sha256
        && current.size_bytes == offer.size_bytes
        && current.format == offer.format
        && current.chunk_size_bytes == offer.chunk_size_bytes as u64
        && current.chunk_count == offer.chunk_count as u64
        && current.state == ArtifactTransferState::Committed
        && current.contiguous_bytes == offer.size_bytes
        && current.next_chunk_index == offer.chunk_count as u64
}

fn unix_ms_after(duration: Duration) -> i64 {
    unix_ms().saturating_add(duration.as_millis().min(i64::MAX as u128) as i64)
}

fn unix_ms() -> i64 {
    let now = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or_default();
    now.as_millis().min(i64::MAX as u128) as i64
}

fn agent_operation_state(
    state: o3k_provider::AgentOperationState,
) -> Option<o3k_provider::OperationState> {
    use o3k_provider::AgentOperationState as AgentState;
    Some(match state {
        AgentState::Accepted => o3k_provider::OperationState::Accepted,
        AgentState::Running => o3k_provider::OperationState::Running,
        AgentState::Succeeded => o3k_provider::OperationState::Succeeded,
        AgentState::Failed => o3k_provider::OperationState::Failed,
        AgentState::UnknownOutcome => o3k_provider::OperationState::UnknownOutcome,
    })
}

fn agent_error_category(
    category: Option<o3k_provider::AgentErrorCategory>,
) -> Option<o3k_provider::ErrorCategory> {
    use o3k_provider::AgentErrorCategory as AgentCategory;
    category.and_then(|category| match category {
        AgentCategory::InvalidRequest => Some(o3k_provider::ErrorCategory::InvalidRequest),
        AgentCategory::Conflict => Some(o3k_provider::ErrorCategory::Conflict),
        AgentCategory::Capacity => Some(o3k_provider::ErrorCategory::Capacity),
        AgentCategory::NotFound => Some(o3k_provider::ErrorCategory::NotFound),
        AgentCategory::Retryable => Some(o3k_provider::ErrorCategory::Retryable),
        AgentCategory::UnknownOutcome => Some(o3k_provider::ErrorCategory::UnknownOutcome),
        AgentCategory::Terminal => Some(o3k_provider::ErrorCategory::Terminal),
        AgentCategory::Unauthenticated | AgentCategory::Unauthorized => None,
    })
}

/// Decodes a durable observed value into the provider's own instance-state
/// vocabulary for the agent provider's rehydrate projection. The durable
/// value is decoded through the canonical fail-closed store decoder first, so
/// the provider vocabulary is a projection of the canonical model rather than
/// a second decoder of persisted strings.
pub(crate) fn instance_state_from_observed(value: &str) -> Option<o3k_provider::InstanceState> {
    let state = server_state_from_storage(value).ok()?;
    match state {
        ServerState::Requested
        | ServerState::Building
        | ServerState::Stopping
        | ServerState::Starting
        | ServerState::Rebooting => Some(o3k_provider::InstanceState::Creating),
        ServerState::Active => Some(o3k_provider::InstanceState::Running),
        ServerState::Stopped => Some(o3k_provider::InstanceState::Stopped),
        ServerState::Deleting => Some(o3k_provider::InstanceState::Deleting),
        ServerState::Deleted => Some(o3k_provider::InstanceState::Deleted),
        ServerState::Error => Some(o3k_provider::InstanceState::Error),
    }
}

pub(crate) async fn apply_artifact_status(
    store: &dyn ComputeRepository,
    status: &o3k_provider::AgentArtifactStatus,
) -> Result<(), StoreError> {
    let transfer = store.get_artifact_transfer(&status.transfer_id).await?;
    if transfer.command_id != status.command_id
        || transfer.operation_id != status.operation_id
        || transfer.resource_id != status.resource_id
        || transfer.agent_id != status.agent_id
    {
        return Err(StoreError::ArtifactTransferConflict(
            "artifact status identity conflicts with durable state".to_owned(),
        ));
    }
    let state = match status.state {
        o3k_provider::ArtifactTransferState::Offered => ArtifactTransferState::Offered,
        o3k_provider::ArtifactTransferState::Receiving => ArtifactTransferState::Receiving,
        o3k_provider::ArtifactTransferState::Committed => ArtifactTransferState::Committed,
        o3k_provider::ArtifactTransferState::Rejected => ArtifactTransferState::Rejected,
        o3k_provider::ArtifactTransferState::Expired => ArtifactTransferState::Expired,
    };
    if transfer.agent_epoch != status.agent_epoch {
        if matches!(
            transfer.state,
            ArtifactTransferState::Committed
                | ArtifactTransferState::Rejected
                | ArtifactTransferState::Expired
        ) {
            return Err(StoreError::ArtifactTransferEpochConflict);
        }
        store
            .rebind_artifact_transfer_epoch(
                &transfer.transfer_id,
                &transfer.agent_epoch,
                &status.agent_epoch,
            )
            .await?;
    }
    store
        .update_artifact_transfer(
            &status.transfer_id,
            &status.agent_epoch,
            ArtifactTransferUpdate {
                state,
                contiguous_bytes: status.contiguous_bytes,
                next_chunk_index: u64::from(status.next_chunk_index),
                retry_count: transfer.retry_count,
            },
        )
        .await
        .map(|_| ())
}

pub(crate) async fn apply_agent_provider_event(
    state: &Arc<RwLock<AgentProviderState>>,
    store: Option<&dyn ComputeRepository>,
    registry: Option<&NodeRegistry>,
    event: o3k_provider::AgentEvent,
) {
    let _epoch_lease = if let Some(registry) = registry {
        let identity = match &event {
            o3k_provider::AgentEvent::CommandAccepted(accepted) => {
                Some((&accepted.agent_id, &accepted.agent_epoch))
            }
            o3k_provider::AgentEvent::Operation(update) => {
                Some((&update.agent_id, &update.agent_epoch))
            }
            o3k_provider::AgentEvent::Observation(observation) => {
                Some((&observation.agent_id, &observation.agent_epoch))
            }
            _ => None,
        };
        if let Some((agent_id, agent_epoch)) = identity {
            match o3k_provider::AgentNodeRegistry::lease_current_epoch(
                registry,
                agent_id,
                agent_epoch,
            )
            .await
            {
                Some(lease) => Some(lease),
                None => {
                    tracing::debug!(%agent_id, %agent_epoch, "replaced-epoch provider event was not projected");
                    return;
                }
            }
        } else {
            None
        }
    } else {
        None
    };
    let mut state = state.write().await;
    match event {
        o3k_provider::AgentEvent::CommandAccepted(accepted) => {
            if let Some(store) = store
                && let Ok(command) = store.get_agent_command(&accepted.command_id).await
                && command.operation_id == accepted.operation_id
                && command.agent_id == accepted.agent_id
                && command.state != AgentCommandState::UnknownOutcome
                && matches!(
                    accepted.state,
                    AgentOperationState::Accepted | AgentOperationState::Running
                )
                && let Ok(operation) = store.get_operation(accepted.operation_id).await
                && !matches!(
                    operation.state,
                    o3k_store::OperationState::Succeeded
                        | o3k_store::OperationState::Failed
                        | o3k_store::OperationState::UnknownOutcome
                )
                && let Err(error) = store
                    .update_agent_command(
                        &accepted.command_id,
                        AgentCommandState::Accepted,
                        accepted.operation_sequence,
                        accepted.operation_sequence,
                        command.provider_operation_id.as_deref(),
                        command.provider_resource_id.as_deref(),
                    )
                    .await
            {
                tracing::debug!(%error, command_id = %accepted.command_id, "backup agent command acceptance projection failed");
            }
            if let Some(operation) = state.operations.get_mut(&accepted.operation_id)
                && let Some(next) = agent_operation_state(accepted.state)
            {
                operation.state = next;
            }
        }
        o3k_provider::AgentEvent::Operation(update) => {
            if let Some(store) = store
                && let Ok(command) = store
                    .get_agent_command_by_operation(update.operation_id)
                    .await
                && command.agent_id == update.agent_id
                && command.resource_id == update.resource_id
                && let Ok(operation) = store.get_operation(update.operation_id).await
                && operation.resource_id == update.resource_id
            {
                let command_state = match update.state {
                    AgentOperationState::Accepted => AgentCommandState::Accepted,
                    AgentOperationState::Running => AgentCommandState::Running,
                    AgentOperationState::Succeeded => AgentCommandState::Succeeded,
                    AgentOperationState::Failed => AgentCommandState::Failed,
                    AgentOperationState::UnknownOutcome => AgentCommandState::UnknownOutcome,
                };
                let operation_state = match update.state {
                    AgentOperationState::Accepted | AgentOperationState::Running => {
                        o3k_store::OperationState::Running
                    }
                    AgentOperationState::Succeeded => o3k_store::OperationState::Succeeded,
                    AgentOperationState::Failed => o3k_store::OperationState::Failed,
                    AgentOperationState::UnknownOutcome => {
                        o3k_store::OperationState::UnknownOutcome
                    }
                };
                let terminal_conflict = matches!(
                    operation.state,
                    o3k_store::OperationState::Succeeded | o3k_store::OperationState::Failed
                ) && operation.state != operation_state;
                let command_terminal_conflict = matches!(
                    command.state,
                    AgentCommandState::Succeeded | AgentCommandState::Failed
                ) && command.state != command_state;
                let unknown_regression = operation.state
                    == o3k_store::OperationState::UnknownOutcome
                    && operation_state == o3k_store::OperationState::Running
                    || command.state == AgentCommandState::UnknownOutcome
                        && matches!(
                            command_state,
                            AgentCommandState::Accepted | AgentCommandState::Running
                        );
                let classified_failure =
                    update.state != AgentOperationState::Failed || update.error_category.is_some();
                let provider_identity_matches = backup_provider_identity_matches(
                    store,
                    &command,
                    &update,
                )
                .await
                .unwrap_or_else(|error| {
                    tracing::debug!(%error, operation_id = %update.operation_id, "backup provider identity validation failed closed");
                    false
                });
                if !terminal_conflict
                    && !command_terminal_conflict
                    && !unknown_regression
                    && classified_failure
                    && provider_identity_matches
                    && let Err(error) = store
                        .update_agent_command(
                            &command.command_id,
                            command_state,
                            command.accepted_sequence,
                            update.operation_sequence,
                            command.provider_operation_id.as_deref(),
                            update.provider_resource_id.as_deref(),
                        )
                        .await
                {
                    tracing::debug!(%error, operation_id = %update.operation_id, "backup agent operation projection failed");
                }
            }
            if let Some(operation) = state.operations.get_mut(&update.operation_id) {
                if let Some(next) = agent_operation_state(update.state) {
                    operation.state = next;
                }
                operation.error_category = agent_error_category(update.error_category);
                if let Some(provider_resource_id) = update.provider_resource_id {
                    operation.provider_resource_id = Some(provider_resource_id);
                }
            }
        }
        o3k_provider::AgentEvent::Observation(observation) => {
            let instance_state = observation.state;
            let provider_id = observation.provider_resource_id.clone();
            // Mirror the journal's `apply_agent_observation` gate: only a
            // Succeeded observation may project a durable provider reference
            // and a volatile instance/binding. A terminal failed presence
            // inspection (domain provably absent) still carries the
            // deterministic libvirt domain name in `provider_resource_id`;
            // attaching a reference from that absence evidence would make
            // the UnknownOutcome create sweep resolve a phantom resource
            // identity and drive `finish_create` against a never-created
            // domain forever instead of converging the absence
            // (issue #87).
            if observation.operation_state == o3k_provider::AgentOperationState::Succeeded
                && let Some(provider_id) = provider_id.as_deref()
            {
                if let Some(store) = store {
                    let reference = o3k_store::ProviderReference {
                        resource_id: observation.resource_id,
                        provider_name: "agent".to_owned(),
                        provider_resource_id: provider_id.to_owned(),
                    };
                    if let Err(error) = store.attach_provider_reference(&reference).await
                        && !matches!(error, StoreError::ProviderReferenceAlreadyExists)
                    {
                        tracing::debug!(%error, resource_id = %observation.resource_id, "agent provider reference was not durably projected");
                    }
                }
                state.bindings.insert(
                    provider_id.to_owned(),
                    AgentBinding {
                        resource_id: observation.resource_id.to_string(),
                        agent_id: observation.agent_id.clone(),
                        agent_epoch: observation.agent_epoch.clone(),
                        provider_resource_id: Some(provider_id.to_owned()),
                    },
                );
                state.instances.insert(
                    provider_id.to_owned(),
                    Instance {
                        provider_instance_id: provider_id.to_owned(),
                        o3k_server_id: observation.resource_id,
                        state: instance_state,
                        observed_message: observation.redacted_message.clone(),
                    },
                );
            }
            if let Some(operation) = state.operations.get_mut(&observation.operation_id) {
                if let Some(next) = agent_operation_state(observation.operation_state) {
                    operation.state = next;
                }
                if let Some(provider_id) = provider_id {
                    operation.provider_resource_id = Some(provider_id);
                }
            }
        }
        o3k_provider::AgentEvent::Error(error) => {
            if let Some(operation_id) = error.operation_id
                && let Some(operation) = state.operations.get_mut(&operation_id)
            {
                operation.state = if error.retryable {
                    o3k_provider::OperationState::Retryable
                } else {
                    o3k_provider::OperationState::Failed
                };
                operation.error_category = agent_error_category(error.category);
            }
        }
        o3k_provider::AgentEvent::ArtifactAck(_ack) => {
            // The foreground create path owns the durable commit after its
            // waiter receives this acknowledgement. Persisting the same
            // transition here races that writer on SQLite. ArtifactStatus
            // events remain the asynchronous recovery projection.
        }
        o3k_provider::AgentEvent::ArtifactStatus(status) => {
            if let Some(store) = store
                && let Err(error) = apply_artifact_status(store, &status).await
            {
                tracing::debug!(%error, transfer_id = %status.transfer_id, "agent artifact status rejected");
            }
        }
    }
}

async fn backup_provider_identity_matches(
    store: &dyn ComputeRepository,
    command: &AgentCommandRecord,
    update: &o3k_provider::AgentOperationUpdate,
) -> Result<bool, StoreError> {
    let Some(incoming) = update.provider_resource_id.as_deref() else {
        return Ok(true);
    };
    if command
        .provider_resource_id
        .as_deref()
        .is_some_and(|existing| existing != incoming)
    {
        return Ok(false);
    }
    let resource = store.get_resource(update.resource_id).await?;
    if resource
        .provider_id
        .as_deref()
        .is_some_and(|existing| existing != incoming)
    {
        return Ok(false);
    }
    for provider_name in ["compute-agent", "agent"] {
        match store
            .get_provider_reference(update.resource_id, provider_name)
            .await
        {
            Ok(reference) if reference.provider_resource_id != incoming => return Ok(false),
            Ok(_) | Err(StoreError::ProviderReferenceNotFound) => {}
            Err(error) => return Err(error),
        }
    }
    Ok(true)
}

/// Projects one authenticated agent capability snapshot into the inventory
/// shape required by the scheduler. Missing capacity is represented as zero

#[async_trait]
impl ComputeProvider for AgentComputeProvider {
    async fn capabilities(&self) -> Result<Capabilities, ProviderError> {
        let mut nodes = self.registry.all().await;
        nodes.sort_by(|left, right| left.agent_id.cmp(&right.agent_id));
        let node = nodes
            .into_iter()
            .find(|node| {
                node.availability == Availability::Available
                    && node.desired_state == agent_proto::AdministrativeState::Enabled as i32
            })
            .ok_or(ProviderError::Retryable)?;
        Ok(Capabilities {
            provider_name: node.capabilities.agent_provider_name,
            provider_version: node.capabilities.agent_provider_version,
            capabilities: node
                .capabilities
                .lifecycle_actions
                .into_iter()
                .chain(
                    node.capabilities
                        .console_log
                        .then_some("compute.console_log".to_owned()),
                )
                .collect(),
        })
    }

    async fn create_instance(
        &self,
        request: CreateInstanceRequest,
    ) -> Result<Operation, ProviderError> {
        tracing::warn!(
            resource_id = %request.o3k_server_id,
            operation_id = %request.operation_id,
            "agent create provider entered"
        );
        let provider_id = request.placement_provider_id.as_deref().ok_or_else(|| {
            tracing::warn!(
                resource_id = %request.o3k_server_id,
                "create request has no placement provider identity"
            );
            ProviderError::InvalidRequest
        })?;
        let agent = self.selected_agent(provider_id).await.map_err(|error| {
            tracing::warn!(
                resource_id = %request.o3k_server_id,
                error = %error,
                "agent create agent selection rejected"
            );
            error
        })?;
        tracing::warn!(
            resource_id = %request.o3k_server_id,
            agent_id = %agent.agent_id,
            "agent create agent selected"
        );
        if request.config_drive.is_some()
            && !agent
                .capabilities
                .flags
                .iter()
                .any(|flag| flag.name == "config_drive" && flag.supported)
        {
            tracing::warn!(
                resource_id = %request.o3k_server_id,
                agent_id = %agent.agent_id,
                capability_flags = ?agent
                    .capabilities
                    .flags
                    .iter()
                    .map(|flag| format!("{}={}", flag.name, flag.supported))
                    .collect::<Vec<_>>(),
                "create request requires an unsupported config-drive capability"
            );
            return Err(ProviderError::InvalidRequest);
        }
        let app_agent = agent_snapshot(&agent);
        let resolved = self
            .resolver
            .resolve(&request, &app_agent)
            .await
            .map_err(|error| {
                tracing::warn!(
                    resource_id = %request.o3k_server_id,
                    error = %error,
                    "create resolver rejected request"
                );
                error
            })?;
        tracing::warn!(
            resource_id = %request.o3k_server_id,
            "agent create inputs resolved"
        );
        let image_id = request.image_id.as_deref().ok_or_else(|| {
            tracing::warn!(
                resource_id = %request.o3k_server_id,
                "create request has no image identity"
            );
            ProviderError::InvalidRequest
        })?;
        let artifact_inputs = resolved.clone();
        let command = build_create_command(CreateCommandSpec {
            agent_id: agent.agent_id.clone(),
            agent_epoch: agent.agent_epoch.clone(),
            project_id: request.project_id.clone(),
            operation_id: request.operation_id.to_string(),
            resource_id: request.o3k_server_id.to_string(),
            idempotency_key: request.idempotency_key.clone(),
            deadline_unix_ms: unix_ms_after(self.command_timeout),
            image_id: image_id.to_owned(),
            flavor_id: resolved.flavor_id,
            image_artifact_id: resolved.image_artifact_id,
            image_sha256: resolved.image_sha256,
            image_format: resolved.image_format,
            vcpus: request.vcpus,
            memory_mib: request.memory_mib,
            disk_gib: resolved.disk_gib,
            config_drive_artifact_id: resolved.config_drive_artifact_id,
            config_drive_sha256: resolved.config_drive_sha256,
            network_attachments: resolved.network_attachments.clone(),
        })
        .map_err(|error| {
            tracing::warn!(
                resource_id = %request.o3k_server_id,
                error = %error,
                "create command construction rejected request"
            );
            map_agent_error(error)
        })?;
        tracing::warn!(
            resource_id = %request.o3k_server_id,
            "agent create command built"
        );
        if let Some(existing) = self
            .persist_pending_command(&command, request.operation_id)
            .await
            .map_err(|error| {
                tracing::warn!(
                    resource_id = %request.o3k_server_id,
                    error = %error,
                    "agent create pending command persistence rejected"
                );
                error
            })?
            && matches!(
                existing.state,
                AgentCommandState::Succeeded | AgentCommandState::Failed
            )
        {
            return self.get_operation(request.operation_id).await;
        }
        tracing::warn!(
            resource_id = %request.o3k_server_id,
            "agent create pending command persisted"
        );
        let artifacts = self
            .artifact_resolver
            .resolve_artifacts(&request, &app_agent, &artifact_inputs)
            .await
            .map_err(|error| {
                tracing::warn!(
                    resource_id = %request.o3k_server_id,
                    error = %error,
                    "create artifact resolver rejected request"
                );
                error
            })?;
        tracing::warn!(
            resource_id = %request.o3k_server_id,
            artifact_count = artifacts.len(),
            "agent create artifacts resolved"
        );
        if artifacts.len() != 2 {
            tracing::warn!(
                resource_id = %request.o3k_server_id,
                artifact_count = artifacts.len(),
                "create artifact resolver returned an unexpected artifact count"
            );
            return Err(ProviderError::InvalidRequest);
        }
        let required = [
            (
                o3k_provider::ArtifactKind::ImageBase,
                &artifact_inputs.image_artifact_id,
                &artifact_inputs.image_sha256,
                artifact_inputs.image_format.as_str(),
            ),
            (
                o3k_provider::ArtifactKind::ConfigDriveIso,
                &artifact_inputs.config_drive_artifact_id,
                &artifact_inputs.config_drive_sha256,
                "iso",
            ),
        ];
        let mut seen = [false; 2];
        for artifact in artifacts {
            let expected_index = required
                .iter()
                .position(|(kind, artifact_id, _, _)| {
                    *kind == artifact.kind && artifact_id.as_str() == artifact.artifact_id
                })
                .ok_or_else(|| {
                    tracing::warn!(
                        resource_id = %request.o3k_server_id,
                        artifact_kind = artifact_kind_name(artifact.kind),
                        "create artifact did not match a required reference"
                    );
                    ProviderError::InvalidRequest
                })?;
            if seen[expected_index] {
                tracing::warn!(
                    resource_id = %request.o3k_server_id,
                    artifact_kind = artifact_kind_name(artifact.kind),
                    "create artifact was duplicated"
                );
                return Err(ProviderError::InvalidRequest);
            }
            seen[expected_index] = true;
            let expected = &required[expected_index];
            let size_bytes = u64::try_from(artifact.bytes.len()).map_err(|_| {
                tracing::warn!(
                    resource_id = %request.o3k_server_id,
                    artifact_kind = artifact_kind_name(artifact.kind),
                    "create artifact size could not be represented"
                );
                ProviderError::InvalidRequest
            })?;
            if size_bytes == 0
                || artifact.artifact_id.trim().is_empty()
                || artifact.sha256.len() != 64
                || artifact.format.trim().is_empty()
                || artifact.sha256 != *expected.2
                || artifact.format != expected.3
            {
                tracing::warn!(
                    resource_id = %request.o3k_server_id,
                    artifact_kind = artifact_kind_name(artifact.kind),
                    "create artifact metadata or digest validation failed"
                );
                return Err(ProviderError::InvalidRequest);
            }
            let chunk_size = MAX_ARTIFACT_CHUNK_BYTES as u64;
            let chunk_count = u32::try_from(size_bytes.div_ceil(chunk_size)).map_err(|_| {
                tracing::warn!(
                    resource_id = %request.o3k_server_id,
                    artifact_kind = artifact_kind_name(artifact.kind),
                    "create artifact chunk count is invalid"
                );
                ProviderError::InvalidRequest
            })?;
            let wire_kind = match artifact.kind {
                o3k_provider::ArtifactKind::ImageBase => agent_proto::ArtifactKind::ImageBase,
                o3k_provider::ArtifactKind::ConfigDriveIso => {
                    agent_proto::ArtifactKind::ConfigDriveIso
                }
            };
            let transfer_id = deterministic_artifact_transfer_id(
                &command.command_id,
                wire_kind,
                &artifact.artifact_id,
            );
            let offer = agent_proto::ArtifactOffer {
                transfer_id,
                command_id: command.command_id.clone(),
                operation_id: command.operation_id.clone(),
                resource_id: command.resource_id.clone(),
                agent_id: agent.agent_id.clone(),
                artifact_id: artifact.artifact_id,
                kind: wire_kind as i32,
                sha256: artifact.sha256,
                size_bytes,
                format: artifact.format,
                chunk_size_bytes: MAX_ARTIFACT_CHUNK_BYTES as u32,
                chunk_count,
                expires_at_unix_ms: command.deadline_unix_ms,
            };
            if let Some(store) = &self.store {
                let transfer = ArtifactTransferRecord {
                    transfer_id: offer.transfer_id.clone(),
                    command_id: offer.command_id.clone(),
                    operation_id: request.operation_id,
                    resource_id: request.o3k_server_id,
                    agent_id: offer.agent_id.clone(),
                    agent_epoch: agent.agent_epoch.clone(),
                    artifact_id: offer.artifact_id.clone(),
                    artifact_kind: artifact_kind_name(artifact.kind).to_owned(),
                    sha256: offer.sha256.clone(),
                    size_bytes: offer.size_bytes,
                    expires_at_unix_ms: offer.expires_at_unix_ms,
                    format: offer.format.clone(),
                    chunk_size_bytes: offer.chunk_size_bytes as u64,
                    chunk_count: offer.chunk_count as u64,
                    state: ArtifactTransferState::Offered,
                    contiguous_bytes: 0,
                    next_chunk_index: 0,
                    retry_count: 0,
                    created_at: String::new(),
                    updated_at: String::new(),
                };
                let existing = match store.insert_artifact_transfer(&transfer).await {
                    Ok(existing) => existing,
                    Err(StoreError::ArtifactTransferConflict(_)) => {
                        let previous = store
                            .get_artifact_transfer(&transfer.transfer_id)
                            .await
                            .map_err(|_| ProviderError::Conflict)?;
                        if previous.state == ArtifactTransferState::Committed {
                            previous
                        } else if previous.command_id == transfer.command_id
                            && previous.operation_id == transfer.operation_id
                            && previous.resource_id == transfer.resource_id
                            && previous.agent_id == transfer.agent_id
                            && previous.artifact_id == transfer.artifact_id
                            && previous.artifact_kind == transfer.artifact_kind
                            && previous.sha256 == transfer.sha256
                            && previous.size_bytes == transfer.size_bytes
                            && previous.format == transfer.format
                            && previous.chunk_size_bytes == transfer.chunk_size_bytes
                            && previous.chunk_count == transfer.chunk_count
                        {
                            store
                                .rebind_artifact_transfer_epoch(
                                    &transfer.transfer_id,
                                    &previous.agent_epoch,
                                    &transfer.agent_epoch,
                                )
                                .await
                                .map_err(|_| ProviderError::Conflict)?
                        } else {
                            return Err(ProviderError::Conflict);
                        }
                    }
                    Err(error) => {
                        tracing::warn!(
                            resource_id = %request.o3k_server_id,
                            artifact_kind = artifact_kind_name(artifact.kind),
                            error = %error,
                            "artifact transfer insert failed"
                        );
                        return Err(ProviderError::Conflict);
                    }
                };
                if existing.state == ArtifactTransferState::Committed {
                    continue;
                }
                if matches!(
                    existing.state,
                    ArtifactTransferState::Rejected | ArtifactTransferState::Expired
                ) {
                    return Err(ProviderError::Conflict);
                }
            }
            self.registry
                .dispatch_artifact_and_wait(offer.clone(), artifact.bytes, self.command_timeout)
                .await
                .map_err(|error| {
                    tracing::warn!(
                        resource_id = %request.o3k_server_id,
                        artifact_kind = artifact_kind_name(artifact.kind),
                        error = %error,
                        "create artifact transfer was rejected"
                    );
                    map_artifact_transfer_error(error, request.operation_id)
                })?;
            tracing::warn!(
                resource_id = %request.o3k_server_id,
                artifact_kind = artifact_kind_name(artifact.kind),
                "agent create artifact transfer committed"
            );
            if let Some(store) = &self.store {
                let commit = store
                    .update_artifact_transfer(
                        &offer.transfer_id,
                        &agent.agent_epoch,
                        ArtifactTransferUpdate {
                            state: ArtifactTransferState::Committed,
                            contiguous_bytes: offer.size_bytes,
                            next_chunk_index: offer.chunk_count as u64,
                            retry_count: 0,
                        },
                    )
                    .await;
                if let Err(error) = commit {
                    // The authenticated agent acknowledgement can be
                    // projected by the event consumer immediately before
                    // this foreground writer. Treat an already-complete
                    // terminal row as the same successful commit; retain
                    // conflicts for incomplete or differently identified
                    // state (P15.7 artifact-transfer race).
                    let already_committed =
                        matches!(error, StoreError::ArtifactTransferConflict(_))
                            && store
                                .get_artifact_transfer(&offer.transfer_id)
                                .await
                                .is_ok_and(|current| {
                                    equivalent_committed_transfer(
                                        &current,
                                        &offer,
                                        request.operation_id,
                                        request.o3k_server_id,
                                        artifact_kind_name(artifact.kind),
                                        &agent.agent_epoch,
                                    )
                                });
                    if !already_committed {
                        tracing::warn!(
                            resource_id = %request.o3k_server_id,
                            artifact_kind = artifact_kind_name(artifact.kind),
                            error = %error,
                            "artifact transfer commit update failed"
                        );
                        return Err(ProviderError::Conflict);
                    }
                }
            }
        }
        if seen != [true, true] {
            tracing::warn!(
                resource_id = %request.o3k_server_id,
                image_seen = seen[0],
                config_drive_seen = seen[1],
                "create artifacts did not include every required artifact"
            );
            return Err(ProviderError::InvalidRequest);
        }
        let operation = self
            .dispatch_recorded(command, request.operation_id)
            .await
            .map_err(|error| {
                tracing::warn!(
                    resource_id = %request.o3k_server_id,
                    error = %error,
                    "create command dispatch was rejected"
                );
                error
            })?;
        self.state.write().await.bindings.insert(
            request.o3k_server_id.to_string(),
            AgentBinding {
                resource_id: request.o3k_server_id.to_string(),
                agent_id: agent.agent_id,
                agent_epoch: agent.agent_epoch,
                provider_resource_id: None,
            },
        );
        Ok(operation)
    }

    async fn get_instance(&self, id: &str) -> Result<Instance, ProviderError> {
        self.rehydrate().await?;
        self.state
            .read()
            .await
            .instances
            .get(id)
            .cloned()
            .ok_or(ProviderError::NotFound)
    }

    async fn inspect_instance(
        &self,
        provider_id: &str,
        resource_id: &str,
        provider_instance_id: &str,
        operation_id: Uuid,
        idempotency_key: &str,
    ) -> Result<Operation, ProviderError> {
        if idempotency_key.trim().is_empty() {
            return Err(ProviderError::InvalidRequest);
        }
        let binding = {
            let state = self.state.read().await;
            state.bindings.get(resource_id).cloned().or_else(|| {
                state
                    .bindings
                    .values()
                    .find(|binding| binding.resource_id == resource_id)
                    .cloned()
            })
        };
        if let Some(binding) = binding.as_ref()
            && let Some(expected) = binding.provider_resource_id.as_deref()
            && expected != provider_instance_id
        {
            return Err(ProviderError::Conflict);
        }
        let agent = self.selected_agent(provider_id).await?;
        if let Some(binding) = binding.as_ref() {
            if binding.agent_id != provider_id {
                return Err(ProviderError::StaleState);
            }
            if binding.agent_epoch != agent.agent_epoch {
                // The registry is authoritative for the agent's current
                // epoch: every registration replaces the stored epoch (minted
                // per connection), so a binding carrying the pre-restart
                // epoch is a legitimate same-agent restart, not a dead
                // stream — the #552 journal-evidence rationale. Re-anchor the
                // in-memory binding so the presence inspection dispatches
                // against the current agent instead of failing as
                // StaleState forever. A binding owned by a DIFFERENT agent is
                // still rejected above; the wire dispatch additionally fences
                // the command by the current registered epoch.
                let mut state = self.state.write().await;
                match state.bindings.get_mut(resource_id) {
                    Some(current) => current.agent_epoch = agent.agent_epoch.clone(),
                    None => {
                        if let Some(current) = state
                            .bindings
                            .values_mut()
                            .find(|binding| binding.resource_id == resource_id)
                        {
                            current.agent_epoch = agent.agent_epoch.clone();
                        }
                    }
                }
            }
        }
        let mut command = build_lifecycle_command(
            LifecycleCommand::Inspect,
            &agent.agent_id,
            &agent.agent_epoch,
            &operation_id.to_string(),
            resource_id,
        )
        .map_err(map_agent_error)?;
        command.idempotency_key = idempotency_key.to_owned();
        self.dispatch_recorded(command, operation_id).await
    }

    async fn delete_instance(
        &self,
        request: DeleteInstanceRequest,
    ) -> Result<Operation, ProviderError> {
        self.rehydrate().await?;
        let binding = {
            let state = self.state.read().await;
            state
                .bindings
                .get(&request.provider_instance_id)
                .cloned()
                .or_else(|| {
                    state
                        .bindings
                        .values()
                        .find(|binding| binding.resource_id == request.provider_instance_id)
                        .cloned()
                })
        };
        let Some(binding) = binding else {
            // Issue #88 S5: no binding exists at all, so the create dispatch
            // was never accepted (the transfer died mid-receipt or committed
            // before acceptance, then the create terminalized Failed/not_found
            // and the delete completed locally). The agent-side residue (the
            // mid-receipt `.part`, the committed config-drive manifest) is
            // otherwise unreachable: the agent never restarts (o3kd-side
            // kill), so the startup reap never runs, and no delete command
            // ever reaches the agent for the resource-scoped reaps. Reap
            // through the durable create command row and the agent's
            // domain-absent delete arm.
            return self.reap_never_accepted_create(request).await;
        };
        let agent = self.selected_agent(&binding.agent_id).await?;
        if binding.provider_resource_id.is_some() && agent.agent_epoch != binding.agent_epoch {
            return Err(ProviderError::StaleState);
        }
        // The command resource identity is the O3K server id, never the
        // provider (libvirt domain) name: the agent derives the domain from
        // the server id and the durable command store requires a UUID.
        //
        // A binding with no provider resource identity (the create dispatch
        // was accepted but no domain was ever defined — issue #88 S3) has no
        // provider object to fence, so the epoch fence above is skipped: the
        // server id IS the fence, and the registry is authoritative for the
        // agent's current epoch (every registration replaces the stored
        // epoch, minted per connection — the #552 journal-evidence
        // rationale). The reap of a crashed pre-mutation create therefore
        // dispatches against the current agent instead of failing as
        // StaleState forever. The wire dispatch additionally fences the
        // command by the current registered epoch, and the binding's own
        // agent id still resolves through `selected_agent`, so a binding
        // owned by a DIFFERENT or unregistered agent is still rejected. A
        // binding that HAS a provider resource identity keeps the strict
        // epoch fence above: a real provider object must never be deleted
        // through a stale binding.
        let command = build_lifecycle_command(
            LifecycleCommand::Delete,
            &agent.agent_id,
            &agent.agent_epoch,
            &request.operation_id.to_string(),
            &binding.resource_id,
        )
        .map_err(map_agent_error)?;
        self.dispatch_recorded(command, request.operation_id).await
    }

    async fn action_instance(
        &self,
        id: &str,
        action: InstanceAction,
        operation_id: Uuid,
        _idempotency_key: &str,
    ) -> Result<Operation, ProviderError> {
        self.rehydrate().await?;
        let binding = self
            .state
            .read()
            .await
            .bindings
            .get(id)
            .cloned()
            .ok_or(ProviderError::NotFound)?;
        let agent = self.selected_agent(&binding.agent_id).await?;
        if agent.agent_epoch != binding.agent_epoch {
            return Err(ProviderError::StaleState);
        }
        let command_action = match action {
            InstanceAction::Start => LifecycleCommand::Start,
            InstanceAction::Stop => LifecycleCommand::Stop,
            InstanceAction::Reboot => LifecycleCommand::HardReboot,
        };
        let command = build_lifecycle_command(
            command_action,
            &agent.agent_id,
            &agent.agent_epoch,
            &operation_id.to_string(),
            &binding.resource_id,
        )
        .map_err(map_agent_error)?;
        self.dispatch_recorded(command, operation_id).await
    }

    async fn get_operation(&self, id: Uuid) -> Result<Operation, ProviderError> {
        // The durable agent command row is the authoritative execution
        // state for a dispatched command: for lifecycle commands the
        // provider operation identity is the operation's own id, so reading
        // the operation row instead would be self-referential (it mirrors
        // the control plane's own projection, not the agent's state) and
        // would hide a stale command forever (issue #575). The command row
        // is updated from authenticated agent evidence and survives
        // control-plane restarts, so observation polls see the true agent
        // state.
        if let Some(store) = &self.store
            && let Ok(command) = store.get_agent_command_by_operation(id).await
        {
            let provider_resource_id = match store
                .get_provider_reference(command.resource_id, "compute")
                .await
            {
                Ok(reference) => Some(reference.provider_resource_id),
                Err(_) => store
                    .get_provider_reference(command.resource_id, "agent")
                    .await
                    .ok()
                    .map(|reference| reference.provider_resource_id),
            };
            let state = match command.state {
                o3k_store::AgentCommandState::Pending | o3k_store::AgentCommandState::Accepted => {
                    o3k_provider::OperationState::Accepted
                }
                o3k_store::AgentCommandState::Running => o3k_provider::OperationState::Running,
                o3k_store::AgentCommandState::Retryable => o3k_provider::OperationState::Retryable,
                o3k_store::AgentCommandState::UnknownOutcome => {
                    o3k_provider::OperationState::UnknownOutcome
                }
                o3k_store::AgentCommandState::Succeeded => o3k_provider::OperationState::Succeeded,
                o3k_store::AgentCommandState::Failed => o3k_provider::OperationState::Failed,
            };
            return Ok(Operation {
                provider_operation_id: command
                    .provider_operation_id
                    .as_deref()
                    .and_then(|value| Uuid::parse_str(value).ok())
                    .unwrap_or(id),
                o3k_operation_id: id,
                state,
                error_category: None,
                provider_resource_id,
            });
        }
        if let Some(store) = &self.store
            && let Ok(record) = store.get_operation(id).await
        {
            let provider_resource_id =
                if let Ok(command) = store.get_agent_command_by_operation(id).await {
                    let reference = match store
                        .get_provider_reference(command.resource_id, "compute")
                        .await
                    {
                        Ok(reference) => Some(reference),
                        Err(_) => store
                            .get_provider_reference(command.resource_id, "agent")
                            .await
                            .ok(),
                    };
                    reference.map(|reference| reference.provider_resource_id)
                } else {
                    None
                };
            let state = match record.state {
                o3k_store::OperationState::Pending => o3k_provider::OperationState::Accepted,
                o3k_store::OperationState::Running => o3k_provider::OperationState::Running,
                o3k_store::OperationState::Succeeded => o3k_provider::OperationState::Succeeded,
                o3k_store::OperationState::Retryable => o3k_provider::OperationState::Retryable,
                o3k_store::OperationState::UnknownOutcome => {
                    o3k_provider::OperationState::UnknownOutcome
                }
                o3k_store::OperationState::Failed => o3k_provider::OperationState::Failed,
            };
            return Ok(Operation {
                provider_operation_id: record
                    .provider_operation_id
                    .as_deref()
                    .and_then(|value| Uuid::parse_str(value).ok())
                    .unwrap_or(id),
                o3k_operation_id: id,
                state,
                error_category: record
                    .error_category
                    .as_deref()
                    .and_then(|value| match value {
                        "invalid_request" => Some(o3k_provider::ErrorCategory::InvalidRequest),
                        "conflict" => Some(o3k_provider::ErrorCategory::Conflict),
                        "capacity" => Some(o3k_provider::ErrorCategory::Capacity),
                        "not_found" => Some(o3k_provider::ErrorCategory::NotFound),
                        "retryable" => Some(o3k_provider::ErrorCategory::Retryable),
                        "unknown_outcome" => Some(o3k_provider::ErrorCategory::UnknownOutcome),
                        "terminal" => Some(o3k_provider::ErrorCategory::Terminal),
                        _ => None,
                    }),
                provider_resource_id,
            });
        }
        self.state
            .read()
            .await
            .operations
            .get(&id)
            .cloned()
            .ok_or(ProviderError::NotFound)
    }

    async fn collect_connector(&self, resource_id: Uuid) -> Result<ConnectorInfo, ProviderError> {
        let (agent, binding_resource) = self.agent_for_server(resource_id).await?;
        let operation_id = Uuid::now_v7();
        let command = build_block_device_command(
            BlockDeviceCommand::CollectConnector,
            &agent.agent_id,
            &agent.agent_epoch,
            &operation_id.to_string(),
            &binding_resource,
        )
        .map_err(map_agent_error)?;
        let observation = self
            .dispatch_block_device_and_wait(command, operation_id, self.command_timeout)
            .await?;
        Ok(ConnectorInfo {
            host: observation.host_name.clone().unwrap_or_default(),
            ip: observation.ip_address.clone().unwrap_or_default(),
            platform: "x86_64".to_owned(),
            os_type: "linux".to_owned(),
            multipath: false,
            initiator: observation.initiator.clone(),
        })
    }

    async fn attach_block_device(
        &self,
        resource_id: Uuid,
        device: &BlockDeviceAttachment,
    ) -> Result<BlockDeviceObservation, ProviderError> {
        let (agent, binding_resource) = self.agent_for_server(resource_id).await?;
        let operation_id = Uuid::now_v7();
        let command = build_block_device_command(
            BlockDeviceCommand::Attach {
                device: agent_proto::AttachDiskCommand {
                    volume_id: device.volume_id.clone(),
                    attachment_id: device.attachment_id.clone(),
                    driver_volume_type: device.driver_volume_type.clone(),
                    target_iqn: device.target_iqn.clone().unwrap_or_default(),
                    target_portal: device.target_portal.clone().unwrap_or_default(),
                    target_lun: device.target_lun.unwrap_or(0),
                    device_path: device.local_path.clone().unwrap_or_default(),
                    multipath: device.multipath,
                    initiator: device.initiator.clone().unwrap_or_default(),
                    auth_method: device.auth_method.clone().unwrap_or_default(),
                    auth_username: device.auth_username.clone().unwrap_or_default(),
                    auth_password: device.auth_password.clone().unwrap_or_default(),
                },
            },
            &agent.agent_id,
            &agent.agent_epoch,
            &operation_id.to_string(),
            &binding_resource,
        )
        .map_err(map_agent_error)?;
        let observation = self
            .dispatch_block_device_and_wait(command, operation_id, self.command_timeout)
            .await?;
        Ok(observation)
    }

    async fn detach_block_device(
        &self,
        resource_id: Uuid,
        device: &BlockDeviceAttachment,
    ) -> Result<BlockDeviceObservation, ProviderError> {
        let (agent, binding_resource) = self.agent_for_server(resource_id).await?;
        let operation_id = Uuid::now_v7();
        let command = build_block_device_command(
            BlockDeviceCommand::Detach {
                device: agent_proto::DetachDiskCommand {
                    volume_id: device.volume_id.clone(),
                    attachment_id: device.attachment_id.clone(),
                    driver_volume_type: device.driver_volume_type.clone(),
                    target_iqn: device.target_iqn.clone().unwrap_or_default(),
                    target_portal: device.target_portal.clone().unwrap_or_default(),
                    target_lun: device.target_lun.unwrap_or(0),
                    device_path: device.local_path.clone().unwrap_or_default(),
                    multipath: device.multipath,
                    initiator: device.initiator.clone().unwrap_or_default(),
                },
            },
            &agent.agent_id,
            &agent.agent_epoch,
            &operation_id.to_string(),
            &binding_resource,
        )
        .map_err(map_agent_error)?;
        let observation = self
            .dispatch_block_device_and_wait(command, operation_id, self.command_timeout)
            .await?;
        Ok(observation)
    }

    async fn observe_block_device(
        &self,
        resource_id: Uuid,
        volume_id: &str,
    ) -> Result<Option<BlockDeviceObservation>, ProviderError> {
        let (agent, binding_resource) = self.agent_for_server(resource_id).await?;
        let operation_id = Uuid::now_v7();
        let command = build_block_device_command(
            BlockDeviceCommand::Observe {
                volume_id: volume_id.to_owned(),
                attachment_id: String::new(),
            },
            &agent.agent_id,
            &agent.agent_epoch,
            &operation_id.to_string(),
            &binding_resource,
        )
        .map_err(map_agent_error)?;
        let observation = self
            .dispatch_block_device_and_wait(command, operation_id, self.command_timeout)
            .await?;
        if !observation.found {
            return Ok(None);
        }
        Ok(Some(observation))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::ProviderAgentEvent;
    use o3k_provider::{
        AgentNodeSnapshot, AgentObservation, AgentOperationState, NetworkAttachmentSpec,
        ResolvedCreateArtifact, ResolvedCreateInputs, ResolvedCreateResolver,
        UnconfiguredResolvedCreateResolver,
    };
    use o3k_store::DurableStore;
    use sha2::Digest;
    use tokio::sync::mpsc;

    fn register_request(id: &str, epoch: &str) -> agent_proto::RegisterRequest {
        agent_proto::RegisterRequest {
            agent_id: id.to_owned(),
            agent_epoch: epoch.to_owned(),
            software_version: "test".to_owned(),
            host_label: id.to_owned(),
            supported_versions: vec![crate::PROTOCOL_VERSION],
            capabilities: Some(agent_proto::Capabilities {
                architecture: "x86_64".to_owned(),
                agent_provider_name: "o3k-compute".to_owned(),
                agent_provider_version: "test".to_owned(),
                // The create dispatch transfers artifacts, which requires the
                // negotiated capability flag (issue #88 E3 C3 race tests).
                flags: vec![agent_proto::CapabilityFlag {
                    name: crate::ARTIFACT_TRANSFER_CAPABILITY.to_owned(),
                    supported: true,
                    bounded_value: String::new(),
                }],
                ..Default::default()
            }),
        }
    }

    #[test]
    fn unknown_artifact_transfer_outcome_is_never_terminal() {
        // Issue #603 (ASR-021 matrix agent-control-plane-network-interruption):
        // a transfer that ends without a definitive acknowledgement is an
        // unknown outcome the engine must observe and re-drive, not a terminal
        // rejection.
        let operation_id = Uuid::now_v7();
        assert_eq!(
            map_artifact_transfer_error(
                AgentError::Protocol("artifact transfer outcome is unknown".to_owned()),
                operation_id,
            ),
            ProviderError::UnknownOutcome { operation_id }
        );
        // Every other classification is delegated unchanged.
        assert_eq!(
            map_artifact_transfer_error(
                AgentError::Protocol("agent control stream is unavailable".to_owned()),
                operation_id,
            ),
            ProviderError::Retryable
        );
        assert_eq!(
            map_artifact_transfer_error(
                AgentError::Protocol("agent rejected artifact transfer".to_owned()),
                operation_id,
            ),
            ProviderError::InvalidRequest
        );
        assert_eq!(
            map_artifact_transfer_error(
                AgentError::Protocol("agent epoch is fenced".to_owned()),
                operation_id,
            ),
            ProviderError::StaleState
        );
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

    /// Seeds the in-memory binding exactly as the create dispatch leaves it
    /// (see `create_instance`): keyed by the O3K server id, carrying the
    /// create-time agent epoch, with no provider resource identity yet.
    async fn seed_create_binding(
        provider: &AgentComputeProvider,
        server_id: Uuid,
        agent_id: &str,
        agent_epoch: &str,
    ) {
        provider.state.write().await.bindings.insert(
            server_id.to_string(),
            AgentBinding {
                resource_id: server_id.to_string(),
                agent_id: agent_id.to_owned(),
                agent_epoch: agent_epoch.to_owned(),
                provider_resource_id: None,
            },
        );
    }

    /// Seeds the in-memory binding exactly as a create observation leaves it
    /// for lifecycle dispatch (see `apply_agent_provider_event`): keyed by
    /// the provider (libvirt domain) identity, carrying the create-time
    /// agent epoch and the O3K server identity as the resource.
    async fn seed_lifecycle_binding(
        provider: &AgentComputeProvider,
        provider_instance_id: &str,
        resource_id: &str,
        agent_id: &str,
        agent_epoch: &str,
    ) {
        provider.state.write().await.bindings.insert(
            provider_instance_id.to_owned(),
            AgentBinding {
                resource_id: resource_id.to_owned(),
                agent_id: agent_id.to_owned(),
                agent_epoch: agent_epoch.to_owned(),
                provider_resource_id: Some(provider_instance_id.to_owned()),
            },
        );
    }

    /// Issue #87 crash-restart defect: the agent crashes and re-registers
    /// under a fresh per-connection epoch while the in-memory `AgentBinding`
    /// still carries the pre-crash epoch. `inspect_instance` must not reject
    /// the presence inspection as `StaleState` before dispatching anything:
    /// the registry is authoritative for the current epoch (the #552
    /// rationale), so the same agent's operation resolves against the current
    /// registration. The dispatch itself cannot complete in-process without a
    /// live control stream, so the observable contract is that the failure is
    /// a dispatch attempt (`Retryable`), never a stale-binding rejection.
    #[tokio::test]
    async fn inspect_after_agent_reregistration_dispatches_against_current_epoch()
    -> Result<(), Box<dyn std::error::Error>> {
        let registry = NodeRegistry::default();
        registry
            .register(&register_request("node-a", "epoch-1"))
            .await?;
        let provider =
            AgentComputeProvider::new(registry.clone(), Arc::new(TestResolvedCreateResolver));
        let server_id = Uuid::now_v7();
        seed_create_binding(&provider, server_id, "node-a", "epoch-1").await;
        // The agent crashed and re-registered; the registry now stores the
        // fresh per-connection epoch, mirroring NodeRegistry::register.
        registry
            .register(&register_request("node-a", "epoch-2"))
            .await?;
        let result = provider
            .inspect_instance(
                "node-a",
                &server_id.to_string(),
                "",
                Uuid::now_v7(),
                "inspect-create-test",
            )
            .await;
        match result {
            Err(ProviderError::Retryable) => {}
            other => {
                return Err(format!(
                    "inspect must dispatch against the current agent, got {other:?}"
                )
                .into());
            }
        }
        // The binding was re-anchored to the current registered epoch.
        let binding = provider
            .state
            .read()
            .await
            .bindings
            .get(&server_id.to_string())
            .cloned();
        assert_eq!(
            binding.as_ref().map(|binding| binding.agent_epoch.as_str()),
            Some("epoch-2")
        );
        Ok(())
    }

    /// Issue #87 invariant: an inspection requested for a DIFFERENT agent
    /// than the one the binding belongs to must still be rejected as
    /// `StaleState`; the re-anchor is limited to the agent the operation
    /// actually belongs to and must not mutate the binding on rejection.
    #[tokio::test]
    async fn inspect_for_a_different_agent_is_still_rejected()
    -> Result<(), Box<dyn std::error::Error>> {
        let registry = NodeRegistry::default();
        registry
            .register(&register_request("node-a", "epoch-1"))
            .await?;
        registry
            .register(&register_request("node-b", "epoch-9"))
            .await?;
        let provider =
            AgentComputeProvider::new(registry.clone(), Arc::new(TestResolvedCreateResolver));
        let server_id = Uuid::now_v7();
        seed_create_binding(&provider, server_id, "node-a", "epoch-1").await;
        registry
            .register(&register_request("node-a", "epoch-2"))
            .await?;
        assert_eq!(
            provider
                .inspect_instance(
                    "node-b",
                    &server_id.to_string(),
                    "",
                    Uuid::now_v7(),
                    "inspect-create-test",
                )
                .await,
            Err(ProviderError::StaleState)
        );
        // The rejected inspection must not have re-anchored the binding.
        let binding = provider
            .state
            .read()
            .await
            .bindings
            .get(&server_id.to_string())
            .cloned();
        assert_eq!(
            binding.as_ref().map(|binding| binding.agent_epoch.as_str()),
            Some("epoch-1")
        );
        Ok(())
    }

    /// Issue #88 S3 reap: the create was accepted by an agent that then
    /// crashed (the in-memory binding keeps the pre-crash epoch) without ever
    /// defining a provider object — the binding's `provider_resource_id` is
    /// None. Deleting that never-defined resource must NOT reject on the
    /// stale binding epoch: there is no provider object to fence, the server
    /// id IS the fence, and the registry is authoritative for the agent's
    /// current epoch. `delete_instance` must dispatch with the registry's
    /// current epoch. The wire dispatch cannot complete in-process without a
    /// live control stream, so the observable contract is a dispatch attempt
    /// (`Retryable` — the registry accepted the command epoch and only the
    /// stream was missing), never a stale-binding rejection. `StaleState` is
    /// also exactly what the wire epoch fence produces for a command
    /// carrying a stale epoch, so `Retryable` proves the dispatched command
    /// carried the registry epoch.
    #[tokio::test]
    async fn delete_of_never_defined_binding_dispatches_with_registry_epoch()
    -> Result<(), Box<dyn std::error::Error>> {
        let registry = NodeRegistry::default();
        registry
            .register(&register_request("node-a", "epoch-1"))
            .await?;
        let provider =
            AgentComputeProvider::new(registry.clone(), Arc::new(TestResolvedCreateResolver));
        let server_id = Uuid::now_v7();
        seed_create_binding(&provider, server_id, "node-a", "epoch-1").await;
        // The agent crashed and re-registered; the registry now stores the
        // fresh per-connection epoch.
        registry
            .register(&register_request("node-a", "epoch-2"))
            .await?;
        let result = provider
            .delete_instance(DeleteInstanceRequest {
                operation_id: Uuid::now_v7(),
                provider_instance_id: server_id.to_string(),
                idempotency_key: "o3k:delete-reap:test".to_owned(),
            })
            .await;
        match result {
            Err(ProviderError::Retryable) => {}
            other => {
                return Err(format!(
                    "a never-defined delete must dispatch against the current \
                     agent, got {other:?}"
                )
                .into());
            }
        }
        Ok(())
    }

    /// The delete lookup mirrors the inspect fallback: when the direct
    /// `provider_instance_id` key misses, a binding whose `resource_id`
    /// matches is accepted. The create-dispatch binding is keyed by the
    /// server id, so the reap caller hits directly; the fallback covers
    /// bindings keyed by another identity.
    #[tokio::test]
    async fn delete_falls_back_to_binding_by_resource_id() -> Result<(), Box<dyn std::error::Error>>
    {
        let registry = NodeRegistry::default();
        registry
            .register(&register_request("node-a", "epoch-1"))
            .await?;
        registry
            .register(&register_request("node-a", "epoch-2"))
            .await?;
        let provider =
            AgentComputeProvider::new(registry.clone(), Arc::new(TestResolvedCreateResolver));
        let server_id = Uuid::now_v7();
        provider.state.write().await.bindings.insert(
            "provider-key".to_owned(),
            AgentBinding {
                resource_id: server_id.to_string(),
                agent_id: "node-a".to_owned(),
                agent_epoch: "epoch-1".to_owned(),
                provider_resource_id: None,
            },
        );
        let result = provider
            .delete_instance(DeleteInstanceRequest {
                operation_id: Uuid::now_v7(),
                provider_instance_id: server_id.to_string(),
                idempotency_key: "o3k:delete-reap:test".to_owned(),
            })
            .await;
        match result {
            Err(ProviderError::Retryable) => {}
            other => {
                return Err(format!(
                    "a resource-id binding must resolve for the delete, got {other:?}"
                )
                .into());
            }
        }
        Ok(())
    }

    /// The epoch relaxation is fenced to the never-defined shape only: a
    /// binding that HAS a provider resource identity keeps the strict fence,
    /// so a stale binding epoch for a real provider object is still rejected
    /// as `StaleState` — the registry can never silently re-anchor a delete
    /// for a defined instance.
    #[tokio::test]
    async fn delete_of_defined_binding_still_fences_stale_epochs()
    -> Result<(), Box<dyn std::error::Error>> {
        let registry = NodeRegistry::default();
        registry
            .register(&register_request("node-a", "epoch-1"))
            .await?;
        registry
            .register(&register_request("node-a", "epoch-2"))
            .await?;
        let provider =
            AgentComputeProvider::new(registry.clone(), Arc::new(TestResolvedCreateResolver));
        let server_id = Uuid::now_v7();
        seed_lifecycle_binding(
            &provider,
            "provider-instance-1",
            &server_id.to_string(),
            "node-a",
            "epoch-1",
        )
        .await;
        assert_eq!(
            provider
                .delete_instance(DeleteInstanceRequest {
                    operation_id: Uuid::now_v7(),
                    provider_instance_id: "provider-instance-1".to_owned(),
                    idempotency_key: "o3k:delete-reap:test".to_owned(),
                })
                .await,
            Err(ProviderError::StaleState),
            "a defined binding must keep the strict epoch fence"
        );
        Ok(())
    }

    /// Issue #88 S3 reap, store-backed shape (the production composition):
    /// `delete_instance` rehydrates its projection from the durable ledger
    /// first, and the never-defined binding is keyed by the server id with no
    /// durable provider reference to rebuild from. Rehydration must preserve
    /// the in-memory never-defined binding while its resource is durably
    /// present but NOT provider-defined (failed/unknown/Deleted creates) —
    /// otherwise the reap delete resolves `NotFound` and the crashed agent's
    /// config-drive media is never reaped. A never-defined binding for a
    /// durably DEFINED resource (a create that succeeded later) stays stale
    /// and is purged as today. Without the preservation, this delete resolves
    /// `NotFound`; with it, the dispatch attempt (`Retryable`) proves the
    /// binding survived rehydration.
    #[tokio::test]
    async fn rehydrate_preserves_never_defined_binding_for_reap_delete()
    -> Result<(), Box<dyn std::error::Error>> {
        let store: Arc<dyn o3k_store::ComputeRepository> =
            Arc::new(o3k_store::testkit::open_memory().await?);
        let registry = NodeRegistry::default();
        registry
            .register(&register_request("node-a", "epoch-1"))
            .await?;
        let provider = AgentComputeProvider::new_with_store(
            registry.clone(),
            Arc::new(TestResolvedCreateResolver),
            Some(store.clone()),
        );
        let server_id = Uuid::now_v7();
        seed_create_binding(&provider, server_id, "node-a", "epoch-1").await;
        // The terminalized failed create: durable ERROR resource with no
        // provider identity (the local-completion shape).
        store
            .insert_resource(&o3k_store::ResourceRecord {
                id: server_id,
                kind: "compute_instance".to_owned(),
                project_id: "project-a".to_owned(),
                generation: 1,
                observed_generation: 1,
                desired_state: "{}".to_owned(),
                observed_state: "ERROR".to_owned(),
                provider_id: None,
            })
            .await?;
        registry
            .register(&register_request("node-a", "epoch-2"))
            .await?;
        // The local-completion branch durably records the deterministic
        // delete operation before dispatching the reap; the durable
        // agent-command record references it.
        let operation_id = Uuid::now_v7();
        store
            .insert_operation(&o3k_store::OperationRecord {
                id: operation_id,
                resource_id: server_id,
                kind: "compute_delete".to_owned(),
                state: o3k_store::OperationState::Succeeded,
                provider_operation_id: None,
                error_category: None,
                error_message: None,
            })
            .await?;
        let result = provider
            .delete_instance(DeleteInstanceRequest {
                operation_id,
                provider_instance_id: server_id.to_string(),
                idempotency_key: "o3k:delete-reap:test".to_owned(),
            })
            .await;
        match result {
            Err(ProviderError::Retryable) => {}
            other => {
                return Err(format!(
                    "the store-backed reap delete must dispatch against the \
                     current agent, got {other:?}"
                )
                .into());
            }
        }
        Ok(())
    }

    /// Seeds the durable records of an UnknownOutcome create exactly as the
    /// issue-87 crash-restart residue leaves them: a BUILD resource with no
    /// provider identity, a create operation in `UnknownOutcome`, and the
    /// agent command record whose resource identity is the O3K server id.
    async fn seed_unknown_outcome_create(
        store: &dyn ComputeRepository,
        operation_id: Uuid,
        resource_id: Uuid,
    ) -> Result<(), Box<dyn std::error::Error>> {
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
                state: o3k_store::OperationState::UnknownOutcome,
                provider_operation_id: Some(operation_id.to_string()),
                error_category: Some("unknown_outcome".to_owned()),
                error_message: None,
            })
            .await?;
        store
            .insert_agent_command(&o3k_store::AgentCommandRecord {
                command_id: "command-create".to_owned(),
                idempotency_key: "create-request".to_owned(),
                operation_id,
                resource_id,
                agent_id: "node-a".to_owned(),
                agent_epoch: "epoch-1".to_owned(),
                payload_fingerprint_sha256: String::new(),
                payload: Vec::new(),
                state: o3k_store::AgentCommandState::UnknownOutcome,
                accepted_sequence: 1,
                last_sequence: 1,
                provider_operation_id: Some(operation_id.to_string()),
                provider_resource_id: None,
            })
            .await?;
        Ok(())
    }

    /// Issue #87 crash-recovery defect: the agent settles the presence
    /// inspection for an UnknownOutcome create as a terminal Failed/NotFound
    /// when the domain provably was never created. That absence evidence
    /// still carries the stable libvirt domain name in `provider_resource_id`
    /// (the name is derived from the server identity, not from existence).
    /// The observation handler must NOT project it: the journal's
    /// `apply_agent_observation` rejects non-Succeeded observations by
    /// design, and a durable provider reference attached from absence
    /// evidence would make the create sweep resolve a phantom resource
    /// identity (`get_operation` reads the "agent" reference) and drive
    /// `finish_create` against a never-created domain forever — the
    /// `server create convergence pass failed` loop — instead of reaching
    /// `converge_absent_create`.
    #[tokio::test]
    async fn absence_observation_does_not_project_a_provider_reference()
    -> Result<(), Box<dyn std::error::Error>> {
        let store: Arc<dyn ComputeRepository> = Arc::new(o3k_store::testkit::open_memory().await?);
        let operation_id = Uuid::now_v7();
        let resource_id = Uuid::now_v7();
        // The agent derives the stable domain name from the server identity
        // (o3k-libvirt `stable_domain_name`), so a provably absent domain
        // still has a deterministic name.
        let domain_name = "o3k-0123456789abcdef0123";
        seed_unknown_outcome_create(store.as_ref(), operation_id, resource_id).await?;
        let state = Arc::new(RwLock::new(AgentProviderState::default()));
        apply_agent_provider_event(
            &state,
            Some(store.as_ref()),
            None,
            o3k_provider::AgentEvent::Observation(Box::new(AgentObservation {
                agent_id: "node-a".to_owned(),
                agent_epoch: "epoch-1".to_owned(),
                resource_id,
                provider_resource_id: Some(domain_name.to_owned()),
                state: o3k_provider::InstanceState::Error,
                operation_id: Uuid::new_v5(
                    &Uuid::NAMESPACE_URL,
                    format!("o3k:inspect-create:{operation_id}").as_bytes(),
                ),
                operation_state: AgentOperationState::Failed,
                observation_sequence: 1,
                observed_at_unix_ms: 1,
                redacted_message: Some("requested domain was not found".to_owned()),
                console_log_bytes: Vec::new(),
                console_log_offset: 0,
                console_log_complete: false,
                console_log_truncated: false,
                block_device: None,
            })),
        )
        .await;
        // Absence evidence must not become a durable provider reference...
        assert!(
            matches!(
                store.get_provider_reference(resource_id, "agent").await,
                Err(StoreError::ProviderReferenceNotFound)
            ),
            "a failed/not_found observation must not attach a provider reference"
        );
        // ...must not project a volatile instance or binding for a domain
        // that was provably never created...
        let provider = AgentComputeProvider {
            registry: NodeRegistry::default(),
            resolver: Arc::new(UnconfiguredResolvedCreateResolver),
            state: state.clone(),
            store: Some(store.clone()),
            artifact_resolver: Arc::new(UnconfiguredCreateArtifactResolver),
            command_timeout: Duration::from_secs(30),
        };
        assert!(
            provider.state.read().await.instances.is_empty(),
            "failed observation must not project a volatile instance"
        );
        assert!(
            provider.state.read().await.bindings.is_empty(),
            "failed observation must not project a volatile binding"
        );
        // ...and the create's provider operation must keep no resource
        // identity, so the reconciler sweep routes the UnknownOutcome create
        // to `observe_create_presence` (whose durable Failed/not_found
        // inspection converges the create as absent) instead of
        // `finish_create` against the phantom domain name.
        assert_eq!(
            provider
                .get_operation(operation_id)
                .await?
                .provider_resource_id,
            None
        );
        Ok(())
    }

    /// ASR-015: an E1 event may already be queued when E2 replaces that
    /// connection.  The provider-side backup projector must consult the live
    /// registry before touching the durable command; only E2 may repair a
    /// lagged authoritative consumer.
    #[tokio::test]
    async fn backup_command_projection_fences_queued_replaced_epoch()
    -> Result<(), Box<dyn std::error::Error>> {
        let store: Arc<dyn ComputeRepository> = Arc::new(o3k_store::testkit::open_memory().await?);
        let operation_id = Uuid::now_v7();
        let resource_id = Uuid::now_v7();
        seed_unknown_outcome_create(store.as_ref(), operation_id, resource_id).await?;
        let registry = NodeRegistry::default();
        registry
            .register(&register_request("node-a", "epoch-2"))
            .await?;
        let state = Arc::new(RwLock::new(AgentProviderState::default()));
        let stale = o3k_provider::AgentOperationUpdate {
            agent_id: "node-a".to_owned(),
            agent_epoch: "epoch-1".to_owned(),
            operation_sequence: 2,
            operation_id,
            resource_id,
            state: AgentOperationState::Succeeded,
            error_category: None,
            redacted_message: None,
            provider_resource_id: Some("domain-a".to_owned()),
        };
        apply_agent_provider_event(
            &state,
            Some(store.as_ref()),
            Some(&registry),
            o3k_provider::AgentEvent::Operation(stale.clone()),
        )
        .await;
        assert_eq!(
            store
                .get_agent_command_by_operation(operation_id)
                .await?
                .state,
            AgentCommandState::UnknownOutcome
        );

        let unclassified_failure = o3k_provider::AgentOperationUpdate {
            agent_epoch: "epoch-2".to_owned(),
            state: AgentOperationState::Failed,
            ..stale
        };
        apply_agent_provider_event(
            &state,
            Some(store.as_ref()),
            Some(&registry),
            o3k_provider::AgentEvent::Operation(unclassified_failure.clone()),
        )
        .await;
        assert_eq!(
            store
                .get_agent_command_by_operation(operation_id)
                .await?
                .state,
            AgentCommandState::UnknownOutcome
        );

        let running = o3k_provider::AgentOperationUpdate {
            state: AgentOperationState::Running,
            ..unclassified_failure
        };
        apply_agent_provider_event(
            &state,
            Some(store.as_ref()),
            Some(&registry),
            o3k_provider::AgentEvent::Operation(running.clone()),
        )
        .await;
        assert_eq!(
            store
                .get_agent_command_by_operation(operation_id)
                .await?
                .state,
            AgentCommandState::UnknownOutcome
        );

        let succeeded = o3k_provider::AgentOperationUpdate {
            state: AgentOperationState::Succeeded,
            ..running
        };
        apply_agent_provider_event(
            &state,
            Some(store.as_ref()),
            Some(&registry),
            o3k_provider::AgentEvent::Operation(succeeded),
        )
        .await;
        assert_eq!(
            store
                .get_agent_command_by_operation(operation_id)
                .await?
                .state,
            AgentCommandState::Succeeded
        );
        Ok(())
    }

    #[tokio::test]
    async fn backup_command_projection_rejects_agent_reference_identity_drift()
    -> Result<(), Box<dyn std::error::Error>> {
        let store: Arc<dyn ComputeRepository> = Arc::new(o3k_store::testkit::open_memory().await?);
        let operation_id = Uuid::now_v7();
        let resource_id = Uuid::now_v7();
        seed_unknown_outcome_create(store.as_ref(), operation_id, resource_id).await?;
        store
            .attach_provider_reference(&o3k_store::ProviderReference {
                resource_id,
                provider_name: "agent".to_owned(),
                provider_resource_id: "domain-established".to_owned(),
            })
            .await?;
        let registry = NodeRegistry::default();
        registry
            .register(&register_request("node-a", "epoch-2"))
            .await?;
        let state = Arc::new(RwLock::new(AgentProviderState::default()));
        apply_agent_provider_event(
            &state,
            Some(store.as_ref()),
            Some(&registry),
            o3k_provider::AgentEvent::Operation(o3k_provider::AgentOperationUpdate {
                agent_id: "node-a".to_owned(),
                agent_epoch: "epoch-2".to_owned(),
                operation_sequence: 2,
                operation_id,
                resource_id,
                state: AgentOperationState::Succeeded,
                error_category: None,
                redacted_message: None,
                provider_resource_id: Some("domain-conflict".to_owned()),
            }),
        )
        .await;
        assert_eq!(
            store
                .get_agent_command_by_operation(operation_id)
                .await?
                .state,
            AgentCommandState::UnknownOutcome
        );
        assert_eq!(
            store
                .get_provider_reference(resource_id, "agent")
                .await?
                .provider_resource_id,
            "domain-established"
        );
        Ok(())
    }

    /// Issue #87 invariant: a SUCCEEDED observation still projects the
    /// durable provider reference, the volatile instance, and the binding —
    /// the domain was verified to exist, and the presence inspection that
    /// finds the instance converges the create to success through this
    /// identity.
    #[tokio::test]
    async fn succeeded_observation_projects_the_provider_reference()
    -> Result<(), Box<dyn std::error::Error>> {
        let store: Arc<dyn ComputeRepository> = Arc::new(o3k_store::testkit::open_memory().await?);
        let operation_id = Uuid::now_v7();
        let resource_id = Uuid::now_v7();
        let domain_name = "o3k-0123456789abcdef0123";
        seed_unknown_outcome_create(store.as_ref(), operation_id, resource_id).await?;
        let state = Arc::new(RwLock::new(AgentProviderState::default()));
        apply_agent_provider_event(
            &state,
            Some(store.as_ref()),
            None,
            o3k_provider::AgentEvent::Observation(Box::new(AgentObservation {
                agent_id: "node-a".to_owned(),
                agent_epoch: "epoch-1".to_owned(),
                resource_id,
                provider_resource_id: Some(domain_name.to_owned()),
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
        let reference = store.get_provider_reference(resource_id, "agent").await?;
        assert_eq!(reference.provider_resource_id, domain_name);
        let provider = AgentComputeProvider {
            registry: NodeRegistry::default(),
            resolver: Arc::new(UnconfiguredResolvedCreateResolver),
            state: state.clone(),
            store: Some(store.clone()),
            artifact_resolver: Arc::new(UnconfiguredCreateArtifactResolver),
            command_timeout: Duration::from_secs(30),
        };
        let instance = provider
            .state
            .read()
            .await
            .instances
            .get(domain_name)
            .cloned()
            .ok_or("succeeded observation must project the volatile instance")?;
        assert_eq!(instance.o3k_server_id, resource_id);
        assert_eq!(instance.state, o3k_provider::InstanceState::Running);
        let binding = provider
            .state
            .read()
            .await
            .bindings
            .get(domain_name)
            .cloned()
            .ok_or("succeeded observation must project the binding")?;
        assert_eq!(binding.resource_id, resource_id.to_string());
        Ok(())
    }

    /// Seeds the durable records of an in-flight lifecycle operation exactly
    /// as the reconcile loop leaves them during a transport stall: an ACTIVE
    /// resource with a provider identity and a valid create intent (the
    /// rehydrate projection decodes it), the attached "agent" provider
    /// reference (the create observation attached it), the lifecycle
    /// operation in `Running`, and (in the caller's step) the pending agent
    /// command. The operation row is the FK target of
    /// `agent_commands.operation_id`.
    async fn seed_lifecycle_operation(
        store: &dyn ComputeRepository,
        operation_id: Uuid,
        resource_id: Uuid,
    ) -> Result<(), Box<dyn std::error::Error>> {
        let request = CreateInstanceRequest {
            operation_id,
            o3k_server_id: resource_id,
            project_id: "project-a".to_owned(),
            name: "server-a".to_owned(),
            vcpus: 1,
            memory_mib: 512,
            flavor_id: "flavor.test".to_owned(),
            disk_gib: 10,
            image_id: Some("image-a".to_owned()),
            key_name: None,
            keypair_id: None,
            network_ids: vec!["port-a".to_owned()],
            placement_provider_id: Some("node-a".to_owned()),
            placement_allocation_id: Some("alloc-a".to_owned()),
            config_drive: None,
            idempotency_key: "create-a".to_owned(),
        };
        store
            .insert_resource(&o3k_store::ResourceRecord {
                id: resource_id,
                kind: "compute_instance".to_owned(),
                project_id: "project-a".to_owned(),
                generation: 3,
                observed_generation: 3,
                desired_state: serde_json::to_string(&request).map_err(|_| {
                    std::io::Error::new(std::io::ErrorKind::InvalidData, "request serialization")
                })?,
                observed_state: "ACTIVE".to_owned(),
                provider_id: Some("domain-a".to_owned()),
            })
            .await?;
        store
            .attach_provider_reference(&o3k_store::ProviderReference {
                resource_id,
                provider_name: "agent".to_owned(),
                provider_resource_id: "domain-a".to_owned(),
            })
            .await?;
        store
            .insert_operation(&o3k_store::OperationRecord {
                id: operation_id,
                resource_id,
                kind: "lifecycle:reboot".to_owned(),
                state: o3k_store::OperationState::Running,
                provider_operation_id: Some(operation_id.to_string()),
                error_category: None,
                error_message: None,
            })
            .await?;
        Ok(())
    }

    /// Issue #87 B2 regression (agent-control-plane-network-interruption):
    /// a re-dispatch of a durably recorded lifecycle command whose embedded
    /// deadline has expired — the residue of an accepted in-flight command
    /// during a stalled control stream — must be classified as an unknown
    /// outcome, never as a rejected request. The command may already have
    /// been delivered and executed while the stream was down (in the
    /// real-host failure the agent accepted and executed the reboot and
    /// re-delivered the terminal observation after the restore); the
    /// reconciler must observe the operation before retrying instead of
    /// terminalizing it as failed/invalid_request.
    #[tokio::test]
    async fn lifecycle_redispatch_past_command_deadline_is_unknown_outcome()
    -> Result<(), Box<dyn std::error::Error>> {
        let registry = NodeRegistry::default();
        registry
            .register(&register_request("node-a", "epoch-1"))
            .await?;
        let store: Arc<dyn ComputeRepository> = Arc::new(o3k_store::testkit::open_memory().await?);
        let provider = AgentComputeProvider::new_with_store(
            registry.clone(),
            Arc::new(TestResolvedCreateResolver),
            Some(store.clone()),
        );
        let server_id = Uuid::now_v7();
        let operation_id = Uuid::now_v7();
        seed_lifecycle_binding(
            &provider,
            "domain-a",
            &server_id.to_string(),
            "node-a",
            "epoch-1",
        )
        .await;
        seed_lifecycle_operation(store.as_ref(), operation_id, server_id).await?;
        // The stalled-stream residue: the command was durably recorded as
        // Pending (its acceptance never reached the control plane) and the
        // reconcile re-drive happens after the embedded 10s deadline
        // expired. The deadline is not part of the canonical payload, so the
        // recorded fingerprint stays valid and only the deadline fence fires.
        let mut command = build_lifecycle_command(
            LifecycleCommand::HardReboot,
            "node-a",
            "epoch-1",
            &operation_id.to_string(),
            &server_id.to_string(),
        )?;
        command.deadline_unix_ms = unix_ms().saturating_sub(1);
        store
            .insert_agent_command(&AgentCommandRecord {
                command_id: command.command_id.clone(),
                idempotency_key: command.idempotency_key.clone(),
                operation_id,
                resource_id: server_id,
                agent_id: command.agent_id.clone(),
                agent_epoch: command.agent_epoch.clone(),
                payload_fingerprint_sha256: command.payload_fingerprint_sha256.clone(),
                payload: command.encode_to_vec(),
                state: AgentCommandState::Pending,
                accepted_sequence: 0,
                last_sequence: 0,
                provider_operation_id: Some(operation_id.to_string()),
                provider_resource_id: None,
            })
            .await?;
        let result = provider
            .action_instance(
                "domain-a",
                o3k_provider::InstanceAction::Reboot,
                operation_id,
                "reboot-a",
            )
            .await;
        match result {
            Err(ProviderError::UnknownOutcome {
                operation_id: unknown,
            }) if unknown == operation_id => {}
            other => {
                return Err(format!(
                    "a stalled-stream lifecycle re-dispatch must be an unknown outcome, got {other:?}"
                )
                .into());
            }
        }
        // The accepted projection must not leak, and the durable command
        // record must be untouched, ready for the reconciler's
        // observe-before-retry pass.
        assert!(
            provider.state.read().await.operations.is_empty(),
            "a failed dispatch must not leave an accepted operation projection"
        );
        assert_eq!(
            store
                .get_agent_command_by_operation(operation_id)
                .await?
                .state,
            AgentCommandState::Pending
        );
        Ok(())
    }

    /// Issue #87 B2 invariant: a genuinely invalid command payload — a
    /// durable record whose fingerprint does not match its canonical payload
    /// — must STILL be rejected as `InvalidRequest` (the reconciler's
    /// terminal failure path). The transport-stall reclassification never
    /// weakens real validation.
    #[tokio::test]
    async fn lifecycle_redispatch_with_corrupt_payload_is_still_invalid_request()
    -> Result<(), Box<dyn std::error::Error>> {
        let registry = NodeRegistry::default();
        registry
            .register(&register_request("node-a", "epoch-1"))
            .await?;
        let store: Arc<dyn ComputeRepository> = Arc::new(o3k_store::testkit::open_memory().await?);
        let provider = AgentComputeProvider::new_with_store(
            registry.clone(),
            Arc::new(TestResolvedCreateResolver),
            Some(store.clone()),
        );
        let server_id = Uuid::now_v7();
        let operation_id = Uuid::now_v7();
        seed_lifecycle_binding(
            &provider,
            "domain-a",
            &server_id.to_string(),
            "node-a",
            "epoch-1",
        )
        .await;
        seed_lifecycle_operation(store.as_ref(), operation_id, server_id).await?;
        let mut command = build_lifecycle_command(
            LifecycleCommand::HardReboot,
            "node-a",
            "epoch-1",
            &operation_id.to_string(),
            &server_id.to_string(),
        )?;
        // The embedded deadline stays live so the fingerprint fence is the
        // only validation that can fire.
        command.payload_fingerprint_sha256 = "f".repeat(64);
        store
            .insert_agent_command(&AgentCommandRecord {
                command_id: command.command_id.clone(),
                idempotency_key: command.idempotency_key.clone(),
                operation_id,
                resource_id: server_id,
                agent_id: command.agent_id.clone(),
                agent_epoch: command.agent_epoch.clone(),
                payload_fingerprint_sha256: command.payload_fingerprint_sha256.clone(),
                payload: command.encode_to_vec(),
                state: AgentCommandState::Pending,
                accepted_sequence: 0,
                last_sequence: 0,
                provider_operation_id: Some(operation_id.to_string()),
                provider_resource_id: None,
            })
            .await?;
        let result = provider
            .action_instance(
                "domain-a",
                o3k_provider::InstanceAction::Reboot,
                operation_id,
                "reboot-a",
            )
            .await;
        assert_eq!(
            result,
            Err(ProviderError::InvalidRequest),
            "a corrupt command payload must stay a rejected request"
        );
        assert!(
            provider.state.read().await.operations.is_empty(),
            "a rejected dispatch must not leave an accepted operation projection"
        );
        Ok(())
    }

    // ------------------------------------------------------------------
    // Issue #88 E3 C3: concurrent create dispatches racing the durable
    // command insert (the API's synchronous create reconcile vs the periodic
    // create-convergence sweep). The second insert must adopt the first
    // caller's row instead of failing the fresh create with a terminal
    // Conflict (the observed real-host 409 + terminalization).
    // ------------------------------------------------------------------

    /// Artifact payloads for the create race tests; the digests advertised by
    /// `RaceTestResolvedCreateResolver` hash exactly these payloads (the wire
    /// validation rehashes the dispatched bytes).
    const IMAGE_PAYLOAD: &[u8] = b"o3k-race-test-image-payload";
    const CONFIG_DRIVE_PAYLOAD: &[u8] = b"o3k-race-test-config-drive-payload";

    fn artifact_transfer_fixture() -> (
        ArtifactTransferRecord,
        agent_proto::ArtifactOffer,
        Uuid,
        Uuid,
        String,
    ) {
        let operation_id = Uuid::now_v7();
        let resource_id = Uuid::now_v7();
        let sha256 = "a".repeat(64);
        let transfer_id = "transfer-race".to_owned();
        let command_id = "command-race".to_owned();
        let agent_id = "node-a".to_owned();
        let agent_epoch = "epoch-1".to_owned();
        let artifact_id = "artifact.test".to_owned();
        let record = ArtifactTransferRecord {
            transfer_id: transfer_id.clone(),
            command_id: command_id.clone(),
            operation_id,
            resource_id,
            agent_id: agent_id.clone(),
            agent_epoch: agent_epoch.clone(),
            artifact_id: artifact_id.clone(),
            artifact_kind: "image_base".to_owned(),
            sha256: sha256.clone(),
            size_bytes: 8,
            expires_at_unix_ms: 2_000_000_000_000,
            format: "qcow2".to_owned(),
            chunk_size_bytes: 4,
            chunk_count: 2,
            state: ArtifactTransferState::Receiving,
            contiguous_bytes: 4,
            next_chunk_index: 1,
            retry_count: 0,
            created_at: String::new(),
            updated_at: String::new(),
        };
        let offer = agent_proto::ArtifactOffer {
            transfer_id,
            command_id,
            operation_id: operation_id.to_string(),
            resource_id: resource_id.to_string(),
            agent_id,
            artifact_id,
            kind: agent_proto::ArtifactKind::ImageBase as i32,
            sha256,
            size_bytes: 8,
            format: "qcow2".to_owned(),
            chunk_size_bytes: 4,
            chunk_count: 2,
            expires_at_unix_ms: 2_000_000_000_000,
        };
        (record, offer, operation_id, resource_id, agent_epoch)
    }

    /// Regression for the foreground artifact waiter racing the asynchronous
    /// status projection: the competing commit wins durably, the foreground
    /// conflict adopts that exact canonical result, and incompatible rows are
    /// never accepted.
    #[tokio::test]
    async fn foreground_artifact_commit_adopts_only_equivalent_terminal_row()
    -> Result<(), Box<dyn std::error::Error>> {
        let store = o3k_store::testkit::open_memory().await?;
        let (mut receiving, offer, operation_id, resource_id, agent_epoch) =
            artifact_transfer_fixture();
        seed_create_durable_rows(&store, operation_id, resource_id).await?;
        store.insert_artifact_transfer(&receiving).await?;

        // The asynchronous recovery/status projection commits first.
        store
            .update_artifact_transfer(
                &offer.transfer_id,
                &agent_epoch,
                ArtifactTransferUpdate {
                    state: ArtifactTransferState::Committed,
                    contiguous_bytes: offer.size_bytes,
                    next_chunk_index: offer.chunk_count as u64,
                    retry_count: 3,
                },
            )
            .await?;
        let foreground = store
            .update_artifact_transfer(
                &offer.transfer_id,
                &agent_epoch,
                ArtifactTransferUpdate {
                    state: ArtifactTransferState::Committed,
                    contiguous_bytes: offer.size_bytes,
                    next_chunk_index: offer.chunk_count as u64,
                    retry_count: 0,
                },
            )
            .await;
        assert!(matches!(
            foreground,
            Err(StoreError::ArtifactTransferConflict(_))
        ));
        let canonical = store.get_artifact_transfer(&offer.transfer_id).await?;
        assert!(equivalent_committed_transfer(
            &canonical,
            &offer,
            operation_id,
            resource_id,
            "image_base",
            &agent_epoch,
        ));
        assert_eq!(canonical.retry_count, 3);
        assert_eq!(store.list_recoverable_artifact_transfers().await?.len(), 0);

        // Every immutable identity/fencing field and complete progress is
        // required for adoption; retry_count remains intentionally mutable.
        let mut incompatible = canonical.clone();
        incompatible.agent_epoch = "epoch-other".to_owned();
        assert!(!equivalent_committed_transfer(
            &incompatible,
            &offer,
            operation_id,
            resource_id,
            "image_base",
            &agent_epoch,
        ));
        incompatible = canonical.clone();
        incompatible.sha256 = "b".repeat(64);
        assert!(!equivalent_committed_transfer(
            &incompatible,
            &offer,
            operation_id,
            resource_id,
            "image_base",
            &agent_epoch,
        ));
        incompatible = canonical.clone();
        incompatible.contiguous_bytes = 4;
        assert!(!equivalent_committed_transfer(
            &incompatible,
            &offer,
            operation_id,
            resource_id,
            "image_base",
            &agent_epoch,
        ));
        receiving.state = ArtifactTransferState::Receiving;
        assert!(!equivalent_committed_transfer(
            &receiving,
            &offer,
            operation_id,
            resource_id,
            "image_base",
            &agent_epoch,
        ));
        Ok(())
    }

    fn sha256_hex(bytes: &[u8]) -> String {
        format!("{:x}", sha2::Sha256::digest(bytes))
    }

    /// Resolved create inputs derived from the test artifact payloads so the
    /// advertised digests are the actual payload hashes.
    #[derive(Debug, Default)]
    struct RaceTestResolvedCreateResolver;

    #[async_trait]
    impl ResolvedCreateResolver for RaceTestResolvedCreateResolver {
        async fn resolve(
            &self,
            _request: &CreateInstanceRequest,
            _agent: &AgentNodeSnapshot,
        ) -> Result<ResolvedCreateInputs, ProviderError> {
            Ok(ResolvedCreateInputs {
                flavor_id: "flavor.test".to_owned(),
                image_artifact_id: "artifact.test".to_owned(),
                image_sha256: sha256_hex(IMAGE_PAYLOAD),
                image_format: "qcow2".to_owned(),
                disk_gib: 10,
                config_drive_artifact_id: "config-drive.test".to_owned(),
                config_drive_sha256: sha256_hex(CONFIG_DRIVE_PAYLOAD),
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

    /// Resolves both required create artifacts from the test payloads.
    #[derive(Debug, Default)]
    struct RaceTestCreateArtifactResolver;

    #[async_trait]
    impl CreateArtifactResolver for RaceTestCreateArtifactResolver {
        async fn resolve_artifacts(
            &self,
            _request: &CreateInstanceRequest,
            _agent: &AgentNodeSnapshot,
            _inputs: &ResolvedCreateInputs,
        ) -> Result<Vec<ResolvedCreateArtifact>, ProviderError> {
            Ok(vec![
                ResolvedCreateArtifact {
                    artifact_id: "artifact.test".to_owned(),
                    kind: o3k_provider::ArtifactKind::ImageBase,
                    sha256: sha256_hex(IMAGE_PAYLOAD),
                    format: "qcow2".to_owned(),
                    bytes: IMAGE_PAYLOAD.to_vec(),
                },
                ResolvedCreateArtifact {
                    artifact_id: "config-drive.test".to_owned(),
                    kind: o3k_provider::ArtifactKind::ConfigDriveIso,
                    sha256: sha256_hex(CONFIG_DRIVE_PAYLOAD),
                    format: "iso".to_owned(),
                    bytes: CONFIG_DRIVE_PAYLOAD.to_vec(),
                },
            ])
        }
    }

    /// The create request used by the race tests; every field matches the
    /// durable command row seeded through `racing_create_command`.
    fn race_create_request(operation_id: Uuid, server_id: Uuid) -> CreateInstanceRequest {
        CreateInstanceRequest {
            operation_id,
            o3k_server_id: server_id,
            project_id: "project-a".to_owned(),
            name: "race-server".to_owned(),
            vcpus: 2,
            memory_mib: 2048,
            flavor_id: "flavor.test".to_owned(),
            disk_gib: 10,
            image_id: Some("image.test".to_owned()),
            key_name: None,
            keypair_id: None,
            network_ids: vec!["net.test".to_owned()],
            placement_provider_id: Some("node-a".to_owned()),
            placement_allocation_id: None,
            config_drive: None,
            idempotency_key: "create-race".to_owned(),
        }
    }

    /// The create command another dispatch already durably recorded for the
    /// operation: the same deterministic command identity the fresh build
    /// produces (agent + operation), with a deadline an hour away so its
    /// payload provably differs from any freshly built command — exactly the
    /// store-level interleaving the real-host race leaves behind.
    fn racing_create_command(
        operation_id: Uuid,
        server_id: Uuid,
    ) -> Result<agent_proto::Command, AgentError> {
        build_create_command(CreateCommandSpec {
            agent_id: "node-a".to_owned(),
            agent_epoch: "epoch-1".to_owned(),
            project_id: "project-a".to_owned(),
            operation_id: operation_id.to_string(),
            resource_id: server_id.to_string(),
            idempotency_key: "create-race".to_owned(),
            deadline_unix_ms: unix_ms() + 3_600_000,
            image_id: "image.test".to_owned(),
            flavor_id: "flavor.test".to_owned(),
            image_artifact_id: "artifact.test".to_owned(),
            image_sha256: sha256_hex(IMAGE_PAYLOAD),
            image_format: "qcow2".to_owned(),
            vcpus: 2,
            memory_mib: 2048,
            disk_gib: 10,
            config_drive_artifact_id: "config-drive.test".to_owned(),
            config_drive_sha256: sha256_hex(CONFIG_DRIVE_PAYLOAD),
            network_attachments: vec![NetworkAttachmentSpec {
                port_id: "port.test".to_owned(),
                mac: "52:54:00:12:34:56".to_owned(),
                fixed_ipv4: "192.0.2.10".to_owned(),
                subnet_cidr: "192.0.2.0/24".to_owned(),
                gateway_ipv4: "192.0.2.1".to_owned(),
            }],
        })
    }

    /// Seeds the durable resource and operation rows a command record
    /// references (foreign keys), exactly as the journal leaves them before
    /// the create dispatch.
    async fn seed_create_durable_rows(
        store: &dyn ComputeRepository,
        operation_id: Uuid,
        server_id: Uuid,
    ) -> Result<(), Box<dyn std::error::Error>> {
        store
            .insert_resource(&o3k_store::ResourceRecord {
                id: server_id,
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
                resource_id: server_id,
                kind: "compute_create".to_owned(),
                state: o3k_store::OperationState::Running,
                provider_operation_id: Some(operation_id.to_string()),
                error_category: None,
                error_message: None,
            })
            .await?;
        Ok(())
    }

    /// Drains the fenced agent control stream: acknowledges every artifact
    /// offer as committed (so `create_instance` completes) and forwards every
    /// dispatched command to the returned channel.
    fn spawn_agent_reader(
        registry: NodeRegistry,
        mut receiver: mpsc::Receiver<Result<agent_proto::ControlResponse, tonic::Status>>,
    ) -> mpsc::UnboundedReceiver<agent_proto::Command> {
        let (commands_tx, commands_rx) = mpsc::unbounded_channel();
        let publisher = registry.clone();
        tokio::spawn(async move {
            while let Some(Ok(response)) = receiver.recv().await {
                match response.body {
                    Some(agent_proto::control_response::Body::ArtifactOffer(offer)) => {
                        let Some(operation_id) = Uuid::parse_str(&offer.operation_id).ok() else {
                            continue;
                        };
                        let Some(resource_id) = Uuid::parse_str(&offer.resource_id).ok() else {
                            continue;
                        };
                        publisher.publish_event(ProviderAgentEvent::ArtifactAck(
                            o3k_provider::AgentArtifactAck {
                                transfer_id: offer.transfer_id,
                                command_id: offer.command_id,
                                operation_id,
                                resource_id,
                                agent_id: offer.agent_id,
                                agent_epoch: "epoch-1".to_owned(),
                                contiguous_bytes: offer.size_bytes,
                                next_chunk_index: offer.chunk_count,
                                state: o3k_provider::ArtifactTransferState::Committed,
                                redacted_message: None,
                            },
                        ));
                    }
                    Some(agent_proto::control_response::Body::Command(command)) => {
                        let _ = commands_tx.send(command);
                    }
                    _ => {}
                }
            }
        });
        commands_rx
    }

    /// Issue #88 E3 C3 create-path race: while the first dispatch's durable
    /// command row already exists, a second `create_instance` for the same
    /// operation reaches its command insert (the observed
    /// "agent create pending command persistence rejected"). The second
    /// caller must adopt the surviving row and re-dispatch it instead of
    /// failing with `Conflict`. The interleaving is driven deterministically
    /// by pre-inserting the first caller's row — whose payload provably
    /// differs from a fresh build (deadline an hour away, matching the
    /// real-host deadline drift) — before the racing caller runs.
    #[tokio::test]
    async fn create_dispatch_race_adopts_existing_durable_command()
    -> Result<(), Box<dyn std::error::Error>> {
        let store: Arc<dyn ComputeRepository> = Arc::new(o3k_store::testkit::open_memory().await?);
        let registry = NodeRegistry::default();
        registry
            .register(&register_request("node-a", "epoch-1"))
            .await?;
        let (sender, receiver) = mpsc::channel(32);
        registry
            .attach_connection("node-a", "epoch-1", sender)
            .await?;
        let mut commands = spawn_agent_reader(registry.clone(), receiver);
        let provider = AgentComputeProvider::new_with_store(
            registry.clone(),
            Arc::new(RaceTestResolvedCreateResolver),
            Some(store.clone()),
        )
        .with_artifact_resolver(Arc::new(RaceTestCreateArtifactResolver));
        let operation_id = Uuid::now_v7();
        let server_id = Uuid::now_v7();
        seed_create_durable_rows(store.as_ref(), operation_id, server_id).await?;
        let recorded = racing_create_command(operation_id, server_id)?;
        store
            .insert_agent_command(&AgentCommandRecord {
                command_id: recorded.command_id.clone(),
                idempotency_key: recorded.idempotency_key.clone(),
                operation_id,
                resource_id: server_id,
                agent_id: recorded.agent_id.clone(),
                agent_epoch: recorded.agent_epoch.clone(),
                payload_fingerprint_sha256: recorded.payload_fingerprint_sha256.clone(),
                payload: recorded.encode_to_vec(),
                state: AgentCommandState::Pending,
                accepted_sequence: 0,
                last_sequence: 0,
                provider_operation_id: Some(operation_id.to_string()),
                provider_resource_id: None,
            })
            .await?;

        let operation = provider
            .create_instance(race_create_request(operation_id, server_id))
            .await
            .map_err(|error| {
                format!(
                    "the racing create must adopt the durable command instead \
                     of failing, got {error:?}"
                )
            })?;
        assert_eq!(operation.state, o3k_provider::OperationState::Accepted);
        let durable = store.list_recoverable_agent_commands().await?;
        assert_eq!(durable.len(), 1, "exactly one durable command row");
        assert_eq!(durable[0].command_id, recorded.command_id);
        let delivered = commands
            .recv()
            .await
            .ok_or("the agent stream must deliver exactly one command")?;
        assert_eq!(delivered.command_id, recorded.command_id);
        assert_eq!(
            delivered.deadline_unix_ms, recorded.deadline_unix_ms,
            "the recorded payload is re-dispatched, not a rebuild"
        );
        assert!(
            commands.try_recv().is_err(),
            "the agent stream must carry exactly one command"
        );
        Ok(())
    }

    /// Issue #88 E3 C3: two REAL `create_instance` calls for the same
    /// operation racing the durable command insert — the observed shape of
    /// the API's synchronous create reconcile against the periodic
    /// create-convergence sweep. Both callers must succeed, the second
    /// adopting the first's row; exactly one durable command remains; every
    /// command the agent stream carries is that single command identity.
    /// The racing caller gets a different command timeout so its freshly
    /// built payload (embedded deadline) provably differs from the first
    /// caller's, and the second insert hits the same unique-identity
    /// conflict the real host observed.
    #[tokio::test]
    async fn two_concurrent_create_dispatches_converge_on_one_command()
    -> Result<(), Box<dyn std::error::Error>> {
        let store: Arc<dyn ComputeRepository> = Arc::new(o3k_store::testkit::open_memory().await?);
        let registry = NodeRegistry::default();
        registry
            .register(&register_request("node-a", "epoch-1"))
            .await?;
        let (sender, receiver) = mpsc::channel(32);
        registry
            .attach_connection("node-a", "epoch-1", sender)
            .await?;
        let mut commands = spawn_agent_reader(registry.clone(), receiver);
        let make_provider = |timeout: Duration| {
            AgentComputeProvider::new_with_store(
                registry.clone(),
                Arc::new(RaceTestResolvedCreateResolver),
                Some(store.clone()),
            )
            .with_command_timeout(timeout)
            .with_artifact_resolver(Arc::new(RaceTestCreateArtifactResolver))
        };
        let first = make_provider(Duration::from_secs(30));
        let racing = make_provider(Duration::from_secs(60));
        let operation_id = Uuid::now_v7();
        let server_id = Uuid::now_v7();
        seed_create_durable_rows(store.as_ref(), operation_id, server_id).await?;
        let request = race_create_request(operation_id, server_id);

        let first_operation = first
            .create_instance(request.clone())
            .await
            .map_err(|error| format!("the first create dispatch must succeed, got {error:?}"))?;
        assert_eq!(
            first_operation.state,
            o3k_provider::OperationState::Accepted
        );
        let racing_operation = racing.create_instance(request).await.map_err(|error| {
            format!(
                "the racing create must adopt the durable command instead \
                     of failing, got {error:?}"
            )
        })?;
        assert_eq!(
            racing_operation.state,
            o3k_provider::OperationState::Accepted
        );

        let durable = store.list_recoverable_agent_commands().await?;
        assert_eq!(durable.len(), 1, "exactly one durable command row");
        let command_id = durable[0].command_id.clone();
        let delivered = commands
            .recv()
            .await
            .ok_or("the agent stream must carry the command")?;
        assert_eq!(delivered.command_id, command_id);
        let adopted = commands
            .recv()
            .await
            .ok_or("the adopted re-dispatch must carry the same command identity")?;
        assert_eq!(
            adopted.command_id, command_id,
            "every delivered command is the single durable command identity"
        );
        assert!(commands.try_recv().is_err());
        Ok(())
    }

    /// Issue #610 (ASR-021 agent-control-plane-network-interruption): a
    /// control-channel drop followed by the agent's re-registration under a
    /// fresh epoch must not strand the pending create. The durable command
    /// row carries the pre-drop epoch, which the registry now fences; the
    /// re-drive must dispatch a freshly built command (current epoch, fresh
    /// deadline) instead of the recorded payload, so the create converges
    /// exactly once after the interruption.
    #[tokio::test]
    async fn create_redrive_after_agent_re_registration_dispatches_fresh_command()
    -> Result<(), Box<dyn std::error::Error>> {
        let store: Arc<dyn ComputeRepository> = Arc::new(o3k_store::testkit::open_memory().await?);
        let registry = NodeRegistry::default();
        registry
            .register(&register_request("node-a", "epoch-1"))
            .await?;
        let (sender, receiver) = mpsc::channel(32);
        registry
            .attach_connection("node-a", "epoch-1", sender)
            .await?;
        let mut commands = spawn_agent_reader(registry.clone(), receiver);
        let provider = AgentComputeProvider::new_with_store(
            registry.clone(),
            Arc::new(RaceTestResolvedCreateResolver),
            Some(store.clone()),
        )
        .with_artifact_resolver(Arc::new(RaceTestCreateArtifactResolver));
        let operation_id = Uuid::now_v7();
        let server_id = Uuid::now_v7();
        seed_create_durable_rows(store.as_ref(), operation_id, server_id).await?;
        let request = race_create_request(operation_id, server_id);

        // First dispatch lands under the pre-drop epoch; the agent never
        // accepts it (the control channel drops mid-transfer).
        let first = provider
            .create_instance(request.clone())
            .await
            .map_err(|error| format!("the first create dispatch must succeed, got {error:?}"))?;
        assert_eq!(first.state, o3k_provider::OperationState::Accepted);
        let delivered = commands
            .recv()
            .await
            .ok_or("the agent stream must carry the first command")?;
        assert_eq!(delivered.agent_epoch, "epoch-1");
        let recorded_deadline = delivered.deadline_unix_ms;
        let durable = store.list_recoverable_agent_commands().await?;
        assert_eq!(durable.len(), 1);
        assert_eq!(durable[0].state, AgentCommandState::Pending);

        // The control channel drops; the agent re-registers under a fresh
        // epoch with a new connection.
        registry.detach_connection("node-a", "epoch-1").await;
        registry
            .register(&register_request("node-a", "epoch-2"))
            .await?;
        let (sender2, receiver2) = mpsc::channel(32);
        registry
            .attach_connection("node-a", "epoch-2", sender2)
            .await?;
        let mut commands2 = spawn_agent_reader(registry.clone(), receiver2);

        // The create-convergence re-drive must dispatch a FRESH command for
        // the current epoch with a fresh deadline — not the fenced recorded
        // payload (which `dispatch_command` rejects with "agent epoch is
        // fenced", stranding the create forever).
        let redriven = provider.create_instance(request).await.map_err(|error| {
            format!(
                "the create re-drive must dispatch after re-registration, \
                     got {error:?}"
            )
        })?;
        assert_eq!(redriven.state, o3k_provider::OperationState::Accepted);
        let redelivered = commands2
            .recv()
            .await
            .ok_or("the re-registered agent stream must carry the re-dispatched command")?;
        assert_eq!(
            redelivered.command_id, delivered.command_id,
            "the re-dispatch keeps the deterministic command identity"
        );
        assert_eq!(
            redelivered.agent_epoch, "epoch-2",
            "the re-dispatch must carry the current registered epoch"
        );
        assert!(
            redelivered.deadline_unix_ms > recorded_deadline,
            "the re-dispatch must carry a fresh deadline, not the recorded one"
        );
        Ok(())
    }

    /// Issue #611 (ASR-021 agent-control-plane-network-interruption): the
    /// artifact-transfer SEND phase is bounded. A control-channel interruption
    /// can leave the agent's response-stream receiver stalled without being
    /// dropped; the chunk sends then fill the bounded channel and block. The
    /// create-convergence sweep drives transfers from its single sequential
    /// task, so one such stalled send froze the entire sweep for minutes in
    /// the gate runs (the create stayed Running with no re-drive for ~5 min,
    /// and the late re-drive then failed on the never-reoffered artifact).
    /// The drive must fail within the transfer timeout with a retryable
    /// outcome — never hang — and the durable transfer row must stay
    /// resumable for the next re-drive.
    #[tokio::test]
    async fn stalled_artifact_transfer_send_is_bounded_and_retryable()
    -> Result<(), Box<dyn std::error::Error>> {
        let store: Arc<dyn ComputeRepository> = Arc::new(o3k_store::testkit::open_memory().await?);
        let registry = NodeRegistry::default();
        registry
            .register(&register_request("node-a", "epoch-1"))
            .await?;
        // The agent's response-stream receiver stays ALIVE but is never
        // polled, and the channel is smaller than one transfer's message
        // count (offer + chunk + end): the sends fill it and then block
        // forever — the stalled-stream shape the gate runs observed. (A
        // dropped receiver would instead fail the sends immediately.)
        let (sender, _stalled_receiver) = mpsc::channel(2);
        registry
            .attach_connection("node-a", "epoch-1", sender)
            .await?;
        let provider = AgentComputeProvider::new_with_store(
            registry.clone(),
            Arc::new(RaceTestResolvedCreateResolver),
            Some(store.clone()),
        )
        .with_command_timeout(Duration::from_millis(500))
        .with_artifact_resolver(Arc::new(RaceTestCreateArtifactResolver));
        let operation_id = Uuid::now_v7();
        let server_id = Uuid::now_v7();
        seed_create_durable_rows(store.as_ref(), operation_id, server_id).await?;
        let request = race_create_request(operation_id, server_id);

        let outcome =
            tokio::time::timeout(Duration::from_secs(10), provider.create_instance(request)).await;
        match outcome {
            Ok(Err(ProviderError::Retryable)) => {}
            other => {
                return Err(format!(
                    "a stalled artifact-transfer send must fail the drive as a \
                     retryable outcome within the transfer timeout, got {other:?}"
                )
                .into());
            }
        }
        // The interrupted transfer stays durably resumable for the next
        // re-drive (the create-path loop re-offers offered/receiving rows).
        let durable = store.list_recoverable_artifact_transfers().await?;
        assert_eq!(durable.len(), 1, "exactly one durable transfer row");
        assert_eq!(durable[0].state, ArtifactTransferState::Offered);
        Ok(())
    }
    /// lifecycle path, where the durable command insert IS the dispatch
    /// point). Two dispatches for the same operation read "no row" before
    /// either inserts; the loser's insert must adopt the winner's row and
    /// re-dispatch its recorded payload instead of failing with `Conflict`.
    /// The interleaving is driven deterministically with the test-only
    /// insert pause parked between the read and the insert.
    #[tokio::test(flavor = "multi_thread", worker_threads = 3)]
    async fn concurrent_dispatch_recorded_insert_conflict_reuses_existing_command()
    -> Result<(), Box<dyn std::error::Error>> {
        super::DISPATCH_RECORDED_INSERT_PAUSE_MS.store(600, std::sync::atomic::Ordering::Relaxed);
        let result = async {
            let store: Arc<dyn ComputeRepository> =
                Arc::new(o3k_store::testkit::open_memory().await?);
            let registry = NodeRegistry::default();
            registry
                .register(&register_request("node-a", "epoch-1"))
                .await?;
            let (sender, mut receiver) = mpsc::channel(32);
            registry
                .attach_connection("node-a", "epoch-1", sender)
                .await?;
            let provider = AgentComputeProvider::new_with_store(
                registry.clone(),
                Arc::new(RaceTestResolvedCreateResolver),
                Some(store.clone()),
            );
            let operation_id = Uuid::now_v7();
            let server_id = Uuid::now_v7();
            seed_create_durable_rows(store.as_ref(), operation_id, server_id).await?;
            let command = build_lifecycle_command(
                LifecycleCommand::HardReboot,
                "node-a",
                "epoch-1",
                &operation_id.to_string(),
                &server_id.to_string(),
            )?;
            let mut racing_command = command.clone();
            racing_command.deadline_unix_ms += 5_000;

            // The loser reads "no row" first, then parks inside the insert
            // pause; the winner runs to completion while it is parked.
            let racing = provider.clone();
            let parked = tokio::spawn(async move {
                racing.dispatch_recorded(racing_command, operation_id).await
            });
            tokio::time::sleep(Duration::from_millis(150)).await;
            let winner = tokio::spawn({
                let provider = provider.clone();
                let command = command.clone();
                async move { provider.dispatch_recorded(command, operation_id).await }
            });
            let winner_operation = winner.await??.state;
            let parked_operation = parked.await??;
            assert_eq!(winner_operation, o3k_provider::OperationState::Accepted);
            assert_eq!(
                parked_operation.state,
                o3k_provider::OperationState::Accepted
            );

            let durable = store.list_recoverable_agent_commands().await?;
            assert_eq!(durable.len(), 1, "exactly one durable command row");
            let first = receiver
                .recv()
                .await
                .ok_or("the winner must dispatch the command")??;
            let second = receiver
                .recv()
                .await
                .ok_or("the adopter must re-dispatch the same command identity")??;
            let Some(agent_proto::control_response::Body::Command(winner_command)) = first.body
            else {
                return Err("expected a dispatched command".into());
            };
            let Some(agent_proto::control_response::Body::Command(adopted_command)) = second.body
            else {
                return Err("expected a dispatched command".into());
            };
            assert_eq!(adopted_command.command_id, winner_command.command_id);
            assert_eq!(
                adopted_command.deadline_unix_ms, winner_command.deadline_unix_ms,
                "the adopted re-dispatch carries the recorded payload"
            );
            Ok(())
        }
        .await;
        super::DISPATCH_RECORDED_INSERT_PAUSE_MS.store(0, std::sync::atomic::Ordering::Relaxed);
        result
    }

    /// Issue #88 E3 C3 regression: the read-time-existing reuse semantics of
    /// `dispatch_recorded` are unchanged — a pre-existing Pending row is
    /// re-dispatched with its RECORDED payload; Succeeded/Failed rows return
    /// the recorded operation without dispatching.
    #[tokio::test]
    async fn dispatch_recorded_reuse_semantics_are_preserved()
    -> Result<(), Box<dyn std::error::Error>> {
        let store: Arc<dyn ComputeRepository> = Arc::new(o3k_store::testkit::open_memory().await?);
        let registry = NodeRegistry::default();
        registry
            .register(&register_request("node-a", "epoch-1"))
            .await?;
        let (sender, mut receiver) = mpsc::channel(32);
        registry
            .attach_connection("node-a", "epoch-1", sender)
            .await?;
        let provider = AgentComputeProvider::new_with_store(
            registry.clone(),
            Arc::new(RaceTestResolvedCreateResolver),
            Some(store.clone()),
        );
        let operation_id = Uuid::now_v7();
        let server_id = Uuid::now_v7();
        seed_create_durable_rows(store.as_ref(), operation_id, server_id).await?;
        let mut command = build_lifecycle_command(
            LifecycleCommand::HardReboot,
            "node-a",
            "epoch-1",
            &operation_id.to_string(),
            &server_id.to_string(),
        )?;
        // A fresh dispatch attempt that differs from the recorded payload.
        let mut fresh = command.clone();
        fresh.deadline_unix_ms += 5_000;
        // The recorded payload: deadline an hour away, so it can never equal
        // the fresh attempt's.
        command.deadline_unix_ms += 3_600_000;
        let recorded = command.clone();
        store
            .insert_agent_command(&AgentCommandRecord {
                command_id: command.command_id.clone(),
                idempotency_key: command.idempotency_key.clone(),
                operation_id,
                resource_id: server_id,
                agent_id: command.agent_id.clone(),
                agent_epoch: command.agent_epoch.clone(),
                payload_fingerprint_sha256: command.payload_fingerprint_sha256.clone(),
                payload: command.encode_to_vec(),
                state: AgentCommandState::Pending,
                accepted_sequence: 0,
                last_sequence: 0,
                provider_operation_id: Some(operation_id.to_string()),
                provider_resource_id: None,
            })
            .await?;
        let operation = provider
            .dispatch_recorded(fresh.clone(), operation_id)
            .await?;
        assert_eq!(operation.state, o3k_provider::OperationState::Accepted);
        let delivered = receiver
            .recv()
            .await
            .ok_or("the pending row must be re-dispatched")??;
        let Some(agent_proto::control_response::Body::Command(delivered_command)) = delivered.body
        else {
            return Err("expected a dispatched command".into());
        };
        assert_eq!(delivered_command.command_id, recorded.command_id);
        assert_eq!(
            delivered_command.deadline_unix_ms, recorded.deadline_unix_ms,
            "the RECORDED payload is re-dispatched, not the fresh attempt"
        );

        // Terminal rows return the recorded operation without dispatching.
        for (state, durable_state, provider_state) in [
            (
                AgentCommandState::Succeeded,
                o3k_store::OperationState::Succeeded,
                o3k_provider::OperationState::Succeeded,
            ),
            (
                AgentCommandState::Failed,
                o3k_store::OperationState::Failed,
                o3k_provider::OperationState::Failed,
            ),
        ] {
            let terminal_operation_id = Uuid::now_v7();
            let terminal_server_id = Uuid::now_v7();
            seed_create_durable_rows(store.as_ref(), terminal_operation_id, terminal_server_id)
                .await?;
            let terminal_command = build_lifecycle_command(
                LifecycleCommand::HardReboot,
                "node-a",
                "epoch-1",
                &terminal_operation_id.to_string(),
                &terminal_server_id.to_string(),
            )?;
            store
                .insert_agent_command(&AgentCommandRecord {
                    command_id: terminal_command.command_id.clone(),
                    idempotency_key: terminal_command.idempotency_key.clone(),
                    operation_id: terminal_operation_id,
                    resource_id: terminal_server_id,
                    agent_id: terminal_command.agent_id.clone(),
                    agent_epoch: terminal_command.agent_epoch.clone(),
                    payload_fingerprint_sha256: terminal_command.payload_fingerprint_sha256.clone(),
                    payload: terminal_command.encode_to_vec(),
                    state,
                    accepted_sequence: 0,
                    last_sequence: 0,
                    provider_operation_id: Some(terminal_operation_id.to_string()),
                    provider_resource_id: None,
                })
                .await?;
            store
                .update_operation(
                    terminal_operation_id,
                    durable_state,
                    Some(&terminal_operation_id.to_string()),
                    None,
                    None,
                )
                .await?;
            let operation = provider
                .dispatch_recorded(terminal_command, terminal_operation_id)
                .await?;
            assert_eq!(
                operation.state, provider_state,
                "a terminal durable command returns the recorded operation"
            );
            assert!(
                receiver.try_recv().is_err(),
                "a terminal durable command must not dispatch"
            );
        }
        Ok(())
    }

    // ------------------------------------------------------------------
    // Issue #88 S5: the best-effort reap delete for a NEVER-ACCEPTED create.
    // No binding exists (the transfer died mid-receipt or committed before
    // acceptance, then the create terminalized Failed/not_found and the
    // delete completed locally), so `delete_instance` falls back to the
    // durable create command row: resolve the create intent from the
    // resource's desired state, take the create command's agent, and
    // dispatch the Delete with the REGISTRY's current epoch.
    // ------------------------------------------------------------------

    /// Seeds the durable residue of a never-accepted create exactly as the
    /// local-completion shape leaves it: a terminal ERROR resource whose
    /// desired state is the create request, and a Failed create operation
    /// with no provider identity.
    async fn seed_never_accepted_resource(
        store: &dyn ComputeRepository,
        create_request: &CreateInstanceRequest,
    ) -> Result<(), Box<dyn std::error::Error>> {
        store
            .insert_resource(&o3k_store::ResourceRecord {
                id: create_request.o3k_server_id,
                kind: "compute_instance".to_owned(),
                project_id: create_request.project_id.clone(),
                generation: 1,
                observed_generation: 1,
                desired_state: serde_json::to_string(create_request)?,
                observed_state: "ERROR".to_owned(),
                provider_id: None,
            })
            .await?;
        store
            .insert_operation(&o3k_store::OperationRecord {
                id: create_request.operation_id,
                resource_id: create_request.o3k_server_id,
                kind: "compute_create".to_owned(),
                state: o3k_store::OperationState::Failed,
                provider_operation_id: None,
                error_category: Some("not_found".to_owned()),
                error_message: None,
            })
            .await?;
        Ok(())
    }

    /// Seeds the never-accepted create's durable command row (the row whose
    /// agent identity the reap fallback resolves).
    async fn seed_never_accepted_create_command(
        store: &dyn ComputeRepository,
        create_request: &CreateInstanceRequest,
        command: &agent_proto::Command,
    ) -> Result<(), Box<dyn std::error::Error>> {
        store
            .insert_agent_command(&AgentCommandRecord {
                command_id: command.command_id.clone(),
                idempotency_key: command.idempotency_key.clone(),
                operation_id: create_request.operation_id,
                resource_id: create_request.o3k_server_id,
                agent_id: command.agent_id.clone(),
                agent_epoch: command.agent_epoch.clone(),
                payload_fingerprint_sha256: command.payload_fingerprint_sha256.clone(),
                payload: command.encode_to_vec(),
                state: AgentCommandState::Pending,
                accepted_sequence: 0,
                last_sequence: 0,
                provider_operation_id: Some(create_request.operation_id.to_string()),
                provider_resource_id: None,
            })
            .await?;
        Ok(())
    }

    /// Seeds the durable delete operation row the local-completion branch
    /// records before dispatching the best-effort reap (the dispatched
    /// delete command record references it).
    async fn seed_delete_operation(
        store: &dyn ComputeRepository,
        operation_id: Uuid,
        server_id: Uuid,
    ) -> Result<(), Box<dyn std::error::Error>> {
        store
            .insert_operation(&o3k_store::OperationRecord {
                id: operation_id,
                resource_id: server_id,
                kind: "compute_delete".to_owned(),
                state: o3k_store::OperationState::Succeeded,
                provider_operation_id: None,
                error_category: None,
                error_message: None,
            })
            .await?;
        Ok(())
    }

    /// Issue #88 S5 exact shape: no binding exists (the create dispatch was
    /// never accepted), but the durable residue is complete — the terminal
    /// resource with the create intent, the Failed create operation, and the
    /// create command row carrying a STALE agent epoch after the
    /// control-plane restart. `delete_instance` must dispatch a Delete
    /// command carrying the CURRENT registry epoch (the row's epoch is never
    /// trusted) with the request's operation identity, and the durable
    /// delete command row must be recorded for idempotent replay.
    #[tokio::test]
    async fn delete_reaps_never_accepted_create_via_durable_command()
    -> Result<(), Box<dyn std::error::Error>> {
        let store: Arc<dyn ComputeRepository> = Arc::new(o3k_store::testkit::open_memory().await?);
        let registry = NodeRegistry::default();
        registry
            .register(&register_request("node-a", "epoch-1"))
            .await?;
        // The agent re-registered under a fresh per-connection epoch after
        // the control-plane restart; the durable create command row below
        // still carries the pre-restart epoch.
        registry
            .register(&register_request("node-a", "epoch-2"))
            .await?;
        let (sender, mut receiver) = mpsc::channel(32);
        registry
            .attach_connection("node-a", "epoch-2", sender)
            .await?;
        let provider = AgentComputeProvider::new_with_store(
            registry.clone(),
            Arc::new(RaceTestResolvedCreateResolver),
            Some(store.clone()),
        );
        let create_operation_id = Uuid::now_v7();
        let server_id = Uuid::now_v7();
        let create_request = race_create_request(create_operation_id, server_id);
        let create_command = racing_create_command(create_operation_id, server_id)?;
        seed_never_accepted_resource(store.as_ref(), &create_request).await?;
        seed_never_accepted_create_command(store.as_ref(), &create_request, &create_command)
            .await?;
        let delete_operation_id = Uuid::now_v7();
        seed_delete_operation(store.as_ref(), delete_operation_id, server_id).await?;

        let operation = provider
            .delete_instance(DeleteInstanceRequest {
                operation_id: delete_operation_id,
                provider_instance_id: server_id.to_string(),
                idempotency_key: format!("o3k:delete-reap:{server_id}"),
            })
            .await
            .map_err(|error| format!("the never-accepted reap must dispatch, got {error:?}"))?;
        assert_eq!(operation.state, o3k_provider::OperationState::Accepted);
        let delivered = receiver
            .recv()
            .await
            .ok_or("the reap delete must reach the agent")??;
        let Some(agent_proto::control_response::Body::Command(command)) = delivered.body else {
            return Err("expected a dispatched delete command".into());
        };
        assert!(
            matches!(
                command.action,
                Some(agent_proto::command::Action::Delete(_))
            ),
            "the reaped command must be a Delete"
        );
        assert_eq!(command.resource_id, server_id.to_string());
        assert_eq!(
            command.agent_epoch, "epoch-2",
            "the reap dispatches with the CURRENT registry epoch, not the stale row epoch"
        );
        assert_eq!(command.operation_id, delete_operation_id.to_string());
        assert_eq!(
            command.idempotency_key,
            format!("o3k:delete-reap:{server_id}"),
            "the reap command carries the request's reap idempotency key"
        );
        assert!(
            receiver.try_recv().is_err(),
            "the agent stream must carry exactly one command"
        );
        let durable = store
            .get_agent_command_by_operation(delete_operation_id)
            .await?;
        assert_eq!(
            durable.command_id, command.command_id,
            "the durable delete command row is recorded for idempotent replay"
        );
        Ok(())
    }

    /// Issue #88 S5 no-op shapes: the durable fallback must not invent a reap
    /// when the residue evidence is incomplete — a missing resource row, an
    /// unparseable desired state, a missing create command row, or an
    /// unregistered agent all fall through to the existing `NotFound` and
    /// nothing is dispatched (the local completion stays a clean no-op).
    #[tokio::test]
    async fn delete_never_accepted_fallback_noops_without_durable_evidence()
    -> Result<(), Box<dyn std::error::Error>> {
        let store: Arc<dyn ComputeRepository> = Arc::new(o3k_store::testkit::open_memory().await?);
        let registry = NodeRegistry::default();
        registry
            .register(&register_request("node-a", "epoch-1"))
            .await?;
        let (sender, mut receiver) = mpsc::channel(32);
        registry
            .attach_connection("node-a", "epoch-1", sender)
            .await?;
        let provider = AgentComputeProvider::new_with_store(
            registry.clone(),
            Arc::new(RaceTestResolvedCreateResolver),
            Some(store.clone()),
        );
        let delete = |server_id: Uuid, operation_id: Uuid| DeleteInstanceRequest {
            operation_id,
            provider_instance_id: server_id.to_string(),
            idempotency_key: format!("o3k:delete-reap:{server_id}"),
        };

        // Missing resource row.
        let server_id = Uuid::now_v7();
        let result = provider
            .delete_instance(delete(server_id, Uuid::now_v7()))
            .await;
        assert_eq!(result, Err(ProviderError::NotFound));
        assert!(
            receiver.try_recv().is_err(),
            "no dispatch for a missing resource"
        );

        // Unparseable desired state (no create operation identity).
        let server_id = Uuid::now_v7();
        store
            .insert_resource(&o3k_store::ResourceRecord {
                id: server_id,
                kind: "compute_instance".to_owned(),
                project_id: "project-a".to_owned(),
                generation: 1,
                observed_generation: 1,
                desired_state: "{}".to_owned(),
                observed_state: "ERROR".to_owned(),
                provider_id: None,
            })
            .await?;
        let result = provider
            .delete_instance(delete(server_id, Uuid::now_v7()))
            .await;
        assert_eq!(result, Err(ProviderError::NotFound));
        assert!(
            receiver.try_recv().is_err(),
            "no dispatch for an unparseable intent"
        );

        // Missing create command row (resource + create operation exist).
        let server_id = Uuid::now_v7();
        let create_operation_id = Uuid::now_v7();
        let create_request = race_create_request(create_operation_id, server_id);
        seed_never_accepted_resource(store.as_ref(), &create_request).await?;
        let result = provider
            .delete_instance(delete(server_id, Uuid::now_v7()))
            .await;
        assert_eq!(result, Err(ProviderError::NotFound));
        assert!(
            receiver.try_recv().is_err(),
            "no dispatch without a create command row"
        );

        // Unregistered agent (complete residue, but the command row's agent
        // never registered).
        let server_id = Uuid::now_v7();
        let create_operation_id = Uuid::now_v7();
        let create_request = race_create_request(create_operation_id, server_id);
        seed_never_accepted_resource(store.as_ref(), &create_request).await?;
        let mut ghost_command = racing_create_command(create_operation_id, server_id)?;
        ghost_command.agent_id = "ghost".to_owned();
        ghost_command.agent_epoch = "epoch-9".to_owned();
        seed_never_accepted_create_command(store.as_ref(), &create_request, &ghost_command).await?;
        let result = provider
            .delete_instance(delete(server_id, Uuid::now_v7()))
            .await;
        assert_eq!(result, Err(ProviderError::NotFound));
        assert!(
            receiver.try_recv().is_err(),
            "no dispatch for an unregistered agent"
        );
        Ok(())
    }

    /// Issue #88 S5 regression: the durable fallback applies ONLY when no
    /// binding exists. A never-defined binding (stale epoch, no provider
    /// object) still dispatches through the binding path with the registry
    /// epoch — even when a durable create command row owned by a DIFFERENT,
    /// unregistered agent would make the fallback fail.
    #[tokio::test]
    async fn delete_with_binding_takes_precedence_over_durable_fallback()
    -> Result<(), Box<dyn std::error::Error>> {
        let store: Arc<dyn ComputeRepository> = Arc::new(o3k_store::testkit::open_memory().await?);
        let registry = NodeRegistry::default();
        registry
            .register(&register_request("node-a", "epoch-1"))
            .await?;
        registry
            .register(&register_request("node-a", "epoch-2"))
            .await?;
        let (sender, mut receiver) = mpsc::channel(32);
        registry
            .attach_connection("node-a", "epoch-2", sender)
            .await?;
        let provider = AgentComputeProvider::new_with_store(
            registry.clone(),
            Arc::new(RaceTestResolvedCreateResolver),
            Some(store.clone()),
        );
        let server_id = Uuid::now_v7();
        let create_operation_id = Uuid::now_v7();
        // The never-defined binding (create accepted, no provider object).
        seed_create_binding(&provider, server_id, "node-a", "epoch-1").await;
        // The durable resource so rehydration preserves the never-defined
        // binding, plus a fallback-tempting command row owned by an
        // UNREGISTERED agent: the binding path must win.
        let create_request = race_create_request(create_operation_id, server_id);
        seed_never_accepted_resource(store.as_ref(), &create_request).await?;
        let mut ghost_command = racing_create_command(create_operation_id, server_id)?;
        ghost_command.agent_id = "ghost".to_owned();
        ghost_command.agent_epoch = "epoch-9".to_owned();
        seed_never_accepted_create_command(store.as_ref(), &create_request, &ghost_command).await?;
        let delete_operation_id = Uuid::now_v7();
        seed_delete_operation(store.as_ref(), delete_operation_id, server_id).await?;

        let operation = provider
            .delete_instance(DeleteInstanceRequest {
                operation_id: delete_operation_id,
                provider_instance_id: server_id.to_string(),
                idempotency_key: format!("o3k:delete-reap:{server_id}"),
            })
            .await
            .map_err(|error| format!("the binding path must dispatch, got {error:?}"))?;
        assert_eq!(operation.state, o3k_provider::OperationState::Accepted);
        let delivered = receiver
            .recv()
            .await
            .ok_or("the binding path must reach the agent")??;
        let Some(agent_proto::control_response::Body::Command(command)) = delivered.body else {
            return Err("expected a dispatched command".into());
        };
        assert_eq!(command.agent_id, "node-a");
        assert_eq!(command.agent_epoch, "epoch-2");
        Ok(())
    }
}
