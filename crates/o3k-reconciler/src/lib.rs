//! Durable operation journal, evidence fencing, retry budget, and
//! reconciliation state machine.
//!
//! ## Responsibility
//!
//! The reconciler owns the durable reconciliation lifecycle: it persists
//! operation intents, fences evidence, applies bounded retries, and
//! drives provider-observation → compensation transitions through a
//! validated state machine (`reconcile_once`, `reconcile_lifecycle_once`,
//! `observe_lifecycle`, etc.).
//!
//! ## Boundary
//!
//! Compute-domain application logic (server CRUD, keypairs, flavors,
//! agent event subscription, convergence orchestration, binding
//! projection) belongs in `o3k-compute`, not here. The reconciler
//! provides the durable state machine; `o3k-compute` drives it.
//!
//! ## Sub-modules
//!
//! - `types` — reconciler-domain types (events, lifecycle actions, errors)
//! - `storage_workflow` — cross-boundary volume attach/detach coordination
//!
//! See also: `o3k-compute` for the compute application service.
//!
#![allow(unused_imports)]

use std::{
    collections::HashMap,
    sync::{Arc, Mutex},
};

use o3k_domain::ServerState;
use o3k_provider::{
    AgentCommandAccepted, AgentErrorCategory, AgentNodeRegistry, AgentObservation,
    AgentOperationState, AgentOperationUpdate, ComputeProvider, CreateInstanceRequest,
    OperationState as ProviderOperationState, ProviderError,
};
use o3k_store::{
    AgentCommandRecord, AgentCommandState, CanonicalAcceptanceOutcome, CanonicalOperationRecord,
    DurableStore, IdempotencyReservationRequest, ObservationUpdate, OperationRecord,
    OperationState, ProviderReference, ResourceRecord, StoreError, server_state_to_storage,
};
use thiserror::Error;
use uuid::Uuid;

pub mod storage_workflow;

/// Test-only fault pause (issue #87): sleeps the configured duration when the
/// named env var is set. Absent, empty, non-numeric, or zero values are no-ops;
/// production configuration never sets these variables.
fn test_fault_pause_ms(name: &str, env_var: &str) {
    let Some(ms) = test_fault_pause_ms_value(std::env::var(env_var).ok()) else {
        return;
    };
    tracing::info!(pause_ms = ms, "test-only fault pause {} enabled", name);
    std::thread::sleep(std::time::Duration::from_millis(ms));
}

/// Parse/guard half of `test_fault_pause_ms`; split out so the no-op
/// conditions can be unit-tested without sleeping.
fn test_fault_pause_ms_value(raw: Option<String>) -> Option<u64> {
    let raw = raw?;
    let Ok(ms) = raw.parse::<u64>() else {
        return None;
    };
    if ms == 0 {
        return None;
    }
    Some(ms)
}

pub mod types;
pub use crate::types::*;

/// Decodes a storage-encoded compute-instance state into whether the instance
/// consumes instance-seconds.
///
/// This is the single canonical state→consuming mapping shared by the
/// reconciler's metering projections, the compute read-path repair, and the
/// `o3kd` metering adapter (which re-exports it). `Some(true)` means the
/// instance currently holds its runtime (`ACTIVE`/`STARTING`/`STOPPING`/
/// `REBOOTING`); `Some(false)` means it does not (`REQUESTED`/`BUILD`/
/// `SHUTOFF`/`DELETING`/`DELETED`/`ERROR`); `None` means the value is not a
/// decodable canonical state and must never be treated as idle.
#[must_use]
pub fn compute_instance_state_consuming(observed_state: &str) -> Option<bool> {
    match observed_state.trim().to_ascii_uppercase().as_str() {
        "ACTIVE" | "STARTING" | "STOPPING" | "REBOOTING" => Some(true),
        "REQUESTED" | "BUILD" | "SHUTOFF" | "DELETING" | "DELETED" | "ERROR" => Some(false),
        _ => None,
    }
}

// ─── OperationJournal ──────────────────────────────────────
pub struct OperationJournal<S: ?Sized, P: ?Sized> {
    store: Arc<S>,
    provider: Arc<P>,
    max_attempts: u8,
    events: Arc<Mutex<Vec<JournalEvent>>>,
    agent_evidence: Arc<Mutex<HashMap<Uuid, AgentEvidenceFence>>>,
    observation_evidence: Arc<Mutex<HashMap<Uuid, ObservationEvidenceFence>>>,
    /// Optional node registry used to resolve the agent's *current* registered
    /// epoch. When present it is authoritative for evidence fencing: the
    /// fence rejects evidence minted under any other epoch (a dead/stale
    /// stream, including the pre-restart connection) and re-anchors the
    /// operation when the same agent legitimately re-registered under a fresh
    /// epoch. Without a registry the fence keeps the strict first-evidence
    /// anchor of the original behavior.
    agent_registry: Option<Arc<dyn AgentNodeRegistry>>,
    /// Optional metering observer that projects each durably applied resource
    /// lifecycle state into O3K metering authority. Wired by the composition
    /// root; without it the projection is a no-op so direct fake-provider
    /// operation is unchanged.
    metering: Option<Arc<dyn o3k_kernel::LifecycleMeteringObserver>>,
}

impl<S: ?Sized, P: ?Sized> Clone for OperationJournal<S, P> {
    fn clone(&self) -> Self {
        Self {
            store: self.store.clone(),
            provider: self.provider.clone(),
            max_attempts: self.max_attempts,
            events: self.events.clone(),
            agent_evidence: self.agent_evidence.clone(),
            observation_evidence: self.observation_evidence.clone(),
            agent_registry: self.agent_registry.clone(),
            metering: self.metering.clone(),
        }
    }
}

impl<S: ?Sized, P: ?Sized> OperationJournal<S, P>
where
    S: DurableStore + 'static,
    P: ComputeProvider + 'static,
{
    pub fn new(store: Arc<S>, provider: Arc<P>, max_attempts: u8) -> Self {
        Self {
            store,
            provider,
            max_attempts: max_attempts.max(1),
            events: Arc::new(Mutex::new(Vec::new())),
            agent_evidence: Arc::new(Mutex::new(HashMap::new())),
            observation_evidence: Arc::new(Mutex::new(HashMap::new())),
            agent_registry: None,
            metering: None,
        }
    }

    /// Attaches the agent node registry so evidence fencing can distinguish
    /// the agent's current registered epoch from dead epochs of replaced
    /// connections (issue #87 crash-restart replay). Wired by the composition
    /// root; the registry is intentionally optional so direct fake-provider
    /// operation keeps the strict anchored fence.
    #[must_use]
    pub fn with_agent_registry(mut self, registry: Arc<dyn AgentNodeRegistry>) -> Self {
        self.agent_registry = Some(registry);
        self
    }

    /// Attaches the metering observer that projects every durably applied
    /// resource lifecycle state into O3K metering authority. Wired by the
    /// composition root; the observer is intentionally optional so direct
    /// fake-provider operation projects no usage.
    #[must_use]
    pub fn with_metering_observer(
        mut self,
        observer: Arc<dyn o3k_kernel::LifecycleMeteringObserver>,
    ) -> Self {
        self.metering = Some(observer);
        self
    }

    /// Projects a resource lifecycle state into metering authority. No-op
    /// without an observer; a metering failure is surfaced as
    /// [`ReconcileError::Metering`] so the caller decides whether the step is
    /// retriable or best-effort.
    async fn project_metering(
        &self,
        resource: &ResourceRecord,
        observed_state: &str,
    ) -> Result<(), ReconcileError> {
        let Some(observer) = self.metering.as_ref() else {
            return Ok(());
        };
        observer
            .observe_resource_state(
                &resource.kind,
                &resource.project_id,
                &resource.id.to_string(),
                observed_state,
            )
            .await
            .map_err(|error| ReconcileError::Metering(error.to_string()))
    }

    /// Best-effort variant of [`Self::project_metering`]: a failure is logged
    /// and never propagated.
    async fn project_metering_best_effort(&self, resource: &ResourceRecord, observed_state: &str) {
        if let Err(error) = self.project_metering(resource, observed_state).await {
            tracing::warn!(
                resource_id = %resource.id,
                %error,
                "metering projection failed; it is best-effort here and the next observation repairs it"
            );
        }
    }

    /// Repairs a possibly-lost metering projection from durable truth: reads
    /// the resource and best-effort re-projects its current `observed_state`.
    /// The observation is idempotent by state, so re-projecting durable truth
    /// is not a fabrication; a read or projection failure is logged/no-op.
    ///
    /// A repair only ever OPENS or REFRESHES a consuming interval. It never
    /// emits a close: closing is owned by the authoritative transition paths
    /// (delete, provider absence), and a read that closed at the read instant
    /// would under-count a teardown tail and could permanently close an
    /// interval for a resource that later resumes consuming.
    async fn repair_metering_from_durable_state(&self, resource_id: Uuid) {
        let Ok(resource) = self.store.get_resource(resource_id).await else {
            return;
        };
        if compute_instance_state_consuming(&resource.observed_state) != Some(true) {
            return;
        }
        self.project_metering_best_effort(&resource, &resource.observed_state)
            .await;
    }

    async fn fence_agent_evidence(
        &self,
        operation_id: Uuid,
        agent_id: &str,
        agent_epoch: &str,
        sequence: u64,
        state: AgentOperationState,
        provider_resource_id: &str,
    ) -> Result<AgentEvidencePermit, ReconcileError> {
        if agent_id.trim().is_empty()
            || agent_epoch.trim().is_empty()
            || sequence == 0
            || !valid_agent_reference(agent_id)
            || !valid_agent_reference(agent_epoch)
        {
            return Err(ReconcileError::InvalidIntent);
        }
        // The registry is authoritative for the agent's current epoch: every
        // registration replaces the stored epoch (minted per connection), so
        // evidence minted under any other epoch is a dead/stale stream and
        // must not mutate current state. This is what lets a legitimate
        // post-restart replay (the same agent re-registered with a fresh
        // epoch) re-anchor the operation while still rejecting evidence from
        // replaced connections. Fail closed when the agent is not registered:
        // an unregistered agent has no current epoch at all.
        let epoch_lease = if let Some(registry) = &self.agent_registry {
            Some(
                registry
                    .lease_current_epoch(agent_id, agent_epoch)
                    .await
                    .ok_or(ReconcileError::StaleAgentEvidence)?,
            )
        } else {
            None
        };
        let mut evidence = self
            .agent_evidence
            .lock()
            .map_err(|_| ReconcileError::InvalidIntent)?;
        let next = AgentEvidenceFence {
            agent_id: agent_id.to_owned(),
            agent_epoch: agent_epoch.to_owned(),
            sequence,
            state,
            provider_resource_id: provider_resource_id.to_owned(),
        };
        let disposition = match evidence.get(&operation_id) {
            None => {
                evidence.insert(operation_id, next);
                Ok(EvidenceDisposition::New)
            }
            // A different agent cannot claim the operation. An epoch change of
            // the SAME agent is legitimate only when the registry resolved it
            // as current above; without a registry the operation stays
            // anchored to the first evidence epoch.
            Some(previous) if previous.agent_id != agent_id => Err(ReconcileError::InvalidIntent),
            Some(previous)
                if previous.agent_epoch != agent_epoch && self.agent_registry.is_none() =>
            {
                Err(ReconcileError::InvalidIntent)
            }
            Some(previous) if previous.agent_epoch != agent_epoch => {
                evidence.insert(operation_id, next);
                Ok(EvidenceDisposition::New)
            }
            Some(previous) if sequence < previous.sequence => Ok(EvidenceDisposition::Stale),
            Some(previous) if sequence == previous.sequence => {
                if previous.state == state && previous.provider_resource_id == provider_resource_id
                {
                    Ok(EvidenceDisposition::Duplicate)
                } else {
                    Err(ReconcileError::InvalidIntent)
                }
            }
            Some(_) => {
                evidence.insert(operation_id, next);
                Ok(EvidenceDisposition::New)
            }
        }?;
        Ok(AgentEvidencePermit {
            disposition,
            _epoch_lease: epoch_lease,
        })
    }

    /// Observations are terminal evidence for a durable command, not a free
    /// standing state update.  Keep their sequence fence separate from command
    /// acceptance/update sequences: both may legitimately start at one.
    async fn fence_agent_observation(
        &self,
        operation_id: Uuid,
        agent_id: &str,
        agent_epoch: &str,
        sequence: u64,
    ) -> Result<AgentEvidencePermit, ReconcileError> {
        if agent_id.trim().is_empty()
            || agent_epoch.trim().is_empty()
            || sequence == 0
            || !valid_agent_reference(agent_id)
            || !valid_agent_reference(agent_epoch)
        {
            return Err(ReconcileError::InvalidIntent);
        }
        let epoch_lease = if let Some(registry) = &self.agent_registry {
            Some(
                registry
                    .lease_current_epoch(agent_id, agent_epoch)
                    .await
                    .ok_or(ReconcileError::StaleAgentEvidence)?,
            )
        } else {
            None
        };
        let mut evidence = self
            .observation_evidence
            .lock()
            .map_err(|_| ReconcileError::InvalidIntent)?;
        let disposition = match evidence.get(&operation_id) {
            None => {
                evidence.insert(
                    operation_id,
                    ObservationEvidenceFence {
                        agent_id: agent_id.to_owned(),
                        agent_epoch: agent_epoch.to_owned(),
                        sequence,
                    },
                );
                Ok(EvidenceDisposition::New)
            }
            Some(previous) if previous.agent_id != agent_id => Err(ReconcileError::InvalidIntent),
            Some(previous) if previous.agent_epoch != agent_epoch => {
                // A fresh epoch is allowed only when the registry above says
                // it is the current connection for the same durable agent.
                if self.agent_registry.is_none() {
                    return Err(ReconcileError::InvalidIntent);
                }
                evidence.insert(
                    operation_id,
                    ObservationEvidenceFence {
                        agent_id: agent_id.to_owned(),
                        agent_epoch: agent_epoch.to_owned(),
                        sequence,
                    },
                );
                Ok(EvidenceDisposition::New)
            }
            Some(previous) if sequence < previous.sequence => Ok(EvidenceDisposition::Stale),
            Some(_) => Ok(EvidenceDisposition::Duplicate),
        }?;
        Ok(AgentEvidencePermit {
            disposition,
            _epoch_lease: epoch_lease,
        })
    }

    pub fn events(&self) -> Vec<JournalEvent> {
        self.events
            .lock()
            .map(|events| events.clone())
            .unwrap_or_default()
    }

    pub async fn begin_create(
        &self,
        project_id: &str,
        request: &CreateInstanceRequest,
    ) -> Result<Uuid, ReconcileError> {
        let resource = ResourceRecord {
            id: request.o3k_server_id,
            kind: "compute_instance".to_owned(),
            project_id: project_id.to_owned(),
            generation: 1,
            observed_generation: 0,
            desired_state: serde_json::to_string(request)
                .map_err(|_| ReconcileError::InvalidIntent)?,
            observed_state: server_state_to_storage(ServerState::Requested).to_owned(),
            provider_id: None,
        };
        let operation = OperationRecord {
            id: request.operation_id,
            resource_id: request.o3k_server_id,
            kind: "create".to_owned(),
            state: OperationState::Pending,
            provider_operation_id: None,
            error_category: None,
            error_message: None,
        };
        self.store
            .insert_resource_and_operation(
                &resource,
                &operation,
                request.placement_allocation_id.as_deref(),
            )
            .await?;
        self.event(
            request.operation_id,
            request.o3k_server_id,
            JournalEventKind::IntentPersisted,
        );
        Ok(operation.id)
    }

    pub async fn begin_canonical_create(
        &self,
        project_id: &str,
        request: &CreateInstanceRequest,
        context: &CanonicalMutationContext,
    ) -> Result<CanonicalAcceptanceOutcome, ReconcileError> {
        let resource = ResourceRecord {
            id: request.o3k_server_id,
            kind: "compute_instance".to_owned(),
            project_id: project_id.to_owned(),
            generation: 1,
            observed_generation: 0,
            desired_state: serde_json::to_string(request)
                .map_err(|_| ReconcileError::InvalidIntent)?,
            observed_state: server_state_to_storage(ServerState::Requested).to_owned(),
            provider_id: None,
        };
        let operation = OperationRecord {
            id: request.operation_id,
            resource_id: request.o3k_server_id,
            kind: "create".to_owned(),
            state: OperationState::Pending,
            provider_operation_id: None,
            error_category: None,
            error_message: None,
        };
        let resource_type = o3k_kernel::ResourceType::new("compute", "server")
            .map_err(|_| ReconcileError::InvalidIntent)?;
        let (canonical, reservation) = context.records(&operation, resource_type, None)?;
        let outcome = self
            .store
            .create_or_replay_canonical_resource_operation(
                &resource,
                &operation,
                &canonical,
                &reservation,
                request.placement_allocation_id.as_deref(),
            )
            .await?;
        if matches!(outcome, CanonicalAcceptanceOutcome::Created { .. }) {
            self.event(
                request.operation_id,
                request.o3k_server_id,
                JournalEventKind::IntentPersisted,
            );
        }
        Ok(outcome)
    }

    pub async fn begin_lifecycle(
        &self,
        resource_id: Uuid,
        operation_id: Uuid,
        action: LifecycleAction,
    ) -> Result<Uuid, ReconcileError> {
        self.store
            .insert_operation(&OperationRecord {
                id: operation_id,
                resource_id,
                kind: action.kind().to_owned(),
                state: OperationState::Pending,
                provider_operation_id: None,
                error_category: None,
                error_message: None,
            })
            .await?;
        self.event(operation_id, resource_id, JournalEventKind::IntentPersisted);
        Ok(operation_id)
    }

    pub async fn begin_canonical_lifecycle(
        &self,
        resource_id: Uuid,
        operation_id: Uuid,
        action: LifecycleAction,
        context: &CanonicalMutationContext,
    ) -> Result<CanonicalAcceptanceOutcome, ReconcileError> {
        let operation = OperationRecord {
            id: operation_id,
            resource_id,
            kind: action.kind().to_owned(),
            state: OperationState::Pending,
            provider_operation_id: None,
            error_category: None,
            error_message: None,
        };
        let resource_type = o3k_kernel::ResourceType::new("compute", "server")
            .map_err(|_| ReconcileError::InvalidIntent)?;
        let target = resource_id.to_string();
        let (canonical, reservation) = context.records(&operation, resource_type, Some(&target))?;
        let outcome = self
            .store
            .create_or_replay_canonical_lifecycle_operation(&operation, &canonical, &reservation)
            .await?;
        if matches!(outcome, CanonicalAcceptanceOutcome::Created { .. }) {
            self.event(operation_id, resource_id, JournalEventKind::IntentPersisted);
        }
        Ok(outcome)
    }

    /// Applies an authenticated compute-agent update to the same durable records
    /// used by the provider reconciliation loop. The agent is responsible for
    /// redacting secrets and connection information before sending a failure
    /// reason; the control plane persists it only after bounding and
    /// sanitizing (bounded_agent_failure_message), so durable records and
    /// operator logs stay free of control characters and unbounded payloads.
    pub async fn apply_agent_update(
        &self,
        update: &AgentOperationUpdate,
    ) -> Result<OperationState, ReconcileError> {
        let operation = self.store.get_operation(update.operation_id).await?;
        if operation.resource_id != update.resource_id {
            return Err(ReconcileError::InvalidIntent);
        }
        let command = self
            .store
            .get_agent_command_by_operation(update.operation_id)
            .await
            .map_err(|_| ReconcileError::InvalidIntent)?;
        if command.agent_id != update.agent_id || command.resource_id != update.resource_id {
            return Err(ReconcileError::InvalidIntent);
        }
        let (command_state, durable_state) = match update.state {
            AgentOperationState::Accepted => (AgentCommandState::Accepted, OperationState::Running),
            AgentOperationState::Running => (AgentCommandState::Running, OperationState::Running),
            AgentOperationState::Succeeded => {
                (AgentCommandState::Succeeded, OperationState::Succeeded)
            }
            AgentOperationState::Failed => (AgentCommandState::Failed, OperationState::Failed),
            AgentOperationState::UnknownOutcome => (
                AgentCommandState::UnknownOutcome,
                OperationState::UnknownOutcome,
            ),
        };
        if operation.state == OperationState::UnknownOutcome
            && matches!(durable_state, OperationState::Running)
            || command.state == AgentCommandState::UnknownOutcome
                && matches!(
                    command_state,
                    AgentCommandState::Accepted | AgentCommandState::Running
                )
        {
            return Err(ReconcileError::InvalidIntent);
        }
        let error_category = if durable_state == OperationState::Failed {
            Some(agent_error_category(update.error_category)?)
        } else {
            None
        };
        let error_message = (durable_state == OperationState::Failed).then(|| {
            bounded_agent_failure_message(update.redacted_message.as_deref().unwrap_or(""))
        });
        if matches!(
            operation.state,
            OperationState::Succeeded | OperationState::Failed
        ) && operation.state != durable_state
        {
            return Err(ReconcileError::InvalidIntent);
        }
        self.validate_agent_provider_identity(&command, update)
            .await?;
        let evidence_permit = self
            .fence_agent_evidence(
                update.operation_id,
                &update.agent_id,
                &update.agent_epoch,
                update.operation_sequence,
                update.state,
                update.provider_resource_id.as_deref().unwrap_or(""),
            )
            .await?;
        if evidence_permit.disposition == EvidenceDisposition::Stale {
            return Ok(operation.state);
        }
        // Persist the agent-reported, contract-redacted failure reason so the
        // durable record carries an actionable cause; it is bounded and
        // sanitized before storage. Unknown-outcome and non-failure updates
        // keep no message.
        // The epoch-fenced journal is the authoritative durable command
        // projector (the provider adapter keeps only a current-epoch,
        // identity-checked backup for broadcast lag).
        // A terminal observation can win the event-consumer race and close
        // the operation before this update arrives, but this write must still
        // close the matching command row (ASR-015 E1 -> E2 crash recovery).
        self.store
            .update_agent_command(
                &command.command_id,
                command_state,
                command.accepted_sequence,
                update.operation_sequence,
                command.provider_operation_id.as_deref(),
                update.provider_resource_id.as_deref(),
            )
            .await?;
        if matches!(
            operation.state,
            OperationState::Succeeded | OperationState::Failed
        ) {
            return Ok(operation.state);
        }
        // A terminally failed create must not leave the resource in its
        // pre-creation state: clients polling the server would otherwise wait
        // forever. Its metering observation is projected here, before the
        // operation terminalizes below, so a failed or crashed projection
        // leaves the step retriable instead of losing the observation.
        let failed_create_resource =
            if durable_state == OperationState::Failed && operation.kind == "create" {
                let resource = self.store.get_resource(update.resource_id).await?;
                self.project_metering(&resource, server_state_to_storage(ServerState::Error))
                    .await?;
                Some(resource)
            } else {
                None
            };

        let provider_operation_id = operation.provider_operation_id.as_deref();
        self.store
            .update_operation(
                update.operation_id,
                durable_state,
                provider_operation_id,
                error_category,
                error_message.as_deref(),
            )
            .await?;

        if let Some(resource) = failed_create_resource {
            // Projecting ERROR keeps the failure durable and visible while
            // observations remain the only success projection.
            self.store
                .update_resource(
                    update.resource_id,
                    resource.generation,
                    &resource.desired_state,
                    server_state_to_storage(ServerState::Error),
                    resource.generation,
                    resource.provider_id.as_deref(),
                )
                .await?;
        }

        if durable_state == OperationState::Succeeded {
            let resource = self.store.get_resource(update.resource_id).await?;
            let provider_id = update
                .provider_resource_id
                .as_deref()
                .or(resource.provider_id.as_deref());
            if let Some(provider_resource_id) = provider_id {
                match self
                    .store
                    .get_provider_reference(update.resource_id, "compute-agent")
                    .await
                {
                    Ok(existing) if existing.provider_resource_id == provider_resource_id => {}
                    Ok(_) => return Err(StoreError::ProviderReferenceAlreadyExists.into()),
                    Err(StoreError::ProviderReferenceNotFound) => {
                        self.store
                            .attach_provider_reference(&ProviderReference {
                                resource_id: update.resource_id,
                                provider_name: "compute-agent".to_owned(),
                                provider_resource_id: provider_resource_id.to_owned(),
                            })
                            .await?;
                    }
                    Err(error) => return Err(error.into()),
                }
            }
            self.store
                .update_resource(
                    update.resource_id,
                    resource.generation,
                    &resource.desired_state,
                    &resource.observed_state,
                    resource.generation,
                    provider_id,
                )
                .await?;
        }
        if evidence_permit.disposition == EvidenceDisposition::New {
            self.event(
                update.operation_id,
                update.resource_id,
                match durable_state {
                    OperationState::Succeeded => JournalEventKind::Succeeded,
                    OperationState::Failed => JournalEventKind::Failed,
                    OperationState::UnknownOutcome => JournalEventKind::UnknownObserved,
                    _ => JournalEventKind::ProviderStarted,
                },
            );
        }
        Ok(durable_state)
    }

    async fn validate_agent_provider_identity(
        &self,
        command: &AgentCommandRecord,
        update: &AgentOperationUpdate,
    ) -> Result<(), ReconcileError> {
        let Some(incoming) = update.provider_resource_id.as_deref() else {
            return Ok(());
        };
        if command
            .provider_resource_id
            .as_deref()
            .is_some_and(|existing| existing != incoming)
        {
            return Err(ReconcileError::InvalidIntent);
        }
        let resource = self.store.get_resource(update.resource_id).await?;
        if resource
            .provider_id
            .as_deref()
            .is_some_and(|existing| existing != incoming)
        {
            return Err(ReconcileError::InvalidIntent);
        }
        for provider_name in ["compute-agent", "agent"] {
            match self
                .store
                .get_provider_reference(update.resource_id, provider_name)
                .await
            {
                Ok(reference) if reference.provider_resource_id != incoming => {
                    return Err(ReconcileError::InvalidIntent);
                }
                Ok(_) | Err(StoreError::ProviderReferenceNotFound) => {}
                Err(error) => return Err(error.into()),
            }
        }
        Ok(())
    }

    /// Commits an authenticated command acceptance before the agent executes
    /// the command. Duplicate acceptances are idempotent because the durable
    /// operation is simply kept in `running` state.
    pub async fn apply_agent_acceptance(
        &self,
        accepted: &AgentCommandAccepted,
    ) -> Result<OperationState, ReconcileError> {
        let operation = self.store.get_operation(accepted.operation_id).await?;
        let command = self
            .store
            .get_agent_command(&accepted.command_id)
            .await
            .map_err(|_| ReconcileError::InvalidIntent)?;
        if command.operation_id != accepted.operation_id || command.agent_id != accepted.agent_id {
            return Err(ReconcileError::InvalidIntent);
        }
        match accepted.state {
            AgentOperationState::Accepted | AgentOperationState::Running => {}
            _ => return Err(ReconcileError::InvalidIntent),
        }
        if operation.state == OperationState::UnknownOutcome
            || command.state == AgentCommandState::UnknownOutcome
        {
            return Err(ReconcileError::InvalidIntent);
        }
        let evidence_permit = self
            .fence_agent_evidence(
                accepted.operation_id,
                &accepted.agent_id,
                &accepted.agent_epoch,
                accepted.operation_sequence,
                accepted.state,
                "",
            )
            .await?;
        if evidence_permit.disposition == EvidenceDisposition::Stale {
            return Ok(operation.state);
        }
        if matches!(
            operation.state,
            OperationState::Succeeded | OperationState::Failed
        ) {
            return Ok(operation.state);
        }
        self.store
            .update_agent_command(
                &command.command_id,
                AgentCommandState::Accepted,
                accepted.operation_sequence,
                accepted.operation_sequence,
                command.provider_operation_id.as_deref(),
                command.provider_resource_id.as_deref(),
            )
            .await?;
        self.store
            .update_operation(
                accepted.operation_id,
                OperationState::Running,
                operation.provider_operation_id.as_deref(),
                operation.error_category.as_deref(),
                operation.error_message.as_deref(),
            )
            .await?;
        if evidence_permit.disposition == EvidenceDisposition::New {
            self.event(
                accepted.operation_id,
                operation.resource_id,
                JournalEventKind::ProviderStarted,
            );
        }
        Ok(OperationState::Running)
    }

    /// Applies the provider state carried by an authenticated agent
    /// observation. Operation updates describe command progress; observations
    /// are the only live input that may change the durable resource state.
    /// Unspecified or non-successful observations are rejected so an incomplete
    /// message cannot make Nova project a healthy state.
    pub async fn apply_agent_observation(
        &self,
        observation: &AgentObservation,
    ) -> Result<(), ReconcileError> {
        let operation = self.store.get_operation(observation.operation_id).await?;
        if operation.resource_id != observation.resource_id {
            tracing::debug!(
                operation_id=%observation.operation_id,
                operation_resource_id=%operation.resource_id,
                observation_resource_id=%observation.resource_id,
                "apply_agent_observation: resource_id mismatch"
            );
            return Err(ReconcileError::InvalidIntent);
        }
        // The operation row alone is not an authorization grant: bind the
        // observation to the durable command that was assigned to this agent
        // and resource.  This prevents any authenticated agent from claiming
        // a successful observation for another agent's operation.
        let command = self
            .store
            .get_agent_command_by_operation(observation.operation_id)
            .await
            .map_err(|_| ReconcileError::InvalidIntent)?;
        if command.agent_id != observation.agent_id
            || command.resource_id != observation.resource_id
        {
            return Err(ReconcileError::InvalidIntent);
        }
        if observation.operation_state != AgentOperationState::Succeeded {
            tracing::debug!(
                operation_id=%observation.operation_id,
                operation_state=?observation.operation_state,
                "apply_agent_observation: operation_state is not Succeeded"
            );
            return Err(ReconcileError::InvalidIntent);
        }
        let evidence_permit = self
            .fence_agent_observation(
                observation.operation_id,
                &observation.agent_id,
                &observation.agent_epoch,
                observation.observation_sequence,
            )
            .await?;
        if evidence_permit.disposition != EvidenceDisposition::New {
            // A re-delivered (duplicate) or out-of-order (stale) observation is
            // a repair opportunity: re-project the durable observed_state so a
            // projection lost after an earlier CAS is healed. The projection is
            // durable-state-derived and idempotent by state, so this never
            // fabricates or double-counts.
            self.repair_metering_from_durable_state(observation.resource_id)
                .await;
            return Ok(());
        }
        let observed_state = server_state_to_storage(ServerState::from(observation.state));
        let resource = self.store.get_resource(observation.resource_id).await?;
        let provider_id = observation
            .provider_resource_id
            .as_deref()
            .or(resource.provider_id.as_deref());
        tracing::debug!(
            operation_id=%observation.operation_id,
            resource_id=%observation.resource_id,
            operation_state=?operation.state,
            resource_generation=resource.generation,
            provider_id=?provider_id,
            observed_state=%observed_state,
            agent_epoch=%observation.agent_epoch,
            observation_sequence=observation.observation_sequence,
            "apply_agent_observation: processing observation"
        );
        if let Some(provider_resource_id) = provider_id {
            match self
                .store
                .get_provider_reference(observation.resource_id, "compute-agent")
                .await
            {
                Ok(existing) if existing.provider_resource_id == provider_resource_id => {
                    tracing::debug!(resource_id=%observation.resource_id, provider_resource_id, "apply_agent_observation: provider reference already matches");
                }
                Ok(existing) => {
                    tracing::debug!(
                        resource_id=%observation.resource_id,
                        existing_provider_resource_id=%existing.provider_resource_id,
                        new_provider_resource_id=provider_resource_id,
                        "apply_agent_observation: provider reference conflict"
                    );
                    return Err(StoreError::ProviderReferenceAlreadyExists.into());
                }
                Err(StoreError::ProviderReferenceNotFound) => {
                    tracing::debug!(resource_id=%observation.resource_id, provider_resource_id, "apply_agent_observation: attaching new provider reference");
                    self.store
                        .attach_provider_reference(&ProviderReference {
                            resource_id: observation.resource_id,
                            provider_name: "compute-agent".to_owned(),
                            provider_resource_id: provider_resource_id.to_owned(),
                        })
                        .await?;
                }
                Err(error) => {
                    tracing::debug!(error=%error, resource_id=%observation.resource_id, "apply_agent_observation: get_provider_reference failed");
                    return Err(error.into());
                }
            }
        }
        let update = ObservationUpdate {
            expected_generation: resource.generation,
            desired_state: &resource.desired_state,
            observed_state,
            observed_generation: resource.generation,
            provider_id,
            agent_epoch: &observation.agent_epoch,
            observation_sequence: observation.observation_sequence,
        };
        let updated = self
            .store
            .update_resource_from_observation(observation.resource_id, &update)
            .await
            .map_err(|e| {
                tracing::debug!(
                    error=%e,
                    resource_id=%observation.resource_id,
                    expected_generation=resource.generation,
                    observed_state=%observed_state,
                    agent_epoch=%observation.agent_epoch,
                    observation_sequence=observation.observation_sequence,
                    "apply_agent_observation: update_resource_from_observation failed"
                );
                e
            })?;
        // Project the state the CAS actually applied. This is best-effort: an
        // agent observation must not be rejected because metering is unhappy.
        // The projection is durable-state-derived and idempotent by state, so a
        // lost projection is repaired when the agent re-delivers the observation
        // (the fence's non-New short-circuit re-projects the durable state).
        self.project_metering_best_effort(&updated, &updated.observed_state)
            .await;
        tracing::debug!(
            operation_id=%observation.operation_id,
            resource_id=%observation.resource_id,
            old_generation=resource.generation,
            new_generation=updated.generation,
            "apply_agent_observation: resource updated from observation"
        );
        // Observations for inspect commands carry the terminal operation state
        // but do not emit a separate OperationUpdate. Promote the operation to
        // Succeeded so that idempotent re-inspect returns the durable result.
        if !matches!(
            operation.state,
            OperationState::Succeeded | OperationState::Failed
        ) {
            self.store
                .update_operation(
                    observation.operation_id,
                    OperationState::Succeeded,
                    operation.provider_operation_id.as_deref(),
                    None,
                    None,
                )
                .await?;
            tracing::debug!(operation_id=%observation.operation_id, "apply_agent_observation: promoted operation to Succeeded");
        }
        if updated.generation == resource.generation {
            tracing::debug!(operation_id=%observation.operation_id, resource_id=%observation.resource_id, "apply_agent_observation: generation unchanged, observation was duplicate");
            return Ok(());
        }
        self.event(
            observation.operation_id,
            observation.resource_id,
            JournalEventKind::UnknownObserved,
        );
        Ok(())
    }

    pub async fn reconcile_lifecycle_once(
        &self,
        operation_id: Uuid,
    ) -> Result<OperationState, ReconcileError> {
        let operation = self.store.get_operation(operation_id).await?;
        if matches!(
            operation.state,
            OperationState::Succeeded | OperationState::Failed
        ) {
            return Ok(operation.state);
        }
        let action =
            LifecycleAction::parse(&operation.kind).ok_or(ReconcileError::InvalidIntent)?;
        let resource = self.store.get_resource(operation.resource_id).await?;
        if operation.state == OperationState::UnknownOutcome {
            if operation.provider_operation_id.is_none() {
                // Issue #609: the retry budget exhausted before any provider
                // operation identity existed (every dispatch was rejected as
                // retryable), so there is no provider operation to poll.
                // Presence decides; a reconnected agent's terminal update can
                // also still arrive through the event stream.
                return self
                    .observe_lifecycle_presence(operation, resource, action)
                    .await;
            }
            return self.observe_lifecycle(operation, resource, action).await;
        }
        let provider_id = resource
            .provider_id
            .clone()
            .ok_or(ReconcileError::InvalidIntent)?;
        self.store
            .update_operation(
                operation_id,
                OperationState::Running,
                operation.provider_operation_id.as_deref(),
                None,
                None,
            )
            .await?;
        self.event(operation_id, resource.id, JournalEventKind::ProviderStarted);
        let result = match action {
            LifecycleAction::Delete => {
                self.provider
                    .delete_instance(o3k_provider::DeleteInstanceRequest {
                        operation_id,
                        provider_instance_id: provider_id.clone(),
                        idempotency_key: format!("o3k-operation-{operation_id}"),
                    })
                    .await
            }
            LifecycleAction::Start | LifecycleAction::Stop | LifecycleAction::Reboot => {
                self.provider
                    .action_instance(
                        &provider_id,
                        match action {
                            LifecycleAction::Start => o3k_provider::InstanceAction::Start,
                            LifecycleAction::Stop => o3k_provider::InstanceAction::Stop,
                            LifecycleAction::Reboot => o3k_provider::InstanceAction::Reboot,
                            LifecycleAction::Delete => unreachable!(),
                        },
                        operation_id,
                        &format!("o3k-operation-{operation_id}"),
                    )
                    .await
            }
        };
        self.handle_lifecycle_result(operation, resource, action, provider_id, result)
            .await
    }

    async fn observe_lifecycle(
        &self,
        operation: OperationRecord,
        resource: ResourceRecord,
        action: LifecycleAction,
    ) -> Result<OperationState, ReconcileError> {
        let Some(provider_operation_id) = operation.provider_operation_id.as_deref() else {
            return Err(ReconcileError::InvalidIntent);
        };
        let provider_id = resource
            .provider_id
            .clone()
            .ok_or(ReconcileError::InvalidIntent)?;
        let presence = self.provider.get_instance(&provider_id).await;
        let instance_present = presence.is_ok();
        if action == LifecycleAction::Delete && matches!(presence, Err(ProviderError::NotFound)) {
            return self
                .finish_lifecycle(
                    operation.id,
                    resource,
                    action,
                    provider_operation_id.to_owned(),
                    provider_id,
                )
                .await;
        }
        let provider_operation = self
            .provider
            .get_operation(
                Uuid::parse_str(provider_operation_id)
                    .map_err(|_| ReconcileError::InvalidIntent)?,
            )
            .await?;
        validate_lifecycle_provider_operation_owner(operation.id, action, &provider_operation)?;
        match provider_operation.state {
            ProviderOperationState::Succeeded => {
                self.finish_lifecycle(
                    operation.id,
                    resource,
                    action,
                    provider_operation_id.to_owned(),
                    provider_id,
                )
                .await
            }
            ProviderOperationState::UnknownOutcome => {
                self.event(operation.id, resource.id, JournalEventKind::UnknownObserved);
                if action != LifecycleAction::Delete {
                    let instance = self.provider.get_instance(&provider_id).await?;
                    let converged = match action {
                        LifecycleAction::Start | LifecycleAction::Reboot => {
                            instance.state == o3k_provider::InstanceState::Running
                        }
                        LifecycleAction::Stop => {
                            instance.state == o3k_provider::InstanceState::Stopped
                        }
                        LifecycleAction::Delete => false,
                    };
                    if converged {
                        return self
                            .finish_lifecycle(
                                operation.id,
                                resource,
                                action,
                                provider_operation_id.to_owned(),
                                provider_id,
                            )
                            .await;
                    }
                } else if instance_present {
                    // #575: the delete command's outcome is unknown and the
                    // instance is still present, so the delete goal is NOT
                    // converged. The recorded command cannot make progress
                    // again (the agent journal replays the recorded unknown
                    // outcome instead of re-executing), so reconciliation
                    // mints one deterministic fresh command identity.
                    return self.redrive_delete(operation, resource, provider_id).await;
                }
                Ok(OperationState::UnknownOutcome)
            }
            ProviderOperationState::Retryable => {
                self.retry_or_fail(operation.id, resource.id, ProviderError::Retryable)
                    .await
            }
            ProviderOperationState::Accepted | ProviderOperationState::Running
                if action == LifecycleAction::Delete && instance_present =>
            {
                // The old accepted command may have been lost after the
                // host mutation began (#575).  Reusing its provider command
                // identity can keep the operation permanently Accepted.
                // Mint one deterministic command identity tied to the
                // durable lifecycle operation, so retries are idempotent and
                // old-stream evidence cannot complete the new command.
                self.redrive_delete(operation, resource, provider_id).await
            }
            ProviderOperationState::Accepted | ProviderOperationState::Running => {
                self.store
                    .update_operation(
                        operation.id,
                        OperationState::Running,
                        Some(provider_operation_id),
                        None,
                        None,
                    )
                    .await?;
                Ok(OperationState::Running)
            }
            ProviderOperationState::Failed => {
                self.store
                    .update_operation(
                        operation.id,
                        OperationState::Failed,
                        Some(provider_operation_id),
                        Some("terminal"),
                        Some("provider operation failed"),
                    )
                    .await?;
                self.event(operation.id, resource.id, JournalEventKind::Failed);
                Ok(OperationState::Failed)
            }
        }
    }

    /// Issue #609: observes the instance at the execution boundary for a
    /// lifecycle operation whose retry budget exhausted before any provider
    /// operation identity existed. There is no provider operation to poll,
    /// so presence decides exactly like `observe_lifecycle`'s unknown-outcome
    /// arm: a delete is converged when the instance is provably absent, a
    /// still-present delete re-drives with the #575 fresh command identity,
    /// and a start/stop/reboot converges when the instance state matches.
    /// Everything else stays `UnknownOutcome` — a reconnected agent's
    /// terminal update still arrives through the event stream, and the
    /// lifecycle convergence sweep re-drives the operation each pass.
    async fn observe_lifecycle_presence(
        &self,
        operation: OperationRecord,
        resource: ResourceRecord,
        action: LifecycleAction,
    ) -> Result<OperationState, ReconcileError> {
        let provider_id = resource
            .provider_id
            .clone()
            .ok_or(ReconcileError::InvalidIntent)?;
        let presence = self.provider.get_instance(&provider_id).await;
        if action == LifecycleAction::Delete {
            return match presence {
                Err(ProviderError::NotFound) => {
                    self.finish_lifecycle(
                        operation.id,
                        resource,
                        action,
                        operation.id.to_string(),
                        provider_id,
                    )
                    .await
                }
                Ok(_) => self.redrive_delete(operation, resource, provider_id).await,
                Err(_) => Ok(OperationState::UnknownOutcome),
            };
        }
        let converged = match presence {
            Ok(instance) => match action {
                LifecycleAction::Start | LifecycleAction::Reboot => {
                    instance.state == o3k_provider::InstanceState::Running
                }
                LifecycleAction::Stop => instance.state == o3k_provider::InstanceState::Stopped,
                LifecycleAction::Delete => false,
            },
            Err(_) => false,
        };
        if converged {
            return self
                .finish_lifecycle(
                    operation.id,
                    resource,
                    action,
                    operation.id.to_string(),
                    provider_id,
                )
                .await;
        }
        Ok(OperationState::UnknownOutcome)
    }

    /// #575 stale-accepted delete re-drive: mints ONE deterministic fresh
    /// command identity tied to the durable lifecycle operation and
    /// dispatches the delete again. The recorded command cannot make
    /// progress (its observation was rejected and the agent journal replays
    /// the recorded outcome instead of re-executing), and the instance is
    /// still present, so the delete goal is not converged. Re-drives are
    /// idempotent: repeated passes re-dispatch the SAME command identity,
    /// which the agent journal reuses without a second execution, and
    /// old-stream evidence cannot complete the fresh command. The dispatch
    /// result is handled by `handle_lifecycle_result`, which keeps a
    /// re-drive that is merely accepted in `UnknownOutcome` so the lifecycle
    /// sweep keeps observing the fresh provider operation to terminal.
    async fn redrive_delete(
        &self,
        operation: OperationRecord,
        resource: ResourceRecord,
        provider_id: String,
    ) -> Result<OperationState, ReconcileError> {
        let redrive_operation_id = delete_redrive_operation_id(operation.id);
        // The fresh command identity must have a durable operation row
        // BEFORE the provider persists its command record: the agent-command
        // ledger references `operations(id)`, the evidence consumers resolve
        // by operation id, and the lifecycle sweep lists lifecycle rows.
        // Without the row the command insert fails the foreign key, the
        // dispatch returns Conflict, and the delete op terminalizes Failed
        // while the instance is still present (real-host finding, run
        // local-5752). Mirrors the presence-inspection pattern of persisting
        // the operation intent before dispatch.
        match self
            .store
            .insert_operation(&OperationRecord {
                id: redrive_operation_id,
                resource_id: operation.resource_id,
                kind: "lifecycle:delete".to_owned(),
                state: OperationState::Pending,
                provider_operation_id: None,
                error_category: None,
                error_message: None,
            })
            .await
        {
            Ok(_) | Err(StoreError::ResourceAlreadyExists) => {}
            Err(error) => return Err(error.into()),
        }
        let result = self
            .provider
            .delete_instance(o3k_provider::DeleteInstanceRequest {
                operation_id: redrive_operation_id,
                provider_instance_id: provider_id.clone(),
                idempotency_key: format!("o3k-operation-{}-redrive", operation.id),
            })
            .await;
        self.handle_lifecycle_result(
            operation,
            resource,
            LifecycleAction::Delete,
            provider_id,
            result,
        )
        .await
    }

    async fn handle_lifecycle_result(
        &self,
        operation: OperationRecord,
        resource: ResourceRecord,
        action: LifecycleAction,
        provider_id: String,
        result: Result<o3k_provider::Operation, ProviderError>,
    ) -> Result<OperationState, ReconcileError> {
        match result {
            Ok(provider_operation) => {
                validate_lifecycle_provider_operation_owner(
                    operation.id,
                    action,
                    &provider_operation,
                )?;
                match provider_operation.state {
                    ProviderOperationState::Succeeded => {
                        self.finish_lifecycle(
                            operation.id,
                            resource,
                            action,
                            provider_operation.provider_operation_id.to_string(),
                            provider_id,
                        )
                        .await
                    }
                    ProviderOperationState::Accepted | ProviderOperationState::Running => {
                        let redrive = action == LifecycleAction::Delete
                            && provider_operation.o3k_operation_id
                                == delete_redrive_operation_id(operation.id);
                        if redrive {
                            // The fresh re-drive command is in flight on the
                            // agent; its terminal evidence cannot arrive
                            // through the operation event stream (no durable
                            // operation row carries the redrive identity, so
                            // every agent evidence consumer rejects it by
                            // design). The durable operation therefore stays
                            // `UnknownOutcome` with the redrive provider
                            // identity so the lifecycle sweep keeps polling
                            // the fresh provider operation until it reaches
                            // terminal (issue #575).
                            self.store
                                .update_operation(
                                    operation.id,
                                    OperationState::UnknownOutcome,
                                    Some(&provider_operation.provider_operation_id.to_string()),
                                    Some("unknown_outcome"),
                                    None,
                                )
                                .await?;
                            self.event(operation.id, resource.id, JournalEventKind::RetryScheduled);
                            return Ok(OperationState::UnknownOutcome);
                        }
                        self.store
                            .update_operation(
                                operation.id,
                                OperationState::Running,
                                Some(&provider_operation.provider_operation_id.to_string()),
                                None,
                                None,
                            )
                            .await?;
                        Ok(OperationState::Running)
                    }
                    ProviderOperationState::UnknownOutcome => {
                        let provider_operation_id =
                            provider_operation.provider_operation_id.to_string();
                        self.store
                            .update_operation(
                                operation.id,
                                OperationState::UnknownOutcome,
                                Some(&provider_operation_id),
                                Some("unknown_outcome"),
                                None,
                            )
                            .await?;
                        self.event(operation.id, resource.id, JournalEventKind::RetryScheduled);
                        Ok(OperationState::UnknownOutcome)
                    }
                    ProviderOperationState::Retryable => {
                        self.retry_or_fail(operation.id, resource.id, ProviderError::Retryable)
                            .await
                    }
                    ProviderOperationState::Failed => {
                        self.store
                            .update_operation(
                                operation.id,
                                OperationState::Failed,
                                Some(&provider_operation.provider_operation_id.to_string()),
                                Some("terminal"),
                                Some("provider operation failed"),
                            )
                            .await?;
                        self.event(operation.id, resource.id, JournalEventKind::Failed);
                        Ok(OperationState::Failed)
                    }
                }
            }
            Err(ProviderError::UnknownOutcome { operation_id }) => {
                self.store
                    .update_operation(
                        operation.id,
                        OperationState::UnknownOutcome,
                        Some(&operation_id.to_string()),
                        Some("unknown_outcome"),
                        None,
                    )
                    .await?;
                self.event(operation.id, resource.id, JournalEventKind::RetryScheduled);
                Ok(OperationState::UnknownOutcome)
            }
            Err(error @ ProviderError::Retryable) | Err(error @ ProviderError::StaleState) => {
                self.retry_or_fail(operation.id, resource.id, error).await
            }
            Err(ProviderError::NotFound) if action == LifecycleAction::Delete => {
                self.finish_lifecycle(
                    operation.id,
                    resource,
                    action,
                    operation
                        .provider_operation_id
                        .unwrap_or_else(|| operation.id.to_string()),
                    provider_id,
                )
                .await
            }
            Err(error) => {
                self.store
                    .update_operation(
                        operation.id,
                        OperationState::Failed,
                        None,
                        Some(provider_error_category_name(error.category())),
                        Some(&error.to_string()),
                    )
                    .await?;
                self.event(operation.id, resource.id, JournalEventKind::Failed);
                Ok(OperationState::Failed)
            }
        }
    }

    async fn finish_lifecycle(
        &self,
        operation_id: Uuid,
        resource: ResourceRecord,
        action: LifecycleAction,
        provider_operation_id: String,
        provider_id: String,
    ) -> Result<OperationState, ReconcileError> {
        let observed_state = if action == LifecycleAction::Delete {
            server_state_to_storage(ServerState::Deleted).to_owned()
        } else {
            match self.provider.get_instance(&provider_id).await {
                Ok(instance) => {
                    server_state_to_storage(ServerState::from(instance.state)).to_owned()
                }
                Err(ProviderError::NotFound) if action == LifecycleAction::Delete => {
                    server_state_to_storage(ServerState::Deleted).to_owned()
                }
                Err(error) => return Err(ReconcileError::Provider(error)),
            }
        };
        // Project before the terminalizing write so the observation lands while
        // the lifecycle is still retriable; the observation is idempotent.
        self.project_metering(&resource, &observed_state).await?;
        // Issue #1041: the operation terminal state and the resource terminal
        // projection commit in ONE durable transaction. The previous two
        // sequential writes could crash between them, leaving the operation
        // terminal with the resource projection non-terminal (or vice versa),
        // which no reconciliation pass repairs.
        self.store
            .terminalize_lifecycle(&o3k_store::LifecycleTerminalization {
                operation_id,
                terminal_state: OperationState::Succeeded,
                provider_operation_id: Some(&provider_operation_id),
                error_category: None,
                error_message: None,
                resource_id: resource.id,
                expected_generation: resource.generation,
                desired_state: &resource.desired_state,
                observed_state: &observed_state,
                observed_generation: resource.generation,
                provider_id: Some(&provider_id),
            })
            .await?;
        self.event(operation_id, resource.id, JournalEventKind::Succeeded);
        Ok(OperationState::Succeeded)
    }

    pub async fn reconcile_once(
        &self,
        operation_id: Uuid,
    ) -> Result<OperationState, ReconcileError> {
        let operation = self.store.get_operation(operation_id).await?;
        if matches!(
            operation.state,
            OperationState::Succeeded | OperationState::Failed
        ) {
            return Ok(operation.state);
        }
        let resource = self.store.get_resource(operation.resource_id).await?;
        if operation.state == OperationState::UnknownOutcome {
            if operation.provider_operation_id.is_some() {
                // Issue #611 (ASR-021 agent-control-plane-network-interruption):
                // an ACCEPTED create whose provider operation never produced a
                // provider resource (Accepted/Running with no
                // provider_resource_id) provably never executed — e.g. the
                // agent reported an unknown outcome because the committed
                // artifacts were missing after the control-channel
                // interruption. The create must be re-driven (the transfer
                // loop re-offers the missing artifact) instead of being parked
                // Running forever. Presence is never projected from transport
                // loss; the provider operation state is the authority.
                if !self.accepted_create_never_executed(operation_id).await? {
                    return self.observe_unknown(operation, resource).await;
                }
            } else {
                // Issue #609: the retry budget exhausted before any provider
                // operation identity existed (every dispatch was rejected as
                // retryable), so there is no provider operation to poll.
                //
                // Issue #610 (ASR-021 agent-control-plane-network-interruption):
                // when the create's durable agent command row is still
                // `pending`, the create was provably never accepted and never
                // executed — the budget only exhausts on pre-acceptance
                // rejections, and the agent journal carries no entry. Presence
                // inspection would then terminalize the absent create as
                // failed; the interruption contract requires the create to
                // converge ACTIVE after the agent returns, so the create falls
                // through to the re-drive below. `create_instance` rebuilds
                // the command with the current epoch and a fresh deadline, and
                // the deterministic command identity keeps the agent journal
                // idempotent — a journal entry that already exists rejects the
                // rebuilt fingerprint instead of re-executing, and its
                // terminal observation (replayed on reconnect) converges the
                // operation. Transport loss is never projected as absence.
                let create_pending = self
                    .store
                    .get_agent_command_by_operation(operation_id)
                    .await
                    .is_ok_and(|command| command.state == o3k_store::AgentCommandState::Pending);
                if !create_pending {
                    return self.observe_create_presence(operation, resource).await;
                }
            }
        }
        let request: CreateInstanceRequest = serde_json::from_str(&resource.desired_state)
            .map_err(|_| ReconcileError::InvalidIntent)?;
        self.store
            .update_operation(
                operation_id,
                OperationState::Running,
                operation.provider_operation_id.as_deref(),
                None,
                None,
            )
            .await?;
        self.event(operation_id, resource.id, JournalEventKind::ProviderStarted);
        test_fault_pause_ms("before-dispatch", "O3K_TEST_FAULT_PAUSE_BEFORE_DISPATCH_MS");
        match self.provider.create_instance(request).await {
            Ok(provider_operation) => {
                validate_provider_operation_owner(operation_id, &provider_operation)?;
                let provider_operation_id = provider_operation.provider_operation_id.to_string();
                match provider_operation.state {
                    ProviderOperationState::Succeeded => {
                        self.finish_create(
                            operation_id,
                            resource,
                            provider_operation_id,
                            provider_operation.provider_resource_id,
                        )
                        .await
                    }
                    ProviderOperationState::Accepted | ProviderOperationState::Running => {
                        if let Some(provider_resource_id) = provider_operation.provider_resource_id
                        {
                            return self
                                .finish_create(
                                    operation_id,
                                    resource,
                                    provider_operation_id,
                                    Some(provider_resource_id),
                                )
                                .await;
                        }
                        self.store
                            .update_operation(
                                operation_id,
                                OperationState::Running,
                                Some(&provider_operation_id),
                                None,
                                None,
                            )
                            .await?;
                        Ok(OperationState::Running)
                    }
                    ProviderOperationState::UnknownOutcome => {
                        self.store
                            .update_operation(
                                operation_id,
                                OperationState::UnknownOutcome,
                                Some(&provider_operation_id),
                                Some("unknown_outcome"),
                                None,
                            )
                            .await?;
                        self.event(operation_id, resource.id, JournalEventKind::RetryScheduled);
                        Ok(OperationState::UnknownOutcome)
                    }
                    ProviderOperationState::Retryable => {
                        self.retry_or_fail(operation_id, resource.id, ProviderError::Retryable)
                            .await
                    }
                    ProviderOperationState::Failed => {
                        self.store
                            .update_operation(
                                operation_id,
                                OperationState::Failed,
                                Some(&provider_operation_id),
                                Some("terminal"),
                                Some("provider operation failed"),
                            )
                            .await?;
                        self.event(operation_id, resource.id, JournalEventKind::Failed);
                        Ok(OperationState::Failed)
                    }
                }
            }
            Err(ProviderError::UnknownOutcome {
                operation_id: provider_operation_id,
            }) => {
                self.store
                    .update_operation(
                        operation_id,
                        OperationState::UnknownOutcome,
                        Some(&provider_operation_id.to_string()),
                        Some("unknown_outcome"),
                        None,
                    )
                    .await?;
                self.event(operation_id, resource.id, JournalEventKind::RetryScheduled);
                Ok(OperationState::UnknownOutcome)
            }
            Err(error @ ProviderError::Retryable) | Err(error @ ProviderError::StaleState) => {
                self.retry_or_fail(operation_id, resource.id, error).await
            }
            Err(ProviderError::NotFound) => {
                // No agent was registered to receive the create (an empty
                // registry while a preserved agent is still in reconnect
                // backoff after a control-plane restart). `selected_agent`
                // fails before anything is dispatched, so the command was
                // provably never delivered and no provider side effect can
                // exist. This is therefore not a terminal failure: the
                // operation stays `Running` without a provider operation
                // identity — the exact residue shape the create-convergence
                // sweep re-drives — until an agent registers and the create
                // dispatches (issue #87). The empty-registry condition must
                // not consume the retry budget: the sweep ticks every few
                // seconds while reconnect backoff can be 8s/16s/32s, so any
                // small budget would exhaust before the agent returns.
                Ok(OperationState::Running)
            }
            Err(error) => {
                self.store
                    .update_operation(
                        operation_id,
                        OperationState::Failed,
                        None,
                        Some("terminal"),
                        Some(&error.to_string()),
                    )
                    .await?;
                self.event(operation_id, resource.id, JournalEventKind::Failed);
                Ok(OperationState::Failed)
            }
        }
    }

    /// Issue #611 (ASR-021 agent-control-plane-network-interruption): decides
    /// whether an unknown-outcome create's provider operation is still
    /// Accepted/Running WITHOUT a provider resource — the create provably
    /// never executed (no instance exists), e.g. the agent reported an unknown
    /// outcome because the committed artifacts were missing after the control
    /// channel was interrupted mid-transfer. Such a create must be re-driven
    /// (the provider's transfer loop re-offers the missing artifact) instead
    /// of being parked Running forever with no recovery path.
    async fn accepted_create_never_executed(
        &self,
        operation_id: Uuid,
    ) -> Result<bool, ReconcileError> {
        let Some(provider_operation_id) = self
            .store
            .get_operation(operation_id)
            .await?
            .provider_operation_id
        else {
            return Ok(false);
        };
        let provider_operation = self
            .provider
            .get_operation(
                Uuid::parse_str(&provider_operation_id)
                    .map_err(|_| ReconcileError::InvalidIntent)?,
            )
            .await?;
        Ok(matches!(
            provider_operation.state,
            o3k_provider::OperationState::Accepted | o3k_provider::OperationState::Running
        ) && provider_operation.provider_resource_id.is_none())
    }

    async fn observe_unknown(
        &self,
        operation: OperationRecord,
        resource: ResourceRecord,
    ) -> Result<OperationState, ReconcileError> {
        let Some(provider_id) = operation.provider_operation_id.as_deref() else {
            return Err(ReconcileError::InvalidIntent);
        };
        let provider_operation = self
            .provider
            .get_operation(Uuid::parse_str(provider_id).map_err(|_| ReconcileError::InvalidIntent)?)
            .await?;
        validate_provider_operation_owner(operation.id, &provider_operation)?;
        self.event(operation.id, resource.id, JournalEventKind::UnknownObserved);
        match provider_operation.state {
            ProviderOperationState::UnknownOutcome => {
                if let Some(resource_id) = provider_operation.provider_resource_id {
                    return self
                        .finish_create(
                            operation.id,
                            resource,
                            provider_id.to_owned(),
                            Some(resource_id),
                        )
                        .await;
                }
                // The provider operation carries no resource identity: the
                // create may or may not have taken effect. Observe instance
                // presence by the server's durable identity before deciding
                // anything (SPEC-0021 unknown-outcome rules).
                self.observe_create_presence(operation, resource).await
            }
            ProviderOperationState::Succeeded => {
                self.finish_create(
                    operation.id,
                    resource,
                    provider_id.to_owned(),
                    provider_operation.provider_resource_id,
                )
                .await
            }
            ProviderOperationState::Accepted | ProviderOperationState::Running => {
                if let Some(resource_id) = provider_operation.provider_resource_id {
                    return self
                        .finish_create(
                            operation.id,
                            resource,
                            provider_id.to_owned(),
                            Some(resource_id),
                        )
                        .await;
                }
                self.store
                    .update_operation(
                        operation.id,
                        OperationState::Running,
                        Some(provider_id),
                        None,
                        None,
                    )
                    .await?;
                Ok(OperationState::Running)
            }
            ProviderOperationState::Retryable => {
                self.retry_or_fail(operation.id, resource.id, ProviderError::Retryable)
                    .await
            }
            ProviderOperationState::Failed => {
                self.store
                    .update_operation(
                        operation.id,
                        OperationState::Failed,
                        Some(provider_id),
                        Some("terminal"),
                        Some("provider operation failed"),
                    )
                    .await?;
                self.event(operation.id, resource.id, JournalEventKind::Failed);
                Ok(OperationState::Failed)
            }
        }
    }

    /// Observes instance presence at the execution boundary for a create
    /// whose provider operation is unknown and carries no provider resource
    /// identity (SPEC-0021 "observe the selected provider before any create
    /// retry"). The agent is addressed by the durable placement identity
    /// recorded in the create intent, the O3K server id is the durable
    /// resource identity, and the inspection operation is deterministic per
    /// create operation so repeated triggers reuse an in-flight or terminal
    /// inspection instead of dispatching duplicates.
    ///
    /// - instance present → the create converged to success;
    /// - instance provably absent → the create never took effect, converges
    ///   to a terminal failure with the resource projected to error;
    /// - the inspection itself is unknown (dispatch timeout, transport loss,
    ///   unreachable agent) → the create stays `UnknownOutcome` and is
    ///   re-observed on the next trigger; transport loss is never projected
    ///   as absence.
    ///
    /// The agent executor settles commands inline in its message loop, so an
    /// inspection dispatched after a timed-out create observes the create's
    /// settled state, and the agent contract classifies only a provably
    /// absent domain as a terminal Failed/NotFound inspection — every other
    /// inspection failure stays unknown.
    async fn observe_create_presence(
        &self,
        operation: OperationRecord,
        resource: ResourceRecord,
    ) -> Result<OperationState, ReconcileError> {
        let request: CreateInstanceRequest = serde_json::from_str(&resource.desired_state)
            .map_err(|_| ReconcileError::InvalidIntent)?;
        let Some(provider_id) = request.placement_provider_id.as_deref() else {
            // No execution agent is recorded, so presence cannot be observed
            // by durable identity; the unknown outcome is preserved.
            return Ok(OperationState::UnknownOutcome);
        };
        let inspect_operation_id = Uuid::new_v5(
            &Uuid::NAMESPACE_URL,
            format!("o3k:inspect-create:{}", operation.id).as_bytes(),
        );
        let idempotency_key = format!("o3k-inspect-create-{}", operation.id);
        match self.store.get_operation(inspect_operation_id).await {
            Ok(inspect) => match inspect.state {
                OperationState::Succeeded => {
                    let Some(provider_resource_id) =
                        self.provider_resource_id_for(&resource).await?
                    else {
                        return Ok(OperationState::UnknownOutcome);
                    };
                    return self
                        .finish_create(
                            operation.id,
                            resource,
                            operation
                                .provider_operation_id
                                .unwrap_or_else(|| inspect_operation_id.to_string()),
                            Some(provider_resource_id),
                        )
                        .await;
                }
                OperationState::Failed
                    if inspect.error_category.as_deref() == Some("not_found") =>
                {
                    return self.converge_absent_create(operation, resource).await;
                }
                OperationState::UnknownOutcome | OperationState::Retryable => {}
                _ => {
                    // The inspection never reached a durable terminal state
                    // (Pending/Running: a crash between persist and dispatch,
                    // a lost agent acceptance, or a write race), or ended
                    // terminally for a reason other than absence (ambiguous).
                    // The durable agent command record is the authoritative
                    // terminal evidence when the agent's update overtook the
                    // reconciler's in-flight write.
                    if let Ok(command) = self
                        .store
                        .get_agent_command_by_operation(inspect_operation_id)
                        .await
                    {
                        match command.state {
                            o3k_store::AgentCommandState::Succeeded => {
                                let Some(provider_resource_id) =
                                    self.provider_resource_id_for(&resource).await?
                                else {
                                    return Ok(OperationState::UnknownOutcome);
                                };
                                let provider_operation_id = command
                                    .provider_operation_id
                                    .clone()
                                    .unwrap_or_else(|| inspect_operation_id.to_string());
                                self.store
                                    .update_operation(
                                        inspect_operation_id,
                                        OperationState::Succeeded,
                                        Some(&provider_operation_id),
                                        None,
                                        None,
                                    )
                                    .await?;
                                return self
                                    .finish_create(
                                        operation.id,
                                        resource,
                                        operation
                                            .provider_operation_id
                                            .unwrap_or_else(|| inspect_operation_id.to_string()),
                                        Some(provider_resource_id),
                                    )
                                    .await;
                            }
                            o3k_store::AgentCommandState::Failed => {
                                // The real agent classifies an absent domain
                                // as a terminal Failed inspection; every other
                                // inspection failure is reported as unknown,
                                // so a terminal failed command record proves
                                // absence.
                                let provider_operation_id = command
                                    .provider_operation_id
                                    .clone()
                                    .unwrap_or_else(|| inspect_operation_id.to_string());
                                self.store
                                    .update_operation(
                                        inspect_operation_id,
                                        OperationState::Failed,
                                        Some(&provider_operation_id),
                                        Some("not_found"),
                                        Some("presence inspection: instance is absent"),
                                    )
                                    .await?;
                                return self.converge_absent_create(operation, resource).await;
                            }
                            _ => {}
                        }
                    }
                    // Without terminal evidence, a Pending record (a crash
                    // between persist and dispatch, or a lost dispatch
                    // response) is re-observed by re-dispatching the
                    // read-only inspection (the provider dedups by the
                    // deterministic operation identity). A Running record is
                    // already accepted by the agent, whose journal guarantees
                    // delivery of the terminal update, so it is never
                    // re-dispatched; a terminal non-absence classification is
                    // ambiguous and is also never re-dispatched.
                    if !matches!(inspect.state, OperationState::Pending) {
                        return Ok(OperationState::UnknownOutcome);
                    }
                }
            },
            Err(_) => {
                // No inspection record yet: persist the intent before
                // dispatch so a terminal agent update can never arrive for an
                // unknown operation.
                self.store
                    .insert_operation(&OperationRecord {
                        id: inspect_operation_id,
                        resource_id: resource.id,
                        kind: "inspect".to_owned(),
                        state: OperationState::Pending,
                        provider_operation_id: None,
                        error_category: None,
                        error_message: None,
                    })
                    .await?;
            }
        }
        // If a provider reference was recorded meanwhile (lost-update window
        // where the agent completed the create), pass it so the provider
        // validates the identity instead of rejecting an empty id; an empty
        // id keeps the inspection keyed on the server's durable identity.
        let known_provider_resource_id = self.provider_resource_id_for(&resource).await?;
        // The inspection dispatch itself persists the durable command row
        // (with the REAL payload and the selected agent's identity) before
        // sending anything over the wire, so a terminal observation can never
        // arrive for an unbound operation after a control-plane crash. A
        // pre-inserted placeholder row would be reused by the provider's
        // `dispatch_recorded` instead, and its empty payload decodes into an
        // action-less command that the agent rejects — stranding every
        // unknown-outcome create in REQUESTED forever (issue #575 real-host
        // finding; introduced by 13d1d65).
        let result = self
            .provider
            .inspect_instance(
                provider_id,
                &resource.id.to_string(),
                known_provider_resource_id.as_deref().unwrap_or(""),
                inspect_operation_id,
                &idempotency_key,
            )
            .await;
        match result {
            Ok(inspect_operation) => {
                validate_provider_operation_owner(inspect_operation_id, &inspect_operation)?;
                match inspect_operation.state {
                    ProviderOperationState::Succeeded => {
                        let Some(provider_resource_id) = inspect_operation.provider_resource_id
                        else {
                            // A success without a resource identity cannot be
                            // converged; keep the operation unknown rather
                            // than inventing a provider identity.
                            self.store
                                .update_operation(
                                    inspect_operation_id,
                                    OperationState::Running,
                                    Some(&inspect_operation.provider_operation_id.to_string()),
                                    None,
                                    None,
                                )
                                .await?;
                            return Ok(OperationState::UnknownOutcome);
                        };
                        self.store
                            .update_operation(
                                inspect_operation_id,
                                OperationState::Succeeded,
                                Some(&inspect_operation.provider_operation_id.to_string()),
                                None,
                                None,
                            )
                            .await?;
                        self.finish_create(
                            operation.id,
                            resource,
                            operation.provider_operation_id.unwrap_or_else(|| {
                                inspect_operation.provider_operation_id.to_string()
                            }),
                            Some(provider_resource_id),
                        )
                        .await
                    }
                    ProviderOperationState::Failed
                        if inspect_operation.error_category
                            == Some(o3k_provider::ErrorCategory::NotFound) =>
                    {
                        self.store
                            .update_operation(
                                inspect_operation_id,
                                OperationState::Failed,
                                Some(&inspect_operation.provider_operation_id.to_string()),
                                Some("not_found"),
                                Some("presence inspection: instance is absent"),
                            )
                            .await?;
                        self.converge_absent_create(operation, resource).await
                    }
                    ProviderOperationState::Failed => {
                        // A terminal inspection failure other than absence is
                        // ambiguous (the instance may still exist); preserve
                        // the unknown outcome.
                        self.store
                            .update_operation(
                                inspect_operation_id,
                                OperationState::Failed,
                                Some(&inspect_operation.provider_operation_id.to_string()),
                                inspect_operation
                                    .error_category
                                    .map(provider_error_category_name),
                                Some("presence inspection failed"),
                            )
                            .await?;
                        Ok(OperationState::UnknownOutcome)
                    }
                    ProviderOperationState::Retryable => {
                        self.store
                            .update_operation(
                                inspect_operation_id,
                                OperationState::Retryable,
                                Some(&inspect_operation.provider_operation_id.to_string()),
                                Some("retryable"),
                                None,
                            )
                            .await?;
                        Ok(OperationState::UnknownOutcome)
                    }
                    ProviderOperationState::Accepted | ProviderOperationState::Running => {
                        self.store
                            .update_operation(
                                inspect_operation_id,
                                OperationState::Running,
                                Some(&inspect_operation.provider_operation_id.to_string()),
                                None,
                                None,
                            )
                            .await?;
                        Ok(OperationState::UnknownOutcome)
                    }
                    ProviderOperationState::UnknownOutcome => {
                        self.store
                            .update_operation(
                                inspect_operation_id,
                                OperationState::UnknownOutcome,
                                Some(&inspect_operation.provider_operation_id.to_string()),
                                Some("unknown_outcome"),
                                None,
                            )
                            .await?;
                        Ok(OperationState::UnknownOutcome)
                    }
                }
            }
            Err(error) => {
                // Transport loss, timeout, or an unreachable agent: the
                // inspection outcome is unknown. Never project absence from a
                // failed dispatch; the record stays re-observable.
                self.store
                    .update_operation(
                        inspect_operation_id,
                        OperationState::UnknownOutcome,
                        None,
                        Some("unknown_outcome"),
                        Some(&error.to_string()),
                    )
                    .await?;
                Ok(OperationState::UnknownOutcome)
            }
        }
    }

    /// Converges a create whose presence inspection provably found no
    /// instance: the create never took effect, so the operation is terminal
    /// Failed and the resource projects a visible error state (mirror of the
    /// agent-failed create projection), which is what makes clients polling
    /// the server stop waiting.
    async fn converge_absent_create(
        &self,
        operation: OperationRecord,
        resource: ResourceRecord,
    ) -> Result<OperationState, ReconcileError> {
        // Project before the terminalizing write so the observation lands while
        // the step is still retriable.
        self.project_metering(&resource, server_state_to_storage(ServerState::Error))
            .await?;
        self.store
            .update_operation(
                operation.id,
                OperationState::Failed,
                operation.provider_operation_id.as_deref(),
                Some("not_found"),
                Some("presence inspection: create never took effect; instance is absent"),
            )
            .await?;
        self.store
            .update_resource(
                resource.id,
                resource.generation,
                &resource.desired_state,
                server_state_to_storage(ServerState::Error),
                resource.generation,
                resource.provider_id.as_deref(),
            )
            .await?;
        self.event(operation.id, resource.id, JournalEventKind::Failed);
        Ok(OperationState::Failed)
    }

    /// Resolves the provider resource identity recorded for the server by
    /// either execution-boundary reference name.
    async fn provider_resource_id_for(
        &self,
        resource: &ResourceRecord,
    ) -> Result<Option<String>, ReconcileError> {
        for name in ["compute", "compute-agent"] {
            match self.store.get_provider_reference(resource.id, name).await {
                Ok(reference) => return Ok(Some(reference.provider_resource_id)),
                Err(StoreError::ProviderReferenceNotFound) => continue,
                Err(error) => return Err(error.into()),
            }
        }
        Ok(None)
    }

    async fn finish_create(
        &self,
        operation_id: Uuid,
        resource: ResourceRecord,
        provider_operation_id: String,
        provider_resource_id: Option<String>,
    ) -> Result<OperationState, ReconcileError> {
        let provider_resource_id = provider_resource_id.ok_or(ReconcileError::InvalidIntent)?;
        let instance = self.provider.get_instance(&provider_resource_id).await?;
        let observed_state = server_state_to_storage(ServerState::from(instance.state));
        if instance.state == o3k_provider::InstanceState::Running {
            return self
                .finish(
                    operation_id,
                    resource,
                    provider_operation_id,
                    Some(provider_resource_id),
                )
                .await;
        }
        // The three non-Running outcomes below all durably project exactly this
        // observed_state, so project it once before any of their writes: the
        // observation must land while the step is still retriable, and the
        // observation is idempotent if a later write fails and re-drives.
        self.project_metering(&resource, observed_state).await?;
        if instance.state == o3k_provider::InstanceState::Error {
            self.store
                .update_operation(
                    operation_id,
                    OperationState::Failed,
                    Some(&provider_operation_id),
                    Some("terminal"),
                    Some("provider instance entered an error state"),
                )
                .await?;
            self.store
                .update_resource(
                    resource.id,
                    resource.generation,
                    &resource.desired_state,
                    observed_state,
                    resource.generation,
                    Some(&provider_resource_id),
                )
                .await?;
            self.event(operation_id, resource.id, JournalEventKind::Failed);
            return Ok(OperationState::Failed);
        }
        if instance.state == o3k_provider::InstanceState::Creating {
            // The create is still in flight at the execution boundary; keep
            // the Running wait with the observed projection.
            self.store
                .update_operation(
                    operation_id,
                    OperationState::Running,
                    Some(&provider_operation_id),
                    None,
                    None,
                )
                .await?;
            self.store
                .update_resource(
                    resource.id,
                    resource.generation,
                    &resource.desired_state,
                    observed_state,
                    resource.generation,
                    Some(&provider_resource_id),
                )
                .await?;
            self.event(operation_id, resource.id, JournalEventKind::ProviderStarted);
            return Ok(OperationState::Running);
        }
        // A present instance in a settled non-Running state (the issue-87
        // crash-between-define-and-start adoption: the domain was defined but
        // never started, so the instance is observed Stopped) is a converged
        // create: presence observation treats any present instance as success,
        // so the adoption terminalizes Succeeded and the server is projected
        // with its observed state (SHUTOFF) — never left Running without a
        // transition path. `reconcile_once` short-circuits on Succeeded, so
        // there is exactly one terminal transition.
        self.store
            .update_operation(
                operation_id,
                OperationState::Succeeded,
                Some(&provider_operation_id),
                None,
                None,
            )
            .await?;
        self.store
            .update_resource(
                resource.id,
                resource.generation,
                &resource.desired_state,
                observed_state,
                resource.generation,
                Some(&provider_resource_id),
            )
            .await?;
        self.event(operation_id, resource.id, JournalEventKind::Succeeded);
        Ok(OperationState::Succeeded)
    }

    async fn finish(
        &self,
        operation_id: Uuid,
        resource: ResourceRecord,
        provider_operation_id: String,
        provider_resource_id: Option<String>,
    ) -> Result<OperationState, ReconcileError> {
        // A concurrent driver (an idempotent retry whose show path re-drives
        // a create while the synchronous pass is still dispatching) can reach
        // `finish` with the operation already converged: both dispatches
        // raced, the provider returned the same deterministic identity, and
        // the first driver already attached the reference and projected the
        // terminal state. Short-circuit on that first-writer outcome instead
        // of re-attaching the reference (unique violation) and clobbering the
        // resource generation (stale generation) — the exact
        // "duplicate reference attach / stale generation" race the create
        // convergence driver documents above.
        let current = self.store.get_operation(operation_id).await?;
        if current.state == OperationState::Succeeded
            && current.provider_operation_id.as_deref() == Some(provider_operation_id.as_str())
        {
            return Ok(OperationState::Succeeded);
        }
        if let Some(provider_resource_id) = provider_resource_id.as_deref() {
            let reference = ProviderReference {
                resource_id: resource.id,
                provider_name: "compute".to_owned(),
                provider_resource_id: provider_resource_id.to_owned(),
            };
            match self
                .store
                .get_provider_reference(resource.id, "compute")
                .await
            {
                Ok(existing) if existing.provider_resource_id == provider_resource_id => {}
                Ok(_) => return Err(StoreError::ProviderReferenceAlreadyExists.into()),
                Err(StoreError::ProviderReferenceNotFound) => {
                    match self.store.attach_provider_reference(&reference).await {
                        Ok(()) => {}
                        // A concurrent driver attached between the read above
                        // and this insert (the same read-then-attach window
                        // the observation path documents). Converge when the
                        // attached identity matches; a different identity is a
                        // genuine drift and stays an error.
                        Err(StoreError::ProviderReferenceAlreadyExists) => {
                            let existing = self
                                .store
                                .get_provider_reference(resource.id, "compute")
                                .await?;
                            if existing.provider_resource_id != provider_resource_id {
                                return Err(StoreError::ProviderReferenceAlreadyExists.into());
                            }
                        }
                        Err(error) => return Err(error.into()),
                    }
                }
                Err(error) => return Err(error.into()),
            }
        }
        // The target state is the constant ACTIVE, so project once before the
        // terminalizing write rather than inside the CAS retry loop (every
        // attempt retries into the same state, never a different one). The
        // observation must land while the step is still retriable.
        self.project_metering(&resource, server_state_to_storage(ServerState::Active))
            .await?;
        self.store
            .update_operation(
                operation_id,
                OperationState::Succeeded,
                Some(&provider_operation_id),
                None,
                None,
            )
            .await?;
        // The resource projection is a generation-guarded CAS, and a
        // concurrent driver's finish can land between this driver's re-read
        // and its update. Converge instead of erroring: re-read, short-circuit
        // on the already-projected terminal state, and retry the CAS on a
        // bounded number of stale snapshots (no sleeps; the re-read sees the
        // other driver's committed projection).
        let mut attempts = 0;
        loop {
            let fresh = self.store.get_resource(resource.id).await?;
            if fresh.observed_state == server_state_to_storage(ServerState::Active)
                && fresh.provider_id.as_deref() == provider_resource_id.as_deref()
            {
                return Ok(OperationState::Succeeded);
            }
            match self
                .store
                .update_resource(
                    fresh.id,
                    fresh.generation,
                    &fresh.desired_state,
                    server_state_to_storage(ServerState::Active),
                    fresh.generation,
                    provider_resource_id.as_deref(),
                )
                .await
            {
                Ok(_) => break,
                Err(StoreError::StaleGeneration)
                    if attempts < FINISH_RESOURCE_UPDATE_MAX_ATTEMPTS =>
                {
                    attempts += 1;
                }
                Err(error) => return Err(error.into()),
            }
        }
        self.event(operation_id, resource.id, JournalEventKind::Succeeded);
        Ok(OperationState::Succeeded)
    }

    async fn retry_or_fail(
        &self,
        operation_id: Uuid,
        resource_id: Uuid,
        error: ProviderError,
    ) -> Result<OperationState, ReconcileError> {
        let attempts = self.store.increment_operation_retry(operation_id).await?;
        if attempts >= self.max_attempts {
            // Issue #609 (ASR-021 agent-control-plane-network-interruption):
            // a retryable provider outcome is by definition not a
            // definitively-known failure, so exhausting the retry budget must
            // never terminalize the operation. The budget only bounds
            // dispatching: the operation stays `UnknownOutcome` (keeping the
            // error for diagnosis) and the convergence sweeps keep observing
            // and re-driving it, so a transient interruption that resolves
            // still converges after recovery. Presence inspection resolves
            // genuinely-absent cases; a reconnected agent's terminal update
            // can also still arrive through the event stream.
            self.store
                .update_operation(
                    operation_id,
                    OperationState::UnknownOutcome,
                    None,
                    Some("retry_exhausted"),
                    Some(&error.to_string()),
                )
                .await?;
            self.event(operation_id, resource_id, JournalEventKind::UnknownObserved);
            Ok(OperationState::UnknownOutcome)
        } else {
            self.store
                .update_operation(
                    operation_id,
                    OperationState::Retryable,
                    None,
                    Some("retryable"),
                    None,
                )
                .await?;
            self.event(operation_id, resource_id, JournalEventKind::RetryScheduled);
            Ok(OperationState::Retryable)
        }
    }

    fn event(&self, operation_id: Uuid, resource_id: Uuid, kind: JournalEventKind) {
        if let Ok(mut events) = self.events.lock() {
            events.push(JournalEvent {
                operation_id,
                resource_id,
                kind,
            });
        }
    }
}

// ─── Internal helpers ─────────────────────────────────────
fn agent_error_category(
    category: Option<AgentErrorCategory>,
) -> Result<&'static str, ReconcileError> {
    // A terminal failure must carry a classified category: an unspecified one
    // means the update is not complete evidence and is rejected.
    let category = category.ok_or(ReconcileError::InvalidIntent)?;
    Ok(match category {
        AgentErrorCategory::InvalidRequest => "invalid_request",
        AgentErrorCategory::Unauthenticated => "unauthenticated",
        AgentErrorCategory::Unauthorized => "unauthorized",
        AgentErrorCategory::Conflict => "conflict",
        AgentErrorCategory::Capacity => "capacity",
        AgentErrorCategory::NotFound => "not_found",
        AgentErrorCategory::Retryable => "retryable",
        AgentErrorCategory::UnknownOutcome => "unknown_outcome",
        AgentErrorCategory::Terminal => "terminal",
    })
}

fn provider_error_category_name(category: o3k_provider::ErrorCategory) -> &'static str {
    match category {
        o3k_provider::ErrorCategory::InvalidRequest => "invalid_request",
        o3k_provider::ErrorCategory::NotFound => "not_found",
        o3k_provider::ErrorCategory::Conflict => "conflict",
        o3k_provider::ErrorCategory::Capacity => "capacity",
        o3k_provider::ErrorCategory::Retryable => "retryable",
        o3k_provider::ErrorCategory::UnknownOutcome => "unknown_outcome",
        o3k_provider::ErrorCategory::Terminal => "terminal",
    }
}

/// Maximum length of a persisted agent failure reason. The durable record
/// stays bounded even if an agent message grows unexpectedly.
const MAX_AGENT_FAILURE_MESSAGE_LEN: usize = 240;

/// Maximum stale-snapshot retries for the terminal resource projection in
/// [`OperationJournal::finish`]. A concurrent driver's finish can commit the
/// same projection between this driver's re-read and its generation-guarded
/// CAS; each retry re-reads the committed state and short-circuits on the
/// converged projection, so the bound is never exercised in a healthy run.
const FINISH_RESOURCE_UPDATE_MAX_ATTEMPTS: u32 = 3;

/// Bounds and sanitizes the agent-reported failure reason for durable storage
/// and operator logs. The agent contract already redacts secrets; the control
/// plane additionally neutralizes control characters, truncates to a bounded
/// length, and falls back to a generic reason when the agent supplied nothing
/// usable.
fn bounded_agent_failure_message(raw: &str) -> String {
    let cleaned: String = raw
        .chars()
        .map(|c| if c.is_control() { ' ' } else { c })
        .collect();
    let trimmed = cleaned.trim();
    if trimmed.is_empty() {
        return "agent operation failed".to_owned();
    }
    let bounded: String = trimmed
        .chars()
        .take(MAX_AGENT_FAILURE_MESSAGE_LEN)
        .collect();
    if trimmed.chars().count() > MAX_AGENT_FAILURE_MESSAGE_LEN {
        format!("{bounded}...")
    } else {
        bounded
    }
}

fn validate_provider_operation_owner(
    operation_id: Uuid,
    provider_operation: &o3k_provider::Operation,
) -> Result<(), ReconcileError> {
    if provider_operation.o3k_operation_id != operation_id {
        return Err(ReconcileError::InvalidIntent);
    }
    Ok(())
}

/// Deterministic fresh command identity for a #575 delete re-drive, tied to
/// the durable lifecycle operation so repeated reconciliations re-dispatch
/// the SAME command and old-stream evidence cannot complete it.
fn delete_redrive_operation_id(operation_id: Uuid) -> Uuid {
    Uuid::new_v5(
        &Uuid::NAMESPACE_URL,
        format!("o3k:lifecycle-delete-redrive:{operation_id}").as_bytes(),
    )
}

fn validate_lifecycle_provider_operation_owner(
    operation_id: Uuid,
    action: LifecycleAction,
    provider_operation: &o3k_provider::Operation,
) -> Result<(), ReconcileError> {
    if provider_operation.o3k_operation_id == operation_id {
        return Ok(());
    }
    if action == LifecycleAction::Delete
        && provider_operation.o3k_operation_id == delete_redrive_operation_id(operation_id)
    {
        return Ok(());
    }
    Err(ReconcileError::InvalidIntent)
}

fn valid_agent_reference(value: &str) -> bool {
    !value.is_empty()
        && value.len() <= 128
        && value
            .bytes()
            .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'.' | b'_' | b'-' | b':'))
}

// ─── Tests ───────────────────────────────────────────────-

#[cfg(test)]
mod tests;
