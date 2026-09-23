use super::{
    AgentNodeRegistry, Arc, AttachmentOrchestrator, ComputeError, ComputeService,
    CreateInstanceRequest, Duration, OperationJournal, PortBindingProjector, ProviderBackend,
    Scheduler, ServerState, StaticAuthorizer, Uuid, VolumeAttachmentProvider,
};

use o3k_kernel::{Authorizer, MemoryAuditSink, RequiredAuditPublisher};
use o3k_store::ComputeRepository;
use o3k_store::server_state_to_storage;

impl ComputeService {
    /// Publish mandatory control-plane evidence before acknowledging an
    /// authenticated mutation/action. Legacy synchronous sinks fail closed;
    /// only the durable async boundary can satisfy this contract.
    pub async fn record_required_audit(
        &self,
        event: &o3k_kernel::AuditEvent,
    ) -> Result<(), ComputeError> {
        self.audit_sink
            .publish(event)
            .await
            .map_err(|_| ComputeError::Unavailable)
    }

    #[must_use]
    pub fn new<P>(
        store: Arc<dyn ComputeRepository>,
        provider: Arc<P>,
        audit_sink: Arc<dyn RequiredAuditPublisher>,
    ) -> Self
    where
        Arc<P>: Into<ProviderBackend>,
    {
        let provider = Arc::new(provider.into());
        let journal = OperationJournal::new(store.clone(), provider.clone(), 3);
        let attachments = AttachmentOrchestrator::new(store.clone(), provider.clone(), None);
        Self {
            store,
            provider,
            journal,
            scheduler: None,
            agent_registry: None,
            cinder: None,
            attachments,
            binding_projector: None,
            config_drive_cleaner: None,
            authorizer: Arc::new(StaticAuthorizer::standard()),
            audit_sink,
            metering: None,
            coordination: None,
        }
    }

    /// Explicit test construction with an in-memory required publisher.
    /// Production callers must use [`ComputeService::new`] and provide the
    /// durable publisher explicitly.
    #[doc(hidden)]
    pub fn new_for_test<P>(store: Arc<dyn ComputeRepository>, provider: Arc<P>) -> Self
    where
        Arc<P>: Into<ProviderBackend>,
    {
        Self::new(store, provider, Arc::new(MemoryAuditSink::new()))
    }

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

    #[must_use]
    pub fn with_authorizer(mut self, authorizer: Arc<dyn Authorizer>) -> Self {
        self.authorizer = authorizer;
        self
    }

    #[must_use]
    pub fn with_required_audit_publisher(
        mut self,
        audit_sink: Arc<dyn RequiredAuditPublisher>,
    ) -> Self {
        self.audit_sink = audit_sink;
        self
    }

    /// Configures the control-plane config-drive store whose per-instance
    /// media is reaped when a server delete reaches terminal success.
    /// Reaping is best-effort and idempotent; without this builder the
    /// cleanup is a no-op, so tests and hosts that do not own a config-drive
    /// store are unchanged.
    #[must_use]
    pub fn with_config_drive_cleaner(mut self, store: o3k_config_drive::ConfigDriveStore) -> Self {
        self.config_drive_cleaner = Some(store);
        self
    }

    /// Best-effort removal of the per-instance config-drive media owned by
    /// this control plane once a server delete is known terminal. A failed
    /// cleanup is logged, never a compute failure: the leak verifier catches
    /// residue separately, and the cleanup is idempotent so a replayed
    /// terminal update reaps nothing more than the first one.
    pub(super) fn cleanup_config_drive_best_effort(&self, server_id: &str) {
        let Some(store) = self.config_drive_cleaner.as_ref() else {
            return;
        };
        if let Err(error) = store.cleanup(server_id) {
            tracing::warn!(
                server_id = %server_id,
                error = %error,
                "config-drive cleanup failed; the delete outcome is unaffected"
            );
        }
    }

    /// Configures the projector that reflects terminal create/delete outcomes
    /// into the durable port binding state of the network control plane.
    #[must_use]
    pub fn with_binding_projector(
        mut self,
        binding_projector: Arc<dyn PortBindingProjector>,
    ) -> Self {
        self.binding_projector = Some(binding_projector);
        self
    }

    /// Configures the external volume-attachment provider used for the
    /// durable attachment lifecycle. External-hosted volume attachment
    /// requires it; the concrete adapter is selected at the composition root.
    #[must_use]
    pub fn with_attachment_provider(mut self, provider: Arc<dyn VolumeAttachmentProvider>) -> Self {
        self.cinder = Some(provider.clone());
        self.attachments =
            AttachmentOrchestrator::new(self.store.clone(), self.provider.clone(), Some(provider));
        self
    }

    #[must_use]
    pub fn attachment_orchestrator(&self) -> AttachmentOrchestrator {
        self.attachments.clone()
    }

    #[must_use]
    pub fn with_scheduler(mut self, scheduler: Scheduler) -> Self {
        self.scheduler = Some(scheduler);
        self
    }

    /// Restricts scheduler candidates to agents that are currently registered,
    /// alive, and administratively enabled. The registry is intentionally
    /// optional so direct fake-provider operation keeps its existing behavior.
    /// The same registry backs the journal's evidence fence: without it the
    /// fence stays anchored to each operation's first evidence epoch (issue
    /// #87 crash-restart replay needs the registry's current epoch to accept
    /// a re-registered agent's replay while rejecting dead epochs).
    #[must_use]
    pub fn with_agent_registry(mut self, registry: Arc<dyn AgentNodeRegistry>) -> Self {
        self.journal = self.journal.clone().with_agent_registry(registry.clone());
        self.agent_registry = Some(registry);
        self
    }

    /// Configures the metering observer that projects compute resource
    /// lifecycle projections into O3K metering authority. It is attached to
    /// both the service's own projections and its reconciliation journal, so
    /// one builder covers the direct and reconciled lifecycle paths. The
    /// observer is intentionally optional so direct fake-provider operation
    /// keeps its existing behavior.
    #[must_use]
    pub fn with_metering_observer(
        mut self,
        observer: Arc<dyn o3k_kernel::LifecycleMeteringObserver>,
    ) -> Self {
        self.journal = self
            .journal
            .clone()
            .with_metering_observer(observer.clone());
        self.metering = Some(observer);
        self
    }

    /// Projects a compute lifecycle state into metering authority. No-op
    /// without an observer; a metering failure is surfaced as `ComputeError`
    /// so the caller decides whether the step is retriable or best-effort.
    pub(super) async fn project_metering(
        &self,
        resource: &o3k_store::ResourceRecord,
        observed_state: &str,
    ) -> Result<(), ComputeError> {
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
            .map_err(|error| ComputeError::Metering(error.to_string()))
    }

    /// Best-effort metering projection for the read-path convergence drive: a
    /// metering failure is logged and swallowed so a metering hiccup cannot
    /// turn a GET into a 500. The next read re-projects the durable state
    /// (idempotent), which repairs any observation lost here.
    pub(super) async fn project_metering_best_effort(
        &self,
        resource: &o3k_store::ResourceRecord,
        observed_state: &str,
    ) {
        if let Err(error) = self.project_metering(resource, observed_state).await {
            tracing::warn!(
                resource_id = %resource.id,
                %error,
                "metering projection on the read path failed; the GET is unaffected and the next read repairs it"
            );
        }
    }

    /// Best-effort read-path repair projection from durable truth.
    ///
    /// A repair only ever OPENS or REFRESHES a consuming interval. It never
    /// emits a close: closing is owned by the authoritative state-transition
    /// paths, and a read that closed at the read instant would under-count a
    /// teardown tail and could permanently close an interval for an instance
    /// that later resumes (`ACTIVE`/`STARTING`/`STOPPING`/`REBOOTING`).
    pub(super) async fn repair_metering_from_durable_state(&self, resource_id: Uuid) {
        let Ok(resource) = self.store.get_resource(resource_id).await else {
            return;
        };
        if o3k_reconciler::compute_instance_state_consuming(&resource.observed_state) != Some(true)
        {
            return;
        }
        self.project_metering_best_effort(&resource, &resource.observed_state)
            .await;
    }

    #[must_use]
    pub fn provider(&self) -> Arc<ProviderBackend> {
        self.provider.clone()
    }

    /// Reports whether the explicitly configured external-Cinder attachment
    /// provider enables the hosted attachment API profile.
    #[must_use]
    pub fn cinder_configured(&self) -> bool {
        self.attachments.cinder_configured()
    }

    /// Applies a live authenticated agent result through the durable journal.
    /// The control-plane event consumer owns subscription and retry policy.
    pub async fn apply_agent_update(
        &self,
        update: &o3k_provider::AgentOperationUpdate,
    ) -> Result<o3k_store::OperationState, ComputeError> {
        let state = self.journal.apply_agent_update(update).await?;
        if matches!(
            state,
            o3k_store::OperationState::Succeeded | o3k_store::OperationState::Failed
        ) {
            self.project_terminal_outcome_best_effort(
                update.operation_id.to_string().as_str(),
                state,
            )
            .await;
        }
        if state == o3k_store::OperationState::Failed {
            self.compensate_failed_create(update.operation_id).await?;
        }
        Ok(state)
    }

    /// Reflects a terminal operation outcome into the durable port binding
    /// state of the network control plane, reaps the per-instance config-drive
    /// media when a delete reached terminal success, and releases the
    /// server-owned network endpoints the deleted server no longer needs.
    ///
    /// The server's ports are read from the durable desired-state snapshot, and
    /// the binding host comes from the intent the network service recorded at
    /// dispatch. Projection, reaping and release are idempotent: a replayed
    /// terminal update projects, reaps and releases the same state again.
    /// Integrity anomalies (a missing operation or resource, or an unparseable
    /// desired-state snapshot) are surfaced as warnings instead of failing the
    /// compute path.
    ///
    /// The one outcome a caller may need to act on is a failed *endpoint
    /// release* after a terminal delete: that is a live, consumable side effect
    /// left behind, so it is reported as `Err` for the request-path delete
    /// callers to fail the mutation (and retry), while projections that no
    /// request is waiting on — the agent terminal-update consumer, the periodic
    /// sweep, the create poll surface — log it and leave the durable delete
    /// terminal. The next delete replay retries the release.
    pub(super) async fn project_terminal_binding_outcome(
        &self,
        operation_id: &str,
        state: o3k_store::OperationState,
    ) -> Result<(), ComputeError> {
        let Ok(operation_id) = Uuid::parse_str(operation_id) else {
            tracing::warn!(
                operation_id = %operation_id,
                "port binding outcome skipped: operation id is not a UUID"
            );
            return Ok(());
        };
        let Ok(operation) = self.store.get_operation(operation_id).await else {
            tracing::warn!(
                operation_id = %operation_id,
                "port binding outcome skipped: operation is missing from the durable store"
            );
            return Ok(());
        };
        // Terminal successful delete reaps the per-instance config-drive media
        // owned by this control plane (best-effort, idempotent, and independent
        // of the binding projector).
        if operation.kind == "lifecycle:delete" && state == o3k_store::OperationState::Succeeded {
            self.cleanup_config_drive_best_effort(&operation.resource_id.to_string());
        }
        let Some(projector) = self.binding_projector.as_ref() else {
            return Ok(());
        };
        let Ok(resource) = self.store.get_resource(operation.resource_id).await else {
            tracing::warn!(
                operation_id = %operation_id,
                resource_id = %operation.resource_id,
                "port binding outcome skipped: server resource is missing from the durable store"
            );
            return Ok(());
        };
        let Ok(request) = serde_json::from_str::<CreateInstanceRequest>(&resource.desired_state)
        else {
            tracing::warn!(
                operation_id = %operation_id,
                resource_id = %operation.resource_id,
                "port binding outcome skipped: server create intent is corrupt"
            );
            return Ok(());
        };
        for port_id in &request.network_ids {
            let outcome = match operation.kind.as_str() {
                "create" => {
                    projector
                        .project_create_outcome(
                            &request.project_id,
                            port_id,
                            state == o3k_store::OperationState::Succeeded,
                        )
                        .await
                }
                "lifecycle:delete" if state == o3k_store::OperationState::Succeeded => {
                    let outcome = projector
                        .unbind_port(&request.project_id, port_id, operation_id)
                        .await;
                    // The endpoint may be released only after its binding was
                    // cleared: the fabric teardown plan reads the durable
                    // endpoint (address, MAC, realm) it has to remove. A failed
                    // unbind therefore keeps the endpoint, so a later delete
                    // replay can still tear the fabric down and then release.
                    if outcome.is_ok() {
                        projector
                            .release_server_owned_endpoint(&request.project_id, port_id)
                            .await
                            .map_err(|error| {
                                ComputeError::EndpointRelease(format!(
                                    "server endpoint {port_id} could not be released: {error}"
                                ))
                            })?;
                    }
                    outcome
                }
                _ => continue,
            };
            if let Err(error) = outcome {
                tracing::warn!(
                    operation_id = %operation_id,
                    resource_id = %operation.resource_id,
                    port_id = %port_id,
                    error = %error,
                    "port binding outcome projection rejected"
                );
            }
        }
        Ok(())
    }

    /// Projects a terminal outcome that no request is waiting on.
    ///
    /// A failed server-owned endpoint release after a terminal delete is
    /// logged: the durable delete stays terminal, the integration anomaly is
    /// observable, and the next delete replay retries the release. Request-path
    /// delete callers use `project_terminal_binding_outcome` directly so they
    /// can fail the mutation instead.
    pub(super) async fn project_terminal_outcome_best_effort(
        &self,
        operation_id: &str,
        state: o3k_store::OperationState,
    ) {
        if let Err(error) = self
            .project_terminal_binding_outcome(operation_id, state)
            .await
        {
            tracing::warn!(
                operation_id = %operation_id,
                error = %error,
                "terminal projection could not release a server-owned endpoint; a delete replay retries it"
            );
        }
    }

    /// Releases the O3K-owned endpoints named by the server's durable create
    /// intent, after an unbind cleared their bindings.
    ///
    /// This is the retry seat for the delete mutation path: a transient failure
    /// is reported to the caller (a failed delete mutation) and the next replay
    /// of the same delete re-runs the release, which is idempotent because an
    /// already-absent endpoint is success. Endpoints that are not O3K
    /// server-owned — a port the caller supplied itself — are left untouched.
    ///
    /// #1035 backstop: a port a NEW live server has explicitly attached must
    /// never be released by replaying the terminally-deleted owner's delete.
    /// The replay's preceding unbind clears the port's durable binding, so a
    /// binding check alone cannot see the live attachment; the same
    /// non-terminal attachment set the sweep uses is consulted instead and a
    /// port any live server still references is left for that server's own
    /// delete to release.
    pub(super) async fn release_server_endpoints_from_intent(
        &self,
        request: &CreateInstanceRequest,
    ) -> Result<(), ComputeError> {
        let Some(projector) = self.binding_projector.as_ref() else {
            return Ok(());
        };
        let attached = self.referenced_port_ids().await?;
        for port_id in &request.network_ids {
            if attached.contains(port_id.as_str()) {
                continue;
            }
            projector
                .release_server_owned_endpoint(&request.project_id, port_id)
                .await
                .map_err(|error| ComputeError::EndpointRelease(error.to_string()))?;
        }
        Ok(())
    }

    /// The identifiers of the endpoints every non-terminally-deleted compute
    /// instance references, built from a fresh durable scan of the compute
    /// realm. A tenant may explicitly attach an existing project port — even a
    /// server-owned one — to a running server, so a deleted server's stale
    /// create intent can name an endpoint a live guest now depends on. Neither
    /// the orphan repair sweep nor a delete replay may release a port in this
    /// set; the live server's own delete releases it.
    async fn referenced_port_ids(&self) -> Result<std::collections::HashSet<String>, ComputeError> {
        let mentioned_deleted = server_state_to_storage(ServerState::Deleted);
        let resources = self
            .store
            .list_resources_by_kind("compute_instance")
            .await?;
        let mut referenced: std::collections::HashSet<String> = std::collections::HashSet::new();
        for resource in &resources {
            if resource.observed_state == mentioned_deleted {
                continue;
            }
            if let Ok(request) =
                serde_json::from_str::<CreateInstanceRequest>(&resource.desired_state)
            {
                referenced.extend(request.network_ids.iter().cloned());
            }
        }
        Ok(referenced)
    }

    /// Public form of [`Self::referenced_port_ids`] for a delete handler that
    /// runs a direct network-side release after the canonical delete. Such a
    /// handler must not hand a port back to the network release when a NEW live
    /// server has explicitly attached it, or the replayed/repeated delete would
    /// strip the live server's NIC (#1035).
    pub async fn live_attached_endpoint_ids(
        &self,
    ) -> Result<std::collections::HashSet<String>, ComputeError> {
        self.referenced_port_ids().await
    }

    /// Clears the binding of every port named by the server's durable create
    /// intent. Used when a delete reached terminal success, including the
    /// already-deleted shortcut, where the delete completed in a previous
    /// run. Best-effort and idempotent like `project_terminal_binding_outcome`.
    ///
    /// #1035 backstop (delete-replay seat): a port a NEW live server has
    /// explicitly re-attached must never be unbound here, or the replay tears
    /// down the live server's NIC before release even runs. The same
    /// non-terminal attachment set the sweep uses is consulted and such a port
    /// is skipped; on scan failure nothing is unbound (fail closed) rather than
    /// risk clearing a binding a live server depends on.
    pub(super) async fn unbind_ports_from_intent(
        &self,
        request: &CreateInstanceRequest,
        operation_id: uuid::Uuid,
    ) {
        let Some(projector) = self.binding_projector.as_ref() else {
            return;
        };
        let attached = match self.referenced_port_ids().await {
            Ok(set) => set,
            Err(error) => {
                tracing::warn!(
                    resource_id = %request.o3k_server_id,
                    error = ?error,
                    "port unbind skipped: live-server attachment set unavailable"
                );
                return;
            }
        };
        for port_id in &request.network_ids {
            if attached.contains(port_id.as_str()) {
                continue;
            }
            if let Err(error) = projector
                .unbind_port(&request.project_id, port_id, operation_id)
                .await
            {
                tracing::warn!(
                    resource_id = %request.o3k_server_id,
                    port_id = %port_id,
                    error = %error,
                    "port unbind projection rejected"
                );
            }
        }
    }

    /// Applies the same reverse-order compensation as the synchronous create
    /// path when a create operation is terminal Failed after the API request
    /// already returned. Compensation is idempotent: keypair detach is a
    /// delete-if-present and the placement allocation is released only when
    /// it is still held, so replayed deliveries and repeated convergence
    /// triggers are safe.
    pub(super) async fn compensate_failed_create(
        &self,
        operation_id: Uuid,
    ) -> Result<(), ComputeError> {
        let operation = self.store.get_operation(operation_id).await?;
        if operation.kind != "create" {
            return Ok(());
        }
        let resource = self.store.get_resource(operation.resource_id).await?;
        self.store.detach_server_keypair(resource.id).await?;
        let request: CreateInstanceRequest = serde_json::from_str(&resource.desired_state)
            .map_err(|_| ComputeError::InvalidRequest)?;
        if let (Some(scheduler), Some(provider_id), Some(allocation_id)) = (
            self.scheduler.as_ref(),
            request.placement_provider_id.as_deref(),
            request.placement_allocation_id.as_deref(),
        ) && scheduler
            .validate_allocation(provider_id, allocation_id, &resource.id.to_string())
            .await
            .is_ok()
        {
            self.release_placement_allocation(resource.id, &request)
                .await?;
        }
        Ok(())
    }

    /// Projects a synchronously observed terminal create failure onto the
    /// canonical resource. The direct create API can drive the journal in the
    /// request path (rather than through the read-side convergence loop), so
    /// it must not leave a failed operation visible as REQUESTED forever.
    pub(super) async fn project_failed_create_error(
        &self,
        resource_id: Uuid,
    ) -> Result<(), ComputeError> {
        let resource = self.store.get_resource(resource_id).await?;
        if resource.observed_state == server_state_to_storage(ServerState::Error) {
            return Ok(());
        }
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
        Ok(())
    }

    pub async fn apply_agent_acceptance(
        &self,
        accepted: &o3k_provider::AgentCommandAccepted,
    ) -> Result<o3k_store::OperationState, ComputeError> {
        Ok(self.journal.apply_agent_acceptance(accepted).await?)
    }

    /// Applies an authenticated provider observation to the durable resource
    /// projection. This is separate from operation progress because a command
    /// may succeed while the provider remains stopped, deleting, or errored.
    pub async fn apply_agent_observation(
        &self,
        observation: &o3k_provider::AgentObservation,
    ) -> Result<(), ComputeError> {
        let operation = self.store.get_operation(observation.operation_id).await?;
        self.journal.apply_agent_observation(observation).await?;

        // Canonical deletes may return before the provider command has
        // finished.  The terminal provider observation is therefore the
        // durable point at which placement can be released.  Keep this
        // idempotent: the synchronous delete path may already have released
        // the allocation before a duplicate observation arrives.
        if operation.kind == "lifecycle:delete"
            && observation.state == o3k_provider::InstanceState::Deleted
        {
            let resource = self.store.get_resource(observation.resource_id).await?;
            let request: CreateInstanceRequest = serde_json::from_str(&resource.desired_state)
                .map_err(|_| ComputeError::InvalidRequest)?;
            if let (Some(scheduler), Some(provider_id), Some(allocation_id)) = (
                self.scheduler.as_ref(),
                request.placement_provider_id.as_deref(),
                request.placement_allocation_id.as_deref(),
            ) && scheduler
                .validate_allocation(provider_id, allocation_id, &resource.id.to_string())
                .await
                .is_ok()
            {
                self.release_placement_allocation(resource.id, &request)
                    .await?;
            }
        }
        Ok(())
    }

    /// Starts the in-memory event bridge used by the control-plane binary.
    /// The journal remains the recovery authority; this task only applies live
    /// updates received from an authenticated agent connection.
    pub fn spawn_agent_event_consumer(
        &self,
        registry: Arc<dyn AgentNodeRegistry>,
    ) -> tokio::task::JoinHandle<()> {
        let mut events = registry.subscribe_events();
        let service = self.clone();
        tokio::spawn(async move {
            loop {
                match events.recv().await {
                    Ok(o3k_provider::AgentEvent::Operation(update)) => {
                        if let Err(error) = service.apply_agent_update(&update).await {
                            tracing::warn!(error = ?error, "agent operation update rejected");
                        }
                    }
                    Ok(o3k_provider::AgentEvent::CommandAccepted(accepted)) => {
                        if let Err(error) = service.apply_agent_acceptance(&accepted).await {
                            tracing::warn!(error = ?error, "agent command acceptance rejected");
                        }
                    }
                    Ok(o3k_provider::AgentEvent::Observation(observation)) => {
                        let current_epoch = registry
                            .snapshot(&observation.agent_id)
                            .await
                            .map(|node| node.agent_epoch);
                        if current_epoch.as_deref() != Some(observation.agent_epoch.as_str()) {
                            tracing::warn!(
                                agent_id = %observation.agent_id,
                                agent_epoch = %observation.agent_epoch,
                                current_epoch = ?current_epoch,
                                "ignored observation from a replaced agent epoch"
                            );
                            continue;
                        }
                        if let Err(error) = service.apply_agent_observation(&observation).await {
                            tracing::warn!(
                                error = ?error,
                                operation_id = %observation.operation_id,
                                resource_id = %observation.resource_id,
                                agent_id = %observation.agent_id,
                                agent_epoch = %observation.agent_epoch,
                                operation_state = ?observation.operation_state,
                                state = ?observation.state,
                                provider_resource_id = ?observation.provider_resource_id,
                                observation_sequence = observation.observation_sequence,
                                "agent resource observation rejected"
                            );
                        }
                    }
                    Ok(_) => {}
                    Err(tokio::sync::broadcast::error::RecvError::Lagged(count)) => {
                        tracing::warn!(
                            count,
                            "agent event consumer lagged; durable recovery required"
                        );
                    }
                    Err(tokio::sync::broadcast::error::RecvError::Closed) => {
                        tracing::warn!("agent event stream closed");
                        break;
                    }
                }
            }
        })
    }

    /// Drives durable attachment recovery after restart or an unknown outcome.
    ///
    /// The attachment orchestrator persists every phase before executing an
    /// external side effect. On restart, in-flight or unknown-outcome records
    /// must converge by observing the Cinder and compute boundaries rather than
    /// re-running mutations blindly. This bounded periodic task is the
    /// production caller for `AttachmentOrchestrator::reconcile`.
    pub fn spawn_attachment_reconciler(&self, interval_secs: u64) -> tokio::task::JoinHandle<()> {
        let service = self.clone();
        tokio::spawn(async move {
            let mut interval = tokio::time::interval(Duration::from_secs(interval_secs));
            interval.tick().await;
            loop {
                interval.tick().await;
                if let Some((coordination, controller_id, controller_epoch)) = &service.coordination
                {
                    let work_key = "reconcile:volume_attachments";
                    match coordination
                        .acquire_work_lease(
                            work_key,
                            "reconciler",
                            controller_id,
                            controller_epoch,
                            Duration::from_secs(15),
                        )
                        .await
                    {
                        Ok(o3k_store::LeaseAcquireOutcome::Acquired { lease }) => {
                            if let Err(error) = service.attachment_orchestrator().reconcile().await
                            {
                                tracing::warn!(%error, "attachment reconcile pass failed");
                            }
                            let _ = coordination
                                .release_work_lease(
                                    work_key,
                                    controller_id,
                                    controller_epoch,
                                    lease.fencing_token,
                                )
                                .await;
                        }
                        Ok(o3k_store::LeaseAcquireOutcome::Busy { .. }) => {
                            tracing::debug!(
                                "attachment reconcile is currently leased by another controller; skipping"
                            );
                        }
                        Err(error) => {
                            tracing::warn!(%error, "failed to acquire attachment reconcile lease");
                        }
                    }
                } else if let Err(error) = service.attachment_orchestrator().reconcile().await {
                    tracing::warn!(%error, "attachment reconcile pass failed");
                }
            }
        })
    }

    /// Periodically drives create convergence for servers left in a state
    /// that nothing else will ever advance: `Pending`, `UnknownOutcome`, or
    /// `Running` without a provider operation identity (issue-87 S1 residue —
    /// a crash between persisting `Running` and dispatching the create).
    /// After a control-plane restart the lazy show path alone would leave
    /// such a server stuck in REQUESTED (and its placement allocation leaked)
    /// until a client polls it; this bounded periodic task is the recovery
    /// authority. Each pass is lazy and idempotent: terminal and accepted
    /// operations are skipped by `drive_create_convergence`, and the
    /// reconciler reuses in-flight and terminal provider work by the
    /// deterministic operation identity.
    pub fn spawn_create_convergence_reconciler(
        &self,
        interval_secs: u64,
    ) -> tokio::task::JoinHandle<()> {
        let service = self.clone();
        tokio::spawn(async move {
            let mut interval = tokio::time::interval(Duration::from_secs(interval_secs));
            interval.tick().await;
            loop {
                interval.tick().await;
                tracing::debug!("create convergence sweep tick");
                if let Err(error) = service.drive_all_create_convergence().await {
                    tracing::warn!(%error, "create convergence reconcile pass failed");
                }
            }
        })
    }

    /// Drives create convergence for every durable compute instance, then
    /// expires artifact transfers abandoned by operations that have already
    /// reached a terminal state (issue #88). The per-resource drive is lazy
    /// and bounded, so healthy servers are skipped and a stuck server
    /// converges regardless of which project owns it.
    pub(super) async fn drive_all_create_convergence(&self) -> Result<(), ComputeError> {
        let resources = self
            .store
            .list_resources_by_kind("compute_instance")
            .await?;
        for resource in resources {
            if let Some((coordination, controller_id, controller_epoch)) = &self.coordination {
                let work_key = format!("convergence:create:{}", resource.id);
                match coordination
                    .acquire_work_lease(
                        &work_key,
                        "convergence",
                        controller_id,
                        controller_epoch,
                        Duration::from_secs(15),
                    )
                    .await
                {
                    Ok(o3k_store::LeaseAcquireOutcome::Acquired { lease }) => {
                        self.drive_create_convergence(&resource).await;
                        let _ = coordination
                            .release_work_lease(
                                &work_key,
                                controller_id,
                                controller_epoch,
                                lease.fencing_token,
                            )
                            .await;
                    }
                    Ok(o3k_store::LeaseAcquireOutcome::Busy { .. }) => {
                        tracing::debug!(
                            resource_id = %resource.id,
                            "create convergence is currently leased by another controller; skipping"
                        );
                    }
                    Err(error) => {
                        tracing::warn!(
                            resource_id = %resource.id,
                            %error,
                            "failed to acquire create convergence lease; skipping"
                        );
                    }
                }
            } else {
                self.drive_create_convergence(&resource).await;
            }
        }
        // Issue #88: an operation can reach a terminal state while its
        // artifact handshake rows are still `offered`/`receiving` (an agent
        // crash can strand them, and a terminalized operation is never driven
        // again), so no per-operation path ever advances them. This per-pass
        // sweep expires exactly those rows. Best-effort and idempotent:
        // repeated passes expire nothing, committed/rejected/expired rows are
        // never touched, and a failure is a warning, not a sweep abort.
        if let Err(error) = self.store.expire_transfers_of_terminal_operations().await {
            tracing::warn!(%error, "artifact transfer expiry sweep failed");
        }
        Ok(())
    }

    /// Periodically drives lifecycle convergence for operations left in a
    /// state that nothing else will ever advance. A lifecycle operation can
    /// be stranded non-terminal by an unknown delete/action outcome
    /// (issue-88 B1: the delete undefine raced a libvirtd restart, the agent
    /// reported unknown, the API's synchronous 10s poll has long returned,
    /// and the event stream rejects non-Succeeded observations), and no path
    /// ever calls `reconcile_lifecycle_once` again — the resource stays
    /// ACTIVE, the API delete retry 409s, and every owned residue (op row,
    /// command row, allocation, config-drive media) is held. This bounded
    /// periodic task is the recovery authority, mirroring the
    /// create-convergence sweep. Each pass is lazy and idempotent: terminal
    /// operations are not listed, in-flight operations are skipped, and
    /// re-dispatches reuse the durable command row and the deterministic
    /// `o3k-operation-{id}` idempotency key.
    pub fn spawn_lifecycle_convergence_reconciler(
        &self,
        interval_secs: u64,
    ) -> tokio::task::JoinHandle<()> {
        let service = self.clone();
        tokio::spawn(async move {
            let mut interval = tokio::time::interval(Duration::from_secs(interval_secs));
            interval.tick().await;
            loop {
                interval.tick().await;
                if let Err(error) = service.drive_all_lifecycle_convergence().await {
                    tracing::warn!(%error, "lifecycle convergence reconcile pass failed");
                }
            }
        })
    }

    /// Drives lifecycle convergence for every non-terminal lifecycle
    /// operation. The per-operation drive is lazy and bounded, so healthy
    /// operations are skipped and a stranded operation converges regardless
    /// of which project owns it.
    pub(super) async fn drive_all_lifecycle_convergence(&self) -> Result<(), ComputeError> {
        let operations = self.store.list_non_terminal_lifecycle_operations().await?;
        for operation in operations {
            // Issue #88 B1: re-drive exactly the states nothing else will
            // ever advance — `Pending`, `UnknownOutcome` (observed, not
            // re-dispatched: presence inspection and adoption decide),
            // `Retryable` (the #572 retry-scheduling addition), and
            // `Running` without a provider operation identity (a crash
            // between persisting `Running` and dispatching). A `Running`
            // operation WITH the identity was accepted and is in flight: the
            // agent event stream terminalizes it, and a re-dispatch would
            // race it on the same operation records.
            let re_drive = matches!(
                operation.state,
                o3k_store::OperationState::Pending
                    | o3k_store::OperationState::UnknownOutcome
                    | o3k_store::OperationState::Retryable
            ) || (operation.state == o3k_store::OperationState::Running
                && operation.provider_operation_id.is_none());
            if !re_drive {
                continue;
            }
            if let Some((coordination, controller_id, controller_epoch)) = &self.coordination {
                let work_key = format!("operation:{}", operation.id);
                match coordination
                    .acquire_work_lease(
                        &work_key,
                        "operation",
                        controller_id,
                        controller_epoch,
                        Duration::from_secs(15),
                    )
                    .await
                {
                    Ok(o3k_store::LeaseAcquireOutcome::Acquired { lease }) => {
                        if let Err(error) =
                            self.journal.reconcile_lifecycle_once(operation.id).await
                        {
                            tracing::warn!(
                                operation_id = %operation.id,
                                resource_id = %operation.resource_id,
                                error = %error,
                                "server lifecycle convergence pass failed; server state is unchanged"
                            );
                        }
                        let _ = coordination
                            .release_work_lease(
                                &work_key,
                                controller_id,
                                controller_epoch,
                                lease.fencing_token,
                            )
                            .await;
                    }
                    Ok(o3k_store::LeaseAcquireOutcome::Busy { .. }) => {
                        tracing::debug!(
                            operation_id = %operation.id,
                            "lifecycle operation is currently leased by another controller; skipping"
                        );
                    }
                    Err(error) => {
                        tracing::warn!(
                            operation_id = %operation.id,
                            %error,
                            "failed to acquire lifecycle operation lease; skipping"
                        );
                    }
                }
            } else if let Err(error) = self.journal.reconcile_lifecycle_once(operation.id).await {
                tracing::warn!(
                    operation_id = %operation.id,
                    resource_id = %operation.resource_id,
                    error = %error,
                    "server lifecycle convergence pass failed; server state is unchanged"
                );
            }
        }
        // #1035: the same bounded pass is the repair authority for endpoints
        // orphaned by an interrupted terminal delete. Listing non-terminal
        // operations above cannot see them, because the delete is already
        // terminal and the endpoint release never ran.
        if let Err(error) = self.repair_orphaned_server_endpoints().await {
            tracing::warn!(%error, "server-owned endpoint orphan repair pass failed");
        }
        Ok(())
    }

    /// Repairs server-owned endpoints orphaned by an interrupted terminal
    /// delete (#1035).
    ///
    /// The crash window:
    ///
    /// ```text
    /// canonical delete reaches durable terminal success
    ///   -> process dies before the request-path endpoint release
    ///   -> the server is DELETED but its `o3k-server:` endpoint stays behind
    /// ```
    ///
    /// Such an endpoint blocks network teardown, and nothing else repairs it:
    /// the periodic sweep above only lists **non-terminal** lifecycle
    /// operations, and the delete *replay* seat
    /// (`release_server_endpoints_from_intent`) needs a request to arrive.
    ///
    /// This is repair-only. The synchronous request-path release stays
    /// authoritative; this pass is idempotent, so it converges whether it runs
    /// once, repeatedly, or concurrently with a request-path delete and with
    /// another reconciler.
    ///
    /// Scope is decided only by durable authority:
    ///
    /// - a server is considered only when its observed state is `DELETED`.
    ///   That state and the delete operation's terminal success are written in
    ///   ONE durable transaction (`DurableStore::terminalize_lifecycle`, issue
    ///   #1041), so a live, in-flight or non-terminal server is never
    ///   repaired, and a crashed control plane can no longer leave the delete
    ///   terminal while this marker is absent. Keying on the later marker is
    ///   deliberate — it is the only one that means the guest is gone;
    /// - an endpoint is released only when the durable endpoint row resolves
    ///   inside the server's own project **and** carries O3K's reserved
    ///   server-owned identity. A caller-supplied endpoint is preserved and a
    ///   foreign endpoint is never touched, even though the create intent
    ///   names both;
    /// - an endpoint is released only when no **non-terminal** server still
    ///   references it. The reserved identity answers "who may release this
    ///   name", not "is this endpoint still in use": a tenant may explicitly
    ///   attach an existing project port — including a server-owned one — to a
    ///   new server, so a deleted server's stale create intent can name an
    ///   endpoint a running guest now depends on. Such an endpoint is counted
    ///   as still attached and left alone; its own server's delete releases it.
    ///
    /// Bounded observability: one `info` line per pass that actually
    /// discovered or repaired something, with a fixed field set, plus a
    /// `warn` per failing server. A pass with nothing to repair stays at
    /// `debug` so a healthy system does not fill the log.
    pub(super) async fn repair_orphaned_server_endpoints(&self) -> Result<(), ComputeError> {
        let Some(projector) = self.binding_projector.as_ref() else {
            return Ok(());
        };
        let resources = self
            .store
            .list_resources_by_kind("compute_instance")
            .await?;
        // Endpoints a non-terminal server still references. Built from the same
        // durable scan, so the guard needs no extra read and no extra authority.
        let still_attached = self.referenced_port_ids().await?;
        let deleted_state = server_state_to_storage(ServerState::Deleted);
        let mut discovered = 0usize;
        let mut released = 0usize;
        let mut preserved = 0usize;
        let mut absent = 0usize;
        let mut failures = 0usize;
        let mut skipped_attached = 0usize;
        let mut deleted_servers = 0usize;
        for resource in resources {
            if resource.observed_state != deleted_state {
                continue;
            }
            let Ok(request) =
                serde_json::from_str::<CreateInstanceRequest>(&resource.desired_state)
            else {
                failures += 1;
                tracing::warn!(
                    resource_id = %resource.id,
                    "terminally deleted server has an undecodable create intent; orphan endpoint repair skipped"
                );
                continue;
            };
            deleted_servers += 1;
            for port_id in &request.network_ids {
                // Fast path: the pass-start scan already knows a live server
                // references this endpoint.
                if still_attached.contains(port_id.as_str()) {
                    skipped_attached += 1;
                    continue;
                }
                // Release-time re-read: closes the F1 same-pass TOCTOU properly
                // instead of relying on the pass-start scan alone. A re-attacher
                // whose durable create has committed is caught here regardless
                // of binding realization; a re-attacher whose create has NOT
                // committed yet is not attached in any durable sense, so
                // releasing the orphan then is correct.
                let attached_now = self.referenced_port_ids().await?;
                if attached_now.contains(port_id.as_str()) {
                    skipped_attached += 1;
                    continue;
                }
                // Restore the request-path invariant for a genuine bound orphan:
                // the process may have died after the delete terminalized but
                // BEFORE the fabric unbind, leaving the port still `bound`. Such
                // an endpoint must be unbound first (the projector dispatches the
                // agent-side Remove and records the `down` tombstone), then
                // released. The durable row is resolved first so a caller-
                // supplied or foreign endpoint is never unbound.
                match projector.port_binding(&resource.project_id, port_id).await {
                    Ok(Some(info))
                        if info.server_owned
                            && matches!(
                                info.binding_state.as_deref(),
                                Some("bound") | Some("binding")
                            ) =>
                    {
                        let operation_id = Uuid::new_v5(
                            &Uuid::NAMESPACE_URL,
                            format!("o3k:orphan-unbind:{}:{}", resource.id, port_id).as_bytes(),
                        );
                        if let Err(error) = projector
                            .unbind_port(&resource.project_id, port_id, operation_id)
                            .await
                        {
                            failures += 1;
                            tracing::warn!(
                                resource_id = %resource.id,
                                project_id = %resource.project_id,
                                port_id = %port_id,
                                %error,
                                "orphaned server-owned endpoint is still bound and could not be \
                                 unbound; the next pass retries it (fail closed, never deleted \
                                 while bound)"
                            );
                            continue;
                        }
                    }
                    Ok(Some(_)) => {}
                    Ok(None) => {}
                    Err(error) => {
                        failures += 1;
                        tracing::warn!(
                            resource_id = %resource.id,
                            project_id = %resource.project_id,
                            port_id = %port_id,
                            %error,
                            "orphaned server-owned endpoint binding could not be resolved; the \
                             next pass retries it"
                        );
                        continue;
                    }
                }
                // The resource row owns the project scope; the create intent is
                // derived state and must not widen it. The binding fence in the
                // network release stays as defense-in-depth: after the unbind
                // above the port is `down`, so it passes.
                match projector
                    .release_server_owned_endpoint(&resource.project_id, port_id)
                    .await
                {
                    Ok(report) => {
                        discovered += report.discovered;
                        released += report.released;
                        preserved += report.preserved;
                        absent += report.absent;
                    }
                    Err(error) => {
                        failures += 1;
                        tracing::warn!(
                            resource_id = %resource.id,
                            project_id = %resource.project_id,
                            port_id = %port_id,
                            %error,
                            "orphaned server-owned endpoint could not be repaired; the next pass retries it"
                        );
                    }
                }
            }
        }
        if released > 0 || failures > 0 || skipped_attached > 0 {
            tracing::info!(
                deleted_servers,
                discovered,
                released,
                preserved,
                absent,
                failures,
                skipped_attached,
                "server-owned endpoint orphan repair sweep"
            );
        } else {
            tracing::debug!(
                deleted_servers,
                discovered,
                released,
                preserved,
                absent,
                failures,
                skipped_attached,
                "server-owned endpoint orphan repair sweep found nothing to repair"
            );
        }
        Ok(())
    }
}
