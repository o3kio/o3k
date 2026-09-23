use super::{
    AuthContext, BTreeSet, ComputeError, ComputeProvider, ComputeService, CreateInstanceRequest,
    DeleteInstanceRequest, Duration, InstanceAction, LifecycleAction, MutationReceipt,
    ProviderError, ReconcileError, ResourceId, ResourceTarget, ResourceType, Scheduler,
    SchedulerFlavor, Server, ServerId, ServerState, StoreError, Uuid, test_fault_pause_ms,
};

use o3k_kernel::{ActionId, AuditEvent, AuditOutcome, AuthorizationRequest, ServiceNamespace};
use o3k_reconciler::CanonicalMutationContext;
use o3k_store::{server_state_from_storage, server_state_to_storage};

impl ComputeService {
    /// Authorize a canonical resource mutation at the application boundary.
    /// Compatibility and native handlers may both call this guard, so policy
    /// cannot be bypassed by invoking the application port directly.
    pub fn authorize_resource_action(
        &self,
        auth: &AuthContext,
        id: ServerId,
        action: ActionId,
    ) -> bool {
        let Ok(resource_type) = ResourceType::new("compute", "server") else {
            return false;
        };
        let Ok(resource_id) = ResourceId::new(id.as_uuid().to_string()) else {
            return false;
        };
        self.authorizer
            .authorize(&AuthorizationRequest {
                auth_context: auth,
                action: action.clone(),
                resource_target: ResourceTarget::instance(
                    resource_type,
                    resource_id,
                    Some(auth.effective_scope().id().clone()),
                ),
            })
            .is_allowed()
    }

    /// Executes a declared server domain action through the same canonical
    /// lifecycle journal used by native and compatibility callers.
    pub async fn action_for_auth_canonical(
        &self,
        auth: &AuthContext,
        id: ServerId,
        action: InstanceAction,
        context: CanonicalMutationContext,
    ) -> Result<MutationReceipt<ServerId>, ComputeError> {
        let action_name = match action {
            InstanceAction::Start => "StartServer",
            InstanceAction::Stop => "StopServer",
            InstanceAction::Reboot => "RebootServer",
        };
        let expected = ActionId::new_unchecked("compute", action_name);
        if context.action != expected
            || context.actor != auth.principal().id().as_str()
            || context.owner_scope.id().as_str() != auth.effective_scope().id().as_str()
        {
            return Err(ComputeError::InvalidRequest);
        }
        let target = ResourceTarget::instance(
            ResourceType::new("compute", "server").map_err(|_| ComputeError::InvalidRequest)?,
            ResourceId::new(id.as_uuid().to_string()).map_err(|_| ComputeError::InvalidRequest)?,
            Some(auth.effective_scope().id().clone()),
        );
        if !self
            .authorizer
            .authorize(&AuthorizationRequest {
                auth_context: auth,
                action: expected.clone(),
                resource_target: target,
            })
            .is_allowed()
        {
            let event = AuditEvent::from_auth(
                auth,
                ServiceNamespace::new_unchecked("compute".to_owned()),
                expected.clone(),
                AuditOutcome::Denied,
            )
            .with_reason("unauthorized");
            self.record_required_audit(&event).await?;
            return Err(ComputeError::NotFound);
        }
        let resource =
            self.store
                .get_resource(id.as_uuid())
                .await
                .map_err(|error| match error {
                    StoreError::ResourceNotFound => ComputeError::NotFound,
                    other => ComputeError::Store(other),
                })?;
        if resource.project_id != auth.effective_scope().id().as_str()
            || resource.provider_id.is_none()
        {
            return Err(ComputeError::NotFound);
        }
        let lifecycle_action = match action {
            InstanceAction::Start => LifecycleAction::Start,
            InstanceAction::Stop => LifecycleAction::Stop,
            InstanceAction::Reboot => LifecycleAction::Reboot,
        };
        let operation_id = Uuid::new_v5(
            &Uuid::NAMESPACE_URL,
            format!(
                "o3k:canonical-action:{}:{}:{}:{}",
                resource.project_id, id, expected, context.idempotency_key
            )
            .as_bytes(),
        );
        let acceptance = self
            .journal
            .begin_canonical_lifecycle(id.as_uuid(), operation_id, lifecycle_action, &context)
            .await
            .map_err(|error| match error {
                ReconcileError::Store(StoreError::ResourceAlreadyExists) => ComputeError::Conflict,
                other => ComputeError::Reconcile(other),
            })?;
        let replayed = match acceptance {
            o3k_store::CanonicalAcceptanceOutcome::Conflict => return Err(ComputeError::Conflict),
            o3k_store::CanonicalAcceptanceOutcome::ExistingEquivalent {
                operation_id: existing,
                resource_id,
            } => {
                let operation = self.store.get_operation(existing).await?;
                return Ok(MutationReceipt {
                    resource: ServerId::from_uuid(resource_id),
                    operation_id: existing,
                    operation_state: operation.state,
                    replayed: true,
                });
            }
            o3k_store::CanonicalAcceptanceOutcome::Created { .. } => false,
        };
        let current = server_state_from_storage(&resource.observed_state)
            .map_err(|_| ComputeError::Conflict)?;
        match (action, current) {
            (InstanceAction::Start, ServerState::Stopped)
            | (InstanceAction::Stop, ServerState::Active)
            | (InstanceAction::Reboot, ServerState::Active | ServerState::Stopped) => {}
            _ => {
                let lifecycle = o3k_store::CanonicalOperationLifecycleUpdate::new(
                    o3k_kernel::OperationState::Failed,
                    1,
                    None,
                    Some(chrono::Utc::now().to_rfc3339()),
                    Some("action not applicable to current resource state".to_owned()),
                )
                .map_err(ComputeError::Store)?;
                self.store
                    .update_canonical_operation_lifecycle(operation_id, &lifecycle)
                    .await
                    .map_err(ComputeError::Store)?;
                return Err(ComputeError::Conflict);
            }
        }
        let operation_state = self
            .reconcile_lifecycle_until_terminal(operation_id)
            .await?;
        let outcome = match operation_state {
            o3k_store::OperationState::Succeeded => AuditOutcome::Succeeded,
            o3k_store::OperationState::Failed => AuditOutcome::Failed,
            _ => AuditOutcome::UnknownOutcome,
        };
        let event = AuditEvent::from_auth(
            auth,
            ServiceNamespace::new_unchecked("compute".to_owned()),
            expected,
            outcome,
        )
        .with_resource(
            ResourceType::new_unchecked("compute".to_owned(), "server".to_owned()),
            ResourceId::new(id.as_uuid().to_string()).ok(),
            Some(auth.effective_scope().clone()),
        )
        .with_operation(operation_id);
        self.record_required_audit(&event).await?;
        Ok(MutationReceipt {
            resource: id,
            operation_id,
            operation_state,
            replayed,
        })
    }

    pub async fn placement_provider_id(
        &self,
        project_id: &str,
        id: ServerId,
    ) -> Result<Option<String>, ComputeError> {
        let resource = self.store.get_resource(id.as_uuid()).await?;
        if resource.kind != "compute_instance" || resource.project_id != project_id {
            return Err(ComputeError::NotFound);
        }
        let request: CreateInstanceRequest =
            serde_json::from_str(&resource.desired_state).map_err(|_| ComputeError::Conflict)?;
        Ok(request.placement_provider_id)
    }

    pub async fn delete_server_for_auth(
        &self,
        auth: &AuthContext,
        id: ServerId,
    ) -> Result<(), ComputeError> {
        let ns = ServiceNamespace::new("compute")
            .unwrap_or_else(|_| ServiceNamespace::new_unchecked("compute".to_owned()));
        let act = ActionId::new("compute", "DeleteServer").unwrap_or_else(|_| {
            ActionId::new_unchecked("compute".to_owned(), "DeleteServer".to_owned())
        });
        let req = AuthorizationRequest {
            auth_context: auth,
            action: act.clone(),
            resource_target: ResourceTarget::instance(
                ResourceType::new("compute", "server").map_err(|_| ComputeError::InvalidRequest)?,
                ResourceId::new(id.as_uuid().to_string())
                    .map_err(|_| ComputeError::InvalidRequest)?,
                Some(auth.effective_scope().id().clone()),
            ),
        };
        let decision = self.authorizer.authorize(&req);
        if !decision.is_allowed() {
            let event = AuditEvent::from_auth(auth, ns, act, AuditOutcome::Denied)
                .with_decision(decision)
                .with_reason("unauthorized");
            self.record_required_audit(&event).await?;
            return Err(ComputeError::NotFound);
        }
        match self
            .delete_server(auth.effective_scope().id().as_str(), id)
            .await
        {
            Ok(()) => {
                let event = AuditEvent::from_auth(auth, ns, act, AuditOutcome::Succeeded)
                    .with_resource(
                        ResourceType::new("compute", "server").unwrap_or_else(|_| {
                            ResourceType::new_unchecked("compute".to_owned(), "server".to_owned())
                        }),
                        ResourceId::new(id.as_uuid().to_string()).ok(),
                        Some(auth.effective_scope().clone()),
                    );
                self.record_required_audit(&event).await?;
                Ok(())
            }
            Err(error) => {
                let event = AuditEvent::from_auth(auth, ns, act, AuditOutcome::Failed)
                    .with_reason(error.to_string());
                self.record_required_audit(&event).await?;
                Err(error)
            }
        }
    }

    pub async fn delete_server_for_auth_canonical(
        &self,
        auth: &AuthContext,
        id: ServerId,
        context: o3k_reconciler::CanonicalMutationContext,
    ) -> Result<MutationReceipt<ServerId>, ComputeError> {
        // CANONICAL INVARIANT: the canonical context's action must match the
        // expected mutation (InvalidRequest), while actor and owner_scope
        // must match the authenticated request (Unauthorized).
        if context.action.to_string() != "compute:DeleteServer" {
            return Err(ComputeError::InvalidRequest);
        }
        if context.actor != auth.principal().id().as_str()
            || context.owner_scope.id().as_str() != auth.effective_scope().id().as_str()
        {
            return Err(ComputeError::Unauthorized);
        }
        let action = context.action.clone();
        let target = ResourceTarget::instance(
            ResourceType::new("compute", "server").map_err(|_| ComputeError::InvalidRequest)?,
            ResourceId::new(id.to_string()).map_err(|_| ComputeError::InvalidRequest)?,
            Some(auth.effective_scope().id().clone()),
        );
        if !self
            .authorizer
            .authorize(&AuthorizationRequest {
                auth_context: auth,
                action: action.clone(),
                resource_target: target,
            })
            .is_allowed()
        {
            let event = AuditEvent::from_auth(
                auth,
                ServiceNamespace::new_unchecked("compute".to_owned()),
                action.clone(),
                AuditOutcome::Denied,
            )
            .with_reason("unauthorized");
            self.record_required_audit(&event).await?;
            return Err(ComputeError::NotFound);
        }
        let resource =
            self.store
                .get_resource(id.as_uuid())
                .await
                .map_err(|error| match error {
                    StoreError::ResourceNotFound => ComputeError::NotFound,
                    other => ComputeError::Store(other),
                })?;
        if resource.project_id != auth.effective_scope().id().as_str() {
            return Err(ComputeError::NotFound);
        }
        let operation_id = Uuid::new_v5(
            &Uuid::NAMESPACE_URL,
            format!(
                "o3k:canonical-delete:{}:{}:{}",
                resource.project_id, id, context.idempotency_key
            )
            .as_bytes(),
        );
        let acceptance = self
            .journal
            .begin_canonical_lifecycle(
                id.as_uuid(),
                operation_id,
                LifecycleAction::Delete,
                &context,
            )
            .await?;
        let replayed = match acceptance {
            o3k_store::CanonicalAcceptanceOutcome::Conflict => return Err(ComputeError::Conflict),
            o3k_store::CanonicalAcceptanceOutcome::ExistingEquivalent {
                operation_id: existing,
                resource_id,
            } => {
                let operation = self.store.get_operation(existing).await?;
                return Ok(MutationReceipt {
                    resource: ServerId::from_uuid(resource_id),
                    operation_id: existing,
                    operation_state: operation.state,
                    replayed: true,
                });
            }
            o3k_store::CanonicalAcceptanceOutcome::Created { .. } => false,
        };
        let operation_state = self
            .delete_server_with_accepted_operation(
                auth.effective_scope().id().as_str(),
                id,
                Some(operation_id),
            )
            .await?;
        let outcome = match operation_state {
            o3k_store::OperationState::Succeeded => AuditOutcome::Succeeded,
            o3k_store::OperationState::Failed => AuditOutcome::Failed,
            _ => AuditOutcome::UnknownOutcome,
        };
        let event = AuditEvent::from_auth(
            auth,
            ServiceNamespace::new_unchecked("compute".to_owned()),
            action,
            outcome,
        )
        .with_resource(
            ResourceType::new_unchecked("compute".to_owned(), "server".to_owned()),
            ResourceId::new(id.as_uuid().to_string()).ok(),
            Some(auth.effective_scope().clone()),
        )
        .with_operation(operation_id);
        self.record_required_audit(&event).await?;
        Ok(MutationReceipt {
            resource: id,
            operation_id,
            operation_state,
            replayed,
        })
    }

    pub async fn delete_server(&self, project_id: &str, id: ServerId) -> Result<(), ComputeError> {
        let state = self
            .delete_server_with_accepted_operation(project_id, id, None)
            .await?;
        if state != o3k_store::OperationState::Succeeded {
            return Err(ComputeError::Conflict);
        }
        Ok(())
    }

    /// Returns the operation state after a bounded execution pass.
    ///
    /// LEGACY callers (no accepted_operation_id) reconcile in a polling loop
    /// until the operation reaches terminal, then run compensatory cleanup and
    /// return `Ok(OperationState::Succeeded)` if completed, or
    /// `Err(ComputeError::Conflict)` if not.
    ///
    /// CANONICAL callers (with accepted_operation_id) perform one
    /// reconciliation pass and return the resulting state directly without
    /// blocking.  The caller maps `Succeeded → 204` and
    /// `Pending/Running/Retryable/UnknownOutcome → 202` in the native API
    /// adapter; compensatory cleanup runs only after terminal success.
    pub(super) async fn delete_server_with_accepted_operation(
        &self,
        project_id: &str,
        id: ServerId,
        accepted_operation_id: Option<Uuid>,
    ) -> Result<o3k_store::OperationState, ComputeError> {
        let resource =
            self.store
                .get_resource(id.as_uuid())
                .await
                .map_err(|error| match error {
                    StoreError::ResourceNotFound => ComputeError::NotFound,
                    other => ComputeError::Store(other),
                })?;
        if resource.project_id != project_id {
            return Err(ComputeError::NotFound);
        }
        // The destructive path must fail closed on corrupt lifecycle state:
        // deleting a row whose state cannot be decoded would dispatch a
        // provider delete on an unknown instance and overwrite the evidence
        // needed for repair. The decode error is propagated before any
        // lifecycle operation begins; only a decodable `Deleted` row takes
        // the already-deleted shortcut.
        let observed =
            server_state_from_storage(&resource.observed_state).map_err(ComputeError::Store)?;
        if observed == ServerState::Deleted {
            let intent: CreateInstanceRequest = serde_json::from_str(&resource.desired_state)
                .map_err(|_| ComputeError::Conflict)?;
            self.release_placement_allocation(id.as_uuid(), &intent)
                .await?;
            self.store.detach_server_keypair(id.as_uuid()).await?;
            self.unbind_ports_from_intent(
                &intent,
                accepted_operation_id.unwrap_or(intent.operation_id),
            )
            .await;
            // The delete is already terminal, so this is the retry seat for the
            // server-owned endpoint release: a replay of the same delete must
            // finish cleanup that a transient failure left behind, and it
            // reports the outcome so the caller can retry again.
            self.release_server_endpoints_from_intent(&intent).await?;
            self.cleanup_config_drive_best_effort(&id.as_uuid().to_string());
            let _ = self
                .store
                .release_reservation_for_operation(&intent.operation_id.to_string())
                .await;
            if let Some(operation_id) = accepted_operation_id {
                self.store
                    .update_operation(
                        operation_id,
                        o3k_store::OperationState::Succeeded,
                        None,
                        None,
                        None,
                    )
                    .await?;
            }
            return Ok(o3k_store::OperationState::Succeeded);
        }
        if resource.provider_id.is_none() {
            // A server that never reached a provider cannot be deleted through
            // the provider path: there is no provider identity to address.
            // That is safe to complete locally only when the create is
            // terminally failed WITHOUT any provider acceptance (no provider
            // operation identity): the create dispatch provably never reached
            // an agent — e.g. the issue-87 empty-registry terminal — so no
            // provider side effect can exist, mirroring the reconciler's
            // "domain already absent" handling of provider NotFound on
            // delete. A create that WAS accepted (a provider operation
            // identity exists) is equally absent-proven when the durable
            // error_category is "not_found": the create provably never took
            // effect, so no provider side effect can exist either — either
            // converge_absent_create's presence-inspection evidence (issue-87
            // S3 rerun #4) or the agent's definitive pre-libvirt failure
            // evidence, where the failure provably happened before any
            // libvirt define (issue-87 C-1 qemu-img failure). Every other
            // shape — in-flight,
            // accepted without absence proof, or terminally failed for a
            // reason other than absence — still fails closed: the provider
            // may hold side effects that only the provider delete can
            // remove.
            let intent: CreateInstanceRequest = serde_json::from_str(&resource.desired_state)
                .map_err(|_| ComputeError::Conflict)?;
            let create = self
                .store
                .get_operation(intent.operation_id)
                .await
                .map_err(|error| match error {
                    StoreError::OperationNotFound => ComputeError::Conflict,
                    other => ComputeError::Store(other),
                })?;
            if !(matches!(create.state, o3k_store::OperationState::Failed)
                && (create.provider_operation_id.is_none()
                    || create.error_category.as_deref() == Some("not_found")))
            {
                return Err(ComputeError::Conflict);
            }
            let operation_id = accepted_operation_id.unwrap_or_else(|| {
                Uuid::new_v5(
                    &Uuid::NAMESPACE_URL,
                    format!("o3k:delete:{project_id}:{id}:{}", resource.generation).as_bytes(),
                )
            });
            if accepted_operation_id.is_none() {
                match self
                    .journal
                    .begin_lifecycle(id.as_uuid(), operation_id, LifecycleAction::Delete)
                    .await
                {
                    Ok(_) | Err(ReconcileError::Store(StoreError::ResourceAlreadyExists)) => {}
                    Err(error) => return Err(ComputeError::Reconcile(error)),
                }
            }
            // Project before terminalizing the delete operation so a crash
            // between the projection and the writes is repaired by re-drive.
            self.project_metering(&resource, server_state_to_storage(ServerState::Deleted))
                .await?;
            // Issue #1041: the operation terminal state and the resource
            // terminal projection commit in ONE durable transaction; the
            // previous sequential pair could crash between the two writes and
            // leave exactly one half committed, which no reconciliation pass
            // repairs. The endpoint release below stays outside the
            // transaction by design: if the process dies before it runs, the
            // shipped orphan-endpoint sweep repairs it (issue #1035).
            self.store
                .terminalize_lifecycle(&o3k_store::LifecycleTerminalization {
                    operation_id,
                    terminal_state: o3k_store::OperationState::Succeeded,
                    provider_operation_id: None,
                    error_category: None,
                    error_message: None,
                    resource_id: id.as_uuid(),
                    expected_generation: resource.generation,
                    desired_state: &resource.desired_state,
                    observed_state: server_state_to_storage(ServerState::Deleted),
                    observed_generation: resource.generation,
                    provider_id: None,
                })
                .await?;
            self.release_placement_allocation(id.as_uuid(), &intent)
                .await?;
            self.store.detach_server_keypair(id.as_uuid()).await?;
            // #1035 crash-window failpoint: the terminal delete is durably
            // committed and no endpoint release has run. Killed here, the
            // server is DELETED while its `o3k-server:` endpoint stays behind;
            // the shipped orphan-repair sweep is the repair authority.
            test_fault_pause_ms(
                "before-endpoint-release",
                "O3K_TEST_FAULT_PAUSE_BEFORE_ENDPOINT_RELEASE_MS",
            );
            // The delete completed here, so this request owns the outcome: a
            // server-owned endpoint that could not be released fails the
            // mutation (the durable delete stays terminal, and a replay retries
            // the release) instead of returning success with a live endpoint.
            self.project_terminal_binding_outcome(
                operation_id.to_string().as_str(),
                o3k_store::OperationState::Succeeded,
            )
            .await?;
            let _ = self
                .store
                .release_reservation_for_operation(&intent.operation_id.to_string())
                .await;
            // Issue #88 S3 residue: the create may have been ACCEPTED by an
            // agent (the config-drive transfers commit before acceptance)
            // that crashed before any libvirt mutation. The accepted
            // create's ConfigDriveIso manifests and content survive on that
            // host with zero durable bindings, and nothing else ever tells
            // the agent to reap them — the local completion above proves
            // absence but does not remove the media. Dispatch a BEST-EFFORT
            // delete for the never-defined resource with the same
            // deterministic delete operation identity (the provider reuses
            // the durable command record idempotently on re-dispatch) and a
            // dedicated reap idempotency key. The agent's delete executor
            // reaps the config-drive media, network, and console residue
            // through its "domain already absent" arm — the single reaping
            // authority. A failed dispatch is logged and never changes the
            // already-terminal local delete: the residue verifier catches
            // leftovers separately. NotFound means the create never reached
            // any agent (e.g. the empty-registry terminal) — a clean no-op.
            if let Err(error) = self
                .provider
                .delete_instance(DeleteInstanceRequest {
                    operation_id,
                    provider_instance_id: id.as_uuid().to_string(),
                    idempotency_key: format!("o3k:delete-reap:{id}"),
                })
                .await
            {
                if matches!(error, ProviderError::NotFound) {
                    tracing::debug!(
                        resource_id = %id,
                        "reap dispatch found no accepted create; nothing to reap"
                    );
                } else {
                    tracing::warn!(
                        resource_id = %id,
                        error = ?error,
                        "best-effort reap dispatch failed; the local delete is unaffected"
                    );
                }
            }
            return Ok(o3k_store::OperationState::Succeeded);
        }
        let operation_id = accepted_operation_id.unwrap_or_else(|| {
            Uuid::new_v5(
                &Uuid::NAMESPACE_URL,
                format!("o3k:delete:{project_id}:{id}:{}", resource.generation).as_bytes(),
            )
        });
        if accepted_operation_id.is_none() {
            match self
                .journal
                .begin_lifecycle(id.as_uuid(), operation_id, LifecycleAction::Delete)
                .await
            {
                Ok(_) | Err(ReconcileError::Store(StoreError::ResourceAlreadyExists)) => {}
                Err(error) => return Err(ComputeError::Reconcile(error)),
            }
        }
        // CANONICAL PATH: one reconciliation pass, return current state without
        // blocking.  The caller maps Succeeded→204 and non-terminal→202.  No
        // compensatory cleanup runs for an incomplete operation.
        //
        // LEGACY PATH: poll until terminal; the synchronous caller contract
        // requires the delete to complete before returning.
        let state = match accepted_operation_id {
            Some(_) => self
                .journal
                .reconcile_lifecycle_once(operation_id)
                .await
                .map_err(ComputeError::Reconcile)?,
            None => {
                self.reconcile_lifecycle_until_terminal(operation_id)
                    .await?
            }
        };
        if state != o3k_store::OperationState::Succeeded {
            return Ok(state);
        }
        let intent: CreateInstanceRequest =
            serde_json::from_str(&resource.desired_state).map_err(|_| ComputeError::Conflict)?;
        self.release_placement_allocation(id.as_uuid(), &intent)
            .await?;
        self.store.detach_server_keypair(id.as_uuid()).await?;
        // #1035 crash-window failpoint: the terminal delete is durably
        // committed and no endpoint release has run. Killed here, the
        // server is DELETED while its `o3k-server:` endpoint stays behind;
        // the shipped orphan-repair sweep is the repair authority.
        test_fault_pause_ms(
            "before-endpoint-release",
            "O3K_TEST_FAULT_PAUSE_BEFORE_ENDPOINT_RELEASE_MS",
        );
        // Request owns the outcome: a server-owned endpoint that could not be
        // released fails the mutation rather than reporting a converged delete.
        self.project_terminal_binding_outcome(
            operation_id.to_string().as_str(),
            o3k_store::OperationState::Succeeded,
        )
        .await?;
        let _ = self
            .store
            .release_reservation_for_operation(&intent.operation_id.to_string())
            .await;
        Ok(o3k_store::OperationState::Succeeded)
    }

    pub(super) async fn release_placement_allocation(
        &self,
        server_id: Uuid,
        intent: &CreateInstanceRequest,
    ) -> Result<(), ComputeError> {
        if let (Some(scheduler), Some(provider_id), Some(allocation_id)) = (
            self.scheduler.as_ref(),
            intent.placement_provider_id.as_deref(),
            intent.placement_allocation_id.as_deref(),
        ) {
            scheduler
                .release_terminal(&o3k_scheduler::ScheduleDecision {
                    provider_id: provider_id.to_owned(),
                    allocation_id: allocation_id.to_owned(),
                    allocation: o3k_placement::Allocation {
                        provider_id: provider_id.to_owned(),
                        consumer_id: server_id.to_string(),
                        resources: std::collections::BTreeMap::new(),
                    },
                })
                .await?;
        }
        Ok(())
    }

    pub(super) async fn release_placement_decision(
        &self,
        decision: &o3k_scheduler::ScheduleDecision,
    ) -> Result<(), ComputeError> {
        if let Some(scheduler) = self.scheduler.as_ref() {
            scheduler.release_terminal(decision).await?;
        }
        Ok(())
    }

    /// Schedules a create request. The ledger reports `InvalidAllocation`
    /// when the `allocation-{server_id}` intent key for this server collided
    /// with a concurrent identical request: the intent was consumed and this
    /// call acquired no capacity. The racing request holds (or will hold) the
    /// allocation, so the collision surfaces as a Conflict without releasing
    /// anything; request-level validation errors are already fenced by the
    /// ledger and the scheduler before this point.
    pub(super) async fn schedule_server(
        &self,
        scheduler: &Scheduler,
        selected_agents: Option<&BTreeSet<String>>,
        server_id: &str,
        flavor: SchedulerFlavor,
    ) -> Result<o3k_scheduler::ScheduleDecision, ComputeError> {
        let attempt = match selected_agents {
            Some(agents) => {
                scheduler
                    .schedule_for_agents(agents, server_id, flavor)
                    .await
            }
            None => scheduler.schedule(server_id, flavor).await,
        };
        match attempt {
            Err(o3k_scheduler::SchedulerError::Placement(
                o3k_placement::PlacementError::InvalidAllocation,
            )) => Err(ComputeError::Conflict),
            result => result.map_err(ComputeError::from),
        }
    }

    pub async fn action_for_auth(
        &self,
        auth: &AuthContext,
        id: ServerId,
        action: InstanceAction,
    ) -> Result<Server, ComputeError> {
        let action_name = match action {
            InstanceAction::Start => "StartServer",
            InstanceAction::Stop => "StopServer",
            InstanceAction::Reboot => "RebootServer",
        };
        let ns = ServiceNamespace::new("compute")
            .unwrap_or_else(|_| ServiceNamespace::new_unchecked("compute".to_owned()));
        let act = ActionId::new("compute", action_name).unwrap_or_else(|_| {
            ActionId::new_unchecked("compute".to_owned(), action_name.to_owned())
        });
        let req = AuthorizationRequest {
            auth_context: auth,
            action: act.clone(),
            resource_target: ResourceTarget::instance(
                ResourceType::new("compute", "server").map_err(|_| ComputeError::InvalidRequest)?,
                ResourceId::new(id.as_uuid().to_string())
                    .map_err(|_| ComputeError::InvalidRequest)?,
                Some(auth.effective_scope().id().clone()),
            ),
        };
        let decision = self.authorizer.authorize(&req);
        if !decision.is_allowed() {
            let event = AuditEvent::from_auth(auth, ns, act, AuditOutcome::Denied)
                .with_decision(decision)
                .with_reason("unauthorized");
            self.record_required_audit(&event).await?;
            return Err(ComputeError::NotFound);
        }
        match self
            .action(auth.effective_scope().id().as_str(), id, action)
            .await
        {
            Ok(server) => {
                let event = AuditEvent::from_auth(auth, ns, act, AuditOutcome::Succeeded)
                    .with_resource(
                        ResourceType::new("compute", "server").unwrap_or_else(|_| {
                            ResourceType::new_unchecked("compute".to_owned(), "server".to_owned())
                        }),
                        ResourceId::new(server.id.as_uuid().to_string()).ok(),
                        Some(auth.effective_scope().clone()),
                    );
                self.record_required_audit(&event).await?;
                Ok(server)
            }
            Err(error) => {
                let event = AuditEvent::from_auth(auth, ns, act, AuditOutcome::Failed)
                    .with_reason(error.to_string());
                self.record_required_audit(&event).await?;
                Err(error)
            }
        }
    }

    pub async fn action(
        &self,
        project_id: &str,
        id: ServerId,
        action: InstanceAction,
    ) -> Result<Server, ComputeError> {
        let resource =
            self.store
                .get_resource(id.as_uuid())
                .await
                .map_err(|error| match error {
                    StoreError::ResourceNotFound => ComputeError::NotFound,
                    other => ComputeError::Store(other),
                })?;
        if resource.project_id != project_id {
            return Err(ComputeError::NotFound);
        }
        if resource.provider_id.is_none() {
            return Err(ComputeError::Conflict);
        }
        // Action applicability is decided on the canonical lifecycle state,
        // decoded fail-closed from the durable observed value. The target
        // state feeds the deterministic journal identity through its storage
        // encoding, so durable operation ids are unchanged.
        let current = server_state_from_storage(&resource.observed_state)
            .map_err(|_| ComputeError::Conflict)?;
        let target = match (action, current) {
            (InstanceAction::Start, ServerState::Stopped) => ServerState::Active,
            (InstanceAction::Stop, ServerState::Active) => ServerState::Stopped,
            (InstanceAction::Reboot, ServerState::Active | ServerState::Stopped) => {
                ServerState::Active
            }
            _ => return Err(ComputeError::Conflict),
        };
        let lifecycle_action = match action {
            InstanceAction::Start => LifecycleAction::Start,
            InstanceAction::Stop => LifecycleAction::Stop,
            InstanceAction::Reboot => LifecycleAction::Reboot,
        };
        let operation_id = Uuid::new_v5(
            &Uuid::NAMESPACE_URL,
            format!(
                "o3k:action:{project_id}:{id}:{}:{}",
                server_state_to_storage(target),
                resource.generation
            )
            .as_bytes(),
        );
        match self
            .journal
            .begin_lifecycle(id.as_uuid(), operation_id, lifecycle_action)
            .await
        {
            Ok(_) | Err(ReconcileError::Store(StoreError::ResourceAlreadyExists)) => {}
            Err(error) => return Err(ComputeError::Reconcile(error)),
        }
        if self
            .reconcile_lifecycle_until_terminal(operation_id)
            .await?
            != o3k_store::OperationState::Succeeded
        {
            return Err(ComputeError::Conflict);
        }
        self.show_server(project_id, id).await
    }

    /// Drives a lifecycle operation to a terminal state. Agent-backed
    /// providers complete commands asynchronously, so a single reconcile pass
    /// almost always returns `Running`; polling briefly preserves the
    /// synchronous action contract without inventing new API semantics.
    /// Passes are idempotent, so transient store races with the live
    /// observation consumer are retried within the same bounded budget;
    /// only a terminal outcome or a deterministic intent error ends the wait.
    pub(super) async fn reconcile_lifecycle_until_terminal(
        &self,
        operation_id: Uuid,
    ) -> Result<o3k_store::OperationState, ComputeError> {
        let deadline = std::time::Instant::now() + Duration::from_secs(10);
        let mut last_error = None;
        loop {
            match self.journal.reconcile_lifecycle_once(operation_id).await {
                Ok(
                    state @ (o3k_store::OperationState::Succeeded
                    | o3k_store::OperationState::Failed),
                ) => return Ok(state),
                Ok(_) => {}
                Err(ReconcileError::InvalidIntent) => {
                    return Err(ComputeError::Reconcile(ReconcileError::InvalidIntent));
                }
                Err(error) => last_error = Some(ComputeError::Reconcile(error)),
            }
            if std::time::Instant::now() >= deadline {
                return match last_error {
                    Some(error) => Err(error),
                    None => Ok(o3k_store::OperationState::Running),
                };
            }
            tokio::time::sleep(Duration::from_millis(100)).await;
        }
    }
}
