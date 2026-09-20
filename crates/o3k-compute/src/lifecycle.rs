use super::{
    AgentAdministrativeState, AgentAvailability, AuthContext, BTreeSet, ComputeError,
    ComputeService, CreateInstanceRequest, CreateMutationReceipt, LimitKey, MutationReceipt,
    OwnershipScope, ReconcileError, ResourceAmount, ResourceId, ResourceTarget, ResourceType,
    SchedulerFlavor, Server, ServerCreateInput, ServerId, ServerState, StoreError, Uuid,
    requests_match_with_keypair_migration, test_fault_pause_ms,
};

use o3k_kernel::{
    ActionId, AuditEvent, AuditOutcome, AuthorizationRequest, ScopeId, ServiceNamespace,
};
use o3k_store::{server_state_from_storage, server_state_to_storage};

impl ComputeService {
    pub async fn create_server_for_auth(
        &self,
        auth: &AuthContext,
        input: ServerCreateInput,
    ) -> Result<Server, ComputeError> {
        let ns = ServiceNamespace::new("compute")
            .unwrap_or_else(|_| ServiceNamespace::new_unchecked("compute".to_owned()));
        let act = ActionId::new("compute", "CreateServer").unwrap_or_else(|_| {
            ActionId::new_unchecked("compute".to_owned(), "CreateServer".to_owned())
        });
        let req = AuthorizationRequest {
            auth_context: auth,
            action: act.clone(),
            resource_target: ResourceTarget::collection(
                ResourceType::new("compute", "server").map_err(|_| ComputeError::InvalidRequest)?,
                Some(auth.effective_scope().id().clone()),
            ),
        };
        let decision = self.authorizer.authorize(&req);
        if !decision.is_allowed() {
            let event = AuditEvent::from_auth(auth, ns, act, AuditOutcome::Denied)
                .with_decision(decision)
                .with_reason("unauthorized");
            self.record_required_audit(&event).await?;
            return Err(ComputeError::Unauthorized);
        }
        match self.create_server_for_user(input).await {
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

    pub async fn create_server_for_auth_canonical(
        &self,
        auth: &AuthContext,
        input: ServerCreateInput,
        context: o3k_reconciler::CanonicalMutationContext,
    ) -> Result<MutationReceipt<Server>, ComputeError> {
        // CANONICAL INVARIANT: the canonical context's action must match the
        // expected mutation (InvalidRequest — a structural wiring error),
        // while the actor and owner_scope must match the authenticated request
        // (Unauthorized — an authorization failure).
        if context.action.to_string() != "compute:CreateServer" {
            return Err(ComputeError::InvalidRequest);
        }
        if context.actor != auth.principal().id().as_str()
            || context.owner_scope.id().as_str() != auth.effective_scope().id().as_str()
        {
            return Err(ComputeError::Unauthorized);
        }
        let action = context.action.clone();
        let target = ResourceTarget::collection(
            ResourceType::new("compute", "server").map_err(|_| ComputeError::InvalidRequest)?,
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
            return Err(ComputeError::Unauthorized);
        }
        let accepted = self
            .create_server_for_user_with_context(input, Some(&context))
            .await?;
        let outcome = match accepted.operation_state {
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
            ResourceId::new(accepted.server.id.as_uuid().to_string()).ok(),
            Some(auth.effective_scope().clone()),
        )
        .with_operation(accepted.operation_id);
        self.record_required_audit(&event).await?;
        Ok(MutationReceipt {
            resource: accepted.server,
            operation_id: accepted.operation_id,
            operation_state: accepted.operation_state,
            replayed: accepted.replayed,
        })
    }

    pub async fn create_server(
        &self,
        project_id: &str,
        name: String,
        image_id: String,
        flavor_id: Uuid,
        network_ids: Vec<String>,
        idempotency_key: String,
    ) -> Result<Server, ComputeError> {
        self.create_server_for_user(ServerCreateInput {
            user_id: String::new(),
            project_id: project_id.to_owned(),
            name,
            image_id,
            flavor_id,
            network_ids,
            key_name: None,
            config_drive: None,
            idempotency_key,
        })
        .await
    }

    pub async fn create_server_for_user(
        &self,
        input: ServerCreateInput,
    ) -> Result<Server, ComputeError> {
        Ok(self
            .create_server_for_user_with_context(input, None)
            .await?
            .server)
    }

    /// Returns the deterministic canonical identity used by the Nova create
    /// adapter before the durable server intent exists.
    pub fn server_id_for_create(project_id: &str, idempotency_key: &str) -> Uuid {
        let canonical = idempotency_key
            .strip_prefix("canonical:")
            .or_else(|| {
                idempotency_key
                    .split_once(":canonical:")
                    .map(|(_, value)| value)
            })
            .and_then(|value| value.parse().ok());
        if let Some(canonical) = canonical {
            return canonical;
        }
        Uuid::new_v5(
            &Uuid::NAMESPACE_URL,
            format!("o3k:server:{project_id}:{idempotency_key}").as_bytes(),
        )
    }

    pub(super) async fn create_server_for_user_with_context(
        &self,
        input: ServerCreateInput,
        canonical: Option<&o3k_reconciler::CanonicalMutationContext>,
    ) -> Result<CreateMutationReceipt, ComputeError> {
        let ServerCreateInput {
            user_id,
            project_id,
            name,
            image_id,
            flavor_id,
            network_ids,
            key_name,
            config_drive,
            idempotency_key,
        } = input;
        if name.trim().is_empty()
            || image_id.trim().is_empty()
            || network_ids.is_empty()
            || network_ids.iter().any(|id| id.trim().is_empty())
            || idempotency_key.trim().is_empty()
        {
            return Err(ComputeError::InvalidRequest);
        }
        let keypair = match key_name.as_deref() {
            Some(name) => Some(
                self.store
                    .get_keypair(&user_id, &project_id, name)
                    .await
                    .map_err(|error| match error {
                        StoreError::KeypairNotFound => ComputeError::NotFound,
                        other => ComputeError::Store(other),
                    })?,
            ),
            None => None,
        };
        let flavor = self.flavor_for_project(&project_id, flavor_id).await?;
        let server_id = Self::server_id_for_create(&project_id, &idempotency_key);
        let existing_res = self.store.get_resource(server_id).await;
        let operation_id = match &existing_res {
            Ok(existing) => {
                let observed = server_state_from_storage(&existing.observed_state).ok();
                if observed == Some(ServerState::Deleted) {
                    Uuid::new_v5(
                        &Uuid::NAMESPACE_URL,
                        format!(
                            "o3k:operation:revive:{project_id}:{idempotency_key}:{}",
                            existing.observed_generation
                        )
                        .as_bytes(),
                    )
                } else if let Ok(req) =
                    serde_json::from_str::<CreateInstanceRequest>(&existing.desired_state)
                {
                    req.operation_id
                } else {
                    Uuid::new_v5(
                        &Uuid::NAMESPACE_URL,
                        format!("o3k:operation:{project_id}:{idempotency_key}").as_bytes(),
                    )
                }
            }
            _ => Uuid::new_v5(
                &Uuid::NAMESPACE_URL,
                format!("o3k:operation:{project_id}:{idempotency_key}").as_bytes(),
            ),
        };
        let scope = OwnershipScope::project(ScopeId::new_unchecked(project_id.clone()), None, None);
        let amounts = vec![
            ResourceAmount::new_unchecked(LimitKey::compute_servers(), 1),
            ResourceAmount::new_unchecked(LimitKey::compute_vcpus(), flavor.vcpus as u64),
            ResourceAmount::new_unchecked(LimitKey::compute_memory_mb(), flavor.ram_mib),
            ResourceAmount::new_unchecked(LimitKey::compute_disk_gb(), flavor.disk_gib),
        ];
        let request = CreateInstanceRequest {
            operation_id,
            o3k_server_id: server_id,
            project_id: project_id.to_owned(),
            name: name.clone(),
            vcpus: flavor.vcpus,
            memory_mib: flavor.ram_mib,
            flavor_id: flavor.id.to_string(),
            disk_gib: flavor.disk_gib,
            image_id: Some(image_id.clone()),
            key_name: key_name.clone(),
            keypair_id: keypair.as_ref().map(|value| value.id),
            network_ids: network_ids.clone(),
            placement_provider_id: None,
            placement_allocation_id: None,
            config_drive: config_drive.clone(),
            idempotency_key: idempotency_key.clone(),
        };
        // A durable row in terminal `Deleted` state is a completed lifecycle
        // over the same deterministic identity, not an in-flight create: the
        // name is free (`list_servers` excludes Deleted rows) and the caller
        // is starting a NEW lifecycle. The tombstone is remembered and the
        // normal schedule+persist flow revives the row under a fresh
        // lifecycle operation identity below. Every other durable state keeps
        // the retry semantics of ADR-0014 (byte-equivalent intent converges,
        // a differing intent conflicts).
        // CANONICAL INVARIANT: a canonical mutation resolves the idempotency
        // identity before any legacy existing-resource shortcut or revive
        // semantics.  The canonical store-level `create_or_replay_*` is the
        // sole authority for live replay and conflict detection.  Legacy
        // deterministic resource handling (omit+revive, keypair migration,
        // reply-equivalence) must NOT run when CanonicalMutationContext is
        // present — doing so would expose a non-canonical Operation or
        // revive a tombstone without canonical metadata.
        let mut revived_from: Option<o3k_store::ResourceRecord> = None;
        if canonical.is_none() {
            match self.store.get_resource(server_id).await {
                Ok(existing) => {
                    let existing_request: CreateInstanceRequest =
                        serde_json::from_str(&existing.desired_state)
                            .map_err(|_| ComputeError::Conflict)?;
                    let existing_request = CreateInstanceRequest {
                        placement_provider_id: None,
                        placement_allocation_id: None,
                        ..existing_request
                    };
                    // Deliberate vs HEAD: corrupt observed state now fails
                    // closed as `ComputeError::Store` instead of being silently
                    // treated as a live row.
                    let observed = server_state_from_storage(&existing.observed_state)
                        .map_err(ComputeError::Store)?;
                    if observed == ServerState::Deleted {
                        revived_from = Some(existing);
                    } else {
                        let legacy_keypair_intent =
                            requests_match_with_keypair_migration(&existing_request, &request);
                        // A recreation revive (issue #613 blocker B) persisted a
                        // fresh lifecycle operation identity for the same caller
                        // intent; a retry of that recreation rebuilds the
                        // pre-revive request and differs from the persisted
                        // intent only in operation_id and idempotency_key. The
                        // durable intent wins for that exact shape (the retry
                        // converges on the persisted row and its operation);
                        // every other difference keeps the ADR-0014 conflict
                        // semantics.
                        let revive_equivalent = existing_request != request
                            && !legacy_keypair_intent
                            && CreateInstanceRequest {
                                operation_id: existing_request.operation_id,
                                idempotency_key: existing_request.idempotency_key.clone(),
                                ..request.clone()
                            } == existing_request;
                        if !(existing_request == request
                            || legacy_keypair_intent
                            || revive_equivalent)
                        {
                            return Err(ComputeError::Conflict);
                        }
                        if legacy_keypair_intent {
                            let desired_state = serde_json::to_string(&request)
                                .map_err(|_| ComputeError::Conflict)?;
                            self.store
                                .update_resource(
                                    existing.id,
                                    existing.generation,
                                    &desired_state,
                                    &existing.observed_state,
                                    existing.observed_generation,
                                    existing.provider_id.as_deref(),
                                )
                                .await?;
                        }
                        let attached = self.store.get_server_keypair_name(server_id).await?;
                        let mut repaired_association = false;
                        if attached != key_name {
                            if attached.is_none() {
                                if let Some(keypair) = keypair.as_ref() {
                                    self.store
                                        .attach_server_keypair(server_id, keypair.id)
                                        .await?;
                                    repaired_association = true;
                                } else {
                                    return Err(ComputeError::Conflict);
                                }
                            } else {
                                return Err(ComputeError::Conflict);
                            }
                        }
                        if repaired_association {
                            match self
                                .journal
                                .reconcile_once(existing_request.operation_id)
                                .await
                            {
                                Ok(o3k_store::OperationState::Failed) => {
                                    self.store.detach_server_keypair(server_id).await?;
                                    self.project_terminal_binding_outcome(
                                        existing_request.operation_id.to_string().as_str(),
                                        o3k_store::OperationState::Failed,
                                    )
                                    .await;
                                    return Err(ComputeError::Conflict);
                                }
                                Ok(o3k_store::OperationState::Succeeded) => {
                                    self.project_terminal_binding_outcome(
                                        existing_request.operation_id.to_string().as_str(),
                                        o3k_store::OperationState::Succeeded,
                                    )
                                    .await;
                                }
                                Ok(_) => {}
                                Err(error) => {
                                    self.store.detach_server_keypair(server_id).await?;
                                    return Err(ComputeError::Reconcile(error));
                                }
                            }
                        }
                        let server = self
                            .show_server(&project_id, ServerId::from_uuid(server_id))
                            .await?;
                        let operation = self
                            .store
                            .get_operation(existing_request.operation_id)
                            .await?;
                        return Ok(CreateMutationReceipt {
                            server,
                            operation_id: operation.id,
                            operation_state: operation.state,
                            replayed: true,
                        });
                    }
                }
                Err(StoreError::ResourceNotFound) => {}
                Err(error) => return Err(ComputeError::Store(error)),
            }
        }
        // A name conflict is deterministic control-plane state. Reject it
        // before reserving Placement capacity; the second check below still
        // protects against a concurrent create racing this read.
        // CANONICAL INVARIANT: when CanonicalMutationContext is present the
        // deterministic server_id uniquely identifies the resource.  A
        // canonical replay carries the same server_id, so the name check must
        // be skipped to avoid rejecting an equivalent replay.
        let canonical_has_existing = canonical.is_some() && existing_res.is_ok();
        if !canonical_has_existing
            && self
                .list_servers(&project_id)
                .await?
                .iter()
                .any(|server| server.name == name && server.state != ServerState::Deleted)
        {
            return Err(ComputeError::Conflict);
        }
        let scheduler_flavor = SchedulerFlavor {
            vcpus: flavor.vcpus as u64,
            memory_mb: flavor.ram_mib,
            disk_gb: flavor.disk_gib,
        };
        let placement = match (self.scheduler.as_ref(), self.agent_registry.as_ref()) {
            (Some(scheduler), Some(registry)) => {
                let eligible = registry
                    .all()
                    .await
                    .into_iter()
                    .filter(|node| {
                        node.availability == AgentAvailability::Available
                            && node.administrative_state == AgentAdministrativeState::Enabled
                    })
                    .map(|node| node.agent_id)
                    .collect::<BTreeSet<_>>();
                Some(
                    self.schedule_server(
                        scheduler,
                        Some(&eligible),
                        &server_id.to_string(),
                        scheduler_flavor,
                    )
                    .await?,
                )
            }
            (Some(scheduler), None) => Some(
                self.schedule_server(scheduler, None, &server_id.to_string(), scheduler_flavor)
                    .await?,
            ),
            (None, _) => None,
        };
        let request = CreateInstanceRequest {
            placement_provider_id: placement
                .as_ref()
                .map(|decision| decision.provider_id.clone()),
            placement_allocation_id: placement
                .as_ref()
                .map(|decision| decision.allocation_id.clone()),
            ..request
        };
        let servers = match self.list_servers(&project_id).await {
            Ok(servers) => servers,
            Err(error) => {
                if let Some(decision) = placement.as_ref() {
                    self.release_placement_decision(decision).await?;
                }
                return Err(error);
            }
        };
        if !canonical_has_existing
            && servers
                .iter()
                .any(|server| server.name == name && server.state != ServerState::Deleted)
        {
            // A racing identical request may have persisted this server while
            // the schedule was in flight; its allocation idempotently backs
            // that live row and must not be released. Only a decision that is
            // not owned by a live row carrying the same placement binding is
            // released here (a name conflict from a different request, or a
            // decision that fell back to a provider the persisted row does
            // not reference).
            let owns_live_server = async {
                let Some(decision) = placement.as_ref() else {
                    return false;
                };
                let Ok(server_id) = Uuid::parse_str(&decision.allocation.consumer_id) else {
                    return false;
                };
                let Ok(resource) = self.store.get_resource(server_id).await else {
                    return false;
                };
                resource.kind == "compute_instance"
                    && server_state_from_storage(&resource.observed_state).ok()
                        != Some(ServerState::Deleted)
                    && serde_json::from_str::<CreateInstanceRequest>(&resource.desired_state)
                        .map(|intent| {
                            intent.placement_provider_id.as_deref()
                                == Some(decision.provider_id.as_str())
                                && intent.placement_allocation_id.as_deref()
                                    == Some(decision.allocation_id.as_str())
                        })
                        .unwrap_or(false)
            }
            .await;
            if let Some(decision) = placement.as_ref()
                && !owns_live_server
            {
                self.release_placement_decision(decision).await?;
            }
            return Err(ComputeError::Conflict);
        }
        let request = CreateInstanceRequest {
            network_ids,
            ..request
        };
        let id = request.o3k_server_id;
        // ASR-018 crash-window failpoint: the placement allocation is already
        // durable; the server/resource/create-operation intent is not yet
        // persisted. Killed here, restart startup reconciliation must release
        // the orphan allocation and the retried create must stay idempotent.
        test_fault_pause_ms(
            "after-placement-commit",
            "O3K_TEST_FAULT_PAUSE_AFTER_PLACEMENT_COMMIT_MS",
        );
        // Reserve only after all pre-persistence validation and placement
        // checks have succeeded.  Placement is a control-plane allocation;
        // no provider side effect is allowed before this durable quota
        // reservation.  If quota reservation fails, release that placement
        // allocation before returning so neither authority leaks state.
        let quota_res = match self
            .store
            .reserve_quota(&scope, &operation_id.to_string(), &amounts)
            .await
        {
            Ok(reservation) => reservation,
            Err(err) => {
                if let Some(decision) = placement.as_ref() {
                    self.release_placement_decision(decision).await?;
                }
                return Err(match err {
                    StoreError::QuotaExceeded {
                        key,
                        limit,
                        used,
                        requested,
                    } => ComputeError::QuotaExceeded {
                        key,
                        limit,
                        used,
                        requested,
                    },
                    StoreError::ReservationConflict(_) => ComputeError::Conflict,
                    other => ComputeError::Store(other),
                });
            }
        };
        macro_rules! release_quota_and_return {
            ($error:expr) => {{
                let error = $error;
                if let Err(release_error) = self.store.release_reservation(&quota_res.id).await {
                    return Err(ComputeError::Store(release_error));
                }
                return Err(error);
            }};
        }
        let request = match revived_from.as_ref() {
            Some(tombstone) => {
                // Revive the tombstoned row into a fresh lifecycle. The
                // operation identity and the provider idempotency key derive
                // deterministically from the tombstone's durable
                // observed_generation, so a retry before this persist
                // recomputes the same identities and a retry after a crash
                // between placement commit and persist converges through the
                // revive again (the tombstone is untouched until the atomic
                // persist below). The fresh idempotency key also keeps the
                // agent command journal from deduplicating the new create
                // against the completed lifecycle's terminal command.
                let revive_operation_id = Uuid::new_v5(
                    &Uuid::NAMESPACE_URL,
                    format!(
                        "o3k:operation:revive:{project_id}:{idempotency_key}:{}",
                        tombstone.observed_generation
                    )
                    .as_bytes(),
                );
                let revive_idempotency_key =
                    format!("{idempotency_key}:revive:{}", tombstone.observed_generation);
                let revive_request = CreateInstanceRequest {
                    operation_id: revive_operation_id,
                    idempotency_key: revive_idempotency_key,
                    ..request
                };
                let desired_state = match serde_json::to_string(&revive_request) {
                    Ok(value) => value,
                    Err(_) => release_quota_and_return!(ComputeError::Conflict),
                };
                match self
                    .store
                    .revive_resource_and_operation(
                        id,
                        tombstone.generation,
                        &desired_state,
                        server_state_to_storage(ServerState::Requested),
                        tombstone.observed_generation,
                        None,
                        &o3k_store::OperationRecord {
                            id: revive_operation_id,
                            resource_id: id,
                            kind: "create".to_owned(),
                            state: o3k_store::OperationState::Pending,
                            provider_operation_id: None,
                            error_category: None,
                            error_message: None,
                        },
                        placement
                            .as_ref()
                            .map(|decision| decision.allocation_id.as_str()),
                    )
                    .await
                {
                    Ok(_) => revive_request,
                    Err(StoreError::StaleGeneration) | Err(StoreError::ResourceAlreadyExists) => {
                        // A concurrent writer already advanced the row.
                        // Observe the durable row before deciding what to
                        // release: a decision owned by the live row backs
                        // that row and must not be released.
                        let existing = match self.store.get_resource(id).await {
                            Ok(value) => value,
                            Err(error) => release_quota_and_return!(ComputeError::Store(error)),
                        };
                        let existing_request: CreateInstanceRequest =
                            match serde_json::from_str(&existing.desired_state) {
                                Ok(value) => value,
                                Err(_) => release_quota_and_return!(ComputeError::Conflict),
                            };
                        let owns_persisted_placement = placement.as_ref().is_some_and(|decision| {
                            existing_request.placement_provider_id.as_deref()
                                == Some(decision.provider_id.as_str())
                                && existing_request.placement_allocation_id.as_deref()
                                    == Some(decision.allocation_id.as_str())
                        });
                        if let Some(decision) = placement.as_ref()
                            && !owns_persisted_placement
                            && let Err(error) = self.release_placement_decision(decision).await
                        {
                            release_quota_and_return!(error);
                        }
                        release_quota_and_return!(ComputeError::Conflict);
                    }
                    // The placement allocation referenced by this revive was
                    // reconciled away before the intent became durable
                    // (startup orphan reconciliation racing an in-flight
                    // create). Fail closed exactly like the fresh-create
                    // path: the caller retries with a fresh allocation.
                    Err(StoreError::PlacementAllocationNotFound) => {
                        release_quota_and_return!(ComputeError::Conflict);
                    }
                    Err(error) => release_quota_and_return!(ComputeError::Store(error)),
                }
            }
            None => {
                let acceptance =
                    match canonical {
                        Some(context) => {
                            self.journal
                                .begin_canonical_create(&project_id, &request, context)
                                .await
                        }
                        None => self.journal.begin_create(&project_id, &request).await.map(
                            |operation_id| o3k_store::CanonicalAcceptanceOutcome::Created {
                                operation_id,
                                resource_id: request.o3k_server_id,
                            },
                        ),
                    };
                match acceptance {
                    Ok(o3k_store::CanonicalAcceptanceOutcome::Conflict) => {
                        if let Some(decision) = placement.as_ref()
                            && let Err(error) = self.release_placement_decision(decision).await
                        {
                            release_quota_and_return!(error);
                        }
                        release_quota_and_return!(ComputeError::Conflict);
                    }
                    Ok(o3k_store::CanonicalAcceptanceOutcome::ExistingEquivalent {
                        operation_id: existing_operation_id,
                        resource_id,
                    }) => {
                        let existing = self.store.get_resource(resource_id).await?;
                        let existing_request: CreateInstanceRequest =
                            serde_json::from_str(&existing.desired_state)
                                .map_err(|_| ComputeError::Conflict)?;
                        let owns_persisted_placement = placement.as_ref().is_some_and(|decision| {
                            existing_request.placement_provider_id.as_deref()
                                == Some(decision.provider_id.as_str())
                                && existing_request.placement_allocation_id.as_deref()
                                    == Some(decision.allocation_id.as_str())
                        });
                        if let Some(decision) = placement.as_ref()
                            && !owns_persisted_placement
                        {
                            self.release_placement_decision(decision).await?;
                        }
                        let server = self
                            .show_server(&project_id, ServerId::from_uuid(resource_id))
                            .await?;
                        let operation = self.store.get_operation(existing_operation_id).await?;
                        match operation.state {
                            o3k_store::OperationState::Succeeded => {
                                self.store.commit_reservation(&quota_res.id).await?;
                            }
                            o3k_store::OperationState::Failed => {
                                self.store.release_reservation(&quota_res.id).await?;
                            }
                            _ => {}
                        }
                        return Ok(CreateMutationReceipt {
                            server,
                            operation_id: existing_operation_id,
                            operation_state: operation.state,
                            replayed: true,
                        });
                    }
                    Ok(_) => {}
                    Err(ReconcileError::Store(StoreError::ResourceAlreadyExists)) => {
                        // CANONICAL INVARIANT: a pre-existing legacy resource
                        // with no matching canonical idempotency reservation
                        // must fail closed.  The legacy path below preserves
                        // the existing OpenStack/TestLab recreate contract
                        // only for non-canonical mutations.
                        if canonical.is_some() {
                            if let Some(decision) = placement.as_ref() {
                                self.release_placement_decision(decision).await?;
                            }
                            release_quota_and_return!(ComputeError::Conflict);
                        }
                        let existing = match self.store.get_resource(id).await {
                            Ok(value) => value,
                            Err(error) => release_quota_and_return!(ComputeError::Store(error)),
                        };
                        let existing_request: CreateInstanceRequest =
                            match serde_json::from_str(&existing.desired_state) {
                                Ok(value) => value,
                                Err(_) => release_quota_and_return!(ComputeError::Conflict),
                            };
                        let owns_persisted_placement = placement.as_ref().is_some_and(|decision| {
                            existing_request.placement_provider_id.as_deref()
                                == Some(decision.provider_id.as_str())
                                && existing_request.placement_allocation_id.as_deref()
                                    == Some(decision.allocation_id.as_str())
                        });
                        if let Some(decision) = placement.as_ref()
                            && !owns_persisted_placement
                            && let Err(error) = self.release_placement_decision(decision).await
                        {
                            release_quota_and_return!(error);
                        }
                        let legacy_keypair_intent =
                            requests_match_with_keypair_migration(&existing_request, &request);
                        if existing_request != request && !legacy_keypair_intent {
                            release_quota_and_return!(ComputeError::Conflict);
                        }
                        if matches!(
                            server_state_from_storage(&existing.observed_state),
                            Ok(ServerState::Deleted)
                        ) {
                            release_quota_and_return!(ComputeError::NotFound);
                        }
                        if legacy_keypair_intent {
                            let desired_state = match serde_json::to_string(&request) {
                                Ok(value) => value,
                                Err(_) => release_quota_and_return!(ComputeError::Conflict),
                            };
                            if let Err(error) = self
                                .store
                                .update_resource(
                                    existing.id,
                                    existing.generation,
                                    &desired_state,
                                    &existing.observed_state,
                                    existing.observed_generation,
                                    existing.provider_id.as_deref(),
                                )
                                .await
                            {
                                release_quota_and_return!(ComputeError::Store(error));
                            }
                        }
                        let attached = match self.store.get_server_keypair_name(id).await {
                            Ok(value) => value,
                            Err(error) => release_quota_and_return!(ComputeError::Store(error)),
                        };
                        let mut repaired_association = false;
                        if attached != request.key_name {
                            if attached.is_none() {
                                if let Some(keypair) = keypair.as_ref() {
                                    if let Err(error) =
                                        self.store.attach_server_keypair(id, keypair.id).await
                                    {
                                        release_quota_and_return!(ComputeError::Store(error));
                                    }
                                    repaired_association = true;
                                } else {
                                    release_quota_and_return!(ComputeError::Conflict);
                                }
                            } else {
                                release_quota_and_return!(ComputeError::Conflict);
                            }
                        }
                        if repaired_association {
                            match self.journal.reconcile_once(request.operation_id).await {
                                Ok(o3k_store::OperationState::Failed) => {
                                    if let Err(error) = self.store.detach_server_keypair(id).await {
                                        release_quota_and_return!(ComputeError::Store(error));
                                    }
                                    self.project_terminal_binding_outcome(
                                        request.operation_id.to_string().as_str(),
                                        o3k_store::OperationState::Failed,
                                    )
                                    .await;
                                    release_quota_and_return!(ComputeError::Conflict);
                                }
                                Ok(o3k_store::OperationState::Succeeded) => {
                                    self.project_terminal_binding_outcome(
                                        request.operation_id.to_string().as_str(),
                                        o3k_store::OperationState::Succeeded,
                                    )
                                    .await;
                                }
                                Ok(_) => {}
                                Err(error) => {
                                    if let Err(error) = self.store.detach_server_keypair(id).await {
                                        release_quota_and_return!(ComputeError::Store(error));
                                    }
                                    release_quota_and_return!(ComputeError::Reconcile(error));
                                }
                            }
                        }
                        let server =
                            match self.show_server(&project_id, ServerId::from_uuid(id)).await {
                                Ok(value) => value,
                                Err(error) => release_quota_and_return!(error),
                            };
                        let operation = match self
                            .store
                            .get_operation(existing_request.operation_id)
                            .await
                        {
                            Ok(value) => value,
                            Err(error) => release_quota_and_return!(ComputeError::Store(error)),
                        };
                        match operation.state {
                            o3k_store::OperationState::Succeeded => {
                                self.store.commit_reservation(&quota_res.id).await?;
                            }
                            o3k_store::OperationState::Failed => {
                                self.store.release_reservation(&quota_res.id).await?;
                            }
                            _ => {}
                        }
                        return Ok(CreateMutationReceipt {
                            server,
                            operation_id: operation.id,
                            operation_state: operation.state,
                            replayed: true,
                        });
                    }
                    // The placement allocation referenced by this create was
                    // reconciled away before the consumer intent became durable
                    // (startup orphan reconciliation racing an in-flight
                    // create). Fail closed: no resource may outlive its
                    // allocation. The caller retries; the deterministic
                    // allocation identity keeps the retry idempotent.
                    Err(ReconcileError::Store(StoreError::PlacementAllocationNotFound)) => {
                        release_quota_and_return!(ComputeError::Conflict);
                    }
                    Err(error) => release_quota_and_return!(ComputeError::Reconcile(error)),
                }
                request
            }
        };
        if let Some(keypair) = keypair
            && let Err(error) = self.store.attach_server_keypair(id, keypair.id).await
        {
            release_quota_and_return!(ComputeError::Store(error));
        }
        let reconcile_state = match self.journal.reconcile_once(request.operation_id).await {
            Ok(state) => state,
            Err(error) => {
                if let Err(detach_error) = self.store.detach_server_keypair(id).await {
                    release_quota_and_return!(ComputeError::Store(detach_error));
                }
                tracing::warn!(
                    operation_id = %request.operation_id,
                    resource_id = %id,
                    error = %error,
                    "server create reconciliation returned an error"
                );
                release_quota_and_return!(ComputeError::Reconcile(error));
            }
        };
        if matches!(
            reconcile_state,
            o3k_store::OperationState::Succeeded | o3k_store::OperationState::Failed
        ) {
            self.project_terminal_binding_outcome(
                request.operation_id.to_string().as_str(),
                reconcile_state,
            )
            .await;
        }
        if reconcile_state == o3k_store::OperationState::Failed {
            if let Ok(operation) = self.store.get_operation(request.operation_id).await {
                tracing::warn!(
                    operation_id = %request.operation_id,
                    resource_id = %id,
                    error_category = ?operation.error_category,
                    error_message = ?operation.error_message,
                    "server create reconciliation failed"
                );
            }
            self.project_failed_create_error(id).await?;
            if let Err(error) = self.store.detach_server_keypair(id).await {
                release_quota_and_return!(ComputeError::Store(error));
            }
            if let (Some(scheduler), Some(provider_id), Some(allocation_id)) = (
                self.scheduler.as_ref(),
                request.placement_provider_id.as_deref(),
                request.placement_allocation_id.as_deref(),
            ) && let Err(error) = scheduler
                .release_terminal(&o3k_scheduler::ScheduleDecision {
                    provider_id: provider_id.to_owned(),
                    allocation_id: allocation_id.to_owned(),
                    allocation: o3k_placement::Allocation {
                        provider_id: provider_id.to_owned(),
                        consumer_id: id.to_string(),
                        resources: std::collections::BTreeMap::new(),
                    },
                })
                .await
            {
                release_quota_and_return!(ComputeError::Scheduler(error));
            }
            release_quota_and_return!(ComputeError::Conflict);
        }
        let server = match self.show_server(&project_id, ServerId::from_uuid(id)).await {
            Ok(value) => value,
            Err(error) => release_quota_and_return!(error),
        };
        if let Err(error) = self.store.commit_reservation(&quota_res.id).await {
            // Do not report a successful create while its quota reservation is
            // still pending.  A commit failure is a durable store failure and
            // must be surfaced to the caller for reconciliation/retry.
            let _ = self.store.release_reservation(&quota_res.id).await;
            return Err(ComputeError::Store(error));
        }
        let operation = self.store.get_operation(request.operation_id).await?;
        Ok(CreateMutationReceipt {
            server,
            operation_id: operation.id,
            operation_state: operation.state,
            replayed: false,
        })
    }
}
