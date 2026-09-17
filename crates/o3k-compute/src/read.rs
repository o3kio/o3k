use super::{
    AuthContext, ComputeError, ComputeService, CreateInstanceRequest, ResourceId, ResourceTarget,
    ResourceType, Server, ServerId, ServerProjectionError, ServerState, StoreError,
    server_from_resource,
};

use o3k_kernel::{ActionId, AuditEvent, AuditOutcome, AuthorizationRequest, ServiceNamespace};
use o3k_store::server_state_to_storage;

impl ComputeService {
    pub async fn list_servers_for_auth(
        &self,
        auth: &AuthContext,
    ) -> Result<Vec<Server>, ComputeError> {
        let ns = ServiceNamespace::new("compute")
            .unwrap_or_else(|_| ServiceNamespace::new_unchecked("compute".to_owned()));
        let act = ActionId::new("compute", "ListServers").unwrap_or_else(|_| {
            ActionId::new_unchecked("compute".to_owned(), "ListServers".to_owned())
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
        self.list_servers(auth.effective_scope().id().as_str())
            .await
    }

    /// Returns the durable control-plane generation for a server already
    /// authorized through the compute read path. The native API uses this
    /// bounded projection instead of fabricating generation metadata.
    pub async fn server_generation_for_auth(
        &self,
        auth: &AuthContext,
        id: ServerId,
    ) -> Result<i64, ComputeError> {
        let record = self
            .store
            .get_resource(id.as_uuid())
            .await
            .map_err(ComputeError::Store)?;
        if record.project_id != auth.effective_scope().id().as_str()
            || record.kind != "compute_instance"
        {
            return Err(ComputeError::NotFound);
        }
        Ok(record.generation)
    }

    /// Returns migration ownership metadata from the durable server intent.
    /// This read-only projection is consumed by the native compatibility edge;
    /// the compute domain remains authoritative for the resource record.
    pub async fn server_migration_metadata_for_auth(
        &self,
        auth: &AuthContext,
        id: ServerId,
    ) -> Result<(Option<String>, Option<String>), ComputeError> {
        let record = self
            .store
            .get_resource(id.as_uuid())
            .await
            .map_err(ComputeError::Store)?;
        if record.project_id != auth.effective_scope().id().as_str()
            || record.kind != "compute_instance"
        {
            return Err(ComputeError::NotFound);
        }
        let desired = serde_json::from_str::<serde_json::Value>(&record.desired_state)
            .map_err(|_| ComputeError::InvalidRequest)?;
        Ok((
            desired
                .get("migration_id")
                .and_then(serde_json::Value::as_str)
                .map(ToOwned::to_owned),
            desired
                .get("source_key")
                .and_then(serde_json::Value::as_str)
                .map(ToOwned::to_owned),
        ))
    }

    pub async fn list_servers(&self, project_id: &str) -> Result<Vec<Server>, ComputeError> {
        let flavors = self.flavors_for_project(project_id).await?;
        let resources = self
            .store
            .list_resources(project_id, "compute_instance")
            .await?;
        let mut servers = Vec::new();
        for resource in resources {
            let resource_id = resource.id;
            let mut server = match server_from_resource(resource, &flavors) {
                Ok(server) => server,
                Err(ServerProjectionError::CorruptState(corrupt)) => {
                    // Corrupt rows are skipped, not misclassified: the
                    // conversion failed closed. Surface the integrity failure
                    // so an operator can repair the durable ledger.
                    tracing::warn!(%resource_id, %corrupt, "server lifecycle state is corrupt; row skipped");
                    continue;
                }
                Err(ServerProjectionError::Unresolvable) => continue,
            };
            if server.state != ServerState::Deleted {
                server.key_name = self
                    .store
                    .get_server_keypair_name(server.id.as_uuid())
                    .await?;
                servers.push(server);
            }
        }
        Ok(servers)
    }

    pub async fn show_server_for_auth(
        &self,
        auth: &AuthContext,
        id: ServerId,
    ) -> Result<Server, ComputeError> {
        let ns = ServiceNamespace::new("compute")
            .unwrap_or_else(|_| ServiceNamespace::new_unchecked("compute".to_owned()));
        let act = ActionId::new("compute", "ReadServer").unwrap_or_else(|_| {
            ActionId::new_unchecked("compute".to_owned(), "ReadServer".to_owned())
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
        self.show_server(auth.effective_scope().id().as_str(), id)
            .await
    }

    /// Returns the durable network attachment intent even after the server
    /// has reached Deleted.  The Nova adapter uses this to retry cleanup after
    /// a process restart or a transient endpoint-store failure; the normal
    /// read projection intentionally hides deleted servers.
    pub async fn server_network_ids_for_auth(
        &self,
        auth: &AuthContext,
        id: ServerId,
    ) -> Result<Vec<String>, ComputeError> {
        let ns = ServiceNamespace::new("compute")
            .unwrap_or_else(|_| ServiceNamespace::new_unchecked("compute".to_owned()));
        let act = ActionId::new("compute", "ReadServer").unwrap_or_else(|_| {
            ActionId::new_unchecked("compute".to_owned(), "ReadServer".to_owned())
        });
        let target = ResourceTarget::instance(
            ResourceType::new("compute", "server").map_err(|_| ComputeError::InvalidRequest)?,
            ResourceId::new(id.as_uuid().to_string()).map_err(|_| ComputeError::InvalidRequest)?,
            Some(auth.effective_scope().id().clone()),
        );
        let decision = self.authorizer.authorize(&AuthorizationRequest {
            auth_context: auth,
            action: act.clone(),
            resource_target: target,
        });
        if !decision.is_allowed() {
            let event = AuditEvent::from_auth(auth, ns, act, AuditOutcome::Denied)
                .with_decision(decision)
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
        if resource.kind != "compute_instance"
            || resource.project_id != auth.effective_scope().id().as_str()
        {
            return Err(ComputeError::NotFound);
        }
        let request: CreateInstanceRequest =
            serde_json::from_str(&resource.desired_state).map_err(|_| ComputeError::Conflict)?;
        Ok(request.network_ids)
    }

    pub async fn show_server(
        &self,
        project_id: &str,
        id: ServerId,
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
        // The show path is the poll surface for `openstack server create
        // --wait`: a create operation left non-terminal after the synchronous
        // pass must be re-driven here or the server stays in BUILD forever.
        // The drive is lazy, bounded, and idempotent; ownership was validated
        // above, so no provider dispatch can happen for a foreign project.
        self.drive_create_convergence(&resource).await;
        // Re-read the durable state: the convergence drive may have projected
        // a terminal outcome onto the resource.
        let resource =
            self.store
                .get_resource(id.as_uuid())
                .await
                .map_err(|error| match error {
                    StoreError::ResourceNotFound => ComputeError::NotFound,
                    other => ComputeError::Store(other),
                })?;
        let flavors = self.flavors_for_project(project_id).await?;
        let mut server = match server_from_resource(resource, &flavors) {
            Ok(server) => server,
            Err(ServerProjectionError::CorruptState(corrupt)) => {
                return Err(ComputeError::Store(corrupt));
            }
            Err(ServerProjectionError::Unresolvable) => {
                return Err(ComputeError::InvalidRequest);
            }
        };
        if server.state == ServerState::Deleted {
            return Err(ComputeError::NotFound);
        }
        server.key_name = self
            .store
            .get_server_keypair_name(server.id.as_uuid())
            .await?;
        Ok(server)
    }

    /// Applies the bounded Nova in-place update supported by P13.2D.  The
    /// canonical resource ledger is the merge base; compatibility callers
    /// cannot update a stale projection or change server identity.
    pub async fn update_server_name_for_auth(
        &self,
        auth: &AuthContext,
        id: ServerId,
        name: String,
    ) -> Result<Server, ComputeError> {
        let action = ActionId::new("compute", "UpdateServer").unwrap_or_else(|_| {
            ActionId::new_unchecked("compute".to_owned(), "UpdateServer".to_owned())
        });
        let target = ResourceTarget::instance(
            ResourceType::new("compute", "server").map_err(|_| ComputeError::InvalidRequest)?,
            ResourceId::new(id.as_uuid().to_string()).map_err(|_| ComputeError::InvalidRequest)?,
            Some(auth.effective_scope().id().clone()),
        );
        if !self
            .authorizer
            .authorize(&AuthorizationRequest {
                auth_context: auth,
                action,
                resource_target: target,
            })
            .is_allowed()
        {
            return Err(ComputeError::NotFound);
        }
        if name.trim().is_empty() {
            return Err(ComputeError::InvalidRequest);
        }
        let resource =
            self.store
                .get_resource(id.as_uuid())
                .await
                .map_err(|error| match error {
                    StoreError::ResourceNotFound => ComputeError::NotFound,
                    other => ComputeError::Store(other),
                })?;
        if resource.kind != "compute_instance"
            || resource.project_id != auth.effective_scope().id().as_str()
        {
            return Err(ComputeError::NotFound);
        }
        let mut request: CreateInstanceRequest =
            serde_json::from_str(&resource.desired_state).map_err(|_| ComputeError::Conflict)?;
        request.name = name;
        let desired = serde_json::to_string(&request).map_err(|_| ComputeError::Conflict)?;
        self.store
            .update_resource(
                resource.id,
                resource.generation,
                &desired,
                &resource.observed_state,
                resource.observed_generation,
                resource.provider_id.as_deref(),
            )
            .await
            .map_err(ComputeError::Store)?;
        self.show_server(auth.effective_scope().id().as_str(), id)
            .await
    }

    /// Drives durable create convergence for a server whose create operation
    /// is stuck in a state that nothing else will ever advance: `Pending` (a
    /// crash between persisting the intent and the synchronous pass),
    /// `UnknownOutcome` (dispatch timeout, transport loss), or `Running`
    /// without a provider operation identity (a crash between the
    /// Pending→Running persist in `reconcile_once` and the dispatch reaching
    /// the provider — issue-87 S1 residue). Without this driver the server
    /// would stay in BUILD forever after the synchronous pass in
    /// `create_server`, and a genuine unknown outcome only converges by
    /// observing instance presence at the execution boundary (issue #481
    /// criterion 3).
    ///
    /// A `Running` operation that carries a provider operation identity is
    /// deliberately NOT driven: the provider has accepted the command (the
    /// identity is attached only after a successful dispatch) and its
    /// terminal update arrives through the agent event stream, and a
    /// concurrent re-drive from the poll path would race the synchronous
    /// finisher on the same operation records (duplicate reference attach /
    /// stale generation). A `Running` operation WITHOUT the identity was
    /// never accepted, so it is re-driven like `Pending`; re-dispatch is
    /// safe because the agent journal dedups by command id/operation/
    /// idempotency key + fingerprint and never re-executes an accepted
    /// command. The drive is lazy (read-triggered), bounded (terminal and
    /// accepted operations are not re-driven), and idempotent (the
    /// reconciler reuses in-flight and terminal provider work by the
    /// deterministic operation identity).
    ///
    /// Metering is best-effort here: a projection failure is logged, never
    /// returned, so a metering hiccup cannot turn `GET /servers/{id}` into a
    /// 500. Every drive first re-projects the resource's durable observed
    /// state, so an observation lost by a failed projection is repaired by the
    /// next read. A converged failure applies the same reverse-order
    /// compensation as the asynchronous agent-failure path.
    pub(super) async fn drive_create_convergence(&self, resource: &o3k_store::ResourceRecord) {
        tracing::debug!(resource_id = %resource.id, "create convergence drive entered");
        // Repair projection: re-read the durable resource and re-project its
        // current observed_state on every drive, before the re-drive guard, so
        // an observation lost by an earlier failed projection is healed by the
        // next read. The helper only ever opens/refreshes a consuming interval
        // (it never closes), is idempotent, and is best-effort: it never fails
        // the GET.
        self.repair_metering_from_durable_state(resource.id).await;
        let Ok(request) = serde_json::from_str::<CreateInstanceRequest>(&resource.desired_state)
        else {
            return;
        };
        let Ok(operation) = self.store.get_operation(request.operation_id).await else {
            return;
        };
        // Issue #88 S5 rerun: a create whose transfer dispatch was rejected
        // mid-flight (agent killed during the handshake) is marked Retryable
        // by retry_or_fail; the scheduled retry must actually fire, or the
        // operation stays Retryable forever, the API delete 409s against it,
        // and every owned residue is held. Re-drive Retryable exactly like
        // Pending and UnknownOutcome — the retry budget in retry_or_fail
        // still bounds it (attempts >= max_attempts terminalizes Failed).
        let re_drive = matches!(
            operation.state,
            o3k_store::OperationState::Pending
                | o3k_store::OperationState::UnknownOutcome
                | o3k_store::OperationState::Retryable
        ) || (operation.state == o3k_store::OperationState::Running
            && operation.provider_operation_id.is_none());
        if !re_drive {
            return;
        }
        let state = match self.journal.reconcile_once(request.operation_id).await {
            Ok(state) => state,
            Err(error) => {
                tracing::warn!(
                    operation_id = %request.operation_id,
                    resource_id = %resource.id,
                    error = %error,
                    "server create convergence pass failed; server state is unchanged"
                );
                return;
            }
        };
        match state {
            o3k_store::OperationState::Failed => {
                self.project_terminal_binding_outcome(
                    request.operation_id.to_string().as_str(),
                    state,
                )
                .await;
                if let Err(error) = self.compensate_failed_create(request.operation_id).await {
                    tracing::warn!(
                        operation_id = %request.operation_id,
                        resource_id = %resource.id,
                        error = %error,
                        "server create failure compensation failed"
                    );
                }
                // A terminal create failure must render ERROR on the poll
                // surface, or `--wait` keeps showing BUILD forever. The
                // reconciler projects ERROR internally only for presence
                // absence; every other failure path (dispatch rejection,
                // retry budget exhaustion, provider-reported failure) needs
                // the drive to project it. The update is idempotent: the
                // resource is only touched when it is not already ERROR.
                let Ok(resource) = self.store.get_resource(resource.id).await else {
                    return;
                };
                if resource.observed_state != server_state_to_storage(ServerState::Error) {
                    // Project after the durable write so the observation always
                    // matches the state that was actually written. Best-effort:
                    // a failure is logged, never returned, and the repair
                    // projection above heals it on the next read.
                    match self
                        .store
                        .update_resource(
                            resource.id,
                            resource.generation,
                            &resource.desired_state,
                            server_state_to_storage(ServerState::Error),
                            resource.generation,
                            resource.provider_id.as_deref(),
                        )
                        .await
                    {
                        Ok(_) => {
                            self.project_metering_best_effort(
                                &resource,
                                server_state_to_storage(ServerState::Error),
                            )
                            .await;
                        }
                        Err(error) => {
                            tracing::warn!(
                                operation_id = %request.operation_id,
                                resource_id = %resource.id,
                                error = %error,
                                "server create failure projection to ERROR failed"
                            );
                        }
                    }
                }
            }
            o3k_store::OperationState::Succeeded => {
                self.project_terminal_binding_outcome(
                    request.operation_id.to_string().as_str(),
                    state,
                )
                .await;
                if let Ok(resource) = self.store.get_resource(resource.id).await
                    && resource.observed_state != "ACTIVE"
                {
                    // Project after the durable write so the observation always
                    // matches the state that was actually written. Best-effort
                    // like the failure arm.
                    match self
                        .store
                        .update_resource(
                            resource.id,
                            resource.generation,
                            &resource.desired_state,
                            "ACTIVE",
                            resource.generation,
                            resource.provider_id.as_deref(),
                        )
                        .await
                    {
                        Ok(_) => {
                            self.project_metering_best_effort(&resource, "ACTIVE").await;
                        }
                        Err(error) => {
                            tracing::warn!(
                                operation_id = %request.operation_id,
                                resource_id = %resource.id,
                                error = %error,
                                "server create success projection to ACTIVE failed"
                            );
                        }
                    }
                }
            }
            _ => {}
        }
    }
}
