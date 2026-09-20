use super::helpers::deterministic_port_mac;
use super::{NetworkError, NetworkService, PortBindingState, map_store_error};
use crate::PortRecord;
use o3k_kernel::{
    ActionId, AuditEvent, AuditOutcome, AuthContext, AuthorizationRequest, LimitKey,
    OwnershipScope, ResourceAmount, ResourceId, ResourceTarget, ResourceType, ScopeId,
    ServiceNamespace,
};
use std::{net::Ipv4Addr, time::Duration};
use uuid::Uuid;

impl NetworkService {
    pub async fn create_port(
        &self,
        auth: &AuthContext,
        network_id: Uuid,
        name: String,
    ) -> Result<PortRecord, NetworkError> {
        self.create_port_with_fixed_ip(auth, network_id, name, None)
            .await
    }

    pub async fn create_port_with_fixed_ip(
        &self,
        auth: &AuthContext,
        network_id: Uuid,
        name: String,
        requested_fixed_ip: Option<(Uuid, Option<Ipv4Addr>)>,
    ) -> Result<PortRecord, NetworkError> {
        if name.starts_with("o3k-server:") {
            return Err(NetworkError::InvalidRequest);
        }
        let ns = ServiceNamespace::new("network")
            .unwrap_or_else(|_| ServiceNamespace::new_unchecked("network".to_owned()));
        let act = ActionId::new("network", "CreatePort").unwrap_or_else(|_| {
            ActionId::new_unchecked("network".to_owned(), "CreatePort".to_owned())
        });
        let req = AuthorizationRequest {
            auth_context: auth,
            action: act.clone(),
            resource_target: ResourceTarget::collection(
                ResourceType::new("network", "port").map_err(|_| NetworkError::InvalidRequest)?,
                Some(auth.effective_scope().id().clone()),
            ),
        };
        let decision = self.authorizer.authorize(&req);
        if !decision.is_allowed() {
            let event = AuditEvent::from_auth(auth, ns, act, AuditOutcome::Denied)
                .with_decision(decision)
                .with_reason("unauthorized");
            self.record_required_audit(&event).await?;
            return Err(NetworkError::Unauthorized);
        }
        match self
            .create_port_for_project_with_fixed_ip(
                auth.effective_scope().id().as_str(),
                network_id,
                name,
                requested_fixed_ip,
            )
            .await
        {
            Ok(record) => {
                let event = AuditEvent::from_auth(auth, ns, act, AuditOutcome::Succeeded)
                    .with_resource(
                        ResourceType::new("network", "port").unwrap_or_else(|_| {
                            ResourceType::new_unchecked("network".to_owned(), "port".to_owned())
                        }),
                        ResourceId::new(record.id.to_string()).ok(),
                        Some(auth.effective_scope().clone()),
                    );
                self.record_required_audit(&event).await?;
                Ok(record)
            }
            Err(error) => {
                let event = AuditEvent::from_auth(auth, ns, act, AuditOutcome::Failed)
                    .with_reason(error.to_string());
                self.record_required_audit(&event).await?;
                Err(error)
            }
        }
    }

    pub async fn create_port_for_project(
        &self,
        project_id: &str,
        network_id: Uuid,
        name: String,
    ) -> Result<PortRecord, NetworkError> {
        self.create_port_for_project_with_fixed_ip(project_id, network_id, name, None)
            .await
    }

    pub async fn create_port_for_project_with_fixed_ip(
        &self,
        project_id: &str,
        network_id: Uuid,
        name: String,
        requested_fixed_ip: Option<(Uuid, Option<Ipv4Addr>)>,
    ) -> Result<PortRecord, NetworkError> {
        self.create_port_for_project_with_id_and_fixed_ip(
            project_id,
            Uuid::now_v7(),
            network_id,
            name,
            requested_fixed_ip,
        )
        .await
    }

    pub async fn create_port_for_project_with_id_and_fixed_ip(
        &self,
        project_id: &str,
        id: Uuid,
        network_id: Uuid,
        name: String,
        requested_fixed_ip: Option<(Uuid, Option<Ipv4Addr>)>,
    ) -> Result<PortRecord, NetworkError> {
        self.create_port_for_project_internal(
            project_id,
            id,
            network_id,
            name,
            requested_fixed_ip,
            requested_fixed_ip.is_some(),
        )
        .await
    }

    /// Creates an endpoint with a caller-owned identity even when the
    /// address is allocated from a pool. Native compute uses this stable
    /// entry point so replay cannot create a second endpoint; ordinary pool
    /// allocation retains its collision-safe fresh identity behavior.
    pub async fn create_port_for_project_with_stable_id(
        &self,
        project_id: &str,
        id: Uuid,
        network_id: Uuid,
        name: String,
    ) -> Result<PortRecord, NetworkError> {
        self.create_port_for_project_internal(project_id, id, network_id, name, None, true)
            .await
    }

    async fn create_port_for_project_internal(
        &self,
        project_id: &str,
        id: Uuid,
        network_id: Uuid,
        name: String,
        requested_fixed_ip: Option<(Uuid, Option<Ipv4Addr>)>,
        stable_id: bool,
    ) -> Result<PortRecord, NetworkError> {
        self.get_canonical_network_for_project(project_id, network_id)
            .await?;
        let realms = self
            .inner
            .repository
            .list_canonical_realms(project_id, &network_id)
            .await
            .map_err(map_store_error)?;
        let realm = if let Some((subnet_id, _)) = requested_fixed_ip {
            realms
                .into_iter()
                .find(|realm| realm.id == subnet_id && realm.state == "active")
                .ok_or(NetworkError::NotFound)?
        } else {
            match realms.as_slice() {
                [] => return Err(NetworkError::NotFound),
                [realm] if realm.state == "active" => realm.clone(),
                [_] => return Err(NetworkError::Conflict),
                _ => return Err(NetworkError::InvalidRequest),
            }
        };
        let pool = self
            .inner
            .repository
            .list_canonical_pools(project_id, &realm.id)
            .await
            .map_err(map_store_error)?
            .into_iter()
            .next()
            .ok_or(NetworkError::NotFound)?;
        let explicit_ip = requested_fixed_ip.and_then(|(_, ip)| ip);
        let mut candidate = explicit_ip
            .map(u32::from)
            .unwrap_or_else(|| u32::from(pool.first_usable));
        let end = explicit_ip
            .map(u32::from)
            .unwrap_or_else(|| u32::from(pool.last_usable));
        let gateway = pool.gateway.ok_or(NetworkError::InvalidRequest)?;
        while candidate <= end {
            let address = Ipv4Addr::from(candidate);
            if address != gateway
                && candidate >= u32::from(pool.first_usable)
                && candidate <= u32::from(pool.last_usable)
            {
                // Ordinary pool allocation uses a fresh identity for each
                // candidate so an address collision can advance through the
                // pool. Stable native/migration callers opt into the supplied
                // identity to make replay deterministic.
                let port_id = if stable_id { id } else { Uuid::now_v7() };
                let port = PortRecord {
                    id: port_id,
                    network_id,
                    subnet_id: Some(realm.id),
                    project_id: project_id.to_owned(),
                    name: name.clone(),
                    mac_address: deterministic_port_mac(port_id),
                    fixed_ip: address,
                    status: "ACTIVE".to_owned(),
                    binding_host: None,
                    binding_state: None,
                };
                let scope = OwnershipScope::project(
                    ScopeId::new_unchecked(project_id.to_owned()),
                    None,
                    None,
                );
                let amounts = vec![ResourceAmount::new(LimitKey::network_ports(), 1)];
                let op_id = format!("o3k:port:create:{}:{}", project_id, port.id);
                let quota_res = self
                    .inner
                    .repository
                    .reserve_quota(&scope, &op_id, &amounts)
                    .await
                    .map_err(|err| match err {
                        o3k_store::StoreError::QuotaExceeded {
                            key,
                            limit,
                            used,
                            requested,
                        } => NetworkError::QuotaExceeded {
                            key,
                            limit,
                            used,
                            requested,
                        },
                        o3k_store::StoreError::ReservationConflict(_) => NetworkError::Conflict,
                        other => map_store_error(other),
                    })?;

                let endpoint = o3k_store::CanonicalEndpointRecord {
                    id: port.id,
                    realm_id: realm.id,
                    project_id: project_id.to_owned(),
                    fixed_ip: port.fixed_ip,
                    mac: port.mac_address.clone(),
                    generation: 1,
                    state: "active".to_owned(),
                };
                let mut insert_result = Err(o3k_store::StoreError::ResourceNotFound);
                for _ in 0..8 {
                    insert_result = self
                        .inner
                        .repository
                        .insert_canonical_endpoint_and_port(&endpoint, &port)
                        .await;
                    if !insert_result
                        .as_ref()
                        .is_err_and(|error| error.to_string().contains("database is locked"))
                    {
                        break;
                    }
                    tokio::time::sleep(Duration::from_millis(10)).await;
                }
                match insert_result {
                    Ok(()) => {
                        let _ = self
                            .inner
                            .repository
                            .commit_reservation(&quota_res.id)
                            .await;
                        return Ok(port);
                    }
                    Err(o3k_store::StoreError::ResourceAlreadyExists) => {
                        let _ = self
                            .inner
                            .repository
                            .release_reservation(&quota_res.id)
                            .await;
                        if stable_id {
                            return Err(NetworkError::Conflict);
                        }
                    }
                    Err(error) => {
                        let _ = self
                            .inner
                            .repository
                            .release_reservation(&quota_res.id)
                            .await;
                        return Err(map_store_error(error));
                    }
                }
            }
            if explicit_ip.is_some() {
                break;
            }
            candidate = candidate.saturating_add(1);
        }
        if explicit_ip.is_some() {
            Err(NetworkError::InvalidRequest)
        } else {
            Err(NetworkError::PoolExhausted)
        }
    }

    pub async fn list_ports(&self, auth: &AuthContext) -> Result<Vec<PortRecord>, NetworkError> {
        let ns = ServiceNamespace::new("network")
            .unwrap_or_else(|_| ServiceNamespace::new_unchecked("network".to_owned()));
        let act = ActionId::new("network", "ListPorts").unwrap_or_else(|_| {
            ActionId::new_unchecked("network".to_owned(), "ListPorts".to_owned())
        });
        let req = AuthorizationRequest {
            auth_context: auth,
            action: act.clone(),
            resource_target: ResourceTarget::collection(
                ResourceType::new("network", "port").map_err(|_| NetworkError::InvalidRequest)?,
                Some(auth.effective_scope().id().clone()),
            ),
        };
        let decision = self.authorizer.authorize(&req);
        if !decision.is_allowed() {
            let event = AuditEvent::from_auth(auth, ns, act, AuditOutcome::Denied)
                .with_decision(decision)
                .with_reason("unauthorized");
            self.record_required_audit(&event).await?;
            return Err(NetworkError::Unauthorized);
        }
        self.list_ports_for_project(auth.effective_scope().id().as_str())
            .await
    }

    pub async fn list_ports_for_project(
        &self,
        project_id: &str,
    ) -> Result<Vec<PortRecord>, NetworkError> {
        let networks = self
            .inner
            .repository
            .list_canonical_networks(project_id)
            .await
            .map_err(map_store_error)?;
        let mut result = Vec::new();
        for network in networks {
            for realm in self
                .inner
                .repository
                .list_canonical_realms(project_id, &network.id)
                .await
                .map_err(map_store_error)?
            {
                for endpoint in self
                    .inner
                    .repository
                    .list_canonical_endpoints(project_id, &realm.id)
                    .await
                    .map_err(map_store_error)?
                {
                    result.push(
                        self.project_canonical_port(project_id, &realm, &endpoint)
                            .await?,
                    );
                }
            }
        }
        Ok(result)
    }

    pub async fn get_port(&self, auth: &AuthContext, id: Uuid) -> Result<PortRecord, NetworkError> {
        let ns = ServiceNamespace::new("network")
            .unwrap_or_else(|_| ServiceNamespace::new_unchecked("network".to_owned()));
        let act = ActionId::new("network", "ReadPort").unwrap_or_else(|_| {
            ActionId::new_unchecked("network".to_owned(), "ReadPort".to_owned())
        });
        let req = AuthorizationRequest {
            auth_context: auth,
            action: act.clone(),
            resource_target: ResourceTarget::instance(
                ResourceType::new("network", "port").map_err(|_| NetworkError::InvalidRequest)?,
                ResourceId::new(id.to_string()).map_err(|_| NetworkError::InvalidRequest)?,
                Some(auth.effective_scope().id().clone()),
            ),
        };
        let decision = self.authorizer.authorize(&req);
        if !decision.is_allowed() {
            let event = AuditEvent::from_auth(auth, ns, act, AuditOutcome::Denied)
                .with_decision(decision)
                .with_reason("unauthorized");
            self.record_required_audit(&event).await?;
            return Err(NetworkError::NotFound);
        }
        self.get_port_for_project(auth.effective_scope().id().as_str(), id)
            .await
    }

    pub async fn get_port_for_project(
        &self,
        project_id: &str,
        id: Uuid,
    ) -> Result<PortRecord, NetworkError> {
        let endpoint = self
            .inner
            .repository
            .get_canonical_endpoint(project_id, &id)
            .await
            .map_err(map_store_error)?
            .ok_or(NetworkError::NotFound)?;
        let realm = self
            .inner
            .repository
            .get_canonical_realm(project_id, &endpoint.realm_id)
            .await
            .map_err(map_store_error)?
            .ok_or(NetworkError::NotFound)?;
        self.project_canonical_port(project_id, &realm, &endpoint)
            .await
    }

    pub async fn update_port_name_for_project(
        &self,
        project_id: &str,
        id: Uuid,
        name: String,
    ) -> Result<PortRecord, NetworkError> {
        let current = self.get_port_for_project(project_id, id).await?;
        if current.name.starts_with("o3k-server:") {
            return Err(NetworkError::Conflict);
        }
        self.inner
            .repository
            .update_port_name(project_id, &id, &name)
            .await
            .map_err(map_store_error)?;
        self.get_port_for_project(project_id, id).await
    }

    async fn project_canonical_port(
        &self,
        project_id: &str,
        realm: &o3k_store::CanonicalAddressRealmRecord,
        endpoint: &o3k_store::CanonicalEndpointRecord,
    ) -> Result<PortRecord, NetworkError> {
        let metadata = self
            .inner
            .repository
            .get_port(project_id, &endpoint.id)
            .await
            .map_err(map_store_error)?;
        Ok(PortRecord {
            id: endpoint.id,
            network_id: realm.network_id,
            subnet_id: Some(realm.id),
            project_id: endpoint.project_id.clone(),
            name: metadata
                .as_ref()
                .map(|value| value.name.clone())
                .unwrap_or_default(),
            mac_address: endpoint.mac.clone(),
            fixed_ip: endpoint.fixed_ip,
            status: endpoint.state.to_ascii_uppercase(),
            binding_host: metadata
                .as_ref()
                .and_then(|value| value.binding_host.clone()),
            binding_state: metadata.and_then(|value| value.binding_state),
        })
    }

    /// Internal owner lookup used by canonical dependency authorization. It
    /// is not exposed as a tenant-facing read path and carries no metadata to
    /// the caller beyond the durable owner record.
    pub async fn find_port_by_id(&self, id: Uuid) -> Result<Option<PortRecord>, NetworkError> {
        self.inner
            .repository
            .get_port_by_id(&id)
            .await
            .map_err(map_store_error)
    }

    pub async fn delete_port(&self, auth: &AuthContext, id: Uuid) -> Result<(), NetworkError> {
        self.authorize_delete_port(auth, id).await?;
        match self
            .delete_port_for_project(auth.effective_scope().id().as_str(), id)
            .await
        {
            Ok(()) => {
                let ns = ServiceNamespace::new("network")
                    .unwrap_or_else(|_| ServiceNamespace::new_unchecked("network".to_owned()));
                let act = ActionId::new("network", "DeletePort").unwrap_or_else(|_| {
                    ActionId::new_unchecked("network".to_owned(), "DeletePort".to_owned())
                });
                let event = AuditEvent::from_auth(auth, ns, act, AuditOutcome::Succeeded)
                    .with_resource(
                        ResourceType::new("network", "port").unwrap_or_else(|_| {
                            ResourceType::new_unchecked("network".to_owned(), "port".to_owned())
                        }),
                        ResourceId::new(id.to_string()).ok(),
                        Some(auth.effective_scope().clone()),
                    );
                self.record_required_audit(&event).await?;
                Ok(())
            }
            Err(error) => {
                let ns = ServiceNamespace::new("network")
                    .unwrap_or_else(|_| ServiceNamespace::new_unchecked("network".to_owned()));
                let act = ActionId::new("network", "DeletePort").unwrap_or_else(|_| {
                    ActionId::new_unchecked("network".to_owned(), "DeletePort".to_owned())
                });
                let event = AuditEvent::from_auth(auth, ns, act, AuditOutcome::Failed)
                    .with_reason(error.to_string());
                self.record_required_audit(&event).await?;
                Err(error)
            }
        }
    }

    pub async fn authorize_delete_port(
        &self,
        auth: &AuthContext,
        id: Uuid,
    ) -> Result<PortRecord, NetworkError> {
        let ns = ServiceNamespace::new("network")
            .unwrap_or_else(|_| ServiceNamespace::new_unchecked("network".to_owned()));
        let act = ActionId::new("network", "DeletePort").unwrap_or_else(|_| {
            ActionId::new_unchecked("network".to_owned(), "DeletePort".to_owned())
        });
        let req = AuthorizationRequest {
            auth_context: auth,
            action: act.clone(),
            resource_target: ResourceTarget::instance(
                ResourceType::new("network", "port").map_err(|_| NetworkError::InvalidRequest)?,
                ResourceId::new(id.to_string()).map_err(|_| NetworkError::InvalidRequest)?,
                Some(auth.effective_scope().id().clone()),
            ),
        };
        let decision = self.authorizer.authorize(&req);
        if !decision.is_allowed() {
            let event = AuditEvent::from_auth(auth, ns, act, AuditOutcome::Denied)
                .with_decision(decision)
                .with_reason("unauthorized");
            self.record_required_audit(&event).await?;
            return Err(NetworkError::NotFound);
        }
        self.get_port_for_project(auth.effective_scope().id().as_str(), id)
            .await
    }

    pub async fn delete_port_for_project(
        &self,
        project_id: &str,
        id: Uuid,
    ) -> Result<(), NetworkError> {
        // Endpoint deletion owns only the endpoint and its canonical
        // attachment relations.  Remove those relations explicitly before
        // the endpoint row so the reusable policy and its rules remain
        // independent and the endpoint delete cannot leave dangling
        // attachments.
        let attachments = self
            .inner
            .repository
            .list_endpoint_policy_attachments(project_id, &id)
            .await
            .map_err(map_store_error)?;
        for attachment in attachments {
            self.inner
                .repository
                .delete_policy_attachment(project_id, &attachment.id)
                .await
                .map_err(map_store_error)?;
        }
        self.inner
            .repository
            .delete_canonical_endpoint_and_port(project_id, &id)
            .await
            .map_err(map_store_error)?;
        let _ = self
            .inner
            .repository
            .release_reservation_for_operation(&format!("o3k:port:create:{}:{}", project_id, id))
            .await;
        Ok(())
    }

    pub async fn record_binding_intent(
        &self,
        project_id: &str,
        port_id: Uuid,
        host: &str,
    ) -> Result<PortRecord, NetworkError> {
        if host.trim().is_empty() {
            return Err(NetworkError::InvalidRequest);
        }
        let _guard = self.lock().await;
        let port = self
            .inner
            .repository
            .get_port(project_id, &port_id)
            .await
            .map_err(map_store_error)?
            .ok_or(NetworkError::NotFound)?;
        if port
            .binding_host
            .as_deref()
            .is_some_and(|current| current != host)
        {
            return Err(NetworkError::Conflict);
        }
        // A create dispatch is underway: transitions from unbound, binding,
        // down, and error to binding. A completed `bound` observation is kept:
        // idempotent dispatch replays of an already-succeeded create must not
        // downgrade durable observed state.
        let next = match port
            .binding_state
            .as_deref()
            .and_then(PortBindingState::parse)
        {
            Some(PortBindingState::Bound) => PortBindingState::Bound,
            _ => PortBindingState::Binding,
        };
        self.inner
            .repository
            .update_port_binding(project_id, &port_id, Some(host), Some(next.as_str()))
            .await
            .map_err(map_store_error)
    }

    pub async fn project_binding_observation(
        &self,
        project_id: &str,
        port_id: Uuid,
        host: &str,
        state: &str,
    ) -> Result<PortRecord, NetworkError> {
        let state = PortBindingState::parse(state).ok_or(NetworkError::InvalidRequest)?;
        let _guard = self.lock().await;
        let port = self
            .inner
            .repository
            .get_port(project_id, &port_id)
            .await
            .map_err(map_store_error)?
            .ok_or(NetworkError::NotFound)?;
        if port.binding_host.as_deref() != Some(host) {
            return Err(NetworkError::Conflict);
        }
        self.inner
            .repository
            .update_port_binding(project_id, &port_id, Some(host), Some(state.as_str()))
            .await
            .map_err(map_store_error)
    }

    /// Projects a terminal create outcome onto the port's binding using the
    /// host recorded by the dispatch intent. The durable intent is
    /// authoritative: the control plane selects the host, so a stale or
    /// mismatched caller identity cannot override it. A port without a
    /// recorded intent (never dispatched) rejects the projection.
    pub async fn project_create_outcome(
        &self,
        project_id: &str,
        port_id: Uuid,
        state: PortBindingState,
    ) -> Result<PortRecord, NetworkError> {
        if !matches!(state, PortBindingState::Bound | PortBindingState::Error) {
            return Err(NetworkError::InvalidRequest);
        }
        let _guard = self.lock().await;
        let port = self
            .inner
            .repository
            .get_port(project_id, &port_id)
            .await
            .map_err(map_store_error)?
            .ok_or(NetworkError::NotFound)?;
        let host = port.binding_host.as_deref().ok_or(NetworkError::Conflict)?;
        self.inner
            .repository
            .update_port_binding(project_id, &port_id, Some(host), Some(state.as_str()))
            .await
            .map_err(map_store_error)
    }

    /// Clears the binding of a port whose server reached terminal deletion.
    /// The durable `down` state is a tombstone for an explicit unbind, so a
    /// late create callback cannot mistake the port for one that was never
    /// bound and recreate execution state.  A future binding intent changes
    /// it back to `binding`.
    /// Idempotent: unbinding a port with no intent is a successful no-op.
    pub async fn unbind_port(
        &self,
        project_id: &str,
        port_id: Uuid,
    ) -> Result<PortRecord, NetworkError> {
        let _guard = self.lock().await;
        self.inner
            .repository
            .get_port(project_id, &port_id)
            .await
            .map_err(map_store_error)?
            .ok_or(NetworkError::NotFound)?;
        self.inner
            .repository
            .update_port_binding(project_id, &port_id, None, Some("down"))
            .await
            .map_err(map_store_error)
    }
}
