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

/// Reserved name prefix of an endpoint that O3K created for a server.
///
/// The tenant-facing create and rename paths reject this prefix, so only an
/// O3K server lifecycle can produce a name carrying it. That makes the durable
/// name a trustworthy ownership discriminator: a server delete may release such
/// an endpoint, and must leave every other endpoint alone even when the server
/// intent names it.
pub const SERVER_OWNED_ENDPOINT_PREFIX: &str = "o3k-server:";

/// Returns the server-context component of an O3K server-owned endpoint name.
///
/// The name is `o3k-server:<project-id>:<context>`. The context is non-empty
/// and the encoded owner must equal `project_id`, so a project can never claim
/// another project's endpoint by naming it, and a malformed reserved name is
/// not treated as owned.
pub fn server_owned_endpoint_context<'a>(project_id: &str, name: &'a str) -> Option<&'a str> {
    let (owner, context) = name
        .strip_prefix(SERVER_OWNED_ENDPOINT_PREFIX)?
        .split_once(':')?;
    (!context.is_empty() && owner == project_id).then_some(context)
}

/// Whether `name` is an O3K server-owned endpoint identity of `project_id`.
pub fn is_server_owned_endpoint_name(project_id: &str, name: &str) -> bool {
    server_owned_endpoint_context(project_id, name).is_some()
}

/// Whether a port is durably attached to a (live or attaching) instance.
///
/// `bound` is an observed realized attachment; `binding` is an attachment whose
/// dispatch selected a host but realization is not yet observed. Either means a
/// guest depends on the endpoint, so a cleanup that does not know about that
/// server must not delete it. `down` and `error` are terminal unbind outcomes
/// recorded by the owning server's delete; those endpoints are safe to release.
fn is_bound_to_instance(port: &PortRecord) -> bool {
    matches!(
        port.binding_state.as_deref(),
        Some("bound") | Some("binding")
    )
}

/// Bounded, endpoint-counted outcome of releasing the server-owned endpoints
/// named by a server's durable create intent.
///
/// Counts only, so the report is safe to log and to assert on. It is the
/// observability contract for the #1035 orphan repair sweep: the request path
/// discards it, and the repair pass reports it.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub struct ServerOwnedEndpointRelease {
    /// O3K server-owned endpoints observed present in `project_id`.
    pub discovered: usize,
    /// Of those, the ones now gone. A concurrent equivalent cleanup that won
    /// the race restores the same invariant, so it counts here too.
    pub released: usize,
    /// Present endpoints that are not O3K server-owned — a caller-supplied
    /// endpoint, or another project's — preserved untouched.
    pub preserved: usize,
    /// Identifiers with nothing present to repair: an already-released
    /// endpoint, or an identifier that does not resolve inside `project_id`.
    pub absent: usize,
}

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
        if name.starts_with(SERVER_OWNED_ENDPOINT_PREFIX) {
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
        // Stable native identities still use the canonical pool allocator. A
        // compatibility/TestLab port may already occupy the first address;
        // skip it rather than coupling deterministic port identity to a fixed
        // IP. The database uniqueness constraint remains the race-safe guard
        // when independent runtimes allocate concurrently.
        let occupied_addresses = self
            .inner
            .repository
            .list_canonical_endpoints(project_id, &realm.id)
            .await
            .map_err(map_store_error)?
            .into_iter()
            .map(|endpoint| endpoint.fixed_ip)
            .collect::<std::collections::HashSet<_>>();
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
                if explicit_ip.is_none() && occupied_addresses.contains(&address) {
                    candidate = candidate.saturating_add(1);
                    continue;
                }
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
                // A failed address attempt releases its reservation. Include
                // the candidate in the idempotency key so a concurrent
                // stable-id retry can advance without reusing a released
                // reservation tombstone.
                let op_id = format!("o3k:port:create:{}:{}:{}", project_id, port.id, address);
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
                        if explicit_ip.is_some() {
                            return Err(NetworkError::Conflict);
                        }
                        if stable_id {
                            // ResourceAlreadyExists can be either the stable
                            // identity replay or a concurrent address winner.
                            // Re-read the authoritative endpoint set to
                            // distinguish them; only the former is a replay
                            // conflict, while the latter advances to the next
                            // free address.
                            let identity_exists = self
                                .inner
                                .repository
                                .get_canonical_endpoint(project_id, &id)
                                .await
                                .map_err(map_store_error)?
                                .is_some();
                            if identity_exists {
                                return Err(NetworkError::Conflict);
                            }
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
        if current.name.starts_with(SERVER_OWNED_ENDPOINT_PREFIX) {
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

    /// Releases the O3K-owned endpoints a server lifecycle created for
    /// `project_id`.
    ///
    /// `port_ids` is the caller's durable view of the server's network
    /// attachments. Ownership is decided from the durable endpoint row, never
    /// from the request: an endpoint is released only when it resolves inside
    /// `project_id` **and** carries the reserved server-owned name
    /// ([`is_server_owned_endpoint_name`]). Therefore:
    ///
    /// - an endpoint the caller supplied itself is preserved, because a server
    ///   attaching an endpoint is not the same as a server owning it;
    /// - an endpoint of another project is never touched, so a forged or
    ///   guessed identifier cannot delete foreign network state;
    /// - an already-absent endpoint is idempotent success, so a replay or a
    ///   concurrent equivalent cleanup converges;
    /// - any other store or lookup failure is returned, so the caller reports
    ///   a failed mutation and retries instead of silently leaving a live,
    ///   consumable side effect behind.
    ///
    /// Endpoint release removes the durable endpoint, its policy attachments
    /// and its create reservation, which frees the address for reuse and
    /// releases the network-port quota.
    ///
    /// The returned [`ServerOwnedEndpointRelease`] is the bounded
    /// observability contract for the #1035 orphan repair sweep. The request
    /// path ignores it: what matters there is only whether the call failed.
    pub async fn cleanup_server_owned_ports_for_project(
        &self,
        project_id: &str,
        port_ids: &[Uuid],
    ) -> Result<ServerOwnedEndpointRelease, NetworkError> {
        let mut report = ServerOwnedEndpointRelease::default();
        for port_id in port_ids {
            // Hold the network-service lock across [binding-fence read -> delete]
            // so the re-read and the delete cannot interleave with a binding
            // transition (issue #1035, atomic fence): a live server that binds
            // this port between the read and the delete is never stripped,
            // because the delete only runs when the fence read just observed
            // `down`. Neither `get_port_for_project` nor
            // `delete_port_for_project` takes this lock, so there is no
            // re-entrancy.
            let _guard = self.lock().await;
            match self.get_port_for_project(project_id, *port_id).await {
                Ok(port) => {
                    if !is_server_owned_endpoint_name(project_id, &port.name) {
                        report.preserved += 1;
                        continue;
                    }
                    report.discovered += 1;
                    // Durable-binding fence (backstop to the sweep's
                    // `still_attached` scan): a terminally deleted server's
                    // endpoint may have been explicitly re-attached by a NEW
                    // live server, which leaves the port bound (or still
                    // binding) even though its original owner is gone. A replay
                    // or a scan that predates the attach must refuse to delete
                    // it, or it strips the live server's NIC. The binding is
                    // re-read immediately before the delete (observe-before-
                    // destroy, now atomic under the network lock); while bound
                    // the endpoint is preserved and the next pass retries it.
                    // Only an endpoint no longer bound to any instance may be
                    // released.
                    if is_bound_to_instance(&port) {
                        report.preserved += 1;
                        continue;
                    }
                    match self.delete_port_for_project(project_id, *port_id).await {
                        Ok(()) => report.released += 1,
                        // The endpoint was observed present and owned, then a
                        // concurrent equivalent cleanup removed it first. The
                        // invariant is restored either way, so the pass reports
                        // it as released rather than as a failure.
                        Err(NetworkError::NotFound) => report.released += 1,
                        Err(error) => return Err(error),
                    }
                }
                Err(NetworkError::NotFound) => report.absent += 1,
                Err(error) => return Err(error),
            }
        }
        Ok(report)
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
