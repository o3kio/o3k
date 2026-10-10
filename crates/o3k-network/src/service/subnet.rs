use super::helpers::Ipv4Net;
use super::{NetworkError, NetworkService, map_store_error};
use crate::SubnetRecord;
use o3k_kernel::{
    ActionId, AuditEvent, AuditOutcome, AuthContext, AuthorizationRequest, LimitKey,
    OwnershipScope, ResourceAmount, ResourceId, ResourceTarget, ResourceType, ScopeId,
    ServiceNamespace,
};
use std::net::Ipv4Addr;
use uuid::Uuid;

impl NetworkService {
    #[allow(clippy::too_many_arguments)]
    pub async fn create_subnet(
        &self,
        auth: &AuthContext,
        network_id: Uuid,
        name: String,
        cidr: String,
        gateway_ip: Option<Ipv4Addr>,
        allocation_start: Option<Ipv4Addr>,
        allocation_end: Option<Ipv4Addr>,
    ) -> Result<SubnetRecord, NetworkError> {
        let ns = ServiceNamespace::new("network")
            .unwrap_or_else(|_| ServiceNamespace::new_unchecked("network".to_owned()));
        let act = ActionId::new("network", "CreateSubnet").unwrap_or_else(|_| {
            ActionId::new_unchecked("network".to_owned(), "CreateSubnet".to_owned())
        });
        let req = AuthorizationRequest {
            auth_context: auth,
            action: act.clone(),
            resource_target: ResourceTarget::collection(
                ResourceType::new("network", "subnet").map_err(|_| NetworkError::InvalidRequest)?,
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
            .create_subnet_for_project(
                auth.effective_scope().id().as_str(),
                network_id,
                name,
                cidr,
                gateway_ip,
                allocation_start,
                allocation_end,
            )
            .await
        {
            Ok(record) => {
                let event = AuditEvent::from_auth(auth, ns, act, AuditOutcome::Succeeded)
                    .with_resource(
                        ResourceType::new("network", "subnet").unwrap_or_else(|_| {
                            ResourceType::new_unchecked("network".to_owned(), "subnet".to_owned())
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

    #[allow(clippy::too_many_arguments)]
    pub async fn create_subnet_for_project(
        &self,
        project_id: &str,
        network_id: Uuid,
        name: String,
        cidr: String,
        gateway_ip: Option<Ipv4Addr>,
        allocation_start: Option<Ipv4Addr>,
        allocation_end: Option<Ipv4Addr>,
    ) -> Result<SubnetRecord, NetworkError> {
        self.create_subnet_for_project_with_id(
            project_id,
            Uuid::now_v7(),
            network_id,
            name,
            cidr,
            gateway_ip,
            allocation_start,
            allocation_end,
        )
        .await
    }

    #[allow(clippy::too_many_arguments)]
    pub async fn create_subnet_for_project_with_id(
        &self,
        project_id: &str,
        id: Uuid,
        network_id: Uuid,
        name: String,
        cidr: String,
        gateway_ip: Option<Ipv4Addr>,
        allocation_start: Option<Ipv4Addr>,
        allocation_end: Option<Ipv4Addr>,
    ) -> Result<SubnetRecord, NetworkError> {
        let net = Ipv4Net::parse(&cidr)?;
        let cidr = net.canonical();
        let gateway = gateway_ip.unwrap_or(net.first_host());
        if !net.contains(gateway) || gateway == net.network || gateway == net.broadcast {
            return Err(NetworkError::InvalidRequest);
        }
        let start = allocation_start.unwrap_or(Ipv4Addr::from(u32::from(net.first_host()) + 1));
        let end = allocation_end.unwrap_or(net.last_host());
        if !net.contains(start)
            || !net.contains(end)
            || start > end
            || (u32::from(start)..=u32::from(end)).contains(&u32::from(gateway))
        {
            return Err(NetworkError::InvalidRequest);
        }
        let _guard = self.lock().await;
        self.get_canonical_network_for_project(project_id, network_id)
            .await?;
        let subnet = SubnetRecord {
            id,
            network_id,
            name,
            project_id: project_id.to_owned(),
            cidr,
            gateway_ip: gateway,
            allocation_start: start,
            allocation_end: end,
            ip_version: 4,
            enable_dhcp: true,
        };
        let scope =
            OwnershipScope::project(ScopeId::new_unchecked(project_id.to_owned()), None, None);
        let amounts = vec![ResourceAmount::new(LimitKey::network_subnets(), 1)];
        let op_id = format!("o3k:subnet:create:{}:{}", project_id, subnet.id);
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

        if self
            .inner
            .repository
            .list_canonical_realms(project_id, &network_id)
            .await
            .map_err(map_store_error)?
            .iter()
            .any(|realm| realm.state == "active")
        {
            let _ = self
                .inner
                .repository
                .release_reservation(&quota_res.id)
                .await;
            return Err(NetworkError::Conflict);
        }

        let realm = o3k_store::CanonicalAddressRealmRecord {
            id: subnet.id,
            network_id: subnet.network_id,
            project_id: subnet.project_id.clone(),
            prefix: subnet.cidr.clone(),
            overlapping_prefixes: false,
            generation: 1,
            state: "active".to_owned(),
        };
        let pool = o3k_store::CanonicalAddressPoolRecord {
            id: Uuid::now_v7(),
            realm_id: realm.id,
            project_id: realm.project_id.clone(),
            prefix: realm.prefix.clone(),
            gateway: Some(subnet.gateway_ip),
            first_usable: subnet.allocation_start,
            last_usable: subnet.allocation_end,
            generation: 1,
            state: "active".to_owned(),
        };
        match self
            .inner
            .repository
            .insert_subnet_bundle(&realm, &pool, &subnet)
            .await
        {
            Ok(()) => {
                let _ = self
                    .inner
                    .repository
                    .commit_reservation(&quota_res.id)
                    .await;
                Ok(subnet)
            }
            Err(o3k_store::StoreError::NetworkInUse)
            | Err(o3k_store::StoreError::ResourceAlreadyExists) => {
                let _ = self
                    .inner
                    .repository
                    .release_reservation(&quota_res.id)
                    .await;
                Err(NetworkError::Conflict)
            }
            Err(error) => {
                let _ = self
                    .inner
                    .repository
                    .release_reservation(&quota_res.id)
                    .await;
                Err(map_store_error(error))
            }
        }
    }

    pub async fn list_subnets(
        &self,
        auth: &AuthContext,
    ) -> Result<Vec<SubnetRecord>, NetworkError> {
        let ns = ServiceNamespace::new("network")
            .unwrap_or_else(|_| ServiceNamespace::new_unchecked("network".to_owned()));
        let act = ActionId::new("network", "ListSubnets").unwrap_or_else(|_| {
            ActionId::new_unchecked("network".to_owned(), "ListSubnets".to_owned())
        });
        let req = AuthorizationRequest {
            auth_context: auth,
            action: act.clone(),
            resource_target: ResourceTarget::collection(
                ResourceType::new("network", "subnet").map_err(|_| NetworkError::InvalidRequest)?,
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
        self.list_subnets_for_project(auth.effective_scope().id().as_str())
            .await
    }

    pub async fn list_subnets_for_project(
        &self,
        project_id: &str,
    ) -> Result<Vec<SubnetRecord>, NetworkError> {
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
                result.push(self.project_canonical_subnet(project_id, &realm).await?);
            }
        }
        Ok(result)
    }

    pub async fn get_subnet(
        &self,
        auth: &AuthContext,
        id: Uuid,
    ) -> Result<SubnetRecord, NetworkError> {
        let ns = ServiceNamespace::new("network")
            .unwrap_or_else(|_| ServiceNamespace::new_unchecked("network".to_owned()));
        let act = ActionId::new("network", "ReadSubnet").unwrap_or_else(|_| {
            ActionId::new_unchecked("network".to_owned(), "ReadSubnet".to_owned())
        });
        let req = AuthorizationRequest {
            auth_context: auth,
            action: act.clone(),
            resource_target: ResourceTarget::instance(
                ResourceType::new("network", "subnet").map_err(|_| NetworkError::InvalidRequest)?,
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
        self.get_subnet_for_project(auth.effective_scope().id().as_str(), id)
            .await
    }

    pub async fn get_subnet_for_project(
        &self,
        project_id: &str,
        id: Uuid,
    ) -> Result<SubnetRecord, NetworkError> {
        let realm = self
            .inner
            .repository
            .get_canonical_realm(project_id, &id)
            .await
            .map_err(map_store_error)?
            .ok_or(NetworkError::NotFound)?;
        self.project_canonical_subnet(project_id, &realm).await
    }

    #[allow(clippy::too_many_arguments)]
    pub async fn update_subnet(
        &self,
        auth: &AuthContext,
        id: Uuid,
        name: Option<String>,
        gateway_ip: Option<Ipv4Addr>,
        enable_dhcp: Option<bool>,
        network_id: Option<Uuid>,
        cidr: Option<String>,
        ip_version: Option<u8>,
    ) -> Result<SubnetRecord, NetworkError> {
        let action = ActionId::new("network", "UpdateSubnet").unwrap_or_else(|_| {
            ActionId::new_unchecked("network".to_owned(), "UpdateSubnet".to_owned())
        });
        let request = AuthorizationRequest {
            auth_context: auth,
            action,
            resource_target: ResourceTarget::instance(
                ResourceType::new("network", "subnet").map_err(|_| NetworkError::InvalidRequest)?,
                ResourceId::new(id.to_string()).map_err(|_| NetworkError::InvalidRequest)?,
                Some(auth.effective_scope().id().clone()),
            ),
        };
        if !self.authorizer.authorize(&request).is_allowed() {
            return Err(NetworkError::NotFound);
        }
        if network_id.is_some() || cidr.is_some() || ip_version.is_some_and(|v| v != 4) {
            return Err(NetworkError::InvalidRequest);
        }
        self.update_subnet_for_project(
            auth.effective_scope().id().as_str(),
            id,
            name,
            gateway_ip,
            enable_dhcp,
        )
        .await
    }

    async fn update_subnet_for_project(
        &self,
        project_id: &str,
        id: Uuid,
        name: Option<String>,
        gateway_ip: Option<Ipv4Addr>,
        enable_dhcp: Option<bool>,
    ) -> Result<SubnetRecord, NetworkError> {
        let realm = self
            .inner
            .repository
            .get_canonical_realm(project_id, &id)
            .await
            .map_err(map_store_error)?
            .ok_or(NetworkError::NotFound)?;
        let pool = self
            .inner
            .repository
            .list_canonical_pools(project_id, &id)
            .await
            .map_err(map_store_error)?
            .into_iter()
            .next()
            .ok_or(NetworkError::InvalidRequest)?;
        let current = self.project_canonical_subnet(project_id, &realm).await?;
        let gateway = gateway_ip.unwrap_or(current.gateway_ip);
        let net = Ipv4Net::parse(&realm.prefix)?;
        if !net.contains(gateway) || gateway == net.network || gateway == net.broadcast {
            return Err(NetworkError::InvalidRequest);
        }
        if (u32::from(pool.first_usable)..=u32::from(pool.last_usable))
            .contains(&u32::from(gateway))
        {
            return Err(NetworkError::Conflict);
        }
        let updated = SubnetRecord {
            name: name.unwrap_or(current.name),
            gateway_ip: gateway,
            enable_dhcp: enable_dhcp.unwrap_or(current.enable_dhcp),
            ..current
        };
        if gateway != pool.gateway.unwrap_or(gateway) {
            self.inner
                .repository
                .update_subnet_bundle(&updated, &pool.id, pool.generation)
                .await
                .map_err(map_store_error)?;
        } else {
            self.inner
                .repository
                .update_subnet(&updated)
                .await
                .map_err(map_store_error)?;
        }
        self.get_subnet_for_project(project_id, id).await
    }

    async fn project_canonical_subnet(
        &self,
        project_id: &str,
        realm: &o3k_store::CanonicalAddressRealmRecord,
    ) -> Result<SubnetRecord, NetworkError> {
        let pool = self
            .inner
            .repository
            .list_canonical_pools(project_id, &realm.id)
            .await
            .map_err(map_store_error)?
            .into_iter()
            .next()
            .ok_or(NetworkError::InvalidRequest)?;
        let metadata = self
            .inner
            .repository
            .get_subnet(project_id, &realm.id)
            .await
            .map_err(map_store_error)?;
        Ok(SubnetRecord {
            id: realm.id,
            network_id: realm.network_id,
            name: metadata
                .as_ref()
                .map(|value| value.name.clone())
                .unwrap_or_default(),
            project_id: realm.project_id.clone(),
            cidr: realm.prefix.clone(),
            gateway_ip: pool.gateway.ok_or(NetworkError::InvalidRequest)?,
            allocation_start: pool.first_usable,
            allocation_end: pool.last_usable,
            ip_version: 4,
            enable_dhcp: metadata
                .as_ref()
                .map(|value| value.enable_dhcp)
                .unwrap_or(true),
        })
    }

    pub async fn delete_subnet(&self, auth: &AuthContext, id: Uuid) -> Result<(), NetworkError> {
        self.authorize_subnet_deletion(auth, id).await?;
        let result = self
            .delete_subnet_for_project(auth.effective_scope().id().as_str(), id)
            .await;
        self.record_subnet_deletion_result(auth, id, result.as_ref().err())
            .await?;
        result
    }

    /// Authorizes a Neutron subnet deletion before a composition-owned
    /// provider workflow begins. This keeps provider transport outside the
    /// canonical NetworkService while preserving the DeleteSubnet action.
    pub async fn authorize_subnet_deletion(
        &self,
        auth: &AuthContext,
        id: Uuid,
    ) -> Result<(), NetworkError> {
        let ns = ServiceNamespace::new("network")
            .unwrap_or_else(|_| ServiceNamespace::new_unchecked("network".to_owned()));
        let act = ActionId::new("network", "DeleteSubnet").unwrap_or_else(|_| {
            ActionId::new_unchecked("network".to_owned(), "DeleteSubnet".to_owned())
        });
        let req = AuthorizationRequest {
            auth_context: auth,
            action: act.clone(),
            resource_target: ResourceTarget::instance(
                ResourceType::new("network", "subnet").map_err(|_| NetworkError::InvalidRequest)?,
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
        Ok(())
    }

    /// Records the result of an authorized subnet deletion, including a
    /// provider-aware deletion performed by the application composition.
    pub async fn record_subnet_deletion_result(
        &self,
        auth: &AuthContext,
        id: Uuid,
        error: Option<&NetworkError>,
    ) -> Result<(), NetworkError> {
        let namespace = ServiceNamespace::new("network")
            .unwrap_or_else(|_| ServiceNamespace::new_unchecked("network".to_owned()));
        let action = ActionId::new("network", "DeleteSubnet").unwrap_or_else(|_| {
            ActionId::new_unchecked("network".to_owned(), "DeleteSubnet".to_owned())
        });
        let resource_type = ResourceType::new("network", "subnet").unwrap_or_else(|_| {
            ResourceType::new_unchecked("network".to_owned(), "subnet".to_owned())
        });
        let mut event = AuditEvent::from_auth(
            auth,
            namespace,
            action,
            if error.is_some() {
                AuditOutcome::Failed
            } else {
                AuditOutcome::Succeeded
            },
        )
        .with_resource(
            resource_type,
            ResourceId::new(id.to_string()).ok(),
            Some(auth.effective_scope().clone()),
        );
        if let Some(error) = error {
            event = event.with_reason(error.to_string());
        }
        self.record_required_audit(&event).await
    }

    pub async fn delete_subnet_for_project(
        &self,
        project_id: &str,
        id: Uuid,
    ) -> Result<(), NetworkError> {
        let _guard = self.lock().await;
        let metadata_exists = self
            .inner
            .repository
            .get_subnet(project_id, &id)
            .await
            .map_err(map_store_error)?
            .is_some();
        let realm_exists = self
            .inner
            .repository
            .get_canonical_realm(project_id, &id)
            .await
            .map_err(map_store_error)?
            .is_some();
        if !metadata_exists && !realm_exists {
            return Err(NetworkError::NotFound);
        }
        self.inner
            .repository
            .delete_subnet_bundle(project_id, &id)
            .await
            .map_err(map_store_error)?;
        let _ = self
            .inner
            .repository
            .release_reservation_for_operation(&format!("o3k:subnet:create:{}:{}", project_id, id))
            .await;
        Ok(())
    }
}
