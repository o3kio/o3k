use super::helpers::Ipv4Net;
use super::legacy_import::import_legacy_metadata;
use super::{Inner, NetworkError, NetworkService, map_store_error};
use crate::{
    CanonicalPolicyService, CanonicalPolicyServiceError, PolicyApplyOutcome,
    PolicySnapshotRealizer, compile_l3_gateway_execution_plan,
};
use o3k_domain::{FabricProviderKind, Ipv4Prefix, NetworkPlanIntent, RealmEncapsulationBinding};
use o3k_kernel::{
    ActionId, AuditEvent, AuditOutcome, AuthContext, AuthorizationRequest, Authorizer,
    DecisionReason, MemoryAuditSink, OwnershipScope, ResourceId, ResourceTarget, ResourceType,
    ScopeId, ServiceNamespace, StaticAuthorizer,
};
use std::{
    collections::{BTreeMap, BTreeSet},
    fs,
    net::Ipv4Addr,
    path::PathBuf,
    sync::Arc,
};
use uuid::Uuid;

fn realm_delete_operation(
    project_id: &str,
    realm_id: Uuid,
) -> Result<
    (
        o3k_store::OperationRecord,
        o3k_store::CanonicalOperationRecord,
        o3k_store::IdempotencyReservationRequest,
    ),
    NetworkError,
> {
    let action =
        ActionId::new("network", "DeleteRealm").map_err(|_| NetworkError::InvalidRequest)?;
    let resource_type =
        ResourceType::new("network", "address_realm").map_err(|_| NetworkError::InvalidRequest)?;
    let operation_id = Uuid::new_v5(
        &Uuid::NAMESPACE_URL,
        format!("o3k:network:realm-delete:{project_id}:{realm_id}").as_bytes(),
    );
    let scope = OwnershipScope::project(ScopeId::new_unchecked(project_id.to_owned()), None, None);
    let kernel = o3k_kernel::Operation::new(
        operation_id,
        "network",
        action.clone(),
        "o3k:network-service",
        scope,
        resource_type.clone(),
        Some(ResourceId::new_unchecked(realm_id.to_string())),
        None,
    );
    let canonical = o3k_store::CanonicalOperationRecord::from_kernel_operation(&kernel)
        .map_err(map_store_error)?;
    let operation = o3k_store::OperationRecord {
        id: operation_id,
        resource_id: realm_id,
        kind: "lifecycle:realm-delete".to_owned(),
        state: o3k_store::OperationState::Pending,
        provider_operation_id: None,
        error_category: None,
        error_message: None,
    };
    let request = o3k_store::IdempotencyReservationRequest::from_semantics(
        project_id,
        action.to_string(),
        format!("canonical:realm-delete:{realm_id}"),
        &resource_type.to_string(),
        Some(&realm_id.to_string()),
        &serde_json::json!({"realm_id": realm_id}),
        operation_id,
    )
    .map_err(map_store_error)?;
    Ok((operation, canonical, request))
}

/// Canonical network reconstruction result. Compatibility projections and
/// provider plans are derived from this durable graph; they are never used to
/// recover missing canonical children.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CanonicalNetworkSnapshot {
    pub network: o3k_store::CanonicalNetworkRecord,
    pub realms: Vec<o3k_store::CanonicalAddressRealmRecord>,
    pub pools: BTreeMap<Uuid, Vec<o3k_store::CanonicalAddressPoolRecord>>,
    pub endpoints: BTreeMap<Uuid, Vec<o3k_store::CanonicalEndpointRecord>>,
    /// Canonical L3 gateway authority relevant to this network's realms.
    /// Provider plans are derived from this graph; it is not compatibility
    /// state and does not redefine AddressRealm identity.
    pub l3_gateways: Vec<(
        o3k_store::CanonicalL3GatewayRecord,
        Vec<o3k_store::CanonicalL3GatewayAttachmentRecord>,
    )>,
}

/// Compiles the canonical gateway graph into the existing provider-neutral
/// routing intents. AddressRealm remains the unit of address interpretation;
/// this function only derives connectivity from the gateway attachments.
pub type GatewayIntentMap = BTreeMap<
    Uuid,
    (
        Vec<o3k_domain::GatewayIntent>,
        Vec<o3k_domain::EgressIntent>,
    ),
>;

pub fn compile_l3_gateway_intents(
    gateway: &o3k_store::CanonicalL3GatewayRecord,
    attachments: &[o3k_store::CanonicalL3GatewayAttachmentRecord],
    realms: &[o3k_store::CanonicalAddressRealmRecord],
    pools: &BTreeMap<Uuid, Vec<o3k_store::CanonicalAddressPoolRecord>>,
) -> Result<GatewayIntentMap, NetworkError> {
    if gateway.state != "active" || gateway.generation == 0 {
        return Err(NetworkError::InvalidRequest);
    }
    let mut realm_map = BTreeMap::new();
    for realm in realms {
        if realm.project_id != gateway.project_id || realm.state != "active" {
            continue;
        }
        let (network, prefix) = realm
            .prefix
            .split_once('/')
            .ok_or(NetworkError::InvalidRequest)?;
        let address = network.parse().map_err(|_| NetworkError::InvalidRequest)?;
        let prefix_len = prefix.parse().map_err(|_| NetworkError::InvalidRequest)?;
        let prefix = Ipv4Prefix::new(address, prefix_len).ok_or(NetworkError::InvalidRequest)?;
        realm_map.insert(realm.id, prefix);
    }
    let attached: BTreeSet<Uuid> = attachments
        .iter()
        .filter(|attachment| {
            attachment.project_id == gateway.project_id && attachment.state == "active"
        })
        .map(|attachment| attachment.realm_id)
        .collect();
    let mut result = BTreeMap::new();
    for realm_id in &attached {
        let local = realm_map.get(realm_id).ok_or(NetworkError::NotFound)?;
        let local_gateway = pools
            .get(realm_id)
            .and_then(|items| items.iter().find_map(|pool| pool.gateway))
            .or_else(|| u32::from(local.network).checked_add(1).map(Ipv4Addr::from))
            .ok_or(NetworkError::InvalidRequest)?;
        let mut routes = Vec::new();
        for remote_id in &attached {
            if remote_id != realm_id {
                routes.push(o3k_domain::GatewayIntent {
                    destination: *realm_map.get(remote_id).ok_or(NetworkError::NotFound)?,
                    gateway: local_gateway,
                    external: false,
                });
            }
        }
        let egress = gateway
            .external_realm_id
            .map(|external_realm_id| {
                vec![o3k_domain::EgressIntent {
                    external_realm_id,
                    enabled: true,
                    nat: gateway.enable_snat,
                }]
            })
            .unwrap_or_default();
        result.insert(*realm_id, (routes, egress));
    }
    Ok(result)
}

/// Result of observing one provider-owned Realm cleanup identity. A Realm
/// remains canonical while the provider outcome is present or unknown.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum RealmCleanupObservation {
    Absent(o3k_store::CanonicalRealmBindingRecord),
    Present(o3k_store::CanonicalRealmBindingRecord),
    Unknown {
        binding: o3k_store::CanonicalRealmBindingRecord,
        reason: String,
    },
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum RealmCleanupProgress {
    Deleting { operation_id: Uuid, generation: u64 },
    AwaitingObservation { operation_id: Uuid, generation: u64 },
    Removed { operation_id: Uuid },
}

impl NetworkService {
    /// Records or idempotently replays one operator-enrolled Fabric transport
    /// identity. This is canonical host admission state; secret key material
    /// is not representable in the record.
    pub async fn enroll_fabric_host_transport_identity(
        &self,
        identity: &o3k_store::FabricHostTransportIdentityRecord,
        expected_generation: Option<u64>,
    ) -> Result<o3k_store::FabricHostTransportIdentityRecord, NetworkError> {
        self.inner
            .repository
            .upsert_fabric_host_identity(identity, expected_generation)
            .await
            .map_err(map_store_error)
    }

    pub async fn list_fabric_host_transport_identities(
        &self,
    ) -> Result<Vec<o3k_store::FabricHostTransportIdentityRecord>, NetworkError> {
        self.inner
            .repository
            .list_fabric_host_identities()
            .await
            .map_err(map_store_error)
    }

    /// Allocates a stable provider VNI for an active realm using the existing
    /// durable encapsulation binding table. A deterministic probe sequence
    /// makes concurrent first allocation converge while the database's
    /// uniqueness constraints arbitrate collisions.
    pub async fn ensure_vxlan_realm_binding(
        &self,
        fabric_domain_id: Uuid,
        realm: &o3k_store::CanonicalAddressRealmRecord,
    ) -> Result<RealmEncapsulationBinding, NetworkError> {
        if fabric_domain_id.is_nil() || realm.state != "active" {
            return Err(NetworkError::InvalidRequest);
        }
        let domain_key = fabric_domain_id.to_string();
        if let Some(existing) = self
            .inner
            .repository
            .get_canonical_realm_binding(&domain_key, &realm.id)
            .await
            .map_err(map_store_error)?
        {
            if existing.provider_kind != "vxlan" || existing.state != "active" {
                return Err(NetworkError::Conflict);
            }
            let binding = RealmEncapsulationBinding {
                fabric_domain_id,
                realm_id: realm.id,
                provider_kind: FabricProviderKind::Vxlan,
                provider_segment_id: u32::try_from(existing.provider_segment_id)
                    .map_err(|_| NetworkError::InvalidRequest)?,
                binding_generation: existing.binding_generation,
            };
            binding.validate().map_err(|_| NetworkError::Conflict)?;
            return Ok(binding);
        }

        const MAX_VNI: u32 = 0x000f_ffff;
        let seed = u32::from_be_bytes(
            realm.id.as_bytes()[..4]
                .try_into()
                .map_err(|_| NetworkError::InvalidRequest)?,
        ) % MAX_VNI;
        for offset in 0..MAX_VNI {
            let segment = ((seed + offset) % MAX_VNI) + 1;
            let candidate = o3k_store::CanonicalRealmBindingRecord {
                fabric_domain_id: domain_key.clone(),
                realm_id: realm.id,
                provider_kind: "vxlan".to_owned(),
                provider_segment_id: u64::from(segment),
                binding_generation: 1,
                state: "active".to_owned(),
            };
            match self
                .inner
                .repository
                .insert_canonical_realm_binding(&candidate)
                .await
            {
                Ok(()) => {
                    return Ok(RealmEncapsulationBinding {
                        fabric_domain_id,
                        realm_id: realm.id,
                        provider_kind: FabricProviderKind::Vxlan,
                        provider_segment_id: segment,
                        binding_generation: 1,
                    });
                }
                Err(o3k_store::StoreError::ResourceAlreadyExists) => {
                    if let Some(existing) = self
                        .inner
                        .repository
                        .get_canonical_realm_binding(&domain_key, &realm.id)
                        .await
                        .map_err(map_store_error)?
                    {
                        if existing.provider_kind == "vxlan" && existing.state == "active" {
                            return Ok(RealmEncapsulationBinding {
                                fabric_domain_id,
                                realm_id: realm.id,
                                provider_kind: FabricProviderKind::Vxlan,
                                provider_segment_id: u32::try_from(existing.provider_segment_id)
                                    .map_err(|_| NetworkError::InvalidRequest)?,
                                binding_generation: existing.binding_generation,
                            });
                        }
                        return Err(NetworkError::Conflict);
                    }
                }
                Err(error) => return Err(map_store_error(error)),
            }
        }
        Err(NetworkError::PoolExhausted)
    }
}

impl NetworkService {
    /// Advances the sole active AddressRealm generation for a network before
    /// a v3 endpoint binding is withdrawn. The compare-and-swap makes a stale
    /// unbind retry fail closed rather than publishing plans under an old
    /// realm directory generation.
    pub async fn advance_fabric_realm_generation(
        &self,
        project_id: &str,
        network_id: Uuid,
    ) -> Result<o3k_store::CanonicalAddressRealmRecord, NetworkError> {
        let realms = self
            .inner
            .repository
            .list_canonical_realms(project_id, &network_id)
            .await
            .map_err(map_store_error)?
            .into_iter()
            .filter(|realm| realm.state == "active")
            .collect::<Vec<_>>();
        let [realm] = realms.as_slice() else {
            return Err(NetworkError::Conflict);
        };
        self.inner
            .repository
            .advance_canonical_realm_generation(project_id, &realm.id, realm.generation)
            .await
            .map_err(map_store_error)
    }

    /// Creates the provider-independent L3 gateway authority. This is
    /// intentionally persistence-only; Neutron projection and provider
    /// realization are layered above the canonical graph.
    pub async fn create_l3_gateway_for_project(
        &self,
        project_id: &str,
        name: String,
        external_realm_id: Option<Uuid>,
        enable_snat: bool,
    ) -> Result<o3k_store::CanonicalL3GatewayRecord, NetworkError> {
        self.create_l3_gateway_for_project_with_id(
            Uuid::now_v7(),
            project_id,
            name,
            external_realm_id,
            enable_snat,
        )
        .await
    }

    pub async fn create_l3_gateway_for_project_with_id(
        &self,
        id: Uuid,
        project_id: &str,
        name: String,
        external_realm_id: Option<Uuid>,
        enable_snat: bool,
    ) -> Result<o3k_store::CanonicalL3GatewayRecord, NetworkError> {
        if name.trim().is_empty() {
            return Err(NetworkError::InvalidRequest);
        }
        if let Some(realm_id) = external_realm_id {
            let realm = self
                .inner
                .repository
                .get_canonical_realm(project_id, &realm_id)
                .await
                .map_err(map_store_error)?
                .ok_or(NetworkError::NotFound)?;
            if realm.state != "active" {
                return Err(NetworkError::Conflict);
            }
        }
        let gateway = o3k_store::CanonicalL3GatewayRecord {
            id,
            project_id: project_id.to_owned(),
            name,
            external_realm_id,
            enable_snat,
            generation: 1,
            state: "active".to_owned(),
        };
        self.inner
            .repository
            .insert_canonical_l3_gateway(&gateway)
            .await
            .map_err(map_store_error)?;
        Ok(gateway)
    }

    pub async fn list_l3_gateways_for_project(
        &self,
        project_id: &str,
    ) -> Result<Vec<o3k_store::CanonicalL3GatewayRecord>, NetworkError> {
        self.inner
            .repository
            .list_canonical_l3_gateways(project_id)
            .await
            .map_err(map_store_error)
    }

    /// Enumerates durable gateway deletion reservations for a fresh runtime.
    /// The returned canonical rows are recovery inputs only; provider state
    /// is never used to recreate them.
    pub async fn list_deleting_l3_gateways(
        &self,
    ) -> Result<Vec<o3k_store::CanonicalL3GatewayRecord>, NetworkError> {
        self.inner
            .repository
            .list_canonical_l3_gateways_by_state("deleting")
            .await
            .map_err(map_store_error)
    }

    pub async fn list_deleting_l3_gateway_attachments(
        &self,
    ) -> Result<Vec<o3k_store::CanonicalL3GatewayAttachmentRecord>, NetworkError> {
        self.inner
            .repository
            .list_canonical_l3_gateway_attachments_by_state("deleting")
            .await
            .map_err(map_store_error)
    }

    /// Enumerates policy child deletion reservations for startup recovery.
    /// These rows are canonical transitional state; provider observations are
    /// used only to decide when they may be finalized.
    pub async fn list_deleting_policy_rules(
        &self,
    ) -> Result<Vec<o3k_store::CanonicalNetworkPolicyRuleRecord>, NetworkError> {
        self.inner
            .repository
            .list_deleting_policy_rules()
            .await
            .map_err(map_store_error)
    }

    pub async fn list_deleting_policy_attachments(
        &self,
    ) -> Result<Vec<o3k_store::CanonicalPolicyAttachmentRecord>, NetworkError> {
        self.inner
            .repository
            .list_deleting_policy_attachments()
            .await
            .map_err(map_store_error)
    }

    /// Resolves the network execution context for a canonical endpoint. The
    /// endpoint and realm remain canonical authority; this is only dispatch
    /// input for the host-local network execution boundary.
    pub async fn network_id_for_canonical_endpoint(
        &self,
        project_id: &str,
        endpoint_id: &Uuid,
    ) -> Result<Uuid, NetworkError> {
        let endpoint = self
            .inner
            .repository
            .get_canonical_endpoint(project_id, endpoint_id)
            .await
            .map_err(map_store_error)?
            .ok_or(NetworkError::NotFound)?;
        self.inner
            .repository
            .get_canonical_realm(project_id, &endpoint.realm_id)
            .await
            .map_err(map_store_error)?
            .map(|realm| realm.network_id)
            .ok_or(NetworkError::NotFound)
    }

    pub async fn get_l3_gateway_for_project(
        &self,
        project_id: &str,
        gateway_id: &Uuid,
    ) -> Result<o3k_store::CanonicalL3GatewayRecord, NetworkError> {
        self.inner
            .repository
            .get_canonical_l3_gateway(project_id, gateway_id)
            .await
            .map_err(map_store_error)?
            .ok_or(NetworkError::NotFound)
    }

    pub async fn attach_l3_gateway_realm(
        &self,
        project_id: &str,
        gateway_id: &Uuid,
        realm_id: &Uuid,
    ) -> Result<o3k_store::CanonicalL3GatewayAttachmentRecord, NetworkError> {
        self.attach_l3_gateway_realm_with_id(Uuid::now_v7(), project_id, gateway_id, realm_id)
            .await
    }

    pub async fn attach_l3_gateway_realm_with_id(
        &self,
        id: Uuid,
        project_id: &str,
        gateway_id: &Uuid,
        realm_id: &Uuid,
    ) -> Result<o3k_store::CanonicalL3GatewayAttachmentRecord, NetworkError> {
        let gateway = self
            .get_l3_gateway_for_project(project_id, gateway_id)
            .await?;
        if gateway.state != "active" {
            return Err(NetworkError::Conflict);
        }
        if self
            .inner
            .repository
            .get_canonical_realm(project_id, realm_id)
            .await
            .map_err(map_store_error)?
            .is_none()
        {
            return Err(NetworkError::NotFound);
        }
        if self
            .inner
            .repository
            .list_canonical_l3_gateway_attachments(project_id, gateway_id)
            .await
            .map_err(map_store_error)?
            .iter()
            .any(|attachment| attachment.realm_id == *realm_id)
        {
            // The relation is a durable deletion reservation as well as a
            // compatibility object. Do not replace it while the provider is
            // still converging the detach.
            return Err(NetworkError::Conflict);
        }
        let attachment = o3k_store::CanonicalL3GatewayAttachmentRecord {
            id,
            gateway_id: *gateway_id,
            realm_id: *realm_id,
            project_id: project_id.to_owned(),
            generation: 1,
            state: "active".to_owned(),
        };
        self.inner
            .repository
            .insert_canonical_l3_gateway_attachment(&attachment)
            .await
            .map_err(map_store_error)?;
        Ok(attachment)
    }

    pub async fn update_l3_gateway_for_project(
        &self,
        project_id: &str,
        gateway_id: &Uuid,
        expected_generation: u64,
        name: String,
        external_realm_id: Option<Uuid>,
        enable_snat: bool,
    ) -> Result<o3k_store::CanonicalL3GatewayRecord, NetworkError> {
        if name.trim().is_empty() {
            return Err(NetworkError::InvalidRequest);
        }
        if let Some(realm_id) = external_realm_id {
            let realm = self
                .inner
                .repository
                .get_canonical_realm(project_id, &realm_id)
                .await
                .map_err(map_store_error)?
                .ok_or(NetworkError::NotFound)?;
            if realm.state != "active" {
                return Err(NetworkError::Conflict);
            }
        }
        self.inner
            .repository
            .update_canonical_l3_gateway(
                project_id,
                gateway_id,
                expected_generation,
                &name,
                external_realm_id,
                enable_snat,
            )
            .await
            .map_err(map_store_error)
    }

    pub async fn delete_l3_gateway_for_project(
        &self,
        project_id: &str,
        gateway_id: &Uuid,
        expected_generation: u64,
    ) -> Result<o3k_store::CanonicalL3GatewayRecord, NetworkError> {
        self.inner
            .repository
            .begin_canonical_l3_gateway_deletion(project_id, gateway_id, expected_generation)
            .await
            .map_err(map_store_error)
    }

    /// Finalizes a gateway deletion only after the provider has withdrawn the
    /// complete gateway realization and absence has been observed.  Keeping
    /// this separate from reservation makes the deleting row restart-safe.
    pub async fn finalize_l3_gateway_deletion_for_project(
        &self,
        project_id: &str,
        gateway_id: &Uuid,
        expected_generation: u64,
    ) -> Result<(), NetworkError> {
        self.inner
            .repository
            .finalize_canonical_l3_gateway_deletion(project_id, gateway_id, expected_generation)
            .await
            .map_err(map_store_error)
    }

    pub async fn detach_l3_gateway_realm(
        &self,
        project_id: &str,
        attachment_id: &Uuid,
        expected_generation: u64,
    ) -> Result<o3k_store::CanonicalL3GatewayAttachmentRecord, NetworkError> {
        self.inner
            .repository
            .begin_canonical_l3_gateway_attachment_deletion(
                project_id,
                attachment_id,
                expected_generation,
            )
            .await
            .map_err(map_store_error)
    }

    /// Finalizes an attachment deletion only after the complete remaining
    /// gateway snapshot has converged and the detached provider link is absent.
    pub async fn finalize_l3_gateway_realm_detachment_for_project(
        &self,
        project_id: &str,
        attachment_id: &Uuid,
        expected_generation: u64,
    ) -> Result<(), NetworkError> {
        self.inner
            .repository
            .finalize_canonical_l3_gateway_attachment_deletion(
                project_id,
                attachment_id,
                expected_generation,
            )
            .await
            .map_err(map_store_error)
    }

    pub async fn list_l3_gateway_attachments(
        &self,
        project_id: &str,
        gateway_id: &Uuid,
    ) -> Result<Vec<o3k_store::CanonicalL3GatewayAttachmentRecord>, NetworkError> {
        self.inner
            .repository
            .list_canonical_l3_gateway_attachments(project_id, gateway_id)
            .await
            .map_err(map_store_error)
    }

    /// Reconstructs the provider-independent multi-Realm gateway execution
    /// unit from canonical persistence. Linux namespace/interface details are
    /// intentionally supplied by the provider's derived Realm directory,
    /// never persisted in this plan.
    pub async fn compile_l3_gateway_execution_plan_for_project(
        &self,
        project_id: &str,
        gateway_id: &Uuid,
    ) -> Result<o3k_domain::L3GatewayExecutionPlan, NetworkError> {
        let gateway = self
            .get_l3_gateway_for_project(project_id, gateway_id)
            .await?;
        let mut compilable_gateway = gateway.clone();
        if !matches!(gateway.state.as_str(), "active" | "deleting") {
            return Err(NetworkError::Conflict);
        }
        // The provider-neutral compiler validates an active desired snapshot.
        // A deleting row is nevertheless a valid durable removal reservation:
        // compile that snapshot without changing its persisted generation.
        compilable_gateway.state = "active".to_owned();
        let attachments = self
            .list_l3_gateway_attachments(project_id, gateway_id)
            .await?;
        let mut realms = BTreeMap::new();
        for attachment in &attachments {
            if let Some(realm) = self
                .inner
                .repository
                .get_canonical_realm(project_id, &attachment.realm_id)
                .await
                .map_err(map_store_error)?
            {
                realms.insert(realm.id, realm);
            }
        }
        if let Some(external_realm_id) = gateway.external_realm_id {
            let external = self
                .inner
                .repository
                .get_canonical_realm(project_id, &external_realm_id)
                .await
                .map_err(map_store_error)?
                .ok_or(NetworkError::NotFound)?;
            if external.state != "active" {
                return Err(NetworkError::Conflict);
            }
            realms.insert(external.id, external);
        }
        compile_l3_gateway_execution_plan(&compilable_gateway, &attachments, &realms)
            .map_err(|_| NetworkError::InvalidRequest)
    }

    pub async fn open(
        root: impl Into<PathBuf>,
        repository: Arc<dyn o3k_store::NetworkRepository>,
        audit_sink: Arc<dyn o3k_kernel::RequiredAuditPublisher>,
    ) -> Result<Self, NetworkError> {
        let root = root.into();
        fs::create_dir_all(&root).map_err(|source| {
            NetworkError::Store(o3k_store::StoreError::CreateDataDirectory {
                path: root.clone(),
                source,
            })
        })?;
        let inner = Arc::new(Inner { root, repository });
        if inner.root.join("metadata.json").exists() {
            import_legacy_metadata(&inner.root, inner.repository.as_ref()).await?;
        }
        inner
            .repository
            .backfill_canonical_network_state()
            .await
            .map_err(map_store_error)?;
        let service = Self {
            inner,
            lock: Arc::new(tokio::sync::Mutex::new(())),
            authorizer: Arc::new(StaticAuthorizer::standard()),
            audit_sink,
        };
        service.recover_realm_deletion_operations().await?;
        Ok(service)
    }

    /// Explicit test construction with an in-memory required publisher.
    #[doc(hidden)]
    pub async fn open_for_test(
        root: impl Into<PathBuf>,
        repository: Arc<dyn o3k_store::NetworkRepository>,
    ) -> Result<Self, NetworkError> {
        Self::open(root, repository, Arc::new(MemoryAuditSink::new())).await
    }

    /// Rebuilds one endpoint's effective policy from canonical reusable policy
    /// state. This is the runtime integration seam; the returned snapshot is
    /// still derived execution input and is never written back as policy
    /// authority.
    pub async fn compile_canonical_policy_for_endpoint(
        &self,
        project_id: &str,
        endpoint_id: Uuid,
    ) -> Result<(Vec<NetworkPlanIntent>, String), CanonicalPolicyServiceError> {
        CanonicalPolicyService::new(self.inner.repository.clone())
            .compile_endpoint(project_id, endpoint_id)
            .await
    }

    pub async fn affected_endpoints_for_canonical_policy(
        &self,
        project_id: &str,
        policy_id: Uuid,
    ) -> Result<Vec<Uuid>, CanonicalPolicyServiceError> {
        CanonicalPolicyService::new(self.inner.repository.clone())
            .affected_endpoints_for_policy(project_id, policy_id)
            .await
    }

    pub async fn reconcile_canonical_policy_for_endpoint<P>(
        &self,
        project_id: &str,
        endpoint_id: Uuid,
        expected_fingerprint: Option<&str>,
        provider: &P,
    ) -> Result<PolicyApplyOutcome, CanonicalPolicyServiceError>
    where
        P: PolicySnapshotRealizer,
    {
        CanonicalPolicyService::new(self.inner.repository.clone())
            .reconcile_endpoint_policy(project_id, endpoint_id, expected_fingerprint, provider)
            .await
    }

    pub async fn reconcile_canonical_policy_endpoints<P>(
        &self,
        project_id: &str,
        policy_id: Uuid,
        provider: &P,
    ) -> Result<Vec<(Uuid, PolicyApplyOutcome)>, CanonicalPolicyServiceError>
    where
        P: PolicySnapshotRealizer,
    {
        CanonicalPolicyService::new(self.inner.repository.clone())
            .reconcile_policy_endpoints(project_id, policy_id, provider)
            .await
    }

    pub async fn recover_canonical_policy_realizations<P>(
        &self,
        project_id: &str,
        provider: &P,
    ) -> Result<Vec<(Uuid, PolicyApplyOutcome)>, CanonicalPolicyServiceError>
    where
        P: PolicySnapshotRealizer,
    {
        CanonicalPolicyService::new(self.inner.repository.clone())
            .recover_policy_realizations(project_id, provider)
            .await
    }

    #[must_use]
    pub fn with_authorizer(mut self, authorizer: Arc<dyn Authorizer>) -> Self {
        self.authorizer = authorizer;
        self
    }

    #[must_use]
    pub fn with_required_audit_publisher(
        mut self,
        audit_sink: Arc<dyn o3k_kernel::RequiredAuditPublisher>,
    ) -> Self {
        self.audit_sink = audit_sink;
        self
    }

    pub(super) async fn authorize_canonical_action(
        &self,
        auth: &AuthContext,
        action_name: &str,
        resource_name: &str,
        resource_id: Option<Uuid>,
        parent: Option<(&str, Uuid)>,
    ) -> Result<(ServiceNamespace, ActionId, ResourceType), NetworkError> {
        let namespace = ServiceNamespace::new("network")
            .unwrap_or_else(|_| ServiceNamespace::new_unchecked("network".to_owned()));
        let action =
            ActionId::new("network", action_name).map_err(|_| NetworkError::InvalidRequest)?;
        let resource_type = ResourceType::new("network", resource_name)
            .map_err(|_| NetworkError::InvalidRequest)?;
        let owner_scope = match resource_id {
            Some(id) => self
                .inner
                .repository
                .get_canonical_owner(resource_name, &id)
                .await
                .map_err(map_store_error)?
                .ok_or(NetworkError::NotFound)?,
            None => match parent {
                Some((parent_name, parent_id)) => self
                    .inner
                    .repository
                    .get_canonical_owner(parent_name, &parent_id)
                    .await
                    .map_err(map_store_error)?
                    .ok_or(NetworkError::NotFound)?,
                None => auth.effective_scope().id().as_str().to_owned(),
            },
        };
        let owner_scope = ScopeId::new(owner_scope).map_err(|_| NetworkError::InvalidRequest)?;
        let target = match resource_id {
            Some(id) => ResourceTarget::instance(
                resource_type.clone(),
                ResourceId::new(id.to_string()).map_err(|_| NetworkError::InvalidRequest)?,
                Some(owner_scope.clone()),
            ),
            None => ResourceTarget::collection(resource_type.clone(), Some(owner_scope.clone())),
        };
        let decision = self.authorizer.authorize(&AuthorizationRequest {
            auth_context: auth,
            action: action.clone(),
            resource_target: target,
        });
        if !decision.is_allowed() {
            // Scope-concealed denials must not turn Audit into an existence
            // oracle.  Preserve the target only for denials where the caller
            // is already entitled to know which resource was addressed.
            let audit_target = match decision.reason() {
                DecisionReason::ScopeMismatch | DecisionReason::MissingOwnership => None,
                _ => resource_id.and_then(|id| ResourceId::new(id.to_string()).ok()),
            };
            self.record_required_audit(
                &AuditEvent::from_auth(
                    auth,
                    namespace.clone(),
                    action.clone(),
                    AuditOutcome::Denied,
                )
                .with_resource(
                    resource_type.clone(),
                    audit_target,
                    Some(OwnershipScope::project(owner_scope, None, None)),
                )
                .with_decision(decision.clone())
                .with_reason("unauthorized"),
            )
            .await?;
            return Err(match decision.reason() {
                DecisionReason::ScopeMismatch | DecisionReason::MissingOwnership => {
                    NetworkError::NotFound
                }
                _ => NetworkError::Unauthorized,
            });
        }
        Ok((namespace, action, resource_type))
    }

    pub(super) async fn audit_canonical_result(
        &self,
        auth: &AuthContext,
        namespace: ServiceNamespace,
        action: ActionId,
        resource_type: ResourceType,
        resource_id: Option<Uuid>,
        result: Result<(), &NetworkError>,
    ) -> Result<(), NetworkError> {
        let outcome = if result.is_ok() {
            AuditOutcome::Succeeded
        } else {
            AuditOutcome::Failed
        };
        let mut event = AuditEvent::from_auth(auth, namespace, action, outcome).with_resource(
            resource_type,
            resource_id.and_then(|id| ResourceId::new(id.to_string()).ok()),
            Some(auth.effective_scope().clone()),
        );
        if let Err(error) = result {
            event = event.with_reason(error.to_string());
        }
        self.record_required_audit(&event).await?;
        Ok(())
    }

    async fn recover_realm_deletion_operations(&self) -> Result<(), NetworkError> {
        let operations = self
            .inner
            .repository
            .list_non_terminal_lifecycle_operations()
            .await
            .map_err(map_store_error)?;
        for operation in operations {
            if operation.kind != "lifecycle:realm-delete" {
                continue;
            }
            let canonical = self
                .inner
                .repository
                .get_canonical_operation(operation.id)
                .await
                .map_err(map_store_error)?;
            let realm_id = canonical
                .resource_id
                .as_deref()
                .ok_or(NetworkError::InvalidRequest)?
                .parse::<Uuid>()
                .map_err(|_| NetworkError::InvalidRequest)?;
            let realm = self
                .inner
                .repository
                .get_canonical_realm(&canonical.owner_scope, &realm_id)
                .await
                .map_err(map_store_error)?;
            let Some(realm) = realm else {
                let update = o3k_store::CanonicalOperationLifecycleUpdate::new(
                    o3k_kernel::OperationState::Succeeded,
                    canonical.attempt.saturating_add(1),
                    canonical.started_at.clone(),
                    Some(
                        canonical
                            .started_at
                            .clone()
                            .unwrap_or_else(|| canonical.created_at.clone()),
                    ),
                    None,
                )
                .map_err(map_store_error)?;
                self.inner
                    .repository
                    .update_canonical_operation_lifecycle(operation.id, &update)
                    .await
                    .map_err(map_store_error)?;
                continue;
            };
            if realm.state == "active" {
                let deleting = match self
                    .inner
                    .repository
                    .begin_canonical_realm_deletion(
                        &canonical.owner_scope,
                        &realm_id,
                        realm.generation,
                    )
                    .await
                {
                    Ok(value) => value,
                    Err(o3k_store::StoreError::NetworkInUse) => {
                        let update = o3k_store::CanonicalOperationLifecycleUpdate::new(
                            o3k_kernel::OperationState::Retryable,
                            canonical.attempt.saturating_add(1),
                            canonical.started_at.clone(),
                            None,
                            Some("realm still has canonical dependents".to_owned()),
                        )
                        .map_err(map_store_error)?;
                        self.inner
                            .repository
                            .update_canonical_operation_lifecycle(operation.id, &update)
                            .await
                            .map_err(map_store_error)?;
                        continue;
                    }
                    Err(error) => return Err(map_store_error(error)),
                };
                self.inner
                    .repository
                    .update_resource(
                        realm_id,
                        i64::try_from(realm.generation)
                            .map_err(|_| NetworkError::InvalidRequest)?,
                        "deleting",
                        "deleting",
                        i64::try_from(deleting.generation)
                            .map_err(|_| NetworkError::InvalidRequest)?,
                        None,
                    )
                    .await
                    .map_err(map_store_error)?;
                let update = o3k_store::CanonicalOperationLifecycleUpdate::new(
                    o3k_kernel::OperationState::Running,
                    canonical.attempt.saturating_add(1),
                    Some(
                        canonical
                            .started_at
                            .clone()
                            .unwrap_or_else(|| canonical.created_at.clone()),
                    ),
                    None,
                    None,
                )
                .map_err(map_store_error)?;
                self.inner
                    .repository
                    .update_canonical_operation_lifecycle(operation.id, &update)
                    .await
                    .map_err(map_store_error)?;
                debug_assert_eq!(deleting.state, "deleting");
            }
        }
        Ok(())
    }

    /// Creates only the canonical Network row.  Address realms, pools and
    /// endpoints are independent child resources and are intentionally not
    /// synthesized here.
    pub async fn create_canonical_network_for_project(
        &self,
        project_id: &str,
        name: String,
    ) -> Result<o3k_store::CanonicalNetworkRecord, NetworkError> {
        if project_id.trim().is_empty() || name.trim().is_empty() {
            return Err(NetworkError::InvalidRequest);
        }
        let _guard = self.lock.lock().await;
        if self
            .inner
            .repository
            .list_canonical_networks(project_id)
            .await
            .map_err(map_store_error)?
            .iter()
            .any(|network| network.name == name)
        {
            return Err(NetworkError::Conflict);
        }
        let network = o3k_store::CanonicalNetworkRecord {
            id: Uuid::now_v7(),
            project_id: project_id.to_owned(),
            name,
            admin_state_up: true,
            generation: 1,
            state: "active".to_owned(),
        };
        self.inner
            .repository
            .insert_canonical_network(&network)
            .await
            .map_err(map_store_error)?;
        Ok(network)
    }

    /// Authenticated entry point for canonical Network creation. The
    /// project-scoped primitive remains intentionally separate for internal
    /// reconciliation and migration callers.
    pub async fn create_canonical_network(
        &self,
        auth: &AuthContext,
        name: String,
    ) -> Result<o3k_store::CanonicalNetworkRecord, NetworkError> {
        let (namespace, action, resource_type) = self
            .authorize_canonical_action(auth, "CreateNetwork", "network", None, None)
            .await?;
        let result = self
            .create_canonical_network_for_project(auth.effective_scope().id().as_str(), name)
            .await;
        let audit_result = result.as_ref().map(|_| ());
        self.audit_canonical_result(auth, namespace, action, resource_type, None, audit_result)
            .await?;
        result
    }

    pub async fn get_canonical_network_for_project(
        &self,
        project_id: &str,
        id: Uuid,
    ) -> Result<o3k_store::CanonicalNetworkRecord, NetworkError> {
        self.inner
            .repository
            .get_canonical_network(project_id, &id)
            .await
            .map_err(map_store_error)?
            .ok_or(NetworkError::NotFound)
    }

    pub async fn get_canonical_network(
        &self,
        auth: &AuthContext,
        id: Uuid,
    ) -> Result<o3k_store::CanonicalNetworkRecord, NetworkError> {
        let (namespace, action, resource_type) = self
            .authorize_canonical_action(auth, "ReadNetwork", "network", Some(id), None)
            .await?;
        let result = self
            .get_canonical_network_for_project(auth.effective_scope().id().as_str(), id)
            .await;
        self.audit_canonical_result(
            auth,
            namespace,
            action,
            resource_type,
            Some(id),
            result.as_ref().map(|_| ()),
        )
        .await?;
        result
    }

    pub async fn list_canonical_networks_for_project(
        &self,
        project_id: &str,
    ) -> Result<Vec<o3k_store::CanonicalNetworkRecord>, NetworkError> {
        self.inner
            .repository
            .list_canonical_networks(project_id)
            .await
            .map_err(map_store_error)
    }

    pub async fn list_canonical_networks(
        &self,
        auth: &AuthContext,
    ) -> Result<Vec<o3k_store::CanonicalNetworkRecord>, NetworkError> {
        let (namespace, action, resource_type) = self
            .authorize_canonical_action(auth, "ListNetworks", "network", None, None)
            .await?;
        let result = self
            .list_canonical_networks_for_project(auth.effective_scope().id().as_str())
            .await;
        self.audit_canonical_result(
            auth,
            namespace,
            action,
            resource_type,
            None,
            result.as_ref().map(|_| ()),
        )
        .await?;
        result
    }

    pub async fn delete_canonical_network_for_project(
        &self,
        project_id: &str,
        id: Uuid,
    ) -> Result<(), NetworkError> {
        let _guard = self.lock.lock().await;
        self.inner
            .repository
            .delete_canonical_network(project_id, &id)
            .await
            .map_err(map_store_error)?;
        match self.inner.repository.delete_network(project_id, &id).await {
            Ok(())
            | Err(o3k_store::StoreError::ResourceNotFound)
            | Err(o3k_store::StoreError::NetworkNotFound) => Ok(()),
            Err(error) => Err(map_store_error(error)),
        }?;
        self.inner
            .repository
            .release_reservation_for_operation(&format!("o3k:network:create:{}:{}", project_id, id))
            .await
            .map_err(map_store_error)?;
        Ok(())
    }

    pub async fn delete_canonical_network(
        &self,
        auth: &AuthContext,
        id: Uuid,
    ) -> Result<(), NetworkError> {
        let (namespace, action, resource_type) = self
            .authorize_canonical_action(auth, "DeleteNetwork", "network", Some(id), None)
            .await?;
        let result = self
            .delete_canonical_network_for_project(auth.effective_scope().id().as_str(), id)
            .await;
        self.audit_canonical_result(
            auth,
            namespace,
            action,
            resource_type,
            Some(id),
            result.as_ref().map(|_| ()),
        )
        .await?;
        result
    }

    pub async fn create_canonical_realm_for_project(
        &self,
        project_id: &str,
        network_id: Uuid,
        prefix: String,
        overlapping_prefixes: bool,
    ) -> Result<o3k_store::CanonicalAddressRealmRecord, NetworkError> {
        let prefix = Ipv4Net::parse(&prefix)?.canonical();
        let _guard = self.lock.lock().await;
        let network = self
            .inner
            .repository
            .get_canonical_network(project_id, &network_id)
            .await
            .map_err(map_store_error)?
            .ok_or(NetworkError::NotFound)?;
        if network.state != "active" {
            return Err(NetworkError::Conflict);
        }
        let realm = o3k_store::CanonicalAddressRealmRecord {
            id: Uuid::now_v7(),
            network_id,
            project_id: project_id.to_owned(),
            prefix,
            overlapping_prefixes,
            generation: 1,
            state: "active".to_owned(),
        };
        self.inner
            .repository
            .insert_canonical_realm(&realm)
            .await
            .map_err(map_store_error)?;
        if let Err(error) = self
            .inner
            .repository
            .insert_resource(&o3k_store::ResourceRecord {
                id: realm.id,
                kind: "network:address_realm".to_owned(),
                project_id: realm.project_id.clone(),
                generation: 1,
                observed_generation: 1,
                desired_state: realm.state.clone(),
                observed_state: realm.state.clone(),
                provider_id: None,
            })
            .await
        {
            let _ = self
                .inner
                .repository
                .delete_canonical_realm(project_id, &realm.id)
                .await;
            return Err(map_store_error(error));
        }
        Ok(realm)
    }

    pub async fn create_canonical_realm(
        &self,
        auth: &AuthContext,
        network_id: Uuid,
        prefix: String,
        overlapping_prefixes: bool,
    ) -> Result<o3k_store::CanonicalAddressRealmRecord, NetworkError> {
        let (namespace, action, resource_type) = self
            .authorize_canonical_action(
                auth,
                "CreateAddressRealm",
                "address_realm",
                None,
                Some(("network", network_id)),
            )
            .await?;
        let result = self
            .create_canonical_realm_for_project(
                auth.effective_scope().id().as_str(),
                network_id,
                prefix,
                overlapping_prefixes,
            )
            .await;
        let audit_result = result.as_ref().map(|_| ());
        self.audit_canonical_result(auth, namespace, action, resource_type, None, audit_result)
            .await?;
        result
    }

    pub async fn list_canonical_realms_for_project(
        &self,
        project_id: &str,
        network_id: Uuid,
    ) -> Result<Vec<o3k_store::CanonicalAddressRealmRecord>, NetworkError> {
        if self
            .get_canonical_network_for_project(project_id, network_id)
            .await
            .is_err()
        {
            return Err(NetworkError::NotFound);
        }
        self.inner
            .repository
            .list_canonical_realms(project_id, &network_id)
            .await
            .map_err(map_store_error)
    }

    pub async fn list_canonical_realms(
        &self,
        auth: &AuthContext,
        network_id: Uuid,
    ) -> Result<Vec<o3k_store::CanonicalAddressRealmRecord>, NetworkError> {
        let (namespace, action, resource_type) = self
            .authorize_canonical_action(
                auth,
                "ListAddressRealms",
                "address_realm",
                None,
                Some(("network", network_id)),
            )
            .await?;
        let result = self
            .list_canonical_realms_for_project(auth.effective_scope().id().as_str(), network_id)
            .await;
        let audit_result = result.as_ref().map(|_| ());
        self.audit_canonical_result(auth, namespace, action, resource_type, None, audit_result)
            .await?;
        result
    }

    pub async fn get_canonical_realm(
        &self,
        auth: &AuthContext,
        realm_id: Uuid,
    ) -> Result<o3k_store::CanonicalAddressRealmRecord, NetworkError> {
        let (namespace, action, resource_type) = self
            .authorize_canonical_action(
                auth,
                "ReadAddressRealm",
                "address_realm",
                Some(realm_id),
                None,
            )
            .await?;
        let result = self
            .inner
            .repository
            .get_canonical_realm(auth.effective_scope().id().as_str(), &realm_id)
            .await
            .map_err(map_store_error)?
            .ok_or(NetworkError::NotFound);
        self.audit_canonical_result(
            auth,
            namespace,
            action,
            resource_type,
            Some(realm_id),
            result.as_ref().map(|_| ()),
        )
        .await?;
        result
    }

    /// Owner-scoped lookup used by compatibility projections after the
    /// request has already been authorized at the API boundary.
    pub async fn get_canonical_realm_for_project(
        &self,
        project_id: &str,
        realm_id: Uuid,
    ) -> Result<o3k_store::CanonicalAddressRealmRecord, NetworkError> {
        self.inner
            .repository
            .get_canonical_realm(project_id, &realm_id)
            .await
            .map_err(map_store_error)?
            .ok_or(NetworkError::NotFound)
    }

    pub async fn delete_canonical_realm_for_project(
        &self,
        project_id: &str,
        realm_id: Uuid,
    ) -> Result<(), NetworkError> {
        let progress = self
            .begin_canonical_realm_deletion_for_project(project_id, realm_id)
            .await?;
        let operation_id = match progress {
            RealmCleanupProgress::Deleting { operation_id, .. }
            | RealmCleanupProgress::AwaitingObservation { operation_id, .. }
            | RealmCleanupProgress::Removed { operation_id } => operation_id,
        };
        let bindings = self
            .inner
            .repository
            .list_canonical_realm_bindings(&realm_id)
            .await
            .map_err(map_store_error)?;
        if bindings.is_empty() {
            match self
                .observe_canonical_realm_cleanup_for_project(project_id, realm_id, Vec::new())
                .await?
            {
                RealmCleanupProgress::Removed { .. } => Ok(()),
                _ => Err(NetworkError::Conflict),
            }
        } else {
            // No provider observation is available at this service boundary;
            // retaining Deleting is the safe result. A provider/reconciler
            // must call the explicit observation method before final removal.
            let _ = operation_id;
            Err(NetworkError::Conflict)
        }
    }

    pub async fn delete_canonical_realm(
        &self,
        auth: &AuthContext,
        realm_id: Uuid,
    ) -> Result<(), NetworkError> {
        let (namespace, action, resource_type) = self
            .authorize_canonical_action(
                auth,
                "DeleteAddressRealm",
                "address_realm",
                Some(realm_id),
                None,
            )
            .await?;
        let result = self
            .delete_canonical_realm_for_project(auth.effective_scope().id().as_str(), realm_id)
            .await;
        self.audit_canonical_result(
            auth,
            namespace,
            action,
            resource_type,
            Some(realm_id),
            result.as_ref().map(|_| ()),
        )
        .await?;
        result
    }

    /// Durably accepts a Realm deletion before any provider mutation. The
    /// operation identity is deterministic, so retries join the same
    /// workflow even after a process restart.
    pub async fn begin_canonical_realm_deletion_for_project(
        &self,
        project_id: &str,
        realm_id: Uuid,
    ) -> Result<RealmCleanupProgress, NetworkError> {
        let _guard = self.lock.lock().await;
        let realm = self
            .inner
            .repository
            .get_canonical_realm(project_id, &realm_id)
            .await
            .map_err(map_store_error)?
            .ok_or(NetworkError::NotFound)?;
        let (operation, canonical, request) = realm_delete_operation(project_id, realm_id)?;
        let accepted = self
            .inner
            .repository
            .create_or_replay_canonical_scoped_operation(&operation, &canonical, &request)
            .await
            .map_err(map_store_error)?;
        let operation_id = match accepted {
            o3k_store::IdempotencyReservation::Conflict => return Err(NetworkError::Conflict),
            o3k_store::IdempotencyReservation::Created(id)
            | o3k_store::IdempotencyReservation::ExistingEquivalent(id) => id,
        };
        if realm.state == "deleting" {
            return Ok(RealmCleanupProgress::AwaitingObservation {
                operation_id,
                generation: realm.generation,
            });
        }
        if realm.state != "active" {
            let _ = self
                .inner
                .repository
                .update_operation(
                    operation_id,
                    o3k_store::OperationState::Failed,
                    None,
                    Some("invalid_state"),
                    Some("Realm is not deletable in its current lifecycle state"),
                )
                .await;
            return Err(NetworkError::Conflict);
        }
        let deleting = match self
            .inner
            .repository
            .begin_canonical_realm_deletion(project_id, &realm_id, realm.generation)
            .await
        {
            Ok(value) => value,
            Err(error) => {
                let state = if matches!(error, o3k_store::StoreError::NetworkInUse) {
                    o3k_store::OperationState::Retryable
                } else {
                    o3k_store::OperationState::Failed
                };
                let _ = self
                    .inner
                    .repository
                    .update_operation(
                        operation_id,
                        state,
                        None,
                        Some("rejected"),
                        Some(&error.to_string()),
                    )
                    .await;
                return Err(map_store_error(error));
            }
        };
        self.inner
            .repository
            .update_resource(
                realm_id,
                i64::try_from(realm.generation).map_err(|_| NetworkError::InvalidRequest)?,
                "deleting",
                "deleting",
                i64::try_from(deleting.generation).map_err(|_| NetworkError::InvalidRequest)?,
                None,
            )
            .await
            .map_err(map_store_error)?;
        let lifecycle = o3k_store::CanonicalOperationLifecycleUpdate::new(
            o3k_kernel::OperationState::Running,
            1,
            Some(canonical.created_at.clone()),
            None,
            None,
        )
        .map_err(map_store_error)?;
        self.inner
            .repository
            .update_canonical_operation_lifecycle(operation_id, &lifecycle)
            .await
            .map_err(map_store_error)?;
        Ok(RealmCleanupProgress::Deleting {
            operation_id,
            generation: deleting.generation,
        })
    }

    /// Applies a provider observation to a durable Realm deletion. Every
    /// current binding must be identified exactly; absent observations remove
    /// only the matching owned binding after generation validation.
    pub async fn observe_canonical_realm_cleanup_for_project(
        &self,
        project_id: &str,
        realm_id: Uuid,
        observations: Vec<RealmCleanupObservation>,
    ) -> Result<RealmCleanupProgress, NetworkError> {
        let _guard = self.lock.lock().await;
        let realm = self
            .inner
            .repository
            .get_canonical_realm(project_id, &realm_id)
            .await
            .map_err(map_store_error)?
            .ok_or(NetworkError::NotFound)?;
        if realm.state != "deleting" {
            return Err(NetworkError::Conflict);
        }
        let (operation, _, _) = realm_delete_operation(project_id, realm_id)?;
        let operation_record = self
            .inner
            .repository
            .get_operation(operation.id)
            .await
            .map_err(map_store_error)?;
        let canonical = self
            .inner
            .repository
            .get_canonical_operation(operation.id)
            .await
            .map_err(map_store_error)?;
        if operation_record.resource_id != realm_id
            || canonical.owner_scope != project_id
            || canonical.resource_id.as_deref() != Some(&realm_id.to_string())
        {
            return Err(NetworkError::InvalidRequest);
        }
        let bindings = self
            .inner
            .repository
            .list_canonical_realm_bindings(&realm_id)
            .await
            .map_err(map_store_error)?;
        if observations.len() != bindings.len() {
            return Err(NetworkError::Conflict);
        }
        let same_binding =
            |left: &o3k_store::CanonicalRealmBindingRecord,
             right: &o3k_store::CanonicalRealmBindingRecord| {
                left == right && left.realm_id == realm_id
            };
        for binding in &bindings {
            let matching: Vec<_> = observations
                .iter()
                .filter(|observation| match observation {
                    RealmCleanupObservation::Absent(value)
                    | RealmCleanupObservation::Present(value) => same_binding(binding, value),
                    RealmCleanupObservation::Unknown { binding: value, .. } => {
                        same_binding(binding, value)
                    }
                })
                .collect();
            if matching.len() != 1 {
                return Err(NetworkError::Conflict);
            }
            match matching[0] {
                RealmCleanupObservation::Unknown { reason, .. } => {
                    let update = o3k_store::CanonicalOperationLifecycleUpdate::new(
                        o3k_kernel::OperationState::UnknownOutcome,
                        canonical.attempt.saturating_add(1),
                        canonical.started_at.clone(),
                        None,
                        Some(reason.clone()),
                    )
                    .map_err(map_store_error)?;
                    self.inner
                        .repository
                        .update_canonical_operation_lifecycle(operation.id, &update)
                        .await
                        .map_err(map_store_error)?;
                    return Ok(RealmCleanupProgress::AwaitingObservation {
                        operation_id: operation.id,
                        generation: realm.generation,
                    });
                }
                RealmCleanupObservation::Present(_) => {
                    let update = o3k_store::CanonicalOperationLifecycleUpdate::new(
                        o3k_kernel::OperationState::Retryable,
                        canonical.attempt.saturating_add(1),
                        canonical.started_at.clone(),
                        None,
                        Some("owned provider Realm state is still present".to_owned()),
                    )
                    .map_err(map_store_error)?;
                    self.inner
                        .repository
                        .update_canonical_operation_lifecycle(operation.id, &update)
                        .await
                        .map_err(map_store_error)?;
                    return Ok(RealmCleanupProgress::AwaitingObservation {
                        operation_id: operation.id,
                        generation: realm.generation,
                    });
                }
                RealmCleanupObservation::Absent(_) => {}
            }
        }
        for binding in bindings {
            self.inner
                .repository
                .delete_canonical_realm_binding(&binding, realm.generation)
                .await
                .map_err(map_store_error)?;
        }
        self.inner
            .repository
            .finalize_canonical_realm_deletion(project_id, &realm_id, realm.generation)
            .await
            .map_err(map_store_error)?;
        let _ = self
            .inner
            .repository
            .update_resource(
                realm_id,
                i64::try_from(realm.generation).map_err(|_| NetworkError::InvalidRequest)?,
                "deleted",
                "deleted",
                i64::try_from(realm.generation).map_err(|_| NetworkError::InvalidRequest)?,
                None,
            )
            .await;
        let update = o3k_store::CanonicalOperationLifecycleUpdate::new(
            o3k_kernel::OperationState::Succeeded,
            canonical.attempt.saturating_add(1),
            canonical.started_at.clone(),
            Some(
                canonical
                    .started_at
                    .clone()
                    .unwrap_or_else(|| canonical.created_at.clone()),
            ),
            None,
        )
        .map_err(map_store_error)?;
        self.inner
            .repository
            .update_canonical_operation_lifecycle(operation.id, &update)
            .await
            .map_err(map_store_error)?;
        Ok(RealmCleanupProgress::Removed {
            operation_id: operation.id,
        })
    }

    pub async fn create_canonical_pool_for_project(
        &self,
        project_id: &str,
        realm_id: Uuid,
        prefix: String,
        gateway: Option<Ipv4Addr>,
        first_usable: Ipv4Addr,
        last_usable: Ipv4Addr,
    ) -> Result<o3k_store::CanonicalAddressPoolRecord, NetworkError> {
        let pool_prefix_net = Ipv4Net::parse(&prefix)?;
        let pool_prefix = pool_prefix_net.canonical();
        if first_usable > last_usable
            || !pool_prefix_net.contains(first_usable)
            || !pool_prefix_net.contains(last_usable)
        {
            return Err(NetworkError::InvalidRequest);
        }
        let _guard = self.lock.lock().await;
        let realm = self
            .inner
            .repository
            .get_canonical_realm(project_id, &realm_id)
            .await
            .map_err(map_store_error)?
            .ok_or(NetworkError::NotFound)?;
        if realm.state != "active" {
            return Err(NetworkError::Conflict);
        }
        let realm_prefix = Ipv4Net::parse(&realm.prefix)?;
        if !realm_prefix.contains(pool_prefix_net.network)
            || pool_prefix_net.prefix < realm_prefix.prefix
        {
            return Err(NetworkError::InvalidRequest);
        }
        if gateway.is_some_and(|value| !pool_prefix_net.contains(value)) {
            return Err(NetworkError::InvalidRequest);
        }
        let pool = o3k_store::CanonicalAddressPoolRecord {
            id: Uuid::now_v7(),
            realm_id,
            project_id: project_id.to_owned(),
            prefix: pool_prefix,
            gateway,
            first_usable,
            last_usable,
            generation: 1,
            state: "active".to_owned(),
        };
        self.inner
            .repository
            .insert_canonical_pool(&pool)
            .await
            .map_err(map_store_error)?;
        Ok(pool)
    }

    pub async fn create_canonical_pool(
        &self,
        auth: &AuthContext,
        realm_id: Uuid,
        prefix: String,
        gateway: Option<Ipv4Addr>,
        first_usable: Ipv4Addr,
        last_usable: Ipv4Addr,
    ) -> Result<o3k_store::CanonicalAddressPoolRecord, NetworkError> {
        let (namespace, action, resource_type) = self
            .authorize_canonical_action(
                auth,
                "CreateAddressPool",
                "address_pool",
                None,
                Some(("address_realm", realm_id)),
            )
            .await?;
        let result = self
            .create_canonical_pool_for_project(
                auth.effective_scope().id().as_str(),
                realm_id,
                prefix,
                gateway,
                first_usable,
                last_usable,
            )
            .await;
        self.audit_canonical_result(
            auth,
            namespace,
            action,
            resource_type,
            None,
            result.as_ref().map(|_| ()),
        )
        .await?;
        result
    }

    pub async fn list_canonical_pools(
        &self,
        auth: &AuthContext,
        realm_id: Uuid,
    ) -> Result<Vec<o3k_store::CanonicalAddressPoolRecord>, NetworkError> {
        let (namespace, action, resource_type) = self
            .authorize_canonical_action(
                auth,
                "ListAddressPools",
                "address_pool",
                None,
                Some(("address_realm", realm_id)),
            )
            .await?;
        let result = self
            .inner
            .repository
            .list_canonical_pools(auth.effective_scope().id().as_str(), &realm_id)
            .await
            .map_err(map_store_error);
        self.audit_canonical_result(
            auth,
            namespace,
            action,
            resource_type,
            None,
            result.as_ref().map(|_| ()),
        )
        .await?;
        result
    }

    pub async fn delete_canonical_pool(
        &self,
        auth: &AuthContext,
        pool_id: Uuid,
    ) -> Result<(), NetworkError> {
        let (namespace, action, resource_type) = self
            .authorize_canonical_action(
                auth,
                "DeleteAddressPool",
                "address_pool",
                Some(pool_id),
                None,
            )
            .await?;
        let result = self
            .inner
            .repository
            .delete_canonical_pool(auth.effective_scope().id().as_str(), &pool_id)
            .await
            .map_err(map_store_error);
        self.audit_canonical_result(
            auth,
            namespace,
            action,
            resource_type,
            Some(pool_id),
            result.as_ref().map(|_| ()),
        )
        .await?;
        result
    }

    pub async fn create_canonical_endpoint_for_project(
        &self,
        project_id: &str,
        realm_id: Uuid,
        fixed_ip: Ipv4Addr,
        mac: String,
    ) -> Result<o3k_store::CanonicalEndpointRecord, NetworkError> {
        if mac.trim().is_empty() {
            return Err(NetworkError::InvalidRequest);
        }
        let _guard = self.lock.lock().await;
        let realm = self
            .inner
            .repository
            .get_canonical_realm(project_id, &realm_id)
            .await
            .map_err(map_store_error)?
            .ok_or(NetworkError::NotFound)?;
        if !Ipv4Net::parse(&realm.prefix)?.contains(fixed_ip) || realm.state != "active" {
            return Err(NetworkError::InvalidRequest);
        }
        let endpoint = o3k_store::CanonicalEndpointRecord {
            id: Uuid::now_v7(),
            realm_id,
            project_id: project_id.to_owned(),
            fixed_ip,
            mac,
            generation: 1,
            state: "active".to_owned(),
        };
        self.inner
            .repository
            .insert_canonical_endpoint(&endpoint)
            .await
            .map_err(map_store_error)?;
        Ok(endpoint)
    }

    pub async fn create_canonical_endpoint(
        &self,
        auth: &AuthContext,
        realm_id: Uuid,
        fixed_ip: Ipv4Addr,
        mac: String,
    ) -> Result<o3k_store::CanonicalEndpointRecord, NetworkError> {
        let (namespace, action, resource_type) = self
            .authorize_canonical_action(
                auth,
                "CreateEndpoint",
                "endpoint",
                None,
                Some(("address_realm", realm_id)),
            )
            .await?;
        let result = self
            .create_canonical_endpoint_for_project(
                auth.effective_scope().id().as_str(),
                realm_id,
                fixed_ip,
                mac,
            )
            .await;
        self.audit_canonical_result(
            auth,
            namespace,
            action,
            resource_type,
            None,
            result.as_ref().map(|_| ()),
        )
        .await?;
        result
    }

    pub async fn list_canonical_endpoints(
        &self,
        auth: &AuthContext,
        realm_id: Uuid,
    ) -> Result<Vec<o3k_store::CanonicalEndpointRecord>, NetworkError> {
        let (namespace, action, resource_type) = self
            .authorize_canonical_action(
                auth,
                "ListEndpoints",
                "endpoint",
                None,
                Some(("address_realm", realm_id)),
            )
            .await?;
        let result = self
            .inner
            .repository
            .list_canonical_endpoints(auth.effective_scope().id().as_str(), &realm_id)
            .await
            .map_err(map_store_error);
        self.audit_canonical_result(
            auth,
            namespace,
            action,
            resource_type,
            None,
            result.as_ref().map(|_| ()),
        )
        .await?;
        result
    }

    /// Internal composition read used to derive execution plans from
    /// canonical state after the caller has already established project and
    /// operation authority. Public protocol handlers use the authenticated
    /// method above.
    pub async fn list_canonical_endpoints_for_project(
        &self,
        project_id: &str,
        realm_id: Uuid,
    ) -> Result<Vec<o3k_store::CanonicalEndpointRecord>, NetworkError> {
        self.inner
            .repository
            .list_canonical_endpoints(project_id, &realm_id)
            .await
            .map_err(map_store_error)
    }

    pub async fn get_canonical_endpoint(
        &self,
        auth: &AuthContext,
        endpoint_id: Uuid,
    ) -> Result<o3k_store::CanonicalEndpointRecord, NetworkError> {
        let (namespace, action, resource_type) = self
            .authorize_canonical_action(auth, "ReadEndpoint", "endpoint", Some(endpoint_id), None)
            .await?;
        let result = self
            .inner
            .repository
            .get_canonical_endpoint(auth.effective_scope().id().as_str(), &endpoint_id)
            .await
            .map_err(map_store_error)?
            .ok_or(NetworkError::NotFound);
        self.audit_canonical_result(
            auth,
            namespace,
            action,
            resource_type,
            Some(endpoint_id),
            result.as_ref().map(|_| ()),
        )
        .await?;
        result
    }

    pub async fn delete_canonical_endpoint(
        &self,
        auth: &AuthContext,
        endpoint_id: Uuid,
    ) -> Result<(), NetworkError> {
        let (namespace, action, resource_type) = self
            .authorize_canonical_action(auth, "DeleteEndpoint", "endpoint", Some(endpoint_id), None)
            .await?;
        let result = self
            .inner
            .repository
            .delete_canonical_endpoint(auth.effective_scope().id().as_str(), &endpoint_id)
            .await
            .map_err(map_store_error);
        self.audit_canonical_result(
            auth,
            namespace,
            action,
            resource_type,
            Some(endpoint_id),
            result.as_ref().map(|_| ()),
        )
        .await?;
        result
    }

    /// Reconstructs canonical execution inputs from durable rows. Empty child
    /// collections are valid and never become NotFound or placeholder realms.
    pub async fn reconstruct_canonical_network(
        &self,
        project_id: &str,
        network_id: Uuid,
    ) -> Result<CanonicalNetworkSnapshot, NetworkError> {
        let network = self
            .get_canonical_network_for_project(project_id, network_id)
            .await?;
        let realms = self
            .inner
            .repository
            .list_canonical_realms(project_id, &network_id)
            .await
            .map_err(map_store_error)?;
        let mut pools = BTreeMap::new();
        let mut endpoints = BTreeMap::new();
        for realm in &realms {
            if realm.network_id != network.id || realm.project_id != network.project_id {
                return Err(NetworkError::InvalidRequest);
            }
            pools.insert(
                realm.id,
                self.inner
                    .repository
                    .list_canonical_pools(project_id, &realm.id)
                    .await
                    .map_err(map_store_error)?,
            );
            endpoints.insert(
                realm.id,
                self.inner
                    .repository
                    .list_canonical_endpoints(project_id, &realm.id)
                    .await
                    .map_err(map_store_error)?,
            );
        }
        let realm_ids: BTreeSet<Uuid> = realms.iter().map(|realm| realm.id).collect();
        let mut l3_gateways = Vec::new();
        for gateway in self
            .inner
            .repository
            .list_canonical_l3_gateways(project_id)
            .await
            .map_err(map_store_error)?
        {
            let attachments = self
                .inner
                .repository
                .list_canonical_l3_gateway_attachments(project_id, &gateway.id)
                .await
                .map_err(map_store_error)?;
            let relevant: Vec<_> = attachments
                .into_iter()
                .filter(|attachment| realm_ids.contains(&attachment.realm_id))
                .collect();
            if !relevant.is_empty() {
                l3_gateways.push((gateway, relevant));
            }
        }
        Ok(CanonicalNetworkSnapshot {
            network,
            realms,
            pools,
            endpoints,
            l3_gateways,
        })
    }
}
