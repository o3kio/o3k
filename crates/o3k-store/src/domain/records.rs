use std::net::Ipv4Addr;

use chrono::DateTime;
use serde::{Deserialize, Serialize};
use uuid::Uuid;

/// Secret-safe durable audit projection.  This deliberately contains only
/// canonical identifiers and bounded reason categories; request/provider
/// payloads are not representable by this type.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct AuditEventRecord {
    pub event_id: String,
    pub timestamp: String,
    pub request_id: String,
    pub audit_id: String,
    pub principal_id: String,
    pub principal_kind: String,
    pub effective_scope: String,
    pub service: String,
    pub action: String,
    pub resource_type: Option<String>,
    pub resource_id: Option<String>,
    pub owner_scope: Option<String>,
    pub operation_id: Option<String>,
    pub outcome: String,
    pub reason_category: Option<String>,
}

impl AuditEventRecord {
    /// Project a kernel event into the bounded, secret-safe durable shape.
    /// Raw request/provider payloads are intentionally not representable here.
    pub fn from_kernel_event(event: &o3k_kernel::AuditEvent) -> Self {
        Self {
            event_id: event.event_id.as_str().to_owned(),
            timestamp: event.timestamp.clone(),
            request_id: event.request_id.clone(),
            audit_id: event.audit_id.clone(),
            principal_id: event.principal_id.to_string(),
            principal_kind: match event.principal_kind {
                o3k_kernel::PrincipalKind::User => "user".to_owned(),
                o3k_kernel::PrincipalKind::Service => "service".to_owned(),
            },
            // Durable scope predicates use the canonical scope identifier;
            // the scope kind is supplied by the surrounding AuthContext and
            // is not encoded into this project-scoped storage key.
            effective_scope: event.effective_scope.id().as_str().to_owned(),
            service: event.service_namespace.to_string(),
            action: event.action.to_string(),
            resource_type: event.resource_type.as_ref().map(|v| v.to_string()),
            resource_id: event.resource_id.as_ref().map(|v| v.to_string()),
            owner_scope: event
                .owner_scope
                .as_ref()
                .map(|v| v.id().as_str().to_owned()),
            operation_id: event.operation_id.map(|v| v.to_string()),
            outcome: event.outcome.to_string(),
            reason_category: event.reason_category.as_deref().map(normalize_audit_reason),
        }
    }
}

fn normalize_audit_reason(reason: &str) -> String {
    const MAX_REASON_BYTES: usize = 128;
    let mut out = reason
        .chars()
        .filter(|c| !c.is_control())
        .take(MAX_REASON_BYTES)
        .collect::<String>();
    if out.is_empty() {
        out.push_str("unspecified");
    }
    out
}

use super::error::StoreError;
use super::state::{AgentCommandState, ImageOverlayState, OperationState};

// ─── Model types ─────────────────────────────────────────────

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct DatabaseHealth {
    pub status: String,
    pub journal_mode: String,
    pub foreign_keys: bool,
    pub integrity_check: String,
    pub page_count: i64,
    pub page_size: i64,
    pub wal_checkpoint_status: Option<String>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct KeypairRecord {
    pub id: Uuid,
    pub user_id: String,
    pub project_id: String,
    pub name: String,
    pub key_type: String,
    pub public_key: String,
    pub fingerprint: String,
    pub created_at: String,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ImageMetadataRecord {
    pub id: Uuid,
    pub name: String,
    pub project_id: String,
    pub status: String,
    pub visibility: String,
    pub container_format: String,
    pub disk_format: String,
    pub size: Option<i64>,
    pub checksum: Option<String>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct NetworkRecord {
    pub id: Uuid,
    pub name: String,
    pub project_id: String,
    pub status: String,
}

/// Canonical Network identity introduced by ADR-0176. `NetworkRecord` remains
/// the legacy OpenStack projection until the compatibility adapter is migrated;
/// these records are the authoritative durable Network rows going forward.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CanonicalNetworkRecord {
    pub id: Uuid,
    pub project_id: String,
    pub name: String,
    pub admin_state_up: bool,
    pub generation: u64,
    pub state: String,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CanonicalAddressRealmRecord {
    pub id: Uuid,
    pub network_id: Uuid,
    pub project_id: String,
    pub prefix: String,
    pub overlapping_prefixes: bool,
    pub generation: u64,
    pub state: String,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CanonicalAddressPoolRecord {
    pub id: Uuid,
    pub realm_id: Uuid,
    pub project_id: String,
    pub prefix: String,
    pub gateway: Option<Ipv4Addr>,
    pub first_usable: Ipv4Addr,
    pub last_usable: Ipv4Addr,
    pub generation: u64,
    pub state: String,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CanonicalL3GatewayRecord {
    pub id: Uuid,
    pub project_id: String,
    pub name: String,
    pub external_realm_id: Option<Uuid>,
    pub enable_snat: bool,
    pub generation: u64,
    pub state: String,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CanonicalL3GatewayAttachmentRecord {
    pub id: Uuid,
    pub gateway_id: Uuid,
    pub realm_id: Uuid,
    pub project_id: String,
    pub generation: u64,
    pub state: String,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CanonicalEndpointRecord {
    pub id: Uuid,
    pub realm_id: Uuid,
    pub project_id: String,
    pub fixed_ip: Ipv4Addr,
    pub mac: String,
    pub generation: u64,
    pub state: String,
}

/// Derived execution truth for one Endpoint's canonical policy snapshot.
/// This record is never a source for NetworkPolicy, Rule, or Attachment
/// desired state; it exists so independent Endpoint realizations remain
/// truthful across retries and process restarts.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CanonicalPolicyRealizationRecord {
    pub endpoint_id: Uuid,
    pub project_id: String,
    /// Unique durable fence for one reconciliation attempt. This is derived
    /// execution state, never canonical policy identity.
    pub attempt_id: Uuid,
    pub desired_fingerprint: String,
    pub desired_generation: u64,
    pub observed_fingerprint: Option<String>,
    pub observed_generation: Option<u64>,
    pub state: String,
    pub provider_resource_id: Option<String>,
    pub last_outcome: Option<String>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CanonicalRealmBindingRecord {
    pub fabric_domain_id: String,
    pub realm_id: Uuid,
    pub provider_kind: String,
    pub provider_segment_id: u64,
    pub binding_generation: u64,
    pub state: String,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SubnetRecord {
    pub id: Uuid,
    pub network_id: Uuid,
    pub name: String,
    pub project_id: String,
    pub cidr: String,
    pub gateway_ip: Ipv4Addr,
    pub allocation_start: Ipv4Addr,
    pub allocation_end: Ipv4Addr,
    pub ip_version: u8,
    pub enable_dhcp: bool,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PortRecord {
    pub id: Uuid,
    pub network_id: Uuid,
    pub subnet_id: Option<Uuid>,
    pub project_id: String,
    pub name: String,
    pub mac_address: String,
    pub fixed_ip: Ipv4Addr,
    pub status: String,
    pub binding_host: Option<String>,
    pub binding_state: Option<String>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SecurityGroupRecord {
    pub id: Uuid,
    pub project_id: String,
    pub name: String,
    pub description: String,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SecurityGroupRuleRecord {
    pub id: Uuid,
    pub security_group_id: Uuid,
    pub project_id: String,
    pub direction: String,
    pub protocol: String,
    pub port_min: Option<u16>,
    pub port_max: Option<u16>,
    pub remote_ip_prefix: Option<String>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SecurityGroupBindingRecord {
    pub project_id: String,
    pub endpoint_id: Uuid,
    pub security_group_id: Uuid,
}

/// Transitional persisted execution/projection data for the legacy P9 path.
/// Canonical Network, Realm, Pool, Endpoint, and Policy rows are authoritative;
/// this payload is migration input or a derived cache and must never recreate
/// or override canonical state.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct NetworkIntentRecord {
    pub id: Uuid,
    pub project_id: String,
    pub generation: u64,
    pub payload: String,
    pub plan_fingerprint_sha256: Option<String>,
    pub status: String,
}

/// Canonical policy desired state.  NetworkIntent payloads are migration input
/// only; this row is the authority used by runtime reconstruction.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CanonicalNetworkPolicyRecord {
    pub id: Uuid,
    pub project_id: String,
    pub endpoint_id: Uuid,
    pub direction: String,
    pub protocol: String,
    pub port_min: Option<u16>,
    pub port_max: Option<u16>,
    pub source: Option<String>,
    pub destination: Option<String>,
    pub action: String,
    pub generation: u64,
    pub state: String,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CanonicalReusableNetworkPolicyRecord {
    pub id: Uuid,
    pub project_id: String,
    pub name: String,
    pub description: String,
    pub stateful_mode: String,
    pub unmatched_action: String,
    pub generation: u64,
    pub state: String,
    pub created_at: String,
    pub updated_at: String,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CanonicalNetworkPolicyRuleRecord {
    pub id: Uuid,
    pub policy_id: Uuid,
    pub project_id: String,
    pub direction: String,
    pub address_family: String,
    pub protocol: String,
    pub port_min: Option<u16>,
    pub port_max: Option<u16>,
    pub remote_selector: Option<String>,
    pub action: String,
    pub state: String,
    pub generation: u64,
    pub enforcement_key: String,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CanonicalPolicyAttachmentRecord {
    pub id: Uuid,
    pub policy_id: Uuid,
    pub endpoint_id: Uuid,
    pub project_id: String,
    pub state: String,
    pub generation: u64,
}

pub(crate) fn legacy_policy_records(
    payload: &str,
    project_id: &str,
) -> Result<Vec<CanonicalNetworkPolicyRecord>, StoreError> {
    let value: serde_json::Value = serde_json::from_str(payload)
        .map_err(|error| StoreError::Corrupt(format!("invalid network intent JSON: {error}")))?;
    let Some(policies) = value.get("policies").and_then(serde_json::Value::as_array) else {
        return Ok(Vec::new());
    };
    policies
        .iter()
        .map(|policy| {
            let id = policy
                .get("id")
                .and_then(serde_json::Value::as_str)
                .ok_or_else(|| StoreError::Corrupt("legacy policy has no id".into()))?
                .parse()
                .map_err(StoreError::InvalidUuid)?;
            let endpoint_id = policy
                .get("endpoint_id")
                .and_then(serde_json::Value::as_str)
                .ok_or_else(|| StoreError::Corrupt("legacy policy has no endpoint".into()))?
                .parse()
                .map_err(StoreError::InvalidUuid)?;
            let ports = policy.get("ports").and_then(|ports| {
                Some((ports.get("start")?.as_u64()?, ports.get("end")?.as_u64()?))
            });
            let prefix = |value: Option<&serde_json::Value>| -> Result<Option<String>, StoreError> {
                let Some(value) = value.filter(|value| !value.is_null()) else {
                    return Ok(None);
                };
                let network = value
                    .get("network")
                    .and_then(serde_json::Value::as_str)
                    .ok_or_else(|| {
                        StoreError::Corrupt("legacy policy prefix has no network".into())
                    })?;
                let prefix_len = value
                    .get("prefix_len")
                    .and_then(serde_json::Value::as_u64)
                    .ok_or_else(|| {
                        StoreError::Corrupt("legacy policy prefix has no length".into())
                    })?;
                if prefix_len > 32 {
                    return Err(StoreError::Corrupt(
                        "legacy policy prefix length is invalid".into(),
                    ));
                }
                Ok(Some(format!("{network}/{prefix_len}")))
            };
            let (port_min, port_max) = match ports {
                Some((start, end)) if start <= end && end <= u64::from(u16::MAX) => {
                    (Some(start as u16), Some(end as u16))
                }
                Some(_) => {
                    return Err(StoreError::Corrupt(
                        "legacy policy port range is invalid".into(),
                    ));
                }
                None => (None, None),
            };
            Ok(CanonicalNetworkPolicyRecord {
                id,
                project_id: project_id.to_owned(),
                endpoint_id,
                direction: policy
                    .get("direction")
                    .and_then(serde_json::Value::as_str)
                    .ok_or_else(|| StoreError::Corrupt("legacy policy has no direction".into()))?
                    .to_owned(),
                protocol: policy
                    .get("protocol")
                    .and_then(serde_json::Value::as_str)
                    .ok_or_else(|| StoreError::Corrupt("legacy policy has no protocol".into()))?
                    .to_owned(),
                port_min,
                port_max,
                source: prefix(policy.get("source"))?,
                destination: prefix(policy.get("destination"))?,
                action: policy
                    .get("action")
                    .and_then(serde_json::Value::as_str)
                    .ok_or_else(|| StoreError::Corrupt("legacy policy has no action".into()))?
                    .to_owned(),
                generation: 1,
                state: "active".to_owned(),
            })
        })
        .collect()
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct NetworkAddressAllocationRecord {
    pub realm_id: Uuid,
    pub project_id: String,
    pub endpoint_id: Uuid,
    pub operation_id: String,
    pub address: Ipv4Addr,
}

#[derive(Debug, Clone, PartialEq)]
pub struct PlacementInventoryRecord {
    pub resource_class: String,
    pub total: u64,
    pub reserved: u64,
    pub allocation_ratio: f64,
    pub used: u64,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PlacementResourceRecord {
    pub resource_class: String,
    pub amount: u64,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PlacementAllocationRecord {
    pub id: String,
    pub provider_id: String,
    pub consumer_id: String,
    pub resources: Vec<PlacementResourceRecord>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PlacementIntentRecord {
    pub id: String,
    pub provider_id: String,
    pub consumer_id: String,
    pub resources: Vec<PlacementResourceRecord>,
}

#[derive(Debug, Clone, PartialEq)]
pub struct PlacementProviderRecord {
    pub id: String,
    pub node_id: String,
    pub state: String,
    pub generation: u64,
    pub inventories: Vec<PlacementInventoryRecord>,
    pub allocations: Vec<PlacementAllocationRecord>,
    /// Optional generic parent provider; `None` preserves the flat model.
    pub parent_provider_id: Option<String>,
    /// Provider-neutral capability names, deterministically sorted.
    pub traits: Vec<String>,
    /// Canonical LocationRegistry failure-domain IDs bound to this provider.
    pub failure_domains: Vec<String>,
    /// Optional canonical region or availability-domain ID.
    pub location: Option<String>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PlacementReconcileRecord {
    pub orphaned_allocations: Vec<PlacementAllocationRecord>,
    pub abandoned_intents: Vec<PlacementIntentRecord>,
}

/// One repository-computed capacity aggregate row, keyed by resource class.
///
/// This is a durable-authority projection, not a scheduler view. `allocatable`
/// is `Σ floor(total × allocation_ratio)` across providers, `reserved` is
/// `Σ reserved`, and `allocated` is `Σ used`. `available` is derived by the
/// caller as the saturating remainder so overflow can never wrap.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PlacementCapacityClassRecord {
    pub resource_class: String,
    pub allocatable: u64,
    pub reserved: u64,
    pub allocated: u64,
}

/// Bounded capacity aggregate over the durable placement authority.
///
/// `classes` contains at most the caller's limit; the repository fails closed
/// if the stored class set exceeds it rather than silently truncating.
/// Provider counts are by canonical placement provider state.
#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub struct PlacementCapacitySummary {
    pub classes: Vec<PlacementCapacityClassRecord>,
    pub providers_enabled: u64,
    pub providers_draining: u64,
    pub providers_unavailable: u64,
    pub providers_deleted: u64,
    /// Providers that have at least one resource class where
    /// `used > allocatable - reserved` (a drifted/corrupt durable invariant).
    pub providers_over_allocated: u64,
}

/// One provider id + durable state row, used by operator diagnostics to
/// aggregate fleet status without materializing inventories or allocations.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PlacementProviderStateRecord {
    pub id: String,
    pub state: String,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct VolumeAttachmentRecord {
    pub id: Uuid,
    pub server_id: Uuid,
    pub volume_id: Uuid,
    pub device: String,
    pub tag: Option<String>,
    pub delete_on_termination: bool,
    pub created_at: String,
    pub status: String,
    pub operation_id: Option<Uuid>,
    pub idempotency_key: Option<String>,
    pub cinder_attachment_id: Option<String>,
    pub connector_host: Option<String>,
    pub connector_ip: Option<String>,
    pub connector_initiator: Option<String>,
    pub driver_volume_type: Option<String>,
    pub target_iqn: Option<String>,
    pub target_portal: Option<String>,
    pub target_lun: Option<u32>,
    pub connection_info_digest: Option<String>,
    pub error: Option<String>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct KeystoneDomainRecord {
    pub id: String,
    pub name: String,
    pub description: Option<String>,
    pub enabled: bool,
    pub created_at: String,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct KeystoneProjectRecord {
    pub id: String,
    pub domain_id: String,
    pub name: String,
    pub description: Option<String>,
    pub enabled: bool,
    pub created_at: String,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct KeystoneUserRecord {
    pub id: String,
    pub domain_id: String,
    pub name: String,
    pub password_hash: String,
    pub email: Option<String>,
    pub enabled: bool,
    pub created_at: String,
}

/// An explicitly provisioned mapping from a validated external identity to a
/// canonical O3K identity. The external subject is the only federated user
/// identity key; display attributes and raw tokens are intentionally absent.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct FederatedBindingRecord {
    pub id: String,
    pub trusted_issuer_id: String,
    pub issuer: String,
    pub subject: String,
    pub principal_id: String,
    pub principal_type: String,
    pub enabled: bool,
    pub created_at: String,
    pub updated_at: String,
}

/// Explicit durable authorization for a human operator profile. This is
/// intentionally separate from project role assignments.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct OperatorAssignmentRecord {
    pub id: String,
    pub user_id: String,
    pub profile: String,
    pub enabled: bool,
    pub created_at: String,
    pub updated_at: String,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct KeystoneRoleRecord {
    pub id: String,
    pub name: String,
    pub description: Option<String>,
    pub created_at: String,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct KeystoneRoleAssignmentRecord {
    pub id: String,
    pub user_id: String,
    pub project_id: String,
    pub role_id: String,
    pub created_at: String,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct KeystoneServiceRecord {
    pub id: String,
    pub name: String,
    pub r#type: String,
    pub description: Option<String>,
    pub enabled: bool,
    pub created_at: String,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct KeystoneEndpointRecord {
    pub id: String,
    pub service_id: String,
    pub interface: String,
    pub url: String,
    pub region: String,
    pub enabled: bool,
    pub created_at: String,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct KeystoneRegionRecord {
    pub id: String,
    pub description: Option<String>,
    pub parent_region_id: Option<String>,
    pub enabled: bool,
    pub created_at: String,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ResourceRecord {
    pub id: Uuid,
    pub kind: String,
    pub project_id: String,
    pub generation: i64,
    pub observed_generation: i64,
    pub desired_state: String,
    pub observed_state: String,
    pub provider_id: Option<String>,
}

pub struct ObservationUpdate<'a> {
    pub expected_generation: i64,
    pub desired_state: &'a str,
    pub observed_state: &'a str,
    pub observed_generation: i64,
    pub provider_id: Option<&'a str>,
    pub agent_epoch: &'a str,
    pub observation_sequence: u64,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct OperationRecord {
    pub id: Uuid,
    pub resource_id: Uuid,
    pub kind: String,
    pub state: OperationState,
    pub provider_operation_id: Option<String>,
    pub error_category: Option<String>,
    pub error_message: Option<String>,
}

/// Canonical metadata persisted separately so historical OperationJournal
/// rows remain readable without inventing public identity fields.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CanonicalOperationRecord {
    pub id: Uuid,
    pub service: String,
    pub action: String,
    pub actor: String,
    pub owner_scope: String,
    pub resource_type: String,
    pub resource_id: Option<String>,
    pub state: OperationState,
    pub attempt: u32,
    pub created_at: String,
    pub started_at: Option<String>,
    pub finished_at: Option<String>,
    pub error: Option<String>,
    pub request_id: Option<String>,
}

/// Durable public lifecycle projection for a canonical operation.  Updates
/// are committed together with the provider-neutral OperationRecord.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CanonicalOperationLifecycleUpdate {
    pub state: OperationState,
    pub attempt: u32,
    pub started_at: Option<String>,
    pub finished_at: Option<String>,
    pub public_error: Option<String>,
}

impl CanonicalOperationLifecycleUpdate {
    /// Build a lifecycle update from the typed kernel state.  Timestamp and
    /// terminal-state rules are checked before a transaction is opened.
    pub fn new(
        state: o3k_kernel::OperationState,
        attempt: u32,
        started_at: Option<String>,
        finished_at: Option<String>,
        public_error: Option<String>,
    ) -> Result<Self, StoreError> {
        let update = Self {
            state: state.into(),
            attempt,
            started_at,
            finished_at,
            public_error,
        };
        validate_canonical_lifecycle_update(&update)?;
        Ok(update)
    }
}

pub(crate) fn validate_canonical_lifecycle_update(
    update: &CanonicalOperationLifecycleUpdate,
) -> Result<(), StoreError> {
    for timestamp in [&update.started_at, &update.finished_at]
        .into_iter()
        .flatten()
    {
        if DateTime::parse_from_rfc3339(timestamp).is_err() {
            return Err(StoreError::Corrupt(
                "invalid canonical operation timestamp".into(),
            ));
        }
    }
    if matches!(update.state, OperationState::Running) && update.started_at.is_none() {
        return Err(StoreError::Corrupt(
            "running operation requires started_at".into(),
        ));
    }
    if matches!(
        update.state,
        OperationState::Succeeded | OperationState::Failed
    ) && update.finished_at.is_none()
    {
        return Err(StoreError::Corrupt(
            "terminal operation requires finished_at".into(),
        ));
    }
    if matches!(update.state, OperationState::UnknownOutcome) && update.finished_at.is_some() {
        return Err(StoreError::Corrupt(
            "unknown outcome cannot have finished_at".into(),
        ));
    }
    Ok(())
}

impl TryFrom<CanonicalOperationRecord> for o3k_kernel::Operation {
    type Error = StoreError;
    fn try_from(value: CanonicalOperationRecord) -> Result<Self, Self::Error> {
        if value.created_at.trim().is_empty()
            || DateTime::parse_from_rfc3339(&value.created_at).is_err()
            || value
                .started_at
                .as_deref()
                .is_some_and(|v| DateTime::parse_from_rfc3339(v).is_err())
            || value
                .finished_at
                .as_deref()
                .is_some_and(|v| DateTime::parse_from_rfc3339(v).is_err())
        {
            return Err(StoreError::Corrupt(
                "invalid canonical operation timestamp".into(),
            ));
        }
        let action = o3k_kernel::ActionId::parse(&value.action)
            .map_err(|e| StoreError::Corrupt(format!("invalid operation action: {e}")))?;
        let scope = o3k_kernel::OwnershipScope::project(
            o3k_kernel::ScopeId::new(value.owner_scope)
                .map_err(|e| StoreError::Corrupt(format!("invalid operation scope: {e}")))?,
            None,
            None,
        );
        let (namespace, name) = value
            .resource_type
            .split_once(':')
            .ok_or_else(|| StoreError::Corrupt("invalid operation resource type".into()))?;
        let resource_type = o3k_kernel::ResourceType::new(namespace, name)
            .map_err(|e| StoreError::Corrupt(format!("invalid operation resource type: {e}")))?;
        let resource_id = value
            .resource_id
            .map(|id| {
                o3k_kernel::ResourceId::new(id)
                    .map_err(|e| StoreError::Corrupt(format!("invalid operation resource id: {e}")))
            })
            .transpose()?;
        Ok(o3k_kernel::Operation {
            id: value.id,
            service: value.service,
            action,
            actor: value.actor,
            owner_scope: scope,
            resource_type,
            resource_id,
            state: value.state.into(),
            attempt: value.attempt,
            created_at: value.created_at,
            started_at: value.started_at,
            finished_at: value.finished_at,
            error: value.error,
            request_id: value.request_id,
        })
    }
}

impl CanonicalOperationRecord {
    /// Construct canonical durable metadata without losing the scope kind.
    /// P12.4 currently persists project-owned operations only; callers using
    /// a domain or system operation are rejected before any string encoding.
    pub fn from_kernel_operation(operation: &o3k_kernel::Operation) -> Result<Self, StoreError> {
        if operation.owner_scope.kind() != o3k_kernel::ScopeKind::Project {
            return Err(StoreError::Corrupt(
                "canonical operations require a project ownership scope".into(),
            ));
        }
        Ok(Self {
            id: operation.id,
            service: operation.service.clone(),
            action: operation.action.to_string(),
            actor: operation.actor.clone(),
            owner_scope: operation.owner_scope.id().as_str().to_owned(),
            resource_type: operation.resource_type.to_string(),
            resource_id: operation.resource_id.as_ref().map(ToString::to_string),
            state: operation.state.into(),
            attempt: operation.attempt,
            created_at: operation.created_at.clone(),
            started_at: operation.started_at.clone(),
            finished_at: operation.finished_at.clone(),
            error: operation.error.clone(),
            request_id: operation.request_id.clone(),
        })
    }
}

// ─── Idempotency types ───────────────────────────────────────

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct IdempotencyReservationRequest {
    pub owner_scope: String,
    pub action: String,
    pub resource_type: String,
    pub key: String,
    pub fingerprint: String,
    pub operation_id: Uuid,
}

/// A durable idempotency reservation as stored, without the request-side
/// resource-type material. Lets callers distinguish a true replay (identical
/// request semantics) from a key reuse with different semantics before
/// re-validating mutable preconditions such as resource generations.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct StoredIdempotencyReservation {
    pub fingerprint: String,
    pub operation_id: Uuid,
}

impl IdempotencyReservationRequest {
    pub const MAX_KEY_LENGTH: usize = 128;

    pub fn from_semantics(
        owner_scope: impl Into<String>,
        action: impl Into<String>,
        key: impl Into<String>,
        resource_type: &str,
        target: Option<&str>,
        body: &serde_json::Value,
        operation_id: Uuid,
    ) -> Result<Self, StoreError> {
        let owner_scope = owner_scope.into();
        let action = action.into();
        let key = key.into();
        if owner_scope.is_empty()
            || action.is_empty()
            || key.is_empty()
            || key.len() > Self::MAX_KEY_LENGTH
        {
            return Err(StoreError::Corrupt("invalid idempotency identity".into()));
        }
        let action_id = o3k_kernel::ActionId::parse(&action)
            .map_err(|error| StoreError::Corrupt(format!("invalid idempotency action: {error}")))?;
        let (resource_namespace, resource_name) = resource_type
            .split_once(':')
            .ok_or_else(|| StoreError::Corrupt("invalid idempotency resource type".into()))?;
        let resource_type = o3k_kernel::ResourceType::new(resource_namespace, resource_name)
            .map_err(|error| {
                StoreError::Corrupt(format!("invalid idempotency resource type: {error}"))
            })?;
        if action_id.namespace() != resource_type.namespace() {
            return Err(StoreError::Corrupt(
                "idempotency action and resource namespaces differ".into(),
            ));
        }
        let resource_type = resource_type.to_string();
        let canonical = canonical_json(body);
        let material = format!(
            "{action}\n{resource_type}\n{}\n{canonical}",
            target.unwrap_or("")
        );
        use sha2::{Digest, Sha256};
        let fingerprint = format!("{:x}", Sha256::digest(material.as_bytes()));
        Ok(Self {
            owner_scope,
            action,
            resource_type,
            key,
            fingerprint,
            operation_id,
        })
    }
}

fn canonical_json(value: &serde_json::Value) -> String {
    match value {
        serde_json::Value::Object(map) => {
            let mut entries: Vec<_> = map.iter().collect();
            entries.sort_by_key(|(key, _)| *key);
            let fields = entries
                .into_iter()
                .map(|(k, v)| {
                    format!(
                        "{}:{}",
                        serde_json::to_string(k).unwrap_or_default(),
                        canonical_json(v)
                    )
                })
                .collect::<Vec<_>>()
                .join(",");
            format!("{{{fields}}}")
        }
        serde_json::Value::Array(values) => format!(
            "[{}]",
            values
                .iter()
                .map(canonical_json)
                .collect::<Vec<_>>()
                .join(",")
        ),
        _ => value.to_string(),
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ProviderReference {
    pub resource_id: Uuid,
    pub provider_name: String,
    pub provider_resource_id: String,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ImageOverlayIdentity {
    pub resource_id: Uuid,
    pub operation_id: Uuid,
    pub command_id: String,
    pub agent_id: String,
    pub agent_epoch: String,
    pub base_sha256: String,
    pub base_format: String,
    pub overlay_format: String,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ImageOverlayOwnershipRecord {
    pub overlay_id: String,
    pub identity: ImageOverlayIdentity,
    pub state: ImageOverlayState,
    pub created_at: String,
    pub updated_at: String,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct ImageOverlayUpdate {
    pub state: ImageOverlayState,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct AgentCommandRecord {
    pub command_id: String,
    pub idempotency_key: String,
    pub operation_id: Uuid,
    pub resource_id: Uuid,
    pub agent_id: String,
    pub agent_epoch: String,
    pub payload_fingerprint_sha256: String,
    pub payload: Vec<u8>,
    pub state: AgentCommandState,
    pub accepted_sequence: u64,
    pub last_sequence: u64,
    pub provider_operation_id: Option<String>,
    pub provider_resource_id: Option<String>,
}
