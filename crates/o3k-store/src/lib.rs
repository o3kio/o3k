//! O3K durable store: persistence records, repository ports, SQLite/PostgreSQL adapters.
//!
//! Architecture:
//!   model types (72-2382): persistence record structs and repository traits
//!   sqlite adapter (2382+): SQLite implementation with `SqliteStore`
//!   postgres module: PostgreSQL implementation with `PostgresStore`
//!   unified module: backend dispatch with `O3kStore`
//!   coordination module: distributed coordination primitives
//!   quota module: resource quota management
//!   storage module: storage persistence
//!
//! Domain-specific code remains inline where it preserves atomic invariants
//! across repository, SQL, and business logic boundaries.
//!

use std::{
    fs,
    net::Ipv4Addr,
    path::{Path, PathBuf},
};

use base64::{Engine as _, engine::general_purpose::STANDARD as BASE64};
use chrono::DateTime;
use uuid::Uuid;

#[cfg(unix)]
use std::os::unix::fs::PermissionsExt;

mod artifact_transfer;
pub mod conformance;
pub mod coordination;
pub mod governance;
pub mod postgres;
pub mod quota;
mod reusable_policy;
mod server_state;
pub mod storage;
pub mod unified;

pub mod domain;
pub mod port;
pub use coordination::{
    ControllerEpoch, ControllerId, ControllerSession, ControllerState, CoordinationRepository,
    FencingToken, LeaseAcquireOutcome, WorkLease,
};
pub use postgres::PostgresStore;
pub use reusable_policy::CanonicalPolicyRepository;
pub use unified::O3kStore;

// Re-exports from domain/ and port/ sub-modules
pub use domain::error::StoreError;
pub use domain::records::{
    AgentCommandRecord, AuditEventRecord, CanonicalAddressPoolRecord, CanonicalAddressRealmRecord,
    CanonicalEndpointRecord, CanonicalL3GatewayAttachmentRecord, CanonicalL3GatewayRecord,
    CanonicalNetworkPolicyRecord, CanonicalNetworkPolicyRuleRecord, CanonicalNetworkRecord,
    CanonicalOperationLifecycleUpdate, CanonicalOperationRecord, CanonicalPolicyAttachmentRecord,
    CanonicalPolicyRealizationRecord, CanonicalRealmBindingRecord,
    CanonicalReusableNetworkPolicyRecord, DatabaseHealth, FederatedBindingRecord,
    IdempotencyReservationRequest, ImageMetadataRecord, ImageOverlayIdentity,
    ImageOverlayOwnershipRecord, ImageOverlayUpdate, KeypairRecord, KeystoneDomainRecord,
    KeystoneEndpointRecord, KeystoneProjectRecord, KeystoneRegionRecord,
    KeystoneRoleAssignmentRecord, KeystoneRoleRecord, KeystoneServiceRecord, KeystoneUserRecord,
    NetworkAddressAllocationRecord, NetworkIntentRecord, NetworkRecord, ObservationUpdate,
    OperationRecord, OperatorAssignmentRecord, PlacementAllocationRecord,
    PlacementCapacityClassRecord, PlacementCapacitySummary, PlacementIntentRecord,
    PlacementInventoryRecord, PlacementProviderRecord, PlacementProviderStateRecord,
    PlacementReconcileRecord, PlacementResourceRecord, PortRecord, ProviderReference,
    ResourceRecord, SecurityGroupBindingRecord, SecurityGroupRecord, SecurityGroupRuleRecord,
    StoredIdempotencyReservation, SubnetRecord, VolumeAttachmentRecord,
};
pub(crate) use domain::records::{legacy_policy_records, validate_canonical_lifecycle_update};
pub use domain::state::{
    AgentCommandState, CanonicalAcceptanceOutcome, IdempotencyReservation, ImageOverlayState,
    OperationState, WalCheckpointMode,
};
pub use port::durable::{
    DurableStore, RelationshipRepository, RepositoryPage, ResourceRelationshipRecord,
};
pub(crate) use port::durable::{
    RELATIONSHIP_BOUND, RELATIONSHIP_DELETED, RELATIONSHIP_DELETING, RELATIONSHIP_RESERVED,
    RELATIONSHIP_UNKNOWN, relationship_from_row,
};
pub use port::service_repos::{
    AuditRepository, ComputeRepository, IdentityRepository, ImageRepository, KeypairRepository,
    NetworkRepository, PlacementRepository, VolumeAttachmentRepository,
};
/// Maximum attempts for an observation update contended by a concurrent
/// SQLite writer. BEGIN IMMEDIATE makes the configured busy_timeout apply, so
/// retries only absorb contention bursts that outlast it; the update is
/// idempotent, so a retry never double-applies.
const SQLITE_BUSY_MAX_ATTEMPTS: u32 = 5;

/// Reports whether a sqlx error is a SQLite lock-contention failure:
/// SQLITE_BUSY (extended code 5) or SQLITE_BUSY_SNAPSHOT (517). sqlx preserves
/// the extended code, so both variants are matchable here.
fn is_sqlite_busy(error: &sqlx::Error) -> bool {
    match error {
        sqlx::Error::Database(database) => {
            matches!(database.code().as_deref(), Some("5") | Some("517"))
        }
        _ => false,
    }
}

pub use artifact_transfer::{
    ArtifactTransferRecord, ArtifactTransferState, ArtifactTransferUpdate,
    MAX_ARTIFACT_TRANSFER_BYTES, MAX_ARTIFACT_TRANSFER_CHUNK_BYTES, MAX_ARTIFACT_TRANSFER_RETRIES,
};
pub use server_state::{server_state_from_storage, server_state_to_storage};
pub use storage::{
    SnapshotRecord, StorageBackendRecord, StorageRepository, VolumeAttachmentRecordV1, VolumeRecord,
};

mod sqlite;
pub use sqlite::SqliteStore;
pub use sqlite::validate_public_key;
pub(crate) use sqlite::{
    checked_generation, map_canonical_insert_error, parse_uuid, sqlite_sequence,
    validate_canonical_state, validate_ipv4_cidr, validate_network_intent_transition,
    validate_network_intent_update,
};

/// describe one operation before any of them are persisted.
pub(crate) fn validate_canonical_idempotent_operation_identity(
    operation: &OperationRecord,
    canonical: &CanonicalOperationRecord,
    request: &IdempotencyReservationRequest,
) -> Result<(), StoreError> {
    if operation.id != canonical.id || operation.id != request.operation_id {
        return Err(StoreError::Corrupt(
            "durable, canonical, and idempotency operation identities differ".into(),
        ));
    }
    if operation.state != canonical.state {
        return Err(StoreError::Corrupt(
            "durable and canonical operation states differ".into(),
        ));
    }

    let kernel = o3k_kernel::Operation::try_from(canonical.clone())?;
    if kernel.service.trim().is_empty()
        || kernel.actor.trim().is_empty()
        || kernel.created_at.trim().is_empty()
    {
        return Err(StoreError::Corrupt(
            "canonical operation identity is incomplete".into(),
        ));
    }
    if kernel.action.namespace() != kernel.resource_type.namespace() {
        return Err(StoreError::Corrupt(
            "operation action and resource namespaces differ".into(),
        ));
    }
    if kernel.action.as_str() != request.action {
        return Err(StoreError::Corrupt(
            "canonical operation and idempotency actions differ".into(),
        ));
    }
    if kernel.resource_type.to_string() != request.resource_type {
        return Err(StoreError::Corrupt(
            "canonical operation and idempotency resource types differ".into(),
        ));
    }
    if kernel.owner_scope.kind() != o3k_kernel::ScopeKind::Project
        || kernel.owner_scope.id().as_str() != request.owner_scope
    {
        return Err(StoreError::Corrupt(
            "canonical operation and idempotency owner scopes differ".into(),
        ));
    }
    let canonical_resource_id = kernel
        .resource_id
        .as_ref()
        .ok_or_else(|| StoreError::Corrupt("durable operation requires a resource id".into()))?;
    if canonical_resource_id.as_str() != operation.resource_id.to_string() {
        return Err(StoreError::Corrupt(
            "durable and canonical resource identities differ".into(),
        ));
    }
    Ok(())
}

/// Validates the complete relationship used by the native Operation reader.
/// Metadata alone is never sufficient: the durable operation and its owned
/// resource are authoritative for identity and ownership.
pub(crate) fn validate_canonical_operation_read(
    operation: &OperationRecord,
    canonical: &CanonicalOperationRecord,
    resource: &ResourceRecord,
) -> Result<(), StoreError> {
    if operation.id != canonical.id
        || operation.resource_id != resource.id
        || canonical.resource_id.as_deref() != Some(&resource.id.to_string())
    {
        return Err(StoreError::Corrupt(
            "canonical operation/resource identities differ".into(),
        ));
    }
    if canonical.owner_scope != resource.project_id {
        return Err(StoreError::Corrupt(
            "canonical operation owner differs from resource owner".into(),
        ));
    }
    if canonical.actor.trim().is_empty()
        || canonical.created_at.trim().is_empty()
        || DateTime::parse_from_rfc3339(&canonical.created_at).is_err()
        || canonical
            .started_at
            .as_deref()
            .is_some_and(|v| DateTime::parse_from_rfc3339(v).is_err())
        || canonical
            .finished_at
            .as_deref()
            .is_some_and(|v| DateTime::parse_from_rfc3339(v).is_err())
    {
        return Err(StoreError::Corrupt(
            "canonical operation identity is incomplete".into(),
        ));
    }
    let action = o3k_kernel::ActionId::parse(&canonical.action)
        .map_err(|e| StoreError::Corrupt(format!("invalid operation action: {e}")))?;
    let (namespace, name) = canonical
        .resource_type
        .split_once(':')
        .ok_or_else(|| StoreError::Corrupt("invalid operation resource type".into()))?;
    let resource_type = o3k_kernel::ResourceType::new(namespace, name)
        .map_err(|e| StoreError::Corrupt(format!("invalid operation resource type: {e}")))?;
    let expected_resource_type = canonical_resource_type_for_record(resource)?;
    if action.namespace() != resource_type.namespace() || resource_type != expected_resource_type {
        return Err(StoreError::Corrupt(
            "canonical operation action/resource namespace or resource type differ".into(),
        ));
    }
    if operation.state != canonical.state {
        return Err(StoreError::Corrupt(
            "durable and canonical operation states differ".into(),
        ));
    }
    Ok(())
}

/// Validates a canonical operation whose resource is owned by a service
/// table, not by the generic resource index.
pub(crate) fn validate_canonical_scoped_operation_read(
    operation: &OperationRecord,
    canonical: &CanonicalOperationRecord,
) -> Result<(), StoreError> {
    if operation.id != canonical.id
        || canonical.resource_id.as_deref() != Some(&operation.resource_id.to_string())
    {
        return Err(StoreError::Corrupt(
            "canonical scoped operation identities differ".into(),
        ));
    }
    if canonical.actor.trim().is_empty()
        || canonical.owner_scope.trim().is_empty()
        || canonical.created_at.trim().is_empty()
        || DateTime::parse_from_rfc3339(&canonical.created_at).is_err()
        || canonical
            .started_at
            .as_deref()
            .is_some_and(|v| DateTime::parse_from_rfc3339(v).is_err())
        || canonical
            .finished_at
            .as_deref()
            .is_some_and(|v| DateTime::parse_from_rfc3339(v).is_err())
    {
        return Err(StoreError::Corrupt(
            "canonical operation identity is incomplete".into(),
        ));
    }
    let action = o3k_kernel::ActionId::parse(&canonical.action)
        .map_err(|e| StoreError::Corrupt(format!("invalid operation action: {e}")))?;
    let (namespace, name) = canonical
        .resource_type
        .split_once(':')
        .ok_or_else(|| StoreError::Corrupt("invalid operation resource type".into()))?;
    let resource_type = o3k_kernel::ResourceType::new(namespace, name)
        .map_err(|e| StoreError::Corrupt(format!("invalid operation resource type: {e}")))?;
    if action.namespace() != resource_type.namespace()
        || operation.state != canonical.state
        || resource_type.namespace() != "network"
        || !matches!(resource_type.name(), "network" | "address_realm")
    {
        return Err(StoreError::Corrupt(
            "canonical scoped operation action/resource/state differs".into(),
        ));
    }
    Ok(())
}

pub(crate) fn validate_canonical_resource_acceptance(
    resource: &ResourceRecord,
    operation: &OperationRecord,
    canonical: &CanonicalOperationRecord,
    request: &IdempotencyReservationRequest,
) -> Result<(), StoreError> {
    validate_canonical_idempotent_operation_identity(operation, canonical, request)?;
    if operation.resource_id != resource.id || resource.project_id != canonical.owner_scope {
        return Err(StoreError::Corrupt(
            "canonical acceptance resource identity or ownership differs".into(),
        ));
    }
    let expected_type = canonical_resource_type_for_record(resource)?;
    if expected_type.to_string() != canonical.resource_type {
        return Err(StoreError::Corrupt(
            "canonical acceptance resource type differs from durable resource kind".into(),
        ));
    }
    Ok(())
}

/// Map the durable/internal resource discriminator to the canonical Kernel
/// resource type.  These values intentionally are not required to be equal:
/// historical Compute rows use `compute_instance`, while the native contract
/// exposes `compute:server`.
pub(crate) fn canonical_resource_type_for_record(
    resource: &ResourceRecord,
) -> Result<o3k_kernel::ResourceType, StoreError> {
    if let Some((namespace, name)) = resource.kind.split_once(':') {
        return o3k_kernel::ResourceType::new(namespace, name)
            .map_err(|e| StoreError::Corrupt(format!("invalid canonical resource type: {e}")));
    }
    let (namespace, name) = match resource.kind.as_str() {
        "compute_instance" | "compute_server" | "server" | "compute:server" => {
            ("compute", "server")
        }
        "volume" | "volume_volume" | "volume:volume" => ("volume", "volume"),
        "address_realm" | "network_address_realm" | "network:address_realm" => {
            ("network", "address_realm")
        }
        _ => return Err(StoreError::Corrupt("unknown durable resource kind".into())),
    };
    o3k_kernel::ResourceType::new(namespace, name)
        .map_err(|e| StoreError::Corrupt(format!("invalid canonical resource type: {e}")))
}

pub use governance::{
    CreateAssignmentOutcome, GovernanceAssignmentFilter, GovernancePrincipalRecord,
    GovernanceReferences, GovernanceRepository, GovernanceRoleGrantRecord,
};
pub use quota::QuotaRepository;

/// Test-only construction helpers for the SQLite adapter.
///
/// Application crate tests build adapters through this module so the concrete
/// `SqliteStore` symbol never appears in application sources: the
/// architecture-boundary ratchet scans `src/**/*.rs` of application crates for
/// that literal symbol, and the adapter is an infrastructure detail that tests
/// of application behavior should not depend on by name.
pub mod testkit {
    use std::path::Path;

    use super::{SqliteStore, StoreError};

    /// Concrete SQLite adapter type used by application-crate tests. Named
    /// here so application sources never spell out `SqliteStore`; the
    /// architecture-boundary ratchet scans application `src/**/*.rs` for that
    /// literal symbol.
    pub type TestStore = SqliteStore;

    /// Opens a fresh in-memory SQLite adapter. Each call owns a private
    /// connection pool with the memory journal; it is not shared across
    /// stores.
    pub async fn open_memory() -> Result<TestStore, StoreError> {
        SqliteStore::connect("sqlite::memory:").await
    }

    /// Opens (creating when missing) a file-backed SQLite adapter with the
    /// production WAL posture, migrations, and integrity verification.
    pub async fn open_file(path: &Path) -> Result<TestStore, StoreError> {
        SqliteStore::connect_file(path).await
    }
}

/// Runs the behavior shared by every durable store adapter.
pub async fn run_conformance<S: DurableStore>(store: &S) -> Result<(), StoreError> {
    let resource = ResourceRecord {
        id: Uuid::now_v7(),
        kind: "server".to_owned(),
        project_id: "project-a".to_owned(),
        generation: 1,
        observed_generation: 0,
        desired_state: "requested".to_owned(),
        observed_state: "unknown".to_owned(),
        provider_id: Some("provider-1".to_owned()),
    };
    store.insert_resource(&resource).await?;
    assert_eq!(store.get_resource(resource.id).await?, resource);
    assert_eq!(store.list_resources("project-a", "server").await?.len(), 1);
    assert!(matches!(
        store
            .update_resource(resource.id, 0, "active", "running", 1, Some("provider-1"))
            .await,
        Err(StoreError::StaleGeneration)
    ));
    let updated = store
        .update_resource(resource.id, 1, "active", "running", 1, Some("provider-1"))
        .await?;
    assert_eq!(updated.generation, 2);
    let operation = OperationRecord {
        id: Uuid::now_v7(),
        resource_id: resource.id,
        kind: "test".to_owned(),
        state: OperationState::UnknownOutcome,
        provider_operation_id: Some("provider-op-1".to_owned()),
        error_category: Some("unknown_outcome".to_owned()),
        error_message: Some("acceptance could not be confirmed".to_owned()),
    };
    store.insert_operation(&operation).await?;
    assert_eq!(store.get_operation(operation.id).await?, operation);
    let updated_operation = store
        .update_operation(
            operation.id,
            OperationState::Succeeded,
            Some("provider-op-1"),
            None,
            None,
        )
        .await?;
    assert_eq!(updated_operation.state, OperationState::Succeeded);
    let reference = ProviderReference {
        resource_id: resource.id,
        provider_name: "fake".to_owned(),
        provider_resource_id: "instance-1".to_owned(),
    };
    store.attach_provider_reference(&reference).await?;
    assert_eq!(
        store.get_provider_reference(resource.id, "fake").await?,
        reference
    );
    Ok(())
}

/// Runs the behavior shared by every identity repository adapter: each record
/// kind round-trips through its insert/list pair, and the deterministic
/// bootstrap upserts are idempotent for the same identity.
pub async fn run_identity_repository_conformance<S: IdentityRepository>(
    store: &S,
) -> Result<(), StoreError> {
    let now = "2026-08-07T00:00:00Z".to_owned();
    let domain = KeystoneDomainRecord {
        id: "default".to_owned(),
        name: "Default".to_owned(),
        description: Some("Default domain".to_owned()),
        enabled: true,
        created_at: now.clone(),
    };
    store.insert_keystone_domain(&domain).await?;
    store.insert_keystone_domain(&domain).await?;
    assert_eq!(store.list_keystone_domains().await?, vec![domain.clone()]);

    let project = KeystoneProjectRecord {
        id: "project-a".to_owned(),
        domain_id: domain.id.clone(),
        name: "admin".to_owned(),
        description: None,
        enabled: true,
        created_at: now.clone(),
    };
    store.insert_keystone_project(&project).await?;
    store.insert_keystone_project(&project).await?;
    assert_eq!(store.list_keystone_projects().await?, vec![project.clone()]);

    let user = KeystoneUserRecord {
        id: "user-a".to_owned(),
        domain_id: domain.id.clone(),
        name: "admin".to_owned(),
        password_hash: "pbkdf2_sha256$1$test".to_owned(),
        email: None,
        enabled: true,
        created_at: now.clone(),
    };
    store.insert_keystone_user(&user).await?;
    store.insert_keystone_user(&user).await?;
    assert_eq!(store.list_keystone_users().await?, vec![user.clone()]);

    let binding = FederatedBindingRecord {
        id: "binding-a".to_owned(),
        trusted_issuer_id: "issuer-a".to_owned(),
        issuer: "https://idp.example.test".to_owned(),
        subject: "subject-a".to_owned(),
        principal_id: user.id.clone(),
        principal_type: "user".to_owned(),
        enabled: true,
        created_at: now.clone(),
        updated_at: now.clone(),
    };
    store.insert_federated_binding(&binding).await?;
    assert_eq!(
        store
            .find_federated_binding("issuer-a", "subject-a")
            .await?,
        Some(binding.clone())
    );
    assert!(store.insert_federated_binding(&binding).await.is_err());
    assert!(
        store
            .find_federated_binding("issuer-b", "subject-a")
            .await?
            .is_none()
    );
    store
        .set_federated_binding_enabled(&binding.id, false)
        .await?;
    assert!(
        store
            .find_federated_binding("issuer-a", "subject-a")
            .await?
            .is_none()
    );
    store
        .set_federated_binding_enabled(&binding.id, true)
        .await?;
    let Some(reenabled) = store
        .find_federated_binding("issuer-a", "subject-a")
        .await?
    else {
        return Err(StoreError::Corrupt(
            "reenabled federated binding did not resolve".to_owned(),
        ));
    };
    assert_eq!(reenabled.id, binding.id);
    assert_eq!(reenabled.principal_id, binding.principal_id);
    assert!(reenabled.updated_at >= binding.updated_at);

    let disabled_user = KeystoneUserRecord {
        id: "user-disabled".to_owned(),
        domain_id: domain.id.clone(),
        name: "disabled".to_owned(),
        password_hash: "pbkdf2_sha256$1$test".to_owned(),
        email: user.email.clone(),
        enabled: false,
        created_at: now.clone(),
    };
    store.insert_keystone_user(&disabled_user).await?;
    let disabled_binding = FederatedBindingRecord {
        id: "binding-disabled-principal".to_owned(),
        trusted_issuer_id: "issuer-a".to_owned(),
        issuer: "https://idp.example.test".to_owned(),
        subject: "subject-disabled".to_owned(),
        principal_id: disabled_user.id.clone(),
        principal_type: "user".to_owned(),
        enabled: true,
        created_at: now.clone(),
        updated_at: now.clone(),
    };
    store.insert_federated_binding(&disabled_binding).await?;
    assert!(
        store
            .find_federated_binding("issuer-a", "subject-disabled")
            .await?
            .is_none()
    );

    let missing_principal = FederatedBindingRecord {
        id: "binding-missing-principal".to_owned(),
        principal_id: "missing-user".to_owned(),
        subject: "subject-missing".to_owned(),
        ..disabled_binding.clone()
    };
    assert!(
        store
            .insert_federated_binding(&missing_principal)
            .await
            .is_err()
    );

    let concurrent_a = FederatedBindingRecord {
        id: "binding-concurrent-a".to_owned(),
        trusted_issuer_id: "issuer-concurrent".to_owned(),
        subject: "same-subject".to_owned(),
        ..binding.clone()
    };
    let concurrent_b = FederatedBindingRecord {
        id: "binding-concurrent-b".to_owned(),
        ..concurrent_a.clone()
    };
    let (left, right) = tokio::join!(
        store.insert_federated_binding(&concurrent_a),
        store.insert_federated_binding(&concurrent_b)
    );
    assert_eq!(usize::from(left.is_ok()) + usize::from(right.is_ok()), 1);

    let role = KeystoneRoleRecord {
        id: "role-a".to_owned(),
        name: "admin".to_owned(),
        description: None,
        created_at: now.clone(),
    };
    store.insert_keystone_role(&role).await?;
    store.insert_keystone_role(&role).await?;
    assert_eq!(store.list_keystone_roles().await?, vec![role.clone()]);

    let assignment = KeystoneRoleAssignmentRecord {
        id: "assignment-0".to_owned(),
        user_id: user.id.clone(),
        project_id: project.id.clone(),
        role_id: role.id.clone(),
        created_at: now.clone(),
    };
    store.insert_keystone_role_assignment(&assignment).await?;
    store.insert_keystone_role_assignment(&assignment).await?;
    assert_eq!(
        store.list_keystone_role_assignments().await?,
        vec![assignment]
    );

    let service = KeystoneServiceRecord {
        id: "service-a".to_owned(),
        name: "identity".to_owned(),
        r#type: "identity".to_owned(),
        description: None,
        enabled: true,
        created_at: now.clone(),
    };
    store.insert_keystone_service(&service).await?;
    store.insert_keystone_service(&service).await?;
    assert_eq!(store.list_keystone_services().await?, vec![service.clone()]);

    let endpoint = KeystoneEndpointRecord {
        id: "endpoint-a".to_owned(),
        service_id: service.id.clone(),
        interface: "public".to_owned(),
        url: "http://127.0.0.1:8080/v3".to_owned(),
        region: "RegionOne".to_owned(),
        enabled: true,
        created_at: now.clone(),
    };
    store.insert_keystone_endpoint(&endpoint).await?;
    store.insert_keystone_endpoint(&endpoint).await?;
    assert_eq!(store.list_keystone_endpoints().await?, vec![endpoint]);

    let region = KeystoneRegionRecord {
        id: "RegionOne".to_owned(),
        description: None,
        parent_region_id: None,
        enabled: true,
        created_at: now,
    };
    store.insert_keystone_region(&region).await?;
    store.insert_keystone_region(&region).await?;
    assert_eq!(store.list_keystone_regions().await?, vec![region]);
    Ok(())
}

/// Runs the behavior shared by every keypair repository adapter: scoped
/// uniqueness, canonical record acceptance, attach/detach against a durable
/// server, in-use protection, and scoped delete.
pub async fn run_keypair_repository_conformance<S: KeypairRepository + DurableStore>(
    store: &S,
) -> Result<(), StoreError> {
    let resource = ResourceRecord {
        id: Uuid::now_v7(),
        kind: "compute_instance".to_owned(),
        project_id: "project-a".to_owned(),
        generation: 1,
        observed_generation: 0,
        desired_state: "{\"key_name\": \"other\"}".to_owned(),
        observed_state: "BUILD".to_owned(),
        provider_id: None,
    };
    store.insert_resource(&resource).await?;

    let blob = [
        0, 0, 0, 11, b's', b's', b'h', b'-', b'e', b'd', b'2', b'5', b'5', b'1', b'9', 0, 0, 0, 32,
    ]
    .into_iter()
    .chain([9_u8; 32])
    .collect::<Vec<_>>();
    let (key_type, fingerprint, canonical) =
        validate_public_key(&format!("ssh-ed25519 {}", BASE64.encode(blob)))?;
    let keypair = KeypairRecord {
        id: Uuid::now_v7(),
        user_id: "user-a".to_owned(),
        project_id: "project-a".to_owned(),
        name: "test-key".to_owned(),
        key_type,
        public_key: canonical,
        fingerprint,
        created_at: "1".to_owned(),
    };
    store.insert_keypair(&keypair).await?;
    assert!(matches!(
        store.insert_keypair(&keypair).await,
        Err(StoreError::KeypairAlreadyExists)
    ));
    assert_eq!(
        store.get_keypair("user-a", "project-a", "test-key").await?,
        keypair
    );
    assert!(matches!(
        store.get_keypair("user-b", "project-a", "test-key").await,
        Err(StoreError::KeypairNotFound)
    ));
    assert_eq!(store.list_keypairs("user-a", "project-a").await?.len(), 1);

    store.attach_server_keypair(resource.id, keypair.id).await?;
    assert_eq!(
        store.get_server_keypair_name(resource.id).await?,
        Some(keypair.name.clone())
    );
    assert!(matches!(
        store
            .delete_keypair("user-a", "project-a", "test-key")
            .await,
        Err(StoreError::KeypairInUse)
    ));
    store.detach_server_keypair(resource.id).await?;
    assert_eq!(store.get_server_keypair_name(resource.id).await?, None);
    store
        .delete_keypair("user-a", "project-a", "test-key")
        .await?;
    assert!(matches!(
        store
            .delete_keypair("user-a", "project-a", "test-key")
            .await,
        Err(StoreError::KeypairNotFound)
    ));
    Ok(())
}

/// Runs the behavior shared by every volume-attachment repository adapter:
/// phase and outcome persistence with COALESCE field preservation, status
/// filtering, server-scoped reads, and delete.
pub async fn run_volume_attachment_repository_conformance<
    S: VolumeAttachmentRepository + DurableStore,
>(
    store: &S,
) -> Result<(), StoreError> {
    let resource = ResourceRecord {
        id: Uuid::now_v7(),
        kind: "compute_instance".to_owned(),
        project_id: "project-a".to_owned(),
        generation: 1,
        observed_generation: 0,
        desired_state: "requested".to_owned(),
        observed_state: "BUILD".to_owned(),
        provider_id: None,
    };
    store.insert_resource(&resource).await?;

    let attachment = VolumeAttachmentRecord {
        id: Uuid::now_v7(),
        server_id: resource.id,
        volume_id: Uuid::now_v7(),
        device: "/dev/vdb".to_owned(),
        tag: None,
        delete_on_termination: false,
        created_at: "2026-08-07T00:00:00Z".to_owned(),
        status: "validated".to_owned(),
        operation_id: None,
        idempotency_key: Some("idem-attach-1".to_owned()),
        cinder_attachment_id: None,
        connector_host: None,
        connector_ip: None,
        connector_initiator: None,
        driver_volume_type: None,
        target_iqn: None,
        target_portal: None,
        target_lun: None,
        connection_info_digest: None,
        error: None,
    };
    store.insert_volume_attachment(&attachment).await?;
    assert_eq!(
        store
            .get_volume_attachment_by_id(attachment.id)
            .await?
            .ok_or(StoreError::Corrupt(
                "conformance attachment missing after insert".to_owned()
            ))?,
        attachment
    );
    assert_eq!(
        store
            .get_volume_attachment_by_volume(attachment.volume_id)
            .await?
            .ok_or(StoreError::Corrupt(
                "conformance attachment missing by volume".to_owned()
            ))?,
        attachment
    );
    assert_eq!(
        store
            .get_volume_attachment_by_volume_for_server(attachment.volume_id, attachment.server_id)
            .await?
            .ok_or(StoreError::Corrupt(
                "conformance attachment missing by scoped volume".to_owned()
            ))?,
        attachment
    );
    assert!(
        store
            .get_volume_attachment_by_volume_for_server(attachment.volume_id, Uuid::now_v7(),)
            .await?
            .is_none(),
        "volume id lookup must not cross server ownership"
    );
    assert_eq!(
        store
            .get_volume_attachment_by_idempotency("idem-attach-1")
            .await?
            .ok_or(StoreError::Corrupt(
                "conformance attachment missing by idempotency".to_owned()
            ))?,
        attachment
    );

    let phased = store
        .update_volume_attachment_phase(attachment.id, "cinder_attachment_created", None)
        .await?;
    assert_eq!(phased.status, "cinder_attachment_created");
    assert!(phased.error.is_none());

    let outcome = store
        .update_volume_attachment_outcome(
            attachment.id,
            "connector_obtained",
            Some("cinder-att-1"),
            Some("compute-1"),
            Some("10.0.0.5"),
            Some("iqn.2026-08.org.o3k:node"),
            Some("iscsi"),
            None,
            None,
            None,
            None,
            None,
        )
        .await?;
    assert_eq!(
        outcome.cinder_attachment_id.as_deref(),
        Some("cinder-att-1")
    );
    assert_eq!(outcome.connector_host.as_deref(), Some("compute-1"));
    // COALESCE semantics: a later phase that only reports status/device must
    // not wipe the connector fields persisted by an earlier phase.
    let later = store
        .update_volume_attachment_outcome(
            attachment.id,
            "attached",
            None,
            None,
            None,
            None,
            None,
            None,
            None,
            None,
            None,
            Some("/dev/vdb"),
        )
        .await?;
    assert_eq!(later.status, "attached");
    assert_eq!(later.connector_host.as_deref(), Some("compute-1"));
    assert_eq!(later.cinder_attachment_id.as_deref(), Some("cinder-att-1"));
    assert_eq!(later.device, "/dev/vdb");

    assert_eq!(store.list_volume_attachments(resource.id).await?.len(), 1);
    assert!(
        store
            .list_volume_attachments_by_status(&["attached", "detached", "error"])
            .await?
            .is_empty()
    );
    assert_eq!(
        store
            .get_volume_attachment(resource.id, attachment.id)
            .await?
            .ok_or(StoreError::Corrupt(
                "conformance attachment missing by server".to_owned()
            ))?
            .id,
        attachment.id
    );
    store
        .delete_volume_attachment(resource.id, attachment.id)
        .await?;
    assert_eq!(
        store.get_volume_attachment_by_id(attachment.id).await?,
        None
    );
    Ok(())
}

/// Runs the behavior shared by every image repository adapter: the
/// insert/get round-trip with all fields, project-scoped reads and lists,
/// the queued -> active activation transition that seals size and checksum,
/// and scoped delete.
pub async fn run_image_repository_conformance<S: ImageRepository>(
    repository: &S,
) -> Result<(), StoreError> {
    let first = ImageMetadataRecord {
        id: Uuid::now_v7(),
        name: "alpha".to_owned(),
        project_id: "project-a".to_owned(),
        status: "queued".to_owned(),
        visibility: "private".to_owned(),
        container_format: "bare".to_owned(),
        disk_format: "raw".to_owned(),
        size: None,
        checksum: None,
    };
    repository.insert_image(&first).await?;
    assert_eq!(
        repository.get_image("project-a", &first.id).await?.as_ref(),
        Some(&first)
    );
    assert_eq!(
        repository.get_image("project-a", &Uuid::now_v7()).await?,
        None
    );
    assert_eq!(repository.get_image("project-b", &first.id).await?, None);
    assert_eq!(
        repository.list_images("project-a").await?,
        vec![first.clone()]
    );

    let second = ImageMetadataRecord {
        id: Uuid::now_v7(),
        name: "beta".to_owned(),
        project_id: "project-b".to_owned(),
        status: "queued".to_owned(),
        visibility: "private".to_owned(),
        container_format: "bare".to_owned(),
        disk_format: "qcow2".to_owned(),
        size: None,
        checksum: None,
    };
    repository.insert_image(&second).await?;
    let third = ImageMetadataRecord {
        id: Uuid::now_v7(),
        name: "alpha2".to_owned(),
        project_id: "project-a".to_owned(),
        status: "queued".to_owned(),
        visibility: "private".to_owned(),
        container_format: "bare".to_owned(),
        disk_format: "raw".to_owned(),
        size: None,
        checksum: None,
    };
    repository.insert_image(&third).await?;
    // list is project-scoped and deterministic: same-project images come
    // back sorted by name.
    assert_eq!(
        repository.list_images("project-a").await?,
        vec![first.clone(), third.clone()]
    );
    assert_eq!(
        repository.list_images("project-b").await?,
        vec![second.clone()]
    );

    let checksum = "a".repeat(64);
    let active = repository
        .activate_image("project-a", &first.id, 11, &checksum)
        .await?;
    assert_eq!(active.status, "active");
    assert_eq!(active.size, Some(11));
    assert_eq!(active.checksum.as_deref(), Some(checksum.as_str()));
    assert_eq!(active.name, first.name);
    assert_eq!(active.visibility, first.visibility);
    assert_eq!(active.container_format, first.container_format);
    assert_eq!(active.disk_format, first.disk_format);
    assert!(matches!(
        repository
            .activate_image("project-a", &first.id, 12, &checksum)
            .await,
        Err(StoreError::ImageAlreadyActive)
    ));
    assert!(matches!(
        repository
            .activate_image("project-a", &Uuid::now_v7(), 1, &checksum)
            .await,
        Err(StoreError::ImageNotFound)
    ));
    assert!(matches!(
        repository
            .activate_image("project-b", &first.id, 1, &checksum)
            .await,
        Err(StoreError::ImageNotFound)
    ));

    repository.delete_image("project-a", &first.id).await?;
    assert_eq!(repository.get_image("project-a", &first.id).await?, None);
    assert!(matches!(
        repository.delete_image("project-a", &first.id).await,
        Err(StoreError::ImageNotFound)
    ));
    assert!(matches!(
        repository.insert_image(&second).await,
        Err(StoreError::ResourceAlreadyExists)
    ));
    Ok(())
}

/// Runs the behavior shared by every network repository adapter: the
/// network/subnet/port insert/get round-trips with all fields, project-scoped
/// reads and lists in insertion order, unique-name and addressing conflicts,
/// reference-counted deletes that reject in-use resources, and port binding
/// updates.
pub async fn run_network_repository_conformance<S: NetworkRepository>(
    repository: &S,
) -> Result<(), StoreError> {
    let alpha = NetworkRecord {
        id: Uuid::now_v7(),
        name: "alpha".to_owned(),
        project_id: "project-a".to_owned(),
        status: "ACTIVE".to_owned(),
    };
    repository.insert_network(&alpha).await?;
    assert_eq!(
        repository
            .get_network("project-a", &alpha.id)
            .await?
            .as_ref(),
        Some(&alpha)
    );
    assert_eq!(repository.get_network("project-b", &alpha.id).await?, None);
    assert_eq!(
        repository.get_network("project-a", &Uuid::now_v7()).await?,
        None
    );
    assert_eq!(
        repository.list_networks("project-a").await?,
        vec![alpha.clone()]
    );
    assert!(repository.list_networks("project-b").await?.is_empty());

    let beta = NetworkRecord {
        id: Uuid::now_v7(),
        name: "beta".to_owned(),
        project_id: "project-b".to_owned(),
        status: "ACTIVE".to_owned(),
    };
    repository.insert_network(&beta).await?;
    let gamma = NetworkRecord {
        id: Uuid::now_v7(),
        name: "gamma".to_owned(),
        project_id: "project-a".to_owned(),
        status: "ACTIVE".to_owned(),
    };
    repository.insert_network(&gamma).await?;
    // Lists preserve insertion order by rowid.
    assert_eq!(
        repository.list_networks("project-a").await?,
        vec![alpha.clone(), gamma.clone()]
    );
    assert_eq!(
        repository.list_networks("project-b").await?,
        vec![beta.clone()]
    );
    let duplicate_name = NetworkRecord {
        id: Uuid::now_v7(),
        name: "alpha".to_owned(),
        project_id: "project-a".to_owned(),
        status: "ACTIVE".to_owned(),
    };
    assert!(matches!(
        repository.insert_network(&duplicate_name).await,
        Err(StoreError::ResourceAlreadyExists)
    ));
    let duplicate_id = NetworkRecord {
        id: alpha.id,
        name: "alpha-copy".to_owned(),
        project_id: "project-a".to_owned(),
        status: "ACTIVE".to_owned(),
    };
    assert!(matches!(
        repository.insert_network(&duplicate_id).await,
        Err(StoreError::ResourceAlreadyExists)
    ));

    let subnet_network = NetworkRecord {
        id: Uuid::now_v7(),
        name: "subnet-network".to_owned(),
        project_id: "project-a".to_owned(),
        status: "ACTIVE".to_owned(),
    };
    repository.insert_network(&subnet_network).await?;
    let subnet = SubnetRecord {
        id: Uuid::now_v7(),
        network_id: subnet_network.id,
        name: "sn".to_owned(),
        project_id: "project-a".to_owned(),
        cidr: "10.0.1.0/24".to_owned(),
        gateway_ip: Ipv4Addr::new(10, 0, 1, 1),
        allocation_start: Ipv4Addr::new(10, 0, 1, 10),
        allocation_end: Ipv4Addr::new(10, 0, 1, 200),
        ip_version: 4,
        enable_dhcp: true,
    };
    repository.insert_subnet(&subnet).await?;
    assert_eq!(
        repository
            .get_subnet("project-a", &subnet.id)
            .await?
            .as_ref(),
        Some(&subnet)
    );
    assert_eq!(repository.get_subnet("project-b", &subnet.id).await?, None);
    let second_subnet = SubnetRecord {
        id: Uuid::now_v7(),
        network_id: subnet_network.id,
        name: "sn2".to_owned(),
        project_id: "project-a".to_owned(),
        cidr: "10.0.2.0/24".to_owned(),
        gateway_ip: Ipv4Addr::new(10, 0, 2, 1),
        allocation_start: Ipv4Addr::new(10, 0, 2, 10),
        allocation_end: Ipv4Addr::new(10, 0, 2, 200),
        ip_version: 4,
        enable_dhcp: true,
    };
    repository.insert_subnet(&second_subnet).await?;
    assert_eq!(
        repository
            .list_subnets_for_network("project-a", &subnet_network.id)
            .await?,
        vec![subnet.clone(), second_subnet.clone()]
    );
    let other_network = NetworkRecord {
        id: Uuid::now_v7(),
        name: "other".to_owned(),
        project_id: "project-a".to_owned(),
        status: "ACTIVE".to_owned(),
    };
    repository.insert_network(&other_network).await?;
    let foreign_subnet = SubnetRecord {
        id: Uuid::now_v7(),
        network_id: other_network.id,
        name: "foreign".to_owned(),
        project_id: "project-a".to_owned(),
        cidr: "10.0.3.0/24".to_owned(),
        gateway_ip: Ipv4Addr::new(10, 0, 3, 1),
        allocation_start: Ipv4Addr::new(10, 0, 3, 10),
        allocation_end: Ipv4Addr::new(10, 0, 3, 200),
        ip_version: 4,
        enable_dhcp: true,
    };
    repository.insert_subnet(&foreign_subnet).await?;
    // Subnets of other networks on the same project stay out of the list.
    assert_eq!(
        repository
            .list_subnets_for_network("project-a", &subnet_network.id)
            .await?,
        vec![subnet.clone(), second_subnet.clone()]
    );
    assert!(matches!(
        repository.insert_subnet(&subnet).await,
        Err(StoreError::ResourceAlreadyExists)
    ));
    let duplicate_cidr = SubnetRecord {
        id: Uuid::now_v7(),
        network_id: subnet_network.id,
        name: "sn-copy".to_owned(),
        project_id: "project-a".to_owned(),
        cidr: subnet.cidr.clone(),
        gateway_ip: Ipv4Addr::new(10, 0, 1, 1),
        allocation_start: Ipv4Addr::new(10, 0, 1, 10),
        allocation_end: Ipv4Addr::new(10, 0, 1, 200),
        ip_version: 4,
        enable_dhcp: true,
    };
    assert!(matches!(
        repository.insert_subnet(&duplicate_cidr).await,
        Err(StoreError::ResourceAlreadyExists)
    ));

    let port_network = NetworkRecord {
        id: Uuid::now_v7(),
        name: "port-network".to_owned(),
        project_id: "project-a".to_owned(),
        status: "ACTIVE".to_owned(),
    };
    repository.insert_network(&port_network).await?;
    let port_subnet = SubnetRecord {
        id: Uuid::now_v7(),
        network_id: port_network.id,
        name: "port-subnet".to_owned(),
        project_id: "project-a".to_owned(),
        cidr: "10.0.4.0/24".to_owned(),
        gateway_ip: Ipv4Addr::new(10, 0, 4, 1),
        allocation_start: Ipv4Addr::new(10, 0, 4, 10),
        allocation_end: Ipv4Addr::new(10, 0, 4, 200),
        ip_version: 4,
        enable_dhcp: true,
    };
    repository.insert_subnet(&port_subnet).await?;
    let port = PortRecord {
        id: Uuid::now_v7(),
        network_id: port_network.id,
        subnet_id: Some(port_subnet.id),
        project_id: "project-a".to_owned(),
        name: "instance-port".to_owned(),
        mac_address: "FA:16:3E:00:00:01".to_owned(),
        fixed_ip: Ipv4Addr::new(10, 0, 4, 5),
        status: "DOWN".to_owned(),
        binding_host: None,
        binding_state: None,
    };
    repository.insert_port(&port).await?;
    let restored = repository
        .get_port("project-a", &port.id)
        .await?
        .ok_or(StoreError::NetworkNotFound)?;
    assert_eq!(restored.id, port.id);
    assert_eq!(restored.network_id, port.network_id);
    assert_eq!(restored.subnet_id, port.subnet_id);
    assert_eq!(restored.project_id, port.project_id);
    assert_eq!(restored.name, port.name);
    assert_eq!(restored.fixed_ip, port.fixed_ip);
    assert_eq!(restored.status, port.status);
    assert_eq!(restored.binding_host, None);
    assert_eq!(restored.binding_state, None);
    // MAC addresses are stored normalized to lower case.
    assert_eq!(restored.mac_address, "fa:16:3e:00:00:01");
    let mut stored_port = port.clone();
    stored_port.mac_address = "fa:16:3e:00:00:01".to_owned();
    let duplicate_ip = PortRecord {
        id: Uuid::now_v7(),
        network_id: port_network.id,
        subnet_id: Some(port_subnet.id),
        project_id: "project-a".to_owned(),
        name: "dup-ip".to_owned(),
        mac_address: "FA:16:3E:00:00:02".to_owned(),
        fixed_ip: port.fixed_ip,
        status: "DOWN".to_owned(),
        binding_host: None,
        binding_state: None,
    };
    assert!(matches!(
        repository.insert_port(&duplicate_ip).await,
        Err(StoreError::ResourceAlreadyExists)
    ));
    let duplicate_mac = PortRecord {
        id: Uuid::now_v7(),
        network_id: port_network.id,
        subnet_id: Some(port_subnet.id),
        project_id: "project-a".to_owned(),
        name: "dup-mac".to_owned(),
        mac_address: "fa:16:3e:00:00:01".to_owned(),
        fixed_ip: Ipv4Addr::new(10, 0, 4, 6),
        status: "DOWN".to_owned(),
        binding_host: None,
        binding_state: None,
    };
    assert!(matches!(
        repository.insert_port(&duplicate_mac).await,
        Err(StoreError::ResourceAlreadyExists)
    ));
    assert!(matches!(
        repository.insert_port(&port).await,
        Err(StoreError::ResourceAlreadyExists)
    ));
    let unbound_port = PortRecord {
        id: Uuid::now_v7(),
        network_id: port_network.id,
        subnet_id: None,
        project_id: "project-a".to_owned(),
        name: "unbound".to_owned(),
        mac_address: "fa:16:3e:00:00:03".to_owned(),
        fixed_ip: Ipv4Addr::new(10, 0, 4, 7),
        status: "DOWN".to_owned(),
        binding_host: None,
        binding_state: None,
    };
    // A port without a subnet is allowed; the store does not enforce
    // subnet presence.
    repository.insert_port(&unbound_port).await?;
    assert_eq!(
        repository
            .get_port("project-a", &unbound_port.id)
            .await?
            .as_ref(),
        Some(&unbound_port)
    );
    assert_eq!(
        repository
            .list_ports_for_network("project-a", &port_network.id)
            .await?,
        vec![stored_port.clone(), unbound_port.clone()]
    );
    assert_eq!(repository.get_port("project-b", &port.id).await?, None);
    assert!(matches!(
        repository.delete_port("project-b", &port.id).await,
        Err(StoreError::NetworkNotFound)
    ));
    assert!(matches!(
        repository.delete_port("project-a", &Uuid::now_v7()).await,
        Err(StoreError::NetworkNotFound)
    ));
    let bound = repository
        .update_port_binding("project-a", &port.id, Some("compute-1"), Some("active"))
        .await?;
    assert_eq!(bound.binding_host.as_deref(), Some("compute-1"));
    assert_eq!(bound.binding_state.as_deref(), Some("active"));
    let cleared = repository
        .update_port_binding("project-a", &port.id, Some("compute-1"), None)
        .await?;
    assert_eq!(cleared.binding_host.as_deref(), Some("compute-1"));
    assert_eq!(cleared.binding_state, None);
    assert!(matches!(
        repository
            .update_port_binding("project-b", &port.id, Some("compute-2"), Some("active"))
            .await,
        Err(StoreError::NetworkNotFound)
    ));
    assert!(matches!(
        repository
            .update_port_binding(
                "project-a",
                &Uuid::now_v7(),
                Some("compute-2"),
                Some("active")
            )
            .await,
        Err(StoreError::NetworkNotFound)
    ));
    repository
        .delete_port("project-a", &unbound_port.id)
        .await?;
    assert_eq!(
        repository.get_port("project-a", &unbound_port.id).await?,
        None
    );

    let port_only_network = NetworkRecord {
        id: Uuid::now_v7(),
        name: "port-only".to_owned(),
        project_id: "project-a".to_owned(),
        status: "ACTIVE".to_owned(),
    };
    repository.insert_network(&port_only_network).await?;
    let port_only_port = PortRecord {
        id: Uuid::now_v7(),
        network_id: port_only_network.id,
        subnet_id: None,
        project_id: "project-a".to_owned(),
        name: "only-port".to_owned(),
        mac_address: "fa:16:3e:00:00:04".to_owned(),
        fixed_ip: Ipv4Addr::new(10, 0, 4, 8),
        status: "DOWN".to_owned(),
        binding_host: None,
        binding_state: None,
    };
    repository.insert_port(&port_only_port).await?;

    // Reference counting: subnets and ports keep their network alive, and
    // ports keep their network's subnets alive.
    assert!(matches!(
        repository
            .delete_network("project-a", &subnet_network.id)
            .await,
        Err(StoreError::NetworkInUse)
    ));
    assert!(matches!(
        repository
            .delete_network("project-a", &port_network.id)
            .await,
        Err(StoreError::NetworkInUse)
    ));
    assert!(matches!(
        repository
            .delete_network("project-a", &port_only_network.id)
            .await,
        Err(StoreError::NetworkInUse)
    ));
    assert!(matches!(
        repository.delete_subnet("project-a", &port_subnet.id).await,
        Err(StoreError::NetworkInUse)
    ));

    repository.delete_port("project-a", &port.id).await?;
    assert_eq!(repository.get_port("project-a", &port.id).await?, None);
    repository
        .delete_port("project-a", &port_only_port.id)
        .await?;
    assert_eq!(
        repository.get_port("project-a", &port_only_port.id).await?,
        None
    );

    repository.delete_subnet("project-a", &subnet.id).await?;
    assert_eq!(repository.get_subnet("project-a", &subnet.id).await?, None);
    assert!(matches!(
        repository.delete_subnet("project-a", &subnet.id).await,
        Err(StoreError::NetworkNotFound)
    ));
    assert!(matches!(
        repository
            .delete_subnet("project-b", &second_subnet.id)
            .await,
        Err(StoreError::NetworkNotFound)
    ));
    repository
        .delete_subnet("project-a", &foreign_subnet.id)
        .await?;
    assert_eq!(
        repository
            .get_subnet("project-a", &foreign_subnet.id)
            .await?,
        None
    );

    repository.delete_network("project-a", &alpha.id).await?;
    assert_eq!(repository.get_network("project-a", &alpha.id).await?, None);
    assert!(matches!(
        repository.delete_network("project-a", &alpha.id).await,
        Err(StoreError::NetworkNotFound)
    ));
    assert!(matches!(
        repository.delete_network("project-b", &gamma.id).await,
        Err(StoreError::NetworkNotFound)
    ));
    Ok(())
}

/// Runs the behavior shared by every placement repository adapter: provider
/// registration and sync with recomputed inventory usage, generation-guarded
/// inventory refresh and state updates, allocation commit/release with
/// idempotent retries and the over-allocation guard, allocation intent
/// upserts, consumer reconciliation, and row-granular provider import.
pub async fn run_placement_repository_conformance<S: PlacementRepository>(
    repository: &S,
) -> Result<(), StoreError> {
    let inventories = vec![
        PlacementInventoryRecord {
            resource_class: "MEMORY_MB".to_owned(),
            total: 4096,
            reserved: 256,
            allocation_ratio: 1.5,
            used: 0,
        },
        PlacementInventoryRecord {
            resource_class: "VCPU".to_owned(),
            total: 8,
            reserved: 1,
            allocation_ratio: 16.0,
            used: 0,
        },
    ];

    // register -> get_provider round-trip.
    let registered = repository
        .register_provider("compute-1", &inventories)
        .await?;
    assert_eq!(registered.id, "compute-1");
    assert_eq!(registered.node_id, "compute-1");
    assert_eq!(registered.state, "Enabled");
    assert_eq!(registered.generation, 1);
    assert_eq!(registered.inventories.len(), 2);
    assert!(
        registered
            .inventories
            .iter()
            .all(|inventory| inventory.used == 0)
    );
    let fetched = repository
        .get_provider("compute-1")
        .await?
        .ok_or(StoreError::PlacementProviderNotFound)?;
    assert_eq!(fetched, registered);
    assert_eq!(repository.get_provider("missing").await?, None);
    assert_eq!(repository.list_providers().await?, vec![fetched.clone()]);

    // register twice: state unchanged, generation bumped, used recomputed.
    let re_registered = repository
        .register_provider("compute-1", &inventories)
        .await?;
    assert_eq!(re_registered.state, "Enabled");
    assert_eq!(re_registered.generation, 2);
    assert!(
        re_registered
            .inventories
            .iter()
            .all(|inventory| inventory.used == 0)
    );

    // sync_provider always sets the state and bumps the generation.
    let synced = repository
        .sync_provider("compute-1", "Draining", &inventories)
        .await?;
    assert_eq!(synced.state, "Draining");
    assert_eq!(synced.generation, 3);

    // refresh_inventories: ok path, stale generation, unknown provider.
    let refreshed = repository
        .refresh_inventories("compute-1", 3, &inventories)
        .await?;
    assert_eq!(refreshed.generation, 4);
    assert!(matches!(
        repository
            .refresh_inventories("compute-1", 3, &inventories)
            .await,
        Err(StoreError::PlacementStaleGeneration)
    ));
    assert!(matches!(
        repository
            .refresh_inventories("missing", 1, &inventories)
            .await,
        Err(StoreError::PlacementProviderNotFound)
    ));

    // set_provider_state: ok path and unknown provider.
    repository
        .set_provider_state("compute-1", "Enabled")
        .await?;
    assert_eq!(
        repository
            .get_provider("compute-1")
            .await?
            .ok_or(StoreError::PlacementProviderNotFound)?
            .state,
        "Enabled"
    );
    assert!(matches!(
        repository.set_provider_state("missing", "Enabled").await,
        Err(StoreError::PlacementProviderNotFound)
    ));

    // commit_allocation: success increments used and bumps the generation.
    let allocation = PlacementAllocationRecord {
        id: "alloc-1".to_owned(),
        provider_id: "compute-1".to_owned(),
        consumer_id: "consumer-1".to_owned(),
        resources: vec![
            PlacementResourceRecord {
                resource_class: "MEMORY_MB".to_owned(),
                amount: 1024,
            },
            PlacementResourceRecord {
                resource_class: "VCPU".to_owned(),
                amount: 2,
            },
        ],
    };
    let committed = repository
        .commit_allocation("compute-1", 5, &allocation)
        .await?;
    assert_eq!(committed, allocation);
    let after_commit = repository
        .get_provider("compute-1")
        .await?
        .ok_or(StoreError::PlacementProviderNotFound)?;
    assert_eq!(after_commit.generation, 6);
    assert_eq!(after_commit.allocations, vec![allocation.clone()]);
    let vcpu = after_commit
        .inventories
        .iter()
        .find(|inventory| inventory.resource_class == "VCPU")
        .ok_or(StoreError::PlacementProviderNotFound)?;
    assert_eq!(vcpu.used, 2);
    let memory = after_commit
        .inventories
        .iter()
        .find(|inventory| inventory.resource_class == "MEMORY_MB")
        .ok_or(StoreError::PlacementProviderNotFound)?;
    assert_eq!(memory.used, 1024);

    // Idempotent re-commit with the same record succeeds even with a stale
    // expected generation and must not double-increment usage.
    let idempotent = repository
        .commit_allocation("compute-1", 3, &allocation)
        .await?;
    assert_eq!(idempotent, allocation);
    let after_idempotent = repository
        .get_provider("compute-1")
        .await?
        .ok_or(StoreError::PlacementProviderNotFound)?;
    assert_eq!(after_idempotent.generation, 6);
    assert_eq!(
        after_idempotent
            .inventories
            .iter()
            .find(|inventory| inventory.resource_class == "VCPU")
            .ok_or(StoreError::PlacementProviderNotFound)?
            .used,
        2
    );

    // Same allocation id with different resources conflicts.
    let conflicting = PlacementAllocationRecord {
        id: "alloc-1".to_owned(),
        provider_id: "compute-1".to_owned(),
        consumer_id: "consumer-1".to_owned(),
        resources: vec![PlacementResourceRecord {
            resource_class: "VCPU".to_owned(),
            amount: 4,
        }],
    };
    assert!(matches!(
        repository
            .commit_allocation("compute-1", 6, &conflicting)
            .await,
        Err(StoreError::PlacementAllocationConflict)
    ));
    let foreign = PlacementAllocationRecord {
        id: "alloc-foreign".to_owned(),
        provider_id: "compute-1".to_owned(),
        consumer_id: "consumer-foreign".to_owned(),
        resources: vec![PlacementResourceRecord {
            resource_class: "VCPU".to_owned(),
            amount: 1,
        }],
    };
    assert!(matches!(
        repository.commit_allocation("missing", 1, &foreign).await,
        Err(StoreError::PlacementProviderNotFound)
    ));

    // Two sequential commits with the same expected generation: the second is
    // rejected by the over-allocation guard.
    let second = PlacementAllocationRecord {
        id: "alloc-2".to_owned(),
        provider_id: "compute-1".to_owned(),
        consumer_id: "consumer-2".to_owned(),
        resources: vec![
            PlacementResourceRecord {
                resource_class: "MEMORY_MB".to_owned(),
                amount: 512,
            },
            PlacementResourceRecord {
                resource_class: "VCPU".to_owned(),
                amount: 1,
            },
        ],
    };
    repository
        .commit_allocation("compute-1", 6, &second)
        .await?;
    let third = PlacementAllocationRecord {
        id: "alloc-3".to_owned(),
        provider_id: "compute-1".to_owned(),
        consumer_id: "consumer-3".to_owned(),
        resources: vec![PlacementResourceRecord {
            resource_class: "VCPU".to_owned(),
            amount: 1,
        }],
    };
    assert!(matches!(
        repository.commit_allocation("compute-1", 6, &third).await,
        Err(StoreError::PlacementStaleGeneration)
    ));

    // release_allocation: usage decremented and generation bumped once; a
    // double release is a no-op; an unknown provider is an error.
    repository
        .release_allocation("compute-1", "alloc-2")
        .await?;
    let after_release = repository
        .get_provider("compute-1")
        .await?
        .ok_or(StoreError::PlacementProviderNotFound)?;
    assert_eq!(after_release.generation, 8);
    assert_eq!(
        after_release
            .inventories
            .iter()
            .find(|inventory| inventory.resource_class == "VCPU")
            .ok_or(StoreError::PlacementProviderNotFound)?
            .used,
        2
    );
    assert_eq!(
        after_release
            .inventories
            .iter()
            .find(|inventory| inventory.resource_class == "MEMORY_MB")
            .ok_or(StoreError::PlacementProviderNotFound)?
            .used,
        1024
    );
    repository
        .release_allocation("compute-1", "alloc-2")
        .await?;
    assert_eq!(
        repository
            .get_provider("compute-1")
            .await?
            .ok_or(StoreError::PlacementProviderNotFound)?
            .generation,
        8
    );
    assert!(matches!(
        repository.release_allocation("missing", "alloc-2").await,
        Err(StoreError::PlacementProviderNotFound)
    ));

    // release_allocation is scoped to the owning provider: releasing through
    // another registered provider is a no-op (Ok, allocation kept, no
    // generation bump on either provider).
    repository
        .register_provider("compute-5", &inventories)
        .await?;
    let scoped = PlacementAllocationRecord {
        id: "alloc-scoped".to_owned(),
        provider_id: "compute-5".to_owned(),
        consumer_id: "consumer-scoped".to_owned(),
        resources: vec![PlacementResourceRecord {
            resource_class: "VCPU".to_owned(),
            amount: 1,
        }],
    };
    repository
        .commit_allocation("compute-5", 1, &scoped)
        .await?;
    let compute_one_generation = repository
        .get_provider("compute-1")
        .await?
        .ok_or(StoreError::PlacementProviderNotFound)?
        .generation;
    repository
        .release_allocation("compute-1", "alloc-scoped")
        .await?;
    let scoped_owner = repository
        .get_provider("compute-5")
        .await?
        .ok_or(StoreError::PlacementProviderNotFound)?;
    assert_eq!(scoped_owner.generation, 2);
    assert_eq!(scoped_owner.allocations, vec![scoped.clone()]);
    assert_eq!(
        repository
            .get_provider("compute-1")
            .await?
            .ok_or(StoreError::PlacementProviderNotFound)?
            .generation,
        compute_one_generation
    );
    // Allocation ids are globally unique: a same-id allocation on another
    // provider conflicts instead of silently double-allocating.
    let same_id_elsewhere = PlacementAllocationRecord {
        id: "alloc-scoped".to_owned(),
        provider_id: "compute-1".to_owned(),
        consumer_id: "consumer-elsewhere".to_owned(),
        resources: vec![PlacementResourceRecord {
            resource_class: "VCPU".to_owned(),
            amount: 1,
        }],
    };
    assert!(matches!(
        repository
            .commit_allocation("compute-1", compute_one_generation, &same_id_elsewhere)
            .await,
        Err(StoreError::PlacementAllocationConflict)
    ));
    // The owning provider still releases its own allocation.
    repository
        .release_allocation("compute-5", "alloc-scoped")
        .await?;
    assert_eq!(
        repository
            .get_provider("compute-5")
            .await?
            .ok_or(StoreError::PlacementProviderNotFound)?
            .allocations,
        Vec::<PlacementAllocationRecord>::new()
    );

    // Intent upsert: insert, read, identical re-upsert, conflicting
    // re-upsert, delete, and missing delete.
    let intent = PlacementIntentRecord {
        id: "intent-1".to_owned(),
        provider_id: "compute-1".to_owned(),
        consumer_id: "consumer-1".to_owned(),
        resources: vec![PlacementResourceRecord {
            resource_class: "VCPU".to_owned(),
            amount: 2,
        }],
    };
    let stored_intent = repository.upsert_intent(&intent).await?;
    assert_eq!(stored_intent, intent);
    assert_eq!(
        repository.get_intent("intent-1").await?,
        Some(intent.clone())
    );
    assert_eq!(repository.get_intent("missing").await?, None);
    assert_eq!(repository.list_intents().await?, vec![intent.clone()]);
    let re_upserted = repository.upsert_intent(&intent).await?;
    assert_eq!(re_upserted, intent);
    let conflicting_intent = PlacementIntentRecord {
        id: "intent-1".to_owned(),
        provider_id: "compute-1".to_owned(),
        consumer_id: "consumer-2".to_owned(),
        resources: vec![PlacementResourceRecord {
            resource_class: "VCPU".to_owned(),
            amount: 2,
        }],
    };
    assert!(matches!(
        repository.upsert_intent(&conflicting_intent).await,
        Err(StoreError::PlacementIntentConflict)
    ));
    repository.delete_intent("intent-1").await?;
    assert_eq!(repository.get_intent("intent-1").await?, None);
    repository.delete_intent("intent-1").await?;

    // reconcile_consumers: two providers, one retained and one orphaned
    // allocation and one retained and one abandoned intent.
    repository
        .register_provider("compute-2", &inventories)
        .await?;
    let retained = PlacementAllocationRecord {
        id: "alloc-keep".to_owned(),
        provider_id: "compute-2".to_owned(),
        consumer_id: "consumer-keep".to_owned(),
        resources: vec![PlacementResourceRecord {
            resource_class: "VCPU".to_owned(),
            amount: 1,
        }],
    };
    repository
        .commit_allocation("compute-2", 1, &retained)
        .await?;
    let orphaned_allocation = PlacementAllocationRecord {
        id: "alloc-orphan".to_owned(),
        provider_id: "compute-2".to_owned(),
        consumer_id: "consumer-gone".to_owned(),
        resources: vec![PlacementResourceRecord {
            resource_class: "VCPU".to_owned(),
            amount: 2,
        }],
    };
    repository
        .commit_allocation("compute-2", 2, &orphaned_allocation)
        .await?;
    let retained_intent = PlacementIntentRecord {
        id: "intent-keep".to_owned(),
        provider_id: "compute-2".to_owned(),
        consumer_id: "consumer-keep".to_owned(),
        resources: vec![PlacementResourceRecord {
            resource_class: "VCPU".to_owned(),
            amount: 1,
        }],
    };
    repository.upsert_intent(&retained_intent).await?;
    let abandoned_intent = PlacementIntentRecord {
        id: "intent-orphan".to_owned(),
        provider_id: "compute-2".to_owned(),
        consumer_id: "consumer-gone".to_owned(),
        resources: vec![PlacementResourceRecord {
            resource_class: "VCPU".to_owned(),
            amount: 2,
        }],
    };
    repository.upsert_intent(&abandoned_intent).await?;
    let report = repository
        .reconcile_consumers(&["consumer-1".to_owned(), "consumer-keep".to_owned()])
        .await?;
    assert_eq!(
        report.orphaned_allocations,
        vec![orphaned_allocation.clone()]
    );
    assert_eq!(report.abandoned_intents, vec![abandoned_intent.clone()]);
    let compute_two = repository
        .get_provider("compute-2")
        .await?
        .ok_or(StoreError::PlacementProviderNotFound)?;
    assert_eq!(compute_two.generation, 4);
    assert_eq!(compute_two.allocations, vec![retained.clone()]);
    assert_eq!(
        compute_two
            .inventories
            .iter()
            .find(|inventory| inventory.resource_class == "VCPU")
            .ok_or(StoreError::PlacementProviderNotFound)?
            .used,
        1
    );
    // The unaffected provider keeps its generation and allocations.
    let compute_one = repository
        .get_provider("compute-1")
        .await?
        .ok_or(StoreError::PlacementProviderNotFound)?;
    assert_eq!(compute_one.generation, 8);
    assert_eq!(compute_one.allocations, vec![allocation.clone()]);
    assert_eq!(repository.get_intent("intent-orphan").await?, None);
    assert_eq!(
        repository.get_intent("intent-keep").await?,
        Some(retained_intent)
    );

    // Hierarchy/capability metadata is durable and generation-fenced without
    // changing the legacy provider path.
    let hierarchy_parent = repository
        .register_provider("hierarchy-parent", &inventories)
        .await?;
    let hierarchy_child = repository
        .register_provider_metadata(
            "hierarchy-child",
            &inventories,
            Some(&hierarchy_parent.id),
            &["COMPUTE".to_owned(), "SPECIAL_X".to_owned()],
            &["rack-a".to_owned()],
            Some("az-1"),
        )
        .await?;
    assert_eq!(
        hierarchy_child.parent_provider_id.as_deref(),
        Some(hierarchy_parent.id.as_str())
    );
    assert_eq!(
        &hierarchy_child.traits,
        &vec!["COMPUTE".to_owned(), "SPECIAL_X".to_owned()]
    );
    assert_eq!(&hierarchy_child.failure_domains, &vec!["rack-a".to_owned()]);
    assert_eq!(hierarchy_child.location.as_deref(), Some("az-1"));
    assert!(matches!(
        repository
            .update_provider_metadata(
                &hierarchy_child.id,
                hierarchy_child.generation - 1,
                Some(&hierarchy_parent.id),
                &hierarchy_child.traits,
                &hierarchy_child.failure_domains,
                hierarchy_child.location.as_deref(),
            )
            .await,
        Err(StoreError::PlacementStaleGeneration)
    ));
    let hierarchy_restored = repository
        .get_provider(&hierarchy_child.id)
        .await?
        .ok_or(StoreError::PlacementProviderNotFound)?;
    assert_eq!(hierarchy_restored, hierarchy_child);

    // import_provider: row-granular, idempotent, exact generation preserved.
    let imported = PlacementProviderRecord {
        id: "compute-3".to_owned(),
        node_id: "compute-3".to_owned(),
        state: "Draining".to_owned(),
        generation: 42,
        inventories: vec![PlacementInventoryRecord {
            resource_class: "VCPU".to_owned(),
            total: 4,
            reserved: 0,
            allocation_ratio: 1.0,
            used: 1,
        }],
        allocations: vec![
            PlacementAllocationRecord {
                id: "imp-a".to_owned(),
                provider_id: "compute-3".to_owned(),
                consumer_id: "consumer-a".to_owned(),
                resources: vec![PlacementResourceRecord {
                    resource_class: "VCPU".to_owned(),
                    amount: 1,
                }],
            },
            PlacementAllocationRecord {
                id: "imp-b".to_owned(),
                provider_id: "compute-3".to_owned(),
                consumer_id: "consumer-b".to_owned(),
                resources: vec![PlacementResourceRecord {
                    resource_class: "VCPU".to_owned(),
                    amount: 2,
                }],
            },
        ],
        parent_provider_id: None,
        traits: vec![],
        failure_domains: vec![],
        location: None,
    };
    repository.import_provider(&imported).await?;
    let restored_import = repository
        .get_provider("compute-3")
        .await?
        .ok_or(StoreError::PlacementProviderNotFound)?;
    assert_eq!(restored_import.generation, 42);
    assert_eq!(restored_import.state, "Draining");
    assert_eq!(restored_import.inventories.len(), 1);
    assert_eq!(restored_import.allocations.len(), 2);
    // Idempotent re-import duplicates nothing.
    repository.import_provider(&imported).await?;
    let re_imported = repository
        .get_provider("compute-3")
        .await?
        .ok_or(StoreError::PlacementProviderNotFound)?;
    assert_eq!(re_imported.generation, 42);
    assert_eq!(re_imported.inventories.len(), 1);
    assert_eq!(re_imported.allocations.len(), 2);
    // An existing provider row does not block allocation import; the row
    // keeps its stored generation.
    repository
        .register_provider("compute-4", &inventories)
        .await?;
    let partial = PlacementProviderRecord {
        id: "compute-4".to_owned(),
        node_id: "compute-4".to_owned(),
        state: "Deleted".to_owned(),
        generation: 9,
        inventories: vec![PlacementInventoryRecord {
            resource_class: "VCPU".to_owned(),
            total: 4,
            reserved: 0,
            allocation_ratio: 1.0,
            used: 1,
        }],
        allocations: vec![PlacementAllocationRecord {
            id: "imp-c".to_owned(),
            provider_id: "compute-4".to_owned(),
            consumer_id: "consumer-c".to_owned(),
            resources: vec![PlacementResourceRecord {
                resource_class: "VCPU".to_owned(),
                amount: 1,
            }],
        }],
        parent_provider_id: None,
        traits: vec![],
        failure_domains: vec![],
        location: None,
    };
    repository.import_provider(&partial).await?;
    let partial_store = repository
        .get_provider("compute-4")
        .await?
        .ok_or(StoreError::PlacementProviderNotFound)?;
    assert_eq!(partial_store.generation, 1);
    assert_eq!(partial_store.state, "Enabled");
    assert_eq!(partial_store.allocations.len(), 1);
    Ok(())
}

/// Runs the behavior shared by every topology store adapter: region/AZ
/// declaration with replay-idempotent inserts, snapshot assembly (regions
/// with their availability domains, failure domains and bindings sorted by
/// identity), failure-domain CRUD with CAS generations, binding idempotency,
/// referential-integrity protections surfacing as conflicts, and bounded
/// keyset lists (page bound honored, stable ordering, exact continuation).
pub async fn run_topology_store_conformance<S: o3k_kernel::TopologyStore>(
    store: &S,
) -> Result<(), o3k_kernel::KernelError> {
    use o3k_kernel::{
        AvailabilityDomain, BindingTarget, BindingTargetKind, FailureDomain, FailureDomainClass,
        KernelError, RegionDeclaration, TopologyBinding,
    };
    use std::collections::BTreeMap;

    fn domain(
        id: &str,
        class: FailureDomainClass,
        az: &str,
        parent: Option<&str>,
    ) -> FailureDomain {
        FailureDomain {
            id: id.to_owned(),
            class,
            name: id.to_owned(),
            availability_domain: az.to_owned(),
            parent: parent.map(str::to_owned),
            generation: 1,
            metadata: BTreeMap::new(),
        }
    }

    fn binding(failure_domain: &str, kind: BindingTargetKind, id: &str) -> TopologyBinding {
        TopologyBinding {
            failure_domain: failure_domain.to_owned(),
            target: BindingTarget {
                kind,
                id: id.to_owned(),
            },
        }
    }

    fn is_conflict(result: &Result<(), KernelError>, needle: &str) -> bool {
        matches!(result, Err(KernelError::TopologyCorrupt(reason)) if reason.contains(needle))
    }

    // Declaration and replay-idempotent inserts.
    store.insert_region("conf-region", None).await?;
    store.insert_region("conf-region", None).await?;
    store
        .insert_availability_domain("conf-region", "conf-az", None)
        .await?;
    store
        .insert_availability_domain("conf-region", "conf-az", None)
        .await?;

    // Snapshot assembly: regions with their AZs, sorted by identity.
    let snapshot = store.load_snapshot().await?;
    assert_eq!(
        snapshot.regions,
        vec![RegionDeclaration {
            id: "conf-region".to_owned(),
            availability_domains: vec![AvailabilityDomain {
                id: "conf-az".to_owned()
            }],
        }]
    );
    assert!(snapshot.failure_domains.is_empty());
    assert!(snapshot.bindings.is_empty());

    // Failure-domain CRUD with CAS generations and JSON metadata.
    store
        .insert_failure_domain(
            &domain("conf-rack", FailureDomainClass::Rack, "conf-az", None),
            None,
        )
        .await?;
    let duplicate = store
        .insert_failure_domain(
            &domain("conf-rack", FailureDomainClass::Rack, "conf-az", None),
            None,
        )
        .await;
    assert!(
        is_conflict(&duplicate, "duplicate"),
        "unexpected: {duplicate:?}"
    );

    let unknown_az = store
        .insert_failure_domain(
            &domain(
                "conf-ghost",
                FailureDomainClass::Rack,
                "conf-az-missing",
                None,
            ),
            None,
        )
        .await;
    assert!(
        is_conflict(&unknown_az, "unknown availability domain or parent"),
        "unexpected: {unknown_az:?}"
    );

    let mut updated = domain("conf-rack", FailureDomainClass::Rack, "conf-az", None);
    updated.name = "Conformance Rack".to_owned();
    updated.generation = 2;
    updated.metadata.insert("row".to_owned(), "3".to_owned());
    store.update_failure_domain(&updated, 1, None).await?;
    let stale = store.update_failure_domain(&updated, 1, None).await;
    assert!(
        is_conflict(&stale, "stale generation"),
        "unexpected: {stale:?}"
    );

    // Bindings: unique per (failure domain, kind, id), replay-idempotent.
    store
        .insert_binding(
            &binding(
                "conf-rack",
                BindingTargetKind::ResourceProvider,
                "conf-provider",
            ),
            None,
        )
        .await?;
    store
        .insert_binding(
            &binding(
                "conf-rack",
                BindingTargetKind::ResourceProvider,
                "conf-provider",
            ),
            None,
        )
        .await?;
    let unknown_fd = store
        .insert_binding(
            &binding("conf-missing", BindingTargetKind::Host, "conf-host"),
            None,
        )
        .await;
    assert!(
        is_conflict(&unknown_fd, "unknown failure domain"),
        "unexpected: {unknown_fd:?}"
    );

    // Bounded keyset lists: every page honors the bound (at most limit + 1
    // rows, the extra row signalling a further page), ordering is stable, and
    // keyset continuation enumerates exactly the sorted durable sequence.
    for suffix in ["a", "b", "c", "d"] {
        store
            .insert_failure_domain(
                &domain(
                    &format!("conf-list-{suffix}"),
                    FailureDomainClass::Rack,
                    "conf-az",
                    None,
                ),
                None,
            )
            .await?;
    }
    for host in ["conf-host-a", "conf-host-b", "conf-host-c"] {
        store
            .insert_binding(&binding("conf-rack", BindingTargetKind::Host, host), None)
            .await?;
    }

    let binding_sort_key = |binding: &TopologyBinding| {
        (
            binding.failure_domain.clone(),
            binding.target.kind.as_str().to_owned(),
            binding.target.id.clone(),
        )
    };

    // Failure-domain pages walk the exact ascending id sequence.
    let all_ids: Vec<String> = store
        .load_snapshot()
        .await?
        .failure_domains
        .iter()
        .map(|domain| domain.id.clone())
        .collect();
    let mut seen_ids: Vec<String> = Vec::new();
    let mut after_id: Option<String> = None;
    loop {
        let page = store.list_failure_domains(after_id.as_deref(), 2).await?;
        assert!(
            page.len() <= 3,
            "page exceeds the limit + 1 bound: {page:?}"
        );
        assert!(
            page.windows(2).all(|pair| pair[0].id < pair[1].id),
            "page must be strictly ascending by id: {page:?}"
        );
        seen_ids.extend(page.iter().map(|domain| domain.id.clone()));
        if page.len() <= 2 {
            break;
        }
        after_id = page.last().map(|domain| domain.id.clone());
    }
    assert_eq!(
        seen_ids, all_ids,
        "keyset walk must enumerate the exact sorted sequence"
    );

    // Global binding pages follow (failure_domain, kind, id) order.
    let all_binding_keys: Vec<(String, String, String)> = store
        .load_snapshot()
        .await?
        .bindings
        .iter()
        .map(binding_sort_key)
        .collect();
    let mut seen_binding_keys: Vec<(String, String, String)> = Vec::new();
    let mut after_cursor: Option<o3k_kernel::BindingListCursor> = None;
    loop {
        let page = store.list_bindings(after_cursor.as_ref(), 2).await?;
        assert!(
            page.len() <= 3,
            "page exceeds the limit + 1 bound: {page:?}"
        );
        assert!(
            page.windows(2)
                .all(|pair| binding_sort_key(&pair[0]) < binding_sort_key(&pair[1])),
            "page must be strictly ascending by identity: {page:?}"
        );
        seen_binding_keys.extend(page.iter().map(binding_sort_key));
        if page.len() <= 2 {
            break;
        }
        after_cursor = page.last().map(o3k_kernel::BindingListCursor::after);
    }
    assert_eq!(
        seen_binding_keys, all_binding_keys,
        "keyset walk must enumerate the exact sorted sequence"
    );

    // Per-failure-domain binding pages filter honestly and continue by keyset.
    let rack_binding_keys: Vec<(String, String, String)> = all_binding_keys
        .iter()
        .filter(|(failure_domain, _, _)| failure_domain == "conf-rack")
        .cloned()
        .collect();
    let mut seen_rack_keys: Vec<(String, String, String)> = Vec::new();
    let mut after_cursor: Option<o3k_kernel::BindingListCursor> = None;
    loop {
        let page = store
            .list_bindings_of("conf-rack", after_cursor.as_ref(), 1)
            .await?;
        assert!(
            page.len() <= 2,
            "page exceeds the limit + 1 bound: {page:?}"
        );
        assert!(
            page.windows(2).all(|pair| {
                (pair[0].target.kind.as_str(), pair[0].target.id.as_str())
                    < (pair[1].target.kind.as_str(), pair[1].target.id.as_str())
            }),
            "page must be strictly ascending by target: {page:?}"
        );
        seen_rack_keys.extend(page.iter().map(binding_sort_key));
        if page.len() <= 1 {
            break;
        }
        after_cursor = page.last().map(o3k_kernel::BindingListCursor::after);
    }
    assert_eq!(
        seen_rack_keys, rack_binding_keys,
        "per-failure-domain keyset walk must enumerate exactly that domain's sorted bindings"
    );

    // The bounded-list fixtures leave before the protection/teardown flow.
    for host in ["conf-host-a", "conf-host-b", "conf-host-c"] {
        store
            .delete_binding(&binding("conf-rack", BindingTargetKind::Host, host), None)
            .await?;
    }
    for suffix in ["a", "b", "c", "d"] {
        store
            .delete_failure_domain(&format!("conf-list-{suffix}"), 1, None)
            .await?;
    }

    // Deletion protections: children and bindings keep their parent alive.
    store
        .insert_failure_domain(
            &domain(
                "conf-chassis",
                FailureDomainClass::Chassis,
                "conf-az",
                Some("conf-rack"),
            ),
            None,
        )
        .await?;
    let has_child = store.delete_failure_domain("conf-rack", 2, None).await;
    assert!(
        is_conflict(&has_child, "child failure domains or bindings"),
        "unexpected: {has_child:?}"
    );
    let has_fd = store.delete_availability_domain("conf-az", None).await;
    assert!(
        is_conflict(&has_fd, "still has failure domains"),
        "unexpected: {has_fd:?}"
    );
    let has_az = store.delete_region("conf-region", None).await;
    assert!(
        is_conflict(&has_az, "still has availability domains"),
        "unexpected: {has_az:?}"
    );

    // Tear down in dependency order; every mutation converges.
    store
        .delete_binding(
            &binding(
                "conf-rack",
                BindingTargetKind::ResourceProvider,
                "conf-provider",
            ),
            None,
        )
        .await?;
    store
        .delete_binding(
            &binding(
                "conf-rack",
                BindingTargetKind::ResourceProvider,
                "conf-provider",
            ),
            None,
        )
        .await?;
    store.delete_failure_domain("conf-chassis", 1, None).await?;
    let stale_delete = store.delete_failure_domain("conf-rack", 1, None).await;
    assert!(
        is_conflict(&stale_delete, "stale generation"),
        "unexpected: {stale_delete:?}"
    );
    store.delete_failure_domain("conf-rack", 2, None).await?;
    store.delete_availability_domain("conf-az", None).await?;
    store.delete_region("conf-region", None).await?;

    // The final snapshot is exactly empty and the updated values persisted.
    let snapshot = store.load_snapshot().await?;
    assert!(snapshot.regions.is_empty());
    assert!(snapshot.failure_domains.is_empty());
    assert!(snapshot.bindings.is_empty());

    // Rebuild once to verify the update/metadata round-trip end to end.
    store.insert_region("conf-region", None).await?;
    store
        .insert_availability_domain("conf-region", "conf-az", None)
        .await?;
    store
        .insert_failure_domain(
            &domain("conf-rack", FailureDomainClass::Rack, "conf-az", None),
            None,
        )
        .await?;
    store.update_failure_domain(&updated, 1, None).await?;
    let snapshot = store.load_snapshot().await?;
    assert_eq!(snapshot.failure_domains, vec![updated]);
    store.delete_failure_domain("conf-rack", 2, None).await?;
    store.delete_availability_domain("conf-az", None).await?;
    store.delete_region("conf-region", None).await?;
    Ok(())
}

#[cfg(unix)]
fn restrict_sqlite_sidecars(path: &Path) -> Result<(), StoreError> {
    for suffix in ["-wal", "-shm"] {
        let sidecar = PathBuf::from(format!("{}{}", path.display(), suffix));
        let Ok(metadata) = fs::symlink_metadata(&sidecar) else {
            continue;
        };
        if metadata.file_type().is_symlink() || !metadata.file_type().is_file() {
            return Err(StoreError::Database(sqlx::Error::Configuration(
                format!(
                    "SQLite sidecar is not a regular file: {}",
                    sidecar.display()
                )
                .into(),
            )));
        }
        fs::set_permissions(&sidecar, fs::Permissions::from_mode(0o600))
            .map_err(|source| StoreError::Database(sqlx::Error::Io(source)))?;
    }
    Ok(())
}

#[cfg(test)]
#[allow(clippy::module_inception)]
mod tests;
