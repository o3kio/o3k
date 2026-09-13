use async_trait::async_trait;
use o3k_kernel::AuditQuery;
use uuid::Uuid;

use crate::domain::error::StoreError;
use crate::domain::records::{
    AuditEventRecord, CanonicalAddressPoolRecord, CanonicalAddressRealmRecord,
    CanonicalEndpointRecord, CanonicalL3GatewayAttachmentRecord, CanonicalL3GatewayRecord,
    CanonicalNetworkPolicyRecord, CanonicalNetworkRecord, CanonicalRealmBindingRecord,
    FederatedBindingRecord, ImageMetadataRecord, KeypairRecord, KeystoneDomainRecord,
    KeystoneEndpointRecord, KeystoneProjectRecord, KeystoneRegionRecord,
    KeystoneRoleAssignmentRecord, KeystoneRoleRecord, KeystoneServiceRecord, KeystoneUserRecord,
    NetworkAddressAllocationRecord, NetworkIntentRecord, NetworkRecord, OperatorAssignmentRecord,
    PlacementAllocationRecord, PlacementCapacitySummary, PlacementIntentRecord,
    PlacementInventoryRecord, PlacementProviderRecord, PlacementProviderStateRecord,
    PlacementReconcileRecord, PortRecord, ResourceRecord, SecurityGroupBindingRecord,
    SecurityGroupRecord, SecurityGroupRuleRecord, SubnetRecord, VolumeAttachmentRecord,
};
use crate::port::durable::DurableStore;
use crate::quota::QuotaRepository;

/// Durable, scope-aware audit persistence. Implementations must enforce the
/// page bound in SQL and never materialize the complete history.
#[async_trait]
pub trait AuditRepository: Send + Sync {
    async fn insert_audit_event(&self, event: &AuditEventRecord) -> Result<(), StoreError>;
    async fn get_audit_event(
        &self,
        scope: &str,
        event_id: &str,
    ) -> Result<AuditEventRecord, StoreError>;
    async fn list_audit_events_page(
        &self,
        scope: &str,
        after_event_id: Option<&str>,
        limit: usize,
    ) -> Result<crate::RepositoryPage<AuditEventRecord>, StoreError>;
    /// Execute the complete canonical AuditQuery at the concrete persistence
    /// boundary. Implementations must push every supported predicate into SQL.
    async fn list_audit_events_page_query(
        &self,
        query: &AuditQuery,
    ) -> Result<crate::RepositoryPage<AuditEventRecord>, StoreError>;
    async fn prune_audit_events_before(
        &self,
        cutoff: &str,
        limit: usize,
    ) -> Result<u64, StoreError>;
}

/// Durable Keystone-compatible identity records used by the identity
/// application service: deterministic bootstrap seeding (upserts) and the
/// one-time snapshot load that feeds token issuance and the catalog.
///
/// This is a narrow port around the identity use cases, not a generic
/// persistence surface. Application code depends on this trait (or a broader
/// combined port) instead of on the concrete `SqliteStore` adapter.
#[async_trait]
pub trait IdentityRepository: Send + Sync {
    async fn insert_keystone_domain(&self, domain: &KeystoneDomainRecord)
    -> Result<(), StoreError>;
    async fn list_keystone_domains(&self) -> Result<Vec<KeystoneDomainRecord>, StoreError>;
    async fn insert_keystone_project(
        &self,
        project: &KeystoneProjectRecord,
    ) -> Result<(), StoreError>;
    async fn list_keystone_projects(&self) -> Result<Vec<KeystoneProjectRecord>, StoreError>;
    async fn insert_keystone_user(&self, user: &KeystoneUserRecord) -> Result<(), StoreError>;
    async fn list_keystone_users(&self) -> Result<Vec<KeystoneUserRecord>, StoreError>;
    async fn insert_federated_binding(
        &self,
        binding: &FederatedBindingRecord,
    ) -> Result<(), StoreError>;
    async fn find_federated_binding(
        &self,
        trusted_issuer_id: &str,
        subject: &str,
    ) -> Result<Option<FederatedBindingRecord>, StoreError>;
    async fn list_federated_bindings(&self) -> Result<Vec<FederatedBindingRecord>, StoreError>;
    async fn set_federated_binding_enabled(
        &self,
        id: &str,
        enabled: bool,
    ) -> Result<(), StoreError>;
    async fn insert_operator_assignment(
        &self,
        assignment: &OperatorAssignmentRecord,
    ) -> Result<(), StoreError>;
    async fn list_operator_assignments(&self) -> Result<Vec<OperatorAssignmentRecord>, StoreError>;
    async fn set_operator_assignment_enabled(
        &self,
        id: &str,
        enabled: bool,
    ) -> Result<(), StoreError>;
    async fn insert_keystone_role(&self, role: &KeystoneRoleRecord) -> Result<(), StoreError>;
    async fn list_keystone_roles(&self) -> Result<Vec<KeystoneRoleRecord>, StoreError>;
    async fn insert_keystone_role_assignment(
        &self,
        assignment: &KeystoneRoleAssignmentRecord,
    ) -> Result<(), StoreError>;
    async fn list_keystone_role_assignments(
        &self,
    ) -> Result<Vec<KeystoneRoleAssignmentRecord>, StoreError>;
    async fn insert_keystone_service(
        &self,
        service: &KeystoneServiceRecord,
    ) -> Result<(), StoreError>;
    async fn list_keystone_services(&self) -> Result<Vec<KeystoneServiceRecord>, StoreError>;
    async fn insert_keystone_endpoint(
        &self,
        endpoint: &KeystoneEndpointRecord,
    ) -> Result<(), StoreError>;
    async fn list_keystone_endpoints(&self) -> Result<Vec<KeystoneEndpointRecord>, StoreError>;
    async fn insert_keystone_region(&self, region: &KeystoneRegionRecord)
    -> Result<(), StoreError>;
    async fn list_keystone_regions(&self) -> Result<Vec<KeystoneRegionRecord>, StoreError>;
}

/// Durable keypair records owned by the compute service. The trait keeps the
/// scoped uniqueness, attach, and delete semantics available to application
/// code without naming the concrete adapter.
#[async_trait]
pub trait KeypairRepository: Send + Sync {
    async fn insert_keypair(&self, keypair: &KeypairRecord) -> Result<(), StoreError>;
    async fn list_keypairs(
        &self,
        user_id: &str,
        project_id: &str,
    ) -> Result<Vec<KeypairRecord>, StoreError>;
    async fn get_keypair(
        &self,
        user_id: &str,
        project_id: &str,
        name: &str,
    ) -> Result<KeypairRecord, StoreError>;
    async fn delete_keypair(
        &self,
        user_id: &str,
        project_id: &str,
        name: &str,
    ) -> Result<(), StoreError>;
    async fn attach_server_keypair(
        &self,
        server_id: Uuid,
        keypair_id: Uuid,
    ) -> Result<(), StoreError>;
    async fn detach_server_keypair(&self, server_id: Uuid) -> Result<(), StoreError>;
    async fn get_server_keypair_name(&self, server_id: Uuid) -> Result<Option<String>, StoreError>;
}

/// Durable Nova volume-attachment records owned by the compute attachment
/// orchestrator. Phase and outcome updates carry the frozen Cinder attachment
/// lifecycle; the port exposes the exact transitions the orchestrator uses.
#[async_trait]
pub trait VolumeAttachmentRepository: Send + Sync {
    async fn insert_volume_attachment(
        &self,
        record: &VolumeAttachmentRecord,
    ) -> Result<(), StoreError>;
    async fn update_volume_attachment_phase(
        &self,
        id: Uuid,
        status: &str,
        error: Option<&str>,
    ) -> Result<VolumeAttachmentRecord, StoreError>;
    #[allow(clippy::too_many_arguments)]
    async fn update_volume_attachment_outcome(
        &self,
        id: Uuid,
        status: &str,
        cinder_attachment_id: Option<&str>,
        connector_host: Option<&str>,
        connector_ip: Option<&str>,
        connector_initiator: Option<&str>,
        driver_volume_type: Option<&str>,
        target_iqn: Option<&str>,
        target_portal: Option<&str>,
        target_lun: Option<u32>,
        connection_info_digest: Option<&str>,
        device: Option<&str>,
    ) -> Result<VolumeAttachmentRecord, StoreError>;
    async fn get_volume_attachment_by_id(
        &self,
        id: Uuid,
    ) -> Result<Option<VolumeAttachmentRecord>, StoreError>;
    async fn get_volume_attachment_by_volume(
        &self,
        volume_id: Uuid,
    ) -> Result<Option<VolumeAttachmentRecord>, StoreError>;

    async fn get_volume_attachment_by_volume_for_server(
        &self,
        volume_id: Uuid,
        server_id: Uuid,
    ) -> Result<Option<VolumeAttachmentRecord>, StoreError>;
    async fn get_volume_attachment_by_idempotency(
        &self,
        idempotency_key: &str,
    ) -> Result<Option<VolumeAttachmentRecord>, StoreError>;
    async fn list_volume_attachments_by_status(
        &self,
        terminal: &[&str],
    ) -> Result<Vec<VolumeAttachmentRecord>, StoreError>;
    async fn list_volume_attachments(
        &self,
        server_id: Uuid,
    ) -> Result<Vec<VolumeAttachmentRecord>, StoreError>;
    async fn get_volume_attachment(
        &self,
        server_id: Uuid,
        attachment_id: Uuid,
    ) -> Result<Option<VolumeAttachmentRecord>, StoreError>;
    async fn delete_volume_attachment(
        &self,
        server_id: Uuid,
        attachment_id: Uuid,
    ) -> Result<(), StoreError>;
}

/// Durable Glance-compatible image metadata owned by the image service:
/// project ownership, format/visibility, and the size/checksum sealed by the
/// queued -> active transition. The bounded artifact bytes stay in the
/// filesystem content directory; this port owns only the metadata.
///
/// This is a narrow port around the image use cases, not a generic
/// persistence surface. Application code depends on this trait instead of on
/// the concrete `SqliteStore` adapter.
#[async_trait]
pub trait ImageRepository: Send + Sync + QuotaRepository {
    async fn insert_image(&self, image: &ImageMetadataRecord) -> Result<(), StoreError>;
    async fn list_images(&self, project_id: &str) -> Result<Vec<ImageMetadataRecord>, StoreError>;
    async fn get_image(
        &self,
        project_id: &str,
        id: &Uuid,
    ) -> Result<Option<ImageMetadataRecord>, StoreError>;
    async fn activate_image(
        &self,
        project_id: &str,
        id: &Uuid,
        size: u64,
        checksum: &str,
    ) -> Result<ImageMetadataRecord, StoreError>;
    async fn delete_image(&self, project_id: &str, id: &Uuid) -> Result<(), StoreError>;
}

/// Durable Neutron-compatible network/subnet/port metadata owned by the
/// network service: project ownership, addressing and allocation ranges, and
/// port binding state. This port owns only the metadata; network datapath
/// behavior stays outside the store.
///
/// This is a narrow port around the network use cases, not a generic
/// persistence surface. Application code depends on this trait instead of on
/// the concrete `SqliteStore` adapter.
#[async_trait]
pub trait NetworkRepository:
    Send + Sync + DurableStore + QuotaRepository + crate::CanonicalPolicyRepository
{
    /// Resolves canonical ownership for authorization without exposing an
    /// unscoped public read API. The network service uses this only to build
    /// an authorization target before applying project non-disclosure.
    async fn get_canonical_owner(
        &self,
        resource_name: &str,
        id: &Uuid,
    ) -> Result<Option<String>, StoreError>;
    async fn insert_canonical_network(
        &self,
        network: &CanonicalNetworkRecord,
    ) -> Result<(), StoreError>;
    async fn get_canonical_network(
        &self,
        project_id: &str,
        id: &Uuid,
    ) -> Result<Option<CanonicalNetworkRecord>, StoreError>;
    async fn list_canonical_networks(
        &self,
        project_id: &str,
    ) -> Result<Vec<CanonicalNetworkRecord>, StoreError>;
    async fn update_canonical_network(
        &self,
        project_id: &str,
        id: &Uuid,
        expected_generation: u64,
        name: &str,
        admin_state_up: bool,
    ) -> Result<CanonicalNetworkRecord, StoreError>;
    async fn insert_canonical_l3_gateway(
        &self,
        gateway: &CanonicalL3GatewayRecord,
    ) -> Result<(), StoreError>;
    async fn get_canonical_l3_gateway(
        &self,
        project_id: &str,
        id: &Uuid,
    ) -> Result<Option<CanonicalL3GatewayRecord>, StoreError>;
    async fn list_canonical_l3_gateways(
        &self,
        project_id: &str,
    ) -> Result<Vec<CanonicalL3GatewayRecord>, StoreError>;
    /// Transitional-resource inventory used by startup recovery.
    async fn list_canonical_l3_gateways_by_state(
        &self,
        state: &str,
    ) -> Result<Vec<CanonicalL3GatewayRecord>, StoreError>;
    async fn update_canonical_l3_gateway(
        &self,
        project_id: &str,
        id: &Uuid,
        expected_generation: u64,
        name: &str,
        external_realm_id: Option<Uuid>,
        enable_snat: bool,
    ) -> Result<CanonicalL3GatewayRecord, StoreError>;
    async fn begin_canonical_l3_gateway_deletion(
        &self,
        project_id: &str,
        id: &Uuid,
        expected_generation: u64,
    ) -> Result<CanonicalL3GatewayRecord, StoreError>;
    async fn finalize_canonical_l3_gateway_deletion(
        &self,
        project_id: &str,
        id: &Uuid,
        expected_generation: u64,
    ) -> Result<(), StoreError>;
    async fn insert_canonical_l3_gateway_attachment(
        &self,
        attachment: &CanonicalL3GatewayAttachmentRecord,
    ) -> Result<(), StoreError>;
    async fn get_canonical_l3_gateway_attachment(
        &self,
        project_id: &str,
        id: &Uuid,
    ) -> Result<Option<CanonicalL3GatewayAttachmentRecord>, StoreError>;
    async fn list_canonical_l3_gateway_attachments(
        &self,
        project_id: &str,
        gateway_id: &Uuid,
    ) -> Result<Vec<CanonicalL3GatewayAttachmentRecord>, StoreError>;
    async fn list_canonical_l3_gateway_attachments_by_state(
        &self,
        state: &str,
    ) -> Result<Vec<CanonicalL3GatewayAttachmentRecord>, StoreError>;
    async fn list_canonical_realm_l3_gateway_attachments(
        &self,
        project_id: &str,
        realm_id: &Uuid,
    ) -> Result<Vec<CanonicalL3GatewayAttachmentRecord>, StoreError>;
    async fn begin_canonical_l3_gateway_attachment_deletion(
        &self,
        project_id: &str,
        id: &Uuid,
        expected_generation: u64,
    ) -> Result<CanonicalL3GatewayAttachmentRecord, StoreError>;
    async fn finalize_canonical_l3_gateway_attachment_deletion(
        &self,
        project_id: &str,
        id: &Uuid,
        expected_generation: u64,
    ) -> Result<(), StoreError>;
    async fn insert_canonical_realm(
        &self,
        realm: &CanonicalAddressRealmRecord,
    ) -> Result<(), StoreError>;
    async fn get_canonical_realm(
        &self,
        project_id: &str,
        id: &Uuid,
    ) -> Result<Option<CanonicalAddressRealmRecord>, StoreError>;
    async fn list_canonical_realms(
        &self,
        project_id: &str,
        network_id: &Uuid,
    ) -> Result<Vec<CanonicalAddressRealmRecord>, StoreError>;
    async fn insert_canonical_pool(
        &self,
        pool: &CanonicalAddressPoolRecord,
    ) -> Result<(), StoreError>;
    async fn insert_subnet_bundle(
        &self,
        realm: &CanonicalAddressRealmRecord,
        pool: &CanonicalAddressPoolRecord,
        subnet: &SubnetRecord,
    ) -> Result<(), StoreError>;
    async fn list_canonical_pools(
        &self,
        project_id: &str,
        realm_id: &Uuid,
    ) -> Result<Vec<CanonicalAddressPoolRecord>, StoreError>;
    async fn delete_canonical_pool(
        &self,
        project_id: &str,
        pool_id: &Uuid,
    ) -> Result<(), StoreError>;
    async fn update_canonical_pool(
        &self,
        project_id: &str,
        pool_id: &Uuid,
        expected_generation: u64,
        gateway: Option<std::net::Ipv4Addr>,
    ) -> Result<CanonicalAddressPoolRecord, StoreError>;
    async fn insert_canonical_endpoint(
        &self,
        endpoint: &CanonicalEndpointRecord,
    ) -> Result<(), StoreError>;
    async fn insert_canonical_endpoint_and_port(
        &self,
        endpoint: &CanonicalEndpointRecord,
        port: &PortRecord,
    ) -> Result<(), StoreError>;
    async fn list_canonical_endpoints(
        &self,
        project_id: &str,
        realm_id: &Uuid,
    ) -> Result<Vec<CanonicalEndpointRecord>, StoreError>;
    async fn get_canonical_endpoint(
        &self,
        project_id: &str,
        endpoint_id: &Uuid,
    ) -> Result<Option<CanonicalEndpointRecord>, StoreError>;
    async fn delete_canonical_endpoint(
        &self,
        project_id: &str,
        endpoint_id: &Uuid,
    ) -> Result<(), StoreError>;
    async fn delete_canonical_endpoint_and_port(
        &self,
        project_id: &str,
        endpoint_id: &Uuid,
    ) -> Result<(), StoreError>;
    async fn upsert_canonical_policy(
        &self,
        policy: &CanonicalNetworkPolicyRecord,
    ) -> Result<(), StoreError>;
    async fn list_canonical_policies(
        &self,
        project_id: &str,
        network_id: &Uuid,
    ) -> Result<Vec<CanonicalNetworkPolicyRecord>, StoreError>;
    async fn delete_canonical_policy(
        &self,
        project_id: &str,
        policy_id: &Uuid,
    ) -> Result<(), StoreError>;
    async fn begin_canonical_realm_deletion(
        &self,
        project_id: &str,
        realm_id: &Uuid,
        expected_generation: u64,
    ) -> Result<CanonicalAddressRealmRecord, StoreError>;
    async fn finalize_canonical_realm_deletion(
        &self,
        project_id: &str,
        realm_id: &Uuid,
        expected_generation: u64,
    ) -> Result<(), StoreError>;
    async fn list_canonical_realm_bindings(
        &self,
        realm_id: &Uuid,
    ) -> Result<Vec<CanonicalRealmBindingRecord>, StoreError>;
    async fn delete_canonical_realm_binding(
        &self,
        binding: &CanonicalRealmBindingRecord,
        expected_realm_generation: u64,
    ) -> Result<(), StoreError>;
    async fn delete_canonical_realm(
        &self,
        project_id: &str,
        realm_id: &Uuid,
    ) -> Result<(), StoreError>;
    async fn delete_canonical_network(
        &self,
        project_id: &str,
        network_id: &Uuid,
    ) -> Result<(), StoreError>;
    async fn backfill_canonical_network_state(&self) -> Result<(), StoreError>;
    async fn allocate_network_address(
        &self,
        realm_id: &Uuid,
        project_id: &str,
        endpoint_id: &Uuid,
        operation_id: &str,
        prefix: &str,
    ) -> Result<NetworkAddressAllocationRecord, StoreError>;
    async fn release_network_address(
        &self,
        project_id: &str,
        endpoint_id: &Uuid,
    ) -> Result<(), StoreError>;
    async fn insert_network_intent(&self, intent: &NetworkIntentRecord) -> Result<(), StoreError>;
    async fn list_network_intents(
        &self,
        project_id: &str,
    ) -> Result<Vec<NetworkIntentRecord>, StoreError>;
    async fn get_network_intent(
        &self,
        project_id: &str,
        id: &Uuid,
    ) -> Result<Option<NetworkIntentRecord>, StoreError>;
    async fn update_network_intent(
        &self,
        project_id: &str,
        id: &Uuid,
        expected_generation: u64,
        payload: &str,
        plan_fingerprint_sha256: Option<&str>,
        status: &str,
    ) -> Result<NetworkIntentRecord, StoreError>;
    async fn insert_network(&self, network: &NetworkRecord) -> Result<(), StoreError>;
    async fn list_networks(&self, project_id: &str) -> Result<Vec<NetworkRecord>, StoreError>;
    async fn get_network(
        &self,
        project_id: &str,
        id: &Uuid,
    ) -> Result<Option<NetworkRecord>, StoreError>;
    async fn delete_network(&self, project_id: &str, id: &Uuid) -> Result<(), StoreError>;

    async fn insert_subnet(&self, subnet: &SubnetRecord) -> Result<(), StoreError>;
    async fn list_subnets(&self, project_id: &str) -> Result<Vec<SubnetRecord>, StoreError>;
    async fn list_subnets_for_network(
        &self,
        project_id: &str,
        network_id: &Uuid,
    ) -> Result<Vec<SubnetRecord>, StoreError>;
    async fn get_subnet(
        &self,
        project_id: &str,
        id: &Uuid,
    ) -> Result<Option<SubnetRecord>, StoreError>;
    async fn delete_subnet(&self, project_id: &str, id: &Uuid) -> Result<(), StoreError>;
    async fn delete_subnet_bundle(&self, project_id: &str, id: &Uuid) -> Result<(), StoreError>;
    async fn update_subnet(&self, subnet: &SubnetRecord) -> Result<(), StoreError>;
    async fn update_subnet_bundle(
        &self,
        subnet: &SubnetRecord,
        pool_id: &Uuid,
        expected_pool_generation: u64,
    ) -> Result<(), StoreError>;

    async fn insert_port(&self, port: &PortRecord) -> Result<(), StoreError>;
    async fn list_ports(&self, project_id: &str) -> Result<Vec<PortRecord>, StoreError>;
    async fn list_ports_for_network(
        &self,
        project_id: &str,
        network_id: &Uuid,
    ) -> Result<Vec<PortRecord>, StoreError>;
    async fn get_port(&self, project_id: &str, id: &Uuid)
    -> Result<Option<PortRecord>, StoreError>;
    async fn get_port_by_id(&self, id: &Uuid) -> Result<Option<PortRecord>, StoreError>;
    async fn delete_port(&self, project_id: &str, id: &Uuid) -> Result<(), StoreError>;
    async fn update_port_binding(
        &self,
        project_id: &str,
        id: &Uuid,
        binding_host: Option<&str>,
        binding_state: Option<&str>,
    ) -> Result<PortRecord, StoreError>;
    async fn update_port_name(
        &self,
        project_id: &str,
        id: &Uuid,
        name: &str,
    ) -> Result<PortRecord, StoreError>;
    async fn insert_security_group(&self, group: &SecurityGroupRecord) -> Result<(), StoreError>;
    async fn list_security_groups(
        &self,
        project_id: &str,
    ) -> Result<Vec<SecurityGroupRecord>, StoreError>;
    async fn get_security_group(
        &self,
        project_id: &str,
        id: &Uuid,
    ) -> Result<Option<SecurityGroupRecord>, StoreError>;
    async fn update_security_group(
        &self,
        project_id: &str,
        id: &Uuid,
        name: &str,
        description: &str,
    ) -> Result<SecurityGroupRecord, StoreError>;
    async fn delete_security_group(&self, project_id: &str, id: &Uuid) -> Result<(), StoreError>;
    async fn insert_security_group_rule(
        &self,
        rule: &SecurityGroupRuleRecord,
    ) -> Result<(), StoreError>;
    async fn list_security_group_rules(
        &self,
        project_id: &str,
        group_id: &Uuid,
    ) -> Result<Vec<SecurityGroupRuleRecord>, StoreError>;
    async fn get_security_group_rule(
        &self,
        project_id: &str,
        id: &Uuid,
    ) -> Result<Option<SecurityGroupRuleRecord>, StoreError>;
    async fn delete_security_group_rule(
        &self,
        project_id: &str,
        id: &Uuid,
    ) -> Result<(), StoreError>;
    async fn list_security_group_bindings(
        &self,
        project_id: &str,
        endpoint_id: Option<&Uuid>,
    ) -> Result<Vec<SecurityGroupBindingRecord>, StoreError>;
    async fn replace_security_group_bindings(
        &self,
        project_id: &str,
        endpoint_id: &Uuid,
        group_ids: &[Uuid],
    ) -> Result<(), StoreError>;
}

/// Durable Placement-compatible provider inventory, allocation, and intent
/// records owned by the placement service: provider registration and state,
/// generation-guarded inventory refresh, allocation commit/release with
/// idempotent retries, allocation intents recorded before capacity is
/// committed, consumer reconciliation, and row-granular provider import.
///
/// This is a narrow port around the placement use cases, not a generic
/// persistence surface. Application code depends on this trait instead of on
/// the concrete `SqliteStore` adapter.
#[async_trait]
pub trait PlacementRepository: Send + Sync {
    async fn get_provider(
        &self,
        provider_id: &str,
    ) -> Result<Option<PlacementProviderRecord>, StoreError>;
    async fn list_providers(&self) -> Result<Vec<PlacementProviderRecord>, StoreError>;

    /// Bounded, paginated provider read for operator diagnostics.
    ///
    /// Returns providers (with inventories but not allocations) whose id
    /// sorts after `after_id`, at most `limit`, ordered by id. Allocations are
    /// deliberately omitted: `Inventory.used` already reflects durable
    /// allocation, and diagnostics must not materialize every allocation row.
    async fn list_providers_bounded(
        &self,
        after_id: Option<&str>,
        limit: usize,
    ) -> Result<Vec<PlacementProviderRecord>, StoreError>;

    /// Bounded read of provider id + durable state only, for operator
    /// diagnostics aggregation. Ordered by id, at most `limit`, continuing
    /// after `after_id`. Never materializes inventories or allocations.
    async fn list_provider_states(
        &self,
        after_id: Option<&str>,
        limit: usize,
    ) -> Result<Vec<PlacementProviderStateRecord>, StoreError>;

    /// Bounded, repository-computed capacity aggregate over the durable
    /// placement authority.
    ///
    /// This exists so operator diagnostics can read authoritative capacity
    /// without materializing every provider, inventory row and allocation.
    /// The implementation must aggregate in the database and fail closed
    /// (never silently truncate) when the stored class set exceeds `limit`.
    async fn capacity_summary(&self, limit: usize) -> Result<PlacementCapacitySummary, StoreError>;
    async fn register_provider(
        &self,
        node_id: &str,
        inventories: &[PlacementInventoryRecord],
    ) -> Result<PlacementProviderRecord, StoreError>;
    async fn register_provider_metadata(
        &self,
        node_id: &str,
        inventories: &[PlacementInventoryRecord],
        parent_provider_id: Option<&str>,
        traits: &[String],
        failure_domains: &[String],
        location: Option<&str>,
    ) -> Result<PlacementProviderRecord, StoreError>;
    async fn update_provider_metadata(
        &self,
        provider_id: &str,
        expected_generation: u64,
        parent_provider_id: Option<&str>,
        traits: &[String],
        failure_domains: &[String],
        location: Option<&str>,
    ) -> Result<PlacementProviderRecord, StoreError>;
    async fn sync_provider(
        &self,
        node_id: &str,
        state: &str,
        inventories: &[PlacementInventoryRecord],
    ) -> Result<PlacementProviderRecord, StoreError>;
    async fn refresh_inventories(
        &self,
        provider_id: &str,
        expected_generation: u64,
        inventories: &[PlacementInventoryRecord],
    ) -> Result<PlacementProviderRecord, StoreError>;
    async fn set_provider_state(&self, provider_id: &str, state: &str) -> Result<(), StoreError>;
    async fn commit_allocation(
        &self,
        provider_id: &str,
        expected_generation: u64,
        allocation: &PlacementAllocationRecord,
    ) -> Result<PlacementAllocationRecord, StoreError>;
    async fn release_allocation(
        &self,
        provider_id: &str,
        allocation_id: &str,
    ) -> Result<(), StoreError>;
    async fn upsert_intent(
        &self,
        intent: &PlacementIntentRecord,
    ) -> Result<PlacementIntentRecord, StoreError>;
    async fn get_intent(
        &self,
        allocation_id: &str,
    ) -> Result<Option<PlacementIntentRecord>, StoreError>;
    async fn list_intents(&self) -> Result<Vec<PlacementIntentRecord>, StoreError>;
    async fn delete_intent(&self, allocation_id: &str) -> Result<(), StoreError>;
    async fn reconcile_consumers(
        &self,
        durable_consumer_ids: &[String],
    ) -> Result<PlacementReconcileRecord, StoreError>;
    async fn import_provider(&self, provider: &PlacementProviderRecord) -> Result<(), StoreError>;
}

/// The persistence surface of the compute application service.
///
/// Combines the reconciler's `DurableStore` semantics (resources, operations,
/// agent commands, artifact transfers, image overlays, provider references —
/// already consumed generically by `OperationJournal`) with the keypair,
/// volume-attachment, and recovery-list capabilities the compute service uses.
/// Application code depends on this port; the composition root chooses the
/// concrete adapter.
#[async_trait]
pub trait ComputeRepository:
    DurableStore + KeypairRepository + VolumeAttachmentRepository + QuotaRepository
{
    async fn list_resources_by_kind(&self, kind: &str) -> Result<Vec<ResourceRecord>, StoreError>;
}
