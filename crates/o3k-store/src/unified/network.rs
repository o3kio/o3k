use async_trait::async_trait;
use uuid::Uuid;

use crate::{
    CanonicalAddressPoolRecord, CanonicalAddressRealmRecord, CanonicalEndpointRecord,
    CanonicalL3GatewayAttachmentRecord, CanonicalL3GatewayRecord, CanonicalNetworkPolicyRecord,
    CanonicalNetworkRecord, CanonicalRealmBindingRecord, FabricHostTransportIdentityRecord,
    NetworkAddressAllocationRecord, NetworkIntentRecord, NetworkRecord, NetworkRepository,
    PortRecord, SecurityGroupBindingRecord, SecurityGroupRecord, SecurityGroupRuleRecord,
    StoreError, SubnetRecord,
};

use super::O3kStore;

#[async_trait]
impl NetworkRepository for O3kStore {
    async fn get_fabric_host_identity(
        &self,
        host_id: &str,
    ) -> Result<Option<FabricHostTransportIdentityRecord>, StoreError> {
        match self {
            Self::Sqlite(store) => store.get_fabric_host_identity(host_id).await,
            Self::Postgres(store) => store.get_fabric_host_identity(host_id).await,
        }
    }

    async fn list_fabric_host_identities(
        &self,
    ) -> Result<Vec<FabricHostTransportIdentityRecord>, StoreError> {
        match self {
            Self::Sqlite(store) => store.list_fabric_host_identities().await,
            Self::Postgres(store) => store.list_fabric_host_identities().await,
        }
    }

    async fn upsert_fabric_host_identity(
        &self,
        identity: &FabricHostTransportIdentityRecord,
        expected_generation: Option<u64>,
    ) -> Result<FabricHostTransportIdentityRecord, StoreError> {
        match self {
            Self::Sqlite(store) => {
                store
                    .upsert_fabric_host_identity(identity, expected_generation)
                    .await
            }
            Self::Postgres(store) => {
                store
                    .upsert_fabric_host_identity(identity, expected_generation)
                    .await
            }
        }
    }

    async fn get_canonical_owner(
        &self,
        resource_name: &str,
        id: &Uuid,
    ) -> Result<Option<String>, StoreError> {
        match self {
            Self::Sqlite(s) => s.get_canonical_owner(resource_name, id).await,
            Self::Postgres(s) => s.get_canonical_owner(resource_name, id).await,
        }
    }
    async fn insert_canonical_network(
        &self,
        network: &CanonicalNetworkRecord,
    ) -> Result<(), StoreError> {
        match self {
            Self::Sqlite(s) => s.insert_canonical_network(network).await,
            Self::Postgres(s) => s.insert_canonical_network(network).await,
        }
    }
    async fn get_canonical_network(
        &self,
        project_id: &str,
        id: &Uuid,
    ) -> Result<Option<CanonicalNetworkRecord>, StoreError> {
        match self {
            Self::Sqlite(s) => s.get_canonical_network(project_id, id).await,
            Self::Postgres(s) => s.get_canonical_network(project_id, id).await,
        }
    }
    async fn list_canonical_networks(
        &self,
        project_id: &str,
    ) -> Result<Vec<CanonicalNetworkRecord>, StoreError> {
        match self {
            Self::Sqlite(s) => s.list_canonical_networks(project_id).await,
            Self::Postgres(s) => s.list_canonical_networks(project_id).await,
        }
    }
    async fn update_canonical_network(
        &self,
        project_id: &str,
        id: &Uuid,
        expected_generation: u64,
        name: &str,
        admin_state_up: bool,
    ) -> Result<CanonicalNetworkRecord, StoreError> {
        match self {
            Self::Sqlite(s) => {
                s.update_canonical_network(
                    project_id,
                    id,
                    expected_generation,
                    name,
                    admin_state_up,
                )
                .await
            }
            Self::Postgres(s) => {
                s.update_canonical_network(
                    project_id,
                    id,
                    expected_generation,
                    name,
                    admin_state_up,
                )
                .await
            }
        }
    }
    async fn insert_canonical_l3_gateway(
        &self,
        g: &CanonicalL3GatewayRecord,
    ) -> Result<(), StoreError> {
        match self {
            Self::Sqlite(s) => s.insert_canonical_l3_gateway(g).await,
            Self::Postgres(s) => s.insert_canonical_l3_gateway(g).await,
        }
    }
    async fn get_canonical_l3_gateway(
        &self,
        p: &str,
        id: &Uuid,
    ) -> Result<Option<CanonicalL3GatewayRecord>, StoreError> {
        match self {
            Self::Sqlite(s) => s.get_canonical_l3_gateway(p, id).await,
            Self::Postgres(s) => s.get_canonical_l3_gateway(p, id).await,
        }
    }
    async fn list_canonical_l3_gateways(
        &self,
        p: &str,
    ) -> Result<Vec<CanonicalL3GatewayRecord>, StoreError> {
        match self {
            Self::Sqlite(s) => s.list_canonical_l3_gateways(p).await,
            Self::Postgres(s) => s.list_canonical_l3_gateways(p).await,
        }
    }
    async fn list_canonical_l3_gateways_by_state(
        &self,
        state: &str,
    ) -> Result<Vec<CanonicalL3GatewayRecord>, StoreError> {
        match self {
            Self::Sqlite(s) => s.list_canonical_l3_gateways_by_state(state).await,
            Self::Postgres(s) => s.list_canonical_l3_gateways_by_state(state).await,
        }
    }
    async fn update_canonical_l3_gateway(
        &self,
        p: &str,
        id: &Uuid,
        e: u64,
        n: &str,
        x: Option<Uuid>,
        s: bool,
    ) -> Result<CanonicalL3GatewayRecord, StoreError> {
        match self {
            Self::Sqlite(v) => v.update_canonical_l3_gateway(p, id, e, n, x, s).await,
            Self::Postgres(v) => v.update_canonical_l3_gateway(p, id, e, n, x, s).await,
        }
    }
    async fn begin_canonical_l3_gateway_deletion(
        &self,
        p: &str,
        id: &Uuid,
        e: u64,
    ) -> Result<CanonicalL3GatewayRecord, StoreError> {
        match self {
            Self::Sqlite(v) => v.begin_canonical_l3_gateway_deletion(p, id, e).await,
            Self::Postgres(v) => v.begin_canonical_l3_gateway_deletion(p, id, e).await,
        }
    }
    async fn finalize_canonical_l3_gateway_deletion(
        &self,
        p: &str,
        id: &Uuid,
        e: u64,
    ) -> Result<(), StoreError> {
        match self {
            Self::Sqlite(v) => v.finalize_canonical_l3_gateway_deletion(p, id, e).await,
            Self::Postgres(v) => v.finalize_canonical_l3_gateway_deletion(p, id, e).await,
        }
    }
    async fn insert_canonical_l3_gateway_attachment(
        &self,
        a: &CanonicalL3GatewayAttachmentRecord,
    ) -> Result<(), StoreError> {
        match self {
            Self::Sqlite(v) => v.insert_canonical_l3_gateway_attachment(a).await,
            Self::Postgres(v) => v.insert_canonical_l3_gateway_attachment(a).await,
        }
    }
    async fn get_canonical_l3_gateway_attachment(
        &self,
        p: &str,
        id: &Uuid,
    ) -> Result<Option<CanonicalL3GatewayAttachmentRecord>, StoreError> {
        match self {
            Self::Sqlite(v) => v.get_canonical_l3_gateway_attachment(p, id).await,
            Self::Postgres(v) => v.get_canonical_l3_gateway_attachment(p, id).await,
        }
    }
    async fn list_canonical_l3_gateway_attachments(
        &self,
        p: &str,
        g: &Uuid,
    ) -> Result<Vec<CanonicalL3GatewayAttachmentRecord>, StoreError> {
        match self {
            Self::Sqlite(v) => v.list_canonical_l3_gateway_attachments(p, g).await,
            Self::Postgres(v) => v.list_canonical_l3_gateway_attachments(p, g).await,
        }
    }
    async fn list_canonical_l3_gateway_attachments_by_state(
        &self,
        state: &str,
    ) -> Result<Vec<CanonicalL3GatewayAttachmentRecord>, StoreError> {
        match self {
            Self::Sqlite(v) => {
                v.list_canonical_l3_gateway_attachments_by_state(state)
                    .await
            }
            Self::Postgres(v) => {
                v.list_canonical_l3_gateway_attachments_by_state(state)
                    .await
            }
        }
    }
    async fn list_canonical_realm_l3_gateway_attachments(
        &self,
        p: &str,
        r: &Uuid,
    ) -> Result<Vec<CanonicalL3GatewayAttachmentRecord>, StoreError> {
        match self {
            Self::Sqlite(v) => v.list_canonical_realm_l3_gateway_attachments(p, r).await,
            Self::Postgres(v) => v.list_canonical_realm_l3_gateway_attachments(p, r).await,
        }
    }
    async fn begin_canonical_l3_gateway_attachment_deletion(
        &self,
        p: &str,
        id: &Uuid,
        e: u64,
    ) -> Result<CanonicalL3GatewayAttachmentRecord, StoreError> {
        match self {
            Self::Sqlite(v) => {
                v.begin_canonical_l3_gateway_attachment_deletion(p, id, e)
                    .await
            }
            Self::Postgres(v) => {
                v.begin_canonical_l3_gateway_attachment_deletion(p, id, e)
                    .await
            }
        }
    }
    async fn finalize_canonical_l3_gateway_attachment_deletion(
        &self,
        p: &str,
        id: &Uuid,
        e: u64,
    ) -> Result<(), StoreError> {
        match self {
            Self::Sqlite(v) => {
                v.finalize_canonical_l3_gateway_attachment_deletion(p, id, e)
                    .await
            }
            Self::Postgres(v) => {
                v.finalize_canonical_l3_gateway_attachment_deletion(p, id, e)
                    .await
            }
        }
    }
    async fn insert_canonical_realm(
        &self,
        realm: &CanonicalAddressRealmRecord,
    ) -> Result<(), StoreError> {
        match self {
            Self::Sqlite(s) => s.insert_canonical_realm(realm).await,
            Self::Postgres(s) => s.insert_canonical_realm(realm).await,
        }
    }
    async fn get_canonical_realm(
        &self,
        project_id: &str,
        id: &Uuid,
    ) -> Result<Option<CanonicalAddressRealmRecord>, StoreError> {
        match self {
            Self::Sqlite(s) => s.get_canonical_realm(project_id, id).await,
            Self::Postgres(s) => s.get_canonical_realm(project_id, id).await,
        }
    }
    async fn list_canonical_realms(
        &self,
        project_id: &str,
        network_id: &Uuid,
    ) -> Result<Vec<CanonicalAddressRealmRecord>, StoreError> {
        match self {
            Self::Sqlite(s) => s.list_canonical_realms(project_id, network_id).await,
            Self::Postgres(s) => s.list_canonical_realms(project_id, network_id).await,
        }
    }
    async fn list_active_canonical_realms(
        &self,
    ) -> Result<Vec<CanonicalAddressRealmRecord>, StoreError> {
        match self {
            Self::Sqlite(s) => s.list_active_canonical_realms().await,
            Self::Postgres(s) => s.list_active_canonical_realms().await,
        }
    }
    async fn insert_canonical_pool(
        &self,
        pool: &CanonicalAddressPoolRecord,
    ) -> Result<(), StoreError> {
        match self {
            Self::Sqlite(s) => s.insert_canonical_pool(pool).await,
            Self::Postgres(s) => s.insert_canonical_pool(pool).await,
        }
    }
    async fn list_canonical_pools(
        &self,
        project_id: &str,
        realm_id: &Uuid,
    ) -> Result<Vec<CanonicalAddressPoolRecord>, StoreError> {
        match self {
            Self::Sqlite(s) => s.list_canonical_pools(project_id, realm_id).await,
            Self::Postgres(s) => s.list_canonical_pools(project_id, realm_id).await,
        }
    }

    async fn insert_subnet_bundle(
        &self,
        realm: &CanonicalAddressRealmRecord,
        pool: &CanonicalAddressPoolRecord,
        subnet: &SubnetRecord,
    ) -> Result<(), StoreError> {
        match self {
            Self::Sqlite(s) => s.insert_subnet_bundle(realm, pool, subnet).await,
            Self::Postgres(s) => s.insert_subnet_bundle(realm, pool, subnet).await,
        }
    }
    async fn delete_canonical_pool(
        &self,
        project_id: &str,
        pool_id: &Uuid,
    ) -> Result<(), StoreError> {
        match self {
            Self::Sqlite(s) => s.delete_canonical_pool(project_id, pool_id).await,
            Self::Postgres(s) => s.delete_canonical_pool(project_id, pool_id).await,
        }
    }

    async fn update_canonical_pool(
        &self,
        project_id: &str,
        pool_id: &Uuid,
        expected_generation: u64,
        gateway: Option<std::net::Ipv4Addr>,
    ) -> Result<CanonicalAddressPoolRecord, StoreError> {
        match self {
            Self::Sqlite(s) => {
                s.update_canonical_pool(project_id, pool_id, expected_generation, gateway)
                    .await
            }
            Self::Postgres(s) => {
                s.update_canonical_pool(project_id, pool_id, expected_generation, gateway)
                    .await
            }
        }
    }
    async fn insert_canonical_endpoint(
        &self,
        endpoint: &CanonicalEndpointRecord,
    ) -> Result<(), StoreError> {
        match self {
            Self::Sqlite(s) => s.insert_canonical_endpoint(endpoint).await,
            Self::Postgres(s) => s.insert_canonical_endpoint(endpoint).await,
        }
    }
    async fn insert_canonical_endpoint_and_port(
        &self,
        endpoint: &CanonicalEndpointRecord,
        port: &PortRecord,
    ) -> Result<(), StoreError> {
        match self {
            Self::Sqlite(s) => s.insert_canonical_endpoint_and_port(endpoint, port).await,
            Self::Postgres(s) => s.insert_canonical_endpoint_and_port(endpoint, port).await,
        }
    }
    async fn list_canonical_endpoints(
        &self,
        project_id: &str,
        realm_id: &Uuid,
    ) -> Result<Vec<CanonicalEndpointRecord>, StoreError> {
        match self {
            Self::Sqlite(s) => s.list_canonical_endpoints(project_id, realm_id).await,
            Self::Postgres(s) => s.list_canonical_endpoints(project_id, realm_id).await,
        }
    }
    async fn get_canonical_endpoint(
        &self,
        project_id: &str,
        endpoint_id: &Uuid,
    ) -> Result<Option<CanonicalEndpointRecord>, StoreError> {
        match self {
            Self::Sqlite(s) => s.get_canonical_endpoint(project_id, endpoint_id).await,
            Self::Postgres(s) => s.get_canonical_endpoint(project_id, endpoint_id).await,
        }
    }
    async fn delete_canonical_endpoint(
        &self,
        project_id: &str,
        endpoint_id: &Uuid,
    ) -> Result<(), StoreError> {
        match self {
            Self::Sqlite(s) => s.delete_canonical_endpoint(project_id, endpoint_id).await,
            Self::Postgres(s) => s.delete_canonical_endpoint(project_id, endpoint_id).await,
        }
    }
    async fn delete_canonical_endpoint_and_port(
        &self,
        project_id: &str,
        endpoint_id: &Uuid,
    ) -> Result<(), StoreError> {
        match self {
            Self::Sqlite(s) => {
                s.delete_canonical_endpoint_and_port(project_id, endpoint_id)
                    .await
            }
            Self::Postgres(s) => {
                s.delete_canonical_endpoint_and_port(project_id, endpoint_id)
                    .await
            }
        }
    }
    async fn upsert_canonical_policy(
        &self,
        policy: &CanonicalNetworkPolicyRecord,
    ) -> Result<(), StoreError> {
        match self {
            Self::Sqlite(s) => s.upsert_canonical_policy(policy).await,
            Self::Postgres(s) => s.upsert_canonical_policy(policy).await,
        }
    }
    async fn list_canonical_policies(
        &self,
        project_id: &str,
        network_id: &Uuid,
    ) -> Result<Vec<CanonicalNetworkPolicyRecord>, StoreError> {
        match self {
            Self::Sqlite(s) => s.list_canonical_policies(project_id, network_id).await,
            Self::Postgres(s) => s.list_canonical_policies(project_id, network_id).await,
        }
    }
    async fn delete_canonical_policy(
        &self,
        project_id: &str,
        policy_id: &Uuid,
    ) -> Result<(), StoreError> {
        match self {
            Self::Sqlite(s) => s.delete_canonical_policy(project_id, policy_id).await,
            Self::Postgres(s) => s.delete_canonical_policy(project_id, policy_id).await,
        }
    }
    async fn begin_canonical_realm_deletion(
        &self,
        project_id: &str,
        realm_id: &Uuid,
        expected_generation: u64,
    ) -> Result<CanonicalAddressRealmRecord, StoreError> {
        match self {
            Self::Sqlite(s) => {
                s.begin_canonical_realm_deletion(project_id, realm_id, expected_generation)
                    .await
            }
            Self::Postgres(s) => {
                s.begin_canonical_realm_deletion(project_id, realm_id, expected_generation)
                    .await
            }
        }
    }
    async fn advance_canonical_realm_generation(
        &self,
        project_id: &str,
        realm_id: &Uuid,
        expected_generation: u64,
    ) -> Result<CanonicalAddressRealmRecord, StoreError> {
        match self {
            Self::Sqlite(s) => {
                s.advance_canonical_realm_generation(project_id, realm_id, expected_generation)
                    .await
            }
            Self::Postgres(s) => {
                s.advance_canonical_realm_generation(project_id, realm_id, expected_generation)
                    .await
            }
        }
    }
    async fn finalize_canonical_realm_deletion(
        &self,
        project_id: &str,
        realm_id: &Uuid,
        expected_generation: u64,
    ) -> Result<(), StoreError> {
        match self {
            Self::Sqlite(s) => {
                s.finalize_canonical_realm_deletion(project_id, realm_id, expected_generation)
                    .await
            }
            Self::Postgres(s) => {
                s.finalize_canonical_realm_deletion(project_id, realm_id, expected_generation)
                    .await
            }
        }
    }
    async fn list_canonical_realm_bindings(
        &self,
        realm_id: &Uuid,
    ) -> Result<Vec<CanonicalRealmBindingRecord>, StoreError> {
        match self {
            Self::Sqlite(s) => s.list_canonical_realm_bindings(realm_id).await,
            Self::Postgres(s) => s.list_canonical_realm_bindings(realm_id).await,
        }
    }
    async fn insert_canonical_realm_binding(
        &self,
        binding: &CanonicalRealmBindingRecord,
    ) -> Result<(), StoreError> {
        match self {
            Self::Sqlite(s) => s.insert_canonical_realm_binding(binding).await,
            Self::Postgres(s) => s.insert_canonical_realm_binding(binding).await,
        }
    }
    async fn get_canonical_realm_binding(
        &self,
        fabric_domain_id: &str,
        realm_id: &Uuid,
    ) -> Result<Option<CanonicalRealmBindingRecord>, StoreError> {
        match self {
            Self::Sqlite(s) => {
                s.get_canonical_realm_binding(fabric_domain_id, realm_id)
                    .await
            }
            Self::Postgres(s) => {
                s.get_canonical_realm_binding(fabric_domain_id, realm_id)
                    .await
            }
        }
    }
    async fn delete_canonical_realm_binding(
        &self,
        binding: &CanonicalRealmBindingRecord,
        expected_realm_generation: u64,
    ) -> Result<(), StoreError> {
        match self {
            Self::Sqlite(s) => {
                s.delete_canonical_realm_binding(binding, expected_realm_generation)
                    .await
            }
            Self::Postgres(s) => {
                s.delete_canonical_realm_binding(binding, expected_realm_generation)
                    .await
            }
        }
    }
    async fn delete_canonical_realm(
        &self,
        project_id: &str,
        realm_id: &Uuid,
    ) -> Result<(), StoreError> {
        match self {
            Self::Sqlite(s) => s.delete_canonical_realm(project_id, realm_id).await,
            Self::Postgres(s) => s.delete_canonical_realm(project_id, realm_id).await,
        }
    }
    async fn delete_canonical_network(
        &self,
        project_id: &str,
        network_id: &Uuid,
    ) -> Result<(), StoreError> {
        match self {
            Self::Sqlite(s) => s.delete_canonical_network(project_id, network_id).await,
            Self::Postgres(s) => s.delete_canonical_network(project_id, network_id).await,
        }
    }
    async fn backfill_canonical_network_state(&self) -> Result<(), StoreError> {
        match self {
            Self::Sqlite(s) => s.backfill_canonical_network_state().await,
            Self::Postgres(s) => s.backfill_canonical_network_state().await,
        }
    }
    async fn allocate_network_address(
        &self,
        realm_id: &Uuid,
        project_id: &str,
        endpoint_id: &Uuid,
        operation_id: &str,
        prefix: &str,
    ) -> Result<NetworkAddressAllocationRecord, StoreError> {
        match self {
            Self::Sqlite(s) => {
                s.allocate_network_address(realm_id, project_id, endpoint_id, operation_id, prefix)
                    .await
            }
            Self::Postgres(s) => {
                s.allocate_network_address(realm_id, project_id, endpoint_id, operation_id, prefix)
                    .await
            }
        }
    }

    async fn release_network_address(
        &self,
        project_id: &str,
        endpoint_id: &Uuid,
    ) -> Result<(), StoreError> {
        match self {
            Self::Sqlite(s) => s.release_network_address(project_id, endpoint_id).await,
            Self::Postgres(s) => s.release_network_address(project_id, endpoint_id).await,
        }
    }

    async fn insert_network_intent(&self, intent: &NetworkIntentRecord) -> Result<(), StoreError> {
        match self {
            Self::Sqlite(s) => s.insert_network_intent(intent).await,
            Self::Postgres(s) => s.insert_network_intent(intent).await,
        }
    }

    async fn list_network_intents(
        &self,
        project_id: &str,
    ) -> Result<Vec<NetworkIntentRecord>, StoreError> {
        match self {
            Self::Sqlite(s) => s.list_network_intents(project_id).await,
            Self::Postgres(s) => s.list_network_intents(project_id).await,
        }
    }

    async fn get_network_intent(
        &self,
        project_id: &str,
        id: &Uuid,
    ) -> Result<Option<NetworkIntentRecord>, StoreError> {
        match self {
            Self::Sqlite(s) => s.get_network_intent(project_id, id).await,
            Self::Postgres(s) => s.get_network_intent(project_id, id).await,
        }
    }

    async fn update_network_intent(
        &self,
        project_id: &str,
        id: &Uuid,
        expected_generation: u64,
        payload: &str,
        plan_fingerprint_sha256: Option<&str>,
        status: &str,
    ) -> Result<NetworkIntentRecord, StoreError> {
        match self {
            Self::Sqlite(s) => {
                s.update_network_intent(
                    project_id,
                    id,
                    expected_generation,
                    payload,
                    plan_fingerprint_sha256,
                    status,
                )
                .await
            }
            Self::Postgres(s) => {
                s.update_network_intent(
                    project_id,
                    id,
                    expected_generation,
                    payload,
                    plan_fingerprint_sha256,
                    status,
                )
                .await
            }
        }
    }

    async fn insert_network(&self, network: &NetworkRecord) -> Result<(), StoreError> {
        match self {
            Self::Sqlite(s) => s.insert_network(network).await,
            Self::Postgres(s) => s.insert_network(network).await,
        }
    }

    async fn list_networks(&self, project_id: &str) -> Result<Vec<NetworkRecord>, StoreError> {
        match self {
            Self::Sqlite(s) => s.list_networks(project_id).await,
            Self::Postgres(s) => s.list_networks(project_id).await,
        }
    }

    async fn get_network(
        &self,
        project_id: &str,
        id: &Uuid,
    ) -> Result<Option<NetworkRecord>, StoreError> {
        match self {
            Self::Sqlite(s) => s.get_network(project_id, id).await,
            Self::Postgres(s) => s.get_network(project_id, id).await,
        }
    }

    async fn delete_network(&self, project_id: &str, id: &Uuid) -> Result<(), StoreError> {
        match self {
            Self::Sqlite(s) => s.delete_network(project_id, id).await,
            Self::Postgres(s) => s.delete_network(project_id, id).await,
        }
    }

    async fn insert_subnet(&self, subnet: &SubnetRecord) -> Result<(), StoreError> {
        match self {
            Self::Sqlite(s) => s.insert_subnet(subnet).await,
            Self::Postgres(s) => s.insert_subnet(subnet).await,
        }
    }

    async fn list_subnets(&self, project_id: &str) -> Result<Vec<SubnetRecord>, StoreError> {
        match self {
            Self::Sqlite(s) => s.list_subnets(project_id).await,
            Self::Postgres(s) => s.list_subnets(project_id).await,
        }
    }

    async fn list_subnets_for_network(
        &self,
        project_id: &str,
        network_id: &Uuid,
    ) -> Result<Vec<SubnetRecord>, StoreError> {
        match self {
            Self::Sqlite(s) => s.list_subnets_for_network(project_id, network_id).await,
            Self::Postgres(s) => s.list_subnets_for_network(project_id, network_id).await,
        }
    }

    async fn get_subnet(
        &self,
        project_id: &str,
        id: &Uuid,
    ) -> Result<Option<SubnetRecord>, StoreError> {
        match self {
            Self::Sqlite(s) => s.get_subnet(project_id, id).await,
            Self::Postgres(s) => s.get_subnet(project_id, id).await,
        }
    }

    async fn delete_subnet(&self, project_id: &str, id: &Uuid) -> Result<(), StoreError> {
        match self {
            Self::Sqlite(s) => s.delete_subnet(project_id, id).await,
            Self::Postgres(s) => s.delete_subnet(project_id, id).await,
        }
    }

    async fn update_subnet(&self, subnet: &SubnetRecord) -> Result<(), StoreError> {
        match self {
            Self::Sqlite(s) => s.update_subnet(subnet).await,
            Self::Postgres(s) => s.update_subnet(subnet).await,
        }
    }

    async fn delete_subnet_bundle(&self, project_id: &str, id: &Uuid) -> Result<(), StoreError> {
        match self {
            Self::Sqlite(s) => s.delete_subnet_bundle(project_id, id).await,
            Self::Postgres(s) => s.delete_subnet_bundle(project_id, id).await,
        }
    }

    async fn update_subnet_bundle(
        &self,
        subnet: &SubnetRecord,
        pool_id: &Uuid,
        expected_pool_generation: u64,
    ) -> Result<(), StoreError> {
        match self {
            Self::Sqlite(s) => {
                s.update_subnet_bundle(subnet, pool_id, expected_pool_generation)
                    .await
            }
            Self::Postgres(s) => {
                s.update_subnet_bundle(subnet, pool_id, expected_pool_generation)
                    .await
            }
        }
    }

    async fn insert_port(&self, port: &PortRecord) -> Result<(), StoreError> {
        match self {
            Self::Sqlite(s) => s.insert_port(port).await,
            Self::Postgres(s) => s.insert_port(port).await,
        }
    }

    async fn list_ports(&self, project_id: &str) -> Result<Vec<PortRecord>, StoreError> {
        match self {
            Self::Sqlite(s) => s.list_ports(project_id).await,
            Self::Postgres(s) => s.list_ports(project_id).await,
        }
    }

    async fn list_ports_for_network(
        &self,
        project_id: &str,
        network_id: &Uuid,
    ) -> Result<Vec<PortRecord>, StoreError> {
        match self {
            Self::Sqlite(s) => s.list_ports_for_network(project_id, network_id).await,
            Self::Postgres(s) => s.list_ports_for_network(project_id, network_id).await,
        }
    }

    async fn get_port(
        &self,
        project_id: &str,
        id: &Uuid,
    ) -> Result<Option<PortRecord>, StoreError> {
        match self {
            Self::Sqlite(s) => s.get_port(project_id, id).await,
            Self::Postgres(s) => s.get_port(project_id, id).await,
        }
    }

    async fn get_port_by_id(&self, id: &Uuid) -> Result<Option<PortRecord>, StoreError> {
        match self {
            Self::Sqlite(s) => s.get_port_by_id(id).await,
            Self::Postgres(s) => s.get_port_by_id(id).await,
        }
    }

    async fn delete_port(&self, project_id: &str, id: &Uuid) -> Result<(), StoreError> {
        match self {
            Self::Sqlite(s) => s.delete_port(project_id, id).await,
            Self::Postgres(s) => s.delete_port(project_id, id).await,
        }
    }

    async fn update_port_binding(
        &self,
        project_id: &str,
        id: &Uuid,
        binding_host: Option<&str>,
        binding_state: Option<&str>,
    ) -> Result<PortRecord, StoreError> {
        match self {
            Self::Sqlite(s) => {
                s.update_port_binding(project_id, id, binding_host, binding_state)
                    .await
            }
            Self::Postgres(s) => {
                s.update_port_binding(project_id, id, binding_host, binding_state)
                    .await
            }
        }
    }
    async fn update_port_name(
        &self,
        project_id: &str,
        id: &Uuid,
        name: &str,
    ) -> Result<PortRecord, StoreError> {
        match self {
            Self::Sqlite(s) => s.update_port_name(project_id, id, name).await,
            Self::Postgres(s) => s.update_port_name(project_id, id, name).await,
        }
    }

    async fn insert_security_group(&self, group: &SecurityGroupRecord) -> Result<(), StoreError> {
        match self {
            Self::Sqlite(s) => s.insert_security_group(group).await,
            Self::Postgres(s) => s.insert_security_group(group).await,
        }
    }
    async fn list_security_groups(
        &self,
        project_id: &str,
    ) -> Result<Vec<SecurityGroupRecord>, StoreError> {
        match self {
            Self::Sqlite(s) => s.list_security_groups(project_id).await,
            Self::Postgres(s) => s.list_security_groups(project_id).await,
        }
    }
    async fn get_security_group(
        &self,
        project_id: &str,
        id: &Uuid,
    ) -> Result<Option<SecurityGroupRecord>, StoreError> {
        match self {
            Self::Sqlite(s) => s.get_security_group(project_id, id).await,
            Self::Postgres(s) => s.get_security_group(project_id, id).await,
        }
    }
    async fn update_security_group(
        &self,
        project_id: &str,
        id: &Uuid,
        name: &str,
        description: &str,
    ) -> Result<SecurityGroupRecord, StoreError> {
        match self {
            Self::Sqlite(s) => {
                s.update_security_group(project_id, id, name, description)
                    .await
            }
            Self::Postgres(s) => {
                s.update_security_group(project_id, id, name, description)
                    .await
            }
        }
    }
    async fn delete_security_group(&self, project_id: &str, id: &Uuid) -> Result<(), StoreError> {
        match self {
            Self::Sqlite(s) => s.delete_security_group(project_id, id).await,
            Self::Postgres(s) => s.delete_security_group(project_id, id).await,
        }
    }
    async fn insert_security_group_rule(
        &self,
        rule: &SecurityGroupRuleRecord,
    ) -> Result<(), StoreError> {
        match self {
            Self::Sqlite(s) => s.insert_security_group_rule(rule).await,
            Self::Postgres(s) => s.insert_security_group_rule(rule).await,
        }
    }
    async fn list_security_group_rules(
        &self,
        project_id: &str,
        group_id: &Uuid,
    ) -> Result<Vec<SecurityGroupRuleRecord>, StoreError> {
        match self {
            Self::Sqlite(s) => s.list_security_group_rules(project_id, group_id).await,
            Self::Postgres(s) => s.list_security_group_rules(project_id, group_id).await,
        }
    }
    async fn get_security_group_rule(
        &self,
        project_id: &str,
        id: &Uuid,
    ) -> Result<Option<SecurityGroupRuleRecord>, StoreError> {
        match self {
            Self::Sqlite(s) => s.get_security_group_rule(project_id, id).await,
            Self::Postgres(s) => s.get_security_group_rule(project_id, id).await,
        }
    }
    async fn delete_security_group_rule(
        &self,
        project_id: &str,
        id: &Uuid,
    ) -> Result<(), StoreError> {
        match self {
            Self::Sqlite(s) => s.delete_security_group_rule(project_id, id).await,
            Self::Postgres(s) => s.delete_security_group_rule(project_id, id).await,
        }
    }
    async fn list_security_group_bindings(
        &self,
        project_id: &str,
        endpoint_id: Option<&Uuid>,
    ) -> Result<Vec<SecurityGroupBindingRecord>, StoreError> {
        match self {
            Self::Sqlite(s) => {
                s.list_security_group_bindings(project_id, endpoint_id)
                    .await
            }
            Self::Postgres(s) => {
                s.list_security_group_bindings(project_id, endpoint_id)
                    .await
            }
        }
    }
    async fn replace_security_group_bindings(
        &self,
        project_id: &str,
        endpoint_id: &Uuid,
        group_ids: &[Uuid],
    ) -> Result<(), StoreError> {
        match self {
            Self::Sqlite(s) => {
                s.replace_security_group_bindings(project_id, endpoint_id, group_ids)
                    .await
            }
            Self::Postgres(s) => {
                s.replace_security_group_bindings(project_id, endpoint_id, group_ids)
                    .await
            }
        }
    }
}
