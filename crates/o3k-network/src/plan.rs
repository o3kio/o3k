use std::{
    collections::{BTreeMap, BTreeSet, HashSet},
    net::Ipv4Addr,
};

use o3k_domain::{
    AddressRealm, Ipv4Prefix, NamespacedRoutedFabricPlan, NetworkCapability, NetworkIntent,
    NetworkPlanIntent, NetworkProtocol, PolicyAction, PolicyDefaultIntent, PolicyDirection,
    PolicyIntent, PolicyStatefulMode, PortRange,
};
use serde::{Deserialize, Serialize};
use thiserror::Error;
use uuid::Uuid;

use crate::service::{
    parse_security_group_direction, parse_security_group_prefix, parse_security_group_protocol,
};
use crate::{NetworkError, gateway};

/// A deterministic, provider-independent compilation of canonical network
/// intent. It contains semantic intents only; host commands and provider
/// handles belong behind the execution boundary.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct NodeNetworkPlan {
    pub schema_version: u16,
    pub plan_id: Uuid,
    pub node_id: String,
    pub operation_id: Uuid,
    pub deadline_unix_ms: u64,
    pub resource_generations: BTreeMap<Uuid, u64>,
    pub intents: Vec<NetworkPlanIntent>,
    /// Optional accepted P11 semantic fabric plan. `None` preserves the P9
    /// wire shape and legacy fingerprint for non-P11 plans.
    #[serde(default)]
    pub fabric: Option<NamespacedRoutedFabricPlan>,
    /// Independent multi-Realm gateway execution unit. This is not part of
    /// the Realm-scoped `fabric` plan.
    #[serde(default)]
    pub gateway: Option<o3k_domain::L3GatewayExecutionPlan>,
    pub fingerprint_sha256: String,
}

#[derive(Debug, Error, PartialEq, Eq)]
pub enum NetworkPlanError {
    #[error("network realm prefix overlaps an existing routed realm")]
    OverlappingRealm,
    #[error("network intent is outside its address realm")]
    AddressOutsideRealm,
    #[error("network intent requires unsupported capability {0:?}")]
    UnsupportedCapability(NetworkCapability),
    #[error("network intent has a conflicting endpoint identity")]
    ConflictingEndpoint,
    #[error("network plan serialization failed")]
    Serialization,
    #[error("network plan identity conflicts with an existing plan")]
    ConflictingPlan,
    #[error("network intent has invalid project ownership")]
    OwnershipViolation,
    #[error("network intent has an invalid address pool")]
    InvalidAddressPool,
    #[error("network intent has an invalid policy")]
    InvalidPolicy,
    #[error("network intent has an invalid IPv4 prefix")]
    InvalidPrefix,
    #[error("P11 fabric plan is invalid")]
    InvalidFabricPlan,
    #[error("L3 gateway execution plan is invalid")]
    InvalidGatewayPlan,
}

pub const NODE_NETWORK_PLAN_SCHEMA_VERSION: u16 = 1;

impl NodeNetworkPlan {
    /// Attaches accepted P11 semantic state and recomputes the transport
    /// fingerprint. Provider-native state is intentionally not accepted here.
    pub fn with_fabric(
        mut self,
        fabric: NamespacedRoutedFabricPlan,
    ) -> Result<Self, NetworkPlanError> {
        self.fabric = Some(fabric);
        self.validate_fabric()?;
        self.fingerprint_sha256 = canonical_plan_fingerprint(&self)?;
        Ok(self)
    }

    /// Attaches the separate provider-independent L3 gateway execution unit.
    pub fn with_gateway(
        mut self,
        gateway: o3k_domain::L3GatewayExecutionPlan,
    ) -> Result<Self, NetworkPlanError> {
        gateway::validate_plan(&gateway).map_err(|_| NetworkPlanError::InvalidGatewayPlan)?;
        self.gateway = Some(gateway);
        self.fingerprint_sha256 = canonical_plan_fingerprint(&self)?;
        Ok(self)
    }

    /// Validates the semantic P11 payload before admission to a node-local
    /// executor. A valid fingerprint alone is insufficient authorization.
    pub fn validate_fabric(&self) -> Result<(), NetworkPlanError> {
        let Some(fabric) = &self.fabric else {
            return Ok(());
        };
        if fabric.local_host != self.node_id
            || fabric.local_host.is_empty()
            || fabric.local_fabric_transport_ip.is_unspecified()
            || fabric.local_fabric_transport_ip.is_loopback()
            || fabric.local_fabric_generation == 0
            || fabric.local_underlay_mtu == 0
            || fabric.local_fabric_mtu == 0
            || fabric.local_fabric_mtu > fabric.local_underlay_mtu
            || !matches!(
                fabric
                    .local_underlay_mtu
                    .saturating_sub(fabric.local_fabric_mtu),
                60 | 80
            )
            || fabric.tenant_mtu > fabric.local_fabric_mtu.saturating_sub(50)
            || fabric.directory_generation == 0
            || fabric.tenant_mtu == 0
            || fabric.tenant_mtu > fabric.local_fabric_mtu
            || fabric.policy_generation == 0
            || fabric.proxy_mac.len() != 17
            || fabric.encapsulation.realm_id != fabric.realm_id
            || fabric.encapsulation.validate().is_err()
            || fabric.directory.realm_id != fabric.realm_id
            || fabric.directory.prefix != fabric.realm_prefix
            || fabric.directory.directory_generation != fabric.directory_generation
            || fabric.directory.proxy_mac != fabric.proxy_mac
            || fabric.encapsulation.provider_kind != o3k_domain::FabricProviderKind::Vxlan
        {
            return Err(NetworkPlanError::InvalidFabricPlan);
        }
        if fabric.peers.iter().any(|peer| {
            peer.host_id.is_empty()
                || peer.fabric_transport_ip.is_unspecified()
                || peer.fabric_transport_ip.is_loopback()
        }) {
            return Err(NetworkPlanError::InvalidFabricPlan);
        }
        if fabric
            .directory
            .entries
            .iter()
            .any(|entry| !fabric.realm_prefix.contains(entry.fixed_ip))
        {
            return Err(NetworkPlanError::InvalidFabricPlan);
        }
        if let Some(dhcp) = fabric.dhcp.as_ref() {
            let participant_hosts = fabric
                .directory
                .entries
                .iter()
                .map(|entry| entry.selected_host.as_str())
                .collect::<BTreeSet<_>>();
            if !fabric.realm_prefix.contains(dhcp.gateway)
                || dhcp.gateway == fabric.realm_prefix.network
                || dhcp.authority_host.trim().is_empty()
                || (!participant_hosts.is_empty()
                    && !participant_hosts.contains(dhcp.authority_host.as_str()))
                || participant_hosts
                    .iter()
                    .next()
                    .is_some_and(|expected| *expected != dhcp.authority_host)
            {
                return Err(NetworkPlanError::InvalidFabricPlan);
            }
        }
        let mut policy_ids = BTreeSet::new();
        for policy in &fabric.policies {
            if policy.id == Uuid::nil()
                || policy.endpoint_id == Uuid::nil()
                || !policy_ids.insert(policy.id)
                || fabric
                    .directory
                    .entries
                    .iter()
                    .all(|entry| entry.endpoint_id != policy.endpoint_id)
            {
                return Err(NetworkPlanError::InvalidFabricPlan);
            }
        }
        let mut default_endpoints = BTreeSet::new();
        for default in &fabric.policy_defaults {
            if default.policy_id.is_nil()
                || default.endpoint_id.is_nil()
                || default.generation == 0
                || default.stateful_mode != o3k_domain::PolicyStatefulMode::Stateful
                || !default_endpoints.insert(default.endpoint_id)
                || fabric
                    .directory
                    .entries
                    .iter()
                    .all(|entry| entry.endpoint_id != default.endpoint_id)
            {
                return Err(NetworkPlanError::InvalidFabricPlan);
            }
        }
        let mut public_ids = BTreeSet::new();
        let mut public_addresses = BTreeSet::new();
        let mut public_endpoints = BTreeSet::new();
        for binding in &fabric.public_bindings {
            if binding.id.is_nil()
                || binding.project_id.is_empty()
                || binding.generation == 0
                || binding.public_address.is_unspecified()
                || !public_ids.insert(binding.id)
                || !public_addresses.insert(binding.public_address)
                || !public_endpoints.insert(binding.endpoint_id)
                || !fabric
                    .directory
                    .location(binding.endpoint_id)
                    .is_some_and(|endpoint| endpoint.project_id == binding.project_id)
            {
                return Err(NetworkPlanError::InvalidFabricPlan);
            }
        }
        let mut route_destinations = BTreeSet::new();
        let mut route_endpoints = BTreeSet::new();
        for route in &fabric.routes {
            if route.destination.prefix_len != 32
                || route.realm_id != fabric.realm_id
                || route.target_host.is_empty()
                || route.target_fabric_transport_ip.is_unspecified()
                || route.target_fabric_transport_ip.is_loopback()
                || route.endpoint_generation == 0
                || route.placement_generation == 0
                || route.realm_binding_generation != fabric.encapsulation.binding_generation
                || route.fabric_generation == 0
                || !route_destinations.insert(route.destination)
                || !route_endpoints.insert(route.endpoint_id)
                || fabric
                    .directory
                    .location(route.endpoint_id)
                    .is_none_or(|entry| {
                        entry.fixed_ip != route.destination.network
                            || entry.selected_host != route.target_host
                    })
            {
                return Err(NetworkPlanError::InvalidFabricPlan);
            }
        }
        let mut peer_hosts = BTreeSet::new();
        let mut peer_transport_ips = BTreeSet::new();
        for peer in &fabric.peers {
            if peer.host_id.is_empty()
                || peer.host_id == fabric.local_host
                || peer.public_key.is_empty()
                || peer.underlay_endpoint.is_empty()
                || peer.fabric_transport_ip.is_unspecified()
                || peer.fabric_transport_ip.is_loopback()
                || peer.fabric_generation == 0
                || !peer_hosts.insert(peer.host_id.as_str())
                || !peer_transport_ips.insert(peer.fabric_transport_ip)
            {
                return Err(NetworkPlanError::InvalidFabricPlan);
            }
            if !fabric.routes.iter().any(|route| {
                route.target_host == peer.host_id
                    && route.target_fabric_transport_ip == peer.fabric_transport_ip
            }) {
                return Err(NetworkPlanError::InvalidFabricPlan);
            }
        }
        if fabric.routes.iter().any(|route| {
            !peer_hosts.contains(route.target_host.as_str())
                || !fabric.peers.iter().any(|peer| {
                    peer.host_id == route.target_host
                        && peer.fabric_transport_ip == route.target_fabric_transport_ip
                })
        }) {
            return Err(NetworkPlanError::InvalidFabricPlan);
        }
        Ok(())
    }
}

/// Builds a node plan whose only execution unit is one complete canonical L3
/// gateway snapshot. This is used for gateway lifecycle operations that have
/// no endpoint plan to carry the gateway, such as deleting an unattached
/// gateway or detaching a Realm with no ports.
pub fn compile_l3_gateway_network_plan(
    gateway: o3k_domain::L3GatewayExecutionPlan,
    node_id: &str,
    operation_id: Uuid,
    deadline_unix_ms: u64,
) -> Result<NodeNetworkPlan, NetworkPlanError> {
    if node_id.trim().is_empty() {
        return Err(NetworkPlanError::InvalidGatewayPlan);
    }
    let mut plan = NodeNetworkPlan {
        schema_version: NODE_NETWORK_PLAN_SCHEMA_VERSION,
        plan_id: gateway.gateway_id,
        node_id: node_id.to_owned(),
        operation_id,
        deadline_unix_ms,
        resource_generations: BTreeMap::from([(gateway.gateway_id, gateway.gateway_generation)]),
        intents: Vec::new(),
        fabric: None,
        gateway: Some(gateway),
        fingerprint_sha256: String::new(),
    };
    plan.fingerprint_sha256 = canonical_plan_fingerprint(&plan)?;
    Ok(plan)
}

/// Compile the currently supported flat attachment projection into the same
/// canonical per-node plan used by routed providers. This helper is kept in
/// the network application boundary so callers cannot construct a wire-only
/// payload that bypasses plan validation.
pub struct AttachmentPlanInput<'a> {
    pub endpoint_id: Uuid,
    pub realm_id: Uuid,
    pub project_id: &'a str,
    pub mac: &'a str,
    pub fixed_ip: std::net::Ipv4Addr,
    pub subnet_cidr: &'a str,
    pub node_id: &'a str,
    pub operation_id: Uuid,
    pub deadline_unix_ms: u64,
    pub public_address: Option<std::net::Ipv4Addr>,
    pub external_realm_id: Option<Uuid>,
    pub policies: Vec<PolicyIntent>,
}

pub fn compile_attachment_plan(
    input: AttachmentPlanInput<'_>,
) -> Result<NodeNetworkPlan, NetworkPlanError> {
    compile_attachment_plan_with_defaults(input, Vec::new())
}

pub fn compile_attachment_plan_with_defaults(
    input: AttachmentPlanInput<'_>,
    policy_defaults: Vec<PolicyDefaultIntent>,
) -> Result<NodeNetworkPlan, NetworkPlanError> {
    let AttachmentPlanInput {
        endpoint_id,
        realm_id,
        project_id,
        mac,
        fixed_ip,
        subnet_cidr,
        node_id,
        operation_id,
        deadline_unix_ms,
        public_address,
        external_realm_id,
        policies,
    } = input;
    let has_policies = !policies.is_empty() || !policy_defaults.is_empty();
    let (network, prefix_len) = subnet_cidr
        .split_once('/')
        .ok_or(NetworkPlanError::InvalidPrefix)?;
    let network = network
        .parse()
        .map_err(|_| NetworkPlanError::InvalidPrefix)?;
    let prefix_len = prefix_len
        .parse::<u8>()
        .map_err(|_| NetworkPlanError::InvalidPrefix)?;
    let prefix =
        o3k_domain::Ipv4Prefix::new(network, prefix_len).ok_or(NetworkPlanError::InvalidPrefix)?;
    let intent = NetworkIntent {
        id: endpoint_id,
        generation: 1,
        project_id: project_id.to_owned(),
        realm: AddressRealm {
            id: realm_id,
            network_id: endpoint_id,
            project_id: project_id.to_owned(),
            prefix,
            overlapping_prefixes: false,
        },
        address_pools: Vec::new(),
        endpoints: vec![o3k_domain::EndpointIntent {
            id: endpoint_id,
            project_id: project_id.to_owned(),
            realm_id,
            mac: mac.to_owned(),
            fixed_ip,
            generation: 1,
        }],
        routes: Vec::new(),
        gateways: Vec::new(),
        egress: external_realm_id
            .map(|external_realm_id| {
                vec![o3k_domain::EgressIntent {
                    external_realm_id,
                    enabled: true,
                    nat: true,
                }]
            })
            .unwrap_or_default(),
        public_addresses: public_address
            .map(|public_address| {
                vec![o3k_domain::PublicAddressBindingIntent {
                    id: endpoint_id,
                    project_id: project_id.to_owned(),
                    public_address,
                    endpoint_id,
                    generation: 1,
                }]
            })
            .unwrap_or_default(),
        policies,
        state: o3k_domain::NetworkIntentState::Requested,
    };
    let mut capabilities: HashSet<NetworkCapability> = [
        NetworkCapability::Ipv4,
        NetworkCapability::EndpointAttachment,
    ]
    .into_iter()
    .collect();
    if public_address.is_some() {
        capabilities.insert(NetworkCapability::PublicAddressRealization);
    }
    if external_realm_id.is_some() {
        capabilities.insert(NetworkCapability::Routing);
        capabilities.insert(NetworkCapability::Nat);
    }
    if has_policies {
        capabilities.insert(NetworkCapability::StatefulPolicy);
    }
    let mut plan = compile_node_network_plan(
        &intent,
        node_id,
        operation_id,
        deadline_unix_ms,
        &capabilities,
        &[],
    )?;
    for default in policy_defaults {
        if default.endpoint_id != endpoint_id
            || default.policy_id.is_nil()
            || default.generation == 0
            || default.stateful_mode != PolicyStatefulMode::Stateful
        {
            return Err(NetworkPlanError::InvalidPolicy);
        }
        plan.resource_generations
            .insert(default.policy_id, default.generation);
        plan.intents.push(NetworkPlanIntent::PolicyDefault(default));
    }
    plan.intents
        .sort_by_key(|intent| serde_json::to_string(intent).unwrap_or_default());
    plan.fingerprint_sha256 = canonical_plan_fingerprint(&plan)?;
    Ok(plan)
}

/// Adds routing derived from the canonical L3Gateway graph to a complete
/// endpoint plan. The mutation is applied to the derived plan only; gateway
/// records remain the source of truth and the existing attachment-plan API
/// remains compatible for callers that have no gateway.
pub fn add_l3_gateway_routing(
    mut plan: NodeNetworkPlan,
    routes: Vec<o3k_domain::GatewayIntent>,
    egress: Vec<o3k_domain::EgressIntent>,
) -> Result<NodeNetworkPlan, NetworkPlanError> {
    if routes.is_empty() && egress.is_empty() {
        return Ok(plan);
    }
    plan.intents
        .extend(routes.into_iter().map(NetworkPlanIntent::Gateway));
    plan.intents
        .extend(egress.into_iter().map(NetworkPlanIntent::Egress));
    plan.intents
        .sort_by_key(|value| serde_json::to_string(value).unwrap_or_default());
    plan.fingerprint_sha256 = canonical_plan_fingerprint(&plan)?;
    Ok(plan)
}

/// Compiles one canonical intent into a stable semantic node plan. The
/// `realms` slice represents existing routed realms in the selected profile;
/// P9 rejects overlap before any provider mutation.
pub fn compile_node_network_plan(
    intent: &NetworkIntent,
    node_id: &str,
    operation_id: Uuid,
    deadline_unix_ms: u64,
    capabilities: &HashSet<NetworkCapability>,
    realms: &[AddressRealm],
) -> Result<NodeNetworkPlan, NetworkPlanError> {
    if node_id.is_empty() || intent.realm.project_id != intent.project_id {
        return Err(NetworkPlanError::OwnershipViolation);
    }
    let overlaps_existing_realm = realms
        .iter()
        .any(|realm| realm.id != intent.realm.id && realm.prefix.overlaps(intent.realm.prefix));
    if overlaps_existing_realm
        && (!intent.realm.overlapping_prefixes
            || !capabilities.contains(&NetworkCapability::OverlappingAddressRealms)
            || !capabilities.contains(&NetworkCapability::EncapsulationModes))
    {
        return Err(NetworkPlanError::OverlappingRealm);
    }
    require_capability(capabilities, NetworkCapability::Ipv4)?;
    require_capability(capabilities, NetworkCapability::EndpointAttachment)?;
    if !intent.routes.is_empty() {
        require_capability(capabilities, NetworkCapability::Routing)?;
    }
    if !intent.gateways.is_empty() {
        require_capability(capabilities, NetworkCapability::Routing)?;
    }
    if intent.egress.iter().any(|egress| egress.enabled) {
        require_capability(capabilities, NetworkCapability::Routing)?;
        if intent.egress.iter().any(|egress| egress.nat) {
            require_capability(capabilities, NetworkCapability::Nat)?;
        }
    }
    if !intent.public_addresses.is_empty() {
        require_capability(capabilities, NetworkCapability::PublicAddressRealization)?;
    }
    if !intent.policies.is_empty() {
        require_capability(capabilities, NetworkCapability::StatefulPolicy)?;
    }

    let mut generations = BTreeMap::new();
    let mut endpoint_addresses = HashSet::new();
    let mut endpoint_macs = HashSet::new();
    let gateway = intent
        .address_pools
        .iter()
        .find_map(|pool| pool.gateway)
        .or_else(|| {
            u32::from(intent.realm.prefix.network)
                .checked_add(1)
                .map(Ipv4Addr::from)
        })
        .ok_or(NetworkPlanError::InvalidAddressPool)?;
    for pool in &intent.address_pools {
        if pool.project_id != intent.project_id
            || pool.realm_id != intent.realm.id
            || pool.prefix.prefix_len < intent.realm.prefix.prefix_len
            || !intent.realm.prefix.contains(pool.prefix.network)
            || !pool.prefix.contains(pool.first_usable)
            || !pool.prefix.contains(pool.last_usable)
            || pool.first_usable == pool.prefix.network
            || pool.last_usable == pool.prefix.network
            || broadcast_address(pool.prefix).is_some_and(|broadcast| {
                pool.first_usable == broadcast || pool.last_usable == broadcast
            })
            || u32::from(pool.first_usable) > u32::from(pool.last_usable)
            || pool.gateway.is_some_and(|gateway| {
                !pool.prefix.contains(gateway)
                    || gateway == pool.prefix.network
                    || broadcast_address(pool.prefix).is_some_and(|broadcast| gateway == broadcast)
                    || u32::from(pool.first_usable) <= u32::from(gateway)
                        && u32::from(gateway) <= u32::from(pool.last_usable)
            })
            || u32::from(pool.first_usable) <= u32::from(gateway)
                && u32::from(gateway) <= u32::from(pool.last_usable)
        {
            return Err(NetworkPlanError::InvalidAddressPool);
        }
    }
    let mut intents =
        Vec::with_capacity(intent.endpoints.len() + intent.routes.len() + intent.policies.len());
    intents.push(NetworkPlanIntent::AddressRealm {
        realm_id: intent.realm.id,
        prefix: intent.realm.prefix,
        gateway,
    });
    for endpoint in &intent.endpoints {
        if endpoint.project_id != intent.project_id
            || !intent.realm.prefix.contains(endpoint.fixed_ip)
            || endpoint.fixed_ip == intent.realm.prefix.network
            || broadcast_address(intent.realm.prefix)
                .is_some_and(|broadcast| endpoint.fixed_ip == broadcast)
        {
            return Err(NetworkPlanError::AddressOutsideRealm);
        }
        let canonical_mac = endpoint.mac.to_ascii_lowercase();
        if !valid_mac(&canonical_mac) {
            return Err(NetworkPlanError::ConflictingEndpoint);
        }
        if generations
            .insert(endpoint.id, endpoint.generation)
            .is_some()
            || !endpoint_addresses.insert(endpoint.fixed_ip)
            || !endpoint_macs.insert(canonical_mac.clone())
            || endpoint.fixed_ip == gateway
        {
            return Err(NetworkPlanError::ConflictingEndpoint);
        }
        intents.push(NetworkPlanIntent::EndpointAttachment {
            endpoint_id: endpoint.id,
            mac: canonical_mac,
            fixed_ip: endpoint.fixed_ip,
            generation: endpoint.generation,
        });
        intents.push(NetworkPlanIntent::AddressAssignment {
            endpoint_id: endpoint.id,
            address: endpoint.fixed_ip,
            generation: endpoint.generation,
        });
    }
    let endpoint_ids: HashSet<Uuid> = generations.keys().copied().collect();
    let mut public_addresses = HashSet::new();
    for binding in &intent.public_addresses {
        if binding.project_id != intent.project_id
            || !endpoint_ids.contains(&binding.endpoint_id)
            || !public_addresses.insert(binding.public_address)
        {
            return Err(NetworkPlanError::OwnershipViolation);
        }
    }
    for policy in &intent.policies {
        if !endpoint_ids.contains(&policy.endpoint_id)
            || policy.ports.is_some_and(|ports| ports.start > ports.end)
            || policy.ports.is_some_and(|_| {
                matches!(
                    policy.protocol,
                    NetworkProtocol::Any | NetworkProtocol::Icmp
                )
            })
            || (matches!(policy.direction, PolicyDirection::Ingress)
                && policy.destination.is_some())
            || (matches!(policy.direction, PolicyDirection::Egress) && policy.source.is_some())
        {
            return Err(NetworkPlanError::InvalidPolicy);
        }
    }
    for gateway in &intent.gateways {
        if !gateway.external && !intent.realm.prefix.contains(gateway.gateway) {
            return Err(NetworkPlanError::AddressOutsideRealm);
        }
    }
    intents.extend(intent.routes.iter().cloned().map(NetworkPlanIntent::Route));
    intents.extend(
        intent
            .gateways
            .iter()
            .cloned()
            .map(NetworkPlanIntent::Gateway),
    );
    intents.extend(intent.egress.iter().cloned().map(NetworkPlanIntent::Egress));
    intents.extend(
        intent
            .public_addresses
            .iter()
            .cloned()
            .map(NetworkPlanIntent::PublicAddressBinding),
    );
    intents.extend(
        intent
            .policies
            .iter()
            .cloned()
            .map(NetworkPlanIntent::Policy),
    );
    intents.sort_by_key(|value| serde_json::to_string(value).unwrap_or_default());

    let unsigned = (
        &intent.id,
        node_id,
        &operation_id,
        &NODE_NETWORK_PLAN_SCHEMA_VERSION,
        &generations,
        &intents,
    );
    let bytes = serde_json::to_vec(&unsigned).map_err(|_| NetworkPlanError::Serialization)?;
    use sha2::{Digest, Sha256};
    let fingerprint_sha256 = format!("{:x}", Sha256::digest(bytes));
    Ok(NodeNetworkPlan {
        schema_version: NODE_NETWORK_PLAN_SCHEMA_VERSION,
        plan_id: intent.id,
        node_id: node_id.to_owned(),
        operation_id,
        deadline_unix_ms,
        resource_generations: generations,
        intents,
        fabric: None,
        gateway: None,
        fingerprint_sha256,
    })
}

/// Accepts an equivalent replay and rejects a payload change for the same
/// plan identity before an execution provider can mutate anything.
pub fn validate_plan_replay(
    existing: &NodeNetworkPlan,
    candidate: &NodeNetworkPlan,
) -> Result<(), NetworkPlanError> {
    let same_identity = existing.plan_id == candidate.plan_id
        && existing.node_id == candidate.node_id
        && existing.operation_id == candidate.operation_id;
    if same_identity
        && (existing.schema_version != candidate.schema_version
            || existing.fingerprint_sha256 != candidate.fingerprint_sha256)
    {
        return Err(NetworkPlanError::ConflictingPlan);
    }
    Ok(())
}

/// Recomputes the transport fingerprint from the semantic plan fields. The
/// executor uses this at the trust boundary so a caller cannot mark an
/// arbitrary mutated payload with a syntactically valid but unrelated hash.
pub fn canonical_plan_fingerprint(plan: &NodeNetworkPlan) -> Result<String, NetworkPlanError> {
    let mut intents = plan.intents.clone();
    let mut keyed = Vec::with_capacity(intents.len());
    for intent in intents.drain(..) {
        let key = serde_json::to_vec(&intent).map_err(|_| NetworkPlanError::Serialization)?;
        keyed.push((key, intent));
    }
    keyed.sort_by(|left, right| left.0.cmp(&right.0));
    intents = keyed.into_iter().map(|(_, intent)| intent).collect();
    let bytes = if let Some(fabric) = &plan.fabric {
        if let Some(gateway) = &plan.gateway {
            serde_json::to_vec(&(
                &plan.plan_id,
                &plan.node_id,
                &plan.operation_id,
                &plan.schema_version,
                &plan.resource_generations,
                &intents,
                gateway,
                fabric,
            ))
        } else {
            serde_json::to_vec(&(
                &plan.plan_id,
                &plan.node_id,
                &plan.operation_id,
                &plan.schema_version,
                &plan.resource_generations,
                &intents,
                fabric,
            ))
        }
    } else if let Some(gateway) = &plan.gateway {
        serde_json::to_vec(&(
            &plan.plan_id,
            &plan.node_id,
            &plan.operation_id,
            &plan.schema_version,
            &plan.resource_generations,
            &intents,
            gateway,
        ))
    } else {
        serde_json::to_vec(&(
            &plan.plan_id,
            &plan.node_id,
            &plan.operation_id,
            &plan.schema_version,
            &plan.resource_generations,
            &intents,
        ))
    }
    .map_err(|_| NetworkPlanError::Serialization)?;
    use sha2::{Digest, Sha256};
    Ok(format!("{:x}", Sha256::digest(bytes)))
}

fn broadcast_address(prefix: o3k_domain::Ipv4Prefix) -> Option<Ipv4Addr> {
    let host_bits = 32u32.saturating_sub(u32::from(prefix.prefix_len));
    let size = 1u64.checked_shl(host_bits)?;
    let value = u64::from(u32::from(prefix.network)) + size - 1;
    u32::try_from(value).ok().map(Ipv4Addr::from)
}

fn valid_mac(value: &str) -> bool {
    value.len() == 17
        && value.split(':').count() == 6
        && value
            .split(':')
            .all(|part| part.len() == 2 && part.bytes().all(|byte| byte.is_ascii_hexdigit()))
}

fn require_capability(
    capabilities: &HashSet<NetworkCapability>,
    capability: NetworkCapability,
) -> Result<(), NetworkPlanError> {
    capabilities
        .contains(&capability)
        .then_some(())
        .ok_or(NetworkPlanError::UnsupportedCapability(capability))
}

pub(crate) fn validate_policy_shape(policy: &PolicyIntent) -> Result<(), NetworkError> {
    if policy.id.is_nil()
        || policy.ports.is_some_and(|ports| ports.start > ports.end)
        || policy.ports.is_some_and(|_| {
            matches!(
                policy.protocol,
                NetworkProtocol::Any | NetworkProtocol::Icmp
            )
        })
        || (matches!(policy.direction, PolicyDirection::Ingress) && policy.destination.is_some())
        || (matches!(policy.direction, PolicyDirection::Egress) && policy.source.is_some())
    {
        return Err(NetworkError::InvalidRequest);
    }
    Ok(())
}

pub(crate) fn canonical_policy_record(
    project_id: &str,
    policy: &PolicyIntent,
) -> o3k_store::CanonicalNetworkPolicyRecord {
    let prefix = |value: Option<Ipv4Prefix>| {
        value.map(|prefix| format!("{}/{}", prefix.network, prefix.prefix_len))
    };
    o3k_store::CanonicalNetworkPolicyRecord {
        id: policy.id,
        project_id: project_id.to_owned(),
        endpoint_id: policy.endpoint_id,
        direction: format!("{:?}", policy.direction),
        protocol: format!("{:?}", policy.protocol),
        port_min: policy.ports.map(|ports| ports.start),
        port_max: policy.ports.map(|ports| ports.end),
        source: prefix(policy.source),
        destination: prefix(policy.destination),
        action: format!("{:?}", policy.action),
        generation: 1,
        state: "active".to_owned(),
    }
}

pub(crate) fn security_group_from_policy(
    policy: o3k_store::CanonicalReusableNetworkPolicyRecord,
) -> o3k_store::SecurityGroupRecord {
    o3k_store::SecurityGroupRecord {
        id: policy.id,
        project_id: policy.project_id,
        name: policy.name,
        description: policy.description,
    }
}

pub(crate) fn security_group_rule_from_policy(
    rule: o3k_store::CanonicalNetworkPolicyRuleRecord,
) -> o3k_store::SecurityGroupRuleRecord {
    o3k_store::SecurityGroupRuleRecord {
        id: rule.id,
        security_group_id: rule.policy_id,
        project_id: rule.project_id,
        direction: rule.direction.to_lowercase(),
        protocol: rule.protocol.to_lowercase(),
        port_min: rule.port_min,
        port_max: rule.port_max,
        remote_ip_prefix: rule.remote_selector,
    }
}

pub(crate) fn policy_from_canonical_record(
    record: o3k_store::CanonicalNetworkPolicyRecord,
) -> Result<PolicyIntent, NetworkError> {
    let parse_prefix = |value: Option<String>| {
        value
            .as_deref()
            .map(parse_security_group_prefix)
            .transpose()
    };
    let policy = PolicyIntent {
        id: record.id,
        endpoint_id: record.endpoint_id,
        direction: parse_security_group_direction(&record.direction)?,
        protocol: parse_security_group_protocol(&record.protocol)?,
        ports: record
            .port_min
            .zip(record.port_max)
            .map(|(start, end)| PortRange { start, end }),
        source: parse_prefix(record.source)?,
        destination: parse_prefix(record.destination)?,
        action: match record.action.as_str() {
            "Allow" | "allow" => PolicyAction::Allow,
            "Deny" | "deny" => PolicyAction::Deny,
            _ => return Err(NetworkError::InvalidRequest),
        },
    };
    validate_policy_shape(&policy)?;
    Ok(policy)
}
