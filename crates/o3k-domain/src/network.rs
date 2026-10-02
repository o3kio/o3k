use serde::{Deserialize, Serialize};
use std::{cmp::Ordering, net::Ipv4Addr};
use thiserror::Error;
use uuid::Uuid;

/// A canonical IPv4 prefix. The stored address is always the network address;
/// host bits are rejected so every serialized value has one representation.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub struct Ipv4Prefix {
    pub network: Ipv4Addr,
    pub prefix_len: u8,
}

impl Ipv4Prefix {
    pub fn new(address: Ipv4Addr, prefix_len: u8) -> Option<Self> {
        if prefix_len > 32 {
            return None;
        }
        let mask = if prefix_len == 0 {
            0
        } else {
            u32::MAX << (32 - prefix_len)
        };
        let value = u32::from(address) & mask;
        (value == u32::from(address)).then_some(Self {
            network: Ipv4Addr::from(value),
            prefix_len,
        })
    }

    #[must_use]
    pub fn contains(self, address: Ipv4Addr) -> bool {
        let mask = if self.prefix_len == 0 {
            0
        } else {
            u32::MAX << (32 - self.prefix_len)
        };
        u32::from(address) & mask == u32::from(self.network)
    }

    #[must_use]
    pub fn overlaps(self, other: Self) -> bool {
        self.contains(other.network) || other.contains(self.network)
    }
}

impl Ord for Ipv4Prefix {
    fn cmp(&self, other: &Self) -> Ordering {
        (self.network, self.prefix_len).cmp(&(other.network, other.prefix_len))
    }
}

impl PartialOrd for Ipv4Prefix {
    fn partial_cmp(&self, other: &Self) -> Option<Ordering> {
        Some(self.cmp(other))
    }
}

/// A project-owned address-isolation namespace. P9's routed profile sets
/// `overlapping_prefixes` to false; the field keeps future VRF/overlay realms
/// explicit without making non-overlap a global O3K invariant.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct AddressRealm {
    pub id: Uuid,
    pub network_id: Uuid,
    pub project_id: String,
    pub prefix: Ipv4Prefix,
    pub overlapping_prefixes: bool,
}

/// Canonical Network identity and lifecycle. This resource remains valid when
/// `realms` is empty; provider projections and execution plans are assembled
/// from its durable child resources rather than defining its identity.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Network {
    pub id: Uuid,
    pub project_id: String,
    pub name: String,
    pub generation: u64,
    pub state: NetworkState,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum NetworkState {
    Requested,
    Active,
    Deleting,
    Deleted,
    Error,
}

/// A bounded, project-owned allocation range within an address realm.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct AddressPool {
    pub id: Uuid,
    pub realm_id: Uuid,
    pub project_id: String,
    pub prefix: Ipv4Prefix,
    pub gateway: Option<Ipv4Addr>,
    pub first_usable: Ipv4Addr,
    pub last_usable: Ipv4Addr,
}

/// Provider-independent L3 connectivity identity. AddressRealm remains the
/// address interpretation and isolation identity; a gateway connects realms.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct L3Gateway {
    pub id: Uuid,
    pub project_id: String,
    pub name: String,
    pub external_realm_id: Option<Uuid>,
    pub enable_snat: bool,
    pub generation: u64,
    pub state: L3GatewayState,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum L3GatewayState {
    Requested,
    Active,
    Deleting,
    Deleted,
    Error,
}

/// Durable relation between an L3Gateway and an AddressRealm.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct L3GatewayAttachment {
    pub id: Uuid,
    pub gateway_id: Uuid,
    pub realm_id: Uuid,
    pub project_id: String,
    pub generation: u64,
    pub state: L3GatewayAttachmentState,
}

/// Provider-independent execution input for one canonical L3 gateway.
/// Unlike `NamespacedRoutedFabricPlan`, this plan may span multiple realms.
/// Provider-local names are derived behind the execution boundary.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct L3GatewayExecutionPlan {
    pub gateway_id: Uuid,
    pub project_id: String,
    pub gateway_generation: u64,
    pub attachments: Vec<L3GatewayExecutionAttachment>,
    pub external_realm_id: Option<Uuid>,
    /// Canonical external Realm address interpretation, when configured.
    /// Provider-local uplink/interface details remain outside this plan.
    #[serde(default)]
    pub external_realm_prefix: Option<Ipv4Prefix>,
    /// Canonical external Realm revision used to fence gateway execution.
    #[serde(default)]
    pub external_realm_generation: Option<u64>,
    pub enable_snat: bool,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct L3GatewayExecutionAttachment {
    pub attachment_id: Uuid,
    pub attachment_generation: u64,
    pub realm_id: Uuid,
    pub realm_generation: u64,
    pub realm_prefix: Ipv4Prefix,
    pub gateway_address: Ipv4Addr,
}

impl L3GatewayExecutionPlan {
    /// A summary marker only. The complete serialized plan is the identity.
    #[must_use]
    pub fn summary_generation(&self) -> u64 {
        self.attachments
            .iter()
            .map(|attachment| {
                attachment
                    .attachment_generation
                    .max(attachment.realm_generation)
            })
            .fold(self.gateway_generation, u64::max)
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum L3GatewayAttachmentState {
    Requested,
    Active,
    Deleting,
    Deleted,
    Error,
}

/// Canonical desired network state owned by the control plane.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct NetworkIntent {
    pub id: Uuid,
    pub project_id: String,
    pub realm: AddressRealm,
    pub address_pools: Vec<AddressPool>,
    pub endpoints: Vec<EndpointIntent>,
    pub routes: Vec<RouteIntent>,
    pub gateways: Vec<GatewayIntent>,
    pub egress: Vec<EgressIntent>,
    pub public_addresses: Vec<PublicAddressBindingIntent>,
    pub policies: Vec<PolicyIntent>,
    pub generation: u64,
    pub state: NetworkIntentState,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum NetworkIntentState {
    Requested,
    Active,
    Deleting,
    Error,
}

impl NetworkIntentState {
    pub fn transition(self, next: Self) -> Result<Self, &'static str> {
        let valid = matches!(
            (self, next),
            (Self::Requested, Self::Active)
                | (Self::Requested, Self::Deleting)
                | (Self::Requested, Self::Error)
                | (Self::Active, Self::Deleting)
                | (Self::Active, Self::Error)
                | (Self::Deleting, Self::Error)
        );
        valid
            .then_some(next)
            .ok_or("invalid network intent transition")
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct EndpointIntent {
    pub id: Uuid,
    pub project_id: String,
    pub realm_id: Uuid,
    pub mac: String,
    pub fixed_ip: Ipv4Addr,
    pub generation: u64,
}

/// Accepted control-plane placement for one endpoint. Provider names, ARP/FDB
/// observations, and kernel interface names are deliberately absent: this is
/// the semantic input from which a host-local provider plan is derived.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct EndpointLocation {
    pub endpoint_id: Uuid,
    pub project_id: String,
    pub realm_id: Uuid,
    pub fixed_ip: Ipv4Addr,
    pub mac: String,
    pub selected_host: String,
    pub endpoint_generation: u64,
    pub placement_generation: u64,
}

/// A deterministic, generation-bound directory used by providers to answer
/// only accepted same-realm neighbor requests and compile endpoint routes.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct RealmEndpointDirectory {
    pub realm_id: Uuid,
    /// Accepted tenant prefix carried into the provider plan. Providers use
    /// it to build realm-local routes; they never reconstruct it from kernel
    /// observations.
    pub prefix: Ipv4Prefix,
    pub directory_generation: u64,
    pub proxy_mac: String,
    pub entries: Vec<EndpointLocation>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum NeighborResolution {
    LocalActualMac(String),
    /// The canonical MAC of a current endpoint on another enrolled host.
    /// VXLAN stretches the realm L2 segment, so ARP is answered by the
    /// endpoint itself and no realm proxy MAC is synthesized.
    RemoteActualMac(String),
    Unknown,
}

/// Bounded public identity for one accepted host fabric enrollment. Private
/// transport keys are intentionally not representable in this value.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct FabricHostIdentity {
    pub host_id: String,
    pub public_key: String,
    pub underlay_endpoint: String,
    /// Provider/operator transport address. This is never a tenant address
    /// and is the only address used for shared WireGuard peer routing.
    pub fabric_transport_ip: Ipv4Addr,
    pub provider_version: String,
    pub fabric_generation: u64,
    pub underlay_mtu: u16,
    pub fabric_mtu: u16,
}

/// Semantic route intent for a remote endpoint. The provider may realize this
/// as a host-local IPv4 /32 route, but the route never becomes endpoint
/// authority by itself.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct FabricEndpointRoute {
    pub realm_id: Uuid,
    pub destination: Ipv4Prefix,
    pub endpoint_id: Uuid,
    pub target_host: String,
    pub target_fabric_transport_ip: Ipv4Addr,
    pub endpoint_generation: u64,
    pub placement_generation: u64,
    pub realm_binding_generation: u64,
    pub fabric_generation: u64,
}

/// Provider-derived public peer state for the shared host fabric. WireGuard
/// routes only the unique provider transport address, never tenant endpoint
/// prefixes. Realm and endpoint destinations are selected by the realm VNI and
/// canonical endpoint directory; the shared WireGuard peer routes only host
/// transport addresses.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct FabricPeer {
    pub host_id: String,
    pub public_key: String,
    pub underlay_endpoint: String,
    pub fabric_transport_ip: Ipv4Addr,
    pub fabric_generation: u64,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum FabricProviderKind {
    Vxlan,
    /// Historical v2 value retained only for deserializing old plans.  New
    /// plans must use `vxlan`; the Linux executor rejects Geneve state.
    Geneve,
}

/// Durable provider mapping that carries AddressRealm identity across hosts.
/// The segment identifier is provider-native state; callers never supply it
/// as tenant input.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct RealmEncapsulationBinding {
    pub fabric_domain_id: Uuid,
    pub realm_id: Uuid,
    pub provider_kind: FabricProviderKind,
    pub provider_segment_id: u32,
    pub binding_generation: u64,
}

/// Legacy provider-independent metadata retained only to deserialize v2 plans;
/// the v3 Linux executor does not use it. A v3 ingress path must authenticate and
/// validate before accepting or emitting a known-unicast packet. The inner IP
/// is deliberately accompanied by realm, endpoint, placement, and transport
/// identity; it is never sufficient on its own.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct GenevePacketMetadata {
    pub realm_id: Uuid,
    pub vni: u32,
    pub source_endpoint_id: Uuid,
    pub source_ip: Ipv4Addr,
    pub source_mac: String,
    pub source_host: String,
    pub source_fabric_transport_ip: Ipv4Addr,
    pub source_fabric_generation: u64,
    pub source_endpoint_generation: u64,
    pub source_placement_generation: u64,
    pub destination_ip: Ipv4Addr,
    pub destination_host: String,
    pub destination_fabric_transport_ip: Ipv4Addr,
    pub destination_fabric_generation: u64,
    pub destination_endpoint_generation: u64,
    pub destination_placement_generation: u64,
    pub realm_binding_generation: u64,
    pub policy_generation: u64,
    pub protocol: NetworkProtocol,
    pub source_port: Option<u16>,
    pub destination_port: Option<u16>,
}

#[derive(Debug, Error, Clone, PartialEq, Eq)]
pub enum GenevePacketValidationError {
    #[error("Geneve packet realm binding is invalid")]
    InvalidBinding,
    #[error("Geneve packet source endpoint is not current local authority")]
    InvalidSource,
    #[error("Geneve packet destination is not current realm authority")]
    InvalidDestination,
    #[error("Geneve packet route or host transport identity is stale")]
    StaleRoute,
    #[error("Geneve packet endpoint or host identity is ambiguous")]
    AmbiguousIdentity,
    #[error("Geneve packet NetworkPolicy generation is stale")]
    StalePolicy,
    #[error("Geneve packet is denied by NetworkPolicy")]
    PolicyDenied,
}

impl RealmEncapsulationBinding {
    pub fn validate(&self) -> Result<(), RealmBindingError> {
        if self.fabric_domain_id == Uuid::nil() || self.realm_id == Uuid::nil() {
            return Err(RealmBindingError::InvalidIdentity);
        }
        if self.provider_segment_id == 0 || self.provider_segment_id > 0x000f_ffff {
            return Err(RealmBindingError::InvalidSegment);
        }
        if self.binding_generation == 0 {
            return Err(RealmBindingError::InvalidGeneration);
        }
        Ok(())
    }
}

#[derive(Debug, Error, Clone, PartialEq, Eq)]
pub enum RealmBindingError {
    #[error("realm encapsulation binding has an invalid identity")]
    InvalidIdentity,
    #[error("realm encapsulation provider segment is outside the VXLAN VNI range")]
    InvalidSegment,
    #[error("realm encapsulation binding generation must be non-zero")]
    InvalidGeneration,
    #[error("realm encapsulation mapping conflicts with an active realm")]
    RealmConflict,
    #[error("realm encapsulation segment is already bound to another active realm")]
    SegmentConflict,
    #[error("realm encapsulation mapping is stale")]
    StaleGeneration,
    #[error("realm encapsulation state is not proven absent")]
    StateNotProvenAbsent,
}

/// Small, serializable semantic registry for the durable realm-to-provider
/// mapping. A persistence adapter must store this state before mutating
/// VXLAN objects; the registry itself never observes kernel state.
#[derive(Debug, Clone, PartialEq, Eq, Default, Serialize, Deserialize)]
pub struct RealmEncapsulationRegistry {
    pub bindings: Vec<RealmEncapsulationBinding>,
}

impl NamespacedRoutedFabricPlan {
    /// Replaces the policy snapshot with the accepted canonical generation.
    /// Policy rules remain semantic input; no provider rule names or kernel
    /// handles are accepted here.
    pub fn with_policy_snapshot(
        mut self,
        policy_generation: u64,
        policies: Vec<PolicyIntent>,
    ) -> Result<Self, EndpointDirectoryError> {
        if policy_generation == 0
            || policies.iter().any(|policy| {
                policy.id == Uuid::nil()
                    || policy.endpoint_id == Uuid::nil()
                    || !self
                        .directory
                        .entries
                        .iter()
                        .any(|entry| entry.endpoint_id == policy.endpoint_id)
            })
        {
            return Err(EndpointDirectoryError::InvalidPolicy);
        }
        self.policy_generation = policy_generation;
        self.policies = policies;
        self.policy_defaults.clear();
        Ok(self)
    }

    /// Replaces a complete derived snapshot compiled from reusable canonical
    /// policies, including per-endpoint unmatched action semantics.
    pub fn with_canonical_policy_snapshot(
        mut self,
        policy_generation: u64,
        defaults: Vec<PolicyDefaultIntent>,
        policies: Vec<PolicyIntent>,
    ) -> Result<Self, EndpointDirectoryError> {
        self = self.with_policy_snapshot(policy_generation, policies)?;
        let mut default_endpoints = std::collections::BTreeSet::new();
        if defaults.iter().any(|default| {
            default.policy_id.is_nil()
                || default.endpoint_id.is_nil()
                || default.generation == 0
                || default.stateful_mode != PolicyStatefulMode::Stateful
                || !default_endpoints.insert(default.endpoint_id)
                || !self
                    .directory
                    .entries
                    .iter()
                    .any(|entry| entry.endpoint_id == default.endpoint_id)
        }) {
            return Err(EndpointDirectoryError::InvalidPolicy);
        }
        self.policy_defaults = defaults;
        Ok(self)
    }

    /// Replaces the canonical public-address snapshot for this realm.
    pub fn with_public_snapshot(
        mut self,
        bindings: Vec<PublicAddressBindingIntent>,
    ) -> Result<Self, EndpointDirectoryError> {
        validate_public_bindings(&self.directory, &bindings)?;
        self.public_bindings = bindings;
        Ok(self)
    }

    fn validate_packet_binding(
        &self,
        packet: &GenevePacketMetadata,
    ) -> Result<(), GenevePacketValidationError> {
        if packet.realm_id != self.realm_id
            || packet.vni != self.encapsulation.provider_segment_id
            || packet.realm_binding_generation != self.encapsulation.binding_generation
        {
            return Err(GenevePacketValidationError::InvalidBinding);
        }
        self.encapsulation
            .validate()
            .map_err(|_| GenevePacketValidationError::InvalidBinding)
    }

    fn validate_packet_policy(
        &self,
        packet: &GenevePacketMetadata,
        destination_endpoint_id: Uuid,
    ) -> Result<(), GenevePacketValidationError> {
        if packet.policy_generation != self.policy_generation || self.policy_generation == 0 {
            return Err(GenevePacketValidationError::StalePolicy);
        }

        let mut matched_allow = false;
        for policy in &self.policies {
            let (endpoint_id, direction, address) = if policy.direction == PolicyDirection::Egress {
                (
                    packet.source_endpoint_id,
                    PolicyDirection::Egress,
                    packet.destination_ip,
                )
            } else {
                (
                    destination_endpoint_id,
                    PolicyDirection::Ingress,
                    packet.source_ip,
                )
            };
            if policy.endpoint_id != endpoint_id || policy.direction != direction {
                continue;
            }
            if !policy.protocol_matches(packet.protocol)
                || !policy.ports_match(packet.destination_port)
                || !policy.prefix_matches(address)
            {
                continue;
            }
            if policy.action == PolicyAction::Deny {
                return Err(GenevePacketValidationError::PolicyDenied);
            }
            matched_allow = true;
        }

        if matched_allow {
            return Ok(());
        }
        if self
            .policy_defaults
            .iter()
            .find(|default| {
                default.endpoint_id == destination_endpoint_id
                    || default.endpoint_id == packet.source_endpoint_id
            })
            .is_some_and(|default| default.unmatched_action == PolicyAction::Deny)
        {
            return Err(GenevePacketValidationError::PolicyDenied);
        }
        // No attached policy, or an attached Allow-default policy, preserves
        // the existing stateful baseline for unmatched traffic.
        Ok(())
    }

    /// Validates a known-unicast Geneve packet before egress encapsulation.
    /// The canonical policy snapshot is checked after realm/endpoint/placement
    /// authority and before a provider may emit the packet.
    pub fn validate_geneve_egress(
        &self,
        packet: &GenevePacketMetadata,
    ) -> Result<(), GenevePacketValidationError> {
        self.validate_packet_binding(packet)?;
        let source = self
            .directory
            .entries
            .iter()
            .filter(|entry| entry.endpoint_id == packet.source_endpoint_id)
            .collect::<Vec<_>>();
        if source.len() != 1 {
            return Err(GenevePacketValidationError::AmbiguousIdentity);
        }
        let source = source[0];
        if source.selected_host != self.local_host
            || source.fixed_ip != packet.source_ip
            || source.mac
                != canonical_mac(&packet.source_mac)
                    .ok_or(GenevePacketValidationError::InvalidSource)?
            || packet.source_host != self.local_host
            || packet.source_fabric_generation != self.local_fabric_generation
            || packet.source_endpoint_generation != source.endpoint_generation
            || packet.source_placement_generation != source.placement_generation
        {
            return Err(GenevePacketValidationError::InvalidSource);
        }
        let Some(route) = self.routes.iter().find(|route| {
            route.destination.network == packet.destination_ip
                && route.target_host == packet.destination_host
                && route.target_fabric_transport_ip == packet.destination_fabric_transport_ip
        }) else {
            return Err(GenevePacketValidationError::InvalidDestination);
        };
        if route.fabric_generation != packet.destination_fabric_generation
            || route.realm_id != packet.realm_id
            || route.realm_binding_generation != packet.realm_binding_generation
            || route.endpoint_generation != packet.destination_endpoint_generation
            || route.placement_generation != packet.destination_placement_generation
        {
            return Err(GenevePacketValidationError::StaleRoute);
        }
        let destination_endpoint = self
            .directory
            .entries
            .iter()
            .filter(|entry| {
                entry.fixed_ip == packet.destination_ip
                    && entry.selected_host == packet.destination_host
            })
            .collect::<Vec<_>>();
        if destination_endpoint.len() != 1 {
            return Err(GenevePacketValidationError::AmbiguousIdentity);
        }
        self.validate_packet_policy(packet, destination_endpoint[0].endpoint_id)?;
        Ok(())
    }

    /// Validates a known-unicast Geneve packet after host transport
    /// authentication and before delivery to a local endpoint.
    pub fn validate_geneve_ingress(
        &self,
        packet: &GenevePacketMetadata,
    ) -> Result<(), GenevePacketValidationError> {
        self.validate_packet_binding(packet)?;
        let Some(peer) = self.peers.iter().find(|peer| {
            peer.host_id == packet.source_host
                && peer.fabric_transport_ip == packet.source_fabric_transport_ip
        }) else {
            return Err(GenevePacketValidationError::InvalidSource);
        };
        if peer.fabric_generation != packet.source_fabric_generation {
            return Err(GenevePacketValidationError::StaleRoute);
        }
        let destinations = self
            .directory
            .entries
            .iter()
            .filter(|entry| entry.fixed_ip == packet.destination_ip)
            .collect::<Vec<_>>();
        if destinations.len() != 1 {
            return Err(GenevePacketValidationError::AmbiguousIdentity);
        }
        let destination = destinations[0];
        if destination.selected_host != self.local_host
            || packet.destination_host != self.local_host
            || packet.destination_fabric_transport_ip != self.local_fabric_transport_ip
            || destination.endpoint_generation != packet.destination_endpoint_generation
            || destination.placement_generation != packet.destination_placement_generation
            || packet.destination_fabric_generation != self.local_fabric_generation
        {
            return Err(GenevePacketValidationError::InvalidDestination);
        }
        let source = self
            .directory
            .entries
            .iter()
            .filter(|entry| entry.endpoint_id == packet.source_endpoint_id)
            .collect::<Vec<_>>();
        if source.len() != 1 {
            return Err(GenevePacketValidationError::AmbiguousIdentity);
        }
        let source = source[0];
        if source.selected_host != packet.source_host
            || source.fixed_ip != packet.source_ip
            || source.mac
                != canonical_mac(&packet.source_mac)
                    .ok_or(GenevePacketValidationError::InvalidSource)?
            || source.endpoint_generation != packet.source_endpoint_generation
            || source.placement_generation != packet.source_placement_generation
        {
            return Err(GenevePacketValidationError::InvalidSource);
        }
        self.validate_packet_policy(packet, destination.endpoint_id)?;
        Ok(())
    }
}

impl RealmEncapsulationRegistry {
    pub fn ensure(
        &mut self,
        fabric_domain_id: Uuid,
        realm_id: Uuid,
        binding_generation: u64,
    ) -> Result<RealmEncapsulationBinding, RealmBindingError> {
        if fabric_domain_id == Uuid::nil() || realm_id == Uuid::nil() || binding_generation == 0 {
            return Err(RealmBindingError::InvalidIdentity);
        }
        if let Some(binding) = self.bindings.iter_mut().find(|binding| {
            binding.fabric_domain_id == fabric_domain_id && binding.realm_id == realm_id
        }) {
            if binding_generation < binding.binding_generation {
                return Err(RealmBindingError::StaleGeneration);
            }
            binding.binding_generation = binding_generation;
            return Ok(binding.clone());
        }
        let segment = (1..=0x000f_ffffu32)
            .find(|segment| {
                !self.bindings.iter().any(|binding| {
                    binding.fabric_domain_id == fabric_domain_id
                        && binding.provider_segment_id == *segment
                })
            })
            .ok_or(RealmBindingError::SegmentConflict)?;
        let binding = RealmEncapsulationBinding {
            fabric_domain_id,
            realm_id,
            provider_kind: FabricProviderKind::Vxlan,
            provider_segment_id: segment,
            binding_generation,
        };
        binding.validate()?;
        self.bindings.push(binding.clone());
        self.bindings
            .sort_by_key(|binding| (binding.fabric_domain_id, binding.realm_id));
        Ok(binding)
    }

    pub fn release(
        &mut self,
        binding: &RealmEncapsulationBinding,
        provider_state_absent: bool,
    ) -> Result<(), RealmBindingError> {
        binding.validate()?;
        if !provider_state_absent {
            return Err(RealmBindingError::StateNotProvenAbsent);
        }
        let Some(index) = self.bindings.iter().position(|current| current == binding) else {
            return Err(RealmBindingError::RealmConflict);
        };
        self.bindings.remove(index);
        Ok(())
    }
}

/// Semantic P11 plan for one host and one AddressRealm. Provider realizers may
/// map it to bridges, realm namespaces, routes, proxy neighbors, nftables and
/// WireGuard state, but none of those mappings are represented here.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct NamespacedRoutedFabricPlan {
    pub local_host: String,
    pub local_fabric_transport_ip: Ipv4Addr,
    pub local_fabric_generation: u64,
    pub local_underlay_mtu: u16,
    pub local_fabric_mtu: u16,
    pub realm_id: Uuid,
    pub realm_prefix: Ipv4Prefix,
    pub encapsulation: RealmEncapsulationBinding,
    pub directory_generation: u64,
    pub directory: RealmEndpointDirectory,
    pub proxy_mac: String,
    pub tenant_mtu: u16,
    /// Derived policy generation and endpoint rules compiled from canonical
    /// reusable policies. Providers may derive nftables/nft flow state from
    /// this snapshot, but may not authorize a packet from observations alone.
    #[serde(default = "default_policy_generation")]
    pub policy_generation: u64,
    #[serde(default)]
    pub policies: Vec<PolicyIntent>,
    /// Derived per-endpoint unmatched semantics from reusable canonical
    /// policies. Empty preserves the legacy no-policy baseline.
    #[serde(default)]
    pub policy_defaults: Vec<PolicyDefaultIntent>,
    /// Canonical public-address bindings admitted for this realm. Public
    /// addresses are provider input; the provider derives all NAT state and
    /// never keys tenant ownership by private IP alone.
    #[serde(default)]
    pub public_bindings: Vec<PublicAddressBindingIntent>,
    pub routes: Vec<FabricEndpointRoute>,
    pub peers: Vec<FabricPeer>,
}

fn default_policy_generation() -> u64 {
    1
}

#[derive(Debug, Error, Clone, PartialEq, Eq)]
pub enum EndpointDirectoryError {
    #[error("endpoint directory generation must be non-zero")]
    InvalidDirectoryGeneration,
    #[error("endpoint location has an empty project, host, or identity")]
    InvalidIdentity,
    #[error("endpoint location generation must be non-zero")]
    InvalidGeneration,
    #[error("endpoint location is outside the address realm")]
    OutsideRealm,
    #[error("endpoint location belongs to a different project or realm")]
    ScopeMismatch,
    #[error("endpoint directory contains a duplicate endpoint, address, or MAC")]
    DuplicateEndpoint,
    #[error("endpoint MAC is not a canonical unicast MAC address")]
    InvalidMac,
    #[error("realm proxy MAC collides with occupied provider state")]
    ProxyMacCollision,
    #[error("host fabric identity is missing or stale")]
    MissingFabricIdentity,
    #[error("host fabric identity is duplicated or invalid")]
    InvalidFabricIdentity,
    #[error("host fabric transport address is duplicated or invalid")]
    InvalidFabricTransportAddress,
    #[error("realm encapsulation binding is invalid or out of scope")]
    InvalidRealmBinding,
    #[error("fabric plan has no local host identity")]
    MissingLocalFabricIdentity,
    #[error("fabric plan has an invalid or unsafe tenant MTU")]
    InvalidMtu,
    #[error("NetworkPolicy snapshot is invalid or references an unknown endpoint")]
    InvalidPolicy,
}

fn validate_public_bindings(
    directory: &RealmEndpointDirectory,
    bindings: &[PublicAddressBindingIntent],
) -> Result<(), EndpointDirectoryError> {
    let mut public_addresses = std::collections::BTreeSet::new();
    let mut endpoints = std::collections::BTreeSet::new();
    for binding in bindings {
        if binding.id.is_nil()
            || binding.project_id.is_empty()
            || binding.generation == 0
            || binding.public_address.is_unspecified()
            || !directory
                .location(binding.endpoint_id)
                .is_some_and(|endpoint| endpoint.project_id == binding.project_id)
            || !public_addresses.insert(binding.public_address)
            || !endpoints.insert(binding.endpoint_id)
        {
            return Err(EndpointDirectoryError::InvalidPolicy);
        }
    }
    Ok(())
}

impl RealmEndpointDirectory {
    /// Builds deterministic planner state from accepted endpoint placement.
    /// `occupied_macs` represents provider-local MAC state that must not be
    /// collided with; it is never used as an authority source.
    pub fn build(
        realm: &AddressRealm,
        mut entries: Vec<EndpointLocation>,
        occupied_macs: &[String],
        directory_generation: u64,
    ) -> Result<Self, EndpointDirectoryError> {
        if directory_generation == 0 {
            return Err(EndpointDirectoryError::InvalidDirectoryGeneration);
        }
        let proxy_mac = realm_proxy_mac(realm.id);
        let mut endpoint_ids = std::collections::BTreeSet::new();
        let mut addresses = std::collections::BTreeSet::new();
        let mut macs = std::collections::BTreeSet::new();
        for entry in &mut entries {
            if entry.project_id.is_empty()
                || entry.selected_host.is_empty()
                || entry.endpoint_id == Uuid::nil()
            {
                return Err(EndpointDirectoryError::InvalidIdentity);
            }
            if entry.endpoint_generation == 0 || entry.placement_generation == 0 {
                return Err(EndpointDirectoryError::InvalidGeneration);
            }
            if entry.project_id != realm.project_id || entry.realm_id != realm.id {
                return Err(EndpointDirectoryError::ScopeMismatch);
            }
            if !realm.prefix.contains(entry.fixed_ip) {
                return Err(EndpointDirectoryError::OutsideRealm);
            }
            entry.mac = canonical_mac(&entry.mac).ok_or(EndpointDirectoryError::InvalidMac)?;
            if !endpoint_ids.insert(entry.endpoint_id)
                || !addresses.insert(entry.fixed_ip)
                || !macs.insert(entry.mac.clone())
            {
                return Err(EndpointDirectoryError::DuplicateEndpoint);
            }
        }
        if macs.contains(&proxy_mac) {
            return Err(EndpointDirectoryError::ProxyMacCollision);
        }
        for occupied_mac in occupied_macs {
            let occupied_mac =
                canonical_mac(occupied_mac).ok_or(EndpointDirectoryError::InvalidMac)?;
            if occupied_mac == proxy_mac {
                return Err(EndpointDirectoryError::ProxyMacCollision);
            }
        }
        entries.sort_by_key(|entry| (entry.fixed_ip, entry.endpoint_id));
        Ok(Self {
            realm_id: realm.id,
            prefix: realm.prefix,
            directory_generation,
            proxy_mac,
            entries,
        })
    }

    #[must_use]
    pub fn resolve_neighbor(&self, destination: Ipv4Addr, local_host: &str) -> NeighborResolution {
        if local_host.is_empty() {
            return NeighborResolution::Unknown;
        }
        let Some(entry) = self
            .entries
            .iter()
            .find(|entry| entry.fixed_ip == destination)
        else {
            return NeighborResolution::Unknown;
        };
        if entry.selected_host == local_host {
            NeighborResolution::LocalActualMac(entry.mac.clone())
        } else {
            NeighborResolution::RemoteActualMac(entry.mac.clone())
        }
    }

    #[must_use]
    pub fn location(&self, endpoint_id: Uuid) -> Option<&EndpointLocation> {
        self.entries
            .iter()
            .find(|entry| entry.endpoint_id == endpoint_id)
    }

    /// Derives only current remote endpoint routes for `local_host`.
    pub fn remote_routes(
        &self,
        local_host: &str,
        host_identities: &[FabricHostIdentity],
        binding: &RealmEncapsulationBinding,
    ) -> Result<Vec<FabricEndpointRoute>, EndpointDirectoryError> {
        if local_host.is_empty() {
            return Err(EndpointDirectoryError::InvalidIdentity);
        }
        if binding.realm_id != self.realm_id || binding.validate().is_err() {
            return Err(EndpointDirectoryError::InvalidRealmBinding);
        }
        let mut hosts = std::collections::BTreeSet::new();
        let mut transport_ips = std::collections::BTreeSet::new();
        for host in host_identities {
            if host.host_id.is_empty()
                || host.public_key.is_empty()
                || host.underlay_endpoint.is_empty()
                || host.provider_version.is_empty()
                || host.fabric_transport_ip.is_unspecified()
                || host.fabric_transport_ip.is_loopback()
                || host.fabric_generation == 0
                || host.underlay_mtu == 0
                || host.fabric_mtu == 0
                || host.fabric_mtu > host.underlay_mtu
                || !hosts.insert(host.host_id.as_str())
            {
                return Err(EndpointDirectoryError::InvalidFabricIdentity);
            }
            if !transport_ips.insert(host.fabric_transport_ip) {
                return Err(EndpointDirectoryError::InvalidFabricTransportAddress);
            }
        }

        let mut routes = Vec::new();
        for entry in &self.entries {
            if entry.selected_host == local_host {
                continue;
            }
            let Some(host) = host_identities
                .iter()
                .find(|host| host.host_id == entry.selected_host)
            else {
                return Err(EndpointDirectoryError::MissingFabricIdentity);
            };
            let Some(destination) = Ipv4Prefix::new(entry.fixed_ip, 32) else {
                return Err(EndpointDirectoryError::OutsideRealm);
            };
            routes.push(FabricEndpointRoute {
                realm_id: self.realm_id,
                destination,
                endpoint_id: entry.endpoint_id,
                target_host: entry.selected_host.clone(),
                target_fabric_transport_ip: host.fabric_transport_ip,
                endpoint_generation: entry.endpoint_generation,
                placement_generation: entry.placement_generation,
                realm_binding_generation: binding.binding_generation,
                fabric_generation: host.fabric_generation,
            });
        }
        routes.sort_by_key(|route| (route.destination, route.endpoint_id));
        Ok(routes)
    }

    /// Compiles the accepted directory and public host identities into one
    /// host/realm semantic plan. The local host is never emitted as a fabric
    /// peer; peer transport identity is the unique host-fabric address, while
    /// endpoint /32 routes remain legacy metadata; v3 same-realm forwarding is
    /// provided by VXLAN learning and HER.
    pub fn compile_fabric_plan(
        &self,
        local_identity: &FabricHostIdentity,
        host_identities: &[FabricHostIdentity],
        tenant_mtu: u16,
        binding: &RealmEncapsulationBinding,
    ) -> Result<NamespacedRoutedFabricPlan, EndpointDirectoryError> {
        if local_identity.host_id.is_empty() {
            return Err(EndpointDirectoryError::MissingLocalFabricIdentity);
        }
        // The host transport is IPv4 WireGuard in the accepted edge profile:
        // 60 bytes of WireGuard overhead followed by 50 bytes of VXLAN/L2
        // encapsulation.  Keep the derivation explicit so a near-boundary
        // packet cannot be admitted against an unverified conservative value.
        let expected_local_fabric_mtu = local_identity.underlay_mtu.checked_sub(60);
        let expected_tenant_mtu = expected_local_fabric_mtu.and_then(|mtu| mtu.checked_sub(50));
        if expected_local_fabric_mtu != Some(local_identity.fabric_mtu)
            || expected_tenant_mtu != Some(tenant_mtu)
        {
            return Err(EndpointDirectoryError::InvalidMtu);
        }
        if host_identities.iter().any(|identity| {
            identity.fabric_mtu != identity.underlay_mtu.saturating_sub(60)
                || identity.fabric_mtu != local_identity.fabric_mtu
        }) {
            return Err(EndpointDirectoryError::InvalidMtu);
        }
        if host_identities
            .iter()
            .all(|identity| identity != local_identity)
        {
            return Err(EndpointDirectoryError::MissingLocalFabricIdentity);
        }
        let routes = self.remote_routes(&local_identity.host_id, host_identities, binding)?;
        let mut peers = Vec::new();
        for identity in host_identities {
            if identity.host_id == local_identity.host_id {
                continue;
            }
            if !routes
                .iter()
                .any(|route| route.target_host == identity.host_id)
            {
                continue;
            }
            peers.push(FabricPeer {
                host_id: identity.host_id.clone(),
                public_key: identity.public_key.clone(),
                underlay_endpoint: identity.underlay_endpoint.clone(),
                fabric_transport_ip: identity.fabric_transport_ip,
                fabric_generation: identity.fabric_generation,
            });
        }
        peers.sort_by_key(|peer| peer.host_id.clone());
        Ok(NamespacedRoutedFabricPlan {
            local_host: local_identity.host_id.clone(),
            local_fabric_transport_ip: local_identity.fabric_transport_ip,
            local_fabric_generation: local_identity.fabric_generation,
            local_underlay_mtu: local_identity.underlay_mtu,
            local_fabric_mtu: local_identity.fabric_mtu,
            realm_id: self.realm_id,
            realm_prefix: self.prefix,
            encapsulation: binding.clone(),
            directory_generation: self.directory_generation,
            directory: self.clone(),
            proxy_mac: self.proxy_mac.clone(),
            tenant_mtu,
            policy_generation: default_policy_generation(),
            policies: Vec::new(),
            policy_defaults: Vec::new(),
            public_bindings: Vec::new(),
            routes,
            peers,
        })
    }
}

/// Versioned deterministic provider mapping for remote same-realm ARP. The
/// result is locally administered and unicast; it is never a VM endpoint ID.
#[must_use]
pub fn realm_proxy_mac(realm_id: Uuid) -> String {
    const VERSION: u8 = 1;
    let mut hash = 0xcbf29ce484222325u64 ^ u64::from(VERSION);
    for byte in realm_id.as_bytes() {
        hash ^= u64::from(*byte);
        hash = hash.wrapping_mul(0x100000001b3);
    }
    let bytes = [
        0x02,
        (hash >> 32) as u8,
        (hash >> 24) as u8,
        (hash >> 16) as u8,
        (hash >> 8) as u8,
        hash as u8,
    ];
    format!(
        "{:02x}:{:02x}:{:02x}:{:02x}:{:02x}:{:02x}",
        bytes[0], bytes[1], bytes[2], bytes[3], bytes[4], bytes[5]
    )
}

fn canonical_mac(value: &str) -> Option<String> {
    let bytes = value
        .split(':')
        .map(|part| (part.len() == 2).then(|| u8::from_str_radix(part, 16).ok())?)
        .collect::<Option<Vec<_>>>()?;
    if bytes.len() != 6 || bytes[0] & 1 != 0 {
        return None;
    }
    Some(
        bytes
            .iter()
            .map(|byte| format!("{byte:02x}"))
            .collect::<Vec<_>>()
            .join(":"),
    )
}

#[cfg(test)]
#[allow(clippy::expect_used, clippy::panic)]
mod endpoint_directory_tests {
    use super::*;

    fn realm() -> AddressRealm {
        AddressRealm {
            id: Uuid::from_u128(1),
            network_id: Uuid::from_u128(0x10),
            project_id: "project-a".to_owned(),
            prefix: Ipv4Prefix {
                network: Ipv4Addr::new(10, 40, 1, 0),
                prefix_len: 24,
            },
            overlapping_prefixes: false,
        }
    }

    fn location(id: u128, ip: [u8; 4], host: &str, mac: &str) -> EndpointLocation {
        EndpointLocation {
            endpoint_id: Uuid::from_u128(id),
            project_id: "project-a".to_owned(),
            realm_id: Uuid::from_u128(1),
            fixed_ip: Ipv4Addr::from(ip),
            mac: mac.to_owned(),
            selected_host: host.to_owned(),
            endpoint_generation: 1,
            placement_generation: 1,
        }
    }

    #[test]
    fn directory_sorts_entries_and_resolves_local_or_remote_neighbors() {
        let directory = RealmEndpointDirectory::build(
            &realm(),
            vec![
                location(2, [10, 40, 1, 12], "host-07", "02:00:00:00:00:12"),
                location(1, [10, 40, 1, 10], "host-01", "02:00:00:00:00:10"),
            ],
            &[],
            3,
        );
        assert!(directory.is_ok());
        let Some(directory) = directory.ok() else {
            return;
        };
        assert_eq!(directory.entries[0].fixed_ip, Ipv4Addr::new(10, 40, 1, 10));
        assert_eq!(
            directory.resolve_neighbor(Ipv4Addr::new(10, 40, 1, 10), "host-01"),
            NeighborResolution::LocalActualMac("02:00:00:00:00:10".to_owned())
        );
        assert_eq!(
            directory.resolve_neighbor(Ipv4Addr::new(10, 40, 1, 12), "host-01"),
            NeighborResolution::RemoteActualMac("02:00:00:00:00:12".to_owned())
        );
        assert_eq!(
            directory.resolve_neighbor(Ipv4Addr::new(10, 40, 1, 99), "host-01"),
            NeighborResolution::Unknown
        );
        assert_eq!(
            directory.resolve_neighbor(Ipv4Addr::new(10, 40, 1, 12), ""),
            NeighborResolution::Unknown
        );
    }

    #[test]
    fn directory_rejects_scope_generation_address_and_identity_conflicts() {
        let mut entry = location(1, [10, 40, 1, 10], "host-01", "02:00:00:00:00:10");
        entry.project_id = "project-b".to_owned();
        assert_eq!(
            RealmEndpointDirectory::build(&realm(), vec![entry], &[], 1),
            Err(EndpointDirectoryError::ScopeMismatch)
        );

        let mut entry = location(1, [10, 40, 2, 10], "host-01", "02:00:00:00:00:10");
        assert_eq!(
            RealmEndpointDirectory::build(&realm(), vec![entry.clone()], &[], 1),
            Err(EndpointDirectoryError::OutsideRealm)
        );
        entry.fixed_ip = Ipv4Addr::new(10, 40, 1, 10);
        entry.endpoint_generation = 0;
        assert_eq!(
            RealmEndpointDirectory::build(&realm(), vec![entry], &[], 1),
            Err(EndpointDirectoryError::InvalidGeneration)
        );

        let duplicate = location(1, [10, 40, 1, 11], "host-01", "02:00:00:00:00:10");
        assert_eq!(
            RealmEndpointDirectory::build(
                &realm(),
                vec![
                    location(2, [10, 40, 1, 12], "host-02", "02:00:00:00:00:10"),
                    duplicate
                ],
                &[],
                1,
            ),
            Err(EndpointDirectoryError::DuplicateEndpoint)
        );
    }

    #[test]
    fn proxy_mac_is_stable_local_unicast_and_collision_checked() {
        let first = realm_proxy_mac(Uuid::from_u128(7));
        assert_eq!(first, realm_proxy_mac(Uuid::from_u128(7)));
        let octets = first
            .split(':')
            .filter_map(|part| u8::from_str_radix(part, 16).ok())
            .collect::<Vec<_>>();
        assert_eq!(octets.len(), 6);
        assert_eq!(octets[0] & 0x03, 0x02);

        let collision = realm_proxy_mac(Uuid::from_u128(1));
        let entry = location(1, [10, 40, 1, 10], "host-01", &collision);
        assert_eq!(
            RealmEndpointDirectory::build(&realm(), vec![entry], &[], 1),
            Err(EndpointDirectoryError::ProxyMacCollision)
        );
        assert_eq!(
            RealmEndpointDirectory::build(
                &realm(),
                vec![location(1, [10, 40, 1, 10], "host-01", "02:00:00:00:00:10")],
                &[collision],
                1,
            ),
            Err(EndpointDirectoryError::ProxyMacCollision)
        );
        assert_eq!(
            RealmEndpointDirectory::build(
                &realm(),
                vec![location(1, [10, 40, 1, 10], "host-01", "02:00:00:00:00:10")],
                &["not-a-mac".to_owned()],
                1,
            ),
            Err(EndpointDirectoryError::InvalidMac)
        );
    }

    #[test]
    fn remote_routes_require_current_host_identity_and_use_endpoint_32s() {
        let directory = RealmEndpointDirectory::build(
            &realm(),
            vec![
                location(2, [10, 40, 1, 12], "host-07", "02:00:00:00:00:12"),
                location(1, [10, 40, 1, 10], "host-01", "02:00:00:00:00:10"),
            ],
            &[],
            3,
        );
        assert!(directory.is_ok());
        let Some(directory) = directory.ok() else {
            return;
        };
        let identities = vec![FabricHostIdentity {
            host_id: "host-07".to_owned(),
            public_key: "public-key-07".to_owned(),
            underlay_endpoint: "192.0.2.7:65001".to_owned(),
            fabric_transport_ip: Ipv4Addr::new(198, 18, 0, 7),
            provider_version: "wireguard-v1".to_owned(),
            fabric_generation: 9,
            underlay_mtu: 1500,
            fabric_mtu: 1420,
        }];
        let binding = RealmEncapsulationBinding {
            fabric_domain_id: Uuid::from_u128(100),
            realm_id: directory.realm_id,
            provider_kind: FabricProviderKind::Vxlan,
            provider_segment_id: 101,
            binding_generation: 1,
        };
        let routes = directory.remote_routes("host-01", &identities, &binding);
        assert!(routes.is_ok());
        let Some(routes) = routes.ok() else {
            return;
        };
        assert_eq!(routes.len(), 1);
        assert_eq!(routes[0].destination.prefix_len, 32);
        assert_eq!(routes[0].destination.network, Ipv4Addr::new(10, 40, 1, 12));
        assert_eq!(routes[0].target_host, "host-07");
        assert_eq!(routes[0].fabric_generation, 9);

        assert_eq!(
            directory.remote_routes("host-01", &[], &binding),
            Err(EndpointDirectoryError::MissingFabricIdentity)
        );
        let mut invalid = identities;
        invalid[0].fabric_mtu = 1501;
        assert_eq!(
            directory.remote_routes("host-01", &invalid, &binding),
            Err(EndpointDirectoryError::InvalidFabricIdentity)
        );
    }

    #[test]
    fn fabric_plan_derives_shared_peers_and_rejects_unsafe_mtu() {
        let directory = RealmEndpointDirectory::build(
            &realm(),
            vec![
                location(1, [10, 40, 1, 10], "host-01", "02:00:00:00:00:10"),
                location(2, [10, 40, 1, 12], "host-07", "02:00:00:00:00:12"),
            ],
            &[],
            4,
        );
        assert!(directory.is_ok());
        let Some(directory) = directory.ok() else {
            return;
        };
        let local = FabricHostIdentity {
            host_id: "host-01".to_owned(),
            public_key: "public-key-01".to_owned(),
            underlay_endpoint: "192.0.2.1:65001".to_owned(),
            fabric_transport_ip: Ipv4Addr::new(198, 18, 0, 1),
            provider_version: "wireguard-v1".to_owned(),
            fabric_generation: 8,
            underlay_mtu: 1500,
            fabric_mtu: 1420,
        };
        let remote = FabricHostIdentity {
            host_id: "host-07".to_owned(),
            public_key: "public-key-07".to_owned(),
            underlay_endpoint: "192.0.2.7:65001".to_owned(),
            fabric_transport_ip: Ipv4Addr::new(198, 18, 0, 7),
            provider_version: "wireguard-v1".to_owned(),
            fabric_generation: 9,
            underlay_mtu: 1500,
            fabric_mtu: 1420,
        };
        let binding = RealmEncapsulationBinding {
            fabric_domain_id: Uuid::from_u128(100),
            realm_id: directory.realm_id,
            provider_kind: FabricProviderKind::Vxlan,
            provider_segment_id: 101,
            binding_generation: 1,
        };
        let plan =
            directory.compile_fabric_plan(&local, &[local.clone(), remote.clone()], 1370, &binding);
        assert!(plan.is_ok());
        let Some(plan) = plan.ok() else {
            return;
        };
        assert_eq!(plan.local_host, "host-01");
        assert_eq!(plan.local_fabric_generation, 8);
        assert_eq!(plan.tenant_mtu, 1370);
        assert_eq!(plan.routes.len(), 1);
        assert_eq!(plan.peers.len(), 1);
        assert_eq!(plan.peers[0].host_id, "host-07");
        let public_binding = PublicAddressBindingIntent {
            id: Uuid::from_u128(200),
            project_id: "project-a".to_owned(),
            public_address: Ipv4Addr::new(203, 0, 113, 10),
            endpoint_id: Uuid::from_u128(1),
            generation: 1,
        };
        let plan = plan
            .clone()
            .with_public_snapshot(vec![public_binding.clone()])
            .expect("public binding snapshot");
        assert_eq!(plan.public_bindings, vec![public_binding]);
        let mut foreign = plan.clone();
        foreign.public_bindings[0].project_id = "project-b".to_owned();
        assert_eq!(
            foreign
                .clone()
                .with_public_snapshot(foreign.public_bindings.clone()),
            Err(EndpointDirectoryError::InvalidPolicy)
        );
        assert_eq!(
            plan.peers[0].fabric_transport_ip,
            Ipv4Addr::new(198, 18, 0, 7)
        );
        assert_eq!(plan.routes[0].realm_id, directory.realm_id);
        assert_eq!(plan.routes[0].realm_binding_generation, 1);
        assert_eq!(
            directory.compile_fabric_plan(&local, std::slice::from_ref(&local), 1370, &binding),
            Err(EndpointDirectoryError::MissingFabricIdentity)
        );
        assert_eq!(
            directory.compile_fabric_plan(&local, std::slice::from_ref(&local), 1501, &binding),
            Err(EndpointDirectoryError::InvalidMtu)
        );

        let packet = GenevePacketMetadata {
            realm_id: directory.realm_id,
            vni: binding.provider_segment_id,
            source_endpoint_id: Uuid::from_u128(1),
            source_ip: Ipv4Addr::new(10, 40, 1, 10),
            source_mac: "02:00:00:00:00:10".to_owned(),
            source_host: "host-01".to_owned(),
            source_fabric_transport_ip: Ipv4Addr::new(198, 18, 0, 1),
            source_fabric_generation: 8,
            source_endpoint_generation: 1,
            source_placement_generation: 1,
            destination_ip: Ipv4Addr::new(10, 40, 1, 12),
            destination_host: "host-07".to_owned(),
            destination_fabric_transport_ip: Ipv4Addr::new(198, 18, 0, 7),
            destination_fabric_generation: 9,
            destination_endpoint_generation: 1,
            destination_placement_generation: 1,
            realm_binding_generation: 1,
            policy_generation: 1,
            protocol: NetworkProtocol::Icmp,
            source_port: None,
            destination_port: None,
        };
        assert_eq!(plan.validate_geneve_egress(&packet), Ok(()));
        let remote_plan = directory
            .compile_fabric_plan(&remote, &[local, remote.clone()], 1370, &binding)
            .expect("remote plan");
        assert_eq!(remote_plan.validate_geneve_ingress(&packet), Ok(()));
        let mut wrong_vni = packet.clone();
        wrong_vni.vni += 1;
        assert_eq!(
            plan.validate_geneve_egress(&wrong_vni),
            Err(GenevePacketValidationError::InvalidBinding)
        );
        let mut spoofed_source = packet.clone();
        spoofed_source.source_ip = Ipv4Addr::new(10, 40, 1, 99);
        assert_eq!(
            plan.validate_geneve_egress(&spoofed_source),
            Err(GenevePacketValidationError::InvalidSource)
        );
        let mut spoofed_transport = packet.clone();
        spoofed_transport.source_fabric_transport_ip = Ipv4Addr::new(198, 18, 0, 99);
        assert_eq!(
            remote_plan.validate_geneve_ingress(&spoofed_transport),
            Err(GenevePacketValidationError::InvalidSource)
        );

        let deny_plan = plan
            .clone()
            .with_policy_snapshot(
                2,
                vec![PolicyIntent {
                    id: Uuid::from_u128(900),
                    endpoint_id: Uuid::from_u128(1),
                    direction: PolicyDirection::Egress,
                    protocol: NetworkProtocol::Icmp,
                    ports: None,
                    source: None,
                    destination: Ipv4Prefix::new(Ipv4Addr::new(10, 40, 1, 0), 24),
                    action: PolicyAction::Deny,
                }],
            )
            .expect("policy snapshot");
        let mut denied_packet = packet.clone();
        denied_packet.policy_generation = 2;
        assert_eq!(
            deny_plan.validate_geneve_egress(&denied_packet),
            Err(GenevePacketValidationError::PolicyDenied)
        );
        let mut stale_policy = denied_packet;
        stale_policy.policy_generation = 1;
        assert_eq!(
            deny_plan.validate_geneve_egress(&stale_policy),
            Err(GenevePacketValidationError::StalePolicy)
        );
        let deny_default_plan = plan
            .clone()
            .with_canonical_policy_snapshot(
                4,
                vec![PolicyDefaultIntent {
                    policy_id: Uuid::from_u128(902),
                    endpoint_id: Uuid::from_u128(1),
                    unmatched_action: PolicyAction::Deny,
                    stateful_mode: PolicyStatefulMode::Stateful,
                    generation: 1,
                }],
                Vec::new(),
            )
            .expect("deny default policy snapshot");
        let mut default_packet = packet.clone();
        default_packet.policy_generation = 4;
        assert_eq!(
            deny_default_plan.validate_geneve_egress(&default_packet),
            Err(GenevePacketValidationError::PolicyDenied)
        );
        let allow_default_plan = deny_default_plan
            .with_canonical_policy_snapshot(
                5,
                vec![PolicyDefaultIntent {
                    policy_id: Uuid::from_u128(903),
                    endpoint_id: Uuid::from_u128(1),
                    unmatched_action: PolicyAction::Allow,
                    stateful_mode: PolicyStatefulMode::Stateful,
                    generation: 1,
                }],
                Vec::new(),
            )
            .expect("allow default policy snapshot");
        default_packet.policy_generation = 5;
        assert_eq!(
            allow_default_plan.validate_geneve_egress(&default_packet),
            Ok(())
        );
        let precedence_plan = plan
            .clone()
            .with_canonical_policy_snapshot(
                6,
                vec![PolicyDefaultIntent {
                    policy_id: Uuid::from_u128(904),
                    endpoint_id: Uuid::from_u128(1),
                    unmatched_action: PolicyAction::Allow,
                    stateful_mode: PolicyStatefulMode::Stateful,
                    generation: 1,
                }],
                vec![
                    PolicyIntent {
                        id: Uuid::from_u128(906),
                        endpoint_id: Uuid::from_u128(1),
                        direction: PolicyDirection::Egress,
                        protocol: NetworkProtocol::Icmp,
                        ports: None,
                        source: None,
                        destination: Ipv4Prefix::new(Ipv4Addr::new(10, 40, 1, 0), 24),
                        action: PolicyAction::Allow,
                    },
                    PolicyIntent {
                        id: Uuid::from_u128(905),
                        endpoint_id: Uuid::from_u128(1),
                        direction: PolicyDirection::Egress,
                        protocol: NetworkProtocol::Icmp,
                        ports: None,
                        source: None,
                        destination: Ipv4Prefix::new(Ipv4Addr::new(10, 40, 1, 0), 24),
                        action: PolicyAction::Deny,
                    },
                ],
            )
            .expect("precedence policy snapshot");
        default_packet.policy_generation = 6;
        assert_eq!(
            precedence_plan.validate_geneve_egress(&default_packet),
            Err(GenevePacketValidationError::PolicyDenied)
        );
        assert_eq!(
            plan.clone().with_policy_snapshot(0, Vec::new(),),
            Err(EndpointDirectoryError::InvalidPolicy)
        );
        assert_eq!(
            plan.with_policy_snapshot(
                3,
                vec![PolicyIntent {
                    id: Uuid::from_u128(901),
                    endpoint_id: Uuid::from_u128(999),
                    direction: PolicyDirection::Ingress,
                    protocol: NetworkProtocol::Any,
                    ports: None,
                    source: None,
                    destination: None,
                    action: PolicyAction::Deny,
                }],
            ),
            Err(EndpointDirectoryError::InvalidPolicy)
        );
    }

    #[test]
    fn overlapping_realms_keep_route_identity_and_transport_identity_distinct() {
        let realm_a = realm();
        let realm_b = AddressRealm {
            id: Uuid::from_u128(0x99),
            project_id: "project-b".to_owned(),
            ..realm_a.clone()
        };
        let endpoint_a = EndpointLocation {
            endpoint_id: Uuid::from_u128(0xa1),
            project_id: realm_a.project_id.clone(),
            realm_id: realm_a.id,
            fixed_ip: Ipv4Addr::new(10, 40, 1, 20),
            mac: "02:00:00:00:10:20".to_owned(),
            selected_host: "host-remote".to_owned(),
            endpoint_generation: 1,
            placement_generation: 1,
        };
        let endpoint_b = EndpointLocation {
            endpoint_id: Uuid::from_u128(0xb1),
            project_id: realm_b.project_id.clone(),
            realm_id: realm_b.id,
            fixed_ip: endpoint_a.fixed_ip,
            mac: "02:00:00:00:20:20".to_owned(),
            selected_host: endpoint_a.selected_host.clone(),
            endpoint_generation: 1,
            placement_generation: 1,
        };
        let directory_a = RealmEndpointDirectory::build(&realm_a, vec![endpoint_a], &[], 1)
            .expect("realm A directory");
        let directory_b = RealmEndpointDirectory::build(&realm_b, vec![endpoint_b], &[], 1)
            .expect("realm B directory");
        let local = FabricHostIdentity {
            host_id: "host-local".to_owned(),
            public_key: "public-local".to_owned(),
            underlay_endpoint: "192.0.2.1:65001".to_owned(),
            fabric_transport_ip: Ipv4Addr::new(198, 18, 0, 1),
            provider_version: "wireguard-v1".to_owned(),
            fabric_generation: 1,
            underlay_mtu: 1500,
            fabric_mtu: 1420,
        };
        let remote = FabricHostIdentity {
            host_id: "host-remote".to_owned(),
            public_key: "public-remote".to_owned(),
            underlay_endpoint: "192.0.2.2:65001".to_owned(),
            fabric_transport_ip: Ipv4Addr::new(198, 18, 0, 2),
            provider_version: "wireguard-v1".to_owned(),
            fabric_generation: 1,
            underlay_mtu: 1500,
            fabric_mtu: 1420,
        };
        let mut registry = RealmEncapsulationRegistry::default();
        let binding_a = registry
            .ensure(Uuid::from_u128(0xfeed), realm_a.id, 1)
            .expect("A binding");
        let binding_b = registry
            .ensure(Uuid::from_u128(0xfeed), realm_b.id, 1)
            .expect("B binding");
        assert_ne!(binding_a.provider_segment_id, binding_b.provider_segment_id);
        let plan_a = directory_a
            .compile_fabric_plan(&local, &[local.clone(), remote.clone()], 1370, &binding_a)
            .expect("A plan");
        let plan_b = directory_b
            .compile_fabric_plan(&local, &[local.clone(), remote], 1370, &binding_b)
            .expect("B plan");
        assert_eq!(plan_a.routes[0].destination, plan_b.routes[0].destination);
        assert_ne!(plan_a.routes[0].realm_id, plan_b.routes[0].realm_id);
        assert_eq!(
            plan_a.peers[0].fabric_transport_ip,
            plan_b.peers[0].fabric_transport_ip
        );
        assert_ne!(
            plan_a.encapsulation.provider_segment_id,
            plan_b.encapsulation.provider_segment_id
        );
    }

    #[test]
    fn realm_binding_replay_and_release_are_fenced() {
        let domain = Uuid::from_u128(0xbeef);
        let realm_id = Uuid::from_u128(0x42);
        let mut registry = RealmEncapsulationRegistry::default();
        let first = registry.ensure(domain, realm_id, 4).expect("binding");
        assert_eq!(registry.ensure(domain, realm_id, 4), Ok(first.clone()));
        assert_eq!(
            registry.ensure(domain, realm_id, 3),
            Err(RealmBindingError::StaleGeneration)
        );
        assert_eq!(
            registry.release(&first, false),
            Err(RealmBindingError::StateNotProvenAbsent)
        );
        registry.release(&first, true).expect("release");
        let next = registry
            .ensure(domain, Uuid::from_u128(0x43), 1)
            .expect("next binding");
        assert_eq!(next.provider_segment_id, first.provider_segment_id);
    }

    #[test]
    fn canonical_network_is_valid_without_address_realms() {
        let network = Network {
            id: Uuid::from_u128(0x500),
            project_id: "project-a".to_owned(),
            name: "network-a".to_owned(),
            generation: 1,
            state: NetworkState::Active,
        };
        let realms: Vec<AddressRealm> = Vec::new();
        assert!(realms.is_empty());
        assert_eq!(network.project_id, "project-a");
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct RouteIntent {
    pub destination: Ipv4Prefix,
    pub next_hop: Option<Ipv4Addr>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct GatewayIntent {
    pub destination: Ipv4Prefix,
    pub gateway: Ipv4Addr,
    pub external: bool,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct EgressIntent {
    pub external_realm_id: Uuid,
    pub enabled: bool,
    pub nat: bool,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct PublicAddressBindingIntent {
    pub id: Uuid,
    pub project_id: String,
    pub public_address: Ipv4Addr,
    pub endpoint_id: Uuid,
    pub generation: u64,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum PolicyAction {
    Allow,
    Deny,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum PolicyDirection {
    Ingress,
    Egress,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum NetworkProtocol {
    Any,
    Tcp,
    Udp,
    Icmp,
}

/// Canonical lifecycle for reusable network policy resources and children.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum PolicyLifecycleState {
    Requested,
    Active,
    Deleting,
    Deleted,
    Error,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum PolicyStatefulMode {
    Stateful,
    Stateless,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum PolicyAddressFamily {
    Ipv4,
    Ipv6,
}

/// Reusable project-owned policy authority. It is valid without an Endpoint.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct NetworkPolicy {
    pub id: Uuid,
    pub project_id: String,
    pub name: String,
    pub description: String,
    pub state: PolicyLifecycleState,
    pub generation: u64,
    pub stateful_mode: PolicyStatefulMode,
    pub unmatched_action: PolicyAction,
    pub created_at: String,
    pub updated_at: String,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct NetworkPolicyRule {
    pub id: Uuid,
    pub policy_id: Uuid,
    pub project_id: String,
    pub direction: PolicyDirection,
    pub address_family: PolicyAddressFamily,
    pub protocol: NetworkProtocol,
    pub ports: Option<PortRange>,
    pub remote_selector: Option<Ipv4Prefix>,
    pub action: PolicyAction,
    pub state: PolicyLifecycleState,
    pub generation: u64,
}

impl NetworkPolicyRule {
    /// A uniqueness key only; the UUID remains the canonical rule identity.
    #[must_use]
    pub fn enforcement_key(&self) -> String {
        format!(
            "{:?}|{:?}|{:?}|{}|{}|{:?}",
            self.direction,
            self.address_family,
            self.protocol,
            self.ports.map_or_else(
                || "-".to_owned(),
                |ports| format!("{}-{}", ports.start, ports.end)
            ),
            self.remote_selector.map_or_else(
                || "-".to_owned(),
                |prefix| format!("{}/{}", prefix.network, prefix.prefix_len)
            ),
            self.action
        )
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct PolicyAttachment {
    pub id: Uuid,
    pub policy_id: Uuid,
    pub endpoint_id: Uuid,
    pub project_id: String,
    pub state: PolicyLifecycleState,
    pub generation: u64,
}

/// Derived endpoint-scoped default semantics for an attached canonical
/// policy. This is execution input, not reusable policy authority.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct PolicyDefaultIntent {
    pub policy_id: Uuid,
    pub endpoint_id: Uuid,
    pub unmatched_action: PolicyAction,
    pub stateful_mode: PolicyStatefulMode,
    pub generation: u64,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub struct PortRange {
    pub start: u16,
    pub end: u16,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct PolicyIntent {
    /// Stable control-plane identity for update/delete/replay. Provider rule
    /// names and handles are derived observations, never canonical identity.
    pub id: Uuid,
    pub endpoint_id: Uuid,
    pub direction: PolicyDirection,
    pub protocol: NetworkProtocol,
    pub ports: Option<PortRange>,
    pub source: Option<Ipv4Prefix>,
    pub destination: Option<Ipv4Prefix>,
    pub action: PolicyAction,
}

impl PolicyIntent {
    fn protocol_matches(&self, protocol: NetworkProtocol) -> bool {
        self.protocol == NetworkProtocol::Any || self.protocol == protocol
    }

    fn ports_match(&self, destination_port: Option<u16>) -> bool {
        let Some(ports) = self.ports else {
            return true;
        };
        destination_port.is_some_and(|port| ports.start <= port && port <= ports.end)
    }

    fn prefix_matches(&self, address: Ipv4Addr) -> bool {
        self.source
            .or(self.destination)
            .is_none_or(|prefix| prefix.contains(address))
    }
}

/// Durable compatibility projection for the bounded IPv4 security-group
/// surface. These values are adapter state, not provider-native authority.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct SecurityGroupIntent {
    pub id: Uuid,
    pub project_id: String,
    pub name: String,
    pub description: String,
    pub rules: Vec<SecurityGroupRuleIntent>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct SecurityGroupRuleIntent {
    pub id: Uuid,
    pub security_group_id: Uuid,
    pub direction: PolicyDirection,
    pub protocol: NetworkProtocol,
    pub ports: Option<PortRange>,
    pub remote_ip_prefix: Option<Ipv4Prefix>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, Default)]
pub struct SecurityGroupState {
    pub project_id: String,
    pub generation: u64,
    pub groups: Vec<SecurityGroupIntent>,
    pub bindings: Vec<SecurityGroupBinding>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct SecurityGroupBinding {
    pub endpoint_id: Uuid,
    pub security_group_id: Uuid,
}

/// Bounded capability vocabulary used before a plan can be dispatched to an
/// execution provider. These are semantic facts, not provider configuration.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub enum NetworkCapability {
    EndpointAttachment,
    Ipv4,
    Ipv6,
    L2AdjacencyScope,
    Routing,
    StatefulPolicy,
    Nat,
    PublicAddressRealization,
    OverlappingAddressRealms,
    EncapsulationModes,
    QosFeatures,
    RouteAdvertisementModes,
}

/// Provider-independent intent carried by a node plan.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub enum NetworkPlanIntent {
    AddressRealm {
        realm_id: Uuid,
        prefix: Ipv4Prefix,
        gateway: Ipv4Addr,
    },
    EndpointAttachment {
        endpoint_id: Uuid,
        mac: String,
        fixed_ip: Ipv4Addr,
        generation: u64,
    },
    AddressAssignment {
        endpoint_id: Uuid,
        address: Ipv4Addr,
        generation: u64,
    },
    Route(RouteIntent),
    Gateway(GatewayIntent),
    Egress(EgressIntent),
    PublicAddressBinding(PublicAddressBindingIntent),
    PolicyDefault(PolicyDefaultIntent),
    Policy(PolicyIntent),
}
