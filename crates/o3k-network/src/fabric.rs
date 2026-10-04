//! Portable P11 fabric realization and conformance seam.
//!
//! This module deliberately models provider-owned state without invoking host
//! commands. The Linux/WireGuard backend realizes the same generation, route,
//! peer, and neighbor invariants with the accepted VXLAN/HER dataplane.

use crate::{
    NodeNetworkPlan, execution::NetworkPlanRealizer, plan::NODE_NETWORK_PLAN_SCHEMA_VERSION,
};
use o3k_domain::{
    AddressRealm, EndpointLocation, NamespacedRoutedFabricPlan, NeighborResolution,
    RealmEncapsulationBinding, RealmEndpointDirectory,
};
use std::collections::{BTreeMap, BTreeSet};
use thiserror::Error;
use uuid::Uuid;

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct FabricRealmPlanSet {
    pub directory: RealmEndpointDirectory,
    pub plans: BTreeMap<String, NodeNetworkPlan>,
}

#[derive(Debug, Error, Clone, PartialEq, Eq)]
pub enum FabricRealmPlanError {
    #[error("realm plan contains an invalid or conflicting host identity")]
    InvalidHostIdentity,
    #[error("realm endpoint selected a host without current accepted Fabric identity")]
    MissingHostIdentity,
    #[error("realm has no participating endpoint placement")]
    NoParticipants,
    #[error("realm endpoint directory is invalid")]
    InvalidDirectory,
    #[error("realm VNI binding is invalid")]
    InvalidBinding,
    #[error("realm participant MTUs are incompatible")]
    IncompatibleMtu,
    #[error("Fabric reconciliation plan could not be fingerprinted")]
    Fingerprint,
}

/// Derives one deterministic, host-local v3 plan per current realm
/// participant. The caller supplies only canonical realm, placement,
/// enrollment, VNI, and generation inputs; runtime observations are absent.
pub fn compile_fabric_realm_plans(
    realm: &AddressRealm,
    locations: Vec<EndpointLocation>,
    participants: &[o3k_domain::FabricHostIdentity],
    binding: &RealmEncapsulationBinding,
    directory_generation: u64,
    operation_id: Uuid,
    deadline_unix_ms: u64,
) -> Result<FabricRealmPlanSet, FabricRealmPlanError> {
    if binding.realm_id != realm.id || binding.validate().is_err() {
        return Err(FabricRealmPlanError::InvalidBinding);
    }
    if participants.is_empty() {
        return Err(FabricRealmPlanError::NoParticipants);
    }
    let mut by_host = BTreeMap::new();
    let mut by_agent_ip = BTreeSet::new();
    for identity in participants {
        let endpoint = identity
            .underlay_endpoint
            .parse::<std::net::SocketAddr>()
            .map_err(|_| FabricRealmPlanError::InvalidHostIdentity)?;
        let overhead = if endpoint.is_ipv4() { 60 } else { 80 };
        let minimum_underlay_mtu = if endpoint.is_ipv4() { 1110 } else { 1130 };
        if identity.host_id.trim().is_empty()
            || identity.public_key.trim().is_empty()
            || identity.provider_version.trim().is_empty()
            || identity.fabric_generation == 0
            || endpoint.port() == 0
            || endpoint.ip().is_unspecified()
            || identity.fabric_transport_ip.is_unspecified()
            || identity.fabric_transport_ip.is_loopback()
            || identity.fabric_transport_ip.is_multicast()
            || identity.underlay_mtu < minimum_underlay_mtu
            || identity.fabric_mtu != identity.underlay_mtu.saturating_sub(overhead)
            || !by_agent_ip.insert(identity.fabric_transport_ip)
            || by_host.insert(identity.host_id.clone(), identity).is_some()
        {
            return Err(FabricRealmPlanError::InvalidHostIdentity);
        }
    }
    let directory = RealmEndpointDirectory::build(realm, locations, &[], directory_generation)
        .map_err(|_| FabricRealmPlanError::InvalidDirectory)?;
    let host_ids = directory
        .entries
        .iter()
        .map(|entry| entry.selected_host.as_str())
        .collect::<BTreeSet<_>>();
    if host_ids.is_empty() {
        return Err(FabricRealmPlanError::NoParticipants);
    }
    if host_ids
        .iter()
        .any(|host_id| !by_host.contains_key(*host_id))
    {
        return Err(FabricRealmPlanError::MissingHostIdentity);
    }
    let selected = host_ids
        .iter()
        .map(|host_id| {
            by_host
                .get(*host_id)
                .copied()
                .ok_or(FabricRealmPlanError::MissingHostIdentity)
        })
        .collect::<Result<Vec<_>, _>>()?;
    let expected_mtu = selected
        .iter()
        .map(|identity| identity.fabric_mtu)
        .min()
        .ok_or(FabricRealmPlanError::NoParticipants)?;
    let tenant_mtu = expected_mtu
        .checked_sub(50)
        .filter(|mtu| *mtu >= 576)
        .ok_or(FabricRealmPlanError::IncompatibleMtu)?;
    let mut plans = BTreeMap::new();
    let selected_identities = selected
        .iter()
        .map(|identity| (*identity).clone())
        .collect::<Vec<_>>();
    for local_identity in &selected {
        let fabric = directory
            .compile_fabric_plan(local_identity, &selected_identities, tenant_mtu, binding)
            .map_err(|_| FabricRealmPlanError::InvalidHostIdentity)?;
        let plan_id = Uuid::new_v5(
            &operation_id,
            format!("fabric-realm:{}:{}", realm.id, local_identity.host_id).as_bytes(),
        );
        let mut resource_generations = BTreeMap::from([(realm.id, directory_generation)]);
        for entry in &directory.entries {
            resource_generations.insert(entry.endpoint_id, entry.endpoint_generation);
        }
        let node_plan = NodeNetworkPlan {
            schema_version: NODE_NETWORK_PLAN_SCHEMA_VERSION,
            plan_id,
            node_id: local_identity.host_id.clone(),
            operation_id,
            deadline_unix_ms,
            resource_generations,
            intents: Vec::new(),
            fabric: None,
            gateway: None,
            fingerprint_sha256: String::new(),
        }
        .with_fabric(fabric)
        .map_err(|_| FabricRealmPlanError::Fingerprint)?;
        plans.insert(local_identity.host_id.clone(), node_plan);
    }
    Ok(FabricRealmPlanSet { directory, plans })
}

#[derive(Debug, Error, Clone, PartialEq, Eq)]
pub enum FabricError {
    #[error("P11 fabric plan is missing or invalid")]
    InvalidPlan,
    #[error("P11 fabric generation is stale")]
    StaleGeneration,
    #[error("P11 fabric backend failed: {0}")]
    Backend(String),
}

/// Narrow provider-owned mutation seam for P11 semantic state.
pub trait FabricBackend {
    fn apply(&mut self, plan: &NamespacedRoutedFabricPlan) -> Result<(), FabricError>;
    fn remove(&mut self, plan: &NamespacedRoutedFabricPlan) -> Result<(), FabricError>;
    fn observe(&self, plan: &NamespacedRoutedFabricPlan) -> Result<bool, FabricError>;
    fn observe_removed(&self, plan: &NamespacedRoutedFabricPlan) -> Result<bool, FabricError>;
}

/// Realizer used by the node-local executor. It does not authorize callers or
/// invent endpoint identity; those checks happen before this boundary.
#[derive(Debug)]
pub struct FabricRealizer<B> {
    backend: B,
}

impl<B> FabricRealizer<B> {
    #[must_use]
    pub fn new(backend: B) -> Self {
        Self { backend }
    }

    pub fn backend(&self) -> &B {
        &self.backend
    }

    pub fn backend_mut(&mut self) -> &mut B {
        &mut self.backend
    }
}

impl<B: FabricBackend> NetworkPlanRealizer for FabricRealizer<B> {
    type Error = FabricError;

    fn realize(&mut self, plan: &NodeNetworkPlan) -> Result<(), Self::Error> {
        let fabric = plan.fabric.as_ref().ok_or(FabricError::InvalidPlan)?;
        plan.validate_fabric()
            .map_err(|_| FabricError::InvalidPlan)?;
        self.backend.apply(fabric)
    }

    fn remove(&mut self, plan: &NodeNetworkPlan) -> Result<(), Self::Error> {
        let fabric = plan.fabric.as_ref().ok_or(FabricError::InvalidPlan)?;
        plan.validate_fabric()
            .map_err(|_| FabricError::InvalidPlan)?;
        self.backend.remove(fabric)
    }

    fn observe(&mut self, plan: &NodeNetworkPlan) -> Result<bool, Self::Error> {
        let fabric = plan.fabric.as_ref().ok_or(FabricError::InvalidPlan)?;
        plan.validate_fabric()
            .map_err(|_| FabricError::InvalidPlan)?;
        self.backend.observe(fabric)
    }

    fn observe_removed(&mut self, plan: &NodeNetworkPlan) -> Result<bool, Self::Error> {
        let fabric = plan.fabric.as_ref().ok_or(FabricError::InvalidPlan)?;
        plan.validate_fabric()
            .map_err(|_| FabricError::InvalidPlan)?;
        self.backend.observe_removed(fabric)
    }
}

/// Portable provider state used by semantic and replay tests. It has the same
/// generation behavior required from a host provider but performs no network
/// mutation.
#[derive(Debug, Default)]
pub struct InMemoryFabricBackend {
    current: BTreeMap<Uuid, NamespacedRoutedFabricPlan>,
}

impl InMemoryFabricBackend {
    #[must_use]
    pub fn current(&self, realm_id: Uuid) -> Option<&NamespacedRoutedFabricPlan> {
        self.current.get(&realm_id)
    }

    #[must_use]
    pub fn resolve_neighbor(&self, destination: std::net::Ipv4Addr) -> NeighborResolution {
        self.current
            .values()
            .map(|plan| {
                plan.directory
                    .resolve_neighbor(destination, &plan.local_host)
            })
            .find(|resolution| !matches!(resolution, NeighborResolution::Unknown))
            .unwrap_or(NeighborResolution::Unknown)
    }

    #[must_use]
    pub fn route_for(&self, endpoint_id: Uuid) -> Option<&o3k_domain::FabricEndpointRoute> {
        self.current
            .values()
            .find(|plan| {
                plan.routes
                    .iter()
                    .any(|route| route.endpoint_id == endpoint_id)
            })?
            .routes
            .iter()
            .find(|route| route.endpoint_id == endpoint_id)
    }

    fn is_stale(current: &NamespacedRoutedFabricPlan, next: &NamespacedRoutedFabricPlan) -> bool {
        current.realm_id == next.realm_id
            && (next.directory_generation < current.directory_generation
                || next.local_fabric_generation < current.local_fabric_generation)
    }
}

impl FabricBackend for InMemoryFabricBackend {
    fn apply(&mut self, plan: &NamespacedRoutedFabricPlan) -> Result<(), FabricError> {
        if self
            .current
            .get(&plan.realm_id)
            .is_some_and(|current| Self::is_stale(current, plan))
        {
            return Err(FabricError::StaleGeneration);
        }
        self.current.insert(plan.realm_id, plan.clone());
        Ok(())
    }

    fn remove(&mut self, plan: &NamespacedRoutedFabricPlan) -> Result<(), FabricError> {
        if self
            .current
            .get(&plan.realm_id)
            .is_some_and(|current| Self::is_stale(current, plan))
        {
            return Err(FabricError::StaleGeneration);
        }
        if self.current.get(&plan.realm_id).is_some_and(|current| {
            current.local_host == plan.local_host
                && current.directory_generation <= plan.directory_generation
        }) {
            self.current.remove(&plan.realm_id);
        }
        Ok(())
    }

    fn observe(&self, plan: &NamespacedRoutedFabricPlan) -> Result<bool, FabricError> {
        Ok(self.current.get(&plan.realm_id) == Some(plan))
    }

    fn observe_removed(&self, plan: &NamespacedRoutedFabricPlan) -> Result<bool, FabricError> {
        Ok(self
            .current
            .get(&plan.realm_id)
            .is_none_or(|current| current.local_host != plan.local_host))
    }
}

#[cfg(test)]
#[allow(clippy::expect_used, clippy::panic)]
mod tests {
    use super::*;
    use o3k_domain::{
        AddressRealm, EndpointLocation, FabricHostIdentity, FabricProviderKind, Ipv4Prefix,
        RealmEncapsulationBinding, RealmEndpointDirectory,
    };
    use std::net::Ipv4Addr;

    fn host(host_id: &str, last_octet: u8) -> FabricHostIdentity {
        FabricHostIdentity {
            host_id: host_id.to_owned(),
            public_key: format!("public-{host_id}"),
            underlay_endpoint: format!("192.0.2.{last_octet}:65001"),
            fabric_transport_ip: Ipv4Addr::new(198, 18, 0, last_octet),
            provider_version: "wireguard-v1".to_owned(),
            fabric_generation: 1,
            underlay_mtu: 1500,
            fabric_mtu: 1440,
        }
    }

    fn realm() -> AddressRealm {
        AddressRealm {
            id: Uuid::from_u128(100),
            network_id: Uuid::from_u128(101),
            project_id: "project-a".to_owned(),
            prefix: Ipv4Prefix::new(Ipv4Addr::new(10, 40, 1, 0), 24).expect("prefix"),
            overlapping_prefixes: false,
        }
    }

    fn endpoint(endpoint_id: u128, host_id: &str, ip: u8) -> EndpointLocation {
        EndpointLocation {
            endpoint_id: Uuid::from_u128(endpoint_id),
            project_id: "project-a".to_owned(),
            realm_id: Uuid::from_u128(100),
            fixed_ip: Ipv4Addr::new(10, 40, 1, ip),
            mac: format!("02:00:00:00:00:{ip:02x}"),
            selected_host: host_id.to_owned(),
            endpoint_generation: 1,
            placement_generation: 1,
        }
    }

    fn binding() -> RealmEncapsulationBinding {
        RealmEncapsulationBinding {
            fabric_domain_id: Uuid::from_u128(102),
            realm_id: Uuid::from_u128(100),
            provider_kind: FabricProviderKind::Vxlan,
            provider_segment_id: 101,
            binding_generation: 1,
        }
    }

    #[test]
    fn realm_compiler_builds_host_local_her_for_three_participants() {
        let result = compile_fabric_realm_plans(
            &realm(),
            vec![
                endpoint(1, "compute-a", 10),
                endpoint(2, "compute-b", 20),
                endpoint(3, "compute-c", 30),
            ],
            &[
                host("compute-a", 1),
                host("compute-b", 2),
                host("compute-c", 3),
            ],
            &binding(),
            1,
            Uuid::from_u128(103),
            10_000,
        )
        .expect("three host plans");
        assert_eq!(result.plans.len(), 3);
        assert_eq!(
            result.plans["compute-a"]
                .fabric
                .as_ref()
                .expect("fabric plan")
                .peers
                .len(),
            2
        );
        assert_eq!(
            result.plans["compute-b"]
                .fabric
                .as_ref()
                .expect("fabric plan")
                .peers
                .len(),
            2
        );
        assert_eq!(
            result.plans["compute-c"]
                .fabric
                .as_ref()
                .expect("fabric plan")
                .peers
                .len(),
            2
        );
        assert_eq!(result.plans["compute-a"].node_id, "compute-a");
        assert_ne!(
            result.plans["compute-a"].fingerprint_sha256,
            result.plans["compute-b"].fingerprint_sha256
        );
    }

    #[test]
    fn realm_compiler_fails_closed_for_missing_identity_and_derives_safe_heterogeneous_mtu() {
        let locations = vec![endpoint(1, "compute-a", 10), endpoint(2, "compute-b", 20)];
        assert_eq!(
            compile_fabric_realm_plans(
                &realm(),
                locations.clone(),
                &[host("compute-a", 1)],
                &binding(),
                1,
                Uuid::from_u128(103),
                10_000,
            ),
            Err(FabricRealmPlanError::MissingHostIdentity)
        );
        let mut lower_mtu = host("compute-b", 2);
        lower_mtu.underlay_mtu = 1450;
        lower_mtu.fabric_mtu = 1390;
        let plans = compile_fabric_realm_plans(
            &realm(),
            locations,
            &[host("compute-a", 1), lower_mtu],
            &binding(),
            1,
            Uuid::from_u128(103),
            10_000,
        )
        .expect("a lower peer MTU yields a common safe tenant MTU");
        assert!(plans.plans.values().all(|plan| {
            plan.fabric
                .as_ref()
                .is_some_and(|fabric| fabric.tenant_mtu == 1340)
        }));
    }

    fn plan(directory_generation: u64) -> NodeNetworkPlan {
        let realm = AddressRealm {
            id: Uuid::from_u128(1),
            network_id: Uuid::from_u128(10),
            project_id: "project-a".to_owned(),
            prefix: Ipv4Prefix::new(Ipv4Addr::new(10, 40, 1, 0), 24).expect("prefix"),
            overlapping_prefixes: false,
        };
        let directory = RealmEndpointDirectory::build(
            &realm,
            vec![
                EndpointLocation {
                    endpoint_id: Uuid::from_u128(1),
                    project_id: "project-a".to_owned(),
                    realm_id: realm.id,
                    fixed_ip: Ipv4Addr::new(10, 40, 1, 10),
                    mac: "02:00:00:00:00:10".to_owned(),
                    selected_host: "node-a".to_owned(),
                    endpoint_generation: 1,
                    placement_generation: 1,
                },
                EndpointLocation {
                    endpoint_id: Uuid::from_u128(2),
                    project_id: "project-a".to_owned(),
                    realm_id: realm.id,
                    fixed_ip: Ipv4Addr::new(10, 40, 1, 12),
                    mac: "02:00:00:00:00:12".to_owned(),
                    selected_host: "node-b".to_owned(),
                    endpoint_generation: 1,
                    placement_generation: directory_generation,
                },
            ],
            &[],
            directory_generation,
        )
        .expect("directory");
        let local = FabricHostIdentity {
            host_id: "node-a".to_owned(),
            public_key: "public-a".to_owned(),
            underlay_endpoint: "192.0.2.1:65001".to_owned(),
            fabric_transport_ip: Ipv4Addr::new(198, 18, 0, 1),
            provider_version: "wireguard-v1".to_owned(),
            fabric_generation: directory_generation,
            underlay_mtu: 1500,
            fabric_mtu: 1440,
        };
        let remote = FabricHostIdentity {
            host_id: "node-b".to_owned(),
            public_key: "public-b".to_owned(),
            underlay_endpoint: "192.0.2.2:65001".to_owned(),
            fabric_transport_ip: Ipv4Addr::new(198, 18, 0, 2),
            provider_version: "wireguard-v1".to_owned(),
            fabric_generation: directory_generation,
            underlay_mtu: 1500,
            fabric_mtu: 1440,
        };
        let binding = RealmEncapsulationBinding {
            fabric_domain_id: Uuid::from_u128(100),
            realm_id: realm.id,
            provider_kind: FabricProviderKind::Vxlan,
            provider_segment_id: 101,
            binding_generation: directory_generation,
        };
        let fabric = directory
            .compile_fabric_plan(&local, &[local.clone(), remote], 1390, &binding)
            .expect("fabric plan");
        let operation_id = Uuid::from_u128(directory_generation as u128 + 10);
        let mut plan = NodeNetworkPlan {
            schema_version: 1,
            plan_id: realm.id,
            node_id: "node-a".to_owned(),
            operation_id,
            deadline_unix_ms: 100,
            resource_generations: std::collections::BTreeMap::new(),
            intents: vec![],
            fabric: Some(fabric),
            gateway: None,
            fingerprint_sha256: String::new(),
        };
        plan.fingerprint_sha256 = crate::canonical_plan_fingerprint(&plan).expect("fingerprint");
        plan
    }

    #[test]
    fn portable_backend_resolves_local_actual_mac_and_remote_proxy() {
        let mut realizer = FabricRealizer::new(InMemoryFabricBackend::default());
        let first = plan(1);
        realizer.realize(&first).expect("apply");
        assert_eq!(
            realizer
                .backend()
                .resolve_neighbor(Ipv4Addr::new(10, 40, 1, 10)),
            NeighborResolution::LocalActualMac("02:00:00:00:00:10".to_owned())
        );
        assert!(matches!(
            realizer
                .backend()
                .resolve_neighbor(Ipv4Addr::new(10, 40, 1, 12)),
            NeighborResolution::RemoteActualMac(_)
        ));
        assert_eq!(
            realizer
                .backend()
                .resolve_neighbor(Ipv4Addr::new(10, 40, 9, 9)),
            NeighborResolution::Unknown
        );
        assert_eq!(
            realizer
                .backend()
                .route_for(Uuid::from_u128(2))
                .map(|route| route.destination.prefix_len),
            Some(32)
        );
    }

    #[test]
    fn portable_backend_rejects_stale_generation_and_removes_current_state() {
        let mut realizer = FabricRealizer::new(InMemoryFabricBackend::default());
        let current = plan(2);
        realizer.realize(&current).expect("apply");
        assert_eq!(
            realizer.realize(&plan(1)),
            Err(FabricError::StaleGeneration)
        );
        assert!(realizer.observe(&current).expect("observe"));
        realizer.remove(&current).expect("remove");
        assert!(realizer.observe_removed(&current).expect("removed"));
    }
}
