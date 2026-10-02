//! Portable P11 fabric realization and conformance seam.
//!
//! This module deliberately models provider-owned state without invoking host
//! commands. The Linux/WireGuard backend realizes the same generation, route,
//! peer, and neighbor invariants with the accepted VXLAN/HER dataplane.

use crate::{NodeNetworkPlan, execution::NetworkPlanRealizer};
use o3k_domain::{NamespacedRoutedFabricPlan, NeighborResolution};
use std::collections::BTreeMap;
use thiserror::Error;
use uuid::Uuid;

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
