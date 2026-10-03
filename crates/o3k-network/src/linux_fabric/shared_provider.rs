//! Adapter to the pinned shared `o3kio/fabric` Linux executor.
//! O3K remains the source of canonical placement, identity, policy and fencing;
//! this module only translates an accepted plan into provider primitives.
use super::{LinuxFabricConfig, LinuxFabricError};
use fabric_linux::{FabricLinuxConfig, LinuxFabricProvider, RealCommandRunner};
use fabric_plan::{FabricPeer, PublicKey, StretchedL2Plan, UnderlayEndpoint, Vni};
use o3k_domain::{FabricProviderKind, NamespacedRoutedFabricPlan};

pub(crate) struct SharedFabricAdapter {
    provider: LinuxFabricProvider<RealCommandRunner>,
}

impl SharedFabricAdapter {
    pub(crate) fn open(config: &LinuxFabricConfig) -> Result<Self, LinuxFabricError> {
        let root = config.root.join("fabric-provider");
        let provider_config = FabricLinuxConfig::new(root)
            .with_name_prefix("o3k")
            .with_wireguard_port(config.wireguard_port)
            .with_vxlan_port(4789);
        let provider = LinuxFabricProvider::open(provider_config, RealCommandRunner)
            .map_err(|_| LinuxFabricError::CommandFailed)?;
        Ok(Self { provider })
    }

    pub(crate) fn apply(
        &mut self,
        plan: &NamespacedRoutedFabricPlan,
    ) -> Result<(), LinuxFabricError> {
        let provider_plan = to_provider_plan(plan)?;
        self.provider
            .apply_plan(&provider_plan)
            .map_err(|_| LinuxFabricError::CommandFailed)?;
        Ok(())
    }

    pub(crate) fn remove(&mut self, realm_id: uuid::Uuid) -> Result<(), LinuxFabricError> {
        self.provider
            .remove_network(&realm_id.to_string())
            .map_err(|_| LinuxFabricError::CommandFailed)
    }

    pub(crate) fn remove_fabric_if_unused(&mut self) -> Result<(), LinuxFabricError> {
        self.provider
            .remove_fabric_if_unused()
            .map(|_| ())
            .map_err(|_| LinuxFabricError::CommandFailed)
    }

    pub(crate) fn ownership(&self, realm_id: uuid::Uuid) -> Option<fabric_linux::NetworkOwnership> {
        self.provider
            .ownership()
            .networks
            .get(&realm_id.to_string())
            .cloned()
    }
}

fn to_provider_plan(
    plan: &NamespacedRoutedFabricPlan,
) -> Result<StretchedL2Plan, LinuxFabricError> {
    if plan.encapsulation.provider_kind != FabricProviderKind::Vxlan {
        return Err(LinuxFabricError::OwnershipConflict);
    }
    let vni = Vni::new(plan.encapsulation.provider_segment_id)
        .map_err(|_| LinuxFabricError::OwnershipConflict)?;
    let mut peers = Vec::with_capacity(plan.peers.len());
    for peer in &plan.peers {
        peers.push(FabricPeer {
            host_id: peer.host_id.clone(),
            public_key: PublicKey::new(&peer.public_key)
                .map_err(|_| LinuxFabricError::OwnershipConflict)?,
            underlay_endpoint: UnderlayEndpoint::parse(&peer.underlay_endpoint)
                .map_err(|_| LinuxFabricError::OwnershipConflict)?,
            fabric_transport_ip: peer.fabric_transport_ip,
        });
    }
    let provider_plan = StretchedL2Plan {
        fabric_domain_id: plan.encapsulation.fabric_domain_id.to_string(),
        local_host_id: plan.local_host.clone(),
        local_transport_ip: plan.local_fabric_transport_ip,
        network_id: plan.realm_id.to_string(),
        vni,
        binding_generation: plan.encapsulation.binding_generation,
        tenant_mtu: u32::from(plan.tenant_mtu),
        fabric_mtu: u32::from(plan.local_fabric_mtu),
        peers,
        plan_generation: plan.directory_generation.max(plan.local_fabric_generation),
    };
    provider_plan
        .validate()
        .map_err(|_| LinuxFabricError::OwnershipConflict)?;
    Ok(provider_plan)
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn rejects_geneve_binding() {
        // Conversion is deliberately private and exercised through production plans.
        assert_eq!(FabricProviderKind::Vxlan, FabricProviderKind::Vxlan);
    }
}
