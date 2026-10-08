//! One generation-fenced DHCP authority for each stretched-L2 AddressRealm.
//!
//! This slice manages dnsmasq plus the authority's scoped gateway address.
//! Fabric remains the sole authority for the Realm bridge, TAPs, VXLAN, and HER.

use o3k_dhcp::{Binding, DhcpConfig, DhcpError, DhcpService, DnsmasqSupervisor};
use o3k_domain::NamespacedRoutedFabricPlan;
use serde::{Deserialize, Serialize};
use std::{
    collections::{BTreeMap, BTreeSet},
    fs, io,
    net::Ipv4Addr,
    path::{Path, PathBuf},
    process::Command,
};
use thiserror::Error;
use uuid::Uuid;

const LEASE_SECONDS: u32 = 3600;

#[derive(Debug, Error)]
pub enum FabricDhcpError {
    #[error("Fabric DHCP plan is missing canonical DHCP settings")]
    MissingIntent,
    #[error("Fabric DHCP plan does not contain a current participant")]
    MissingParticipants,
    #[error("Fabric DHCP endpoint host is absent from the current participant set")]
    MissingParticipant,
    #[error("Fabric DHCP generation is stale or conflicts with durable ownership")]
    StaleGeneration,
    #[error("Fabric DHCP durable ownership is corrupt")]
    CorruptOwnership(#[source] serde_json::Error),
    #[error("Fabric DHCP bridge address ownership is corrupt")]
    CorruptGatewayOwnership(#[source] serde_json::Error),
    #[error("Fabric DHCP bridge has foreign IPv4 state")]
    ForeignBridgeAddress,
    #[error("Fabric DHCP bridge address observation failed")]
    BridgeAddressObservation,
    #[error("Fabric DHCP bridge address command failed")]
    BridgeAddressCommand,
    #[error("Fabric DHCP state storage failed")]
    Storage(#[source] io::Error),
    #[error("Fabric DHCP service failed: {0}")]
    Dhcp(#[from] DhcpError),
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
struct Ownership {
    schema_version: u16,
    realm_id: Uuid,
    local_host: String,
    authority_host: String,
    realm_generation: u64,
    directory_generation: u64,
    binding_generation: u64,
    local_fabric_generation: u64,
    dhcp_enabled: bool,
    gateway: Option<Ipv4Addr>,
    tenant_mtu: u16,
    #[serde(default)]
    pending: bool,
    withdrawn: bool,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
struct GatewayAddressOwnership {
    schema_version: u16,
    realm_id: Uuid,
    local_host: String,
    authority_host: String,
    interface: String,
    address: Ipv4Addr,
    prefix_len: u8,
    realm_generation: u64,
    directory_generation: u64,
    binding_generation: u64,
    #[serde(default)]
    pending: bool,
}

impl GatewayAddressOwnership {
    fn from_plan(
        plan: &NamespacedRoutedFabricPlan,
        authority: &str,
        interface: &str,
        gateway: Ipv4Addr,
        pending: bool,
    ) -> Self {
        Self {
            schema_version: 1,
            realm_id: plan.realm_id,
            local_host: plan.local_host.clone(),
            authority_host: authority.to_owned(),
            interface: interface.to_owned(),
            address: gateway,
            // The bridge only needs to own the DHCP gateway address. A /32
            // avoids adding a second connected route for the tenant subnet.
            prefix_len: 32,
            realm_generation: plan.directory_generation,
            directory_generation: plan.directory_generation,
            binding_generation: plan.encapsulation.binding_generation,
            pending,
        }
    }

    fn same_authority(&self, desired: &Self) -> bool {
        self.realm_id == desired.realm_id
            && self.local_host == desired.local_host
            && self.authority_host == desired.authority_host
    }
}

#[derive(Debug, Deserialize)]
struct LinkAddressObservation {
    ifname: String,
    addr_info: Vec<AddressInfoObservation>,
}

#[derive(Debug, Deserialize)]
struct LinkIdentityObservation {
    ifname: String,
}

#[derive(Debug, Deserialize)]
struct AddressInfoObservation {
    local: Ipv4Addr,
    prefixlen: u8,
}

impl Ownership {
    fn from_plan(plan: &NamespacedRoutedFabricPlan, authority: &str, enabled: bool) -> Self {
        Self {
            schema_version: 1,
            realm_id: plan.realm_id,
            local_host: plan.local_host.clone(),
            authority_host: authority.to_owned(),
            realm_generation: plan.directory_generation,
            directory_generation: plan.directory_generation,
            binding_generation: plan.encapsulation.binding_generation,
            local_fabric_generation: plan.local_fabric_generation,
            dhcp_enabled: enabled,
            gateway: plan.dhcp.map(|dhcp| dhcp.gateway),
            tenant_mtu: plan.tenant_mtu,
            pending: false,
            withdrawn: false,
        }
    }

    fn generation(&self) -> (u64, u64, u64) {
        (
            self.realm_generation,
            self.directory_generation,
            self.binding_generation,
        )
    }
}

struct RealmRuntime {
    root: PathBuf,
    service: DhcpService,
    supervisor: Option<DnsmasqSupervisor>,
    ownership: Option<Ownership>,
    ip_binary: PathBuf,
    gateway_address: Option<GatewayAddressOwnership>,
}

impl RealmRuntime {
    fn open(root: PathBuf, dnsmasq: &Path, ip_binary: &Path) -> Result<Self, FabricDhcpError> {
        fs::create_dir_all(&root).map_err(FabricDhcpError::Storage)?;
        let service = DhcpService::open(&root)?;
        let supervisor = service.adopt_supervisor(dnsmasq)?;
        let ownership_path = root.join("fabric-dhcp-ownership.json");
        let ownership = match fs::read(ownership_path) {
            Ok(bytes) => {
                Some(serde_json::from_slice(&bytes).map_err(FabricDhcpError::CorruptOwnership)?)
            }
            Err(error) if error.kind() == io::ErrorKind::NotFound => None,
            Err(error) => return Err(FabricDhcpError::Storage(error)),
        };
        let gateway_address_path = root.join("gateway-address-ownership.json");
        let gateway_address = match fs::read(gateway_address_path) {
            Ok(bytes) => Some(
                serde_json::from_slice(&bytes).map_err(FabricDhcpError::CorruptGatewayOwnership)?,
            ),
            Err(error) if error.kind() == io::ErrorKind::NotFound => None,
            Err(error) => return Err(FabricDhcpError::Storage(error)),
        };
        Ok(Self {
            root,
            service,
            supervisor,
            ownership,
            ip_binary: ip_binary.to_owned(),
            gateway_address,
        })
    }

    fn persist_gateway_address(
        &mut self,
        ownership: GatewayAddressOwnership,
    ) -> Result<(), FabricDhcpError> {
        let path = self.root.join("gateway-address-ownership.json");
        let bytes = serde_json::to_vec_pretty(&ownership)
            .map_err(|_| FabricDhcpError::BridgeAddressObservation)?;
        let temporary = self.root.join(format!("gateway-{}.tmp", Uuid::now_v7()));
        fs::write(&temporary, bytes).map_err(FabricDhcpError::Storage)?;
        fs::rename(&temporary, path).map_err(FabricDhcpError::Storage)?;
        self.gateway_address = Some(ownership);
        Ok(())
    }

    fn observe_ipv4(&self, interface: &str) -> Result<Vec<(Ipv4Addr, u8)>, FabricDhcpError> {
        // `ip -j -4 addr show dev <link>` emits `[]` for an existing link
        // that has no IPv4 address. Verify the link separately so that this
        // valid no-address state is distinguishable from a missing bridge.
        let link_output = Command::new(&self.ip_binary)
            .args(["-j", "link", "show", "dev", interface])
            .output()
            .map_err(|_| FabricDhcpError::BridgeAddressCommand)?;
        if !link_output.status.success() {
            return Err(FabricDhcpError::BridgeAddressCommand);
        }
        let links: Vec<LinkIdentityObservation> = serde_json::from_slice(&link_output.stdout)
            .map_err(|_| FabricDhcpError::BridgeAddressObservation)?;
        if links.len() != 1 || links[0].ifname != interface {
            return Err(FabricDhcpError::BridgeAddressObservation);
        }

        let output = Command::new(&self.ip_binary)
            .args(["-j", "-4", "addr", "show", "dev", interface])
            .output()
            .map_err(|_| FabricDhcpError::BridgeAddressCommand)?;
        if !output.status.success() {
            return Err(FabricDhcpError::BridgeAddressCommand);
        }
        let links: Vec<LinkAddressObservation> = serde_json::from_slice(&output.stdout)
            .map_err(|_| FabricDhcpError::BridgeAddressObservation)?;
        if links.is_empty() {
            return Ok(Vec::new());
        }
        if links.len() != 1 || links[0].ifname != interface {
            return Err(FabricDhcpError::BridgeAddressObservation);
        }
        Ok(links[0]
            .addr_info
            .iter()
            .map(|address| (address.local, address.prefixlen))
            .collect())
    }

    fn mutate_gateway_address(
        &self,
        verb: &str,
        ownership: &GatewayAddressOwnership,
    ) -> Result<(), FabricDhcpError> {
        let address = format!("{}/{}", ownership.address, ownership.prefix_len);
        let output = Command::new(&self.ip_binary)
            .args(["addr", verb, &address, "dev", &ownership.interface])
            .output()
            .map_err(|_| FabricDhcpError::BridgeAddressCommand)?;
        if output.status.success() {
            Ok(())
        } else {
            Err(FabricDhcpError::BridgeAddressCommand)
        }
    }

    fn ensure_gateway_address(
        &mut self,
        desired: GatewayAddressOwnership,
    ) -> Result<(), FabricDhcpError> {
        if desired.prefix_len != 32 {
            return Err(FabricDhcpError::BridgeAddressObservation);
        }
        if let Some(current) = self.gateway_address.clone() {
            let generations = (
                current.realm_generation,
                current.directory_generation,
                current.binding_generation,
            );
            let wanted_generations = (
                desired.realm_generation,
                desired.directory_generation,
                desired.binding_generation,
            );
            if generations > wanted_generations || !current.same_authority(&desired) {
                return Err(FabricDhcpError::StaleGeneration);
            }
            if current.interface != desired.interface || current.address != desired.address {
                self.release_gateway_address()?;
            } else {
                let observed = self.observe_ipv4(&current.interface)?;
                if observed == [(current.address, current.prefix_len)] {
                    let mut committed = desired;
                    committed.pending = false;
                    return self.persist_gateway_address(committed);
                }
                if observed.is_empty() {
                    // The previous attempt persisted intent before a crash
                    // or the owned bridge address was lost; durable ownership
                    // authorizes restoring this exact address only.
                } else {
                    return Err(FabricDhcpError::ForeignBridgeAddress);
                }
            }
        }

        let existing = self.observe_ipv4(&desired.interface)?;
        if !existing.is_empty() {
            return Err(FabricDhcpError::ForeignBridgeAddress);
        }
        let mut pending = desired.clone();
        pending.pending = true;
        self.persist_gateway_address(pending)?;
        self.mutate_gateway_address("add", &desired)?;
        if self.observe_ipv4(&desired.interface)? != [(desired.address, desired.prefix_len)] {
            return Err(FabricDhcpError::ForeignBridgeAddress);
        }
        let mut committed = desired;
        committed.pending = false;
        self.persist_gateway_address(committed)
    }

    fn release_gateway_address(&mut self) -> Result<(), FabricDhcpError> {
        let Some(ownership) = self.gateway_address.clone() else {
            return Ok(());
        };
        let observed = self.observe_ipv4(&ownership.interface)?;
        if observed == [(ownership.address, ownership.prefix_len)] {
            self.mutate_gateway_address("del", &ownership)?;
            if self
                .observe_ipv4(&ownership.interface)?
                .contains(&(ownership.address, ownership.prefix_len))
            {
                return Err(FabricDhcpError::ForeignBridgeAddress);
            }
        } else if observed.contains(&(ownership.address, ownership.prefix_len)) {
            return Err(FabricDhcpError::ForeignBridgeAddress);
        }
        let path = self.root.join("gateway-address-ownership.json");
        match fs::remove_file(path) {
            Ok(()) => {
                self.gateway_address = None;
                Ok(())
            }
            Err(error) if error.kind() == io::ErrorKind::NotFound => {
                self.gateway_address = None;
                Ok(())
            }
            Err(error) => Err(FabricDhcpError::Storage(error)),
        }
    }

    fn check_generation(
        &self,
        desired: &Ownership,
        withdrawal: bool,
    ) -> Result<(), FabricDhcpError> {
        if let Some(current) = &self.ownership
            && (desired.generation() < current.generation()
                || (desired.generation() == current.generation()
                    && (desired.local_host != current.local_host
                        || (!withdrawal && desired.authority_host != current.authority_host)
                        || (!withdrawal
                            && (desired.dhcp_enabled != current.dhcp_enabled
                                || desired.gateway != current.gateway
                                || desired.tenant_mtu != current.tenant_mtu
                                || desired.withdrawn != current.withdrawn
                                || desired.local_fabric_generation
                                    != current.local_fabric_generation)))))
        {
            return Err(FabricDhcpError::StaleGeneration);
        }
        Ok(())
    }

    fn persist_ownership(&mut self, ownership: Ownership) -> Result<(), FabricDhcpError> {
        let path = self.root.join("fabric-dhcp-ownership.json");
        let bytes =
            serde_json::to_vec_pretty(&ownership).map_err(|_| FabricDhcpError::StaleGeneration)?;
        let temporary = self.root.join(format!("ownership-{}.tmp", Uuid::now_v7()));
        fs::write(&temporary, bytes).map_err(FabricDhcpError::Storage)?;
        fs::rename(&temporary, path).map_err(FabricDhcpError::Storage)?;
        self.ownership = Some(ownership);
        Ok(())
    }

    fn clear_owned_service(&mut self) -> Result<(), FabricDhcpError> {
        if let Some(supervisor) = self.supervisor.as_mut() {
            supervisor.stop()?;
            self.supervisor = None;
        }
        let existing = self
            .service
            .bindings()
            .map(|binding| binding.port_id.clone())
            .collect::<Vec<_>>();
        for port_id in existing {
            self.service.remove_binding_and_lease(&port_id)?;
        }
        if self.service.configuration().is_some() {
            self.service.clear_configuration()?;
        }
        self.release_gateway_address()?;
        Ok(())
    }

    fn reconcile_authority(
        &mut self,
        config: DhcpConfig,
        bindings: Vec<Binding>,
        dnsmasq: &Path,
    ) -> Result<(), FabricDhcpError> {
        if let Some(supervisor) = self.supervisor.as_mut() {
            supervisor.stop()?;
            self.supervisor = None;
        }
        let wanted = bindings
            .iter()
            .map(|binding| (binding.port_id.clone(), binding.clone()))
            .collect::<BTreeMap<_, _>>();
        let existing = self
            .service
            .bindings()
            .map(|binding| (binding.port_id.clone(), binding.clone()))
            .collect::<BTreeMap<_, _>>();
        for (port_id, current) in &existing {
            if wanted.get(port_id) != Some(current) {
                self.service.remove_binding_and_lease(port_id)?;
            }
        }
        if self
            .service
            .configuration()
            .is_some_and(|current| current != &config)
        {
            for port_id in self
                .service
                .bindings()
                .map(|binding| binding.port_id.clone())
                .collect::<Vec<_>>()
            {
                self.service.remove_binding_and_lease(&port_id)?;
            }
            self.service.clear_configuration()?;
        }
        self.service.configure(config)?;
        for binding in bindings {
            if self.service.binding(&binding.port_id) != Some(&binding) {
                self.service.upsert_binding(binding)?;
            }
        }
        self.supervisor = Some(self.service.start(dnsmasq)?);
        if self
            .supervisor
            .as_mut()
            .is_none_or(|supervisor| !supervisor.is_running().unwrap_or(false))
        {
            return Err(FabricDhcpError::Dhcp(DhcpError::CommandFailed));
        }
        Ok(())
    }
}

/// Reconciles DHCP independently of Fabric link creation and ownership.
pub struct FabricDhcpRealizer {
    root: PathBuf,
    dnsmasq: PathBuf,
    ip_binary: PathBuf,
    realms: BTreeMap<Uuid, RealmRuntime>,
}

impl FabricDhcpRealizer {
    pub fn open(
        root: impl Into<PathBuf>,
        dnsmasq: impl Into<PathBuf>,
    ) -> Result<Self, FabricDhcpError> {
        let root = root.into();
        fs::create_dir_all(&root).map_err(FabricDhcpError::Storage)?;
        Ok(Self {
            root,
            dnsmasq: dnsmasq.into(),
            ip_binary: PathBuf::from("ip"),
            realms: BTreeMap::new(),
        })
    }

    #[cfg(test)]
    fn open_with_ip(
        root: impl Into<PathBuf>,
        dnsmasq: impl Into<PathBuf>,
        ip_binary: impl Into<PathBuf>,
    ) -> Result<Self, FabricDhcpError> {
        let mut realizer = Self::open(root, dnsmasq)?;
        realizer.ip_binary = ip_binary.into();
        Ok(realizer)
    }

    fn runtime(&mut self, realm_id: Uuid) -> Result<&mut RealmRuntime, FabricDhcpError> {
        if !self.realms.contains_key(&realm_id) {
            let path = self.root.join(realm_id.to_string());
            self.realms.insert(
                realm_id,
                RealmRuntime::open(path, &self.dnsmasq, &self.ip_binary)?,
            );
        }
        self.realms
            .get_mut(&realm_id)
            .ok_or(FabricDhcpError::StaleGeneration)
    }

    pub fn apply(
        &mut self,
        plan: &NamespacedRoutedFabricPlan,
        realm_generation: u64,
        realm_bridge: &str,
    ) -> Result<(), FabricDhcpError> {
        if realm_generation != plan.directory_generation {
            return Err(FabricDhcpError::StaleGeneration);
        }
        let dhcp = plan.dhcp.ok_or(FabricDhcpError::MissingIntent)?;
        let participants = current_participants(plan)?;
        let authority = participants
            .first()
            .ok_or(FabricDhcpError::MissingParticipants)?;
        let ownership = Ownership::from_plan(plan, authority, dhcp.enabled);
        let dnsmasq = self.dnsmasq.clone();
        let runtime = self.runtime(plan.realm_id)?;
        runtime.check_generation(&ownership, false)?;
        let mut pending = ownership.clone();
        pending.pending = true;
        runtime.persist_ownership(pending)?;

        if !dhcp.enabled || plan.local_host != *authority {
            runtime.clear_owned_service()?;
            return runtime.persist_ownership(ownership);
        }

        runtime.ensure_gateway_address(GatewayAddressOwnership::from_plan(
            plan,
            authority,
            realm_bridge,
            dhcp.gateway,
            false,
        ))?;

        let bindings = plan
            .directory
            .entries
            .iter()
            .map(|entry| Binding {
                port_id: entry.endpoint_id.to_string(),
                mac: entry.mac.clone(),
                address: entry.fixed_ip,
            })
            .collect::<Vec<_>>();
        let config = DhcpConfig {
            subnet: format!(
                "{}/{}",
                plan.realm_prefix.network, plan.realm_prefix.prefix_len
            ),
            gateway: dhcp.gateway,
            dns: Vec::new(),
            interface: realm_bridge.to_owned(),
            lease_seconds: LEASE_SECONDS,
            mtu: Some(plan.tenant_mtu),
        };
        runtime.reconcile_authority(config, bindings, &dnsmasq)?;
        runtime.persist_ownership(ownership)
    }

    pub fn remove(
        &mut self,
        plan: &NamespacedRoutedFabricPlan,
        realm_generation: u64,
    ) -> Result<(), FabricDhcpError> {
        let participants = current_participants(plan).unwrap_or_default();
        let authority = participants
            .first()
            .cloned()
            .unwrap_or_else(|| plan.local_host.clone());
        let mut ownership = Ownership::from_plan(plan, &authority, false);
        ownership.realm_generation = realm_generation;
        ownership.directory_generation = plan.directory_generation;
        ownership.withdrawn = true;
        let runtime = self.runtime(plan.realm_id)?;
        runtime.check_generation(&ownership, true)?;
        ownership.pending = true;
        runtime.persist_ownership(ownership.clone())?;
        runtime.clear_owned_service()?;
        ownership.pending = false;
        runtime.persist_ownership(ownership)
    }

    pub fn observe(
        &mut self,
        plan: &NamespacedRoutedFabricPlan,
        realm_generation: u64,
        realm_bridge: &str,
    ) -> Result<bool, FabricDhcpError> {
        let Some(dhcp) = plan.dhcp else {
            return Ok(false);
        };
        let participants = current_participants(plan)?;
        let authority = participants
            .first()
            .ok_or(FabricDhcpError::MissingParticipants)?;
        let desired = Ownership::from_plan(plan, authority, dhcp.enabled);
        if realm_generation != desired.realm_generation {
            return Ok(false);
        }
        let runtime = self.runtime(plan.realm_id)?;
        if runtime.ownership.as_ref() != Some(&desired) || desired.pending {
            return Ok(false);
        }
        let is_authority = dhcp.enabled && plan.local_host == *authority;
        if !is_authority {
            return Ok(runtime.supervisor.is_none()
                && runtime.service.bindings().next().is_none()
                && runtime.gateway_address.is_none());
        }
        let expected_config = DhcpConfig {
            subnet: format!(
                "{}/{}",
                plan.realm_prefix.network, plan.realm_prefix.prefix_len
            ),
            gateway: dhcp.gateway,
            dns: Vec::new(),
            interface: realm_bridge.to_owned(),
            lease_seconds: LEASE_SECONDS,
            mtu: Some(plan.tenant_mtu),
        };
        let expected = plan
            .directory
            .entries
            .iter()
            .map(|entry| {
                (
                    entry.endpoint_id.to_string(),
                    (entry.mac.clone(), entry.fixed_ip),
                )
            })
            .collect::<BTreeMap<_, _>>();
        let actual = runtime
            .service
            .bindings()
            .map(|binding| {
                (
                    binding.port_id.clone(),
                    (binding.mac.clone(), binding.address),
                )
            })
            .collect::<BTreeMap<_, _>>();
        let running = match runtime.supervisor.as_mut() {
            Some(supervisor) => supervisor.is_running()?,
            None => false,
        };
        let expected_gateway =
            GatewayAddressOwnership::from_plan(plan, authority, realm_bridge, dhcp.gateway, false);
        let gateway_address_matches = runtime.gateway_address.as_ref() == Some(&expected_gateway)
            && runtime
                .observe_ipv4(realm_bridge)
                .is_ok_and(|addresses| addresses == [(dhcp.gateway, 32)]);
        Ok(running
            && gateway_address_matches
            && runtime.service.configuration() == Some(&expected_config)
            && actual == expected)
    }

    pub fn observe_removed(
        &mut self,
        plan: &NamespacedRoutedFabricPlan,
        realm_generation: u64,
    ) -> Result<bool, FabricDhcpError> {
        let runtime = self.runtime(plan.realm_id)?;
        let Some(ownership) = runtime.ownership.as_ref() else {
            return Ok(false);
        };
        let no_service = runtime.supervisor.is_none()
            && runtime.service.configuration().is_none()
            && runtime.service.bindings().next().is_none();
        Ok(no_service
            && !ownership.pending
            && ownership.withdrawn
            && ownership.local_host == plan.local_host
            && ownership.realm_generation == realm_generation
            && ownership.directory_generation == plan.directory_generation
            && ownership.binding_generation == plan.encapsulation.binding_generation)
    }
}

fn current_participants(plan: &NamespacedRoutedFabricPlan) -> Result<Vec<String>, FabricDhcpError> {
    let participants = plan
        .directory
        .entries
        .iter()
        .map(|entry| entry.selected_host.clone())
        .collect::<BTreeSet<_>>();
    if participants.is_empty() {
        return Err(FabricDhcpError::MissingParticipants);
    }
    let known = plan
        .peers
        .iter()
        .map(|peer| peer.host_id.as_str())
        .chain(std::iter::once(plan.local_host.as_str()))
        .collect::<BTreeSet<_>>();
    if participants
        .iter()
        .any(|host| !known.contains(host.as_str()))
    {
        return Err(FabricDhcpError::MissingParticipant);
    }
    Ok(participants.into_iter().collect())
}

#[cfg(test)]
#[allow(clippy::expect_used)]
mod tests {
    use super::*;
    use o3k_domain::{
        AddressRealm, EndpointLocation, FabricDhcpIntent, FabricHostIdentity, FabricPeer,
        FabricProviderKind, Ipv4Prefix, RealmEncapsulationBinding, RealmEndpointDirectory,
    };
    use std::os::unix::fs::PermissionsExt;
    use std::process::Command;

    fn host(id: &str, ip: &str) -> FabricHostIdentity {
        FabricHostIdentity {
            host_id: id.to_owned(),
            public_key: format!("key-{id}"),
            underlay_endpoint: format!("{ip}:51820"),
            fabric_transport_ip: ip.parse().expect("transport IP"),
            provider_version: "test".to_owned(),
            fabric_generation: 1,
            underlay_mtu: 1500,
            fabric_mtu: 1440,
        }
    }

    fn plan(host_ids: &[&str], local: &str, enabled: bool) -> NamespacedRoutedFabricPlan {
        let realm_id = Uuid::new_v4();
        let realm = AddressRealm {
            id: realm_id,
            network_id: Uuid::new_v4(),
            project_id: "project".to_owned(),
            prefix: Ipv4Prefix::new("192.0.2.0".parse().expect("prefix"), 24)
                .expect("valid prefix"),
            overlapping_prefixes: true,
        };
        let locations = host_ids
            .iter()
            .enumerate()
            .map(|(index, host)| EndpointLocation {
                endpoint_id: Uuid::new_v4(),
                project_id: "project".to_owned(),
                realm_id,
                fixed_ip: Ipv4Addr::new(192, 0, 2, 10 + index as u8),
                mac: format!("02:00:00:00:00:{:02x}", index + 1),
                selected_host: (*host).to_owned(),
                endpoint_generation: 1,
                placement_generation: 1,
            })
            .collect::<Vec<_>>();
        let directory =
            RealmEndpointDirectory::build(&realm, locations, &[], 1).expect("directory");
        let identities = host_ids
            .iter()
            .enumerate()
            .map(|(index, id)| host(id, &format!("198.51.100.{}", index + 1)))
            .collect::<Vec<_>>();
        let local_identity = identities
            .iter()
            .find(|identity| identity.host_id == local)
            .expect("local participant");
        let binding = RealmEncapsulationBinding {
            fabric_domain_id: Uuid::new_v4(),
            realm_id,
            provider_kind: FabricProviderKind::Vxlan,
            provider_segment_id: 42,
            binding_generation: 1,
        };
        let fabric = directory
            .compile_fabric_plan(local_identity, &identities, 1390, &binding)
            .expect("fabric plan");
        NamespacedRoutedFabricPlan {
            dhcp: Some(FabricDhcpIntent {
                enabled,
                gateway: "192.0.2.1".parse().expect("gateway"),
            }),
            ..fabric
        }
    }

    fn dnsmasq_stub(root: &Path) -> PathBuf {
        let path = root.join("dnsmasq-stub.sh");
        fs::write(
            &path,
            "#!/bin/sh\nif [ \"$1\" = \"--test\" ]; then exit 0; fi\nsleep 60\n",
        )
        .expect("write dnsmasq stub");
        fs::set_permissions(&path, fs::Permissions::from_mode(0o755)).expect("chmod stub");
        path
    }

    fn fake_ip(root: &Path) -> PathBuf {
        let state = root.join("fake-ip-state.json");
        let log = root.join("fake-ip.log");
        if !state.exists() {
            fs::write(&state, "{}").expect("write fake ip state");
        }
        let path = root.join("fake-ip");
        let script = format!(
            "#!/usr/bin/env python3\nimport json, pathlib, sys\nstate=pathlib.Path({:?})\nlog=pathlib.Path({:?})\nargs=sys.argv[1:]\nwith log.open('a') as f: f.write(' '.join(args)+'\\n')\ndata=json.loads(state.read_text())\nif len(args)==5 and args[:4]==['-j','link','show','dev']:\n    dev=args[4]\n    print(json.dumps([] if dev in data.get('__missing__',[]) else [{{'ifname':dev}}]))\nelif len(args)==6 and args[:5]==['-j','-4','addr','show','dev']:\n    dev=args[5]\n    if dev in data.get('__missing__',[]): sys.exit(1)\n    values=data.get(dev,[])\n    print(json.dumps([] if not values else [{{'ifname':dev,'addr_info':[{{'local':x.split('/')[0],'prefixlen':int(x.split('/')[1])}} for x in values]}}]))\nelif len(args)==5 and args[:2]==['addr','add'] and args[3]=='dev':\n    address,dev=args[2],args[4]\n    if dev in data.get('__missing__',[]): sys.exit(1)\n    values=data.setdefault(dev,[])\n    if address in values: sys.exit(2)\n    values.append(address); state.write_text(json.dumps(data))\nelif len(args)==5 and args[:2]==['addr','del'] and args[3]=='dev':\n    address,dev=args[2],args[4]\n    values=data.get(dev,[])\n    if address not in values: sys.exit(2)\n    values.remove(address); state.write_text(json.dumps(data))\nelse: sys.exit(2)\n",
            state.display().to_string(),
            log.display().to_string(),
        );
        fs::write(&path, script).expect("write fake ip");
        fs::set_permissions(&path, fs::Permissions::from_mode(0o755)).expect("chmod fake ip");
        path
    }

    fn open_test_dhcp(
        root: impl Into<PathBuf>,
        dnsmasq: impl Into<PathBuf>,
    ) -> Result<FabricDhcpRealizer, FabricDhcpError> {
        let root = root.into();
        fs::create_dir_all(&root).expect("create fake DHCP root");
        let ip = fake_ip(&root);
        FabricDhcpRealizer::open_with_ip(root, dnsmasq, ip)
    }

    fn peer(id: &str, ip: &str) -> FabricPeer {
        FabricPeer {
            host_id: id.to_owned(),
            public_key: format!("key-{id}"),
            underlay_endpoint: format!("{ip}:51820"),
            fabric_transport_ip: ip.parse().expect("transport IP"),
            fabric_generation: 1,
        }
    }

    #[test]
    fn deterministic_authority_has_all_remote_bindings_and_restarts() {
        let root = std::env::temp_dir().join(format!("o3k-fabric-dhcp-{}", Uuid::now_v7()));
        fs::create_dir_all(&root).expect("create test root");
        let dnsmasq = dnsmasq_stub(&root);
        let plan_a = plan(&["host-c", "host-a", "host-b"], "host-a", true);
        let mut plan_b = NamespacedRoutedFabricPlan {
            local_host: "host-b".into(),
            ..plan_a.clone()
        };
        plan_b.peers = vec![
            peer("host-a", "198.51.100.1"),
            peer("host-c", "198.51.100.3"),
        ];
        let mut plan_c = NamespacedRoutedFabricPlan {
            local_host: "host-c".into(),
            ..plan_a.clone()
        };
        plan_c.peers = vec![
            peer("host-a", "198.51.100.1"),
            peer("host-b", "198.51.100.2"),
        ];
        let mut non_authority = open_test_dhcp(root.join("b"), &dnsmasq).expect("open host b DHCP");
        non_authority
            .apply(&plan_b, 1, "o3k-b-test")
            .expect("apply nonauthority");
        assert!(
            non_authority
                .observe(&plan_b, 1, "o3k-b-test")
                .expect("observe B")
        );
        assert!(non_authority.realms[&plan_a.realm_id].supervisor.is_none());

        let mut third_host = open_test_dhcp(root.join("c"), &dnsmasq).expect("open host c DHCP");
        third_host
            .apply(&plan_c, 1, "o3k-c-test")
            .expect("apply host C");
        assert!(
            third_host
                .observe(&plan_c, 1, "o3k-c-test")
                .expect("observe C")
        );
        assert!(third_host.realms[&plan_a.realm_id].supervisor.is_none());

        let mut authority = open_test_dhcp(root.join("a"), &dnsmasq).expect("open host a DHCP");
        authority
            .apply(&plan_a, 1, "o3k-b-test")
            .expect("apply authority");
        assert!(
            authority
                .observe(&plan_a, 1, "o3k-b-test")
                .expect("observe authority")
        );
        let bindings = authority.realms[&plan_a.realm_id]
            .service
            .bindings()
            .count();
        assert_eq!(bindings, 3, "all host endpoints must be bound");
        assert_eq!(
            authority.realms[&plan_a.realm_id]
                .service
                .configuration()
                .expect("authority DHCP config")
                .mtu,
            Some(1390),
            "tenant MTU must be sent through DHCP"
        );
        assert!(
            authority.realms[&plan_a.realm_id]
                .service
                .bindings()
                .any(|binding| binding.address == Ipv4Addr::new(192, 0, 2, 12))
        );
        assert!(non_authority.realms[&plan_a.realm_id].supervisor.is_none());
        assert!(third_host.realms[&plan_a.realm_id].supervisor.is_none());

        drop(authority);
        let mut recovered =
            open_test_dhcp(root.join("a"), &dnsmasq).expect("reopen DHCP authority");
        recovered
            .apply(&plan_a, 1, "o3k-b-test")
            .expect("reconcile after authority restart");
        assert!(
            recovered
                .observe(&plan_a, 1, "o3k-b-test")
                .expect("observe recovered")
        );
        let _ = fs::remove_dir_all(root);
    }

    #[test]
    fn one_host_realm_has_one_serving_authority() {
        let root = std::env::temp_dir().join(format!("o3k-fabric-dhcp-one-{}", Uuid::now_v7()));
        fs::create_dir_all(&root).expect("create test root");
        let dnsmasq = dnsmasq_stub(&root);
        let plan = plan(&["host-a"], "host-a", true);
        let mut realizer = open_test_dhcp(root.join("a"), &dnsmasq).expect("open host A DHCP");
        realizer.apply(&plan, 1, "o3k-realm").expect("apply DHCP");
        assert!(
            realizer
                .observe(&plan, 1, "o3k-realm")
                .expect("observe DHCP")
        );
        assert_eq!(
            realizer.realms[&plan.realm_id].service.bindings().count(),
            1
        );
        assert!(realizer.realms[&plan.realm_id].supervisor.is_some());
        assert_eq!(
            realizer.realms[&plan.realm_id]
                .gateway_address
                .as_ref()
                .map(|owned| (owned.interface.as_str(), owned.address, owned.prefix_len)),
            Some(("o3k-realm", Ipv4Addr::new(192, 0, 2, 1), 32))
        );
        let address_state: serde_json::Value = serde_json::from_slice(
            &fs::read(root.join("a/fake-ip-state.json")).expect("read fake addresses"),
        )
        .expect("parse fake addresses");
        assert_eq!(address_state["o3k-realm"][0], "192.0.2.1/32");
        let _ = fs::remove_dir_all(root);
    }

    #[test]
    fn foreign_bridge_address_fails_closed_without_mutation() {
        let root = std::env::temp_dir().join(format!("o3k-fabric-dhcp-foreign-{}", Uuid::now_v7()));
        fs::create_dir_all(&root).expect("create test root");
        let dnsmasq = dnsmasq_stub(&root);
        fs::create_dir_all(root.join("a")).expect("create host A DHCP root");
        let ip = fake_ip(&root.join("a"));
        let state = root.join("a/fake-ip-state.json");
        fs::write(&state, r#"{"o3k-realm":["192.0.2.9/24"]}"#)
            .expect("write foreign bridge address");
        let plan = plan(&["host-a"], "host-a", true);
        let mut realizer =
            FabricDhcpRealizer::open_with_ip(root.join("a"), &dnsmasq, ip).expect("open DHCP");
        assert!(matches!(
            realizer.apply(&plan, 1, "o3k-realm"),
            Err(FabricDhcpError::ForeignBridgeAddress)
        ));
        let addresses: serde_json::Value =
            serde_json::from_slice(&fs::read(state).expect("read foreign address state"))
                .expect("parse foreign address state");
        assert_eq!(addresses["o3k-realm"][0], "192.0.2.9/24");
        assert!(realizer.realms[&plan.realm_id].supervisor.is_none());
        let _ = fs::remove_dir_all(root);
    }

    #[test]
    fn missing_realm_bridge_is_distinct_from_an_existing_bridge_without_ipv4() {
        let root =
            std::env::temp_dir().join(format!("o3k-fabric-dhcp-missing-link-{}", Uuid::now_v7()));
        fs::create_dir_all(&root).expect("create test root");
        let dnsmasq = dnsmasq_stub(&root);
        fs::create_dir_all(root.join("a")).expect("create host A DHCP root");
        let state = root.join("a/fake-ip-state.json");
        fs::write(&state, r#"{"__missing__":["o3k-realm"]}"#).expect("write missing bridge state");
        let ip = fake_ip(&root.join("a"));
        let plan = plan(&["host-a"], "host-a", true);
        let mut realizer = FabricDhcpRealizer::open_with_ip(root.join("a"), &dnsmasq, ip.clone())
            .expect("open DHCP");
        assert!(matches!(
            realizer.apply(&plan, 1, "o3k-realm"),
            Err(FabricDhcpError::BridgeAddressObservation)
        ));
        let commands = fs::read_to_string(root.join("a/fake-ip.log")).expect("read command log");
        assert!(
            !commands
                .lines()
                .any(|command| command.starts_with("addr add "))
        );
        assert!(realizer.realms[&plan.realm_id].supervisor.is_none());
        let _ = fs::remove_dir_all(root);
    }

    #[test]
    fn failed_start_keeps_pending_state_for_safe_retry() {
        let root = std::env::temp_dir().join(format!("o3k-fabric-dhcp-pending-{}", Uuid::now_v7()));
        fs::create_dir_all(&root).expect("create test root");
        let bad_dnsmasq = root.join("dnsmasq-fails.sh");
        fs::write(
            &bad_dnsmasq,
            "#!/bin/sh\nif [ \"$1\" = \"--test\" ]; then exit 0; fi\nexit 1\n",
        )
        .expect("write failing dnsmasq stub");
        fs::set_permissions(&bad_dnsmasq, fs::Permissions::from_mode(0o755))
            .expect("chmod failing stub");
        let good_dnsmasq = dnsmasq_stub(&root);
        let plan = plan(&["host-a"], "host-a", true);
        let mut failed = open_test_dhcp(root.join("a"), &bad_dnsmasq).expect("open failing DHCP");
        assert!(failed.apply(&plan, 1, "o3k-realm").is_err());
        assert!(
            failed.realms[&plan.realm_id]
                .ownership
                .as_ref()
                .expect("pending ownership")
                .pending
        );
        drop(failed);

        let mut retry = open_test_dhcp(root.join("a"), &good_dnsmasq).expect("reopen DHCP");
        retry
            .apply(&plan, 1, "o3k-realm")
            .expect("recover pending apply");
        assert!(
            retry
                .observe(&plan, 1, "o3k-realm")
                .expect("observe recovered DHCP")
        );
        assert!(
            !retry.realms[&plan.realm_id]
                .ownership
                .as_ref()
                .expect("committed ownership")
                .pending
        );
        let _ = fs::remove_dir_all(root);
    }

    #[test]
    fn endpoint_removal_reconciles_binding_and_lease() {
        let root = std::env::temp_dir().join(format!("o3k-fabric-dhcp-remove-{}", Uuid::now_v7()));
        fs::create_dir_all(&root).expect("create test root");
        let dnsmasq = dnsmasq_stub(&root);
        let mut current = plan(&["host-a", "host-b"], "host-a", true);
        let removed = current
            .directory
            .entries
            .iter()
            .find(|entry| entry.selected_host == "host-b")
            .expect("remote endpoint")
            .clone();
        let mut authority = open_test_dhcp(root.join("a"), &dnsmasq).expect("open authority");
        authority
            .apply(&current, 1, "o3k-realm")
            .expect("apply initial bindings");
        let service = &authority.realms[&current.realm_id].service;
        fs::write(
            service.managed_lease_path(),
            format!("1 {} {} remote *\n", removed.mac, removed.fixed_ip),
        )
        .expect("write managed lease fixture");

        current
            .directory
            .entries
            .retain(|entry| entry.endpoint_id != removed.endpoint_id);
        current.directory_generation = 2;
        current.directory.directory_generation = 2;
        authority
            .apply(&current, 2, "o3k-realm")
            .expect("reconcile endpoint removal");
        assert_eq!(
            authority.realms[&current.realm_id]
                .service
                .bindings()
                .count(),
            1
        );
        let leases = fs::read_to_string(
            authority.realms[&current.realm_id]
                .service
                .managed_lease_path(),
        )
        .expect("read managed leases");
        assert!(!leases.contains(&removed.mac));
        assert!(
            authority
                .observe(&current, 2, "o3k-realm")
                .expect("observe update")
        );
        let _ = fs::remove_dir_all(root);
    }

    #[test]
    fn authority_withdrawal_reselection_and_teardown_are_scoped() {
        let root =
            std::env::temp_dir().join(format!("o3k-fabric-dhcp-transition-{}", Uuid::now_v7()));
        fs::create_dir_all(&root).expect("create test root");
        let dnsmasq = dnsmasq_stub(&root);
        let original = plan(&["host-a", "host-b", "host-c"], "host-a", true);
        let mut authority_a = open_test_dhcp(root.join("a"), &dnsmasq).expect("open authority A");
        authority_a
            .apply(&original, 1, "o3k-realm")
            .expect("start authority A");
        let address_state: serde_json::Value = serde_json::from_slice(
            &fs::read(root.join("a/fake-ip-state.json")).expect("read authority A address"),
        )
        .expect("parse A address");
        assert_eq!(address_state["o3k-realm"][0], "192.0.2.1/32");

        let mut after_a_departure = original.clone();
        after_a_departure
            .directory
            .entries
            .retain(|entry| entry.selected_host != "host-a");
        after_a_departure.directory_generation = 2;
        after_a_departure.directory.directory_generation = 2;
        authority_a
            .remove(&after_a_departure, 2)
            .expect("withdraw departing authority");
        assert!(
            authority_a
                .observe_removed(&after_a_departure, 2)
                .expect("observe authority withdrawal")
        );
        let address_state: serde_json::Value = serde_json::from_slice(
            &fs::read(root.join("a/fake-ip-state.json")).expect("read withdrawn address"),
        )
        .expect("parse withdrawn address");
        assert_eq!(address_state["o3k-realm"].as_array().map(Vec::len), Some(0));
        let stale_apply = authority_a.apply(&original, 1, "o3k-realm");
        assert!(matches!(stale_apply, Err(FabricDhcpError::StaleGeneration)));

        let mut plan_b = after_a_departure.clone();
        plan_b.local_host = "host-b".to_owned();
        plan_b.peers = vec![
            peer("host-a", "198.51.100.1"),
            peer("host-c", "198.51.100.3"),
        ];
        let mut authority_b = open_test_dhcp(root.join("b"), &dnsmasq).expect("open authority B");
        authority_b
            .apply(&plan_b, 2, "o3k-realm")
            .expect("start reselected authority B");
        let address_state: serde_json::Value = serde_json::from_slice(
            &fs::read(root.join("b/fake-ip-state.json")).expect("read authority B address"),
        )
        .expect("parse B address");
        assert_eq!(address_state["o3k-realm"][0], "192.0.2.1/32");
        assert!(
            authority_b
                .observe(&plan_b, 2, "o3k-realm")
                .expect("observe authority B")
        );
        assert!(authority_a.realms[&original.realm_id].supervisor.is_none());
        assert!(authority_b.realms[&original.realm_id].supervisor.is_some());
        let foreign_marker = root.join("foreign-dnsmasq-state");
        fs::write(&foreign_marker, "foreign state").expect("write foreign state marker");
        let mut foreign_process = Command::new("sleep")
            .arg("60")
            .spawn()
            .expect("start foreign process");

        let empty_directory = RealmEndpointDirectory::build(
            &AddressRealm {
                id: plan_b.realm_id,
                network_id: Uuid::new_v4(),
                project_id: "project".to_owned(),
                prefix: plan_b.realm_prefix,
                overlapping_prefixes: true,
            },
            Vec::new(),
            &[],
            3,
        )
        .expect("empty teardown directory");
        let mut teardown = plan_b.clone();
        teardown.directory = empty_directory;
        teardown.directory_generation = 3;
        teardown.directory.directory_generation = 3;
        authority_b
            .remove(&teardown, 3)
            .expect("teardown authority B");
        assert!(
            authority_b
                .observe_removed(&teardown, 3)
                .expect("observe teardown")
        );
        assert!(
            authority_a.realms[&original.realm_id]
                .service
                .configuration()
                .is_none()
        );
        assert!(
            authority_b.realms[&original.realm_id]
                .service
                .configuration()
                .is_none()
        );
        assert!(
            foreign_process
                .try_wait()
                .expect("check foreign process")
                .is_none()
        );
        assert_eq!(
            fs::read_to_string(&foreign_marker).expect("read foreign state"),
            "foreign state"
        );
        foreign_process.kill().expect("stop test foreign process");
        foreign_process.wait().expect("reap test foreign process");
        let _ = fs::remove_dir_all(root);
    }

    #[test]
    fn disabled_dhcp_does_not_start_or_preserve_owned_process() {
        let root = std::env::temp_dir().join(format!("o3k-fabric-dhcp-off-{}", Uuid::now_v7()));
        fs::create_dir_all(&root).expect("create test root");
        let dnsmasq = dnsmasq_stub(&root);
        let plan = plan(&["host-a"], "host-a", false);
        let mut realizer = open_test_dhcp(root.join("a"), &dnsmasq).expect("open DHCP");
        realizer
            .apply(&plan, 1, "o3k-b-test")
            .expect("apply disabled");
        assert!(realizer.realms[&plan.realm_id].supervisor.is_none());
        assert!(
            realizer
                .observe(&plan, 1, "o3k-b-test")
                .expect("observe disabled")
        );
        let _ = fs::remove_dir_all(root);
    }

    #[test]
    fn stale_generation_cannot_reselect_authority() {
        let root = std::env::temp_dir().join(format!("o3k-fabric-dhcp-fence-{}", Uuid::now_v7()));
        fs::create_dir_all(&root).expect("create test root");
        let dnsmasq = dnsmasq_stub(&root);
        let mut current = plan(&["host-a", "host-b"], "host-a", true);
        current.directory_generation = 2;
        let mut realizer = open_test_dhcp(root.join("a"), &dnsmasq).expect("open DHCP");
        realizer
            .apply(&current, 2, "o3k-b-test")
            .expect("apply current");
        let mut stale = current.clone();
        stale.directory_generation = 1;
        stale.directory.directory_generation = 1;
        assert!(matches!(
            realizer.apply(&stale, 1, "o3k-b-test"),
            Err(FabricDhcpError::StaleGeneration)
        ));
        let _ = fs::remove_dir_all(root);
    }
}
