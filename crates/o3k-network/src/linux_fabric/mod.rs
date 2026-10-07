//! Fail-closed Linux realization for the accepted edge fabric contract.
//!
//! Provider-native objects are bounded by an ownership manifest. WireGuard
//! private-key bytes are generated and retained locally and never occur in
//! plans, protocol messages, observations, or ordinary logs.

use crate::fabric::{FabricBackend, FabricError};
use o3k_domain::{
    FabricPeer, FabricProviderKind, NamespacedRoutedFabricPlan, NetworkProtocol, PolicyAction,
    PolicyDirection, PolicyStatefulMode,
};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use std::os::unix::fs::PermissionsExt;
use std::{
    collections::{BTreeMap, BTreeSet},
    fs::{self, File},
    io::{self, Write},
    net::Ipv4Addr,
    path::{Path, PathBuf},
    process::Command,
    sync::Arc,
};
use thiserror::Error;
use uuid::Uuid;

mod naming;
mod ownership;
mod persistence;

mod anti_spoof;
mod attachment;
mod fabric;
mod policy;
mod public_;
mod realm;
mod shared_provider;
mod tap_observation;
mod vxlan;

pub use attachment::{
    FabricAttachmentError, FabricEndpointAttachmentEvidence, LinuxFabricAttachmentResolver,
};

pub(crate) mod gateway;
pub(crate) mod gateway_execution;
pub(crate) mod network_execution;
pub(crate) mod policy_execution;
pub(crate) mod policy_realization;
pub(crate) mod public_execution;
pub(crate) mod public_realization;
pub(crate) mod routed;
pub(crate) mod routed_execution;

pub(crate) use naming::*;
pub(crate) use ownership::*;
pub(crate) use persistence::*;

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct LinuxFabricConfig {
    pub root: PathBuf,
    pub fabric_namespace: String,
    pub fabric_interface: String,
    pub wireguard_port: u16,
    pub vxlan_port: u16,
    pub public_uplink: Option<String>,
}

impl LinuxFabricConfig {
    #[must_use]
    pub fn for_root(root: impl Into<PathBuf>) -> Self {
        Self {
            root: root.into(),
            fabric_namespace: "o3k-fabric".to_owned(),
            fabric_interface: "o3k-wg".to_owned(),
            wireguard_port: 65_001,
            vxlan_port: 4_789,
            public_uplink: None,
        }
    }

    #[must_use]
    pub fn with_public_uplink(mut self, uplink: impl Into<String>) -> Self {
        self.public_uplink = Some(uplink.into());
        self
    }

    #[must_use]
    pub fn with_wireguard_port(mut self, port: u16) -> Self {
        self.wireguard_port = port;
        self
    }

    #[must_use]
    pub fn with_vxlan_port(mut self, port: u16) -> Self {
        self.vxlan_port = port;
        self
    }

    fn validate(&self) -> Result<(), LinuxFabricError> {
        if !self.root.is_absolute()
            || self.root == Path::new("/")
            || self.root.as_os_str().is_empty()
            || !valid_name(&self.fabric_namespace)
            || !valid_name(&self.fabric_interface)
            || self.wireguard_port == 0
            || self.vxlan_port != 4_789
            || self
                .public_uplink
                .as_deref()
                .is_some_and(|uplink| !valid_name(uplink))
        {
            return Err(LinuxFabricError::InvalidConfiguration);
        }
        Ok(())
    }

    /// Validate port ranges (1..=65535) and emit a warning if the selected
    /// WireGuard port falls inside the host's ephemeral range, without
    /// mutating the OS range. Returns an error if the port is already bound.
    pub fn validate_ports(&self) -> Result<(), LinuxFabricError> {
        if self.wireguard_port < 1 || self.vxlan_port != 4_789 {
            return Err(LinuxFabricError::InvalidConfiguration);
        }
        if is_port_bound(self.wireguard_port) {
            return Err(LinuxFabricError::InvalidConfiguration);
        }
        if let Some(low) = ephemeral_port_low()
            && self.wireguard_port >= low
        {
            eprintln!(
                "WARNING: WireGuard port {} lies inside the ephemeral range ({}..=65535)",
                self.wireguard_port, low
            );
        }
        Ok(())
    }
}
#[derive(Debug, Error)]
pub enum LinuxFabricError {
    #[error("Linux fabric configuration is invalid")]
    InvalidConfiguration,
    #[error("Linux fabric provider state is corrupt")]
    CorruptState,
    #[error("Linux fabric provider state is foreign or ambiguous")]
    ForeignState,
    #[error("Linux fabric provider state conflicts with the requested plan")]
    OwnershipConflict,
    #[error("Linux fabric provider command failed")]
    CommandFailed,
    #[error("shared Linux fabric provider rejected the operation: {0}")]
    Provider(String),
    #[error("Linux fabric provider state storage failed: {0}")]
    Storage(#[from] io::Error),
}

impl From<LinuxFabricError> for FabricError {
    fn from(error: LinuxFabricError) -> Self {
        Self::Backend(error.to_string())
    }
}
pub(crate) trait LinuxFabricCommand: Send + Sync {
    fn output(&self, program: &str, args: &[&str]) -> io::Result<(bool, String)>;
    fn run(&self, program: &str, args: &[&str]) -> io::Result<bool>;
    fn run_with_input(&self, program: &str, args: &[&str], input: &[u8]) -> io::Result<bool>;
}

pub(crate) struct SystemLinuxFabricCommand;

impl LinuxFabricCommand for SystemLinuxFabricCommand {
    fn output(&self, program: &str, args: &[&str]) -> io::Result<(bool, String)> {
        let output = Command::new(program).args(args).output()?;
        Ok((
            output.status.success(),
            String::from_utf8_lossy(&output.stdout).into_owned(),
        ))
    }

    fn run(&self, program: &str, args: &[&str]) -> io::Result<bool> {
        Ok(Command::new(program).args(args).status()?.success())
    }

    fn run_with_input(&self, program: &str, args: &[&str], input: &[u8]) -> io::Result<bool> {
        let mut child = Command::new(program)
            .args(args)
            .stdin(std::process::Stdio::piped())
            .stdout(std::process::Stdio::null())
            .stderr(std::process::Stdio::null())
            .spawn()?;
        if let Some(mut stdin) = child.stdin.take() {
            stdin.write_all(input)?;
        }
        Ok(child.wait()?.success())
    }
}
pub struct LinuxFabricBackend {
    pub(crate) config: LinuxFabricConfig,
    pub(crate) state_path: PathBuf,
    pub(crate) plans_path: PathBuf,
    pub(crate) command: Arc<dyn LinuxFabricCommand>,
    pub(crate) state: ProviderState,
    pub(crate) plans: BTreeMap<Uuid, NamespacedRoutedFabricPlan>,
    pub(crate) shared: Option<shared_provider::SharedFabricAdapter>,
}
impl LinuxFabricBackend {
    pub fn open(config: LinuxFabricConfig) -> Result<Self, LinuxFabricError> {
        config.validate()?;
        let state_path = config.root.join("ownership.json");
        let plans_path = config.root.join("plans");
        fs::create_dir_all(&plans_path)?;
        let shared = shared_provider::SharedFabricAdapter::open(&config)?;
        let backend = Self {
            config,
            state_path: state_path.clone(),
            plans_path: plans_path.clone(),
            command: Arc::new(SystemLinuxFabricCommand),
            state: load_state(&state_path)?,
            plans: load_plans(&plans_path)?,
            shared: Some(shared),
        };
        backend.validate_loaded_state()?;
        Ok(backend)
    }

    /// Exposes only the derived Realm attachment directory needed by the
    /// separate L3 gateway provider. Canonical Realm desired state remains in
    /// the control-plane store; namespace and link names stay provider-local.
    pub fn realm_execution_contexts(
        &self,
    ) -> BTreeMap<Uuid, crate::gateway::RealmExecutionContext> {
        self.state
            .realms
            .values()
            .map(|realm| {
                (
                    realm.realm_id,
                    crate::gateway::RealmExecutionContext {
                        realm_id: realm.realm_id,
                        realm_generation: realm.directory_generation,
                        namespace: realm.namespace.clone(),
                        bridge: realm.bridge.clone(),
                        realm_interface: realm.realm_veth.clone(),
                    },
                )
            })
            .collect()
    }

    /// Returns the bridge name recorded by the current Fabric ownership state
    /// for one Realm. DHCP may bind to this interface, but never creates or
    /// mutates it.
    pub fn realm_bridge_name(&self, realm_id: Uuid) -> Option<&str> {
        self.state
            .realms
            .get(&realm_id)
            .map(|realm| realm.bridge.as_str())
    }

    #[cfg(test)]
    fn with_command(
        config: LinuxFabricConfig,
        command: Arc<dyn LinuxFabricCommand>,
    ) -> Result<Self, LinuxFabricError> {
        config.validate()?;
        let state_path = config.root.join("ownership.json");
        let plans_path = config.root.join("plans");
        fs::create_dir_all(&plans_path)?;
        let backend = Self {
            config,
            state_path: state_path.clone(),
            plans_path: plans_path.clone(),
            command,
            state: load_state(&state_path)?,
            plans: load_plans(&plans_path)?,
            shared: None,
        };
        backend.validate_loaded_state()?;
        Ok(backend)
    }
}

impl LinuxFabricBackend {
    fn validate_loaded_state(&self) -> Result<(), LinuxFabricError> {
        if self.state.version != STATE_VERSION {
            return Err(LinuxFabricError::CorruptState);
        }
        let expected_key_parent = if self.shared.is_some() {
            self.config.root.join("fabric-provider")
        } else {
            self.config.root.clone()
        };
        if let Some(fabric) = &self.state.fabric
            && (fabric.namespace != self.config.fabric_namespace
                || fabric.interface != self.config.fabric_interface
                || fabric.fabric_transport_ip.is_unspecified()
                || fabric.fabric_transport_ip.is_loopback()
                || fabric.fabric_generation == 0
                || fabric.fabric_mtu == 0
                || self
                    .plans
                    .values()
                    .any(|plan| plan.local_fabric_mtu != fabric.fabric_mtu)
                || Path::new(&fabric.private_key_path).parent()
                    != Some(expected_key_parent.as_path()))
        {
            return Err(LinuxFabricError::CorruptState);
        }
        if let Some(fabric) = &self.state.fabric {
            validate_private_key_file(Path::new(&fabric.private_key_path))?;
        }
        for (realm_id, ownership) in &self.state.realms {
            let Some(plan) = self.plans.get(realm_id) else {
                return Err(LinuxFabricError::CorruptState);
            };
            if realm_id != &ownership.realm_id
                || plan.realm_id != *realm_id
                || plan.directory_generation != ownership.directory_generation
                || plan.local_fabric_generation != ownership.local_fabric_generation
            {
                return Err(LinuxFabricError::CorruptState);
            }
            if matches!(plan.encapsulation.provider_kind, FabricProviderKind::Vxlan)
                && (!ownership.fabric_veth.is_empty() || !ownership.fabric_realm_veth.is_empty())
            {
                return Err(LinuxFabricError::ForeignState);
            }
            for (target_host, geneve) in &ownership.geneve {
                if target_host != &geneve.target_host
                    || !valid_name(&geneve.interface)
                    || geneve.remote_transport_ip.is_unspecified()
                    || geneve.remote_transport_ip.is_loopback()
                    || geneve.vni == 0
                    || geneve.vni > 0x000f_ffff
                    || geneve.binding_generation == 0
                    || geneve.vni != plan.encapsulation.provider_segment_id
                    || geneve.binding_generation != plan.encapsulation.binding_generation
                    || !valid_mac(&geneve.local_tunnel_mac)
                    || !valid_mac(&geneve.remote_tunnel_mac)
                    || !valid_name(&geneve.bridge)
                    || !valid_name(&geneve.realm_veth)
                    || !valid_name(&geneve.fabric_veth)
                    || !plan.peers.iter().any(|peer| {
                        peer.host_id == geneve.target_host
                            && peer.fabric_transport_ip == geneve.remote_transport_ip
                    })
                {
                    return Err(LinuxFabricError::CorruptState);
                }
            }
            for (target_host, attachment) in &ownership.attachments {
                if target_host != &attachment.target_host
                    || !valid_name(&attachment.bridge)
                    || !valid_name(&attachment.realm_veth)
                    || !valid_name(&attachment.fabric_veth)
                    || !valid_mac(&attachment.local_tunnel_mac)
                    || !valid_mac(&attachment.remote_tunnel_mac)
                    || !ownership.geneve.contains_key(target_host)
                {
                    return Err(LinuxFabricError::CorruptState);
                }
            }
            if let Some(vxlan) = &ownership.vxlan
                && (!valid_name(&vxlan.interface)
                    || !valid_name(&vxlan.bridge)
                    || !valid_name(&vxlan.host_veth)
                    || !valid_name(&vxlan.fabric_veth)
                    || vxlan.vni == 0
                    || vxlan.vni > 0x00ff_ffff
                    || vxlan.binding_generation == 0
                    || vxlan.vni != plan.encapsulation.provider_segment_id
                    || vxlan.binding_generation != plan.encapsulation.binding_generation
                    || vxlan.local_transport_ip != plan.local_fabric_transport_ip
                    || vxlan.tenant_mtu != plan.tenant_mtu
                    || vxlan.local_transport_ip.is_unspecified()
                    || vxlan.local_transport_ip.is_loopback()
                    || vxlan.tenant_mtu == 0
                    || vxlan.flood_peers.contains(&vxlan.local_transport_ip)
                    || vxlan
                        .flood_peers
                        .iter()
                        .any(|peer| peer.is_unspecified() || peer.is_loopback())
                    || vxlan.flood_peers
                        != plan
                            .peers
                            .iter()
                            .map(|peer| peer.fabric_transport_ip)
                            .collect::<BTreeSet<_>>())
            {
                return Err(LinuxFabricError::CorruptState);
            }
            if ownership.anti_spoof_generation == 0 && !ownership.anti_spoof_fingerprint.is_empty()
                || ownership.anti_spoof_generation > plan.directory_generation
                || (ownership.anti_spoof_generation > 0
                    && ownership.anti_spoof_fingerprint.is_empty())
            {
                return Err(LinuxFabricError::CorruptState);
            }
            for (endpoint_id, tap) in &ownership.endpoint_taps {
                if endpoint_id != &tap.endpoint_id
                    || !valid_name(&tap.interface)
                    || !valid_mac(&tap.mac)
                    || !tap.interface.starts_with("o3k-t-")
                {
                    return Err(LinuxFabricError::CorruptState);
                }
            }
            for (endpoint_id, tap) in &ownership.pending_endpoint_taps {
                if endpoint_id != &tap.endpoint_id
                    || !valid_name(&tap.interface)
                    || !valid_mac(&tap.mac)
                    || !tap.interface.starts_with("o3k-t-")
                {
                    return Err(LinuxFabricError::CorruptState);
                }
            }
            if ownership.policy_generation == 0 && !ownership.policy_fingerprint.is_empty() {
                return Err(LinuxFabricError::CorruptState);
            }
            if ownership.public_generation == 0 && !ownership.public_fingerprint.is_empty()
                || ownership.public_generation != 0
                    && (ownership.public_mark == 0 || ownership.public_route_table == 0)
            {
                return Err(LinuxFabricError::CorruptState);
            }
        }
        Ok(())
    }
}

impl LinuxFabricBackend {
    /// Observe the exact policy fingerprint advertised by the provider-owned
    /// nftables table. This reads provider state after restart; it does not
    /// consult the control-plane realization record and cannot reconstruct
    /// canonical policy state.
    pub fn observe_policy_fingerprint(
        &self,
        realm_id: Uuid,
    ) -> Result<Option<String>, LinuxFabricError> {
        let Some(ownership) = self.state.realms.get(&realm_id) else {
            return Ok(None);
        };
        let table = policy_table_name(realm_id);
        let (exists, listing) = self
            .command
            .output(
                "ip",
                &[
                    "netns",
                    "exec",
                    ownership.namespace.as_str(),
                    "nft",
                    "list",
                    "table",
                    "ip",
                    table.as_str(),
                ],
            )
            .map_err(LinuxFabricError::Storage)?;
        if !exists {
            return Ok(None);
        }
        Ok(Some(extract_policy_fingerprint(&listing)?))
    }

    fn persist_plan(&mut self, plan: &NamespacedRoutedFabricPlan) -> Result<(), LinuxFabricError> {
        store_plan(
            &self.plans_path.join(format!("{}.json", plan.realm_id)),
            plan,
        )?;
        self.plans.insert(plan.realm_id, plan.clone());
        Ok(())
    }
    fn remove_plan(&mut self, plan: &NamespacedRoutedFabricPlan) -> Result<(), LinuxFabricError> {
        self.plans.remove(&plan.realm_id);
        let _ = fs::remove_file(self.plans_path.join(format!("{}.json", plan.realm_id)));
        if self.state.realms.remove(&plan.realm_id).is_some() {
            store_state(&self.state_path, &self.state)?;
        }
        Ok(())
    }
}

fn extract_policy_fingerprint(listing: &str) -> Result<String, LinuxFabricError> {
    let marker = "o3k-p11-policy:";
    let start = listing.find(marker).ok_or(LinuxFabricError::ForeignState)? + marker.len();
    listing[start..]
        .split(|character: char| character == '"' || character.is_whitespace())
        .next()
        .filter(|value| !value.is_empty())
        .map(str::to_owned)
        .ok_or(LinuxFabricError::CorruptState)
}

impl FabricBackend for LinuxFabricBackend {
    fn apply(&mut self, plan: &NamespacedRoutedFabricPlan) -> Result<(), FabricError> {
        Self::validate_policy_plan(plan)?;
        Self::validate_public_plan(plan)?;
        if self.shared.is_none() {
            self.ensure_fabric(plan)?;
        }
        self.persist_plan(plan)?;
        self.ensure_realm(plan)?;
        if let Some(shared) = self.shared.as_mut() {
            shared.apply(plan)?;
            let owned = shared
                .ownership(plan.realm_id)
                .ok_or(LinuxFabricError::CorruptState)?;
            let bridge = {
                let realm = self
                    .state
                    .realms
                    .get_mut(&plan.realm_id)
                    .ok_or(LinuxFabricError::CorruptState)?;
                realm.vxlan = Some(VxlanOwnership {
                    interface: owned.vxlan_name.clone(),
                    bridge: owned.bridge_name.clone(),
                    host_veth: owned.consumer_port_veth.clone(),
                    fabric_veth: owned.fabric_port_veth.clone(),
                    vni: owned.vni,
                    binding_generation: plan.encapsulation.binding_generation,
                    local_transport_ip: plan.local_fabric_transport_ip,
                    tenant_mtu: plan.tenant_mtu,
                    flood_peers: owned.flood_peers.iter().copied().collect(),
                });
                realm.bridge.clone()
            };
            store_state(&self.state_path, &self.state)?;
            let consumer = self
                .command
                .output(
                    "ip",
                    &[
                        "-d",
                        "link",
                        "show",
                        "dev",
                        owned.consumer_port_veth.as_str(),
                    ],
                )
                .map_err(LinuxFabricError::Storage)?;
            let bridge_observed = self
                .command
                .output("ip", &["-d", "link", "show", "dev", bridge.as_str()])
                .map_err(LinuxFabricError::Storage)?;
            if !consumer.0 || !consumer.1.contains("veth") {
                return Err(LinuxFabricError::ForeignState.into());
            }
            if !bridge_observed.0 || !bridge_observed.1.contains("bridge") {
                return Err(LinuxFabricError::ForeignState.into());
            }
            if !self
                .command
                .run(
                    "ip",
                    &[
                        "link",
                        "set",
                        owned.consumer_port_veth.as_str(),
                        "master",
                        bridge.as_str(),
                    ],
                )
                .map_err(LinuxFabricError::Storage)?
            {
                return Err(LinuxFabricError::CommandFailed.into());
            }
        }
        if self.shared.is_none() {
            self.configure_peers()?;
            self.ensure_vxlan(plan)?;
            self.reconcile_ingress_auth()?;
        } else {
            // Mirror only provider-derived host identity into O3K's execution
            // journal; canonical generations and VNI admission remain O3K-owned.
            let ingress_owner_token = self
                .state
                .fabric
                .as_ref()
                .map(|owned| owned.ingress_owner_token.clone())
                .unwrap_or_default();
            self.state.fabric = Some(FabricOwnership {
                namespace: self.config.fabric_namespace.clone(),
                interface: "o3k-wg".to_owned(),
                private_key_path: self
                    .config
                    .root
                    .join("fabric-provider/wireguard-private.key")
                    .display()
                    .to_string(),
                fabric_transport_ip: plan.local_fabric_transport_ip,
                fabric_generation: plan.local_fabric_generation,
                fabric_mtu: plan.local_fabric_mtu,
                ingress_owner_token,
                ingress_auth_fingerprint: String::new(),
                ingress_vni_fingerprint: String::new(),
                managed_peers: self
                    .plans
                    .values()
                    .filter(|p| self.state.realms.contains_key(&p.realm_id))
                    .flat_map(|p| p.peers.iter().map(|peer| peer.public_key.clone()))
                    .collect(),
            });
            store_state(&self.state_path, &self.state)?;
            // The shared provider authenticates the host transport; O3K still
            // owns the realm/VNI/source-host admission decision.
            self.reconcile_ingress_auth()?;
        }
        self.ensure_endpoint_taps(plan)?;
        self.attest_committed_endpoint_taps(plan.realm_id)?;
        self.ensure_anti_spoof(plan)?;
        self.attest_committed_endpoint_taps(plan.realm_id)?;
        self.ensure_policy(plan)?;
        self.attest_committed_endpoint_taps(plan.realm_id)?;
        self.ensure_public(plan)?;
        self.attest_committed_endpoint_taps(plan.realm_id)?;
        let ownership = self
            .state
            .realms
            .get(&plan.realm_id)
            .cloned()
            .ok_or(LinuxFabricError::CorruptState)?;
        self.realize_routes(plan, &ownership)?;
        self.attest_committed_endpoint_taps(plan.realm_id)?;
        Ok(())
    }

    fn remove(&mut self, plan: &NamespacedRoutedFabricPlan) -> Result<(), FabricError> {
        let Some(ownership) = self.state.realms.get(&plan.realm_id).cloned() else {
            self.remove_fabric_if_unused(plan.local_fabric_generation)?;
            return Ok(());
        };
        if plan.directory_generation < ownership.directory_generation
            || plan.local_fabric_generation < ownership.local_fabric_generation
        {
            return Err(FabricError::StaleGeneration);
        }
        self.remove_public(plan)?;
        self.remove_policy(plan)?;
        self.remove_anti_spoof(plan, &ownership)?;
        for tap in ownership.endpoint_taps.values() {
            self.remove_endpoint_tap(tap, &ownership.bridge)?;
        }
        for tap in ownership.pending_endpoint_taps.values() {
            if !ownership.endpoint_taps.contains_key(&tap.endpoint_id) {
                self.remove_endpoint_tap(tap, &ownership.bridge)?;
            }
        }
        if let Some(shared) = self.shared.as_mut() {
            // The consumer veth is owned by the shared provider but enslaved
            // to the O3K realm bridge. Detach it before provider teardown and
            // refuse a same-name foreign link.
            let Some(vxlan) = ownership.vxlan.as_ref() else {
                return Err(LinuxFabricError::CorruptState.into());
            };
            let consumer = self
                .command
                .output(
                    "ip",
                    &["-d", "link", "show", "dev", vxlan.host_veth.as_str()],
                )
                .map_err(LinuxFabricError::Storage)?;
            if consumer.0 {
                if !consumer.1.contains("veth") {
                    return Err(LinuxFabricError::ForeignState.into());
                }
                if !self
                    .command
                    .run("ip", &["link", "set", vxlan.host_veth.as_str(), "nomaster"])
                    .map_err(LinuxFabricError::Storage)?
                {
                    return Err(LinuxFabricError::CommandFailed.into());
                }
            }
            shared.remove(plan.realm_id)?;
        } else {
            self.remove_vxlan(plan, &ownership)?;
        }
        let commands = [
            vec![
                "netns",
                "exec",
                ownership.namespace.as_str(),
                "ip",
                "route",
                "flush",
                "table",
                "main",
            ],
            vec!["link", "del", ownership.host_veth.as_str()],
            vec!["link", "del", ownership.bridge.as_str()],
            vec!["netns", "del", ownership.namespace.as_str()],
        ];
        for args in commands {
            if !self
                .command
                .run("ip", &args)
                .map_err(LinuxFabricError::Storage)?
            {
                return Err(LinuxFabricError::CommandFailed.into());
            }
        }
        self.remove_plan(plan)?;
        if self.shared.is_none() && !self.state.realms.is_empty() {
            self.configure_peers()?;
            self.reconcile_ingress_auth()?;
        }
        if self.shared.is_some() && !self.state.realms.is_empty() {
            if let Some(fabric) = self.state.fabric.as_mut() {
                fabric.managed_peers = self
                    .plans
                    .values()
                    .filter(|p| self.state.realms.contains_key(&p.realm_id))
                    .flat_map(|p| p.peers.iter().map(|peer| peer.public_key.clone()))
                    .collect();
            }
            store_state(&self.state_path, &self.state)?;
            self.reconcile_ingress_auth()?;
        }
        if let Some(shared) = self.shared.as_mut() {
            shared.remove_fabric_if_unused()?;
            if self.state.realms.is_empty() {
                self.state.fabric = None;
                store_state(&self.state_path, &self.state)?;
            }
        } else {
            self.remove_fabric_if_unused(plan.local_fabric_generation)?;
        }
        Ok(())
    }

    fn observe(&self, plan: &NamespacedRoutedFabricPlan) -> Result<bool, FabricError> {
        let Some(ownership) = self.state.realms.get(&plan.realm_id) else {
            return Ok(false);
        };
        let (success, _) = self
            .command
            .output("ip", &["netns", "exec", &ownership.namespace, "true"])
            .map_err(LinuxFabricError::Storage)?;
        Ok(success && self.plans.get(&plan.realm_id) == Some(plan))
    }

    fn observe_removed(&self, plan: &NamespacedRoutedFabricPlan) -> Result<bool, FabricError> {
        Ok(!self.state.realms.contains_key(&plan.realm_id)
            && !self.plans.contains_key(&plan.realm_id))
    }
}
// ---------------------------------------------------------------------------
// Port validation helpers
// ---------------------------------------------------------------------------

/// Check whether a UDP port is already in use on 0.0.0.0 by attempting to
/// bind a socket. Returns `true` if the port cannot be bound.
pub(crate) fn is_port_bound(port: u16) -> bool {
    use std::net::UdpSocket;
    UdpSocket::bind(std::net::SocketAddrV4::new(
        std::net::Ipv4Addr::UNSPECIFIED,
        port,
    ))
    .is_err()
}

/// Return the lower bound of the ephemeral port range, or `None` if the
/// kernel parameter cannot be read.
pub(crate) fn ephemeral_port_low() -> Option<u16> {
    let path = "/proc/sys/net/ipv4/ip_local_port_range";
    let content = std::fs::read_to_string(path).ok()?;
    let first = content.split_whitespace().next()?;
    first.parse::<u16>().ok()
}

#[cfg(test)]
#[allow(clippy::expect_used, clippy::panic)]
mod tests {
    use super::*;
    use o3k_domain::{
        AddressRealm, EndpointLocation, FabricHostIdentity, FabricProviderKind, Ipv4Prefix,
        NetworkProtocol, PolicyAction, PolicyDirection, PolicyIntent, PortRange,
        PublicAddressBindingIntent, RealmEncapsulationBinding, RealmEndpointDirectory,
    };
    use serde_json::{Value, json};
    use std::{os::unix::fs::PermissionsExt, sync::Mutex};

    struct EndpointTapCommand {
        tap_name: String,
        tap: Mutex<Option<Value>>,
        extra_links: Mutex<Vec<Value>>,
        set_expected_mac: bool,
        run_calls: Mutex<Vec<Vec<String>>>,
    }

    impl EndpointTapCommand {
        fn new(plan: &NamespacedRoutedFabricPlan, initially_present: bool, set_mac: bool) -> Self {
            let entry = &plan.directory.entries[0];
            let interface = endpoint_tap_name(plan.realm_id, entry.endpoint_id);
            let bridge = format!("o3k-b-{}", &plan.realm_id.simple().to_string()[..8]);
            let expected_mac = endpoint_tap_mac(plan.realm_id, entry.endpoint_id);
            let tap = initially_present.then(|| {
                json!({
                    "ifname": interface,
                    "ifindex": 41,
                    "address": expected_mac,
                    "master": bridge,
                    "linkinfo": {"info_kind":"tun", "info_data":{"type":"tap"}},
                    "flags": ["BROADCAST", "MULTICAST", "UP"],
                    "operstate": "DOWN"
                })
            });
            Self {
                tap_name: interface,
                tap: Mutex::new(tap),
                extra_links: Mutex::new(Vec::new()),
                set_expected_mac: set_mac,
                run_calls: Mutex::new(Vec::new()),
            }
        }
    }

    impl LinuxFabricCommand for EndpointTapCommand {
        fn output(&self, program: &str, args: &[&str]) -> io::Result<(bool, String)> {
            if program == "wg" {
                return Ok((true, format!("{}\n", "A".repeat(43) + "=")));
            }
            if args.first() != Some(&"-j") {
                return Ok((false, String::new()));
            }
            let name = args.last().copied().unwrap_or_default();
            if name.starts_with("o3k-b-") {
                return Ok((
                    true,
                    json!([{
                        "ifname": name,
                        "ifindex": 55,
                        "linkinfo": {"info_kind":"bridge", "info_data":{}}
                    }])
                    .to_string(),
                ));
            }
            if name != self.tap_name {
                return Ok((false, String::new()));
            }
            let Some(tap) = self.tap.lock().expect("tap").clone() else {
                return Ok((false, String::new()));
            };
            let mut links = vec![tap];
            links.extend(self.extra_links.lock().expect("extra links").clone());
            Ok((true, Value::Array(links).to_string()))
        }

        fn run(&self, _program: &str, args: &[&str]) -> io::Result<bool> {
            self.run_calls
                .lock()
                .expect("run calls")
                .push(args.iter().map(|value| (*value).to_owned()).collect());
            let mut tap = self.tap.lock().expect("tap");
            match args {
                ["tuntap", "add", "dev", name, "mode", "tap"] if *name == self.tap_name => {
                    *tap = Some(json!({
                        "ifname": name,
                        "ifindex": 41,
                        "address": "ea:7b:0b:df:96:4b",
                        "linkinfo": {"info_kind":"tun", "info_data":{"type":"tap"}},
                        "flags": ["BROADCAST", "MULTICAST"],
                        "operstate": "DOWN"
                    }));
                }
                ["link", "set", "dev", name, "address", mac] if *name == self.tap_name => {
                    if self.set_expected_mac {
                        tap.as_mut().expect("created TAP")["address"] = json!(mac);
                    }
                }
                ["link", "set", "dev", name, "master", bridge] if *name == self.tap_name => {
                    tap.as_mut().expect("created TAP")["master"] = json!(bridge);
                }
                ["link", "set", "dev", name, "up"] if *name == self.tap_name => {
                    tap.as_mut().expect("created TAP")["flags"] =
                        json!(["BROADCAST", "MULTICAST", "UP"]);
                }
                ["link", "del", "dev", name] if *name == self.tap_name => *tap = None,
                _ => {}
            }
            Ok(true)
        }

        fn run_with_input(
            &self,
            _program: &str,
            _args: &[&str],
            _input: &[u8],
        ) -> io::Result<bool> {
            Ok(true)
        }
    }

    fn local_endpoint_plan() -> NamespacedRoutedFabricPlan {
        let mut plan = plan();
        plan.directory.entries[0].selected_host = plan.local_host.clone();
        plan
    }

    fn endpoint_tap_backend(
        root: &Path,
        plan: &NamespacedRoutedFabricPlan,
        command: Arc<dyn LinuxFabricCommand>,
    ) -> LinuxFabricBackend {
        let mut backend =
            LinuxFabricBackend::with_command(LinuxFabricConfig::for_root(root), command)
                .expect("backend");
        let realm = backend.realm_ownership(plan);
        backend.state.realms.insert(plan.realm_id, realm);
        store_state(&backend.state_path, &backend.state).expect("initial ownership");
        backend
    }

    struct FakeCommand {
        calls: Mutex<Vec<(String, Vec<String>)>>,
        namespace_exists: bool,
    }

    impl LinuxFabricCommand for FakeCommand {
        fn output(&self, program: &str, args: &[&str]) -> io::Result<(bool, String)> {
            self.calls.lock().expect("calls").push((
                program.to_owned(),
                args.iter().map(|arg| (*arg).to_owned()).collect(),
            ));
            if program == "ip"
                && args
                    .windows(4)
                    .any(|window| window == ["bridge", "fdb", "show", "dev"])
            {
                let reconciled = self
                    .calls
                    .lock()
                    .expect("calls")
                    .iter()
                    .any(|(_, call)| call.windows(2).any(|window| window == ["fdb", "append"]));
                return Ok((
                    true,
                    if reconciled {
                        "00:00:00:00:00:00 dst 198.18.0.2\n".to_owned()
                    } else {
                        String::new()
                    },
                ));
            }
            if args
                .windows(3)
                .any(|window| window == ["nft", "list", "table"])
            {
                return Ok((false, String::new()));
            }
            if args.starts_with(&["netns", "exec"]) && self.namespace_exists {
                return Ok((true, String::new()));
            }
            if program == "wg" {
                return Ok((true, format!("{}\n", "A".repeat(43) + "=")));
            }
            Ok((false, String::new()))
        }

        fn run(&self, program: &str, args: &[&str]) -> io::Result<bool> {
            self.calls.lock().expect("calls").push((
                program.to_owned(),
                args.iter().map(|arg| (*arg).to_owned()).collect(),
            ));
            Ok(true)
        }

        fn run_with_input(&self, program: &str, args: &[&str], input: &[u8]) -> io::Result<bool> {
            let mut recorded: Vec<String> = args.iter().map(|arg| (*arg).to_owned()).collect();
            recorded.push(String::from_utf8_lossy(input).into_owned());
            self.calls
                .lock()
                .expect("calls")
                .push((program.to_owned(), recorded));
            Ok(true)
        }
    }

    fn plan() -> NamespacedRoutedFabricPlan {
        plan_with_realm(Uuid::from_u128(11))
    }

    fn plan_with_realm(realm_id: Uuid) -> NamespacedRoutedFabricPlan {
        let realm = AddressRealm {
            id: realm_id,
            network_id: Uuid::from_u128(12),
            project_id: "project-a".to_owned(),
            prefix: Ipv4Prefix::new("10.40.1.0".parse().expect("ip"), 24).expect("prefix"),
            overlapping_prefixes: false,
        };
        let directory = RealmEndpointDirectory::build(
            &realm,
            vec![EndpointLocation {
                endpoint_id: Uuid::from_u128(12),
                project_id: realm.project_id.clone(),
                realm_id: realm.id,
                fixed_ip: "10.40.1.12".parse().expect("ip"),
                mac: "02:00:00:00:00:12".to_owned(),
                selected_host: "host-b".to_owned(),
                endpoint_generation: 1,
                placement_generation: 1,
            }],
            &[],
            2,
        )
        .expect("directory");
        let local = FabricHostIdentity {
            host_id: "host-a".to_owned(),
            public_key: "public-a".to_owned(),
            underlay_endpoint: "192.0.2.1:65001".to_owned(),
            fabric_transport_ip: "198.18.0.1".parse().expect("transport ip"),
            provider_version: "wireguard-v1".to_owned(),
            fabric_generation: 3,
            underlay_mtu: 1500,
            fabric_mtu: 1440,
        };
        let remote = FabricHostIdentity {
            host_id: "host-b".to_owned(),
            public_key: "B".repeat(43) + "=",
            underlay_endpoint: "192.0.2.2:65001".to_owned(),
            fabric_transport_ip: "198.18.0.2".parse().expect("transport ip"),
            provider_version: "wireguard-v1".to_owned(),
            fabric_generation: 3,
            underlay_mtu: 1500,
            fabric_mtu: 1440,
        };
        let binding = RealmEncapsulationBinding {
            fabric_domain_id: Uuid::from_u128(100),
            realm_id: realm.id,
            provider_kind: FabricProviderKind::Vxlan,
            provider_segment_id: 101,
            binding_generation: 3,
        };
        directory
            .compile_fabric_plan(&local, &[local.clone(), remote], 1390, &binding)
            .expect("plan")
    }

    #[test]
    fn provider_refuses_foreign_fabric_namespace() {
        let root = std::env::temp_dir().join(format!("o3k-p11-linux-{}", Uuid::now_v7()));
        let command = Arc::new(FakeCommand {
            calls: Mutex::new(Vec::new()),
            namespace_exists: true,
        });
        let mut provider =
            LinuxFabricBackend::with_command(LinuxFabricConfig::for_root(&root), command)
                .expect("provider");
        assert!(matches!(
            provider.apply(&plan()),
            Err(FabricError::Backend(message)) if message.contains("foreign")
        ));
        let _ = fs::remove_dir_all(root);
    }

    #[test]
    fn endpoint_tap_wrong_live_mac_never_commits_even_when_mutations_succeed() {
        let root = std::env::temp_dir().join(format!("o3k-tap-wrong-mac-{}", Uuid::now_v7()));
        let plan = local_endpoint_plan();
        let command = Arc::new(EndpointTapCommand::new(&plan, false, false));
        let mut backend = endpoint_tap_backend(&root, &plan, command.clone());

        assert!(matches!(
            backend.ensure_endpoint_taps(&plan),
            Err(LinuxFabricError::ForeignState)
        ));
        let realm = backend.state.realms.get(&plan.realm_id).expect("realm");
        assert!(realm.endpoint_taps.is_empty());
        assert_eq!(realm.pending_endpoint_taps.len(), 1);
        assert!(
            fs::read_to_string(&backend.state_path)
                .expect("durable state")
                .contains("pending_endpoint_taps")
        );
        let calls = command.run_calls.lock().expect("mutation calls");
        assert!(
            calls
                .iter()
                .any(|call| call.first().is_some_and(|word| word == "tuntap"))
        );
        assert!(
            calls
                .iter()
                .any(|call| call.iter().any(|word| word == "address"))
        );
        assert!(
            calls
                .iter()
                .any(|call| call.iter().any(|word| word == "master"))
        );
        assert!(
            calls
                .iter()
                .any(|call| call.last().is_some_and(|word| word == "up"))
        );
        assert!(calls.iter().any(|call| call
            == &[
                "link",
                "del",
                "dev",
                endpoint_tap_name(plan.realm_id, plan.directory.entries[0].endpoint_id).as_str()
            ]));
        drop(calls);
        fs::remove_dir_all(root).expect("remove fixture");
    }

    #[test]
    fn valid_endpoint_tap_creation_commits_only_after_live_attestation() {
        let root = std::env::temp_dir().join(format!("o3k-tap-valid-{}", Uuid::now_v7()));
        let plan = local_endpoint_plan();
        let command = Arc::new(EndpointTapCommand::new(&plan, false, true));
        let mut backend = endpoint_tap_backend(&root, &plan, command);

        backend
            .ensure_endpoint_taps(&plan)
            .expect("attested endpoint TAP creation");
        let realm = backend.state.realms.get(&plan.realm_id).expect("realm");
        assert_eq!(realm.endpoint_taps.len(), 1);
        assert!(realm.pending_endpoint_taps.is_empty());
        fs::remove_dir_all(root).expect("remove fixture");
    }

    #[test]
    fn existing_valid_endpoint_tap_is_reused_without_kernel_mutation() {
        let root = std::env::temp_dir().join(format!("o3k-tap-reuse-{}", Uuid::now_v7()));
        let plan = local_endpoint_plan();
        let command = Arc::new(EndpointTapCommand::new(&plan, true, true));
        let mut backend = endpoint_tap_backend(&root, &plan, command.clone());
        let entry = &plan.directory.entries[0];
        let tap = EndpointTapOwnership {
            endpoint_id: entry.endpoint_id,
            interface: endpoint_tap_name(plan.realm_id, entry.endpoint_id),
            mac: endpoint_tap_mac(plan.realm_id, entry.endpoint_id),
        };
        backend
            .state
            .realms
            .get_mut(&plan.realm_id)
            .expect("realm")
            .endpoint_taps
            .insert(entry.endpoint_id, tap);
        store_state(&backend.state_path, &backend.state).expect("committed TAP state");

        backend
            .ensure_endpoint_taps(&plan)
            .expect("reuse exact existing TAP");
        assert!(command.run_calls.lock().expect("mutation calls").is_empty());
        fs::remove_dir_all(root).expect("remove fixture");
    }

    #[test]
    fn pending_endpoint_tap_recovery_attests_reuses_or_safely_recreates() {
        let plan = local_endpoint_plan();
        let entry = &plan.directory.entries[0];
        let tap = EndpointTapOwnership {
            endpoint_id: entry.endpoint_id,
            interface: endpoint_tap_name(plan.realm_id, entry.endpoint_id),
            mac: endpoint_tap_mac(plan.realm_id, entry.endpoint_id),
        };

        let root = std::env::temp_dir().join(format!("o3k-tap-pending-live-{}", Uuid::now_v7()));
        let command = Arc::new(EndpointTapCommand::new(&plan, true, true));
        let mut backend = endpoint_tap_backend(&root, &plan, command.clone());
        backend
            .state
            .realms
            .get_mut(&plan.realm_id)
            .expect("realm")
            .pending_endpoint_taps
            .insert(entry.endpoint_id, tap.clone());
        store_state(&backend.state_path, &backend.state).expect("pending state");
        backend
            .ensure_endpoint_taps(&plan)
            .expect("recover valid pending TAP");
        let realm = backend.state.realms.get(&plan.realm_id).expect("realm");
        assert!(realm.pending_endpoint_taps.is_empty());
        assert_eq!(realm.endpoint_taps.get(&entry.endpoint_id), Some(&tap));
        assert!(command.run_calls.lock().expect("mutation calls").is_empty());
        fs::remove_dir_all(root).expect("remove fixture");

        let root = std::env::temp_dir().join(format!("o3k-tap-pending-absent-{}", Uuid::now_v7()));
        let command = Arc::new(EndpointTapCommand::new(&plan, false, true));
        let mut backend = endpoint_tap_backend(&root, &plan, command);
        backend
            .state
            .realms
            .get_mut(&plan.realm_id)
            .expect("realm")
            .pending_endpoint_taps
            .insert(entry.endpoint_id, tap);
        store_state(&backend.state_path, &backend.state).expect("pending state");
        backend
            .ensure_endpoint_taps(&plan)
            .expect("recreate absent pending TAP");
        let realm = backend.state.realms.get(&plan.realm_id).expect("realm");
        assert!(realm.pending_endpoint_taps.is_empty());
        assert!(realm.endpoint_taps.contains_key(&entry.endpoint_id));
        fs::remove_dir_all(root).expect("remove fixture");
    }

    #[test]
    fn absent_committed_tap_is_demoted_before_recreation() {
        let root =
            std::env::temp_dir().join(format!("o3k-tap-absent-committed-{}", Uuid::now_v7()));
        let plan = local_endpoint_plan();
        let entry = &plan.directory.entries[0];
        let command = Arc::new(EndpointTapCommand::new(&plan, false, false));
        let mut backend = endpoint_tap_backend(&root, &plan, command);
        let tap = EndpointTapOwnership {
            endpoint_id: entry.endpoint_id,
            interface: endpoint_tap_name(plan.realm_id, entry.endpoint_id),
            mac: endpoint_tap_mac(plan.realm_id, entry.endpoint_id),
        };
        backend
            .state
            .realms
            .get_mut(&plan.realm_id)
            .expect("realm")
            .endpoint_taps
            .insert(entry.endpoint_id, tap);
        store_state(&backend.state_path, &backend.state).expect("committed state");

        assert!(matches!(
            backend.ensure_endpoint_taps(&plan),
            Err(LinuxFabricError::ForeignState)
        ));
        let realm = backend.state.realms.get(&plan.realm_id).expect("realm");
        assert!(!realm.endpoint_taps.contains_key(&entry.endpoint_id));
        assert!(realm.pending_endpoint_taps.contains_key(&entry.endpoint_id));
        assert!(
            fs::read_to_string(&backend.state_path)
                .expect("durable state")
                .contains("pending_endpoint_taps")
        );
        fs::remove_dir_all(root).expect("remove fixture");
    }

    #[test]
    fn existing_mismatched_endpoint_taps_fail_closed_without_kernel_mutation() {
        let plan = local_endpoint_plan();
        let entry = &plan.directory.entries[0];
        for variant in [
            "wrong-mac",
            "wrong-bridge",
            "tun",
            "veth",
            "missing-subtype",
            "multiple",
        ] {
            let root = std::env::temp_dir().join(format!("o3k-tap-foreign-{}", Uuid::now_v7()));
            let command = Arc::new(EndpointTapCommand::new(&plan, true, true));
            let mut backend = endpoint_tap_backend(&root, &plan, command.clone());
            let tap = EndpointTapOwnership {
                endpoint_id: entry.endpoint_id,
                interface: endpoint_tap_name(plan.realm_id, entry.endpoint_id),
                mac: endpoint_tap_mac(plan.realm_id, entry.endpoint_id),
            };
            backend
                .state
                .realms
                .get_mut(&plan.realm_id)
                .expect("realm")
                .endpoint_taps
                .insert(entry.endpoint_id, tap);
            store_state(&backend.state_path, &backend.state).expect("committed TAP state");

            if variant == "multiple" {
                command
                    .extra_links
                    .lock()
                    .expect("extra links")
                    .push(json!({
                        "ifname": "unexpected", "ifindex": 42,
                        "address": "02:00:00:00:00:01",
                        "linkinfo": {"info_kind":"tun", "info_data":{"type":"tap"}}
                    }));
            } else {
                let mut live = command.tap.lock().expect("tap");
                let tap = live.as_mut().expect("initial TAP");
                match variant {
                    "wrong-mac" => tap["address"] = json!("02:aa:bb:cc:dd:ee"),
                    "wrong-bridge" => tap["master"] = json!("o3k-b-ffffffff"),
                    "tun" => tap["linkinfo"]["info_data"]["type"] = json!("tun"),
                    "veth" => tap["linkinfo"]["info_kind"] = json!("veth"),
                    "missing-subtype" => tap["linkinfo"]["info_data"] = json!({}),
                    _ => unreachable!(),
                }
            }

            assert!(
                matches!(
                    backend.ensure_endpoint_taps(&plan),
                    Err(LinuxFabricError::ForeignState)
                ),
                "{variant}"
            );
            assert!(
                command.run_calls.lock().expect("mutation calls").is_empty(),
                "{variant}"
            );
            let realm = backend.state.realms.get(&plan.realm_id).expect("realm");
            assert!(
                !realm.endpoint_taps.contains_key(&entry.endpoint_id),
                "{variant}"
            );
            assert!(
                realm.pending_endpoint_taps.contains_key(&entry.endpoint_id),
                "{variant}"
            );
            fs::remove_dir_all(root).expect("remove fixture");
        }
    }

    #[test]
    fn provider_committed_tap_is_accepted_by_the_compute_attachment_resolver() {
        let root = std::env::temp_dir().join(format!("o3k-tap-cross-boundary-{}", Uuid::now_v7()));
        let plan = local_endpoint_plan();
        let entry = &plan.directory.entries[0];
        let command = Arc::new(EndpointTapCommand::new(&plan, false, true));
        let mut backend = endpoint_tap_backend(&root, &plan, command.clone());
        backend.ensure_endpoint_taps(&plan).expect("provider TAP");

        backend.state.fabric = Some(FabricOwnership {
            namespace: "o3k-fabric".to_owned(),
            interface: "o3k-wg".to_owned(),
            private_key_path: root.join("wireguard-private.key").display().to_string(),
            fabric_transport_ip: plan.local_fabric_transport_ip,
            fabric_generation: plan.local_fabric_generation,
            fabric_mtu: plan.local_fabric_mtu,
            ingress_owner_token: "owned".to_owned(),
            ingress_auth_fingerprint: String::new(),
            ingress_vni_fingerprint: String::new(),
            managed_peers: Default::default(),
        });
        let realm = backend.state.realms.get_mut(&plan.realm_id).expect("realm");
        realm.vxlan = Some(VxlanOwnership {
            interface: "o3k-x-test".to_owned(),
            bridge: "o3k-c-test".to_owned(),
            host_veth: "o3k-v-test".to_owned(),
            fabric_veth: "o3k-i-test".to_owned(),
            vni: plan.encapsulation.provider_segment_id,
            binding_generation: plan.encapsulation.binding_generation,
            local_transport_ip: plan.local_fabric_transport_ip,
            tenant_mtu: plan.tenant_mtu,
            flood_peers: Default::default(),
        });
        store_state(&backend.state_path, &backend.state).expect("provider state");
        store_plan(
            &root.join("plans").join(format!("{}.json", plan.realm_id)),
            &plan,
        )
        .expect("current plan");

        let resolver = LinuxFabricAttachmentResolver::with_command(
            root.clone(),
            plan.local_host.clone(),
            command,
        )
        .expect("resolver");
        let evidence = resolver
            .resolve(entry.endpoint_id, &entry.mac, &plan.local_host)
            .expect("same provider TAP attests across boundary");
        assert_eq!(
            evidence.tap_mac,
            endpoint_tap_mac(plan.realm_id, entry.endpoint_id)
        );
        assert_eq!(evidence.guest_mac, entry.mac);
        assert_ne!(evidence.tap_mac, evidence.guest_mac);
        fs::remove_dir_all(root).expect("remove fixture");
    }

    #[test]
    #[ignore = "requires CAP_NET_ADMIN; creates one uniquely named disposable bridge and TAP"]
    fn real_host_provider_tap_microgate() {
        let root = std::env::temp_dir().join(format!("o3k-tap-microgate-{}", Uuid::now_v7()));
        let mut plan = plan_with_realm(Uuid::now_v7());
        plan.directory.entries[0].selected_host = plan.local_host.clone();
        let command: Arc<dyn LinuxFabricCommand> = Arc::new(SystemLinuxFabricCommand);
        let mut backend =
            LinuxFabricBackend::with_command(LinuxFabricConfig::for_root(&root), command.clone())
                .expect("provider backend");
        let mut realm = backend.realm_ownership(&plan);
        let bridge = realm.bridge.clone();
        let endpoint = &plan.directory.entries[0];
        let tap = EndpointTapOwnership {
            endpoint_id: endpoint.endpoint_id,
            interface: endpoint_tap_name(plan.realm_id, endpoint.endpoint_id),
            mac: endpoint_tap_mac(plan.realm_id, endpoint.endpoint_id),
        };
        let (exists, _) = command
            .output("ip", &["-j", "-d", "link", "show", "dev", &bridge])
            .expect("observe candidate bridge name");
        assert!(!exists, "refusing to adopt pre-existing bridge {bridge}");
        assert!(
            command
                .run("ip", &["link", "add", &bridge, "type", "bridge"])
                .expect("create disposable bridge")
        );
        assert!(
            command
                .run("ip", &["link", "set", "dev", &bridge, "up"])
                .expect("bring disposable bridge up")
        );

        realm
            .pending_endpoint_taps
            .insert(endpoint.endpoint_id, tap.clone());
        backend.state.realms.insert(plan.realm_id, realm);
        store_state(&backend.state_path, &backend.state).expect("persist provider fixture");
        store_plan(
            &root.join("plans").join(format!("{}.json", plan.realm_id)),
            &plan,
        )
        .expect("persist current plan");

        let provider_result = backend.ensure_endpoint_taps(&plan);
        assert!(
            provider_result.is_ok(),
            "provider TAP realization: {provider_result:?}"
        );
        let committed = backend
            .state
            .realms
            .get(&plan.realm_id)
            .expect("realm ownership")
            .endpoint_taps
            .get(&endpoint.endpoint_id)
            .expect("committed provider TAP");
        assert_eq!(committed, &tap);

        let (exists, observed_json) = command
            .output("ip", &["-j", "-d", "link", "show", "dev", &tap.interface])
            .expect("independent TAP observation");
        assert!(exists, "provider TAP missing from kernel");
        eprintln!("real host TAP observation: {observed_json}");
        let observed: Value = serde_json::from_str(&observed_json).expect("iproute2 JSON");
        let link = observed
            .as_array()
            .and_then(|links| (links.len() == 1).then(|| &links[0]))
            .expect("exactly one TAP link");
        assert_eq!(link["ifname"].as_str(), Some(tap.interface.as_str()));
        assert_eq!(link["linkinfo"]["info_kind"].as_str(), Some("tun"));
        assert_eq!(link["linkinfo"]["info_data"]["type"].as_str(), Some("tap"));
        assert_eq!(
            link["address"].as_str().map(str::to_ascii_lowercase),
            Some(tap.mac.clone())
        );
        assert_eq!(link["master"].as_str(), Some(bridge.as_str()));

        backend.state.fabric = Some(FabricOwnership {
            namespace: "o3k-fabric".to_owned(),
            interface: "o3k-wg".to_owned(),
            private_key_path: root
                .join("fabric-provider/wireguard-private.key")
                .display()
                .to_string(),
            fabric_transport_ip: plan.local_fabric_transport_ip,
            fabric_generation: plan.local_fabric_generation,
            fabric_mtu: plan.local_fabric_mtu,
            ingress_owner_token: "microgate-owned".to_owned(),
            ingress_auth_fingerprint: String::new(),
            ingress_vni_fingerprint: String::new(),
            managed_peers: Default::default(),
        });
        backend
            .state
            .realms
            .get_mut(&plan.realm_id)
            .expect("realm ownership")
            .vxlan = Some(VxlanOwnership {
            interface: "o3k-x-micro".to_owned(),
            bridge: "o3k-c-micro".to_owned(),
            host_veth: "o3k-v-micro".to_owned(),
            fabric_veth: "o3k-i-micro".to_owned(),
            vni: plan.encapsulation.provider_segment_id,
            binding_generation: plan.encapsulation.binding_generation,
            local_transport_ip: plan.local_fabric_transport_ip,
            tenant_mtu: plan.tenant_mtu,
            flood_peers: Default::default(),
        });
        store_state(&backend.state_path, &backend.state).expect("persist committed state");
        let resolver = LinuxFabricAttachmentResolver::open(&root, plan.local_host.clone())
            .expect("production read-only resolver");
        let evidence = resolver
            .resolve(endpoint.endpoint_id, &endpoint.mac, &plan.local_host)
            .expect("production resolver accepts provider-owned live TAP");
        assert_eq!(evidence.tap_mac, tap.mac);
        assert_eq!(evidence.guest_mac, endpoint.mac);
        assert_ne!(evidence.tap_mac, evidence.guest_mac);

        backend
            .remove_endpoint_tap(&tap, &bridge)
            .expect("ownership-safe test TAP cleanup");
        assert!(
            command
                .run("ip", &["link", "del", "dev", &bridge])
                .expect("remove disposable bridge")
        );
        fs::remove_dir_all(root).expect("remove microgate provider state");
    }

    #[test]
    fn provider_records_key_path_but_never_plan_key_material() {
        let root = std::env::temp_dir().join(format!("o3k-p11-linux-{}", Uuid::now_v7()));
        let command = Arc::new(FakeCommand {
            calls: Mutex::new(Vec::new()),
            namespace_exists: false,
        });
        let command_for_assertion = Arc::clone(&command);
        let mut provider =
            LinuxFabricBackend::with_command(LinuxFabricConfig::for_root(&root), command)
                .expect("provider");
        provider.apply(&plan()).expect("apply");
        let state = fs::read_to_string(root.join("ownership.json")).expect("state");
        let serialized =
            fs::read_to_string(root.join("plans").join(format!("{}.json", plan().realm_id)))
                .expect("plan");
        assert!(!state.contains(&"A".repeat(43)));
        assert!(!serialized.contains(&"A".repeat(43)));
        assert!(state.contains("wireguard-private.key"));
        assert_eq!(
            fs::metadata(root.join("wireguard-private.key"))
                .expect("key")
                .permissions()
                .mode()
                & 0o077,
            0
        );
        let calls = command_for_assertion.calls.lock().expect("calls");
        assert!(
            calls
                .iter()
                .any(|(program, args)| program == "wg" && args == &["genkey"])
        );
        let interface = vxlan_name(plan().realm_id);
        assert!(calls.iter().any(|(program, args)| {
            program == "ip"
                && args
                    .windows(6)
                    .any(|window| window == ["type", "vxlan", "id", "101", "dstport", "4789"])
                && args.iter().any(|arg| arg == &interface)
        }));
        assert!(calls.iter().any(|(program, args)| {
            program == "ip"
                && args
                    .windows(2)
                    .any(|window| window == ["allowed-ips", "198.18.0.2/32"])
        }));
        assert!(!calls.iter().any(|(_, args)| {
            args.windows(2)
                .any(|window| window == ["allowed-ips", "10.40.1.12/32"])
        }));
        let vxlan = provider
            .state
            .realms
            .get(&plan().realm_id)
            .and_then(|realm| realm.vxlan.as_ref())
            .expect("vxlan ownership");
        assert_eq!(vxlan.vni, 101);
        assert_eq!(
            vxlan.flood_peers,
            BTreeSet::from([Ipv4Addr::new(198, 18, 0, 2)])
        );
        assert!(calls.iter().any(|(program, args)| {
            program == "ip"
                && args.contains(&"fdb".to_owned())
                && args.contains(&"append".to_owned())
                && args.contains(&"00:00:00:00:00:00".to_owned())
                && args.contains(&"198.18.0.2".to_owned())
        }));
        let ingress_batch = calls
            .iter()
            .find_map(|(program, args)| {
                (program == "ip" && args.windows(2).any(|window| window == ["nft", "-f"]))
                    .then(|| args.last().expect("nft batch"))
            })
            .expect("atomic nftables reconciliation batch");
        assert!(ingress_batch.contains("add table netdev o3k-fabric-auth"));
        assert!(ingress_batch.contains("policy drop"));
        assert!(ingress_batch.contains("@th,96,24 101 ip saddr 198.18.0.2"));
        assert!(ingress_batch.contains("counter drop comment \"o3k-fabric-auth\""));
        assert!(ingress_batch.contains("add table bridge o3k-fabric-vni-auth"));
        assert!(ingress_batch.contains("counter drop comment \"o3k-fabric-vni-auth\""));
        assert_eq!(
            calls
                .iter()
                .filter(|(program, args)| {
                    program == "ip" && args.windows(2).any(|window| window == ["nft", "-f"])
                })
                .count(),
            1,
            "both admission tables must change in a single kernel transaction"
        );
        assert!(!calls.iter().any(|(program, args)| {
            program == "ip"
                && args
                    .windows(4)
                    .any(|window| window == ["add", "rule", "netdev", "o3k-fabric-auth"])
                && args.contains(&"vxlan".to_owned())
                && args.contains(&"vni".to_owned())
        }));
        assert!(ingress_batch.contains("add table bridge o3k-fabric-vni-auth"));
        assert!(ingress_batch.contains("counter drop comment \"o3k-fabric-vni-auth\""));
        assert!(calls.iter().any(|(program, args)| {
            program == "ip" && args.contains(&vxlan_name(plan().realm_id))
        }));
        assert!(calls.iter().any(|(program, args)| {
            program == "ip" && args.windows(2).any(|window| window == ["mtu", "1390"])
        }));
        let _ = fs::remove_dir_all(root);
    }

    #[test]
    fn provider_reconciles_bounded_her_entries() {
        let root = std::env::temp_dir().join(format!("o3k-p11-linux-{}", Uuid::now_v7()));
        let command = Arc::new(FakeCommand {
            calls: Mutex::new(Vec::new()),
            namespace_exists: false,
        });
        let command_for_assertion = Arc::clone(&command);
        let mut provider =
            LinuxFabricBackend::with_command(LinuxFabricConfig::for_root(&root), command)
                .expect("provider");
        provider.apply(&plan()).expect("apply");
        let calls = command_for_assertion.calls.lock().expect("calls");
        let bridge_calls: Vec<_> = calls
            .iter()
            .filter(|(prog, args)| {
                prog == "ip"
                    && args.contains(&"fdb".to_owned())
                    && args.contains(&"append".to_owned())
                    && args.contains(&"00:00:00:00:00:00".to_owned())
            })
            .collect();
        assert!(!bridge_calls.is_empty(), "no bridge fdb calls found");
        assert!(bridge_calls.iter().all(|(_, args)| {
            !args.contains(&"static".to_owned()) && !args.contains(&"permanent".to_owned())
        }));
        let _ = fs::remove_dir_all(root);
    }

    #[test]
    fn provider_realizes_realm_scoped_policy_with_owned_marker() {
        let root = std::env::temp_dir().join(format!("o3k-p11-linux-{}", Uuid::now_v7()));
        let command = Arc::new(FakeCommand {
            calls: Mutex::new(Vec::new()),
            namespace_exists: false,
        });
        let command_for_assertion = Arc::clone(&command);
        let mut provider =
            LinuxFabricBackend::with_command(LinuxFabricConfig::for_root(&root), command)
                .expect("provider");
        let current = plan()
            .with_policy_snapshot(
                7,
                vec![PolicyIntent {
                    id: Uuid::from_u128(13),
                    endpoint_id: Uuid::from_u128(12),
                    direction: PolicyDirection::Ingress,
                    protocol: NetworkProtocol::Tcp,
                    ports: Some(PortRange {
                        start: 443,
                        end: 443,
                    }),
                    source: Some(
                        Ipv4Prefix::new("192.0.2.0".parse().expect("ip"), 24).expect("prefix"),
                    ),
                    destination: None,
                    action: PolicyAction::Deny,
                }],
            )
            .expect("policy plan");
        provider.apply(&current).expect("apply");
        let table = policy_table_name(current.realm_id);
        let calls = command_for_assertion.calls.lock().expect("calls");
        assert!(calls.iter().any(|(program, args)| {
            program == "ip"
                && args
                    .windows(5)
                    .any(|window| window == ["nft", "add", "table", "ip", table.as_str()])
        }));
        assert!(calls.iter().any(|(program, args)| {
            program == "ip"
                && args.iter().any(|arg| arg == "drop")
                && args.iter().any(|arg| arg == "443-443")
                && args.iter().any(|arg| arg.contains("o3k-p11-policy:0"))
        }));
        let ownership = provider.state.realms.get(&current.realm_id).expect("realm");
        assert_eq!(ownership.policy_generation, 7);
        assert!(!ownership.policy_fingerprint.is_empty());
        drop(calls);
        provider.remove(&current).expect("remove");
        assert!(provider.observe_removed(&current).expect("removed"));
        let _ = fs::remove_dir_all(root);
    }

    #[test]
    fn provider_observation_extracts_exact_owned_fingerprint() {
        assert_eq!(
            extract_policy_fingerprint(
                "table ip o3k-policy { comment \"o3k-p11-policy:sha256:f1\"; }"
            )
            .expect("marker"),
            "sha256:f1"
        );
        assert!(matches!(
            extract_policy_fingerprint("table ip o3k-policy { }"),
            Err(LinuxFabricError::ForeignState)
        ));
    }

    #[test]
    fn provider_rejects_invalid_policy_before_host_mutation() {
        let root = std::env::temp_dir().join(format!("o3k-p11-linux-{}", Uuid::now_v7()));
        let command = Arc::new(FakeCommand {
            calls: Mutex::new(Vec::new()),
            namespace_exists: false,
        });
        let command_for_assertion = Arc::clone(&command);
        let mut provider =
            LinuxFabricBackend::with_command(LinuxFabricConfig::for_root(&root), command)
                .expect("provider");
        let invalid = plan()
            .with_policy_snapshot(
                7,
                vec![PolicyIntent {
                    id: Uuid::from_u128(14),
                    endpoint_id: Uuid::from_u128(12),
                    direction: PolicyDirection::Ingress,
                    protocol: NetworkProtocol::Tcp,
                    ports: Some(PortRange {
                        start: 8443,
                        end: 443,
                    }),
                    source: None,
                    destination: None,
                    action: PolicyAction::Allow,
                }],
            )
            .expect("policy snapshot");
        assert!(matches!(
            provider.apply(&invalid),
            Err(FabricError::Backend(message)) if message.contains("conflicts")
        ));
        assert!(
            command_for_assertion
                .calls
                .lock()
                .expect("calls")
                .is_empty()
        );
        let _ = fs::remove_dir_all(root);
    }

    #[test]
    fn provider_realizes_realm_scoped_public_binding_without_bare_ip_nat() {
        let root = std::env::temp_dir().join(format!("o3k-p11-linux-{}", Uuid::now_v7()));
        let command = Arc::new(FakeCommand {
            calls: Mutex::new(Vec::new()),
            namespace_exists: false,
        });
        let command_for_assertion = Arc::clone(&command);
        let mut provider = LinuxFabricBackend::with_command(
            LinuxFabricConfig::for_root(&root).with_public_uplink("eth-public"),
            command,
        )
        .expect("provider");
        let current = plan()
            .with_public_snapshot(vec![PublicAddressBindingIntent {
                id: Uuid::from_u128(15),
                project_id: "project-a".to_owned(),
                public_address: "203.0.113.10".parse().expect("ip"),
                endpoint_id: Uuid::from_u128(12),
                generation: 4,
            }])
            .expect("public plan");
        provider.apply(&current).expect("apply");
        let calls = command_for_assertion.calls.lock().expect("calls");
        assert!(calls.iter().any(|(program, args)| {
            program == "ip"
                && args.iter().any(|arg| arg == "dnat")
                && args.iter().any(|arg| arg == "10.40.1.12")
        }));
        assert!(calls.iter().any(|(program, args)| {
            program == "ip"
                && args.iter().any(|arg| arg == "snat")
                && args.iter().any(|arg| arg == "203.0.113.10")
        }));
        assert!(calls.iter().any(|(program, args)| {
            program == "nft"
                && args.iter().any(|arg| arg == "meta")
                && args.iter().any(|arg| arg == "mark")
        }));
        let ownership = provider.state.realms.get(&current.realm_id).expect("realm");
        assert_eq!(
            ownership.public_addresses,
            vec!["203.0.113.10".parse::<Ipv4Addr>().expect("ip")]
        );
        drop(calls);
        provider.remove(&current).expect("remove");
        assert!(provider.observe_removed(&current).expect("removed"));
        let _ = fs::remove_dir_all(root);
    }

    #[test]
    fn provider_fences_generation_changes_and_retains_host_key() {
        let root = std::env::temp_dir().join(format!("o3k-p11-linux-{}", Uuid::now_v7()));
        let command = Arc::new(FakeCommand {
            calls: Mutex::new(Vec::new()),
            namespace_exists: false,
        });
        let mut provider =
            LinuxFabricBackend::with_command(LinuxFabricConfig::for_root(&root), command)
                .expect("provider");
        let current = plan();
        provider.apply(&current).expect("apply");
        let mut changed = current.clone();
        changed.local_fabric_generation += 1;
        assert!(matches!(
            provider.apply(&changed),
            Err(FabricError::Backend(message)) if message.contains("conflicts")
        ));
        provider.remove(&current).expect("remove");
        assert!(provider.observe_removed(&current).expect("removed"));
        // The private key is provisioned host identity material and must
        // survive fabric removal.
        assert!(root.join("wireguard-private.key").exists());
        let _ = fs::remove_dir_all(root);
    }

    #[test]
    fn provider_adopts_preprovisioned_host_key() {
        let root = std::env::temp_dir().join(format!("o3k-p11-linux-{}", Uuid::now_v7()));
        fs::create_dir_all(&root).expect("root");
        let key_path = root.join("wireguard-private.key");
        let provisioned = format!("{}\n", "C".repeat(43) + "=");
        fs::write(&key_path, &provisioned).expect("key");
        fs::set_permissions(&key_path, fs::Permissions::from_mode(0o600)).expect("mode");
        let command = Arc::new(FakeCommand {
            calls: Mutex::new(Vec::new()),
            namespace_exists: false,
        });
        let command_for_assertion = Arc::clone(&command);
        let mut provider =
            LinuxFabricBackend::with_command(LinuxFabricConfig::for_root(&root), command)
                .expect("provider");
        provider.apply(&plan()).expect("apply");
        assert_eq!(fs::read_to_string(&key_path).expect("key"), provisioned);
        let calls = command_for_assertion.calls.lock().expect("calls");
        assert!(
            !calls
                .iter()
                .any(|(program, args)| program == "wg" && args == &["genkey"])
        );
        let key_path_argument = key_path.to_str().expect("path").to_owned();
        assert!(calls.iter().any(|(program, args)| {
            program == "ip"
                && args
                    .windows(2)
                    .any(|window| window == ["private-key", key_path_argument.as_str()])
        }));
        let _ = fs::remove_dir_all(root);
    }

    #[test]
    fn provider_rejects_invalid_preprovisioned_host_key() {
        let root = std::env::temp_dir().join(format!("o3k-p11-linux-{}", Uuid::now_v7()));
        fs::create_dir_all(&root).expect("root");
        let key_path = root.join("wireguard-private.key");
        fs::write(&key_path, "not-a-wireguard-key\n").expect("key");
        fs::set_permissions(&key_path, fs::Permissions::from_mode(0o600)).expect("mode");
        let command = Arc::new(FakeCommand {
            calls: Mutex::new(Vec::new()),
            namespace_exists: false,
        });
        let mut provider =
            LinuxFabricBackend::with_command(LinuxFabricConfig::for_root(&root), command)
                .expect("provider");
        assert!(matches!(
            provider.apply(&plan()),
            Err(FabricError::Backend(message)) if message.contains("foreign")
        ));
        // Operator-provisioned material is never overwritten.
        assert_eq!(
            fs::read_to_string(&key_path).expect("key"),
            "not-a-wireguard-key\n"
        );
        let _ = fs::remove_dir_all(root);
    }
}
