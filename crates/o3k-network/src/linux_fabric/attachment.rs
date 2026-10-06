use super::{
    LinuxFabricCommand, ProviderState, STATE_VERSION, SystemLinuxFabricCommand, endpoint_tap_mac,
};
use o3k_domain::NamespacedRoutedFabricPlan;
use serde_json::Value;
use std::{
    collections::BTreeMap,
    fs,
    path::{Path, PathBuf},
    sync::Arc,
};
use thiserror::Error;
use uuid::Uuid;

/// Read-only proof that a canonical endpoint is currently realized as a
/// Fabric-owned host TAP and can be attached to a guest. The host TAP MAC is
/// provider-local; `guest_mac` remains the canonical endpoint identity used
/// in the libvirt interface XML.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct FabricEndpointAttachmentEvidence {
    pub endpoint_id: Uuid,
    pub realm_id: Uuid,
    pub tap_name: String,
    pub tap_mac: String,
    pub realm_bridge: String,
    pub guest_mac: String,
    pub local_host: String,
    pub endpoint_generation: u64,
    pub placement_generation: u64,
    pub directory_generation: u64,
    pub fabric_generation: u64,
    pub binding_generation: u64,
    pub vni: u32,
    pub tenant_mtu: u16,
}

/// Failure to prove a current, local, Fabric-owned endpoint attachment.
#[derive(Debug, Error, Clone, PartialEq, Eq)]
pub enum FabricAttachmentError {
    #[error("Fabric attachment state is unavailable")]
    StateUnavailable,
    #[error("Fabric attachment state is corrupt or ambiguous")]
    CorruptState,
    #[error("endpoint is not present in a current local Fabric plan")]
    EndpointNotFound,
    #[error("endpoint is assigned to another host")]
    WrongHost,
    #[error("endpoint guest MAC does not match the canonical attachment")]
    GuestMacMismatch,
    #[error("endpoint Fabric realization is pending")]
    Pending,
    #[error("Fabric provider ownership does not match the current plan")]
    OwnershipMismatch,
    #[error("live Fabric TAP is absent")]
    LiveTapAbsent,
    #[error("live interface is not the expected TAP device")]
    WrongLinkType,
    #[error("live TAP MAC does not match Fabric ownership")]
    TapMacMismatch,
    #[error("live TAP is not attached to the current Realm bridge")]
    RealmBridgeMismatch,
    #[error("Fabric provider observation failed")]
    ObservationFailed,
}

/// A process-local read-only view over the same durable state root used by
/// `LinuxFabricBackend`. It reloads atomic snapshots on every lookup so a
/// long-running compute agent observes Fabric reconciliation without a
/// restart. It never creates directories or changes provider/kernel state.
pub struct LinuxFabricAttachmentResolver {
    root: PathBuf,
    local_host: String,
    command: Arc<dyn LinuxFabricCommand>,
}

impl std::fmt::Debug for LinuxFabricAttachmentResolver {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter
            .debug_struct("LinuxFabricAttachmentResolver")
            .field("root", &self.root)
            .field("local_host", &self.local_host)
            .finish_non_exhaustive()
    }
}

impl LinuxFabricAttachmentResolver {
    pub fn open(
        root: impl Into<PathBuf>,
        local_host: impl Into<String>,
    ) -> Result<Self, FabricAttachmentError> {
        Self::with_command(
            root.into(),
            local_host.into(),
            Arc::new(SystemLinuxFabricCommand),
        )
    }

    fn with_command(
        root: PathBuf,
        local_host: String,
        command: Arc<dyn LinuxFabricCommand>,
    ) -> Result<Self, FabricAttachmentError> {
        if !root.is_absolute()
            || root == Path::new("/")
            || local_host.trim().is_empty()
            || !local_host
                .bytes()
                .all(|byte| byte.is_ascii_alphanumeric() || b"._:-".contains(&byte))
        {
            return Err(FabricAttachmentError::StateUnavailable);
        }
        let metadata =
            fs::symlink_metadata(&root).map_err(|_| FabricAttachmentError::StateUnavailable)?;
        if metadata.file_type().is_symlink() || !metadata.is_dir() {
            return Err(FabricAttachmentError::StateUnavailable);
        }
        Ok(Self {
            root,
            local_host,
            command,
        })
    }

    /// Proves that `endpoint_id` has one current local plan entry, committed
    /// durable TAP ownership, and a live TAP on the plan's current Realm
    /// bridge. No observed IP/MAC/VNI is used to infer endpoint identity.
    pub fn resolve(
        &self,
        endpoint_id: Uuid,
        expected_guest_mac: &str,
        expected_local_host: &str,
    ) -> Result<FabricEndpointAttachmentEvidence, FabricAttachmentError> {
        if expected_local_host != self.local_host {
            return Err(FabricAttachmentError::WrongHost);
        }
        if !valid_mac(expected_guest_mac) {
            return Err(FabricAttachmentError::GuestMacMismatch);
        }
        let state = read_state(&self.root.join("ownership.json"))?;
        if state.version != STATE_VERSION {
            return Err(FabricAttachmentError::CorruptState);
        }
        let plans = read_plans(&self.root.join("plans"))?;
        let matches = plans
            .values()
            .filter_map(|plan| {
                plan.directory
                    .entries
                    .iter()
                    .find(|entry| entry.endpoint_id == endpoint_id)
                    .map(|entry| (plan, entry))
            })
            .collect::<Vec<_>>();
        if matches.len() != 1 {
            return Err(if matches.is_empty() {
                FabricAttachmentError::EndpointNotFound
            } else {
                FabricAttachmentError::CorruptState
            });
        }
        let (plan, endpoint) = matches[0];
        if plan.local_host != self.local_host || endpoint.selected_host != self.local_host {
            return Err(FabricAttachmentError::WrongHost);
        }
        if plan.realm_id != plan.directory.realm_id
            || endpoint.realm_id != plan.realm_id
            || plan.directory_generation != plan.directory.directory_generation
            || plan.encapsulation.realm_id != plan.realm_id
            || plan.encapsulation.provider_segment_id == 0
            || plan.encapsulation.binding_generation == 0
            || plan.local_fabric_generation == 0
            || endpoint.endpoint_generation == 0
            || endpoint.placement_generation == 0
        {
            return Err(FabricAttachmentError::CorruptState);
        }
        if !endpoint.mac.eq_ignore_ascii_case(expected_guest_mac) {
            return Err(FabricAttachmentError::GuestMacMismatch);
        }
        let realm = state
            .realms
            .get(&plan.realm_id)
            .ok_or(FabricAttachmentError::OwnershipMismatch)?;
        if realm.realm_id != plan.realm_id
            || realm.directory_generation != plan.directory_generation
            || realm.local_fabric_generation != plan.local_fabric_generation
            || realm.bridge != expected_realm_bridge(plan.realm_id)
        {
            return Err(FabricAttachmentError::OwnershipMismatch);
        }
        let vxlan = realm
            .vxlan
            .as_ref()
            .ok_or(FabricAttachmentError::OwnershipMismatch)?;
        if vxlan.vni != plan.encapsulation.provider_segment_id
            || vxlan.binding_generation != plan.encapsulation.binding_generation
            || vxlan.tenant_mtu != plan.tenant_mtu
            || state
                .fabric
                .as_ref()
                .is_none_or(|fabric| fabric.fabric_generation != plan.local_fabric_generation)
        {
            return Err(FabricAttachmentError::OwnershipMismatch);
        }
        let tap = realm.endpoint_taps.get(&endpoint_id).ok_or_else(|| {
            if realm.pending_endpoint_taps.contains_key(&endpoint_id) {
                FabricAttachmentError::Pending
            } else {
                FabricAttachmentError::OwnershipMismatch
            }
        })?;
        if tap.endpoint_id != endpoint_id
            || tap.interface != super::endpoint_tap_name(plan.realm_id, endpoint_id)
            || tap.mac != endpoint_tap_mac(plan.realm_id, endpoint_id)
            || !valid_mac(&tap.mac)
            || tap.mac.eq_ignore_ascii_case(&endpoint.mac)
        {
            return Err(FabricAttachmentError::OwnershipMismatch);
        }
        let expected = LiveTapExpectation {
            name: &tap.interface,
            mac: &tap.mac,
            bridge: &realm.bridge,
        };
        observe_live_tap(self.command.as_ref(), expected)?;
        Ok(FabricEndpointAttachmentEvidence {
            endpoint_id,
            realm_id: plan.realm_id,
            tap_name: tap.interface.clone(),
            tap_mac: tap.mac.clone(),
            realm_bridge: realm.bridge.clone(),
            guest_mac: endpoint.mac.clone(),
            local_host: plan.local_host.clone(),
            endpoint_generation: endpoint.endpoint_generation,
            placement_generation: endpoint.placement_generation,
            directory_generation: plan.directory_generation,
            fabric_generation: plan.local_fabric_generation,
            binding_generation: plan.encapsulation.binding_generation,
            vni: plan.encapsulation.provider_segment_id,
            tenant_mtu: plan.tenant_mtu,
        })
    }
}

struct LiveTapExpectation<'a> {
    name: &'a str,
    mac: &'a str,
    bridge: &'a str,
}

fn observe_live_tap(
    command: &dyn LinuxFabricCommand,
    expected: LiveTapExpectation<'_>,
) -> Result<(), FabricAttachmentError> {
    let (tap_exists, tap_output) = command
        .output("ip", &["-j", "-d", "link", "show", "dev", expected.name])
        .map_err(|_| FabricAttachmentError::ObservationFailed)?;
    if !tap_exists {
        return Err(FabricAttachmentError::LiveTapAbsent);
    }
    let tap: Value =
        serde_json::from_str(&tap_output).map_err(|_| FabricAttachmentError::ObservationFailed)?;
    let Some(tap) = tap
        .as_array()
        .and_then(|links| (links.len() == 1).then(|| &links[0]))
    else {
        return Err(FabricAttachmentError::LiveTapAbsent);
    };
    let tap_info = &tap["linkinfo"];
    let mode = tap_info["info_data"]["mode"].as_str();
    let tap_name = tap["ifname"].as_str();
    let tap_mac = tap["address"].as_str();
    if tap_name != Some(expected.name) || tap_info["info_kind"].as_str() != Some("tun") {
        return Err(FabricAttachmentError::WrongLinkType);
    }
    if tap_mac.is_none_or(|mac| !mac.eq_ignore_ascii_case(expected.mac)) {
        return Err(FabricAttachmentError::TapMacMismatch);
    }
    if !matches!(mode, Some("tap") | Some("2")) {
        return Err(FabricAttachmentError::WrongLinkType);
    }
    let (bridge_exists, bridge_output) = command
        .output("ip", &["-j", "-d", "link", "show", "dev", expected.bridge])
        .map_err(|_| FabricAttachmentError::ObservationFailed)?;
    if !bridge_exists {
        return Err(FabricAttachmentError::RealmBridgeMismatch);
    }
    let bridge: Value = serde_json::from_str(&bridge_output)
        .map_err(|_| FabricAttachmentError::ObservationFailed)?;
    let Some(bridge) = bridge
        .as_array()
        .and_then(|links| (links.len() == 1).then(|| &links[0]))
    else {
        return Err(FabricAttachmentError::RealmBridgeMismatch);
    };
    if bridge["ifname"].as_str() != Some(expected.bridge)
        || bridge["linkinfo"]["info_kind"].as_str() != Some("bridge")
    {
        return Err(FabricAttachmentError::RealmBridgeMismatch);
    }
    let tap_master = tap["master"].as_str().or_else(|| {
        tap["master"].as_u64().and_then(|index| {
            (bridge["ifindex"].as_u64() == Some(index)).then_some(expected.bridge)
        })
    });
    if tap_master != Some(expected.bridge) {
        return Err(FabricAttachmentError::RealmBridgeMismatch);
    }
    Ok(())
}

fn read_state(path: &Path) -> Result<ProviderState, FabricAttachmentError> {
    read_regular_file(path)?
        .map(|bytes| {
            serde_json::from_slice(&bytes).map_err(|_| FabricAttachmentError::CorruptState)
        })
        .transpose()?
        .ok_or(FabricAttachmentError::StateUnavailable)
}

fn read_plans(
    path: &Path,
) -> Result<BTreeMap<Uuid, NamespacedRoutedFabricPlan>, FabricAttachmentError> {
    let metadata =
        fs::symlink_metadata(path).map_err(|_| FabricAttachmentError::StateUnavailable)?;
    if metadata.file_type().is_symlink() || !metadata.is_dir() {
        return Err(FabricAttachmentError::CorruptState);
    }
    let mut plans = BTreeMap::new();
    let entries = fs::read_dir(path).map_err(|_| FabricAttachmentError::StateUnavailable)?;
    for entry in entries {
        let entry = entry.map_err(|_| FabricAttachmentError::StateUnavailable)?;
        let name = entry.file_name().to_string_lossy().into_owned();
        if !name.ends_with(".json") {
            return Err(FabricAttachmentError::CorruptState);
        }
        let bytes = read_regular_file(&entry.path())?.ok_or(FabricAttachmentError::CorruptState)?;
        let plan: NamespacedRoutedFabricPlan =
            serde_json::from_slice(&bytes).map_err(|_| FabricAttachmentError::CorruptState)?;
        if name != format!("{}.json", plan.realm_id)
            || plan.directory.realm_id != plan.realm_id
            || plans.insert(plan.realm_id, plan).is_some()
        {
            return Err(FabricAttachmentError::CorruptState);
        }
    }
    Ok(plans)
}

fn read_regular_file(path: &Path) -> Result<Option<Vec<u8>>, FabricAttachmentError> {
    match fs::symlink_metadata(path) {
        Ok(metadata) if metadata.file_type().is_symlink() || !metadata.is_file() => {
            Err(FabricAttachmentError::CorruptState)
        }
        Ok(_) => fs::read(path)
            .map(Some)
            .map_err(|_| FabricAttachmentError::StateUnavailable),
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => Ok(None),
        Err(_) => Err(FabricAttachmentError::StateUnavailable),
    }
}

fn valid_mac(value: &str) -> bool {
    let parts = value.split(':').collect::<Vec<_>>();
    parts.len() == 6
        && parts
            .iter()
            .all(|part| part.len() == 2 && part.bytes().all(|byte| byte.is_ascii_hexdigit()))
}

fn expected_realm_bridge(realm_id: Uuid) -> String {
    format!("o3k-b-{}", &realm_id.simple().to_string()[..8])
}

#[cfg(test)]
#[allow(clippy::expect_used, clippy::unwrap_used)]
mod tests {
    use super::*;
    use crate::linux_fabric::{
        EndpointTapOwnership, FabricOwnership, RealmOwnership, VxlanOwnership, endpoint_tap_mac,
        endpoint_tap_name, store_plan, store_state,
    };
    use o3k_domain::{
        AddressRealm, FabricHostIdentity, FabricProviderKind, Ipv4Prefix,
        RealmEncapsulationBinding, RealmEndpointDirectory,
    };
    use std::{io, sync::Mutex};

    struct LinkCommand {
        tap_mac: Mutex<String>,
        bridge: Mutex<String>,
        tap_mode: Mutex<String>,
        tap_present: Mutex<bool>,
        bridge_present: Mutex<bool>,
        calls: Mutex<Vec<Vec<String>>>,
    }

    impl LinuxFabricCommand for LinkCommand {
        fn output(&self, _program: &str, args: &[&str]) -> io::Result<(bool, String)> {
            self.calls
                .lock()
                .expect("calls lock")
                .push(args.iter().map(|arg| (*arg).to_owned()).collect());
            let name = args.last().copied().unwrap_or_default();
            if name == "o3k-b-00000000" || name.starts_with("o3k-b-") {
                let bridge_present = *self.bridge_present.lock().expect("bridge state");
                return Ok((
                    bridge_present,
                    format!(
                        "[{{\"ifname\":\"{name}\",\"ifindex\":55,\"linkinfo\":{{\"info_kind\":\"bridge\"}}}}]"
                    ),
                ));
            }
            let tap_name = name;
            let tap_mac = self.tap_mac.lock().expect("tap MAC").clone();
            let bridge = self.bridge.lock().expect("bridge name").clone();
            let tap_mode = self.tap_mode.lock().expect("tap mode").clone();
            let tap_present = *self.tap_present.lock().expect("tap state");
            Ok((
                tap_present,
                format!(
                    "[{{\"ifname\":\"{tap_name}\",\"ifindex\":44,\"address\":\"{}\",\"master\":\"{}\",\"linkinfo\":{{\"info_kind\":\"tun\",\"info_data\":{{\"mode\":\"{}\"}}}}}}]",
                    tap_mac, bridge, tap_mode
                ),
            ))
        }

        fn run(&self, _program: &str, _args: &[&str]) -> io::Result<bool> {
            Ok(false)
        }

        fn run_with_input(
            &self,
            _program: &str,
            _args: &[&str],
            _input: &[u8],
        ) -> io::Result<bool> {
            Ok(false)
        }
    }

    fn plan() -> NamespacedRoutedFabricPlan {
        plan_with(0x1100_0000_0000_0000_0000_0000_0000_0011, 12, 501)
    }

    fn plan_with(realm: u128, endpoint: u128, vni: u32) -> NamespacedRoutedFabricPlan {
        let realm = AddressRealm {
            id: Uuid::from_u128(realm),
            network_id: Uuid::from_u128(13),
            project_id: "project-a".to_owned(),
            prefix: Ipv4Prefix::new("10.30.0.0".parse().expect("network IP"), 24).expect("prefix"),
            overlapping_prefixes: false,
        };
        let directory = RealmEndpointDirectory::build(
            &realm,
            vec![
                o3k_domain::EndpointLocation {
                    endpoint_id: Uuid::from_u128(endpoint),
                    project_id: "project-a".to_owned(),
                    realm_id: realm.id,
                    fixed_ip: "10.30.0.12".parse().expect("endpoint ip"),
                    mac: "fa:16:3e:12:34:56".to_owned(),
                    selected_host: "compute-a".to_owned(),
                    endpoint_generation: 7,
                    placement_generation: 9,
                },
                o3k_domain::EndpointLocation {
                    endpoint_id: Uuid::from_u128(endpoint + 1),
                    project_id: "project-a".to_owned(),
                    realm_id: realm.id,
                    fixed_ip: "10.30.0.13".parse().expect("second endpoint ip"),
                    mac: "fa:16:3e:12:34:57".to_owned(),
                    selected_host: "compute-a".to_owned(),
                    endpoint_generation: 8,
                    placement_generation: 10,
                },
            ],
            &[],
            4,
        )
        .expect("directory");
        let local = FabricHostIdentity {
            host_id: "compute-a".to_owned(),
            public_key: "A".repeat(43) + "=",
            underlay_endpoint: "192.0.2.10:65001".to_owned(),
            fabric_transport_ip: "198.18.0.1".parse().expect("transport ip"),
            provider_version: "fabric-linux-v0.1.5".to_owned(),
            fabric_generation: 3,
            underlay_mtu: 1500,
            fabric_mtu: 1440,
        };
        let binding = RealmEncapsulationBinding {
            fabric_domain_id: Uuid::from_u128(17),
            realm_id: realm.id,
            provider_kind: FabricProviderKind::Vxlan,
            provider_segment_id: vni,
            binding_generation: 6,
        };
        directory
            .compile_fabric_plan(&local, std::slice::from_ref(&local), 1390, &binding)
            .expect("fabric plan")
    }

    fn ownership(plan: &NamespacedRoutedFabricPlan) -> ProviderState {
        let endpoint_taps = plan
            .directory
            .entries
            .iter()
            .map(|endpoint| {
                let tap = EndpointTapOwnership {
                    endpoint_id: endpoint.endpoint_id,
                    interface: endpoint_tap_name(plan.realm_id, endpoint.endpoint_id),
                    mac: endpoint_tap_mac(plan.realm_id, endpoint.endpoint_id),
                };
                (tap.endpoint_id, tap)
            })
            .collect();
        ProviderState {
            version: STATE_VERSION,
            fabric: Some(FabricOwnership {
                namespace: "o3k-fabric".to_owned(),
                interface: "o3k-wg".to_owned(),
                private_key_path: "/var/lib/o3k/private.key".to_owned(),
                fabric_transport_ip: plan.local_fabric_transport_ip,
                fabric_generation: plan.local_fabric_generation,
                fabric_mtu: plan.local_fabric_mtu,
                ingress_owner_token: "owner-token".to_owned(),
                ingress_auth_fingerprint: String::new(),
                ingress_vni_fingerprint: String::new(),
                managed_peers: Default::default(),
            }),
            realms: BTreeMap::from([(
                plan.realm_id,
                RealmOwnership {
                    realm_id: plan.realm_id,
                    namespace: format!("o3k-r-{}", &plan.realm_id.simple().to_string()[..8]),
                    bridge: expected_realm_bridge(plan.realm_id),
                    host_veth: "o3k-host".to_owned(),
                    realm_veth: "o3k-realm".to_owned(),
                    fabric_veth: String::new(),
                    fabric_realm_veth: String::new(),
                    public_host_veth: "o3k-phost".to_owned(),
                    public_realm_veth: "o3k-prealm".to_owned(),
                    geneve: BTreeMap::new(),
                    vxlan: Some(VxlanOwnership {
                        interface: "o3k-x-vxlan".to_owned(),
                        bridge: "o3k-c-vxlan".to_owned(),
                        host_veth: "o3k-v-host".to_owned(),
                        fabric_veth: "o3k-i-fabric".to_owned(),
                        vni: plan.encapsulation.provider_segment_id,
                        binding_generation: plan.encapsulation.binding_generation,
                        local_transport_ip: plan.local_fabric_transport_ip,
                        tenant_mtu: plan.tenant_mtu,
                        flood_peers: Default::default(),
                    }),
                    attachments: BTreeMap::new(),
                    endpoint_taps,
                    pending_endpoint_taps: BTreeMap::new(),
                    policy_generation: plan.policy_generation,
                    policy_fingerprint: String::new(),
                    anti_spoof_generation: plan.directory_generation,
                    anti_spoof_fingerprint: String::new(),
                    public_generation: 0,
                    public_fingerprint: String::new(),
                    public_mark: 0,
                    public_route_table: 0,
                    public_addresses: Vec::new(),
                    directory_generation: plan.directory_generation,
                    local_fabric_generation: plan.local_fabric_generation,
                },
            )]),
        }
    }

    fn resolver(
        root: &Path,
        plan: &NamespacedRoutedFabricPlan,
        command: Arc<dyn LinuxFabricCommand>,
    ) -> LinuxFabricAttachmentResolver {
        fs::create_dir_all(root.join("plans")).expect("state directories");
        store_state(&root.join("ownership.json"), &ownership(plan)).expect("ownership state");
        store_plan(
            &root.join("plans").join(format!("{}.json", plan.realm_id)),
            plan,
        )
        .expect("plan state");
        LinuxFabricAttachmentResolver::with_command(
            root.to_path_buf(),
            "compute-a".to_owned(),
            command,
        )
        .expect("read-only resolver")
    }

    fn command(tap_mac: String, bridge: String) -> Arc<LinkCommand> {
        Arc::new(LinkCommand {
            tap_mac: Mutex::new(tap_mac),
            bridge: Mutex::new(bridge),
            tap_mode: Mutex::new("tap".to_owned()),
            tap_present: Mutex::new(true),
            bridge_present: Mutex::new(true),
            calls: Mutex::new(Vec::new()),
        })
    }

    #[test]
    fn resolves_fabric_tap_with_distinct_guest_mac_and_live_bridge_proof() {
        let root = std::env::temp_dir().join(format!("o3k-fabric-attest-{}", Uuid::now_v7()));
        let plan = plan();
        let endpoint_id = Uuid::from_u128(12);
        let tap_mac = endpoint_tap_mac(plan.realm_id, endpoint_id);
        let command = command(tap_mac.clone(), expected_realm_bridge(plan.realm_id));
        let resolver = resolver(&root, &plan, command);
        let evidence = resolver
            .resolve(endpoint_id, "fa:16:3e:12:34:56", "compute-a")
            .expect("current Fabric TAP is attachable");
        assert_eq!(evidence.tap_mac, tap_mac);
        assert_eq!(evidence.guest_mac, "fa:16:3e:12:34:56");
        assert_ne!(evidence.tap_mac, evidence.guest_mac);
        assert_eq!(evidence.endpoint_generation, 7);
        assert_eq!(evidence.placement_generation, 9);
        assert_eq!(evidence.directory_generation, 4);
        assert_eq!(evidence.fabric_generation, 3);
        assert_eq!(evidence.binding_generation, 6);
        assert_eq!(evidence.vni, 501);
        fs::remove_dir_all(root).expect("remove fixture");
    }

    #[test]
    fn rejects_wrong_guest_mac_host_and_unrealized_kernel_state() {
        let plan = plan();
        let endpoint_id = Uuid::from_u128(12);
        let root = std::env::temp_dir().join(format!("o3k-fabric-attest-{}", Uuid::now_v7()));
        let link_command = command(
            endpoint_tap_mac(plan.realm_id, endpoint_id),
            expected_realm_bridge(plan.realm_id),
        );
        let resolver = resolver(&root, &plan, link_command.clone());
        assert_eq!(
            resolver.resolve(endpoint_id, "fa:16:3e:00:00:01", "compute-a"),
            Err(FabricAttachmentError::GuestMacMismatch)
        );
        assert_eq!(
            resolver.resolve(endpoint_id, "fa:16:3e:12:34:56", "compute-b"),
            Err(FabricAttachmentError::WrongHost)
        );
        *link_command.tap_present.lock().expect("tap state") = false;
        assert_eq!(
            resolver.resolve(endpoint_id, "fa:16:3e:12:34:56", "compute-a"),
            Err(FabricAttachmentError::LiveTapAbsent)
        );
        fs::remove_dir_all(root).expect("remove fixture");
    }

    #[test]
    fn rejects_pending_provider_ownership_and_wrong_live_link_identity() {
        let plan = plan();
        let endpoint_id = Uuid::from_u128(12);
        let root = std::env::temp_dir().join(format!("o3k-fabric-attest-{}", Uuid::now_v7()));
        let link_command = command(
            endpoint_tap_mac(plan.realm_id, endpoint_id),
            expected_realm_bridge(plan.realm_id),
        );
        let current = resolver(&root, &plan, link_command.clone());
        let mut state = ownership(&plan);
        let realm = state.realms.get_mut(&plan.realm_id).expect("realm");
        let tap = realm.endpoint_taps.remove(&endpoint_id).expect("tap");
        realm.pending_endpoint_taps.insert(endpoint_id, tap);
        store_state(&root.join("ownership.json"), &state).expect("pending state");
        assert_eq!(
            current.resolve(endpoint_id, "fa:16:3e:12:34:56", "compute-a"),
            Err(FabricAttachmentError::Pending)
        );

        let state = ownership(&plan);
        store_state(&root.join("ownership.json"), &state).expect("committed state");
        *link_command.bridge.lock().expect("bridge name") = "o3k-b-ffffffff".to_owned();
        assert_eq!(
            current.resolve(endpoint_id, "fa:16:3e:12:34:56", "compute-a"),
            Err(FabricAttachmentError::RealmBridgeMismatch)
        );
        *link_command.bridge.lock().expect("bridge name") = expected_realm_bridge(plan.realm_id);
        *link_command.tap_mac.lock().expect("tap MAC") = "02:aa:bb:cc:dd:ef".to_owned();
        assert_eq!(
            current.resolve(endpoint_id, "fa:16:3e:12:34:56", "compute-a"),
            Err(FabricAttachmentError::TapMacMismatch)
        );
        *link_command.tap_mac.lock().expect("tap MAC") =
            endpoint_tap_mac(plan.realm_id, endpoint_id);
        *link_command.tap_mode.lock().expect("tap mode") = "tun".to_owned();
        assert_eq!(
            current.resolve(endpoint_id, "fa:16:3e:12:34:56", "compute-a"),
            Err(FabricAttachmentError::WrongLinkType)
        );
        fs::remove_dir_all(root).expect("remove fixture");
    }

    #[test]
    fn kernel_only_same_name_tap_is_not_attachment_authority() {
        let plan = plan();
        let endpoint_id = Uuid::from_u128(12);
        let root = std::env::temp_dir().join(format!("o3k-fabric-attest-{}", Uuid::now_v7()));
        let link_command = command(
            endpoint_tap_mac(plan.realm_id, endpoint_id),
            expected_realm_bridge(plan.realm_id),
        );
        let current = resolver(&root, &plan, link_command);
        let mut state = ownership(&plan);
        state
            .realms
            .get_mut(&plan.realm_id)
            .expect("realm")
            .endpoint_taps
            .clear();
        store_state(&root.join("ownership.json"), &state).expect("state without TAP owner");
        assert_eq!(
            current.resolve(endpoint_id, "fa:16:3e:12:34:56", "compute-a"),
            Err(FabricAttachmentError::OwnershipMismatch)
        );
        fs::remove_dir_all(root).expect("remove fixture");
    }

    #[test]
    fn rejects_ambiguous_or_stale_fabric_ownership() {
        let plan = plan();
        let endpoint_id = Uuid::from_u128(12);
        let root = std::env::temp_dir().join(format!("o3k-fabric-attest-{}", Uuid::now_v7()));
        let link_command = command(
            endpoint_tap_mac(plan.realm_id, endpoint_id),
            expected_realm_bridge(plan.realm_id),
        );
        let current = resolver(&root, &plan, link_command);

        let mut state = ownership(&plan);
        let tap = state
            .realms
            .get_mut(&plan.realm_id)
            .expect("realm")
            .endpoint_taps
            .get_mut(&endpoint_id)
            .expect("committed TAP");
        tap.mac = "02:aa:bb:cc:dd:ee".to_owned();
        store_state(&root.join("ownership.json"), &state).expect("altered ownership state");
        assert_eq!(
            current.resolve(endpoint_id, "fa:16:3e:12:34:56", "compute-a"),
            Err(FabricAttachmentError::OwnershipMismatch),
            "a state record that does not match the provider's deterministic TAP identity is rejected"
        );

        let mut stale_state = ownership(&plan);
        stale_state
            .realms
            .get_mut(&plan.realm_id)
            .expect("realm")
            .directory_generation += 1;
        store_state(&root.join("ownership.json"), &stale_state).expect("stale generation");
        assert_eq!(
            current.resolve(endpoint_id, "fa:16:3e:12:34:56", "compute-a"),
            Err(FabricAttachmentError::OwnershipMismatch),
            "stale provider generations cannot attest a TAP"
        );
        fs::remove_dir_all(root).expect("remove fixture");
    }

    #[test]
    fn resolves_multiple_endpoints_across_realms_from_one_provider_state() {
        let first = plan();
        let second = plan_with(0x2200_0000_0000_0000_0000_0000_0000_0021, 22, 502);
        let root = std::env::temp_dir().join(format!("o3k-fabric-attest-{}", Uuid::now_v7()));
        fs::create_dir_all(root.join("plans")).expect("state directories");
        let mut state = ownership(&first);
        state.realms.extend(ownership(&second).realms);
        store_state(&root.join("ownership.json"), &state).expect("shared ownership state");
        store_plan(
            &root.join("plans").join(format!("{}.json", first.realm_id)),
            &first,
        )
        .expect("first realm plan");
        store_plan(
            &root.join("plans").join(format!("{}.json", second.realm_id)),
            &second,
        )
        .expect("second realm plan");
        let link_command = command(
            endpoint_tap_mac(first.realm_id, Uuid::from_u128(12)),
            expected_realm_bridge(first.realm_id),
        );
        let current = LinuxFabricAttachmentResolver::with_command(
            root.clone(),
            "compute-a".to_owned(),
            link_command.clone(),
        )
        .expect("read-only resolver");
        let first_evidence = current
            .resolve(Uuid::from_u128(12), "fa:16:3e:12:34:56", "compute-a")
            .expect("first realm endpoint");
        let mut changed_state = ownership(&first);
        let first_realm = changed_state
            .realms
            .get_mut(&first.realm_id)
            .expect("first realm");
        let pending = first_realm
            .endpoint_taps
            .remove(&Uuid::from_u128(13))
            .expect("second endpoint TAP");
        first_realm
            .pending_endpoint_taps
            .insert(pending.endpoint_id, pending);
        changed_state.realms.extend(ownership(&second).realms);
        store_state(&root.join("ownership.json"), &changed_state).expect("publish state change");
        assert_eq!(
            current.resolve(Uuid::from_u128(13), "fa:16:3e:12:34:57", "compute-a"),
            Err(FabricAttachmentError::Pending),
            "the long-running resolver observes a newly published provider snapshot"
        );
        let mut restored_state = ownership(&first);
        restored_state.realms.extend(ownership(&second).realms);
        store_state(&root.join("ownership.json"), &restored_state).expect("restore state");
        *link_command.tap_mac.lock().expect("tap MAC") =
            endpoint_tap_mac(first.realm_id, Uuid::from_u128(13));
        let second_endpoint = current
            .resolve(Uuid::from_u128(13), "fa:16:3e:12:34:57", "compute-a")
            .expect("second endpoint on same host and realm");
        *link_command.tap_mac.lock().expect("tap MAC") =
            endpoint_tap_mac(second.realm_id, Uuid::from_u128(22));
        *link_command.bridge.lock().expect("bridge") = expected_realm_bridge(second.realm_id);
        let second_evidence = current
            .resolve(Uuid::from_u128(22), "fa:16:3e:12:34:56", "compute-a")
            .expect("second realm endpoint");
        assert_ne!(first_evidence.realm_id, second_evidence.realm_id);
        assert_ne!(first_evidence.realm_bridge, second_evidence.realm_bridge);
        assert_ne!(first_evidence.tap_name, second_endpoint.tap_name);
        assert_eq!(first_evidence.realm_id, second_endpoint.realm_id);
        assert_eq!(first_evidence.vni, 501);
        assert_eq!(second_evidence.vni, 502);
        fs::remove_dir_all(root).expect("remove fixture");
    }
}
