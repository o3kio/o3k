use super::*;

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub(crate) struct FabricOwnership {
    pub(crate) namespace: String,
    pub(crate) interface: String,
    pub(crate) private_key_path: String,
    pub(crate) fabric_transport_ip: std::net::Ipv4Addr,
    pub(crate) fabric_generation: u64,
    #[serde(default)]
    pub(crate) fabric_mtu: u16,
    /// Fingerprint of the provider-owned netdev ingress admission rules. The
    /// rules bind authenticated WireGuard transport addresses to peer marks;
    /// the marks are bound to current realm VNIs by the bridge admission
    /// fingerprint below and both are reconstructed from durable plans after
    /// restart.
    #[serde(default)]
    pub(crate) ingress_auth_fingerprint: String,
    /// Fingerprint of the provider-namespace bridge admission rules. These
    /// bind the authenticated peer mark to the one VXLAN device for each
    /// current realm and are reconstructed from durable plans after restart.
    #[serde(default)]
    pub(crate) ingress_vni_fingerprint: String,
    #[serde(default)]
    pub(crate) managed_peers: BTreeSet<String>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub(crate) struct RealmOwnership {
    pub(crate) realm_id: Uuid,
    pub(crate) namespace: String,
    pub(crate) bridge: String,
    pub(crate) host_veth: String,
    pub(crate) realm_veth: String,
    /// Legacy v2 fan-out fields.  v3 leaves these empty and rejects any
    /// populated value rather than adopting old Geneve state.
    pub(crate) fabric_veth: String,
    pub(crate) fabric_realm_veth: String,
    #[serde(default)]
    pub(crate) public_host_veth: String,
    #[serde(default)]
    pub(crate) public_realm_veth: String,
    #[serde(default)]
    pub(crate) geneve: BTreeMap<String, GeneveOwnership>,
    /// One learning VXLAN and one fabric bridge per active realm.  The
    /// bridge is connected to the realm L2 island through one veth pair;
    /// HER membership is reconciled from the canonical endpoint directory.
    #[serde(default)]
    pub(crate) vxlan: Option<VxlanOwnership>,
    /// One isolated L2 attachment exists for every remote target host.  The
    /// shared fabric namespace therefore never needs a tenant-IP route table;
    /// overlapping realms are selected by their attachment and Geneve VNI.
    #[serde(default)]
    pub(crate) attachments: BTreeMap<String, FabricAttachmentOwnership>,
    #[serde(default)]
    pub(crate) endpoint_taps: BTreeMap<Uuid, EndpointTapOwnership>,
    #[serde(default)]
    pub(crate) pending_endpoint_taps: BTreeMap<Uuid, EndpointTapOwnership>,
    #[serde(default)]
    pub(crate) policy_generation: u64,
    #[serde(default)]
    pub(crate) policy_fingerprint: String,
    #[serde(default)]
    pub(crate) anti_spoof_generation: u64,
    #[serde(default)]
    pub(crate) anti_spoof_fingerprint: String,
    #[serde(default)]
    pub(crate) public_generation: u64,
    #[serde(default)]
    pub(crate) public_fingerprint: String,
    #[serde(default)]
    pub(crate) public_mark: u32,
    #[serde(default)]
    pub(crate) public_route_table: u32,
    #[serde(default)]
    pub(crate) public_addresses: Vec<Ipv4Addr>,
    pub(crate) directory_generation: u64,
    pub(crate) local_fabric_generation: u64,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub(crate) struct EndpointTapOwnership {
    pub(crate) endpoint_id: Uuid,
    pub(crate) interface: String,
    pub(crate) mac: String,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub(crate) struct GeneveOwnership {
    pub(crate) target_host: String,
    pub(crate) interface: String,
    pub(crate) remote_transport_ip: std::net::Ipv4Addr,
    pub(crate) vni: u32,
    pub(crate) binding_generation: u64,
    pub(crate) local_tunnel_mac: String,
    pub(crate) remote_tunnel_mac: String,
    pub(crate) bridge: String,
    pub(crate) realm_veth: String,
    pub(crate) fabric_veth: String,
    #[serde(default)]
    pub(crate) realized: bool,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub(crate) struct FabricAttachmentOwnership {
    pub(crate) target_host: String,
    pub(crate) bridge: String,
    pub(crate) realm_veth: String,
    pub(crate) fabric_veth: String,
    pub(crate) local_tunnel_mac: String,
    pub(crate) remote_tunnel_mac: String,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub(crate) struct VxlanOwnership {
    pub(crate) interface: String,
    pub(crate) bridge: String,
    pub(crate) host_veth: String,
    pub(crate) fabric_veth: String,
    pub(crate) vni: u32,
    pub(crate) binding_generation: u64,
    pub(crate) local_transport_ip: std::net::Ipv4Addr,
    pub(crate) tenant_mtu: u16,
    #[serde(default)]
    pub(crate) flood_peers: BTreeSet<std::net::Ipv4Addr>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub(crate) struct ProviderState {
    pub(crate) version: u32,
    #[serde(default)]
    pub(crate) fabric: Option<FabricOwnership>,
    #[serde(default)]
    pub(crate) realms: BTreeMap<Uuid, RealmOwnership>,
}

impl Default for ProviderState {
    fn default() -> Self {
        Self {
            version: STATE_VERSION,
            fabric: None,
            realms: BTreeMap::new(),
        }
    }
}
