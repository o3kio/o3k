//! Regression-test helper for the P11 v3 dataplane.
//!
//! Each invocation applies or removes fabric plans for one host. The topology
//! is hardcoded: two overlapping-prefix realms (A and B), each with two
//! endpoints (one per host).  Run via the `fabric-v3-bridge-gate.sh` script
//! after building with `cargo build --example fabric-regression-helper --all-features`.
//!
//! Usage:
//! ```text
//! fabric-regression-helper \
//!   --root /tmp/o3k-reg-a \
//!   --mode apply|remove \
//!   --host-id reg-host-a \
//!   --transport-ip 198.18.0.1 \
//!   --peer-host-id reg-host-b \
//!   --peer-transport-ip 198.18.0.2 \
//!   --peer-public-key <base64-key> \
//!   --underlay-endpoint 10.77.0.2:65001
//! ```
//!
//! The `--peer-*` and `--underlay-endpoint` describe the **remote** host that
//! WireGuard and VXLAN connect to.

use o3k_domain::{
    AddressRealm, EndpointLocation, FabricHostIdentity, FabricProviderKind, Ipv4Prefix,
    NamespacedRoutedFabricPlan, RealmEncapsulationBinding, RealmEndpointDirectory,
};
use o3k_network::{FabricBackend, LinuxFabricBackend, LinuxFabricConfig};
use std::{env, net::Ipv4Addr, path::PathBuf, process};
use uuid::Uuid;

// ---------------------------------------------------------------------------
// Hardcoded regression topology
// ---------------------------------------------------------------------------
//
// Realm A and B share the same tenant prefix (10.0.0.0/24) to exercise the
// overlapping-prefix / VXLAN-encapsulation path.  Each realm owns two
// endpoints, one placed on each host.

const REALM_A_ID: u128 = 0xa100_0000_0000_0000_0000_0000_0000_0001;
const REALM_B_ID: u128 = 0xb100_0000_0000_0000_0000_0000_0000_0001;

const EP_A1_ID: u128 = 0xa100_0000_0000_0000_0000_0000_0000_0101;
const EP_A2_ID: u128 = 0xa100_0000_0000_0000_0000_0000_0000_0102;
const EP_B1_ID: u128 = 0xb100_0000_0000_0000_0000_0000_0000_0101;
const EP_B2_ID: u128 = 0xb100_0000_0000_0000_0000_0000_0000_0102;

const REALM_A_VNI: u32 = 101;
const REALM_B_VNI: u32 = 102;

const FABRIC_DOMAIN_ID: u128 = 0x0102_0304_0506_0708_090a_0b0c_0d0e_0f10;

/// Shared realm prefix used by both realms (overlapping).
const REALM_PREFIX_STR: &str = "10.0.0.0/24";

/// Local endpoint IPs (on reg-host-a).
const LOCAL_ENDPOINT_IP: Ipv4Addr = Ipv4Addr::new(10, 0, 0, 10);
/// Remote endpoint IPs (on reg-host-b).
const REMOTE_ENDPOINT_IP: Ipv4Addr = Ipv4Addr::new(10, 0, 0, 20);

const TENANT_MTU: u16 = 1390;
const UNDERLAY_MTU: u16 = 1500;
const FABRIC_MTU: u16 = 1440;
const DIRECTORY_GENERATION: u64 = 1;
const FABRIC_GENERATION: u64 = 1;
const ENDPOINT_GENERATION: u64 = 1;
const PLACEMENT_GENERATION: u64 = 1;

/// Build a `NamespacedRoutedFabricPlan` for one realm, one host.
#[allow(clippy::too_many_arguments)]
fn build_realm_plan(
    realm_id: Uuid,
    vni: u32,
    local_host_id: &str,
    local_transport_ip: Ipv4Addr,
    peer_host_id: &str,
    peer_transport_ip: Ipv4Addr,
    peer_public_key: &str,
    peer_underlay_endpoint: &str,
) -> Result<NamespacedRoutedFabricPlan, Box<dyn std::error::Error>> {
    let (network, prefix_len) = REALM_PREFIX_STR
        .split_once('/')
        .ok_or("invalid realm prefix")?;
    let prefix =
        Ipv4Prefix::new(network.parse()?, prefix_len.parse()?).ok_or("invalid realm prefix")?;

    let realm = AddressRealm {
        id: realm_id,
        network_id: Uuid::from_u128(0xfeed),
        project_id: "fabric-regression".to_owned(),
        prefix,
        overlapping_prefixes: true,
    };

    // The fixture places .10 on host A and .20 on host B.  Build the
    // directory from the actual local/peer host arguments so the anti-spoof
    // rules and provider placement match the endpoint namespaces in the
    // bridge harness on both sides.
    let realm_a = realm_id == Uuid::from_u128(REALM_A_ID);
    let (ip_a, mac_a, endpoint_a) = if realm_a {
        (
            LOCAL_ENDPOINT_IP,
            "02:00:00:00:a1:01",
            Uuid::from_u128(EP_A1_ID),
        )
    } else {
        (
            LOCAL_ENDPOINT_IP,
            "02:00:00:00:b1:01",
            Uuid::from_u128(EP_B1_ID),
        )
    };
    let (ip_b, mac_b, endpoint_b) = if realm_a {
        (
            REMOTE_ENDPOINT_IP,
            "02:00:00:00:a1:02",
            Uuid::from_u128(EP_A2_ID),
        )
    } else {
        (
            REMOTE_ENDPOINT_IP,
            "02:00:00:00:b1:02",
            Uuid::from_u128(EP_B2_ID),
        )
    };
    let local_is_a = local_host_id == "reg-host-a";
    let (local_ip, local_mac, local_endpoint_id, remote_ip, remote_mac, remote_endpoint_id) =
        if local_is_a {
            (ip_a, mac_a, endpoint_a, ip_b, mac_b, endpoint_b)
        } else {
            (ip_b, mac_b, endpoint_b, ip_a, mac_a, endpoint_a)
        };

    let directory = RealmEndpointDirectory::build(
        &realm,
        vec![
            EndpointLocation {
                endpoint_id: local_endpoint_id,
                project_id: realm.project_id.clone(),
                realm_id: realm.id,
                fixed_ip: local_ip,
                mac: local_mac.to_owned(),
                selected_host: local_host_id.to_owned(),
                endpoint_generation: ENDPOINT_GENERATION,
                placement_generation: PLACEMENT_GENERATION,
            },
            EndpointLocation {
                endpoint_id: remote_endpoint_id,
                project_id: realm.project_id.clone(),
                realm_id: realm.id,
                fixed_ip: remote_ip,
                mac: remote_mac.to_owned(),
                selected_host: peer_host_id.to_owned(),
                endpoint_generation: ENDPOINT_GENERATION,
                placement_generation: PLACEMENT_GENERATION,
            },
        ],
        &[],
        DIRECTORY_GENERATION,
    )?;

    let local_identity = FabricHostIdentity {
        host_id: local_host_id.to_owned(),
        public_key: "local-placeholder".to_owned(),
        underlay_endpoint: "127.0.0.1:65001".to_owned(),
        fabric_transport_ip: local_transport_ip,
        provider_version: "wireguard-v1".to_owned(),
        fabric_generation: FABRIC_GENERATION,
        underlay_mtu: UNDERLAY_MTU,
        fabric_mtu: FABRIC_MTU,
    };

    let peer_identity = FabricHostIdentity {
        host_id: peer_host_id.to_owned(),
        public_key: peer_public_key.to_owned(),
        underlay_endpoint: peer_underlay_endpoint.to_owned(),
        fabric_transport_ip: peer_transport_ip,
        provider_version: "wireguard-v1".to_owned(),
        fabric_generation: FABRIC_GENERATION,
        underlay_mtu: UNDERLAY_MTU,
        fabric_mtu: FABRIC_MTU,
    };

    let binding = RealmEncapsulationBinding {
        fabric_domain_id: Uuid::from_u128(FABRIC_DOMAIN_ID),
        realm_id: realm.id,
        provider_kind: FabricProviderKind::Vxlan,
        provider_segment_id: vni,
        binding_generation: 1,
    };

    let plan = directory.compile_fabric_plan(
        &local_identity,
        &[local_identity.clone(), peer_identity],
        TENANT_MTU,
        &binding,
    )?;

    Ok(plan)
}

fn main() -> Result<(), Box<dyn std::error::Error>> {
    let args: Vec<String> = env::args().collect();

    let mut root = None;
    let mut mode = None;
    let mut host_id = None;
    let mut transport_ip = None;
    let mut peer_host_id = None;
    let mut peer_transport_ip = None;
    let mut peer_public_key = None;
    let mut underlay_endpoint = None;
    let mut wireguard_port = None;
    let mut vxlan_port = None;

    let mut i = 1;
    while i < args.len() {
        match args[i].as_str() {
            "--root" => {
                i += 1;
                root = Some(PathBuf::from(&args[i]));
            }
            "--mode" => {
                i += 1;
                mode = Some(args[i].clone());
            }
            "--host-id" => {
                i += 1;
                host_id = Some(args[i].clone());
            }
            "--transport-ip" => {
                i += 1;
                transport_ip = Some(args[i].parse::<Ipv4Addr>()?);
            }
            "--peer-host-id" => {
                i += 1;
                peer_host_id = Some(args[i].clone());
            }
            "--peer-transport-ip" => {
                i += 1;
                peer_transport_ip = Some(args[i].parse::<Ipv4Addr>()?);
            }
            "--peer-public-key" => {
                i += 1;
                peer_public_key = Some(args[i].clone());
            }
            "--underlay-endpoint" => {
                i += 1;
                underlay_endpoint = Some(args[i].clone());
            }
            "--wireguard-port" => {
                i += 1;
                wireguard_port = Some(args[i].parse::<u16>()?);
            }
            "--vxlan-port" => {
                i += 1;
                vxlan_port = Some(args[i].parse::<u16>()?);
            }
            other => {
                eprintln!("unknown argument: {other}");
                process::exit(1);
            }
        }
        i += 1;
    }

    let root = root.ok_or("--root is required")?;
    let mode = mode.ok_or("--mode is required (apply|remove)")?;
    let host_id = host_id.ok_or("--host-id is required")?;
    let transport_ip = transport_ip.ok_or("--transport-ip is required")?;
    let peer_host_id = peer_host_id.ok_or("--peer-host-id is required")?;
    let peer_transport_ip = peer_transport_ip.ok_or("--peer-transport-ip is required")?;
    let peer_public_key = peer_public_key.ok_or("--peer-public-key is required")?;
    let underlay_endpoint = underlay_endpoint.ok_or("--underlay-endpoint is required")?;

    if mode != "apply" && mode != "remove" {
        eprintln!("--mode must be 'apply' or 'remove', got: {mode}");
        process::exit(1);
    }

    // Build plans for both realms.
    let plans = vec![
        build_realm_plan(
            Uuid::from_u128(REALM_A_ID),
            REALM_A_VNI,
            &host_id,
            transport_ip,
            &peer_host_id,
            peer_transport_ip,
            &peer_public_key,
            &underlay_endpoint,
        )?,
        build_realm_plan(
            Uuid::from_u128(REALM_B_ID),
            REALM_B_VNI,
            &host_id,
            transport_ip,
            &peer_host_id,
            peer_transport_ip,
            &peer_public_key,
            &underlay_endpoint,
        )?,
    ];

    let mut config = LinuxFabricConfig::for_root(&root);
    if let Some(port) = wireguard_port {
        config = config.with_wireguard_port(port);
    }
    if let Some(port) = vxlan_port {
        config = config.with_vxlan_port(port);
    }
    let mut backend = LinuxFabricBackend::open(config)?;

    for plan in &plans {
        match mode.as_str() {
            "apply" => {
                backend.apply(plan)?;
                if !backend.observe(plan)? {
                    eprintln!("ERROR: backend did not observe applied plan");
                    process::exit(1);
                }
            }
            "remove" => {
                backend.remove(plan)?;
                if !backend.observe_removed(plan)? {
                    eprintln!("ERROR: backend did not observe removed plan");
                    process::exit(1);
                }
            }
            _ => unreachable!(),
        }
    }

    if mode == "apply" {
        println!("BACKEND_APPLIED");
    } else {
        println!("BACKEND_REMOVED");
    }

    Ok(())
}
