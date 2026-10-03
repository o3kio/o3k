//! Disposable three-host Fabric v3 provider gate helper.
//!
//! This is test tooling only. It builds the accepted canonical fixture:
//! Realm A has A1 on host-a and A2 on host-b; Realm B has B1 on host-c and B2
//! on host-b. Each invocation applies the complete current peer set so HER is
//! derived from all enrolled hosts rather than from observed traffic.

use o3k_domain::{
    AddressRealm, EndpointLocation, FabricHostIdentity, FabricProviderKind, Ipv4Prefix,
    NamespacedRoutedFabricPlan, RealmEncapsulationBinding, RealmEndpointDirectory,
};
use o3k_network::{FabricBackend, LinuxFabricBackend, LinuxFabricConfig};
use std::{env, net::Ipv4Addr, path::PathBuf, process};
use uuid::Uuid;

const REALM_A_ID: u128 = 0xa100_0000_0000_0000_0000_0000_0000_0001;
const REALM_B_ID: u128 = 0xb100_0000_0000_0000_0000_0000_0000_0001;
const EP_A1_ID: u128 = 0xa100_0000_0000_0000_0000_0000_0000_0101;
const EP_A2_ID: u128 = 0xa100_0000_0000_0000_0000_0000_0000_0102;
const EP_B1_ID: u128 = 0xb100_0000_0000_0000_0000_0000_0000_0101;
const EP_B2_ID: u128 = 0xb100_0000_0000_0000_0000_0000_0000_0102;
const FABRIC_DOMAIN_ID: u128 = 0x0102_0304_0506_0708_090a_0b0c_0d0e_0f10;

#[derive(Clone)]
struct Peer {
    host_id: String,
    transport_ip: Ipv4Addr,
    public_key: String,
    underlay_endpoint: String,
}

fn endpoint(
    endpoint_id: u128,
    realm_id: Uuid,
    project_id: &str,
    fixed_ip: &str,
    mac: &str,
    selected_host: &str,
) -> Result<EndpointLocation, Box<dyn std::error::Error>> {
    Ok(EndpointLocation {
        endpoint_id: Uuid::from_u128(endpoint_id),
        project_id: project_id.to_owned(),
        realm_id,
        fixed_ip: fixed_ip.parse()?,
        mac: mac.to_owned(),
        selected_host: selected_host.to_owned(),
        endpoint_generation: 1,
        placement_generation: 1,
    })
}

fn plan(
    realm_id: Uuid,
    vni: u32,
    local_host: &str,
    local_transport_ip: Ipv4Addr,
    peers: &[Peer],
) -> Result<NamespacedRoutedFabricPlan, Box<dyn std::error::Error>> {
    let prefix = Ipv4Prefix::new("10.0.0.0".parse()?, 24).ok_or("invalid prefix")?;
    let project_id = if realm_id == Uuid::from_u128(REALM_A_ID) {
        "project-a"
    } else {
        "project-b"
    };
    let realm = AddressRealm {
        id: realm_id,
        network_id: Uuid::from_u128(realm_id.as_u128() ^ 0xfeed),
        project_id: project_id.to_owned(),
        prefix,
        overlapping_prefixes: true,
    };
    let locations = if realm_id == Uuid::from_u128(REALM_A_ID) {
        vec![
            endpoint(
                EP_A1_ID,
                realm_id,
                project_id,
                "10.0.0.10",
                "02:00:00:00:a1:01",
                "host-a",
            )?,
            endpoint(
                EP_A2_ID,
                realm_id,
                project_id,
                "10.0.0.20",
                "02:00:00:00:a1:02",
                "host-b",
            )?,
        ]
    } else {
        vec![
            endpoint(
                EP_B1_ID,
                realm_id,
                project_id,
                "10.0.0.10",
                "02:00:00:00:b1:01",
                "host-c",
            )?,
            endpoint(
                EP_B2_ID,
                realm_id,
                project_id,
                "10.0.0.20",
                "02:00:00:00:b1:02",
                "host-b",
            )?,
        ]
    };
    let directory = RealmEndpointDirectory::build(&realm, locations, &[], 1)?;
    let local = FabricHostIdentity {
        host_id: local_host.to_owned(),
        public_key: "local-placeholder".to_owned(),
        underlay_endpoint: "127.0.0.1:65001".to_owned(),
        fabric_transport_ip: local_transport_ip,
        provider_version: "wireguard-v1".to_owned(),
        fabric_generation: 1,
        underlay_mtu: 1500,
        fabric_mtu: 1440,
    };
    let mut hosts = vec![local.clone()];
    for peer in peers {
        hosts.push(FabricHostIdentity {
            host_id: peer.host_id.clone(),
            public_key: peer.public_key.clone(),
            underlay_endpoint: peer.underlay_endpoint.clone(),
            fabric_transport_ip: peer.transport_ip,
            provider_version: "wireguard-v1".to_owned(),
            fabric_generation: 1,
            underlay_mtu: 1500,
            fabric_mtu: 1440,
        });
    }
    let binding = RealmEncapsulationBinding {
        fabric_domain_id: Uuid::from_u128(FABRIC_DOMAIN_ID),
        realm_id,
        provider_kind: FabricProviderKind::Vxlan,
        provider_segment_id: vni,
        binding_generation: 1,
    };
    Ok(directory.compile_fabric_plan(&local, &hosts, 1390, &binding)?)
}

fn usage() -> ! {
    eprintln!(
        "usage: --root PATH --mode apply|remove --host-id host-a|host-b|host-c --transport-ip IP --peer HOST,IP,UNDERLAY,KEY [--peer ...]"
    );
    process::exit(2)
}

fn main() -> Result<(), Box<dyn std::error::Error>> {
    let args: Vec<String> = env::args().collect();
    let mut root = None;
    let mut mode = None;
    let mut host_id = None;
    let mut transport_ip = None;
    let mut peers = Vec::new();
    let mut i = 1;
    while i < args.len() {
        match args[i].as_str() {
            "--root" => {
                i += 1;
                root = args.get(i).map(PathBuf::from);
            }
            "--mode" => {
                i += 1;
                mode = args.get(i).cloned();
            }
            "--host-id" => {
                i += 1;
                host_id = args.get(i).cloned();
            }
            "--transport-ip" => {
                i += 1;
                transport_ip = args.get(i).and_then(|v| v.parse().ok());
            }
            "--peer" => {
                i += 1;
                let raw = args.get(i).ok_or("missing --peer value")?;
                let fields: Vec<_> = raw.splitn(4, ',').collect();
                if fields.len() != 4 {
                    usage();
                }
                peers.push(Peer {
                    host_id: fields[0].to_owned(),
                    transport_ip: fields[1].parse()?,
                    underlay_endpoint: fields[2].to_owned(),
                    public_key: fields[3].to_owned(),
                });
            }
            _ => usage(),
        }
        i += 1;
    }
    let root = root.ok_or("--root required")?;
    let mode = mode.ok_or("--mode required")?;
    let host_id = host_id.ok_or("--host-id required")?;
    let transport_ip = transport_ip.ok_or("--transport-ip required")?;
    if !matches!(host_id.as_str(), "host-a" | "host-b" | "host-c") || peers.len() != 2 {
        return Err(
            "three-host fixture requires one of host-a/host-b/host-c and exactly two peers".into(),
        );
    }
    if peers.iter().any(|p| p.host_id == host_id) || peers.iter().any(|p| p.host_id.is_empty()) {
        return Err("peer set contains local or empty host".into());
    }
    let mut backend = LinuxFabricBackend::open(LinuxFabricConfig::for_root(&root))?;
    let plans = [
        plan(
            Uuid::from_u128(REALM_A_ID),
            101,
            &host_id,
            transport_ip,
            &peers,
        )?,
        plan(
            Uuid::from_u128(REALM_B_ID),
            102,
            &host_id,
            transport_ip,
            &peers,
        )?,
    ];
    for fabric_plan in &plans {
        match mode.as_str() {
            "apply" => {
                backend.apply(fabric_plan)?;
                if !backend.observe(fabric_plan)? {
                    return Err("provider observe after apply failed".into());
                }
            }
            "remove" => {
                backend.remove(fabric_plan)?;
                if !backend.observe_removed(fabric_plan)? {
                    return Err("provider observe after remove failed".into());
                }
            }
            _ => usage(),
        }
    }
    println!("three-host-provider={mode}-passed");
    Ok(())
}
