//! Disposable real-command smoke for the Linux P11 provider.
//!
//! This proves only provider topology creation and cleanup on one host. It is
//! not guest traffic, policy, MTU, multi-host, or product-profile evidence.

use o3k_domain::{
    AddressRealm, EndpointLocation, FabricHostIdentity, FabricProviderKind, Ipv4Prefix,
    RealmEncapsulationBinding, RealmEndpointDirectory,
};
use o3k_network::{FabricBackend, LinuxFabricBackend, LinuxFabricConfig};
use std::{env, fs, path::PathBuf, process::Command};
use uuid::Uuid;

fn main() -> Result<(), Box<dyn std::error::Error>> {
    let root = env::var_os("O3K_FABRIC_SMOKE_ROOT")
        .map(PathBuf::from)
        .ok_or("O3K_FABRIC_SMOKE_ROOT must name a disposable provider root")?;
    if root == std::path::Path::new("/") || root.as_os_str().is_empty() {
        return Err("refusing an unsafe smoke root".into());
    }
    let realm = AddressRealm {
        id: Uuid::from_u128(0x1100),
        network_id: Uuid::from_u128(0x1101),
        project_id: "fabric-smoke".to_owned(),
        prefix: Ipv4Prefix::new("10.250.1.0".parse()?, 24).ok_or("invalid prefix")?,
        overlapping_prefixes: false,
    };
    let directory = RealmEndpointDirectory::build(
        &realm,
        vec![
            EndpointLocation {
                endpoint_id: Uuid::from_u128(0x1201),
                project_id: realm.project_id.clone(),
                realm_id: realm.id,
                fixed_ip: "10.250.1.11".parse()?,
                mac: "02:00:00:00:01:11".to_owned(),
                selected_host: "smoke-local".to_owned(),
                endpoint_generation: 1,
                placement_generation: 1,
            },
            EndpointLocation {
                endpoint_id: Uuid::from_u128(0x1200),
                project_id: realm.project_id.clone(),
                realm_id: realm.id,
                fixed_ip: "10.250.1.12".parse()?,
                mac: "02:00:00:00:01:12".to_owned(),
                selected_host: "smoke-remote".to_owned(),
                endpoint_generation: 1,
                placement_generation: 1,
            },
        ],
        &[],
        1,
    )?;
    let local = FabricHostIdentity {
        host_id: "smoke-local".to_owned(),
        public_key: "local-public-key-is-not-a-peer".to_owned(),
        underlay_endpoint: "127.0.0.1:65001".to_owned(),
        fabric_transport_ip: "198.18.0.1".parse()?,
        provider_version: "wireguard-v1".to_owned(),
        fabric_generation: 1,
        underlay_mtu: 1500,
        fabric_mtu: 1440,
    };
    let remote = FabricHostIdentity {
        host_id: "smoke-remote".to_owned(),
        public_key: "v+3Zvbhhd38dkie1myZTB4IyAIlHlM23ImWM9QXqnFM=".to_owned(),
        underlay_endpoint: "127.0.0.1:51821".to_owned(),
        fabric_transport_ip: "198.18.0.2".parse()?,
        provider_version: "wireguard-v1".to_owned(),
        fabric_generation: 1,
        underlay_mtu: 1500,
        fabric_mtu: 1440,
    };
    let binding = RealmEncapsulationBinding {
        fabric_domain_id: Uuid::from_u128(0x1300),
        realm_id: realm.id,
        provider_kind: FabricProviderKind::Vxlan,
        provider_segment_id: 101,
        binding_generation: 1,
    };
    let plan = directory.compile_fabric_plan(&local, &[local.clone(), remote], 1390, &binding)?;
    let mut provider = LinuxFabricBackend::open(LinuxFabricConfig::for_root(&root))?;
    provider.apply(&plan)?;
    if !provider.observe(&plan)? {
        return Err("provider did not observe its applied state".into());
    }
    let geneve = Command::new("ip")
        .args([
            "netns",
            "exec",
            "o3k-fabric",
            "ip",
            "-d",
            "link",
            "show",
            "type",
            "geneve",
        ])
        .output()?;
    let geneve_output = String::from_utf8_lossy(&geneve.stdout);
    if !geneve.status.success()
        || !geneve_output.contains("geneve")
        || !geneve_output.contains("id 101")
        || !geneve_output.contains("remote 198.18.0.2")
    {
        return Err("provider did not realize the expected Geneve object".into());
    }
    let transport = Command::new("ip")
        .args([
            "netns",
            "exec",
            "o3k-fabric",
            "ip",
            "-4",
            "addr",
            "show",
            "dev",
            "wg-o3k",
        ])
        .output()?;
    if !transport.status.success()
        || !String::from_utf8_lossy(&transport.stdout).contains("198.18.0.1/32")
    {
        return Err("provider did not assign the local fabric transport address".into());
    }
    let attachments = Command::new("ip")
        .args([
            "netns",
            "exec",
            "o3k-fabric",
            "ip",
            "-d",
            "link",
            "show",
            "type",
            "bridge",
        ])
        .output()?;
    if !attachments.status.success()
        || !String::from_utf8_lossy(&attachments.stdout).contains("o3k-c-")
    {
        return Err("provider did not realize the isolated Geneve attachment bridge".into());
    }
    let realm_attachment = Command::new("ip")
        .args(["netns", "exec", "o3k-r-00000000", "ip", "link", "show"])
        .output()?;
    if !realm_attachment.status.success()
        || !String::from_utf8_lossy(&realm_attachment.stdout).contains("o3k-e-")
    {
        return Err("provider did not realize the realm-side Geneve attachment".into());
    }
    let local_tap = Command::new("ip")
        .args(["-d", "link", "show", "type", "tun"])
        .output()?;
    if !local_tap.status.success() || !String::from_utf8_lossy(&local_tap.stdout).contains("o3k-t-")
    {
        return Err("provider did not realize the local endpoint TAP".into());
    }
    let gateway = Command::new("ip")
        .args([
            "netns",
            "exec",
            "o3k-r-00000000",
            "ip",
            "-4",
            "addr",
            "show",
            "dev",
            "o3k-n-00000000",
        ])
        .output()?;
    if !gateway.status.success()
        || !String::from_utf8_lossy(&gateway.stdout).contains("10.250.1.1/24")
    {
        return Err("provider did not realize the realm-local gateway".into());
    }
    println!("linux-fabric-smoke: host-transport-address=passed");
    println!("linux-fabric-smoke: geneve-realization=passed");
    println!("linux-fabric-smoke: isolated-attachment=passed");
    provider.remove(&plan)?;
    if !provider.observe_removed(&plan)? {
        return Err("provider did not observe cleanup".into());
    }
    fs::remove_dir_all(root)?;
    println!("linux-fabric-smoke: topology-and-cleanup=passed");
    Ok(())
}
