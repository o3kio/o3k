//! Disposable real-command smoke for realm-scoped P11 public NAT.
//!
//! The smoke creates only named network namespaces/veths and a temporary
//! provider root. It is local provider evidence, not the independent
//! multi-hypervisor gate.

use o3k_domain::{
    AddressRealm, EndpointLocation, FabricHostIdentity, FabricProviderKind, Ipv4Prefix,
    PublicAddressBindingIntent, RealmEncapsulationBinding, RealmEndpointDirectory,
};
use o3k_network::{FabricBackend, LinuxFabricBackend, LinuxFabricConfig};
use std::{env, fs, path::PathBuf, process::Command};
use uuid::Uuid;

const GUEST_NS: &str = "o3k-fabric-fip-guest";
const CLIENT_NS: &str = "o3k-fabric-fip-client";
const GUEST_ROOT: &str = "o3k-fip-g0";
const CLIENT_ROOT: &str = "o3k-fip-u";

fn run(program: &str, args: &[&str]) -> Result<(), Box<dyn std::error::Error>> {
    let status = Command::new(program).args(args).status()?;
    if !status.success() {
        return Err(format!("{program} {:?} failed", args).into());
    }
    Ok(())
}

fn ns(namespace: &str, args: &[&str]) -> Result<(), Box<dyn std::error::Error>> {
    let mut command = vec!["netns", "exec", namespace];
    command.extend_from_slice(args);
    run("ip", &command)
}

fn cleanup(root: &PathBuf) {
    let _ = Command::new("ip").args(["netns", "del", GUEST_NS]).output();
    let _ = Command::new("ip")
        .args(["netns", "del", CLIENT_NS])
        .output();
    let _ = Command::new("ip")
        .args(["link", "del", GUEST_ROOT])
        .output();
    let _ = Command::new("ip")
        .args(["link", "del", CLIENT_ROOT])
        .output();
    let _ = fs::remove_dir_all(root);
}

struct CleanupGuard(PathBuf);

impl Drop for CleanupGuard {
    fn drop(&mut self) {
        if env::var("O3K_FABRIC_FIP_KEEP").ok().as_deref() != Some("1") {
            cleanup(&self.0);
        }
    }
}

fn main() -> Result<(), Box<dyn std::error::Error>> {
    let uid = Command::new("id").args(["-u"]).output()?;
    if !uid.status.success() || String::from_utf8_lossy(&uid.stdout).trim() != "0" {
        return Err("root is required".into());
    }
    let root = env::var_os("O3K_FABRIC_FIP_ROOT")
        .map(PathBuf::from)
        .ok_or("O3K_FABRIC_FIP_ROOT must name a disposable provider root")?;
    let uplink = env::var("O3K_FABRIC_FIP_UPLINK").unwrap_or_else(|_| CLIENT_ROOT.to_owned());
    if root == std::path::Path::new("/") || root.as_os_str().is_empty() {
        return Err("refusing an unsafe smoke root".into());
    }
    let _cleanup_guard = CleanupGuard(root.clone());
    if Command::new("ip")
        .args(["netns", "list"])
        .output()?
        .stdout
        .windows(GUEST_NS.len())
        .any(|window| window == GUEST_NS.as_bytes())
    {
        return Err("foreign or stale guest namespace exists".into());
    }
    let realm = AddressRealm {
        id: Uuid::from_u128(0x5100),
        network_id: Uuid::from_u128(0x5101),
        project_id: "fabric-fip-smoke".to_owned(),
        prefix: Ipv4Prefix::new("10.250.2.0".parse()?, 24).ok_or("invalid prefix")?,
        overlapping_prefixes: false,
    };
    let endpoint_id = Uuid::from_u128(0x5201);
    let endpoint_mac = "02:00:00:00:02:11";
    let guest_mac = "02:00:00:00:aa:11";
    let directory = RealmEndpointDirectory::build(
        &realm,
        vec![EndpointLocation {
            endpoint_id,
            project_id: realm.project_id.clone(),
            realm_id: realm.id,
            fixed_ip: "10.250.2.11".parse()?,
            mac: endpoint_mac.to_owned(),
            selected_host: "fip-local".to_owned(),
            endpoint_generation: 1,
            placement_generation: 1,
        }],
        &[],
        1,
    )?;
    let local = FabricHostIdentity {
        host_id: "fip-local".to_owned(),
        public_key: "local-public-key".to_owned(),
        underlay_endpoint: "127.0.0.1:65001".to_owned(),
        fabric_transport_ip: "198.18.2.1".parse()?,
        provider_version: "wireguard-v1".to_owned(),
        fabric_generation: 1,
        underlay_mtu: 1500,
        fabric_mtu: 1440,
    };
    let binding = RealmEncapsulationBinding {
        fabric_domain_id: Uuid::from_u128(0x5300),
        realm_id: realm.id,
        provider_kind: FabricProviderKind::Vxlan,
        provider_segment_id: 201,
        binding_generation: 1,
    };
    let plan = directory
        .compile_fabric_plan(&local, std::slice::from_ref(&local), 1390, &binding)?
        .with_public_snapshot(vec![PublicAddressBindingIntent {
            id: Uuid::from_u128(0x5401),
            project_id: realm.project_id.clone(),
            public_address: "203.0.113.10".parse()?,
            endpoint_id,
            generation: 1,
        }])?;

    run("ip", &["netns", "add", GUEST_NS])?;
    run("ip", &["netns", "add", CLIENT_NS])?;
    run(
        "ip",
        &[
            "link", "add", GUEST_ROOT, "type", "veth", "peer", "name", "eth0", "netns", GUEST_NS,
        ],
    )?;
    run(
        "ip",
        &[
            "link",
            "add",
            CLIENT_ROOT,
            "type",
            "veth",
            "peer",
            "name",
            "eth0",
            "netns",
            CLIENT_NS,
        ],
    )?;
    run("ip", &["link", "set", GUEST_ROOT, "up"])?;
    run("ip", &["link", "set", CLIENT_ROOT, "up"])?;
    ns(GUEST_NS, &["ip", "link", "set", "lo", "up"])?;
    ns(
        GUEST_NS,
        &["ip", "link", "set", "eth0", "address", guest_mac],
    )?;
    ns(GUEST_NS, &["ip", "link", "set", "eth0", "up"])?;
    ns(
        GUEST_NS,
        &["ip", "addr", "add", "10.250.2.11/24", "dev", "eth0"],
    )?;
    ns(
        GUEST_NS,
        &["ip", "route", "replace", "default", "via", "10.250.2.1"],
    )?;
    ns(CLIENT_NS, &["ip", "link", "set", "lo", "up"])?;
    ns(CLIENT_NS, &["ip", "link", "set", "eth0", "up"])?;
    ns(
        CLIENT_NS,
        &["ip", "addr", "add", "203.0.113.2/24", "dev", "eth0"],
    )?;
    run(
        "ip",
        &["link", "set", CLIENT_ROOT, "address", "02:00:00:00:ee:01"],
    )?;
    ns(
        CLIENT_NS,
        &[
            "ip",
            "neigh",
            "replace",
            "203.0.113.10",
            "lladdr",
            "02:00:00:00:ee:01",
            "dev",
            "eth0",
        ],
    )?;
    run("ip", &["addr", "add", "203.0.113.1/24", "dev", CLIENT_ROOT])?;
    run("sysctl", &["-qw", "net.ipv4.ip_forward=1"])?;

    let mut provider = LinuxFabricBackend::open(
        LinuxFabricConfig::for_root(&root).with_public_uplink(uplink.clone()),
    )?;
    if let Err(error) = provider.apply(&plan) {
        let _ = provider.remove(&plan);
        return Err(error.into());
    }
    run(
        "ip",
        &["link", "set", GUEST_ROOT, "master", "o3k-b-00000000"],
    )?;
    let traffic = (|| -> Result<(), Box<dyn std::error::Error>> {
        run("ping", &["-c", "1", "-W", "2", "-n", "203.0.113.1"])?;
        ns(CLIENT_NS, &["ping", "-c", "3", "-W", "2", "203.0.113.10"])?;
        Ok(())
    })();
    if let Err(error) = traffic {
        let _ = provider.remove(&plan);
        return Err(error);
    }
    println!("linux-fabric-fip-smoke: realm-scoped-public-traffic=passed");
    provider.remove(&plan)?;
    if !provider.observe_removed(&plan)? {
        return Err("provider did not observe public cleanup".into());
    }
    if env::var("O3K_FABRIC_FIP_KEEP").ok().as_deref() != Some("1") {
        cleanup(&root);
    }
    println!("linux-fabric-fip-smoke: cleanup=passed");
    Ok(())
}
