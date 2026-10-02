//! Edge fabric multi-host gate fabric driver.
//!
//! Reads the O3K controller SQLite database to discover projects, realms,
//! subnets, ports and binding hosts, then compiles and dispatches fabric
//! plans directly to each host's `o3k-network` agent.
//!
//! Usage:
//! ```text
//! cargo run --example p11-multi-host-driver --all-features -- \
//!   --db /var/lib/o3k/controller/o3k.sqlite \
//!   --hosts host1=10.77.0.11,host2=10.77.0.12,host3=10.77.0.13 \
//!   --pki /opt/o3k/pki \
//!   --controller-id controller-1 --controller-epoch epoch-1 --fencing-token 1 \
//!   [--remove]
//! ```

use o3k_domain::{
    AddressRealm, EndpointLocation, FabricHostIdentity, FabricProviderKind, Ipv4Prefix,
    NamespacedRoutedFabricPlan, RealmEncapsulationBinding, RealmEncapsulationRegistry,
    RealmEndpointDirectory,
};
use o3k_network::NodeNetworkPlan;
use o3k_network_protocol::NetworkAgentClient;
use sqlx::{Row, sqlite::SqliteConnectOptions};
use std::{
    collections::{BTreeMap, HashMap},
    net::Ipv4Addr,
    path::{Path, PathBuf},
    str::FromStr,
};
use uuid::Uuid;

const FABRIC_STATE_DIR: &str = "/var/lib/o3k-fabric-lab/fabric-state";
const VNI_REGISTRY: &str = "vni-registry.json";
const AGENT_GRPC_PORT: u16 = 50_052;
const WG_PORT: u16 = 51_820;
const TENANT_MTU: u16 = 1_370;
const UNDERLAY_MTU: u16 = 1_500;
const FABRIC_MTU: u16 = 1_420;
const FABRIC_DOMAIN_ID: u128 = 0x0102030405060708090a0b0c0d0e0f10;

#[derive(Debug, thiserror::Error)]
enum DriverError {
    #[error("invalid CLI argument: {0}")]
    Argument(String),
    #[error("database error: {0}")]
    Database(#[from] sqlx::Error),
    #[error("I/O error: {0}")]
    Io(#[from] std::io::Error),
    #[error("JSON error: {0}")]
    Json(#[from] serde_json::Error),
    #[error("plan error: {0}")]
    Plan(String),
    #[error("transport error: {0}")]
    Transport(#[from] o3k_network_protocol::NetworkTransportError),
    #[error("agent command failed: {status} {error_code}")]
    Agent { status: String, error_code: String },
}

struct HostSpec {
    host_id: String,
    underlay_ip: Ipv4Addr,
    transport_ip: Ipv4Addr,
    public_key: String,
}

struct Config {
    db_path: PathBuf,
    hosts: Vec<HostSpec>,
    pki_dir: PathBuf,
    controller_id: String,
    controller_epoch: String,
    fencing_token: u64,
    remove: bool,
}

fn parse_args() -> Result<Config, DriverError> {
    let mut db_path = None;
    let mut hosts_arg = None;
    let mut pki_dir = None;
    let mut controller_id = None;
    let mut controller_epoch = None;
    let mut fencing_token = None;
    let mut remove = false;

    let mut args = std::env::args().skip(1);
    while let Some(arg) = args.next() {
        match arg.as_str() {
            "--db" => db_path = args.next().map(PathBuf::from),
            "--hosts" => hosts_arg = args.next(),
            "--pki" => pki_dir = args.next().map(PathBuf::from),
            "--controller-id" => controller_id = args.next(),
            "--controller-epoch" => controller_epoch = args.next(),
            "--fencing-token" => fencing_token = args.next().and_then(|v| v.parse().ok()),
            "--remove" => remove = true,
            other => return Err(DriverError::Argument(format!("unknown flag {other}"))),
        }
    }

    let db_path = db_path.ok_or_else(|| DriverError::Argument("--db required".to_owned()))?;
    let hosts_arg =
        hosts_arg.ok_or_else(|| DriverError::Argument("--hosts required".to_owned()))?;
    let pki_dir = pki_dir.ok_or_else(|| DriverError::Argument("--pki required".to_owned()))?;
    let controller_id = controller_id
        .ok_or_else(|| DriverError::Argument("--controller-id required".to_owned()))?;
    let controller_epoch = controller_epoch
        .ok_or_else(|| DriverError::Argument("--controller-epoch required".to_owned()))?;
    let fencing_token = fencing_token
        .ok_or_else(|| DriverError::Argument("--fencing-token required".to_owned()))?;

    let mut hosts = Vec::new();
    for pair in hosts_arg.split(',') {
        let (name, ip) = pair
            .split_once('=')
            .ok_or_else(|| DriverError::Argument(format!("host must be name=ip, got {pair}")))?;
        let underlay_ip = Ipv4Addr::from_str(ip)
            .map_err(|_| DriverError::Argument(format!("invalid host IP {ip}")))?;
        let transport_ip = fabric_transport_ip(name)?;
        let public_key = wireguard_public_key(name)?;
        hosts.push(HostSpec {
            host_id: name.to_owned(),
            underlay_ip,
            transport_ip,
            public_key,
        });
    }

    Ok(Config {
        db_path,
        hosts,
        pki_dir,
        controller_id,
        controller_epoch,
        fencing_token,
        remove,
    })
}

fn fabric_transport_ip(host_id: &str) -> Result<Ipv4Addr, DriverError> {
    let n = match host_id {
        "host1" => 1,
        "host2" => 2,
        "host3" => 3,
        other => return Err(DriverError::Argument(format!("unknown host {other}"))),
    };
    Ipv4Addr::from_str(&format!("198.18.0.{n}")).map_err(|_| {
        DriverError::Argument(format!("cannot build fabric transport IP for {host_id}"))
    })
}

fn wireguard_public_key(host_id: &str) -> Result<String, DriverError> {
    let key_path =
        Path::new("/var/lib/o3k-fabric-lab/fabric-state").join(format!("{host_id}.wg.pub"));
    std::fs::read_to_string(&key_path)
        .map(|s| s.trim().to_owned())
        .map_err(DriverError::Io)
}

#[derive(Debug, Clone)]
struct Realm {
    id: Uuid,
    project_id: String,
    name: String,
    prefix: Ipv4Prefix,
}

#[derive(Debug, Clone)]
struct Port {
    id: Uuid,
    network_id: Uuid,
    project_id: String,
    name: String,
    mac_address: String,
    fixed_ip: Ipv4Addr,
    binding_host: String,
}

async fn load_projects(pool: &sqlx::SqlitePool) -> Result<Vec<String>, DriverError> {
    let rows =
        sqlx::query("SELECT id FROM keystone_projects WHERE name IN ('project-a', 'project-b')")
            .fetch_all(pool)
            .await?;
    let mut projects = Vec::new();
    for row in rows {
        projects.push(row.try_get("id")?);
    }
    Ok(projects)
}

async fn load_realms(pool: &sqlx::SqlitePool) -> Result<Vec<Realm>, DriverError> {
    let rows = sqlx::query(
        "SELECT n.id, n.project_id, n.name, s.cidr \
         FROM network_networks n \
         JOIN network_subnets s ON s.network_id = n.id \
         WHERE n.name IN ('realm-a', 'realm-b')",
    )
    .fetch_all(pool)
    .await?;
    let mut realms = Vec::new();
    for row in rows {
        let id: String = row.try_get("id")?;
        let cidr: String = row.try_get("cidr")?;
        let prefix = parse_prefix(&cidr)?;
        realms.push(Realm {
            id: Uuid::parse_str(&id).map_err(|e| DriverError::Argument(e.to_string()))?,
            project_id: row.try_get("project_id")?,
            name: row.try_get("name")?,
            prefix,
        });
    }
    Ok(realms)
}

async fn load_ports(pool: &sqlx::SqlitePool) -> Result<Vec<Port>, DriverError> {
    let rows = sqlx::query(
        "SELECT id, network_id, project_id, name, mac_address, fixed_ip, binding_host \
         FROM network_ports \
         WHERE name IN ('A1','A2','B1','B2') AND binding_host IS NOT NULL",
    )
    .fetch_all(pool)
    .await?;
    let mut ports = Vec::new();
    for row in rows {
        let id: String = row.try_get("id")?;
        let network_id: String = row.try_get("network_id")?;
        let fixed_ip: String = row.try_get("fixed_ip")?;
        ports.push(Port {
            id: Uuid::parse_str(&id).map_err(|e| DriverError::Argument(e.to_string()))?,
            network_id: Uuid::parse_str(&network_id)
                .map_err(|e| DriverError::Argument(e.to_string()))?,
            project_id: row.try_get("project_id")?,
            name: row.try_get("name")?,
            mac_address: row.try_get("mac_address")?,
            fixed_ip: Ipv4Addr::from_str(&fixed_ip)
                .map_err(|e| DriverError::Argument(e.to_string()))?,
            binding_host: row.try_get("binding_host")?,
        });
    }
    Ok(ports)
}

fn parse_prefix(cidr: &str) -> Result<Ipv4Prefix, DriverError> {
    let (net, len) = cidr
        .split_once('/')
        .ok_or_else(|| DriverError::Argument(format!("invalid CIDR {cidr}")))?;
    let network = Ipv4Addr::from_str(net)
        .map_err(|_| DriverError::Argument(format!("invalid CIDR network {net}")))?;
    let prefix_len = len
        .parse()
        .map_err(|_| DriverError::Argument(format!("invalid CIDR length {len}")))?;
    Ipv4Prefix::new(network, prefix_len)
        .ok_or_else(|| DriverError::Argument(format!("invalid CIDR {cidr}")))
}

fn load_or_allocate_vnis(realms: &[Realm]) -> Result<BTreeMap<Uuid, u32>, DriverError> {
    let dir = Path::new(FABRIC_STATE_DIR);
    std::fs::create_dir_all(dir)?;
    let path = dir.join(VNI_REGISTRY);
    let mut registry: RealmEncapsulationRegistry = if path.exists() {
        serde_json::from_slice(&std::fs::read(&path)?)?
    } else {
        RealmEncapsulationRegistry::default()
    };

    let fabric_domain_id = Uuid::from_u128(FABRIC_DOMAIN_ID);
    let mut vnis = BTreeMap::new();
    for realm in realms {
        let binding = registry
            .ensure(fabric_domain_id, realm.id, 1)
            .map_err(|e| {
                DriverError::Plan(format!("VNI allocation failed for {}: {e}", realm.name))
            })?;
        vnis.insert(realm.id, binding.provider_segment_id);
    }
    std::fs::write(&path, serde_json::to_vec_pretty(&registry)?)?;
    Ok(vnis)
}

fn build_host_identities(hosts: &[HostSpec]) -> Vec<FabricHostIdentity> {
    hosts
        .iter()
        .map(|h| FabricHostIdentity {
            host_id: h.host_id.clone(),
            public_key: h.public_key.clone(),
            underlay_endpoint: format!("{}:{WG_PORT}", h.underlay_ip),
            fabric_transport_ip: h.transport_ip,
            provider_version: "wireguard-v1".to_owned(),
            fabric_generation: 1,
            underlay_mtu: UNDERLAY_MTU,
            fabric_mtu: FABRIC_MTU,
        })
        .collect()
}

fn compile_realm_plan(
    realm: &Realm,
    ports: &[Port],
    host_identities: &[FabricHostIdentity],
    vni: u32,
    local_host_id: &str,
) -> Result<NamespacedRoutedFabricPlan, DriverError> {
    let address_realm = AddressRealm {
        id: realm.id,
        network_id: Uuid::from_u128(0xfeed),
        project_id: realm.project_id.clone(),
        prefix: realm.prefix,
        overlapping_prefixes: true,
    };

    let locations: Vec<EndpointLocation> = ports
        .iter()
        .map(|p| EndpointLocation {
            endpoint_id: p.id,
            project_id: p.project_id.clone(),
            realm_id: realm.id,
            fixed_ip: p.fixed_ip,
            mac: p.mac_address.clone(),
            selected_host: p.binding_host.clone(),
            endpoint_generation: 1,
            placement_generation: 1,
        })
        .collect();

    let directory =
        RealmEndpointDirectory::build(&address_realm, locations, &[], 1).map_err(|e| {
            DriverError::Plan(format!("directory build failed for {}: {e}", realm.name))
        })?;

    let local = host_identities
        .iter()
        .find(|h| h.host_id == local_host_id)
        .ok_or_else(|| DriverError::Plan(format!("missing local host {local_host_id}")))?
        .clone();

    let binding = RealmEncapsulationBinding {
        fabric_domain_id: Uuid::from_u128(FABRIC_DOMAIN_ID),
        realm_id: realm.id,
        provider_kind: FabricProviderKind::Vxlan,
        provider_segment_id: vni,
        binding_generation: 1,
    };

    directory
        .compile_fabric_plan(&local, host_identities, TENANT_MTU, &binding)
        .map_err(|e| DriverError::Plan(format!("compile failed for {}: {e}", realm.name)))
}

#[derive(Debug, serde::Serialize)]
struct EndpointManifestEntry {
    name: String,
    endpoint_id: String,
    realm_id: String,
    host: String,
    bridge: String,
    tap: String,
    fixed_ip: String,
    mac: String,
}

fn bridge_name(realm_id: Uuid) -> String {
    let suffix = realm_id.simple().to_string();
    format!("o3k-b-{}", &suffix[..8])
}

fn tap_name(realm_id: Uuid, endpoint_id: Uuid) -> String {
    let bytes = realm_id
        .as_bytes()
        .iter()
        .copied()
        .chain(endpoint_id.as_bytes().iter().copied())
        .fold(0xcbf29ce484222325u64, |hash, byte| {
            (hash ^ u64::from(byte)).wrapping_mul(0x100000001b3)
        })
        .to_be_bytes();
    format!(
        "o3k-t-{:02x}{:02x}{:02x}{:02x}",
        bytes[4], bytes[5], bytes[6], bytes[7]
    )
}

fn write_endpoint_manifest(ports: &[Port], realms: &[Realm]) -> Result<(), DriverError> {
    let mut entries = Vec::new();
    for port in ports {
        let realm = realms
            .iter()
            .find(|r| r.id == port.network_id)
            .ok_or_else(|| DriverError::Plan(format!("realm missing for port {}", port.id)))?;
        entries.push(EndpointManifestEntry {
            name: port.name.clone(),
            endpoint_id: port.id.to_string(),
            realm_id: realm.id.to_string(),
            host: port.binding_host.clone(),
            bridge: bridge_name(realm.id),
            tap: tap_name(realm.id, port.id),
            fixed_ip: port.fixed_ip.to_string(),
            mac: port.mac_address.clone(),
        });
    }
    let dir = Path::new(FABRIC_STATE_DIR);
    std::fs::create_dir_all(dir)?;
    let path = dir.join("fabric-endpoint-manifest.json");
    std::fs::write(&path, serde_json::to_vec_pretty(&entries)?)?;
    println!("wrote endpoint manifest to {}", path.display());
    Ok(())
}

fn build_node_plan(fabric: NamespacedRoutedFabricPlan) -> Result<NodeNetworkPlan, DriverError> {
    let mut plan = NodeNetworkPlan {
        schema_version: 1,
        plan_id: fabric.realm_id,
        node_id: fabric.local_host.clone(),
        operation_id: Uuid::new_v5(
            &Uuid::NAMESPACE_URL,
            format!(
                "o3k:fabric:multi-host:{}:{}",
                fabric.realm_id, fabric.local_host
            )
            .as_bytes(),
        ),
        deadline_unix_ms: (std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .map_err(|_| DriverError::Plan("system clock before epoch".to_owned()))?
            .as_millis() as u64)
            + 600_000,
        resource_generations: BTreeMap::new(),
        intents: Vec::new(),
        fabric: None,
        gateway: None,
        fingerprint_sha256: String::new(),
    };
    plan = plan
        .with_fabric(fabric)
        .map_err(|e| DriverError::Plan(format!("invalid fabric plan: {e}")))?;
    Ok(plan)
}

fn network_agent_server_name(host_id: &str) -> Result<String, DriverError> {
    Ok(format!("{}.{}", host_id, "fabric.o3k.local"))
}

async fn dispatch_plan(
    config: &Config,
    host: &HostSpec,
    plan: NodeNetworkPlan,
) -> Result<(), DriverError> {
    let endpoint = format!("https://{}:{}", host.underlay_ip, AGENT_GRPC_PORT);
    let server_name = network_agent_server_name(&host.host_id)?;
    let ca = config.pki_dir.join("ca.crt");
    let client_cert = config.pki_dir.join(format!("{}-client.crt", host.host_id));
    let client_key = config.pki_dir.join(format!("{}-client.key", host.host_id));

    let client =
        NetworkAgentClient::connect(&endpoint, &server_name, &ca, &client_cert, &client_key)
            .await?;

    let command_id = Uuid::new_v5(
        &Uuid::NAMESPACE_URL,
        format!(
            "o3k:fabric:command:{}:{}:{}",
            plan.plan_id, plan.node_id, config.remove
        )
        .as_bytes(),
    );

    let result = client
        .execute(
            o3k_network_protocol::proto::Register {
                agent_id: host.host_id.clone(),
                agent_epoch: "epoch-1".to_owned(),
            },
            o3k_network_protocol::proto::NetworkCommand {
                command_id: command_id.to_string(),
                operation_id: plan.operation_id.to_string(),
                idempotency_key: format!("o3k:fabric:multi-host:{}:{}", plan.plan_id, plan.node_id),
                agent_id: host.host_id.clone(),
                agent_epoch: "epoch-1".to_owned(),
                controller_id: config.controller_id.clone(),
                controller_epoch: config.controller_epoch.clone(),
                fencing_token: config.fencing_token,
                deadline_unix_ms: plan.deadline_unix_ms,
                plan_json: serde_json::to_string(&plan)?,
                remove: config.remove,
            },
        )
        .await?;

    if result.status != "succeeded" && result.status != "replayed" && result.status != "recovered" {
        return Err(DriverError::Agent {
            status: result.status,
            error_code: result.error_code,
        });
    }
    Ok(())
}

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    let config = parse_args()?;

    let options = SqliteConnectOptions::new()
        .filename(&config.db_path)
        .read_only(true);
    let pool = sqlx::SqlitePool::connect_with(options).await?;

    let projects = load_projects(&pool).await?;
    if projects.len() != 2 {
        Err(DriverError::Plan(format!(
            "expected 2 projects, found {}",
            projects.len()
        )))?;
    }
    println!("discovered {} projects", projects.len());

    let realms = load_realms(&pool).await?;
    if realms.len() != 2 {
        Err(DriverError::Plan(format!(
            "expected 2 realms, found {}",
            realms.len()
        )))?;
    }

    let ports = load_ports(&pool).await?;
    if ports.len() != 4 {
        Err(DriverError::Plan(format!(
            "expected 4 ports, found {}",
            ports.len()
        )))?;
    }

    write_endpoint_manifest(&ports, &realms)?;
    let vnis = load_or_allocate_vnis(&realms)?;
    let host_identities = build_host_identities(&config.hosts);

    let mut plans_by_host: HashMap<String, Vec<NodeNetworkPlan>> = HashMap::new();
    for realm in &realms {
        let realm_ports: Vec<Port> = ports
            .iter()
            .filter(|p| p.network_id == realm.id)
            .cloned()
            .collect();
        let vni = *vnis
            .get(&realm.id)
            .ok_or_else(|| DriverError::Plan(format!("missing VNI for realm {}", realm.name)))?;

        for host in &config.hosts {
            if !realm_ports.iter().any(|p| p.binding_host == host.host_id) {
                continue;
            }
            let fabric =
                compile_realm_plan(realm, &realm_ports, &host_identities, vni, &host.host_id)?;
            let plan = build_node_plan(fabric)?;
            plans_by_host
                .entry(host.host_id.clone())
                .or_default()
                .push(plan);
        }
    }

    let mut errors = Vec::new();
    for host in &config.hosts {
        let plans = plans_by_host.remove(&host.host_id).unwrap_or_default();
        for plan in plans {
            if let Err(error) = dispatch_plan(&config, host, plan).await {
                errors.push(format!("{}: {}", host.host_id, error));
            }
        }
    }

    if !errors.is_empty() {
        Err(DriverError::Plan(errors.join("; ")))?;
    }

    println!(
        "p11-multi-host-driver: dispatch-complete={}",
        !config.remove
    );
    Ok(())
}
