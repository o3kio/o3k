use super::helpers::deterministic_port_mac;
use super::{NetworkError, map_store_error};
use crate::{NetworkRecord, PortRecord, SubnetRecord};
use std::{collections::HashSet, fs, net::Ipv4Addr, path::Path};
use uuid::Uuid;

/// The legacy `metadata.json` shape written by previous versions. It is
/// parsed once, imported into the durable store, and the file is renamed so
/// it is never read again.
#[derive(serde::Deserialize)]
struct LegacyFile {
    networks: Vec<LegacyNetwork>,
    subnets: Vec<LegacySubnet>,
    ports: Vec<LegacyPort>,
}

#[derive(serde::Deserialize)]
struct LegacyNetwork {
    id: Uuid,
    name: String,
    project_id: String,
    status: String,
}

#[derive(serde::Deserialize)]
struct LegacySubnet {
    id: Uuid,
    network_id: Uuid,
    name: String,
    project_id: String,
    cidr: String,
    gateway_ip: Ipv4Addr,
    allocation_start: Ipv4Addr,
    allocation_end: Ipv4Addr,
}

#[derive(serde::Deserialize)]
struct LegacyPort {
    id: Uuid,
    network_id: Uuid,
    #[serde(default)]
    subnet_id: Uuid,
    project_id: String,
    name: String,
    #[serde(default)]
    mac_address: String,
    fixed_ip: Ipv4Addr,
    status: String,
}

/// Imports the legacy `metadata.json` file exactly once, in dependency order
/// (networks, then subnets, then ports), and renames it so `open` never reads
/// it again. The rename is best-effort: when it fails, the next `open`
/// re-reads the file, but the import is idempotent (records already present
/// are skipped), so the file can never double-import. Inserts skip records
/// that are already present, which makes a partially completed previous
/// import crash-resume safe. A corrupt file, duplicate MACs, or any
/// non-already-exists insert error fails the import closed and leaves the
/// file in place.
pub(super) async fn import_legacy_metadata(
    root: &Path,
    repository: &dyn o3k_store::NetworkRepository,
) -> Result<(), NetworkError> {
    let path = root.join("metadata.json");
    let file = fs::File::open(&path)
        .map_err(|error| NetworkError::CorruptMetadata(serde_json::Error::io(error)))?;
    let mut legacy: LegacyFile =
        serde_json::from_reader(file).map_err(NetworkError::CorruptMetadata)?;
    let mut macs = HashSet::new();
    for port in &mut legacy.ports {
        if port.mac_address.is_empty() {
            port.mac_address = deterministic_port_mac(port.id);
        }
        if port.subnet_id.is_nil()
            && let Some(subnet) = legacy.subnets.iter().find(|subnet| {
                subnet.network_id == port.network_id && subnet.project_id == port.project_id
            })
        {
            port.subnet_id = subnet.id;
        }
        if !macs.insert(port.mac_address.to_ascii_lowercase()) {
            return Err(NetworkError::Conflict);
        }
    }
    for network in &legacy.networks {
        let record = NetworkRecord {
            id: network.id,
            name: network.name.clone(),
            project_id: network.project_id.clone(),
            status: network.status.clone(),
        };
        match repository.insert_network(&record).await {
            Ok(()) | Err(o3k_store::StoreError::ResourceAlreadyExists) => {}
            Err(error) => return Err(map_store_error(error)),
        }
    }
    for subnet in &legacy.subnets {
        let record = SubnetRecord {
            id: subnet.id,
            network_id: subnet.network_id,
            name: subnet.name.clone(),
            project_id: subnet.project_id.clone(),
            cidr: subnet.cidr.clone(),
            gateway_ip: subnet.gateway_ip,
            allocation_start: subnet.allocation_start,
            allocation_end: subnet.allocation_end,
            ip_version: 4,
            enable_dhcp: true,
        };
        match repository.insert_subnet(&record).await {
            Ok(()) | Err(o3k_store::StoreError::ResourceAlreadyExists) => {}
            Err(error) => return Err(map_store_error(error)),
        }
    }
    for port in &legacy.ports {
        let record = PortRecord {
            id: port.id,
            network_id: port.network_id,
            subnet_id: (!port.subnet_id.is_nil()).then_some(port.subnet_id),
            project_id: port.project_id.clone(),
            name: port.name.clone(),
            mac_address: port.mac_address.clone(),
            fixed_ip: port.fixed_ip,
            status: port.status.clone(),
            binding_host: None,
            binding_state: None,
            binding_generation: 0,
        };
        match repository.insert_port(&record).await {
            Ok(()) | Err(o3k_store::StoreError::ResourceAlreadyExists) => {}
            Err(error) => return Err(map_store_error(error)),
        }
    }
    let _ = fs::rename(&path, root.join("metadata.json.imported"));
    Ok(())
}
