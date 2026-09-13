use base64::{Engine as _, engine::general_purpose::STANDARD as BASE64};
use md5::{Digest as Md5Digest, Md5};
use sqlx::{Row, sqlite::SqliteRow};
use std::net::Ipv4Addr;
use uuid::Uuid;

use crate::{
    AgentCommandRecord, AgentCommandState, CanonicalAddressPoolRecord, CanonicalAddressRealmRecord,
    CanonicalEndpointRecord, CanonicalNetworkPolicyRecord, CanonicalNetworkRecord,
    ImageMetadataRecord, ImageOverlayIdentity, ImageOverlayOwnershipRecord, ImageOverlayState,
    KeypairRecord, NetworkAddressAllocationRecord, NetworkIntentRecord, NetworkRecord,
    OperationRecord, OperationState, PlacementAllocationRecord, PlacementIntentRecord,
    PlacementInventoryRecord, PlacementProviderRecord, PlacementResourceRecord, PortRecord,
    ResourceRecord, SecurityGroupBindingRecord, SecurityGroupRecord, SecurityGroupRuleRecord,
    StoreError, SubnetRecord,
};

pub(super) fn keypair_from_row(row: &sqlx::sqlite::SqliteRow) -> Result<KeypairRecord, StoreError> {
    Ok(KeypairRecord {
        id: parse_uuid(row.get("id"))?,
        user_id: row.get("user_id"),
        project_id: row.get("project_id"),
        name: row.get("name"),
        key_type: row.get("key_type"),
        public_key: row.get("public_key"),
        fingerprint: row.get("fingerprint"),
        created_at: row.get("created_at"),
    })
}

pub(super) fn image_metadata_from_row(
    row: &sqlx::sqlite::SqliteRow,
) -> Result<ImageMetadataRecord, StoreError> {
    Ok(ImageMetadataRecord {
        id: parse_uuid(row.get("id"))?,
        name: row.get("name"),
        project_id: row.get("project_id"),
        status: row.get("status"),
        visibility: row.get("visibility"),
        container_format: row.get("container_format"),
        disk_format: row.get("disk_format"),
        size: row.get("size"),
        checksum: row.get("checksum"),
    })
}

pub(super) fn network_from_row(row: &sqlx::sqlite::SqliteRow) -> Result<NetworkRecord, StoreError> {
    Ok(NetworkRecord {
        id: parse_uuid(row.get("id"))?,
        name: row.get("name"),
        project_id: row.get("project_id"),
        status: row.get("status"),
    })
}

pub(crate) fn validate_canonical_state(state: &str) -> Result<(), StoreError> {
    if matches!(
        state,
        "requested" | "active" | "deleting" | "deleted" | "error"
    ) {
        Ok(())
    } else {
        Err(StoreError::Corrupt(format!(
            "invalid canonical network state `{state}`"
        )))
    }
}

pub(crate) fn validate_ipv4_cidr(value: &str) -> Result<(), StoreError> {
    let (address, prefix) = value
        .split_once('/')
        .ok_or_else(|| StoreError::Corrupt("invalid canonical IPv4 prefix".to_owned()))?;
    let address: Ipv4Addr = address
        .parse()
        .map_err(|_| StoreError::Corrupt("invalid canonical IPv4 prefix".to_owned()))?;
    let prefix: u8 = prefix
        .parse()
        .map_err(|_| StoreError::Corrupt("invalid canonical IPv4 prefix".to_owned()))?;
    if prefix > 32 {
        return Err(StoreError::Corrupt(
            "invalid canonical IPv4 prefix length".to_owned(),
        ));
    }
    let mask = if prefix == 0 {
        0
    } else {
        u32::MAX << (32 - prefix)
    };
    if u32::from(address) & mask != u32::from(address) {
        return Err(StoreError::Corrupt("non-canonical IPv4 prefix".to_owned()));
    }
    Ok(())
}

pub(crate) fn checked_generation(generation: u64) -> Result<i64, StoreError> {
    i64::try_from(generation)
        .ok()
        .filter(|value| *value > 0)
        .ok_or_else(|| StoreError::Corrupt("invalid canonical generation".to_owned()))
}

pub(crate) fn map_canonical_insert_error(error: sqlx::Error) -> StoreError {
    if matches!(&error, sqlx::Error::Database(database) if database.is_unique_violation()) {
        StoreError::ResourceAlreadyExists
    } else {
        StoreError::Database(error)
    }
}

pub(super) fn canonical_network_from_row(
    row: &sqlx::sqlite::SqliteRow,
) -> Result<CanonicalNetworkRecord, StoreError> {
    let generation: i64 = row.get("generation");
    Ok(CanonicalNetworkRecord {
        id: parse_uuid(row.get("id"))?,
        project_id: row.get("project_id"),
        name: row.get("name"),
        admin_state_up: row.get("admin_state_up"),
        generation: u64::try_from(generation)
            .map_err(|_| StoreError::Corrupt("negative canonical generation".to_owned()))?,
        state: row.get("state"),
    })
}

pub(super) fn canonical_realm_from_row(
    row: &sqlx::sqlite::SqliteRow,
) -> Result<CanonicalAddressRealmRecord, StoreError> {
    let generation: i64 = row.get("generation");
    let overlapping: i64 = row.get("overlapping_prefixes");
    Ok(CanonicalAddressRealmRecord {
        id: parse_uuid(row.get("id"))?,
        network_id: parse_uuid(row.get("network_id"))?,
        project_id: row.get("project_id"),
        prefix: row.get("prefix"),
        overlapping_prefixes: overlapping != 0,
        generation: u64::try_from(generation)
            .map_err(|_| StoreError::Corrupt("negative canonical generation".to_owned()))?,
        state: row.get("state"),
    })
}

pub(super) fn canonical_pool_from_row(
    row: &sqlx::sqlite::SqliteRow,
) -> Result<CanonicalAddressPoolRecord, StoreError> {
    let generation: i64 = row.get("generation");
    Ok(CanonicalAddressPoolRecord {
        id: parse_uuid(row.get("id"))?,
        realm_id: parse_uuid(row.get("realm_id"))?,
        project_id: row.get("project_id"),
        prefix: row.get("prefix"),
        gateway: row
            .get::<Option<String>, _>("gateway")
            .map(|value| value.parse())
            .transpose()
            .map_err(|_| StoreError::Corrupt("invalid canonical gateway".to_owned()))?,
        first_usable: row
            .get::<String, _>("first_usable")
            .parse()
            .map_err(|_| StoreError::Corrupt("invalid canonical pool start".to_owned()))?,
        last_usable: row
            .get::<String, _>("last_usable")
            .parse()
            .map_err(|_| StoreError::Corrupt("invalid canonical pool end".to_owned()))?,
        generation: u64::try_from(generation)
            .map_err(|_| StoreError::Corrupt("negative canonical generation".to_owned()))?,
        state: row.get("state"),
    })
}

pub(super) fn canonical_endpoint_from_row(
    row: &sqlx::sqlite::SqliteRow,
) -> Result<CanonicalEndpointRecord, StoreError> {
    let generation: i64 = row.get("generation");
    Ok(CanonicalEndpointRecord {
        id: parse_uuid(row.get("id"))?,
        realm_id: parse_uuid(row.get("realm_id"))?,
        project_id: row.get("project_id"),
        fixed_ip: row
            .get::<String, _>("fixed_ip")
            .parse()
            .map_err(|_| StoreError::Corrupt("invalid canonical endpoint IP".to_owned()))?,
        mac: row.get("mac"),
        generation: u64::try_from(generation)
            .map_err(|_| StoreError::Corrupt("negative canonical generation".to_owned()))?,
        state: row.get("state"),
    })
}

pub(super) fn canonical_policy_from_row(
    row: &sqlx::sqlite::SqliteRow,
) -> Result<CanonicalNetworkPolicyRecord, StoreError> {
    Ok(CanonicalNetworkPolicyRecord {
        id: parse_uuid(row.get("id"))?,
        project_id: row.get("project_id"),
        endpoint_id: parse_uuid(row.get("endpoint_id"))?,
        direction: row.get("direction"),
        protocol: row.get("protocol"),
        port_min: row
            .get::<Option<i64>, _>("port_min")
            .map(parse_port_min)
            .transpose()?,
        port_max: row
            .get::<Option<i64>, _>("port_max")
            .map(parse_port_min)
            .transpose()?,
        source: row.get("source"),
        destination: row.get("destination"),
        action: row.get("action"),
        generation: u64::try_from(row.get::<i64, _>("generation"))
            .map_err(|_| StoreError::Corrupt("invalid policy generation".into()))?,
        state: row.get("state"),
    })
}

pub(super) fn parse_port_min(value: i64) -> Result<u16, StoreError> {
    u16::try_from(value).map_err(|_| StoreError::Corrupt("invalid policy port".into()))
}

pub(super) fn validate_network_intent(intent: &NetworkIntentRecord) -> Result<(), StoreError> {
    if intent.project_id.is_empty() {
        return Err(StoreError::Corrupt(
            "network intent has empty project".to_owned(),
        ));
    }
    validate_network_intent_update(&intent.project_id, &intent.payload, &intent.status)?;
    if intent.generation == 0 {
        return Err(StoreError::Corrupt(
            "network intent generation must be positive".to_owned(),
        ));
    }
    Ok(())
}

pub(crate) fn validate_network_intent_update(
    project_id: &str,
    payload: &str,
    status: &str,
) -> Result<(), StoreError> {
    if project_id.is_empty() || payload.is_empty() {
        return Err(StoreError::Corrupt(
            "network intent has empty required field".to_owned(),
        ));
    }
    if !matches!(status, "requested" | "active" | "deleting" | "error") {
        return Err(StoreError::Corrupt(
            "network intent has invalid lifecycle status".to_owned(),
        ));
    }
    Ok(())
}

pub(crate) fn validate_network_intent_transition(
    current: &str,
    next: &str,
) -> Result<(), StoreError> {
    let valid = current == next
        || matches!(
            (current, next),
            ("requested", "active" | "deleting" | "error")
                | ("active", "deleting" | "error")
                | ("deleting", "error")
        );
    if valid {
        Ok(())
    } else {
        Err(StoreError::Corrupt(
            "network intent lifecycle transition is invalid".to_owned(),
        ))
    }
}

pub(super) fn parse_ipv4_prefix(value: &str) -> Result<(u32, u8), StoreError> {
    let (address, length) = value
        .split_once('/')
        .ok_or_else(|| StoreError::Corrupt("network prefix is missing length".to_owned()))?;
    let address = address
        .parse::<Ipv4Addr>()
        .map_err(|_| StoreError::Corrupt("network prefix has invalid address".to_owned()))?;
    let prefix_len = length
        .parse::<u8>()
        .map_err(|_| StoreError::Corrupt("network prefix has invalid length".to_owned()))?;
    if !(1..=30).contains(&prefix_len) {
        return Err(StoreError::Corrupt(
            "network allocation prefix must leave usable addresses".to_owned(),
        ));
    }
    let mask = u32::MAX << (32 - prefix_len);
    let network = u32::from(address) & mask;
    if network != u32::from(address) {
        return Err(StoreError::Corrupt(
            "network prefix is not canonical".to_owned(),
        ));
    }
    Ok((network, prefix_len))
}

pub(super) fn allocation_bounds(network: u32, prefix_len: u8) -> (u32, u32) {
    let size = 1u32 << (32 - prefix_len);
    (network + 1, network + size - 2)
}

pub(super) fn network_allocation_from_row(
    row: &sqlx::sqlite::SqliteRow,
) -> Result<NetworkAddressAllocationRecord, StoreError> {
    Ok(NetworkAddressAllocationRecord {
        realm_id: Uuid::parse_str(row.get::<&str, _>("realm_id"))
            .map_err(StoreError::InvalidUuid)?,
        project_id: row.get("project_id"),
        endpoint_id: Uuid::parse_str(row.get::<&str, _>("endpoint_id"))
            .map_err(StoreError::InvalidUuid)?,
        operation_id: row.get("operation_id"),
        address: row
            .get::<String, _>("address")
            .parse()
            .map_err(|_| StoreError::Corrupt("invalid allocated network address".to_owned()))?,
    })
}

pub(super) fn network_intent_from_row(
    row: &sqlx::sqlite::SqliteRow,
) -> Result<NetworkIntentRecord, StoreError> {
    let generation: i64 = row.get("generation");
    Ok(NetworkIntentRecord {
        id: Uuid::parse_str(row.get::<&str, _>("id")).map_err(StoreError::InvalidUuid)?,
        project_id: row.get("project_id"),
        generation: u64::try_from(generation)
            .map_err(|_| StoreError::Corrupt("negative network intent generation".to_owned()))?,
        payload: row.get("payload"),
        plan_fingerprint_sha256: row.get("plan_fingerprint_sha256"),
        status: row.get("status"),
    })
}

pub(super) fn subnet_from_row(row: &sqlx::sqlite::SqliteRow) -> Result<SubnetRecord, StoreError> {
    Ok(SubnetRecord {
        id: parse_uuid(row.get("id"))?,
        network_id: parse_uuid(row.get("network_id"))?,
        name: row.get("name"),
        project_id: row.get("project_id"),
        cidr: row.get("cidr"),
        gateway_ip: row
            .get::<String, _>("gateway_ip")
            .parse()
            .map_err(|_| StoreError::Corrupt("invalid IPv4 address in durable state".to_owned()))?,
        allocation_start: row
            .get::<String, _>("allocation_start")
            .parse()
            .map_err(|_| StoreError::Corrupt("invalid IPv4 address in durable state".to_owned()))?,
        allocation_end: row
            .get::<String, _>("allocation_end")
            .parse()
            .map_err(|_| StoreError::Corrupt("invalid IPv4 address in durable state".to_owned()))?,
        ip_version: u8::try_from(row.get::<i64, _>("ip_version"))
            .map_err(|_| StoreError::Corrupt("invalid subnet IP version".to_owned()))?,
        enable_dhcp: row.get("enable_dhcp"),
    })
}

pub(super) fn security_group_from_row(
    row: &sqlx::sqlite::SqliteRow,
) -> Result<SecurityGroupRecord, StoreError> {
    Ok(SecurityGroupRecord {
        id: parse_uuid(row.get("id"))?,
        project_id: row.get("project_id"),
        name: row.get("name"),
        description: row.get("description"),
    })
}

pub(super) fn security_group_rule_from_row(
    row: &sqlx::sqlite::SqliteRow,
) -> Result<SecurityGroupRuleRecord, StoreError> {
    let port_min = row
        .try_get::<Option<i64>, _>("port_min")
        .map_err(StoreError::Database)?
        .map(u16::try_from)
        .transpose()
        .map_err(|_| StoreError::Corrupt("security-group port is out of range".to_owned()))?;
    let port_max = row
        .try_get::<Option<i64>, _>("port_max")
        .map_err(StoreError::Database)?
        .map(u16::try_from)
        .transpose()
        .map_err(|_| StoreError::Corrupt("security-group port is out of range".to_owned()))?;
    Ok(SecurityGroupRuleRecord {
        id: parse_uuid(row.get("id"))?,
        security_group_id: parse_uuid(row.get("security_group_id"))?,
        project_id: row.get("project_id"),
        direction: row.get("direction"),
        protocol: row.get("protocol"),
        port_min,
        port_max,
        remote_ip_prefix: row.get("remote_ip_prefix"),
    })
}

pub(super) fn security_group_binding_from_row(
    row: &sqlx::sqlite::SqliteRow,
) -> Result<SecurityGroupBindingRecord, StoreError> {
    Ok(SecurityGroupBindingRecord {
        project_id: row.get("project_id"),
        endpoint_id: parse_uuid(row.get("endpoint_id"))?,
        security_group_id: parse_uuid(row.get("security_group_id"))?,
    })
}

pub(super) fn port_from_row(row: &sqlx::sqlite::SqliteRow) -> Result<PortRecord, StoreError> {
    Ok(PortRecord {
        id: parse_uuid(row.get("id"))?,
        network_id: parse_uuid(row.get("network_id"))?,
        subnet_id: row
            .get::<Option<String>, _>("subnet_id")
            .map(parse_uuid)
            .transpose()?,
        project_id: row.get("project_id"),
        name: row.get("name"),
        mac_address: row.get("mac_address"),
        fixed_ip: row
            .get::<String, _>("fixed_ip")
            .parse()
            .map_err(|_| StoreError::Corrupt("invalid IPv4 address in durable state".to_owned()))?,
        status: row.get("status"),
        binding_host: row.get("binding_host"),
        binding_state: row.get("binding_state"),
    })
}

pub(super) fn placement_i64(value: u64) -> Result<i64, StoreError> {
    i64::try_from(value)
        .map_err(|_| StoreError::Corrupt("placement value exceeds SQLite range".to_owned()))
}

pub(super) fn placement_u64(value: i64) -> Result<u64, StoreError> {
    u64::try_from(value)
        .map_err(|_| StoreError::Corrupt("negative placement value in durable state".to_owned()))
}

pub(super) fn placement_provider_from_row(
    row: &SqliteRow,
) -> Result<PlacementProviderRecord, StoreError> {
    Ok(PlacementProviderRecord {
        id: row.get("id"),
        node_id: row.get("node_id"),
        state: row.get("state"),
        generation: placement_u64(row.get("generation"))?,
        inventories: Vec::new(),
        allocations: Vec::new(),
        parent_provider_id: row.get("parent_provider_id"),
        traits: Vec::new(),
        failure_domains: Vec::new(),
        location: row.get("location"),
    })
}

pub(super) fn placement_inventory_from_row(
    row: &SqliteRow,
) -> Result<PlacementInventoryRecord, StoreError> {
    Ok(PlacementInventoryRecord {
        resource_class: row.get("resource_class"),
        total: placement_u64(row.get("total"))?,
        reserved: placement_u64(row.get("reserved"))?,
        allocation_ratio: row.get("allocation_ratio"),
        used: placement_u64(row.get("used"))?,
    })
}

pub(super) fn placement_allocation_from_row(
    row: &SqliteRow,
) -> Result<PlacementAllocationRecord, StoreError> {
    Ok(PlacementAllocationRecord {
        id: row.get("id"),
        provider_id: row.get("provider_id"),
        consumer_id: row.get("consumer_id"),
        resources: Vec::new(),
    })
}

pub(super) fn placement_resource_from_row(
    row: &SqliteRow,
) -> Result<PlacementResourceRecord, StoreError> {
    Ok(PlacementResourceRecord {
        resource_class: row.get("resource_class"),
        amount: placement_u64(row.get("amount"))?,
    })
}

pub(super) fn placement_intent_from_row(
    row: &SqliteRow,
) -> Result<PlacementIntentRecord, StoreError> {
    Ok(PlacementIntentRecord {
        id: row.get("id"),
        provider_id: row.get("provider_id"),
        consumer_id: row.get("consumer_id"),
        resources: Vec::new(),
    })
}

/// Validate the public OpenSSH key form accepted by the TestLab profile.
/// This deliberately imports public material only; private-key generation is not supported.
pub fn validate_public_key(value: &str) -> Result<(String, String, String), StoreError> {
    let value = value.trim();
    if value.chars().any(char::is_control) {
        return Err(StoreError::InvalidKeypair(
            "public key contains control characters".to_owned(),
        ));
    }
    let mut fields = value.split_whitespace();
    let key_type = fields
        .next()
        .ok_or_else(|| StoreError::InvalidKeypair("public key is empty".to_owned()))?;
    if !matches!(key_type, "ssh-ed25519" | "ssh-rsa" | "ecdsa-sha2-nistp256") {
        return Err(StoreError::InvalidKeypair(
            "unsupported public key type".to_owned(),
        ));
    }
    let encoded = fields
        .next()
        .ok_or_else(|| StoreError::InvalidKeypair("public key data is missing".to_owned()))?;
    let comment = fields.collect::<Vec<_>>().join(" ");
    if comment.len() > 256 || encoded.len() > 16_384 {
        return Err(StoreError::InvalidKeypair(
            "public key is too large".to_owned(),
        ));
    }
    let decoded = BASE64
        .decode(encoded)
        .map_err(|_| StoreError::InvalidKeypair("public key data is not base64".to_owned()))?;
    if decoded.is_empty() {
        return Err(StoreError::InvalidKeypair(
            "public key data is empty".to_owned(),
        ));
    }
    let mut cursor = 0;
    let embedded_type = ssh_string(&decoded, &mut cursor)?;
    if embedded_type != key_type.as_bytes() {
        return Err(StoreError::InvalidKeypair(
            "key type does not match public key data".to_owned(),
        ));
    }
    match key_type {
        "ssh-ed25519" => {
            let key_data = ssh_string(&decoded, &mut cursor)?;
            if key_data.len() != 32 || cursor != decoded.len() {
                return Err(StoreError::InvalidKeypair(
                    "ed25519 key data has the wrong length".to_owned(),
                ));
            }
        }
        "ssh-rsa" => {
            let exponent = ssh_string(&decoded, &mut cursor)?;
            let modulus = ssh_string(&decoded, &mut cursor)?;
            if exponent.is_empty() || modulus.is_empty() || cursor != decoded.len() {
                return Err(StoreError::InvalidKeypair(
                    "rsa key data is invalid".to_owned(),
                ));
            }
        }
        "ecdsa-sha2-nistp256" => {
            let curve = ssh_string(&decoded, &mut cursor)?;
            let point = ssh_string(&decoded, &mut cursor)?;
            if curve != b"nistp256"
                || point.len() != 65
                || point.first() != Some(&4)
                || cursor != decoded.len()
            {
                return Err(StoreError::InvalidKeypair(
                    "ecdsa key data is invalid".to_owned(),
                ));
            }
        }
        _ => unreachable!(),
    }
    let digest = Md5::digest(&decoded);
    let fingerprint = digest
        .iter()
        .map(|byte| format!("{byte:02x}"))
        .collect::<Vec<_>>()
        .join(":");
    Ok((
        key_type.to_owned(),
        fingerprint,
        format!("{key_type} {}", BASE64.encode(decoded)),
    ))
}

pub(super) fn ssh_string<'a>(data: &'a [u8], cursor: &mut usize) -> Result<&'a [u8], StoreError> {
    let header_end = cursor
        .checked_add(4)
        .ok_or_else(|| StoreError::InvalidKeypair("truncated public key data".to_owned()))?;
    let header = data
        .get(*cursor..header_end)
        .ok_or_else(|| StoreError::InvalidKeypair("truncated public key data".to_owned()))?;
    let length = u32::from_be_bytes(
        header
            .try_into()
            .map_err(|_| StoreError::InvalidKeypair("invalid public key length".to_owned()))?,
    ) as usize;
    let end = header_end
        .checked_add(length)
        .ok_or_else(|| StoreError::InvalidKeypair("truncated public key data".to_owned()))?;
    if end > data.len() {
        return Err(StoreError::InvalidKeypair(
            "truncated public key data".to_owned(),
        ));
    }
    let value = &data[header_end..end];
    *cursor = end;
    Ok(value)
}

pub(super) fn resource_from_row(
    row: &sqlx::sqlite::SqliteRow,
) -> Result<ResourceRecord, StoreError> {
    Ok(ResourceRecord {
        id: parse_uuid(row.get("id"))?,
        kind: row.get("kind"),
        project_id: row.get("project_id"),
        generation: row.get("generation"),
        observed_generation: row.get("observed_generation"),
        desired_state: row.get("desired_state"),
        observed_state: row.get("observed_state"),
        provider_id: row.get("provider_id"),
    })
}

pub(super) fn operation_from_row(
    row: &sqlx::sqlite::SqliteRow,
) -> Result<OperationRecord, StoreError> {
    Ok(OperationRecord {
        id: parse_uuid(row.get("id"))?,
        resource_id: parse_uuid(row.get("resource_id"))?,
        kind: row.get("kind"),
        state: OperationState::parse(row.get("state"))?,
        provider_operation_id: row.get("provider_operation_id"),
        error_category: row.get("error_category"),
        error_message: row.get("error_message"),
    })
}

pub(crate) fn sqlite_sequence(value: u64) -> Result<i64, StoreError> {
    i64::try_from(value)
        .map_err(|_| StoreError::Corrupt("agent command sequence exceeds SQLite range".to_owned()))
}

pub(super) fn agent_command_from_row(row: &SqliteRow) -> Result<AgentCommandRecord, StoreError> {
    let accepted_sequence: i64 = row.get("accepted_sequence");
    let last_sequence: i64 = row.get("last_sequence");
    Ok(AgentCommandRecord {
        command_id: row.get("command_id"),
        idempotency_key: row.get("idempotency_key"),
        operation_id: parse_uuid(row.get("operation_id"))?,
        resource_id: parse_uuid(row.get("resource_id"))?,
        agent_id: row.get("agent_id"),
        agent_epoch: row.get("agent_epoch"),
        payload_fingerprint_sha256: row.get("payload_fingerprint_sha256"),
        payload: row.get("payload"),
        state: AgentCommandState::parse(row.get::<String, _>("state").as_str())?,
        accepted_sequence: u64::try_from(accepted_sequence)
            .map_err(|_| StoreError::Corrupt("negative agent command sequence".to_owned()))?,
        last_sequence: u64::try_from(last_sequence)
            .map_err(|_| StoreError::Corrupt("negative agent command sequence".to_owned()))?,
        provider_operation_id: row.get("provider_operation_id"),
        provider_resource_id: row.get("provider_resource_id"),
    })
}

pub(crate) fn parse_uuid(value: String) -> Result<Uuid, StoreError> {
    Uuid::parse_str(&value).map_err(StoreError::InvalidUuid)
}

pub(super) fn validate_image_overlay(
    overlay: &ImageOverlayOwnershipRecord,
) -> Result<(), StoreError> {
    bounded_overlay_text("overlay_id", &overlay.overlay_id, 128)?;
    validate_image_overlay_identity(&overlay.identity)?;
    if overlay.state.is_terminal() {
        return Err(StoreError::InvalidImageOverlay(
            "a new overlay cannot start in deleted state".to_owned(),
        ));
    }
    Ok(())
}

pub(super) fn validate_image_overlay_identity(
    identity: &ImageOverlayIdentity,
) -> Result<(), StoreError> {
    bounded_overlay_text("command_id", &identity.command_id, 128)?;
    bounded_overlay_text("agent_id", &identity.agent_id, 128)?;
    bounded_overlay_text("agent_epoch", &identity.agent_epoch, 256)?;
    validate_base_identity(&identity.base_sha256, &identity.base_format)?;
    if identity.overlay_format != "qcow2" {
        return Err(StoreError::InvalidImageOverlay(
            "overlay format must be qcow2".to_owned(),
        ));
    }
    Ok(())
}

pub(super) fn validate_base_identity(sha256: &str, format: &str) -> Result<(), StoreError> {
    if sha256.len() != 64 || !sha256.bytes().all(|byte| byte.is_ascii_hexdigit()) {
        return Err(StoreError::InvalidImageOverlay(
            "base checksum must be 64 hexadecimal characters".to_owned(),
        ));
    }
    if !matches!(format, "raw" | "qcow2") {
        return Err(StoreError::InvalidImageOverlay(
            "base format must be raw or qcow2".to_owned(),
        ));
    }
    Ok(())
}

pub(super) fn bounded_overlay_text(name: &str, value: &str, max: usize) -> Result<(), StoreError> {
    if value.is_empty() || value.len() > max || value.chars().any(char::is_control) {
        return Err(StoreError::InvalidImageOverlay(format!(
            "{name} is empty, too long, or contains control characters"
        )));
    }
    Ok(())
}

pub(super) fn image_overlay_identity_matches(
    left: &ImageOverlayOwnershipRecord,
    right: &ImageOverlayOwnershipRecord,
) -> bool {
    left.overlay_id == right.overlay_id && left.identity == right.identity
}

pub(super) fn ensure_image_overlay_identity(
    current: &ImageOverlayOwnershipRecord,
    expected: &ImageOverlayIdentity,
) -> Result<(), StoreError> {
    if current.identity.agent_epoch != expected.agent_epoch {
        return Err(StoreError::ImageOverlayEpochConflict);
    }
    if current.identity != *expected {
        return Err(StoreError::ImageOverlayConflict(
            "overlay identity conflicts with durable state".to_owned(),
        ));
    }
    Ok(())
}

pub(super) fn validate_image_overlay_transition(
    current: ImageOverlayState,
    next: ImageOverlayState,
) -> Result<(), StoreError> {
    let allowed = match current {
        ImageOverlayState::Pending => matches!(
            next,
            ImageOverlayState::Pending
                | ImageOverlayState::Materializing
                | ImageOverlayState::Deleting
                | ImageOverlayState::Failed
        ),
        ImageOverlayState::Materializing => matches!(
            next,
            ImageOverlayState::Materializing
                | ImageOverlayState::Ready
                | ImageOverlayState::Deleting
                | ImageOverlayState::Failed
        ),
        ImageOverlayState::Ready => {
            matches!(next, ImageOverlayState::Ready | ImageOverlayState::Deleting)
        }
        ImageOverlayState::Deleting => {
            matches!(
                next,
                ImageOverlayState::Deleting | ImageOverlayState::Deleted
            )
        }
        ImageOverlayState::Deleted => next == ImageOverlayState::Deleted,
        ImageOverlayState::Failed => matches!(
            next,
            ImageOverlayState::Failed
                | ImageOverlayState::Materializing
                | ImageOverlayState::Deleting
        ),
    };
    if allowed {
        Ok(())
    } else {
        Err(StoreError::ImageOverlayConflict(format!(
            "invalid overlay state transition from {current:?} to {next:?}"
        )))
    }
}

pub(super) fn image_overlay_from_row(
    row: &SqliteRow,
) -> Result<ImageOverlayOwnershipRecord, StoreError> {
    let record = ImageOverlayOwnershipRecord {
        overlay_id: row.get("overlay_id"),
        identity: ImageOverlayIdentity {
            resource_id: parse_uuid(row.get("resource_id"))?,
            operation_id: parse_uuid(row.get("operation_id"))?,
            command_id: row.get("command_id"),
            agent_id: row.get("agent_id"),
            agent_epoch: row.get("agent_epoch"),
            base_sha256: row.get("base_sha256"),
            base_format: row.get("base_format"),
            overlay_format: row.get("overlay_format"),
        },
        state: ImageOverlayState::parse(row.get::<String, _>("state").as_str())?,
        created_at: row.get("created_at"),
        updated_at: row.get("updated_at"),
    };
    bounded_overlay_text("overlay_id", &record.overlay_id, 128)?;
    validate_image_overlay_identity(&record.identity)?;
    Ok(record)
}
