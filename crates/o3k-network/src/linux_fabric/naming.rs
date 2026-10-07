use super::*;

pub(crate) const STATE_VERSION: u32 = 3;
pub(crate) const FABRIC_PUBLIC_MARKER: &str = "o3k-p11-public";
pub(crate) fn valid_name(value: &str) -> bool {
    !value.is_empty()
        && value.len() <= 15
        && value
            .bytes()
            .all(|byte| byte.is_ascii_alphanumeric() || byte == b'-' || byte == b'_')
}

pub(crate) fn valid_mac(value: &str) -> bool {
    let octets = value.split(':').collect::<Vec<_>>();
    octets.len() == 6
        && octets
            .iter()
            .all(|octet| octet.len() == 2 && octet.bytes().all(|byte| byte.is_ascii_hexdigit()))
}
pub(crate) fn provider_name(prefix: &str, realm_id: Uuid, target_host: &str) -> String {
    let mut hash = 0xcbf29ce484222325u64;
    for byte in prefix
        .as_bytes()
        .iter()
        .copied()
        .chain(realm_id.as_bytes().iter().copied())
        .chain(target_host.as_bytes().iter().copied())
    {
        hash ^= u64::from(byte);
        hash = hash.wrapping_mul(0x100000001b3);
    }
    format!("o3k-{}-{:08x}", prefix, hash as u32)
}
pub(crate) fn policy_table_name(realm_id: Uuid) -> String {
    provider_name("p", realm_id, "policy")
}

pub(crate) fn public_root_table_name(realm_id: Uuid) -> String {
    provider_name("u", realm_id, "public")
}

pub(crate) fn public_realm_table_name(realm_id: Uuid) -> String {
    provider_name("n", realm_id, "public")
}
pub(crate) fn policy_fingerprint(
    plan: &NamespacedRoutedFabricPlan,
) -> Result<String, serde_json::Error> {
    let bytes = serde_json::to_vec(&(
        plan.policy_generation,
        &plan.policy_defaults,
        &plan.policies,
    ))?;
    Ok(format!("{:x}", Sha256::digest(bytes)))
}
pub(crate) fn policy_protocol(protocol: NetworkProtocol) -> Option<&'static str> {
    match protocol {
        NetworkProtocol::Any => None,
        NetworkProtocol::Tcp => Some("tcp"),
        NetworkProtocol::Udp => Some("udp"),
        NetworkProtocol::Icmp => Some("icmp"),
    }
}
pub(crate) fn public_fingerprint(
    plan: &NamespacedRoutedFabricPlan,
) -> Result<String, serde_json::Error> {
    let bytes = serde_json::to_vec(&plan.public_bindings)?;
    Ok(format!("{:x}", Sha256::digest(bytes)))
}
pub(crate) fn public_mark(realm_id: Uuid) -> u32 {
    let digest = Sha256::digest(realm_id.as_bytes());
    u32::from_be_bytes([digest[0], digest[1], digest[2], digest[3]]) | 1
}

pub(crate) fn public_route_table(realm_id: Uuid) -> u32 {
    20_000 + (public_mark(realm_id) % 10_000)
}

pub(crate) fn public_transit_addresses(realm_id: Uuid) -> (Ipv4Addr, Ipv4Addr) {
    let digest = Sha256::digest(realm_id.as_bytes());
    let subnet = u16::from_be_bytes([digest[0], digest[1]]) % 16_000;
    let base = 0x6440_0000u32 + u32::from(subnet) * 4;
    (Ipv4Addr::from(base + 1), Ipv4Addr::from(base + 2))
}
pub(crate) fn vxlan_name(realm_id: Uuid) -> String {
    provider_name("x", realm_id, "vxlan")
}

pub(crate) fn vxlan_bridge_name(realm_id: Uuid) -> String {
    provider_name("c", realm_id, "vxlan")
}

pub(crate) fn vxlan_host_veth_name(realm_id: Uuid) -> String {
    provider_name("v", realm_id, "vxlan-host")
}

pub(crate) fn vxlan_fabric_veth_name(realm_id: Uuid) -> String {
    provider_name("i", realm_id, "vxlan-fabric")
}

pub(crate) fn vxlan_link_matches(output: &str, vni: u32, local: Ipv4Addr) -> bool {
    output.contains("vxlan")
        && output.contains(&format!("id {vni}"))
        && output.contains("dstport 4789")
        && output.contains(&format!("local {local}"))
        && !output.contains("nolearning")
}
pub(crate) fn endpoint_tap_name(realm_id: Uuid, endpoint_id: Uuid) -> String {
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

pub(crate) fn endpoint_tap_mac(realm_id: Uuid, endpoint_id: Uuid) -> String {
    // The TAP must not share a MAC with the guest NIC, otherwise the Linux
    // bridge drops frames from the guest as "own address" loops.  Use a
    // deterministic locally-administered MAC that is distinct from the
    // endpoint MAC carried by the guest.
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
        "02:{:02x}:{:02x}:{:02x}:{:02x}:{:02x}",
        bytes[2], bytes[3], bytes[4], bytes[5], bytes[6]
    )
}

pub(crate) fn valid_wireguard_key(value: &str) -> bool {
    value.len() == 44
        && value.ends_with('=')
        && value[..43]
            .bytes()
            .all(|byte| byte.is_ascii_alphanumeric() || byte == b'+' || byte == b'/')
}
