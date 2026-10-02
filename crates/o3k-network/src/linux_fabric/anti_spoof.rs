//! Realm-local TAP ingress enforcement for P11 v3.
//!
//! Rules are rebuilt from the current endpoint directory and are scoped to
//! the owned TAP interface.  This keeps a guest from claiming another
//! endpoint's IP or MAC while allowing real endpoint MACs to cross VXLAN.

use super::*;
use crate::anti_spoof::{EndpointIdentity, IngressIdentity, validate_ingress};

const TABLE_PREFIX: &str = "o3k-as-";
const MARKER: &str = "o3k-p11-antispoof";

impl LinuxFabricBackend {
    pub(crate) fn ensure_anti_spoof(
        &mut self,
        plan: &NamespacedRoutedFabricPlan,
    ) -> Result<(), LinuxFabricError> {
        let realm = self
            .state
            .realms
            .get(&plan.realm_id)
            .cloned()
            .ok_or(LinuxFabricError::CorruptState)?;
        let snapshot = plan
            .directory
            .entries
            .iter()
            .map(|entry| {
                (
                    (plan.realm_id.to_string(), entry.fixed_ip),
                    EndpointIdentity {
                        realm_id: plan.realm_id.to_string(),
                        endpoint_id: entry.endpoint_id.to_string(),
                        fixed_ip: entry.fixed_ip,
                        canonical_mac: entry.mac.clone(),
                        host_id: entry.selected_host.clone(),
                        placement_generation: entry.placement_generation,
                        source_host_generation: plan.local_fabric_generation,
                        binding_generation: plan.encapsulation.binding_generation,
                        vni: plan.encapsulation.provider_segment_id,
                    },
                )
            })
            .collect::<BTreeMap<_, _>>();
        for entry in plan
            .directory
            .entries
            .iter()
            .filter(|entry| entry.selected_host == plan.local_host)
        {
            validate_ingress(
                &snapshot,
                &IngressIdentity {
                    realm_id: plan.realm_id.to_string(),
                    source_host: plan.local_host.clone(),
                    source_host_generation: plan.local_fabric_generation,
                    vni: plan.encapsulation.provider_segment_id,
                    source_mac: entry.mac.clone(),
                    source_ip: entry.fixed_ip,
                    arp_sender_mac: Some(entry.mac.clone()),
                    arp_sender_ip: Some(entry.fixed_ip),
                    placement_generation: entry.placement_generation,
                    binding_generation: plan.encapsulation.binding_generation,
                },
            )
            .map_err(|_| LinuxFabricError::OwnershipConflict)?;
        }
        let table = format!("{TABLE_PREFIX}{:08x}", public_mark(plan.realm_id));
        let fingerprint = format!(
            "{:x}",
            Sha256::digest(
                serde_json::to_vec(&(
                    plan.directory_generation,
                    plan.local_fabric_generation,
                    plan.encapsulation.binding_generation,
                    plan.encapsulation.provider_segment_id,
                    plan.directory
                        .entries
                        .iter()
                        .filter(|entry| entry.selected_host == plan.local_host)
                        .map(|entry| (
                            entry.endpoint_id,
                            entry.fixed_ip,
                            &entry.mac,
                            entry.endpoint_generation,
                            entry.placement_generation
                        ))
                        .collect::<Vec<_>>(),
                ))
                .map_err(|_| LinuxFabricError::CorruptState)?,
            )
        );
        let listed = self
            .command
            .output("nft", &["list", "table", "bridge", table.as_str()])
            .map_err(LinuxFabricError::Storage)?;
        if listed.0 && !listed.1.contains(MARKER) {
            return Err(LinuxFabricError::ForeignState);
        }
        if listed.0
            && realm.anti_spoof_generation == plan.directory_generation
            && realm.anti_spoof_fingerprint == fingerprint
        {
            return Ok(());
        }
        if !listed.0
            && !self
                .command
                .run("nft", &["add", "table", "bridge", table.as_str()])
                .map_err(LinuxFabricError::Storage)?
        {
            return Err(LinuxFabricError::CommandFailed);
        }

        let chain = "forward";
        if !listed.0
            && !self
                .command
                .run(
                    "nft",
                    &[
                        "add",
                        "chain",
                        "bridge",
                        table.as_str(),
                        chain,
                        "{",
                        "type",
                        "filter",
                        "hook",
                        "forward",
                        "priority",
                        "0",
                        ";",
                        "policy",
                        "accept",
                        ";",
                        "comment",
                        MARKER,
                        ";",
                        "}",
                    ],
                )
                .map_err(LinuxFabricError::Storage)?
        {
            return Err(LinuxFabricError::CommandFailed);
        }
        if !self
            .command
            .run("nft", &["flush", "chain", "bridge", table.as_str(), chain])
            .map_err(LinuxFabricError::Storage)?
        {
            return Err(LinuxFabricError::CommandFailed);
        }
        if let Some(vxlan) = realm.vxlan.as_ref() {
            // The root-side veth is the only ingress path from the fabric
            // namespace.  Accept only canonical remote endpoint pairs (plus
            // DHCP discovery with the canonical source MAC), then fail closed
            // for every other frame arriving from that path.
            for endpoint in plan
                .directory
                .entries
                .iter()
                .filter(|entry| entry.selected_host != plan.local_host)
            {
                let fixed_ip = endpoint.fixed_ip.to_string();
                for rule in [
                    vec![
                        "iifname",
                        vxlan.host_veth.as_str(),
                        "ether",
                        "saddr",
                        endpoint.mac.as_str(),
                        "ip",
                        "saddr",
                        fixed_ip.as_str(),
                        "accept",
                    ],
                    vec![
                        "iifname",
                        vxlan.host_veth.as_str(),
                        "ether",
                        "saddr",
                        endpoint.mac.as_str(),
                        "ip",
                        "saddr",
                        "0.0.0.0",
                        "accept",
                    ],
                    vec![
                        "iifname",
                        vxlan.host_veth.as_str(),
                        "arp",
                        "saddr",
                        "ether",
                        endpoint.mac.as_str(),
                        "arp",
                        "saddr",
                        "ip",
                        fixed_ip.as_str(),
                        "accept",
                    ],
                ] {
                    let mut args = vec!["add", "rule", "bridge", table.as_str(), chain];
                    args.extend(rule);
                    if !self
                        .command
                        .run("nft", &args)
                        .map_err(LinuxFabricError::Storage)?
                    {
                        return Err(LinuxFabricError::CommandFailed);
                    }
                }
            }
            if !self
                .command
                .run(
                    "nft",
                    &[
                        "add",
                        "rule",
                        "bridge",
                        table.as_str(),
                        chain,
                        "iifname",
                        vxlan.host_veth.as_str(),
                        "counter",
                        "comment",
                        MARKER,
                        "drop",
                    ],
                )
                .map_err(LinuxFabricError::Storage)?
            {
                return Err(LinuxFabricError::CommandFailed);
            }
        }
        for endpoint in plan
            .directory
            .entries
            .iter()
            .filter(|entry| entry.selected_host == plan.local_host)
        {
            let Some(tap) = realm.endpoint_taps.get(&endpoint.endpoint_id) else {
                return Err(LinuxFabricError::CorruptState);
            };
            let fixed_ip = endpoint.fixed_ip.to_string();
            for rule in [
                vec![
                    "iifname",
                    tap.interface.as_str(),
                    "ether",
                    "saddr",
                    "!=",
                    endpoint.mac.as_str(),
                    "counter",
                    "comment",
                    MARKER,
                    "drop",
                ],
                vec![
                    "iifname",
                    tap.interface.as_str(),
                    "ip",
                    "saddr",
                    "!=",
                    fixed_ip.as_str(),
                    "counter",
                    "comment",
                    MARKER,
                    "drop",
                ],
                vec![
                    "iifname",
                    tap.interface.as_str(),
                    "arp",
                    "saddr",
                    "ether",
                    "!=",
                    endpoint.mac.as_str(),
                    "counter",
                    "comment",
                    MARKER,
                    "drop",
                ],
                vec![
                    "iifname",
                    tap.interface.as_str(),
                    "arp",
                    "saddr",
                    "ip",
                    "!=",
                    fixed_ip.as_str(),
                    "counter",
                    "comment",
                    MARKER,
                    "drop",
                ],
            ] {
                if !self
                    .command
                    .run(
                        "nft",
                        &["add", "rule", "bridge", table.as_str(), chain]
                            .iter()
                            .copied()
                            .chain(rule.iter().copied())
                            .collect::<Vec<_>>(),
                    )
                    .map_err(LinuxFabricError::Storage)?
                {
                    return Err(LinuxFabricError::CommandFailed);
                }
            }
        }
        if let Some(state) = self.state.realms.get_mut(&plan.realm_id) {
            state.anti_spoof_generation = plan.directory_generation;
            state.anti_spoof_fingerprint = fingerprint;
        }
        store_state(&self.state_path, &self.state)
    }

    pub(crate) fn remove_anti_spoof(
        &self,
        plan: &NamespacedRoutedFabricPlan,
        _ownership: &RealmOwnership,
    ) -> Result<(), LinuxFabricError> {
        let table = format!("{TABLE_PREFIX}{:08x}", public_mark(plan.realm_id));
        let listed = self
            .command
            .output("nft", &["list", "table", "bridge", table.as_str()])
            .map_err(LinuxFabricError::Storage)?;
        if listed.0 && !listed.1.contains(MARKER) {
            return Err(LinuxFabricError::ForeignState);
        }
        if listed.0
            && !self
                .command
                .run("nft", &["delete", "table", "bridge", table.as_str()])
                .map_err(LinuxFabricError::Storage)?
        {
            return Err(LinuxFabricError::CommandFailed);
        }
        Ok(())
    }
}
