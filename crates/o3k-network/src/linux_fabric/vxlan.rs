//! P11 v3 stretched-L2 realization.
//!
//! A realm owns exactly one learning VXLAN device on a host.  The device is
//! connected to a provider bridge in the shared fabric namespace and to the
//! realm's host bridge through one veth pair.  Flood membership is derived
//! only from the plan's current endpoint directory and is reconciled against
//! observed FDB state.

use super::*;

const VXLAN_PORT: u16 = 4789;
const FLOOD_MAC: &str = "00:00:00:00:00:00";

/// `ip link` prints a veth peer as `name@peer` in one namespace and as
/// `name@if<N>` after its peer has moved to another namespace.  The paired
/// kernel ifindices (or names when available) are the identity that binds the
/// two halves; checking only `veth` plus bridge membership would allow a
/// foreign same-name topology to be adopted.
fn veth_pair_matches(
    local_output: &str,
    peer_output: &str,
    local_name: &str,
    peer_name: &str,
    local_master: &str,
    peer_master: &str,
) -> bool {
    let Some((local_index, local_peer)) = link_identity(local_output, local_name) else {
        return false;
    };
    let Some((peer_index, peer_peer)) = link_identity(peer_output, peer_name) else {
        return false;
    };
    local_output.contains("veth")
        && peer_output.contains("veth")
        && local_output.contains(&format!("master {local_master}"))
        && peer_output.contains(&format!("master {peer_master}"))
        && peer_refers_to(&local_peer, &peer_index, peer_name)
        && peer_refers_to(&peer_peer, &local_index, local_name)
}

fn link_identity(output: &str, expected_name: &str) -> Option<(String, String)> {
    let line = output.lines().find(|line| line.contains(": "))?;
    let (index, remainder) = line.split_once(": ")?;
    let name = remainder.split_whitespace().next()?.trim_end_matches(':');
    let (name, peer) = name.split_once('@')?;
    (name == expected_name).then(|| (index.to_owned(), peer.to_owned()))
}

fn peer_refers_to(peer: &str, expected_index: &str, expected_name: &str) -> bool {
    peer == expected_name || peer == format!("if{expected_index}")
}

impl LinuxFabricBackend {
    pub(crate) fn ensure_vxlan(
        &mut self,
        plan: &NamespacedRoutedFabricPlan,
    ) -> Result<(), LinuxFabricError> {
        if self.plans.values().any(|other| {
            other.realm_id != plan.realm_id
                && other.encapsulation.fabric_domain_id == plan.encapsulation.fabric_domain_id
                && other.encapsulation.provider_segment_id == plan.encapsulation.provider_segment_id
        }) {
            return Err(LinuxFabricError::OwnershipConflict);
        }
        let current = self
            .state
            .realms
            .get(&plan.realm_id)
            .cloned()
            .ok_or(LinuxFabricError::CorruptState)?;
        if !current.geneve.is_empty() || !current.attachments.is_empty() {
            // A v2 journal cannot be silently adopted.  The operator must
            // remove/prove absence of the old objects before VNI reuse.
            return Err(LinuxFabricError::ForeignState);
        }
        let wanted = VxlanOwnership {
            interface: vxlan_name(plan.realm_id),
            bridge: vxlan_bridge_name(plan.realm_id),
            host_veth: vxlan_host_veth_name(plan.realm_id),
            fabric_veth: vxlan_fabric_veth_name(plan.realm_id),
            vni: plan.encapsulation.provider_segment_id,
            binding_generation: plan.encapsulation.binding_generation,
            local_transport_ip: plan.local_fabric_transport_ip,
            tenant_mtu: plan.tenant_mtu,
            flood_peers: plan
                .peers
                .iter()
                .map(|peer| peer.fabric_transport_ip)
                .collect(),
        };
        if let Some(existing) = &current.vxlan
            && existing != &wanted
            && (existing.vni != wanted.vni
                || existing.binding_generation != wanted.binding_generation
                || existing.local_transport_ip != wanted.local_transport_ip)
        {
            return Err(LinuxFabricError::OwnershipConflict);
        }
        self.state
            .realms
            .entry(plan.realm_id)
            .and_modify(|realm| realm.vxlan = Some(wanted.clone()));
        store_state(&self.state_path, &self.state)?;

        let fabric_ns = self.config.fabric_namespace.as_str();
        let show = self
            .command
            .output(
                "ip",
                &[
                    "netns",
                    "exec",
                    fabric_ns,
                    "ip",
                    "-d",
                    "link",
                    "show",
                    "dev",
                    wanted.interface.as_str(),
                ],
            )
            .map_err(LinuxFabricError::Storage)?;
        if show.0 {
            if !vxlan_link_matches(&show.1, wanted.vni, wanted.local_transport_ip) {
                return Err(LinuxFabricError::ForeignState);
            }
        } else {
            let vni = wanted.vni.to_string();
            let dstport = VXLAN_PORT.to_string();
            let local = wanted.local_transport_ip.to_string();
            let args = vec![
                "netns",
                "exec",
                fabric_ns,
                "ip",
                "link",
                "add",
                wanted.interface.as_str(),
                "type",
                "vxlan",
                "id",
                vni.as_str(),
                "dstport",
                dstport.as_str(),
                "local",
                local.as_str(),
                "dev",
                self.config.fabric_interface.as_str(),
            ];
            if !self
                .command
                .run("ip", &args)
                .map_err(LinuxFabricError::Storage)?
            {
                return Err(LinuxFabricError::CommandFailed);
            }
        }

        self.ensure_fabric_bridge(&wanted, plan)?;
        self.reconcile_vxlan_fdb(&wanted, plan)?;
        Ok(())
    }

    fn ensure_fabric_bridge(
        &self,
        vxlan: &VxlanOwnership,
        plan: &NamespacedRoutedFabricPlan,
    ) -> Result<(), LinuxFabricError> {
        let ns = self.config.fabric_namespace.as_str();
        let realm_bridge = self
            .state
            .realms
            .get(&plan.realm_id)
            .ok_or(LinuxFabricError::CorruptState)?
            .bridge
            .clone();
        let bridge = self
            .command
            .output(
                "ip",
                &[
                    "netns",
                    "exec",
                    ns,
                    "ip",
                    "-d",
                    "link",
                    "show",
                    "dev",
                    vxlan.bridge.as_str(),
                ],
            )
            .map_err(LinuxFabricError::Storage)?;
        if bridge.0 && !bridge.1.contains("bridge") {
            return Err(LinuxFabricError::ForeignState);
        }
        if bridge.0 {
            let vxlan_link = self
                .command
                .output(
                    "ip",
                    &[
                        "netns",
                        "exec",
                        ns,
                        "ip",
                        "-d",
                        "link",
                        "show",
                        "dev",
                        vxlan.interface.as_str(),
                    ],
                )
                .map_err(LinuxFabricError::Storage)?;
            let fabric_link = self
                .command
                .output(
                    "ip",
                    &[
                        "netns",
                        "exec",
                        ns,
                        "ip",
                        "-d",
                        "link",
                        "show",
                        "dev",
                        vxlan.fabric_veth.as_str(),
                    ],
                )
                .map_err(LinuxFabricError::Storage)?;
            let root_link = self
                .command
                .output(
                    "ip",
                    &["-d", "link", "show", "dev", vxlan.host_veth.as_str()],
                )
                .map_err(LinuxFabricError::Storage)?;
            if !vxlan_link.0
                || !vxlan_link.1.contains("vxlan")
                || !vxlan_link.1.contains(&format!("master {}", vxlan.bridge))
                || !root_link.0
                || !fabric_link.0
                || !veth_pair_matches(
                    &root_link.1,
                    &fabric_link.1,
                    &vxlan.host_veth,
                    &vxlan.fabric_veth,
                    &realm_bridge,
                    &vxlan.bridge,
                )
            {
                return Err(LinuxFabricError::ForeignState);
            }
        }
        if !bridge.0
            && !self
                .command
                .run(
                    "ip",
                    &[
                        "netns",
                        "exec",
                        ns,
                        "ip",
                        "link",
                        "add",
                        vxlan.bridge.as_str(),
                        "type",
                        "bridge",
                    ],
                )
                .map_err(LinuxFabricError::Storage)?
        {
            return Err(LinuxFabricError::CommandFailed);
        }
        let root_veth = self
            .command
            .output(
                "ip",
                &["-d", "link", "show", "dev", vxlan.host_veth.as_str()],
            )
            .map_err(LinuxFabricError::Storage)?;
        if !root_veth.0 {
            if !self
                .command
                .run(
                    "ip",
                    &[
                        "link",
                        "add",
                        vxlan.host_veth.as_str(),
                        "type",
                        "veth",
                        "peer",
                        "name",
                        vxlan.fabric_veth.as_str(),
                    ],
                )
                .map_err(LinuxFabricError::Storage)?
                || !self
                    .command
                    .run(
                        "ip",
                        &["link", "set", vxlan.fabric_veth.as_str(), "netns", ns],
                    )
                    .map_err(LinuxFabricError::Storage)?
            {
                return Err(LinuxFabricError::CommandFailed);
            }
        } else {
            let fabric_veth = self
                .command
                .output(
                    "ip",
                    &[
                        "netns",
                        "exec",
                        ns,
                        "ip",
                        "link",
                        "show",
                        "dev",
                        vxlan.fabric_veth.as_str(),
                    ],
                )
                .map_err(LinuxFabricError::Storage)?;
            if !fabric_veth.0
                || !veth_pair_matches(
                    &root_veth.1,
                    &fabric_veth.1,
                    &vxlan.host_veth,
                    &vxlan.fabric_veth,
                    &realm_bridge,
                    &vxlan.bridge,
                )
            {
                return Err(LinuxFabricError::ForeignState);
            }
        }
        let tenant_mtu = plan.tenant_mtu.to_string();
        for args in [
            vec![
                "netns",
                "exec",
                ns,
                "ip",
                "link",
                "set",
                "dev",
                vxlan.bridge.as_str(),
                "up",
            ],
            vec![
                "netns",
                "exec",
                ns,
                "ip",
                "link",
                "set",
                "dev",
                vxlan.interface.as_str(),
                "mtu",
                tenant_mtu.as_str(),
            ],
            vec![
                "netns",
                "exec",
                ns,
                "ip",
                "link",
                "set",
                "dev",
                vxlan.interface.as_str(),
                "master",
                vxlan.bridge.as_str(),
            ],
            vec![
                "netns",
                "exec",
                ns,
                "ip",
                "link",
                "set",
                "dev",
                vxlan.interface.as_str(),
                "up",
            ],
            vec![
                "netns",
                "exec",
                ns,
                "ip",
                "link",
                "set",
                "dev",
                vxlan.fabric_veth.as_str(),
                "mtu",
                tenant_mtu.as_str(),
            ],
            vec![
                "netns",
                "exec",
                ns,
                "ip",
                "link",
                "set",
                "dev",
                vxlan.fabric_veth.as_str(),
                "master",
                vxlan.bridge.as_str(),
            ],
            vec![
                "netns",
                "exec",
                ns,
                "ip",
                "link",
                "set",
                "dev",
                vxlan.fabric_veth.as_str(),
                "up",
            ],
            vec![
                "link",
                "set",
                "dev",
                vxlan.host_veth.as_str(),
                "mtu",
                tenant_mtu.as_str(),
            ],
            vec![
                "link",
                "set",
                "dev",
                vxlan.host_veth.as_str(),
                "master",
                self.state
                    .realms
                    .get(&plan.realm_id)
                    .ok_or(LinuxFabricError::CorruptState)?
                    .bridge
                    .as_str(),
            ],
            vec!["link", "set", "dev", vxlan.host_veth.as_str(), "up"],
        ] {
            if !self
                .command
                .run("ip", &args)
                .map_err(LinuxFabricError::Storage)?
            {
                return Err(LinuxFabricError::CommandFailed);
            }
        }
        Ok(())
    }

    fn reconcile_vxlan_fdb(
        &self,
        vxlan: &VxlanOwnership,
        plan: &NamespacedRoutedFabricPlan,
    ) -> Result<(), LinuxFabricError> {
        let ns = self.config.fabric_namespace.as_str();
        let observed = self
            .command
            .output(
                "ip",
                &[
                    "netns",
                    "exec",
                    ns,
                    "bridge",
                    "fdb",
                    "show",
                    "dev",
                    vxlan.interface.as_str(),
                ],
            )
            .map_err(LinuxFabricError::Storage)?;
        if !observed.0 {
            return Err(LinuxFabricError::CommandFailed);
        }
        let mut seen = BTreeMap::<Ipv4Addr, usize>::new();
        for line in observed.1.lines() {
            let fields = line.split_whitespace().collect::<Vec<_>>();
            if fields.first() == Some(&FLOOD_MAC)
                && let Some(dst) = fields
                    .windows(2)
                    .find_map(|w| (w[0] == "dst").then_some(w[1]))
                && let Ok(ip) = dst.parse::<Ipv4Addr>()
            {
                *seen.entry(ip).or_default() += 1;
            }
        }
        for peer in &vxlan.flood_peers {
            if !seen.contains_key(peer) {
                let destination = peer.to_string();
                if !self
                    .command
                    .run(
                        "ip",
                        &[
                            "netns",
                            "exec",
                            ns,
                            "bridge",
                            "fdb",
                            // Multicast/broadcast FDB entries deliberately
                            // use append: one all-zero entry is required per
                            // participating VTEP, whereas replace would
                            // collapse the set on kernels that key the entry
                            // by LLADDR and device.
                            "append",
                            FLOOD_MAC,
                            "dev",
                            vxlan.interface.as_str(),
                            "dst",
                            destination.as_str(),
                        ],
                    )
                    .map_err(LinuxFabricError::Storage)?
                {
                    return Err(LinuxFabricError::CommandFailed);
                }
            }
        }
        for (peer, count) in seen {
            let keep = usize::from(vxlan.flood_peers.contains(&peer));
            for _ in keep..count {
                let destination = peer.to_string();
                if !self
                    .command
                    .run(
                        "ip",
                        &[
                            "netns",
                            "exec",
                            ns,
                            "bridge",
                            "fdb",
                            "del",
                            FLOOD_MAC,
                            "dev",
                            vxlan.interface.as_str(),
                            "dst",
                            destination.as_str(),
                        ],
                    )
                    .map_err(LinuxFabricError::Storage)?
                {
                    return Err(LinuxFabricError::CommandFailed);
                }
            }
        }
        let _ = plan;
        Ok(())
    }

    pub(crate) fn remove_vxlan(
        &self,
        plan: &NamespacedRoutedFabricPlan,
        ownership: &RealmOwnership,
    ) -> Result<(), LinuxFabricError> {
        let Some(vxlan) = ownership.vxlan.as_ref() else {
            return Ok(());
        };
        let ns = self.config.fabric_namespace.as_str();
        let realm_bridge = self
            .state
            .realms
            .get(&plan.realm_id)
            .ok_or(LinuxFabricError::CorruptState)?
            .bridge
            .clone();
        let vxlan_observed = self
            .command
            .output(
                "ip",
                &[
                    "netns",
                    "exec",
                    ns,
                    "ip",
                    "-d",
                    "link",
                    "show",
                    "dev",
                    vxlan.interface.as_str(),
                ],
            )
            .map_err(LinuxFabricError::Storage)?;
        if vxlan_observed.0
            && !vxlan_link_matches(&vxlan_observed.1, vxlan.vni, vxlan.local_transport_ip)
        {
            return Err(LinuxFabricError::ForeignState);
        }
        let bridge_observed = self
            .command
            .output(
                "ip",
                &[
                    "netns",
                    "exec",
                    ns,
                    "ip",
                    "-d",
                    "link",
                    "show",
                    "dev",
                    vxlan.bridge.as_str(),
                ],
            )
            .map_err(LinuxFabricError::Storage)?;
        if bridge_observed.0 && !bridge_observed.1.contains("bridge") {
            return Err(LinuxFabricError::ForeignState);
        }
        if bridge_observed.0 {
            let vxlan_link = self
                .command
                .output(
                    "ip",
                    &[
                        "netns",
                        "exec",
                        ns,
                        "ip",
                        "-d",
                        "link",
                        "show",
                        "dev",
                        vxlan.interface.as_str(),
                    ],
                )
                .map_err(LinuxFabricError::Storage)?;
            let fabric_link = self
                .command
                .output(
                    "ip",
                    &[
                        "netns",
                        "exec",
                        ns,
                        "ip",
                        "-d",
                        "link",
                        "show",
                        "dev",
                        vxlan.fabric_veth.as_str(),
                    ],
                )
                .map_err(LinuxFabricError::Storage)?;
            let root_link = self
                .command
                .output(
                    "ip",
                    &["-d", "link", "show", "dev", vxlan.host_veth.as_str()],
                )
                .map_err(LinuxFabricError::Storage)?;
            if !vxlan_link.0
                || !vxlan_link.1.contains("vxlan")
                || !vxlan_link.1.contains(&format!("master {}", vxlan.bridge))
                || !root_link.0
                || !fabric_link.0
                || !veth_pair_matches(
                    &root_link.1,
                    &fabric_link.1,
                    &vxlan.host_veth,
                    &vxlan.fabric_veth,
                    &realm_bridge,
                    &vxlan.bridge,
                )
            {
                return Err(LinuxFabricError::ForeignState);
            }
        }
        let root_veth_observed = self
            .command
            .output(
                "ip",
                &["-d", "link", "show", "dev", vxlan.host_veth.as_str()],
            )
            .map_err(LinuxFabricError::Storage)?;
        let fabric_veth_observed = self
            .command
            .output(
                "ip",
                &[
                    "netns",
                    "exec",
                    ns,
                    "ip",
                    "-d",
                    "link",
                    "show",
                    "dev",
                    vxlan.fabric_veth.as_str(),
                ],
            )
            .map_err(LinuxFabricError::Storage)?;
        if root_veth_observed.0
            && (!fabric_veth_observed.0
                || !veth_pair_matches(
                    &root_veth_observed.1,
                    &fabric_veth_observed.1,
                    &vxlan.host_veth,
                    &vxlan.fabric_veth,
                    &realm_bridge,
                    &vxlan.bridge,
                ))
        {
            return Err(LinuxFabricError::ForeignState);
        }
        let _ = self.command.run(
            "ip",
            &[
                "netns",
                "exec",
                ns,
                "bridge",
                "fdb",
                "flush",
                "dev",
                vxlan.interface.as_str(),
            ],
        );
        for (program, args) in [
            (
                "ip",
                vec![
                    "netns",
                    "exec",
                    ns,
                    "ip",
                    "link",
                    "del",
                    vxlan.interface.as_str(),
                ],
            ),
            (
                "ip",
                vec![
                    "netns",
                    "exec",
                    ns,
                    "ip",
                    "link",
                    "del",
                    vxlan.bridge.as_str(),
                ],
            ),
            ("ip", vec!["link", "del", vxlan.host_veth.as_str()]),
        ] {
            // Deletion is replay-safe: absence is already the desired state,
            // while an observed object must be successfully removed.
            let exists = if args.starts_with(&["netns", "exec"]) {
                self.command
                    .output(
                        "ip",
                        &[
                            "netns",
                            "exec",
                            ns,
                            "ip",
                            "link",
                            "show",
                            "dev",
                            args.last().copied().unwrap_or(""),
                        ],
                    )
                    .map_err(LinuxFabricError::Storage)?
                    .0
            } else {
                self.command
                    .output(
                        "ip",
                        &["link", "show", "dev", args.last().copied().unwrap_or("")],
                    )
                    .map_err(LinuxFabricError::Storage)?
                    .0
            };
            if exists
                && !self
                    .command
                    .run(program, &args)
                    .map_err(LinuxFabricError::Storage)?
            {
                return Err(LinuxFabricError::CommandFailed);
            }
        }
        let _ = plan;
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::veth_pair_matches;

    #[test]
    fn veth_ownership_requires_the_kernel_peer_identity() {
        let local = "12: o3k-h@o3k-f: <BROADCAST> veth master o3k-b-12345678";
        let peer = "13: o3k-f@o3k-h: <BROADCAST> veth master o3k-c-12345678";
        assert!(veth_pair_matches(
            local,
            peer,
            "o3k-h",
            "o3k-f",
            "o3k-b-12345678",
            "o3k-c-12345678"
        ));
        assert!(!veth_pair_matches(
            local,
            "14: foreign-f@o3k-h: <BROADCAST> veth master o3k-c-12345678",
            "o3k-h",
            "o3k-f",
            "o3k-b-12345678",
            "o3k-c-12345678"
        ));
    }
}
