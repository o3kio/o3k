use super::*;

fn nft_chain_has_comment(listing: &str, chain: &str, marker: &str) -> bool {
    let heading = format!("chain {chain} {{");
    let mut in_chain = false;
    for line in listing.lines() {
        let line = line.trim();
        if !in_chain {
            in_chain = line == heading;
            continue;
        }
        if line == "}" {
            return false;
        }
        if line
            .strip_prefix("comment \"")
            .and_then(|comment| comment.strip_suffix('"'))
            == Some(marker)
        {
            return true;
        }
    }
    false
}

fn nft_table_has_owner_marker(listing: &str, marker: &str) -> bool {
    let mut depth = 0_i32;
    for line in listing.lines() {
        let line = line.trim();
        if depth == 1
            && line
                .strip_prefix("comment \"")
                .and_then(|comment| comment.strip_suffix('"'))
                == Some(marker)
        {
            return true;
        }
        depth += line.matches('{').count() as i32;
        depth -= line.matches('}').count() as i32;
    }
    false
}

// A durable state write can be interrupted after the nft transaction commits,
// leaving the chain marker ahead of its fingerprint in provider state. Recover
// that case only when the chain has the exact O3K marker format and expected
// fail-closed hook/device shape. Table or object names alone never establish
// ownership.
fn nft_chain_has_owner_marker(
    listing: &str,
    chain: &str,
    marker_prefix: &str,
    owner_token: &str,
    hook: &str,
    device: Option<&str>,
) -> bool {
    let heading = format!("chain {chain} {{");
    let expected_device = device.map(|name| format!("device \"{name}\""));
    let mut in_chain = false;
    let mut marker_ok = false;
    let mut hook_ok = false;
    for line in listing.lines() {
        let line = line.trim();
        if !in_chain {
            in_chain = line == heading;
            continue;
        }
        if line == "}" {
            return marker_ok && hook_ok;
        }
        if let Some(comment) = line
            .strip_prefix("comment \"")
            .and_then(|comment| comment.strip_suffix('"'))
            && let Some(fingerprint) =
                comment.strip_prefix(&format!("{marker_prefix}:{owner_token}:"))
        {
            marker_ok = fingerprint.len() == 64
                && fingerprint
                    .bytes()
                    .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte));
        }
        if line.starts_with("type filter hook ")
            && line.contains(&format!("hook {hook} "))
            && line.contains("policy drop;")
            && expected_device
                .as_ref()
                .is_none_or(|expected| line.contains(expected))
        {
            hook_ok = true;
        }
    }
    false
}

fn nft_chain_has_fail_closed_hook(
    listing: &str,
    chain: &str,
    hook: &str,
    device: Option<&str>,
) -> bool {
    let heading = format!("chain {chain} {{");
    let expected_device = device.map(|name| format!("device \"{name}\""));
    let mut in_chain = false;
    for line in listing.lines() {
        let line = line.trim();
        if !in_chain {
            in_chain = line == heading;
            continue;
        }
        if line == "}" {
            return false;
        }
        if line.starts_with("type filter hook ")
            && line.contains(&format!("hook {hook} "))
            && line.contains("policy drop;")
            && expected_device
                .as_ref()
                .is_none_or(|expected| line.contains(expected))
        {
            return true;
        }
    }
    false
}

impl super::LinuxFabricBackend {
    fn iptables_rule_present(&self, rule: &[&str]) -> Result<bool, LinuxFabricError> {
        let mut args = vec!["-t", "nat", "-C"];
        args.extend_from_slice(rule);
        self.command
            .output("iptables", &args)
            .map(|(present, _)| present)
            .map_err(LinuxFabricError::Storage)
    }

    fn ensure_iptables_rule(&self, rule: &[&str]) -> Result<(), LinuxFabricError> {
        if !self.iptables_rule_present(rule)? {
            let mut args = vec!["-t", "nat", "-A"];
            args.extend_from_slice(rule);
            if !self
                .command
                .run("iptables", &args)
                .map_err(LinuxFabricError::Storage)?
            {
                return Err(LinuxFabricError::CommandFailed);
            }
        }
        Ok(())
    }

    fn remove_iptables_rule(&self, rule: &[&str]) -> Result<(), LinuxFabricError> {
        while self.iptables_rule_present(rule)? {
            let mut args = vec!["-t", "nat", "-D"];
            args.extend_from_slice(rule);
            if !self
                .command
                .run("iptables", &args)
                .map_err(LinuxFabricError::Storage)?
            {
                return Err(LinuxFabricError::CommandFailed);
            }
        }
        Ok(())
    }

    pub(crate) fn ensure_fabric(
        &mut self,
        plan: &NamespacedRoutedFabricPlan,
    ) -> Result<(), LinuxFabricError> {
        if let Some(fabric) = &self.state.fabric {
            if plan.local_fabric_generation != fabric.fabric_generation {
                return Err(LinuxFabricError::OwnershipConflict);
            }
            if plan.local_fabric_mtu != fabric.fabric_mtu {
                return Err(LinuxFabricError::OwnershipConflict);
            }
            if plan.local_fabric_transport_ip != fabric.fabric_transport_ip {
                return Err(LinuxFabricError::OwnershipConflict);
            }
            let (wg_exists, _) = self
                .command
                .output(
                    "ip",
                    &[
                        "netns",
                        "exec",
                        &self.config.fabric_namespace,
                        "ip",
                        "link",
                        "show",
                        "dev",
                        &self.config.fabric_interface,
                    ],
                )
                .map_err(LinuxFabricError::Storage)?;
            if !wg_exists {
                let _ = self.command.run("ip", &["link", "del", "o3k-u"]);
                let _ = self
                    .command
                    .run("ip", &["netns", "del", &self.config.fabric_namespace]);
                self.state.fabric = None;
            } else {
                let mtu = plan.local_fabric_mtu.to_string();
                if !self
                    .command
                    .run(
                        "ip",
                        &[
                            "netns",
                            "exec",
                            &self.config.fabric_namespace,
                            "ip",
                            "link",
                            "set",
                            "dev",
                            &self.config.fabric_interface,
                            "mtu",
                            &mtu,
                        ],
                    )
                    .map_err(LinuxFabricError::Storage)?
                {
                    return Err(LinuxFabricError::CommandFailed);
                }
                return Ok(());
            }
        }
        let private_key_path = self.config.root.join("wireguard-private.key");
        let (ns_exists, _) = self
            .command
            .output(
                "ip",
                &["netns", "exec", &self.config.fabric_namespace, "true"],
            )
            .map_err(LinuxFabricError::Storage)?;
        if ns_exists {
            return Err(LinuxFabricError::ForeignState);
        }
        let (if_exists, _) = self
            .command
            .output(
                "ip",
                &["link", "show", "dev", &self.config.fabric_interface],
            )
            .map_err(LinuxFabricError::Storage)?;
        if if_exists {
            return Err(LinuxFabricError::ForeignState);
        }
        // The key file is provisioned host identity material (like the TLS
        // keys under /opt/o3k/pki): the controller generates the keypair so
        // that planned FabricPeer public keys match this host. A valid
        // pre-provisioned key is adopted as-is; a missing file is generated
        // here, and anything invalid is foreign state that is never
        // overwritten. The file intentionally survives fabric teardown and
        // crash recovery so planned peer public keys stay valid.
        if private_key_path.exists() {
            validate_private_key_file(&private_key_path)?;
        } else {
            write_private_key(&private_key_path, &self.command)?;
        }
        // Create the fabric namespace and wg-o3k inside it.
        if !self
            .command
            .run("ip", &["netns", "add", &self.config.fabric_namespace])
            .map_err(LinuxFabricError::Storage)?
            || !self
                .command
                .run(
                    "ip",
                    &[
                        "link",
                        "add",
                        &self.config.fabric_interface,
                        "type",
                        "wireguard",
                    ],
                )
                .map_err(LinuxFabricError::Storage)?
            || !self
                .command
                .run(
                    "ip",
                    &[
                        "link",
                        "set",
                        &self.config.fabric_interface,
                        "netns",
                        &self.config.fabric_namespace,
                    ],
                )
                .map_err(LinuxFabricError::Storage)?
        {
            return Err(LinuxFabricError::CommandFailed);
        }
        let transport_ip = format!("{}/32", plan.local_fabric_transport_ip);
        let fabric_mtu = plan.local_fabric_mtu.to_string();
        if !self
            .command
            .run(
                "ip",
                &[
                    "netns",
                    "exec",
                    &self.config.fabric_namespace,
                    "wg",
                    "set",
                    &self.config.fabric_interface,
                    "private-key",
                    private_key_path
                        .to_str()
                        .ok_or(LinuxFabricError::CorruptState)?,
                    "listen-port",
                    &self.config.wireguard_port.to_string(),
                ],
            )
            .map_err(LinuxFabricError::Storage)?
            || !self
                .command
                .run(
                    "ip",
                    &[
                        "netns",
                        "exec",
                        &self.config.fabric_namespace,
                        "ip",
                        "link",
                        "set",
                        &self.config.fabric_interface,
                        "up",
                    ],
                )
                .map_err(LinuxFabricError::Storage)?
            || !self
                .command
                .run(
                    "ip",
                    &[
                        "netns",
                        "exec",
                        &self.config.fabric_namespace,
                        "ip",
                        "addr",
                        "replace",
                        &transport_ip,
                        "dev",
                        &self.config.fabric_interface,
                    ],
                )
                .map_err(LinuxFabricError::Storage)?
            || !self
                .command
                .run(
                    "ip",
                    &[
                        "netns",
                        "exec",
                        &self.config.fabric_namespace,
                        "ip",
                        "link",
                        "set",
                        "dev",
                        &self.config.fabric_interface,
                        "mtu",
                        &fabric_mtu,
                    ],
                )
                .map_err(LinuxFabricError::Storage)?
        {
            return Err(LinuxFabricError::CommandFailed);
        }
        // Veth pair to connect fabric namespace to the host default namespace
        // so WireGuard encrypted traffic can traverse to/from the underlay.
        let _ = self.command.output("ip", &["link", "del", "o3k-u"]);
        if !self
            .command
            .run(
                "ip",
                &[
                    "link", "add", "o3k-u", "type", "veth", "peer", "name", "o3k-v",
                ],
            )
            .map_err(LinuxFabricError::Storage)?
            || !self
                .command
                .run(
                    "ip",
                    &[
                        "link",
                        "set",
                        "o3k-v",
                        "netns",
                        &self.config.fabric_namespace,
                    ],
                )
                .map_err(LinuxFabricError::Storage)?
            || !self
                .command
                .run("ip", &["link", "set", "o3k-u", "up"])
                .map_err(LinuxFabricError::Storage)?
            || !self
                .command
                .run(
                    "ip",
                    &[
                        "netns",
                        "exec",
                        &self.config.fabric_namespace,
                        "ip",
                        "link",
                        "set",
                        "o3k-v",
                        "up",
                    ],
                )
                .map_err(LinuxFabricError::Storage)?
            || !self
                .command
                .run(
                    "ip",
                    &[
                        "netns",
                        "exec",
                        &self.config.fabric_namespace,
                        "ip",
                        "addr",
                        "replace",
                        "169.254.253.2/30",
                        "dev",
                        "o3k-v",
                    ],
                )
                .map_err(LinuxFabricError::Storage)?
            || !self
                .command
                .run(
                    "ip",
                    &["addr", "replace", "169.254.253.1/30", "dev", "o3k-u"],
                )
                .map_err(LinuxFabricError::Storage)?
            || !self
                .command
                .run(
                    "ip",
                    &[
                        "netns",
                        "exec",
                        &self.config.fabric_namespace,
                        "ip",
                        "route",
                        "replace",
                        "default",
                        "via",
                        "169.254.253.1",
                    ],
                )
                .map_err(LinuxFabricError::Storage)?
        {
            return Err(LinuxFabricError::CommandFailed);
        }
        // Disable rp_filter on the veth interfaces so forwarded packets with
        // source IPs from the fabric namespace are not dropped in the host ns.
        let _ = self
            .command
            .run("sysctl", &["-w", "net.ipv4.conf.o3k-u.rp_filter=0"]);
        let _ = self.command.run(
            "ip",
            &[
                "netns",
                "exec",
                &self.config.fabric_namespace,
                "sysctl",
                "-w",
                "net.ipv4.conf.o3k-v.rp_filter=0",
            ],
        );
        // SNAT fabric namespace traffic to the host IP.
        self.ensure_iptables_rule(&["POSTROUTING", "-s", "169.254.253.0/30", "-j", "MASQUERADE"])?;
        // DNAT incoming WireGuard UDP to the fabric namespace.
        let wg_port = self.config.wireguard_port.to_string();
        self.ensure_iptables_rule(&[
            "PREROUTING",
            "!",
            "-i",
            "o3k-u",
            "-p",
            "udp",
            "--dport",
            &wg_port,
            "-j",
            "DNAT",
            "--to-destination",
            "169.254.253.2",
        ])?;
        self.state.fabric = Some(FabricOwnership {
            namespace: self.config.fabric_namespace.clone(),
            interface: self.config.fabric_interface.clone(),
            private_key_path: private_key_path.display().to_string(),
            fabric_transport_ip: plan.local_fabric_transport_ip,
            fabric_generation: plan.local_fabric_generation,
            fabric_mtu: plan.local_fabric_mtu,
            ingress_auth_fingerprint: String::new(),
            ingress_vni_fingerprint: String::new(),
            ingress_owner_token: Uuid::new_v4().simple().to_string(),
            managed_peers: BTreeSet::new(),
        });
        store_state(&self.state_path, &self.state)?;
        Ok(())
    }
    pub(crate) fn configure_peers(&mut self) -> Result<(), LinuxFabricError> {
        let Some(fabric) = self.state.fabric.clone() else {
            return Err(LinuxFabricError::CorruptState);
        };
        let mut peers = BTreeMap::<String, FabricPeer>::new();
        for plan in self
            .plans
            .values()
            .filter(|plan| self.state.realms.contains_key(&plan.realm_id))
        {
            for peer in &plan.peers {
                if let Some(existing) = peers.get_mut(&peer.host_id) {
                    if existing.public_key != peer.public_key
                        || existing.underlay_endpoint != peer.underlay_endpoint
                        || existing.fabric_transport_ip != peer.fabric_transport_ip
                        || existing.fabric_generation != peer.fabric_generation
                    {
                        return Err(LinuxFabricError::OwnershipConflict);
                    }
                } else {
                    peers.insert(peer.host_id.clone(), peer.clone());
                }
            }
        }
        let current_keys = peers
            .values()
            .map(|peer| peer.public_key.clone())
            .collect::<BTreeSet<_>>();
        for stale_key in fabric.managed_peers.difference(&current_keys) {
            if !self
                .command
                .run(
                    "ip",
                    &[
                        "netns",
                        "exec",
                        &fabric.namespace,
                        "wg",
                        "set",
                        &fabric.interface,
                        "peer",
                        stale_key,
                        "remove",
                    ],
                )
                .map_err(LinuxFabricError::Storage)?
            {
                return Err(LinuxFabricError::CommandFailed);
            }
        }
        for peer in peers.values_mut() {
            if !valid_wireguard_key(&peer.public_key)
                || peer.host_id.is_empty()
                || peer.host_id.len() > 63
                || !peer
                    .host_id
                    .bytes()
                    .all(|byte| byte.is_ascii_alphanumeric() || byte == b'-' || byte == b'_')
                || peer
                    .underlay_endpoint
                    .parse::<std::net::SocketAddr>()
                    .is_err()
                || peer.fabric_transport_ip.is_unspecified()
                || peer.fabric_transport_ip.is_loopback()
            {
                return Err(LinuxFabricError::OwnershipConflict);
            }
            // wg-o3k is in the fabric namespace.
            if !self
                .command
                .run(
                    "ip",
                    &[
                        "netns",
                        "exec",
                        &fabric.namespace,
                        "wg",
                        "set",
                        &fabric.interface,
                        "peer",
                        &peer.public_key,
                        "endpoint",
                        &peer.underlay_endpoint,
                        "allowed-ips",
                        &format!("{}/32", peer.fabric_transport_ip),
                    ],
                )
                .map_err(LinuxFabricError::Storage)?
            {
                return Err(LinuxFabricError::CommandFailed);
            }
            let route = format!("{}/32", peer.fabric_transport_ip);
            if !self
                .command
                .run(
                    "ip",
                    &[
                        "netns",
                        "exec",
                        &fabric.namespace,
                        "ip",
                        "route",
                        "replace",
                        &route,
                        "dev",
                        &fabric.interface,
                    ],
                )
                .map_err(LinuxFabricError::Storage)?
            {
                return Err(LinuxFabricError::CommandFailed);
            }
        }
        if let Some(stored) = self.state.fabric.as_mut() {
            stored.managed_peers = current_keys;
            store_state(&self.state_path, &self.state)?;
        }
        Ok(())
    }

    /// Admit only current peer/VNI pairs on the authenticated WireGuard
    /// interface, then bind the peer mark to the one current VXLAN device for
    /// each realm. The VNI field is read from the VXLAN header before Linux's
    /// VXLAN socket lookup, so unknown/stale VNI and nonparticipant-peer drops
    /// are counted instead of disappearing inside the kernel. The bridge
    /// check remains a second guard after decapsulation, where the VXLAN device
    /// itself is the structural realm discriminator. Both rule sets are
    /// derived from durable plans and are not a second placement authority.
    pub(crate) fn reconcile_ingress_auth(&mut self) -> Result<(), LinuxFabricError> {
        let Some(mut fabric) = self.state.fabric.clone() else {
            return Err(LinuxFabricError::CorruptState);
        };
        let mut admissions = BTreeSet::<(Ipv4Addr, u32, u64)>::new();
        let mut wireguard_vni_admissions = BTreeSet::<(Ipv4Addr, u32)>::new();
        let mut vni_admissions = BTreeSet::<(String, Ipv4Addr, u32)>::new();
        for plan in self
            .plans
            .values()
            .filter(|plan| self.state.realms.contains_key(&plan.realm_id))
        {
            let Some(vxlan) = self
                .state
                .realms
                .get(&plan.realm_id)
                .and_then(|realm| realm.vxlan.as_ref())
            else {
                return Err(LinuxFabricError::CorruptState);
            };
            for peer in &plan.peers {
                admissions.insert((
                    peer.fabric_transport_ip,
                    plan.encapsulation.provider_segment_id,
                    peer.fabric_generation,
                ));
                vni_admissions.insert((
                    vxlan.interface.clone(),
                    peer.fabric_transport_ip,
                    vxlan.vni,
                ));
                wireguard_vni_admissions.insert((peer.fabric_transport_ip, vxlan.vni));
            }
        }
        let auth_fingerprint = format!(
            "{:x}",
            Sha256::digest(
                serde_json::to_vec(&("wireguard-vni-ingress-v2", &admissions))
                    .map_err(|_| LinuxFabricError::CorruptState)?,
            )
        );
        let vni_fingerprint = format!(
            "{:x}",
            Sha256::digest(
                serde_json::to_vec(&("vni-admission-v3", &vni_admissions))
                    .map_err(|_| LinuxFabricError::CorruptState,)?
            )
        );
        const AUTH_TABLE: &str = "o3k-fabric-auth";
        const VNI_TABLE: &str = "o3k-fabric-vni-auth";
        const CHAIN: &str = "ingress";
        const FORWARD_CHAIN: &str = "forward";
        const AUTH_MARKER: &str = "o3k-fabric-auth";
        const VNI_MARKER: &str = "o3k-fabric-vni-auth";
        let ns = fabric.namespace.as_str();
        let listed_auth = self
            .command
            .output(
                "ip",
                &[
                    "netns", "exec", ns, "nft", "list", "table", "netdev", AUTH_TABLE,
                ],
            )
            .map_err(LinuxFabricError::Storage)?;
        let listed_vni = self
            .command
            .output(
                "ip",
                &[
                    "netns", "exec", ns, "nft", "list", "table", "bridge", VNI_TABLE,
                ],
            )
            .map_err(LinuxFabricError::Storage)?;
        let legacy_auth_marker = format!("{AUTH_MARKER}:{}", fabric.ingress_auth_fingerprint);
        let legacy_vni_marker = format!("{VNI_MARKER}:{}", fabric.ingress_vni_fingerprint);
        let legacy_markers_match = listed_auth.0
            && listed_vni.0
            && !fabric.ingress_auth_fingerprint.is_empty()
            && !fabric.ingress_vni_fingerprint.is_empty()
            && nft_chain_has_comment(&listed_auth.1, CHAIN, &legacy_auth_marker)
            && nft_chain_has_comment(&listed_vni.1, FORWARD_CHAIN, &legacy_vni_marker)
            && nft_chain_has_fail_closed_hook(
                &listed_auth.1,
                CHAIN,
                "ingress",
                Some(&fabric.interface),
            )
            && nft_chain_has_fail_closed_hook(&listed_vni.1, FORWARD_CHAIN, "forward", None);
        let legacy_migration = fabric.ingress_owner_token.is_empty() && legacy_markers_match;
        if fabric.ingress_owner_token.is_empty() {
            // Older v3 state predated the durable random nft owner token. It
            // is safe to initialize one before the next mutation when both
            // tables are absent, or to migrate only the exact fingerprints
            // durably recorded by that older provider state.
            if (listed_auth.0 || listed_vni.0) && !legacy_migration {
                return Err(LinuxFabricError::ForeignState);
            }
            fabric.ingress_owner_token = Uuid::new_v4().simple().to_string();
            if let Some(stored) = self.state.fabric.as_mut() {
                stored.ingress_owner_token = fabric.ingress_owner_token.clone();
            }
            store_state(&self.state_path, &self.state)?;
        }
        if fabric.ingress_owner_token.len() != 32
            || !fabric
                .ingress_owner_token
                .bytes()
                .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte))
        {
            return Err(LinuxFabricError::ForeignState);
        }
        let auth_marker = format!(
            "{AUTH_MARKER}:{}:{auth_fingerprint}",
            fabric.ingress_owner_token
        );
        let vni_marker = format!(
            "{VNI_MARKER}:{}:{vni_fingerprint}",
            fabric.ingress_owner_token
        );
        let previous_auth_marker = format!(
            "{AUTH_MARKER}:{}:{}",
            fabric.ingress_owner_token, fabric.ingress_auth_fingerprint
        );
        let previous_vni_marker = format!(
            "{VNI_MARKER}:{}:{}",
            fabric.ingress_owner_token, fabric.ingress_vni_fingerprint
        );
        let auth_table_marker = format!("{AUTH_MARKER}-table:{}", fabric.ingress_owner_token);
        let vni_table_marker = format!("{VNI_MARKER}-table:{}", fabric.ingress_owner_token);
        let owned_auth_table =
            listed_auth.0 && nft_table_has_owner_marker(&listed_auth.1, &auth_table_marker);
        let owned_vni_table =
            listed_vni.0 && nft_table_has_owner_marker(&listed_vni.1, &vni_table_marker);
        let auth_chain_current = nft_chain_has_comment(&listed_auth.1, CHAIN, &auth_marker)
            && nft_chain_has_fail_closed_hook(
                &listed_auth.1,
                CHAIN,
                "ingress",
                Some(&fabric.interface),
            );
        let auth_chain_previous =
            nft_chain_has_comment(&listed_auth.1, CHAIN, &previous_auth_marker)
                && nft_chain_has_fail_closed_hook(
                    &listed_auth.1,
                    CHAIN,
                    "ingress",
                    Some(&fabric.interface),
                );
        let vni_chain_current = nft_chain_has_comment(&listed_vni.1, FORWARD_CHAIN, &vni_marker)
            && nft_chain_has_fail_closed_hook(&listed_vni.1, FORWARD_CHAIN, "forward", None);
        let vni_chain_previous =
            nft_chain_has_comment(&listed_vni.1, FORWARD_CHAIN, &previous_vni_marker)
                && nft_chain_has_fail_closed_hook(&listed_vni.1, FORWARD_CHAIN, "forward", None);
        if listed_auth.0
            && !owned_auth_table
            && !auth_chain_current
            && !auth_chain_previous
            && !(fabric.ingress_auth_fingerprint.is_empty()
                && nft_chain_has_owner_marker(
                    &listed_auth.1,
                    CHAIN,
                    AUTH_MARKER,
                    &fabric.ingress_owner_token,
                    "ingress",
                    Some(&fabric.interface),
                ))
            && !(legacy_migration
                && nft_chain_has_comment(&listed_auth.1, CHAIN, &legacy_auth_marker)
                && nft_chain_has_fail_closed_hook(
                    &listed_auth.1,
                    CHAIN,
                    "ingress",
                    Some(&fabric.interface),
                ))
        {
            return Err(LinuxFabricError::ForeignState);
        }
        if listed_vni.0
            && !owned_vni_table
            && !vni_chain_current
            && !vni_chain_previous
            && !(fabric.ingress_vni_fingerprint.is_empty()
                && nft_chain_has_owner_marker(
                    &listed_vni.1,
                    FORWARD_CHAIN,
                    VNI_MARKER,
                    &fabric.ingress_owner_token,
                    "forward",
                    None,
                ))
            && !(legacy_migration
                && nft_chain_has_comment(&listed_vni.1, FORWARD_CHAIN, &legacy_vni_marker)
                && nft_chain_has_fail_closed_hook(&listed_vni.1, FORWARD_CHAIN, "forward", None))
        {
            return Err(LinuxFabricError::ForeignState);
        }
        if auth_chain_current && vni_chain_current {
            if let Some(stored) = self.state.fabric.as_mut() {
                stored.ingress_auth_fingerprint = auth_fingerprint;
                stored.ingress_vni_fingerprint = vni_fingerprint;
            }
            store_state(&self.state_path, &self.state)?;
            return Ok(());
        }
        // Replace both ingress guards in one nftables transaction. nft -f
        // applies a batch atomically, so process death or an unknown command
        // outcome leaves either the old pair or the new pair installed. The
        // base-chain policies are drop in both versions; no intermediate
        // accept-all window is possible.
        let mut batch = String::new();
        if listed_auth.0 {
            batch.push_str(&format!("delete table netdev {AUTH_TABLE}\n"));
        }
        if listed_vni.0 {
            batch.push_str(&format!("delete table bridge {VNI_TABLE}\n"));
        }
        batch.push_str(&format!(
            "add table netdev {AUTH_TABLE} {{ comment \"{auth_table_marker}\"; }}\n\
             add chain netdev {AUTH_TABLE} {CHAIN} {{ type filter hook ingress device \"{}\" priority -500; policy drop; comment \"{}\"; }}\n",
            fabric.interface, auth_marker
        ));
        for (peer_ip, vni) in wireguard_vni_admissions {
            let source = peer_ip.to_string();
            let mark = u32::from(peer_ip).max(1).to_string();
            batch.push_str(&format!(
                "add rule netdev {AUTH_TABLE} {CHAIN} iifname \"{}\" udp dport 4789 @th,96,24 {} ip saddr {} meta mark set {} counter accept comment \"{}\"\n",
                fabric.interface, vni, source, mark, AUTH_MARKER
            ));
        }
        batch.push_str(&format!(
            "add rule netdev {AUTH_TABLE} {CHAIN} counter drop comment \"{}\"\n\
             add table bridge {VNI_TABLE} {{ comment \"{vni_table_marker}\"; }}\n\
             add chain bridge {VNI_TABLE} {FORWARD_CHAIN} {{ type filter hook forward priority -500; policy drop; comment \"{}\"; }}\n",
            AUTH_MARKER, vni_marker
        ));
        for (realm_id, realm) in &self.state.realms {
            let Some(vxlan) = realm.vxlan.as_ref() else {
                return Err(LinuxFabricError::CorruptState);
            };
            let Some(plan) = self.plans.get(realm_id) else {
                return Err(LinuxFabricError::CorruptState);
            };
            // This is the provider bridge's local realm-facing port. Frames
            // arrive here only after crossing the paired root consumer port,
            // where the realm TAP anti-spoof chain validates source identity.
            // Decapsulated remote frames enter through `vxlan.interface` and
            // must match the peer/VNI mark rule below.
            let fabric_port = vxlan.fabric_veth.as_str();
            batch.push_str(&format!(
                "add rule bridge {VNI_TABLE} {FORWARD_CHAIN} iifname \"{}\" counter accept comment \"{}\"\n",
                fabric_port, VNI_MARKER
            ));
            for peer in &plan.peers {
                let mark = u32::from(peer.fabric_transport_ip).max(1).to_string();
                batch.push_str(&format!(
                    "add rule bridge {VNI_TABLE} {FORWARD_CHAIN} iifname \"{}\" meta mark {} counter accept comment \"{}\"\n",
                    vxlan.interface, mark, VNI_MARKER
                ));
            }
        }
        // Keep the bridge chain fail-closed while making rejected
        // authenticated-peer/VNI combinations observable. This terminal rule
        // is provider-owned with the chain and is rebuilt from the same
        // durable admission fingerprint as its accept rules.
        batch.push_str(&format!(
            "add rule bridge {VNI_TABLE} {FORWARD_CHAIN} counter drop comment \"{}\"\n",
            VNI_MARKER
        ));
        if !self
            .command
            .run_with_input(
                "ip",
                &["netns", "exec", ns, "nft", "-f", "-"],
                batch.as_bytes(),
            )
            .map_err(LinuxFabricError::Storage)?
        {
            return Err(LinuxFabricError::CommandFailed);
        }
        if let Some(stored) = self.state.fabric.as_mut() {
            stored.ingress_auth_fingerprint = auth_fingerprint;
            stored.ingress_vni_fingerprint = vni_fingerprint;
        }
        store_state(&self.state_path, &self.state)
    }
    pub(crate) fn remove_fabric_if_unused(
        &mut self,
        generation: u64,
    ) -> Result<(), LinuxFabricError> {
        if !self.state.realms.is_empty() {
            return Ok(());
        }
        let Some(fabric) = self.state.fabric.clone() else {
            return Ok(());
        };
        if generation < fabric.fabric_generation {
            return Err(LinuxFabricError::OwnershipConflict);
        }
        let mut nft_cleanup = String::new();
        {
            let listed_auth = self
                .command
                .output(
                    "ip",
                    &[
                        "netns",
                        "exec",
                        fabric.namespace.as_str(),
                        "nft",
                        "list",
                        "table",
                        "netdev",
                        "o3k-fabric-auth",
                    ],
                )
                .map_err(LinuxFabricError::Storage)?;
            let marker = format!(
                "o3k-fabric-auth:{}:{}",
                fabric.ingress_owner_token, fabric.ingress_auth_fingerprint
            );
            let table_marker = format!("o3k-fabric-auth-table:{}", fabric.ingress_owner_token);
            if listed_auth.0
                && !nft_table_has_owner_marker(&listed_auth.1, &table_marker)
                && !(nft_chain_has_comment(&listed_auth.1, "ingress", &marker)
                    && nft_chain_has_fail_closed_hook(
                        &listed_auth.1,
                        "ingress",
                        "ingress",
                        Some(&fabric.interface),
                    ))
                && !(fabric.ingress_auth_fingerprint.is_empty()
                    && nft_chain_has_owner_marker(
                        &listed_auth.1,
                        "ingress",
                        "o3k-fabric-auth",
                        &fabric.ingress_owner_token,
                        "ingress",
                        Some(&fabric.interface),
                    ))
                && !(fabric.ingress_owner_token.is_empty()
                    && !fabric.ingress_auth_fingerprint.is_empty()
                    && nft_chain_has_comment(
                        &listed_auth.1,
                        "ingress",
                        &format!("o3k-fabric-auth:{}", fabric.ingress_auth_fingerprint),
                    )
                    && nft_chain_has_fail_closed_hook(
                        &listed_auth.1,
                        "ingress",
                        "ingress",
                        Some(&fabric.interface),
                    ))
            {
                return Err(LinuxFabricError::ForeignState);
            }
            if listed_auth.0 {
                nft_cleanup.push_str("delete table netdev o3k-fabric-auth\n");
            }
        }
        {
            let listed_vni = self
                .command
                .output(
                    "ip",
                    &[
                        "netns",
                        "exec",
                        fabric.namespace.as_str(),
                        "nft",
                        "list",
                        "table",
                        "bridge",
                        "o3k-fabric-vni-auth",
                    ],
                )
                .map_err(LinuxFabricError::Storage)?;
            let marker = format!(
                "o3k-fabric-vni-auth:{}:{}",
                fabric.ingress_owner_token, fabric.ingress_vni_fingerprint
            );
            let table_marker = format!("o3k-fabric-vni-auth-table:{}", fabric.ingress_owner_token);
            if listed_vni.0
                && !nft_table_has_owner_marker(&listed_vni.1, &table_marker)
                && !(nft_chain_has_comment(&listed_vni.1, "forward", &marker)
                    && nft_chain_has_fail_closed_hook(&listed_vni.1, "forward", "forward", None))
                && !(fabric.ingress_vni_fingerprint.is_empty()
                    && nft_chain_has_owner_marker(
                        &listed_vni.1,
                        "forward",
                        "o3k-fabric-vni-auth",
                        &fabric.ingress_owner_token,
                        "forward",
                        None,
                    ))
                && !(fabric.ingress_owner_token.is_empty()
                    && !fabric.ingress_vni_fingerprint.is_empty()
                    && nft_chain_has_comment(
                        &listed_vni.1,
                        "forward",
                        &format!("o3k-fabric-vni-auth:{}", fabric.ingress_vni_fingerprint),
                    )
                    && nft_chain_has_fail_closed_hook(&listed_vni.1, "forward", "forward", None))
            {
                return Err(LinuxFabricError::ForeignState);
            }
            if listed_vni.0 {
                nft_cleanup.push_str("delete table bridge o3k-fabric-vni-auth\n");
            }
        }
        if !nft_cleanup.is_empty()
            && !self
                .command
                .run_with_input(
                    "ip",
                    &["netns", "exec", fabric.namespace.as_str(), "nft", "-f", "-"],
                    nft_cleanup.as_bytes(),
                )
                .map_err(LinuxFabricError::Storage)?
        {
            return Err(LinuxFabricError::CommandFailed);
        }
        // wg-o3k is in the fabric namespace.
        let (ns_exists, _) = self
            .command
            .output("ip", &["netns", "exec", &fabric.namespace, "true"])
            .map_err(LinuxFabricError::Storage)?;
        if ns_exists {
            let (wg_exists, _) = self
                .command
                .output(
                    "ip",
                    &[
                        "netns",
                        "exec",
                        &fabric.namespace,
                        "ip",
                        "link",
                        "show",
                        "dev",
                        &fabric.interface,
                    ],
                )
                .map_err(LinuxFabricError::Storage)?;
            if wg_exists
                && !self
                    .command
                    .run(
                        "ip",
                        &[
                            "netns",
                            "exec",
                            &fabric.namespace,
                            "ip",
                            "link",
                            "del",
                            &fabric.interface,
                        ],
                    )
                    .map_err(LinuxFabricError::Storage)?
            {
                return Err(LinuxFabricError::CommandFailed);
            }
        }
        let _ = self.command.output("ip", &["link", "del", "o3k-u"]);
        self.remove_iptables_rule(&["POSTROUTING", "-s", "169.254.253.0/30", "-j", "MASQUERADE"])?;
        let wg_port = self.config.wireguard_port.to_string();
        self.remove_iptables_rule(&[
            "PREROUTING",
            "!",
            "-i",
            "o3k-u",
            "-p",
            "udp",
            "--dport",
            &wg_port,
            "-j",
            "DNAT",
            "--to-destination",
            "169.254.253.2",
        ])?;
        let _ = self.command.run("ip", &["netns", "del", &fabric.namespace]);
        // The WireGuard private key is provisioned host identity material
        // and intentionally survives fabric removal so planned peer public
        // keys stay valid across teardown and crash recovery.
        self.state.fabric = None;
        store_state(&self.state_path, &self.state)?;
        Ok(())
    }
}

#[cfg(test)]
mod nft_ownership_tests {
    use super::{nft_chain_has_comment, nft_chain_has_owner_marker, nft_table_has_owner_marker};

    #[test]
    fn nft_table_ownership_survives_device_bound_chain_removal() {
        let listing = r#"table netdev o3k-fabric-auth {
	comment "o3k-fabric-auth-table:fedcba9876543210fedcba9876543210"
}"#;
        assert!(nft_table_has_owner_marker(
            listing,
            "o3k-fabric-auth-table:fedcba9876543210fedcba9876543210"
        ));
        assert!(!nft_table_has_owner_marker(
            listing,
            "o3k-fabric-auth-table:00000000000000000000000000000000"
        ));
        assert!(!nft_table_has_owner_marker(
            &listing.replace("\tcomment", "\tchain foreign {\n\t\tcomment"),
            "o3k-fabric-auth-table:fedcba9876543210fedcba9876543210"
        ));
    }

    #[test]
    fn nft_ownership_requires_the_exact_expected_chain_comment() {
        let listing = r#"table netdev o3k-fabric-auth {
	chain ingress {
		comment "o3k-fabric-auth:abc123"
		type filter hook ingress device "o3k-wg" priority -500; policy drop;
		counter packets 0 bytes 0 drop comment "o3k-fabric-auth"
	}
}"#;
        assert!(nft_chain_has_comment(
            listing,
            "ingress",
            "o3k-fabric-auth:abc123"
        ));
        assert!(!nft_chain_has_comment(
            listing,
            "ingress",
            "o3k-fabric-auth:other"
        ));
        assert!(!nft_chain_has_comment(
            listing,
            "forward",
            "o3k-fabric-auth:abc123"
        ));
        assert!(!nft_chain_has_comment(
            &listing.replace(
                "comment \"o3k-fabric-auth:abc123\"",
                "counter packets 0 bytes 0 accept comment \"o3k-fabric-auth:abc123\""
            ),
            "ingress",
            "o3k-fabric-auth:abc123"
        ));
    }

    #[test]
    fn nft_recovery_requires_durable_random_token_and_fail_closed_expected_hook() {
        let listing = r#"table netdev o3k-fabric-auth {
    chain ingress {
        comment "o3k-fabric-auth:fedcba9876543210fedcba9876543210:0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef"
        type filter hook ingress device "o3k-wg" priority -500; policy drop;
    }
}"#;
        assert!(nft_chain_has_owner_marker(
            listing,
            "ingress",
            "o3k-fabric-auth",
            "fedcba9876543210fedcba9876543210",
            "ingress",
            Some("o3k-wg")
        ));
        assert!(!nft_chain_has_owner_marker(
            listing,
            "ingress",
            "o3k-fabric-auth",
            "00000000000000000000000000000000",
            "ingress",
            Some("foreign-wg")
        ));
        assert!(!nft_chain_has_owner_marker(
            &listing.replace("policy drop", "policy accept"),
            "ingress",
            "o3k-fabric-auth",
            "fedcba9876543210fedcba9876543210",
            "ingress",
            Some("o3k-wg")
        ));
        assert!(!nft_chain_has_owner_marker(
            &listing.replace("0123456789abcdef", "bad"),
            "ingress",
            "o3k-fabric-auth",
            "fedcba9876543210fedcba9876543210",
            "ingress",
            Some("o3k-wg")
        ));
        assert!(!nft_chain_has_owner_marker(
            &listing.replace(
                "comment \"o3k-fabric-auth:fedcba9876543210fedcba9876543210:0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef\"",
                "counter drop comment \"o3k-fabric-auth:fedcba9876543210fedcba9876543210:0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef\""
            ),
            "ingress",
            "o3k-fabric-auth",
            "fedcba9876543210fedcba9876543210",
            "ingress",
            Some("o3k-wg")
        ));
    }
}
