use super::*;

impl super::LinuxFabricBackend {
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
        let _ = self.command.run("ip", &["link", "del", "o3k-u"]);
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
        let _ = self.command.run(
            "iptables",
            &[
                "-t",
                "nat",
                "-A",
                "POSTROUTING",
                "-s",
                "169.254.253.0/30",
                "-j",
                "MASQUERADE",
            ],
        );
        // DNAT incoming WireGuard UDP to the fabric namespace.
        let wg_port = self.config.wireguard_port.to_string();
        let _ = self.command.run(
            "iptables",
            &[
                "-t",
                "nat",
                "-A",
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
            ],
        );
        self.state.fabric = Some(FabricOwnership {
            namespace: self.config.fabric_namespace.clone(),
            interface: self.config.fabric_interface.clone(),
            private_key_path: private_key_path.display().to_string(),
            fabric_transport_ip: plan.local_fabric_transport_ip,
            fabric_generation: plan.local_fabric_generation,
            fabric_mtu: plan.local_fabric_mtu,
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
        let _ = self.command.run("ip", &["link", "del", "o3k-u"]);
        let _ = self.command.run(
            "iptables",
            &[
                "-t",
                "nat",
                "-D",
                "POSTROUTING",
                "-s",
                "169.254.253.0/30",
                "-j",
                "MASQUERADE",
            ],
        );
        let wg_port = self.config.wireguard_port.to_string();
        for rule in [
            vec![
                "-t",
                "nat",
                "-D",
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
            ],
            vec![
                "-t",
                "nat",
                "-D",
                "PREROUTING",
                "-p",
                "udp",
                "--dport",
                &wg_port,
                "-j",
                "DNAT",
                "--to-destination",
                "169.254.253.2",
            ],
        ] {
            let _ = self.command.run("iptables", &rule);
        }
        let _ = self.command.run("ip", &["netns", "del", &fabric.namespace]);
        // The WireGuard private key is provisioned host identity material
        // and intentionally survives fabric removal so planned peer public
        // keys stay valid across teardown and crash recovery.
        self.state.fabric = None;
        store_state(&self.state_path, &self.state)?;
        Ok(())
    }
}
