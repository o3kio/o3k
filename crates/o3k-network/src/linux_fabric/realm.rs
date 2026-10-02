use super::*;

impl super::LinuxFabricBackend {
    pub(crate) fn realm_ownership(&self, plan: &NamespacedRoutedFabricPlan) -> RealmOwnership {
        let suffix = plan.realm_id.simple().to_string();
        RealmOwnership {
            realm_id: plan.realm_id,
            namespace: format!("o3k-r-{}", &suffix[..8]),
            bridge: format!("o3k-b-{}", &suffix[..8]),
            host_veth: format!("o3k-h-{}", &suffix[..8]),
            realm_veth: format!("o3k-n-{}", &suffix[..8]),
            // The v3 VXLAN bridge uses its own per-realm root/fabric veth
            // pair.  These legacy v2 fan-out fields remain in the durable
            // shape only so old state can be rejected rather than adopted.
            fabric_veth: String::new(),
            fabric_realm_veth: String::new(),
            public_host_veth: format!("o3k-p-{}", &suffix[..8]),
            public_realm_veth: format!("o3k-q-{}", &suffix[..8]),
            geneve: BTreeMap::new(),
            vxlan: None,
            attachments: BTreeMap::new(),
            endpoint_taps: BTreeMap::new(),
            pending_endpoint_taps: BTreeMap::new(),
            policy_generation: 0,
            policy_fingerprint: String::new(),
            anti_spoof_generation: 0,
            anti_spoof_fingerprint: String::new(),
            public_generation: 0,
            public_fingerprint: String::new(),
            public_mark: 0,
            public_route_table: 0,
            public_addresses: Vec::new(),
            directory_generation: plan.directory_generation,
            local_fabric_generation: plan.local_fabric_generation,
        }
    }
    pub(crate) fn ensure_realm(
        &mut self,
        plan: &NamespacedRoutedFabricPlan,
    ) -> Result<(), LinuxFabricError> {
        let mut ownership = self.realm_ownership(plan);
        if let Some(existing) = self.state.realms.get(&plan.realm_id) {
            ownership.geneve = existing.geneve.clone();
            ownership.vxlan = existing.vxlan.clone();
            ownership.attachments = existing.attachments.clone();
            ownership.endpoint_taps = existing.endpoint_taps.clone();
            ownership.pending_endpoint_taps = existing.pending_endpoint_taps.clone();
            ownership.policy_generation = existing.policy_generation;
            ownership.policy_fingerprint = existing.policy_fingerprint.clone();
            ownership.anti_spoof_generation = existing.anti_spoof_generation;
            ownership.anti_spoof_fingerprint = existing.anti_spoof_fingerprint.clone();
            if !existing.public_host_veth.is_empty() {
                ownership.public_host_veth = existing.public_host_veth.clone();
            }
            if !existing.public_realm_veth.is_empty() {
                ownership.public_realm_veth = existing.public_realm_veth.clone();
            }
            ownership.public_generation = existing.public_generation;
            ownership.public_fingerprint = existing.public_fingerprint.clone();
            ownership.public_mark = existing.public_mark;
            ownership.public_route_table = existing.public_route_table;
            ownership.public_addresses = existing.public_addresses.clone();
        }
        if let Some(existing) = self.state.realms.get(&plan.realm_id)
            && (existing.namespace != ownership.namespace
                || existing.bridge != ownership.bridge
                || existing.host_veth != ownership.host_veth
                || existing.realm_veth != ownership.realm_veth
                || existing.fabric_veth != ownership.fabric_veth
                || existing.fabric_realm_veth != ownership.fabric_realm_veth
                || existing.public_host_veth != ownership.public_host_veth
                || existing.public_realm_veth != ownership.public_realm_veth
                || plan.directory_generation < existing.directory_generation
                || plan.local_fabric_generation < existing.local_fabric_generation)
        {
            return Err(LinuxFabricError::OwnershipConflict);
        }
        // If state says we own this realm but the bridge is gone (e.g. after a
        // crash or test fabric-interruption), clean up stale state so the
        // creation block below runs and recreates everything from scratch.
        if self.state.realms.contains_key(&plan.realm_id) {
            let (bridge_exists, _) = self
                .command
                .output("ip", &["link", "show", "dev", &ownership.bridge])
                .map_err(LinuxFabricError::Storage)?;
            if !bridge_exists {
                let _ = self
                    .command
                    .run("ip", &["netns", "delete", &ownership.namespace]);
                self.state.realms.remove(&plan.realm_id);
                store_state(&self.state_path, &self.state)?;
            }
        }
        if !self.state.realms.contains_key(&plan.realm_id) {
            let (exists, _) = self
                .command
                .output("ip", &["netns", "exec", &ownership.namespace, "true"])
                .map_err(LinuxFabricError::Storage)?;
            if exists {
                return Err(LinuxFabricError::ForeignState);
            }
            for interface in [
                &ownership.bridge,
                &ownership.host_veth,
                &ownership.realm_veth,
            ] {
                let (interface_exists, _) = self
                    .command
                    .output("ip", &["link", "show", "dev", interface])
                    .map_err(LinuxFabricError::Storage)?;
                if interface_exists {
                    return Err(LinuxFabricError::ForeignState);
                }
            }
            self.state.realms.insert(plan.realm_id, ownership.clone());
            store_state(&self.state_path, &self.state)?;
            let commands = [
                vec!["netns", "add", ownership.namespace.as_str()],
                vec!["link", "add", ownership.bridge.as_str(), "type", "bridge"],
                vec!["link", "set", ownership.bridge.as_str(), "up"],
                vec![
                    "link",
                    "add",
                    ownership.host_veth.as_str(),
                    "type",
                    "veth",
                    "peer",
                    "name",
                    ownership.realm_veth.as_str(),
                ],
                vec![
                    "link",
                    "set",
                    ownership.realm_veth.as_str(),
                    "netns",
                    ownership.namespace.as_str(),
                ],
                vec![
                    "link",
                    "set",
                    ownership.host_veth.as_str(),
                    "master",
                    ownership.bridge.as_str(),
                ],
                vec!["link", "set", ownership.host_veth.as_str(), "up"],
            ];
            for args in commands {
                if !self
                    .command
                    .run("ip", &args)
                    .map_err(LinuxFabricError::Storage)?
                {
                    return Err(LinuxFabricError::CommandFailed);
                }
            }
            if !self
                .command
                .run(
                    "ip",
                    &[
                        "netns",
                        "exec",
                        &ownership.namespace,
                        "ip",
                        "link",
                        "set",
                        &ownership.realm_veth,
                        "up",
                    ],
                )
                .map_err(LinuxFabricError::Storage)?
            {
                return Err(LinuxFabricError::CommandFailed);
            }
            if !self
                .command
                .run(
                    "ip",
                    &[
                        "netns",
                        "exec",
                        &ownership.namespace,
                        "sysctl",
                        "-w",
                        "net.ipv4.ip_forward=1",
                    ],
                )
                .map_err(LinuxFabricError::Storage)?
            {
                return Err(LinuxFabricError::CommandFailed);
            }
        } else if self.state.realms.get(&plan.realm_id) != Some(&ownership) {
            self.state.realms.insert(plan.realm_id, ownership.clone());
            store_state(&self.state_path, &self.state)?;
        }
        let tenant_mtu = plan.tenant_mtu.to_string();
        let gateway = u32::from(plan.realm_prefix.network)
            .checked_add(1)
            .map(std::net::Ipv4Addr::from)
            .filter(|gateway| plan.realm_prefix.contains(*gateway))
            .ok_or(LinuxFabricError::OwnershipConflict)?;
        let gateway_cidr = format!("{gateway}/{}", plan.realm_prefix.prefix_len);
        if !self
            .command
            .run(
                "ip",
                &[
                    "netns",
                    "exec",
                    &ownership.namespace,
                    "ip",
                    "addr",
                    "replace",
                    &gateway_cidr,
                    "dev",
                    &ownership.realm_veth,
                ],
            )
            .map_err(LinuxFabricError::Storage)?
        {
            return Err(LinuxFabricError::CommandFailed);
        }
        for interface in [&ownership.bridge, &ownership.host_veth] {
            if !self
                .command
                .run("ip", &["link", "set", "dev", interface, "mtu", &tenant_mtu])
                .map_err(LinuxFabricError::Storage)?
            {
                return Err(LinuxFabricError::CommandFailed);
            }
        }
        for (namespace, interface, mtu) in [(
            ownership.namespace.as_str(),
            ownership.realm_veth.as_str(),
            tenant_mtu.as_str(),
        )] {
            if !self
                .command
                .run(
                    "ip",
                    &[
                        "netns", "exec", namespace, "ip", "link", "set", "dev", interface, "mtu",
                        mtu,
                    ],
                )
                .map_err(LinuxFabricError::Storage)?
            {
                return Err(LinuxFabricError::CommandFailed);
            }
        }
        Ok(())
    }
    pub(crate) fn realize_routes(
        &self,
        plan: &NamespacedRoutedFabricPlan,
        ownership: &RealmOwnership,
    ) -> Result<(), LinuxFabricError> {
        // P11 v3 is a literal stretched L2 segment.  Remote endpoint
        // reachability is provided by VXLAN learning/HER and real guest ARP;
        // v2 per-peer /32 routes and synthetic neighbor entries must not be
        // recreated.  The routed realm gateway remains available for the
        // existing north/south provider path, but it is not used to steer
        // same-realm traffic.
        if ownership.vxlan.is_some() {
            return Ok(());
        }
        for route in &plan.routes {
            let attachment = ownership
                .attachments
                .get(&route.target_host)
                .ok_or(LinuxFabricError::CorruptState)?;
            let destination = format!("{}/32", route.destination.network);
            if !self
                .command
                .run(
                    "ip",
                    &[
                        "netns",
                        "exec",
                        &ownership.namespace,
                        "ip",
                        "route",
                        "replace",
                        &destination,
                        "dev",
                        &attachment.realm_veth,
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
                            &ownership.namespace,
                            "ip",
                            "neigh",
                            "replace",
                            &route.destination.network.to_string(),
                            "lladdr",
                            &attachment.remote_tunnel_mac,
                            "nud",
                            "permanent",
                            "dev",
                            &attachment.realm_veth,
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
                            &ownership.namespace,
                            "ip",
                            "neigh",
                            "replace",
                            "proxy",
                            &route.destination.network.to_string(),
                            "dev",
                            &ownership.realm_veth,
                        ],
                    )
                    .map_err(LinuxFabricError::Storage)?
            {
                return Err(LinuxFabricError::CommandFailed);
            }
        }
        Ok(())
    }
    pub(crate) fn ensure_endpoint_taps(
        &mut self,
        plan: &NamespacedRoutedFabricPlan,
    ) -> Result<(), LinuxFabricError> {
        let Some(current) = self.state.realms.get(&plan.realm_id).cloned() else {
            return Err(LinuxFabricError::CorruptState);
        };
        let desired = plan
            .directory
            .entries
            .iter()
            .filter(|entry| entry.selected_host == plan.local_host)
            .map(|entry| {
                (
                    entry.endpoint_id,
                    EndpointTapOwnership {
                        endpoint_id: entry.endpoint_id,
                        interface: endpoint_tap_name(plan.realm_id, entry.endpoint_id),
                        mac: endpoint_tap_mac(plan.realm_id, entry.endpoint_id),
                    },
                )
            })
            .collect::<BTreeMap<_, _>>();
        if !current.pending_endpoint_taps.is_empty() && current.pending_endpoint_taps != desired {
            return Err(LinuxFabricError::OwnershipConflict);
        }
        if current.endpoint_taps != desired && current.pending_endpoint_taps.is_empty() {
            let mut pending = current.clone();
            pending.pending_endpoint_taps = desired.clone();
            self.state.realms.insert(plan.realm_id, pending);
            store_state(&self.state_path, &self.state)?;
        }
        for (endpoint_id, old) in &current.endpoint_taps {
            if desired.contains_key(endpoint_id) {
                continue;
            }
            self.remove_endpoint_tap(old, &current.bridge)?;
        }
        for wanted in desired.values() {
            if let Some(existing) = current.endpoint_taps.get(&wanted.endpoint_id)
                && existing != wanted
            {
                return Err(LinuxFabricError::OwnershipConflict);
            }
            let (exists, output) = self
                .command
                .output("ip", &["-d", "link", "show", "dev", &wanted.interface])
                .map_err(LinuxFabricError::Storage)?;
            if exists && !tap_link_matches(&output, wanted, &current.bridge) {
                return Err(LinuxFabricError::ForeignState);
            }
            if exists
                && !current.endpoint_taps.contains_key(&wanted.endpoint_id)
                && !current
                    .pending_endpoint_taps
                    .contains_key(&wanted.endpoint_id)
            {
                return Err(LinuxFabricError::ForeignState);
            }
            if !exists {
                for args in [
                    vec![
                        "tuntap",
                        "add",
                        "dev",
                        wanted.interface.as_str(),
                        "mode",
                        "tap",
                    ],
                    vec![
                        "link",
                        "set",
                        "dev",
                        wanted.interface.as_str(),
                        "address",
                        wanted.mac.as_str(),
                    ],
                    vec![
                        "link",
                        "set",
                        "dev",
                        wanted.interface.as_str(),
                        "master",
                        current.bridge.as_str(),
                    ],
                    vec!["link", "set", "dev", wanted.interface.as_str(), "up"],
                ] {
                    if !self
                        .command
                        .run("ip", &args)
                        .map_err(LinuxFabricError::Storage)?
                    {
                        return Err(LinuxFabricError::CommandFailed);
                    }
                }
            }
        }
        if current.endpoint_taps != desired || !current.pending_endpoint_taps.is_empty() {
            let mut next = self
                .state
                .realms
                .get(&plan.realm_id)
                .cloned()
                .ok_or(LinuxFabricError::CorruptState)?;
            next.endpoint_taps = desired;
            next.pending_endpoint_taps.clear();
            self.state.realms.insert(plan.realm_id, next);
            store_state(&self.state_path, &self.state)?;
        }
        Ok(())
    }
    pub(crate) fn remove_endpoint_tap(
        &self,
        tap: &EndpointTapOwnership,
        bridge: &str,
    ) -> Result<(), LinuxFabricError> {
        let (exists, output) = self
            .command
            .output("ip", &["-d", "link", "show", "dev", &tap.interface])
            .map_err(LinuxFabricError::Storage)?;
        if exists && !tap_link_matches(&output, tap, bridge) {
            return Err(LinuxFabricError::ForeignState);
        }
        if exists
            && !self
                .command
                .run("ip", &["link", "del", "dev", &tap.interface])
                .map_err(LinuxFabricError::Storage)?
        {
            return Err(LinuxFabricError::CommandFailed);
        }
        Ok(())
    }
}
