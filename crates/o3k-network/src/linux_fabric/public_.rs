use super::*;

impl super::LinuxFabricBackend {
    pub(crate) fn ensure_public(
        &mut self,
        plan: &NamespacedRoutedFabricPlan,
    ) -> Result<(), LinuxFabricError> {
        if plan.public_bindings.is_empty() {
            return self.remove_public(plan);
        }
        let uplink = self
            .config
            .public_uplink
            .as_deref()
            .ok_or(LinuxFabricError::InvalidConfiguration)?;
        Self::validate_public_plan(plan)?;
        if self.state.realms.iter().any(|(realm_id, ownership)| {
            *realm_id != plan.realm_id
                && plan
                    .public_bindings
                    .iter()
                    .any(|binding| ownership.public_addresses.contains(&binding.public_address))
        }) {
            return Err(LinuxFabricError::OwnershipConflict);
        }
        let current = self
            .state
            .realms
            .get(&plan.realm_id)
            .cloned()
            .ok_or(LinuxFabricError::CorruptState)?;
        let fingerprint = public_fingerprint(plan).map_err(|_| LinuxFabricError::CorruptState)?;
        let mark = public_mark(plan.realm_id);
        let route_table = public_route_table(plan.realm_id);
        let root_table = public_root_table_name(plan.realm_id);
        let realm_table = public_realm_table_name(plan.realm_id);
        let (root_table_exists, root_listing) = self
            .command
            .output("nft", &["list", "table", "ip", &root_table])
            .map_err(LinuxFabricError::Storage)?;
        if root_table_exists && !root_listing.contains(FABRIC_PUBLIC_MARKER) {
            return Err(LinuxFabricError::ForeignState);
        }
        let (realm_table_exists, realm_listing) = self
            .command
            .output(
                "ip",
                &[
                    "netns",
                    "exec",
                    &current.namespace,
                    "nft",
                    "list",
                    "table",
                    "ip",
                    &realm_table,
                ],
            )
            .map_err(LinuxFabricError::Storage)?;
        if realm_table_exists && !realm_listing.contains(FABRIC_PUBLIC_MARKER) {
            return Err(LinuxFabricError::ForeignState);
        }
        let mut next = current.clone();
        next.public_generation = plan
            .public_bindings
            .iter()
            .map(|binding| binding.generation)
            .max()
            .ok_or(LinuxFabricError::OwnershipConflict)?;
        next.public_fingerprint = fingerprint.clone();
        next.public_mark = mark;
        next.public_route_table = route_table;
        next.public_addresses = plan
            .public_bindings
            .iter()
            .map(|binding| binding.public_address)
            .collect();
        self.state.realms.insert(plan.realm_id, next.clone());
        store_state(&self.state_path, &self.state)?;

        self.ensure_public_veth(&next)?;
        let (root_transit, realm_transit) = public_transit_addresses(plan.realm_id);
        for args in [
            vec![
                "addr",
                "replace",
                &format!("{root_transit}/30"),
                "dev",
                next.public_host_veth.as_str(),
            ],
            vec![
                "netns",
                "exec",
                next.namespace.as_str(),
                "ip",
                "addr",
                "replace",
                &format!("{realm_transit}/30"),
                "dev",
                next.public_realm_veth.as_str(),
            ],
            vec![
                "netns",
                "exec",
                next.namespace.as_str(),
                "ip",
                "route",
                "replace",
                "default",
                "via",
                &root_transit.to_string(),
                "dev",
                next.public_realm_veth.as_str(),
            ],
        ] {
            if !self
                .command
                .run("ip", &args)
                .map_err(LinuxFabricError::Storage)?
            {
                return Err(LinuxFabricError::CommandFailed);
            }
        }
        for binding in &plan.public_bindings {
            let address = format!("{}/32", binding.public_address);
            let public_string = binding.public_address.to_string();
            for args in [
                vec![
                    "route",
                    "replace",
                    "table",
                    &route_table.to_string(),
                    address.as_str(),
                    "via",
                    &realm_transit.to_string(),
                    "dev",
                    next.public_host_veth.as_str(),
                ],
                vec![
                    "neigh",
                    "replace",
                    "proxy",
                    public_string.as_str(),
                    "dev",
                    uplink,
                ],
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
        for key in [
            "net.ipv4.ip_forward=1".to_owned(),
            format!("net.ipv4.conf.{uplink}.proxy_arp=1"),
        ] {
            if !self
                .command
                .run("sysctl", &["-w", key.as_str()])
                .map_err(LinuxFabricError::Storage)?
            {
                return Err(LinuxFabricError::CommandFailed);
            }
        }
        let rule_listing = self
            .command
            .output("ip", &["rule", "list"])
            .map_err(LinuxFabricError::Storage)?;
        let rule = format!("fwmark {mark} lookup {route_table}");
        if (!rule_listing.0 || !rule_listing.1.contains(&rule))
            && !self
                .command
                .run(
                    "ip",
                    &[
                        "rule",
                        "add",
                        "fwmark",
                        &mark.to_string(),
                        "table",
                        &route_table.to_string(),
                    ],
                )
                .map_err(LinuxFabricError::Storage)?
        {
            return Err(LinuxFabricError::CommandFailed);
        }
        if root_table_exists
            && !self
                .command
                .run("nft", &["delete", "table", "ip", &root_table])
                .map_err(LinuxFabricError::Storage)?
        {
            return Err(LinuxFabricError::CommandFailed);
        }
        if realm_table_exists
            && !self
                .command
                .run(
                    "ip",
                    &[
                        "netns",
                        "exec",
                        next.namespace.as_str(),
                        "nft",
                        "delete",
                        "table",
                        "ip",
                        &realm_table,
                    ],
                )
                .map_err(LinuxFabricError::Storage)?
        {
            return Err(LinuxFabricError::CommandFailed);
        }
        let marker = format!("\"{FABRIC_PUBLIC_MARKER}:{fingerprint}\"");
        for args in [
            vec![
                "add",
                "table",
                "ip",
                root_table.as_str(),
                "{",
                "comment",
                marker.as_str(),
                ";",
                "}",
            ],
            vec![
                "add",
                "chain",
                "ip",
                root_table.as_str(),
                "prerouting",
                "{",
                "type",
                "filter",
                "hook",
                "prerouting",
                "priority",
                "-150",
                ";",
                "policy",
                "accept",
                ";",
                "}",
            ],
        ] {
            if !self
                .command
                .run("nft", &args)
                .map_err(LinuxFabricError::Storage)?
            {
                return Err(LinuxFabricError::CommandFailed);
            }
        }
        for binding in &plan.public_bindings {
            let public_address = binding.public_address.to_string();
            let comment = format!(
                "\"{FABRIC_PUBLIC_MARKER}:{}:{}\"",
                plan.realm_id, binding.endpoint_id
            );
            if !self
                .command
                .run(
                    "nft",
                    &[
                        "add",
                        "rule",
                        "ip",
                        &root_table,
                        "prerouting",
                        "iifname",
                        uplink,
                        "ip",
                        "daddr",
                        &public_address,
                        "meta",
                        "mark",
                        "set",
                        &mark.to_string(),
                        "comment",
                        &comment,
                    ],
                )
                .map_err(LinuxFabricError::Storage)?
            {
                return Err(LinuxFabricError::CommandFailed);
            }
        }
        for args in [
            vec![
                "netns",
                "exec",
                next.namespace.as_str(),
                "nft",
                "add",
                "table",
                "ip",
                realm_table.as_str(),
                "{",
                "comment",
                marker.as_str(),
                ";",
                "}",
            ],
            vec![
                "netns",
                "exec",
                next.namespace.as_str(),
                "nft",
                "add",
                "chain",
                "ip",
                realm_table.as_str(),
                "prerouting",
                "{",
                "type",
                "nat",
                "hook",
                "prerouting",
                "priority",
                "-100",
                ";",
                "policy",
                "accept",
                ";",
                "}",
            ],
            vec![
                "netns",
                "exec",
                next.namespace.as_str(),
                "nft",
                "add",
                "chain",
                "ip",
                realm_table.as_str(),
                "postrouting",
                "{",
                "type",
                "nat",
                "hook",
                "postrouting",
                "priority",
                "100",
                ";",
                "policy",
                "accept",
                ";",
                "}",
            ],
        ] {
            if !self
                .command
                .run("ip", &args)
                .map_err(LinuxFabricError::Storage)?
            {
                return Err(LinuxFabricError::CommandFailed);
            }
        }
        for binding in &plan.public_bindings {
            let endpoint = plan
                .directory
                .location(binding.endpoint_id)
                .ok_or(LinuxFabricError::OwnershipConflict)?;
            let public_address = binding.public_address.to_string();
            let private_address = endpoint.fixed_ip.to_string();
            let comment = format!(
                "\"{FABRIC_PUBLIC_MARKER}:{}:{}\"",
                plan.realm_id, binding.endpoint_id
            );
            for args in [
                vec![
                    "netns",
                    "exec",
                    next.namespace.as_str(),
                    "nft",
                    "add",
                    "rule",
                    "ip",
                    realm_table.as_str(),
                    "prerouting",
                    "ip",
                    "daddr",
                    public_address.as_str(),
                    "dnat",
                    "to",
                    private_address.as_str(),
                    "comment",
                    comment.as_str(),
                ],
                vec![
                    "netns",
                    "exec",
                    next.namespace.as_str(),
                    "nft",
                    "add",
                    "rule",
                    "ip",
                    realm_table.as_str(),
                    "postrouting",
                    "oifname",
                    next.public_realm_veth.as_str(),
                    "ip",
                    "saddr",
                    private_address.as_str(),
                    "snat",
                    "to",
                    public_address.as_str(),
                    "comment",
                    comment.as_str(),
                ],
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
        Ok(())
    }
    pub(crate) fn ensure_public_veth(
        &self,
        ownership: &RealmOwnership,
    ) -> Result<(), LinuxFabricError> {
        let (host_exists, _) = self
            .command
            .output("ip", &["link", "show", "dev", &ownership.public_host_veth])
            .map_err(LinuxFabricError::Storage)?;
        let (realm_exists, _) = self
            .command
            .output(
                "ip",
                &[
                    "netns",
                    "exec",
                    &ownership.namespace,
                    "ip",
                    "link",
                    "show",
                    "dev",
                    &ownership.public_realm_veth,
                ],
            )
            .map_err(LinuxFabricError::Storage)?;
        if host_exists != realm_exists {
            return Err(LinuxFabricError::ForeignState);
        }
        if !host_exists {
            for args in [
                vec![
                    "link",
                    "add",
                    &ownership.public_host_veth,
                    "type",
                    "veth",
                    "peer",
                    "name",
                    &ownership.public_realm_veth,
                ],
                vec![
                    "link",
                    "set",
                    &ownership.public_realm_veth,
                    "netns",
                    &ownership.namespace,
                ],
                vec!["link", "set", "dev", &ownership.public_host_veth, "up"],
                vec![
                    "netns",
                    "exec",
                    &ownership.namespace,
                    "ip",
                    "link",
                    "set",
                    "dev",
                    &ownership.public_realm_veth,
                    "up",
                ],
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
        Ok(())
    }
    pub(crate) fn remove_public(
        &mut self,
        plan: &NamespacedRoutedFabricPlan,
    ) -> Result<(), LinuxFabricError> {
        let Some(current) = self.state.realms.get(&plan.realm_id).cloned() else {
            return Ok(());
        };
        if current.public_fingerprint.is_empty() {
            return Ok(());
        }
        let uplink = self
            .config
            .public_uplink
            .as_deref()
            .ok_or(LinuxFabricError::InvalidConfiguration)?;
        let root_table = public_root_table_name(plan.realm_id);
        let realm_table = public_realm_table_name(plan.realm_id);
        let (root_exists, root_listing) = self
            .command
            .output("nft", &["list", "table", "ip", &root_table])
            .map_err(LinuxFabricError::Storage)?;
        if root_exists && !root_listing.contains(FABRIC_PUBLIC_MARKER) {
            return Err(LinuxFabricError::ForeignState);
        }
        if root_exists
            && !self
                .command
                .run("nft", &["delete", "table", "ip", &root_table])
                .map_err(LinuxFabricError::Storage)?
        {
            return Err(LinuxFabricError::CommandFailed);
        }
        let realm_list_args = [
            "netns",
            "exec",
            current.namespace.as_str(),
            "nft",
            "list",
            "table",
            "ip",
            realm_table.as_str(),
        ];
        let (realm_exists, realm_listing) = self
            .command
            .output("ip", &realm_list_args)
            .map_err(LinuxFabricError::Storage)?;
        if realm_exists && !realm_listing.contains(FABRIC_PUBLIC_MARKER) {
            return Err(LinuxFabricError::ForeignState);
        }
        if realm_exists
            && !self
                .command
                .run(
                    "ip",
                    &[
                        "netns",
                        "exec",
                        current.namespace.as_str(),
                        "nft",
                        "delete",
                        "table",
                        "ip",
                        &realm_table,
                    ],
                )
                .map_err(LinuxFabricError::Storage)?
        {
            return Err(LinuxFabricError::CommandFailed);
        }
        let route_listing = self
            .command
            .output(
                "ip",
                &[
                    "route",
                    "show",
                    "table",
                    &current.public_route_table.to_string(),
                ],
            )
            .map_err(LinuxFabricError::Storage)?;
        if route_listing.0 {
            let public_addresses = if current.public_addresses.is_empty() {
                plan.public_bindings
                    .iter()
                    .map(|binding| binding.public_address)
                    .collect::<Vec<_>>()
            } else {
                current.public_addresses.clone()
            };
            for public_address in public_addresses {
                let address = format!("{public_address}/32");
                if route_listing.1.contains(&address)
                    && !self
                        .command
                        .run(
                            "ip",
                            &[
                                "route",
                                "del",
                                "table",
                                &current.public_route_table.to_string(),
                                &address,
                                "dev",
                                &current.public_host_veth,
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
                            "neigh",
                            "del",
                            "proxy",
                            &public_address.to_string(),
                            "dev",
                            uplink,
                        ],
                    )
                    .map_err(LinuxFabricError::Storage)?
                {
                    return Err(LinuxFabricError::CommandFailed);
                }
            }
        }
        let rule_listing = self
            .command
            .output("ip", &["rule", "list"])
            .map_err(LinuxFabricError::Storage)?;
        if rule_listing.0
            && rule_listing
                .1
                .contains(&format!("fwmark {}", current.public_mark))
            && !self
                .command
                .run(
                    "ip",
                    &[
                        "rule",
                        "del",
                        "fwmark",
                        &current.public_mark.to_string(),
                        "table",
                        &current.public_route_table.to_string(),
                    ],
                )
                .map_err(LinuxFabricError::Storage)?
        {
            return Err(LinuxFabricError::CommandFailed);
        }
        let (host_exists, _) = self
            .command
            .output("ip", &["link", "show", "dev", &current.public_host_veth])
            .map_err(LinuxFabricError::Storage)?;
        if host_exists
            && !self
                .command
                .run("ip", &["link", "del", &current.public_host_veth])
                .map_err(LinuxFabricError::Storage)?
        {
            return Err(LinuxFabricError::CommandFailed);
        }
        let mut next = self.state.clone();
        let cleared = next
            .realms
            .get_mut(&plan.realm_id)
            .ok_or(LinuxFabricError::CorruptState)?;
        cleared.public_generation = 0;
        cleared.public_fingerprint.clear();
        cleared.public_mark = 0;
        cleared.public_route_table = 0;
        cleared.public_addresses.clear();
        store_state(&self.state_path, &next)?;
        self.state = next;
        Ok(())
    }
    pub(crate) fn validate_public_plan(
        plan: &NamespacedRoutedFabricPlan,
    ) -> Result<(), LinuxFabricError> {
        let mut ids = BTreeSet::new();
        let mut addresses = BTreeSet::new();
        let mut endpoints = BTreeSet::new();
        for binding in &plan.public_bindings {
            if binding.id.is_nil()
                || binding.project_id.is_empty()
                || binding.generation == 0
                || binding.public_address.is_unspecified()
                || !ids.insert(binding.id)
                || !addresses.insert(binding.public_address)
                || !endpoints.insert(binding.endpoint_id)
                || !plan
                    .directory
                    .location(binding.endpoint_id)
                    .is_some_and(|endpoint| endpoint.project_id == binding.project_id)
            {
                return Err(LinuxFabricError::OwnershipConflict);
            }
        }
        Ok(())
    }
}
