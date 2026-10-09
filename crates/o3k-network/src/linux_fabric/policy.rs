use super::*;

impl super::LinuxFabricBackend {
    pub(crate) fn ensure_policy(
        &mut self,
        plan: &NamespacedRoutedFabricPlan,
    ) -> Result<(), LinuxFabricError> {
        let Some(current) = self.state.realms.get(&plan.realm_id).cloned() else {
            return Err(LinuxFabricError::CorruptState);
        };
        if plan.policies.is_empty() && plan.policy_defaults.is_empty() {
            return self.remove_policy(plan);
        }
        Self::validate_policy_plan(plan)?;
        let fingerprint = policy_fingerprint(plan).map_err(|_| LinuxFabricError::CorruptState)?;
        if current.policy_generation == plan.policy_generation
            && current.policy_fingerprint == fingerprint
        {
            return Ok(());
        }
        let table = policy_table_name(plan.realm_id);
        let namespace = current.namespace.as_str();
        let (table_exists, listing) = self
            .command
            .output(
                "ip",
                &[
                    "netns", "exec", namespace, "nft", "list", "table", "ip", &table,
                ],
            )
            .map_err(LinuxFabricError::Storage)?;
        if table_exists && !listing.contains("o3k-p11-policy") {
            return Err(LinuxFabricError::ForeignState);
        }
        let mut next = current.clone();
        next.policy_generation = plan.policy_generation;
        next.policy_fingerprint = fingerprint.clone();
        self.state.realms.insert(plan.realm_id, next);
        store_state(&self.state_path, &self.state)?;
        if table_exists
            && !self
                .command
                .run(
                    "ip",
                    &[
                        "netns", "exec", namespace, "nft", "delete", "table", "ip", &table,
                    ],
                )
                .map_err(LinuxFabricError::Storage)?
        {
            return Err(LinuxFabricError::CommandFailed);
        }
        let marker = format!("\"o3k-p11-policy:{fingerprint}\"");
        for args in [
            vec![
                "netns",
                "exec",
                namespace,
                "nft",
                "add",
                "table",
                "ip",
                table.as_str(),
                "{",
                "comment",
                marker.as_str(),
                ";",
                "}",
            ],
            vec![
                "netns",
                "exec",
                namespace,
                "nft",
                "add",
                "chain",
                "ip",
                table.as_str(),
                "forward",
                "{",
                "type",
                "filter",
                "hook",
                "forward",
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
                namespace,
                "nft",
                "add",
                "rule",
                "ip",
                table.as_str(),
                "forward",
                "ct",
                "state",
                "established,related",
                "accept",
                "comment",
                "o3k-p11-policy",
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
        let mut sorted_policies = plan.policies.clone();
        sorted_policies.sort_by_key(|policy| (policy.action != PolicyAction::Deny, policy.id));
        for (index, policy) in sorted_policies.iter().enumerate() {
            let endpoint = plan
                .directory
                .location(policy.endpoint_id)
                .ok_or(LinuxFabricError::OwnershipConflict)?;
            let endpoint_address = endpoint.fixed_ip.to_string();
            let mut args = vec![
                "netns".to_owned(),
                "exec".to_owned(),
                namespace.to_owned(),
                "nft".to_owned(),
                "add".to_owned(),
                "rule".to_owned(),
                "ip".to_owned(),
                table.clone(),
                "forward".to_owned(),
            ];
            if matches!(policy.direction, PolicyDirection::Ingress) {
                args.extend([
                    "ip".to_owned(),
                    "daddr".to_owned(),
                    endpoint_address.clone(),
                ]);
            } else {
                args.extend([
                    "ip".to_owned(),
                    "saddr".to_owned(),
                    endpoint_address.clone(),
                ]);
            }
            if let Some(prefix) = policy.source.or(policy.destination) {
                let prefix = format!("{}/{}", prefix.network, prefix.prefix_len);
                if matches!(policy.direction, PolicyDirection::Ingress) {
                    args.extend(["ip".to_owned(), "saddr".to_owned(), prefix]);
                } else {
                    args.extend(["ip".to_owned(), "daddr".to_owned(), prefix]);
                }
            }
            if let Some(protocol) = policy_protocol(policy.protocol) {
                args.push(protocol.to_owned());
                if let Some(ports) = policy.ports {
                    args.extend(["dport".to_owned(), format!("{}-{}", ports.start, ports.end)]);
                }
            }
            args.extend([
                "counter".to_owned(),
                if policy.action == PolicyAction::Allow {
                    "accept".to_owned()
                } else {
                    "drop".to_owned()
                },
                "comment".to_owned(),
                format!("\"o3k-p11-policy:{index}\""),
            ]);
            let refs = args.iter().map(String::as_str).collect::<Vec<_>>();
            if !self
                .command
                .run("ip", &refs)
                .map_err(LinuxFabricError::Storage)?
            {
                return Err(LinuxFabricError::CommandFailed);
            }
        }
        for default in &plan.policy_defaults {
            let endpoint = plan
                .directory
                .location(default.endpoint_id)
                .ok_or(LinuxFabricError::OwnershipConflict)?;
            if default.unmatched_action == PolicyAction::Deny {
                let endpoint_address = endpoint.fixed_ip.to_string();
                let mut args = vec![
                    "netns",
                    "exec",
                    namespace,
                    "nft",
                    "add",
                    "rule",
                    "ip",
                    &table,
                    "forward",
                    "ip",
                    "daddr",
                    &endpoint_address,
                    "drop",
                    "comment",
                    "o3k-p11-policy-default",
                ];
                let refs = args;
                if !self
                    .command
                    .run("ip", &refs)
                    .map_err(LinuxFabricError::Storage)?
                {
                    return Err(LinuxFabricError::CommandFailed);
                }
                args = vec![
                    "netns",
                    "exec",
                    namespace,
                    "nft",
                    "add",
                    "rule",
                    "ip",
                    &table,
                    "forward",
                    "ip",
                    "saddr",
                    &endpoint_address,
                    "drop",
                    "comment",
                    "o3k-p11-policy-default",
                ];
                let refs = args;
                if !self
                    .command
                    .run("ip", &refs)
                    .map_err(LinuxFabricError::Storage)?
                {
                    return Err(LinuxFabricError::CommandFailed);
                }
            }
        }
        Ok(())
    }
    pub(crate) fn remove_policy(
        &mut self,
        plan: &NamespacedRoutedFabricPlan,
    ) -> Result<(), LinuxFabricError> {
        let Some(current) = self.state.realms.get(&plan.realm_id).cloned() else {
            return Ok(());
        };
        if current.policy_fingerprint.is_empty() {
            return Ok(());
        }
        let table = policy_table_name(plan.realm_id);
        let (exists, listing) = self
            .command
            .output(
                "ip",
                &[
                    "netns",
                    "exec",
                    current.namespace.as_str(),
                    "nft",
                    "list",
                    "table",
                    "ip",
                    &table,
                ],
            )
            .map_err(LinuxFabricError::Storage)?;
        if exists && !listing.contains("o3k-p11-policy") {
            return Err(LinuxFabricError::ForeignState);
        }
        if exists
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
                        &table,
                    ],
                )
                .map_err(LinuxFabricError::Storage)?
        {
            return Err(LinuxFabricError::CommandFailed);
        }
        let (remains, _) = self
            .command
            .output(
                "ip",
                &[
                    "netns",
                    "exec",
                    current.namespace.as_str(),
                    "nft",
                    "list",
                    "table",
                    "ip",
                    &table,
                ],
            )
            .map_err(LinuxFabricError::Storage)?;
        if remains {
            return Err(LinuxFabricError::CommandFailed);
        }
        let mut next = self.state.clone();
        let cleared = next
            .realms
            .get_mut(&plan.realm_id)
            .ok_or(LinuxFabricError::CorruptState)?;
        cleared.policy_generation = 0;
        cleared.policy_fingerprint.clear();
        store_state(&self.state_path, &next)?;
        self.state = next;
        Ok(())
    }
    pub(crate) fn validate_policy_plan(
        plan: &NamespacedRoutedFabricPlan,
    ) -> Result<(), LinuxFabricError> {
        let mut default_endpoints = BTreeSet::new();
        if plan.policy_generation == 0
            || plan.policy_defaults.iter().any(|default| {
                default.policy_id.is_nil()
                    || default.endpoint_id.is_nil()
                    || default.generation == 0
                    || default.stateful_mode != PolicyStatefulMode::Stateful
                    || plan.directory.location(default.endpoint_id).is_none()
                    || !default_endpoints.insert(default.endpoint_id)
            })
            || plan.policies.iter().any(|policy| {
                policy.id.is_nil()
                    || policy.endpoint_id.is_nil()
                    || plan.directory.location(policy.endpoint_id).is_none()
                    || policy.ports.is_some_and(|ports| ports.start > ports.end)
                    || policy.ports.is_some_and(|_| {
                        matches!(
                            policy.protocol,
                            NetworkProtocol::Any | NetworkProtocol::Icmp
                        )
                    })
                    || (matches!(policy.direction, PolicyDirection::Ingress)
                        && policy.destination.is_some())
                    || (matches!(policy.direction, PolicyDirection::Egress)
                        && policy.source.is_some())
            })
        {
            return Err(LinuxFabricError::OwnershipConflict);
        }
        Ok(())
    }
}
