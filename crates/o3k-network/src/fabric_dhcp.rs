//! One fenced DHCP realization per Fabric Realm, independent of TAP/bridge
//! creation. The semantic input is the canonical per-Realm plan; only this
//! provider resolves and binds the provider-owned Realm bridge.

use o3k_dhcp::{Binding, DhcpConfig, DhcpError, DhcpService, DnsmasqSupervisor};
use o3k_domain::NamespacedRoutedFabricPlan;
use serde::{Deserialize, Serialize};
use std::{
    collections::BTreeMap,
    fs::{self, File},
    io::Write,
    path::{Path, PathBuf},
};
use thiserror::Error;
use uuid::Uuid;

#[derive(Debug, Error)]
pub enum FabricDhcpError {
    #[error("Fabric DHCP plan is missing or invalid")]
    InvalidPlan,
    #[error("Fabric DHCP plan generation is stale")]
    StaleGeneration,
    #[error("Fabric DHCP ownership state is corrupt or foreign")]
    OwnershipConflict,
    #[error("Fabric DHCP service failed: {0}")]
    Dhcp(#[from] DhcpError),
    #[error("Fabric DHCP storage failed: {0}")]
    Storage(#[from] std::io::Error),
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
struct FabricDhcpOwnership {
    schema: u16,
    realm_id: Uuid,
    authority_host: String,
    directory_generation: u64,
    local_fabric_generation: u64,
    namespace: String,
    bridge: String,
    enabled: bool,
    pending: bool,
}

struct RealmService {
    service: DhcpService,
    supervisor: Option<DnsmasqSupervisor>,
    owner: FabricDhcpOwnership,
}

/// Node-local realization of the existing `o3k-dhcp` service for Fabric
/// plans. It never creates or attaches a Fabric interface.
pub struct FabricDhcpRealizer {
    root: PathBuf,
    local_host: String,
    dnsmasq_binary: PathBuf,
    realms: BTreeMap<Uuid, RealmService>,
}

impl FabricDhcpRealizer {
    pub fn open(
        root: impl Into<PathBuf>,
        local_host: impl Into<String>,
        dnsmasq_binary: impl Into<PathBuf>,
    ) -> Result<Self, FabricDhcpError> {
        let root = root.into();
        let local_host = local_host.into();
        if !root.is_absolute() || root == Path::new("/") || local_host.trim().is_empty() {
            return Err(FabricDhcpError::InvalidPlan);
        }
        fs::create_dir_all(root.join("fabric"))?;
        Ok(Self {
            root,
            local_host,
            dnsmasq_binary: dnsmasq_binary.into(),
            realms: BTreeMap::new(),
        })
    }

    fn realm_root(&self, realm_id: Uuid) -> PathBuf {
        self.root.join("fabric").join(realm_id.to_string())
    }

    fn read_owner(&self, realm_id: Uuid) -> Result<Option<FabricDhcpOwnership>, FabricDhcpError> {
        let path = self.realm_root(realm_id).join("owner.json");
        match fs::read(path) {
            Ok(bytes) => {
                let owner: FabricDhcpOwnership = serde_json::from_slice(&bytes)
                    .map_err(|_| FabricDhcpError::OwnershipConflict)?;
                if owner.schema != 1 || owner.realm_id != realm_id {
                    return Err(FabricDhcpError::OwnershipConflict);
                }
                Ok(Some(owner))
            }
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => Ok(None),
            Err(error) => Err(error.into()),
        }
    }

    fn write_owner(&self, owner: &FabricDhcpOwnership) -> Result<(), FabricDhcpError> {
        let root = self.realm_root(owner.realm_id);
        fs::create_dir_all(&root)?;
        let path = root.join("owner.json");
        let temporary = root.join("owner.json.tmp");
        let bytes = serde_json::to_vec_pretty(owner).map_err(|_| FabricDhcpError::InvalidPlan)?;
        let mut file = File::create(&temporary)?;
        file.write_all(&bytes)?;
        file.sync_all()?;
        fs::rename(temporary, path)?;
        File::open(root)?.sync_all()?;
        Ok(())
    }

    fn open_owned_service(
        &mut self,
        realm_id: Uuid,
        namespace: &str,
    ) -> Result<&mut RealmService, FabricDhcpError> {
        if !self.realms.contains_key(&realm_id) {
            let owner = self
                .read_owner(realm_id)?
                .ok_or(FabricDhcpError::OwnershipConflict)?;
            if owner.authority_host != self.local_host || owner.namespace != namespace {
                return Err(FabricDhcpError::OwnershipConflict);
            }
            let root = self.realm_root(realm_id);
            let service = DhcpService::open(&root)?;
            let supervisor = service.adopt_supervisor(&self.dnsmasq_binary)?;
            self.realms.insert(
                realm_id,
                RealmService {
                    service,
                    supervisor,
                    owner,
                },
            );
        }
        self.realms
            .get_mut(&realm_id)
            .ok_or(FabricDhcpError::OwnershipConflict)
    }

    /// Reconcile the complete binding snapshot. Only the deterministic
    /// authority starts dnsmasq; all other participants withdraw only state
    /// carrying this provider's Realm ownership marker.
    pub fn realize(
        &mut self,
        plan: &NamespacedRoutedFabricPlan,
        namespace: &str,
        bridge: &str,
    ) -> Result<(), FabricDhcpError> {
        let intent = plan.dhcp.as_ref().ok_or(FabricDhcpError::InvalidPlan)?;
        if plan.local_host != self.local_host
            || namespace.is_empty()
            || bridge.is_empty()
            || plan.directory_generation == 0
        {
            return Err(FabricDhcpError::InvalidPlan);
        }
        let is_authority = intent.enabled && intent.authority_host == self.local_host;
        if !is_authority {
            return self.withdraw(plan, namespace);
        }
        if !plan.realm_prefix.contains(intent.gateway)
            || intent.gateway == plan.realm_prefix.network
            || plan.directory.entries.is_empty()
            || !plan
                .directory
                .entries
                .iter()
                .any(|entry| entry.selected_host == self.local_host)
        {
            return Err(FabricDhcpError::InvalidPlan);
        }
        // Correct committed state is idempotent. Do not restart a healthy
        // authority merely because another endpoint triggered reconciliation.
        if self.observe_runtime(plan, namespace, bridge, true)? {
            return Ok(());
        }
        let mut owner = self
            .read_owner(plan.realm_id)?
            .unwrap_or(FabricDhcpOwnership {
                schema: 1,
                realm_id: plan.realm_id,
                authority_host: self.local_host.clone(),
                directory_generation: 0,
                local_fabric_generation: 0,
                namespace: namespace.to_owned(),
                bridge: bridge.to_owned(),
                enabled: true,
                pending: true,
            });
        if owner.authority_host != self.local_host
            || owner.namespace != namespace
            || owner.bridge != bridge
            || plan.directory_generation < owner.directory_generation
            || plan.local_fabric_generation < owner.local_fabric_generation
        {
            return Err(FabricDhcpError::StaleGeneration);
        }
        owner.directory_generation = plan.directory_generation;
        owner.local_fabric_generation = plan.local_fabric_generation;
        owner.enabled = true;
        owner.pending = true;
        // Intent is durable before config, binding, or process mutation.
        self.write_owner(&owner)?;
        if let Some(supervisor) = self
            .realms
            .get_mut(&plan.realm_id)
            .and_then(|current| current.supervisor.as_mut())
        {
            // Quiesce dnsmasq before changing its config, bindings, or lease
            // snapshot. A failed update leaves durable pending state for retry.
            supervisor.stop()?;
        }
        let service = if self.realms.contains_key(&plan.realm_id) {
            &mut self
                .realms
                .get_mut(&plan.realm_id)
                .ok_or(FabricDhcpError::OwnershipConflict)?
                .service
        } else {
            // Open and adopt only after verifying the provider ownership marker.
            let _ = self.open_owned_service(plan.realm_id, namespace)?;
            &mut self
                .realms
                .get_mut(&plan.realm_id)
                .ok_or(FabricDhcpError::OwnershipConflict)?
                .service
        };
        service.configure_with_mtu(
            DhcpConfig {
                subnet: format!(
                    "{}/{}",
                    plan.realm_prefix.network, plan.realm_prefix.prefix_len
                ),
                gateway: intent.gateway,
                dns: Vec::new(),
                interface: bridge.to_owned(),
                lease_seconds: 3600,
            },
            Some(plan.tenant_mtu),
        )?;
        let expected = plan
            .directory
            .entries
            .iter()
            .map(|entry| {
                (
                    entry.endpoint_id.to_string(),
                    Binding {
                        port_id: entry.endpoint_id.to_string(),
                        mac: entry.mac.clone(),
                        address: entry.fixed_ip,
                    },
                )
            })
            .collect::<BTreeMap<_, _>>();
        let old_ids = service
            .bindings()
            .map(|binding| binding.port_id.clone())
            .collect::<Vec<_>>();
        for id in old_ids {
            if !expected.contains_key(&id) {
                service.remove_binding_and_lease(&id)?;
            }
        }
        for binding in expected.values() {
            service.upsert_binding(binding.clone())?;
        }
        {
            let current = self
                .realms
                .get_mut(&plan.realm_id)
                .ok_or(FabricDhcpError::OwnershipConflict)?;
            match current.supervisor.as_mut() {
                Some(supervisor) => current.service.reload(supervisor)?,
                None => {
                    current.supervisor = Some(current.service.start(&self.dnsmasq_binary)?);
                }
            }
        }
        if !self.observe_runtime(plan, namespace, bridge, false)? {
            return Err(FabricDhcpError::OwnershipConflict);
        }
        owner.pending = false;
        self.write_owner(&owner)?;
        self.realms
            .get_mut(&plan.realm_id)
            .ok_or(FabricDhcpError::OwnershipConflict)?
            .owner = owner;
        Ok(())
    }

    pub fn observe(
        &mut self,
        plan: &NamespacedRoutedFabricPlan,
        namespace: &str,
        bridge: &str,
    ) -> Result<bool, FabricDhcpError> {
        self.observe_runtime(plan, namespace, bridge, true)
    }

    pub fn is_withdrawn(&self, realm_id: Uuid) -> Result<bool, FabricDhcpError> {
        Ok(self.read_owner(realm_id)?.is_none() && !self.realms.contains_key(&realm_id))
    }

    fn observe_runtime(
        &mut self,
        plan: &NamespacedRoutedFabricPlan,
        namespace: &str,
        bridge: &str,
        require_committed: bool,
    ) -> Result<bool, FabricDhcpError> {
        let intent = plan.dhcp.as_ref().ok_or(FabricDhcpError::InvalidPlan)?;
        let expected_authority = intent.enabled && intent.authority_host == self.local_host;
        let Some(owner) = self.read_owner(plan.realm_id)? else {
            return Ok(!expected_authority);
        };
        if !expected_authority {
            return Ok(false);
        }
        if (require_committed && owner.pending)
            || !owner.enabled
            || owner.authority_host != self.local_host
            || owner.directory_generation != plan.directory_generation
            || owner.local_fabric_generation != plan.local_fabric_generation
            || owner.namespace != namespace
            || owner.bridge != bridge
        {
            return Ok(false);
        }
        let service = self.open_owned_service(plan.realm_id, namespace)?;
        let config = service.service.configuration();
        let rendered_config = service.service.render_config()?;
        let live_config = fs::read_to_string(service.service.managed_config_path())
            .map_err(FabricDhcpError::Storage)?;
        let expected_config = DhcpConfig {
            subnet: format!(
                "{}/{}",
                plan.realm_prefix.network, plan.realm_prefix.prefix_len
            ),
            gateway: intent.gateway,
            dns: Vec::new(),
            interface: bridge.to_owned(),
            lease_seconds: 3600,
        };
        let expected_bindings = plan
            .directory
            .entries
            .iter()
            .map(|entry| {
                (
                    entry.endpoint_id.to_string(),
                    Binding {
                        port_id: entry.endpoint_id.to_string(),
                        mac: entry.mac.clone(),
                        address: entry.fixed_ip,
                    },
                )
            })
            .collect::<BTreeMap<_, _>>();
        let observed_bindings = service
            .service
            .bindings()
            .map(|binding| (binding.port_id.clone(), binding.clone()))
            .collect::<BTreeMap<_, _>>();
        let running = service
            .supervisor
            .as_mut()
            .is_some_and(|supervisor| supervisor.is_running().unwrap_or(false));
        Ok(config == Some(&expected_config)
            && service.service.tenant_mtu() == Some(plan.tenant_mtu)
            && live_config == rendered_config
            && observed_bindings == expected_bindings
            && running)
    }

    pub fn withdraw(
        &mut self,
        plan: &NamespacedRoutedFabricPlan,
        namespace: &str,
    ) -> Result<(), FabricDhcpError> {
        let realm_id = plan.realm_id;
        let Some(mut owner) = self.read_owner(realm_id)? else {
            return Ok(());
        };
        if owner.authority_host != self.local_host || owner.namespace != namespace {
            return Err(FabricDhcpError::OwnershipConflict);
        }
        if plan.directory_generation < owner.directory_generation
            || plan.local_fabric_generation < owner.local_fabric_generation
        {
            return Err(FabricDhcpError::StaleGeneration);
        }
        owner.directory_generation = plan.directory_generation;
        owner.local_fabric_generation = plan.local_fabric_generation;
        owner.enabled = false;
        owner.pending = true;
        // Withdrawal is also a fenced mutation: persist its intent before
        // stopping the process or deleting owned configuration.
        self.write_owner(&owner)?;
        let root = self.realm_root(realm_id);
        let mut service = DhcpService::open(&root)?;
        let mut supervisor = if let Some(current) = self.realms.get_mut(&realm_id) {
            current.supervisor.take()
        } else {
            service.adopt_supervisor(&self.dnsmasq_binary)?
        };
        if let Some(supervisor) = supervisor.as_mut() {
            supervisor.stop()?;
        }
        let ids = service
            .bindings()
            .map(|binding| binding.port_id.clone())
            .collect::<Vec<_>>();
        for id in ids {
            service.remove_binding_and_lease(&id)?;
        }
        service.clear_configuration()?;
        for file in ["dnsmasq.conf", "dnsmasq.leases", "state.json"] {
            match fs::remove_file(root.join(file)) {
                Ok(()) => {}
                Err(error) if error.kind() == std::io::ErrorKind::NotFound => {}
                Err(error) => return Err(error.into()),
            }
        }
        fs::remove_file(root.join("owner.json"))?;
        self.realms.remove(&realm_id);
        // Remove only an empty private Realm directory. Unexpected files are
        // left in place as foreign evidence.
        let _ = fs::remove_dir(root);
        Ok(())
    }
}

#[cfg(test)]
#[allow(clippy::expect_used, clippy::panic)]
mod tests {
    use super::*;
    use crate::{FabricRealmPlanContext, compile_fabric_realm_plans};
    use o3k_domain::{
        AddressRealm, EndpointLocation, FabricHostIdentity, FabricProviderKind, Ipv4Prefix,
        RealmEncapsulationBinding,
    };
    use std::net::Ipv4Addr;
    use std::os::unix::fs::PermissionsExt;

    fn realm() -> AddressRealm {
        AddressRealm {
            id: Uuid::from_u128(901),
            network_id: Uuid::from_u128(902),
            project_id: "project-dhcp".to_owned(),
            prefix: Ipv4Prefix::new(Ipv4Addr::new(10, 77, 0, 0), 24).expect("prefix"),
            overlapping_prefixes: false,
        }
    }

    fn host(host_id: &str, octet: u8) -> FabricHostIdentity {
        FabricHostIdentity {
            host_id: host_id.to_owned(),
            public_key: format!("public-{host_id}"),
            underlay_endpoint: format!("192.0.2.{octet}:65001"),
            fabric_transport_ip: Ipv4Addr::new(198, 18, 0, octet),
            provider_version: "wireguard-v1".to_owned(),
            fabric_generation: 1,
            underlay_mtu: 1500,
            fabric_mtu: 1440,
        }
    }

    fn endpoint(id: u128, host_id: &str, octet: u8) -> EndpointLocation {
        EndpointLocation {
            endpoint_id: Uuid::from_u128(id),
            project_id: "project-dhcp".to_owned(),
            realm_id: Uuid::from_u128(901),
            fixed_ip: Ipv4Addr::new(10, 77, 0, octet),
            mac: format!("02:00:00:00:77:{octet:02x}"),
            selected_host: host_id.to_owned(),
            endpoint_generation: 1,
            placement_generation: 1,
        }
    }

    fn binding() -> RealmEncapsulationBinding {
        RealmEncapsulationBinding {
            fabric_domain_id: Uuid::from_u128(903),
            realm_id: Uuid::from_u128(901),
            provider_kind: FabricProviderKind::Vxlan,
            provider_segment_id: 9077,
            binding_generation: 1,
        }
    }

    fn plans(include_a: bool) -> crate::FabricRealmPlanSet {
        let mut endpoints = vec![endpoint(911, "host-b", 3), endpoint(912, "host-c", 4)];
        let mut hosts = vec![host("host-b", 2), host("host-c", 3)];
        if include_a {
            endpoints.push(endpoint(910, "host-a", 2));
            hosts.push(host("host-a", 1));
        }
        compile_fabric_realm_plans(
            &realm(),
            endpoints,
            &hosts,
            &binding(),
            FabricRealmPlanContext {
                directory_generation: if include_a { 1 } else { 2 },
                dhcp_enabled: true,
                dhcp_gateway: Ipv4Addr::new(10, 77, 0, 1),
                operation_id: Uuid::from_u128(if include_a { 920 } else { 921 }),
                deadline_unix_ms: 100_000,
            },
        )
        .expect("compiled canonical realm plans")
    }

    fn fake_dnsmasq(root: &Path) -> PathBuf {
        let path = root.join("fake-dnsmasq.py");
        fs::write(
            &path,
            "#!/usr/bin/python3\nimport signal, sys, time\nif '--test' in sys.argv: sys.exit(0)\nsignal.signal(signal.SIGTERM, lambda *_: sys.exit(0))\nsignal.signal(signal.SIGINT, lambda *_: sys.exit(0))\nwhile True: time.sleep(1)\n",
        )
        .expect("write fake dnsmasq");
        fs::set_permissions(&path, fs::Permissions::from_mode(0o700))
            .expect("make fake dnsmasq executable");
        path
    }

    fn temp_root(label: &str) -> PathBuf {
        let root = std::env::temp_dir().join(format!("o3k-fabric-dhcp-{label}-{}", Uuid::now_v7()));
        fs::create_dir_all(&root).expect("create test root");
        root
    }

    #[test]
    fn one_authority_serves_complete_remote_binding_snapshot_and_is_idempotent() {
        let temp = temp_root("authority");
        let binary = fake_dnsmasq(&temp);
        let plan_set = plans(true);
        assert_eq!(
            plan_set.plans["host-a"]
                .fabric
                .as_ref()
                .and_then(|plan| plan.dhcp.as_ref())
                .map(|intent| intent.authority_host.as_str()),
            Some("host-a")
        );
        let mut authority = FabricDhcpRealizer::open(temp.join("a"), "host-a", binary.clone())
            .expect("authority provider");
        let plan = plan_set.plans["host-a"].fabric.as_ref().expect("fabric");
        authority
            .realize(plan, "ns-a", "br-realm-a")
            .expect("realize DHCP");
        assert!(
            authority
                .observe(plan, "ns-a", "br-realm-a")
                .expect("observe")
        );
        let pid_path = fs::read_dir(authority.realm_root(plan.realm_id))
            .expect("state directory")
            .filter_map(Result::ok)
            .map(|entry| entry.path())
            .find(|path| {
                path.extension()
                    .is_some_and(|extension| extension == "owner")
            })
            .expect("owned process identity file");
        let first_identity = fs::read_to_string(&pid_path).expect("read process identity");
        authority
            .realize(plan, "ns-a", "br-realm-a")
            .expect("idempotent realize");
        let second_identity =
            fs::read_to_string(&pid_path).expect("read process identity after replay");
        assert_eq!(
            first_identity, second_identity,
            "healthy authority is not restarted"
        );
        let service = DhcpService::open(authority.realm_root(plan.realm_id)).expect("service");
        assert_eq!(service.bindings().count(), 3, "A/B/C bindings are complete");
        assert_eq!(service.tenant_mtu(), Some(plan.tenant_mtu));
        assert!(
            service
                .render_config()
                .expect("config")
                .contains("dhcp-option=26,")
        );

        for host_id in ["host-b", "host-c"] {
            let host_root = temp.join(host_id);
            let mut non_authority = FabricDhcpRealizer::open(&host_root, host_id, binary.clone())
                .expect("non-authority provider");
            let local_plan = plan_set.plans[host_id].fabric.as_ref().expect("fabric");
            non_authority
                .realize(
                    local_plan,
                    &format!("ns-{host_id}"),
                    &format!("br-{host_id}"),
                )
                .expect("non-authority does not start DHCP");
            assert!(
                !host_root
                    .join("fabric")
                    .join(local_plan.realm_id.to_string())
                    .exists(),
                "non-authority must not create a serving state directory"
            );
        }
        drop(authority);
        fs::remove_dir_all(temp).expect("remove test root");
    }

    #[test]
    fn disabled_dhcp_and_authority_reselection_withdraw_only_owned_state() {
        let temp = temp_root("transition");
        let binary = fake_dnsmasq(&temp);
        let original = plans(true);
        let mut old_authority = FabricDhcpRealizer::open(temp.join("a"), "host-a", binary.clone())
            .expect("old authority");
        let old_plan = original.plans["host-a"].fabric.as_ref().expect("fabric");
        old_authority
            .realize(old_plan, "ns-a", "br-a")
            .expect("start old authority");

        let mut withdraw_plan = old_plan.clone();
        withdraw_plan
            .directory
            .entries
            .retain(|entry| entry.selected_host != "host-a");
        withdraw_plan.directory.directory_generation = 2;
        withdraw_plan.directory_generation = 2;
        withdraw_plan.dhcp.as_mut().expect("DHCP intent").enabled = false;
        old_authority
            .realize(&withdraw_plan, "ns-a", "br-a")
            .expect("disable and withdraw old authority");
        assert!(
            old_authority
                .is_withdrawn(old_plan.realm_id)
                .expect("withdrawn")
        );

        let reselected = plans(false);
        assert_eq!(
            reselected.plans["host-b"]
                .fabric
                .as_ref()
                .and_then(|plan| plan.dhcp.as_ref())
                .map(|intent| intent.authority_host.as_str()),
            Some("host-b")
        );
        let mut next_authority =
            FabricDhcpRealizer::open(temp.join("b"), "host-b", binary).expect("new authority");
        next_authority
            .realize(
                reselected.plans["host-b"].fabric.as_ref().expect("fabric"),
                "ns-b",
                "br-b",
            )
            .expect("start selected replacement only after withdrawal");
        assert!(
            next_authority
                .observe(
                    reselected.plans["host-b"].fabric.as_ref().expect("fabric"),
                    "ns-b",
                    "br-b"
                )
                .expect("observe replacement")
        );
        drop(next_authority);
        drop(old_authority);
        fs::remove_dir_all(temp).expect("remove test root");
    }
}
