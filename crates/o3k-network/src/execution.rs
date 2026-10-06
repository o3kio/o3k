//! The node-local network execution boundary.
//!
//! The control plane owns the semantic [`NodeNetworkPlan`]; a network provider
//! owns host mutation behind [`NetworkPlanRealizer`]. Admission and mutation
//! outcomes are journaled so a reconnect can replay accepted identity and
//! observe an interrupted provider call instead of issuing a blind duplicate.

use crate::{
    GatewaySpec, HostNetworkConfig, HostNetworkError, HostNetworkManager, NodeNetworkPlan, TapSpec,
};
use o3k_dhcp::{Binding as DhcpBinding, DhcpConfig, DhcpError, DhcpService, DnsmasqSupervisor};
use o3k_domain::NetworkPlanIntent;
use serde::{Deserialize, Serialize};
use std::{
    fs::{self, File},
    io::{self, Write},
    path::{Path, PathBuf},
    sync::Mutex,
};
use thiserror::Error;
use uuid::Uuid;

/// Control-plane port for the bounded node-local network transport. The
/// application crate owns the command semantics; an adapter supplies the
/// authenticated wire delivery.
#[async_trait::async_trait]
pub trait NetworkPlanDispatcher: Send + Sync {
    /// Resolve the current network execution identity for a stable host.
    /// Fabric plans use this host-scoped directory; it is deliberately
    /// separate from the compute-agent registry.
    async fn target_for_host(
        &self,
        _host_id: &str,
    ) -> Result<Option<NetworkAgentIdentity>, NetworkDispatchError> {
        Ok(None)
    }

    /// Stable host IDs covered by the configured target-aware network-agent
    /// directory. Legacy single-agent dispatchers return an empty list.
    fn configured_target_hosts(&self) -> Vec<String> {
        Vec::new()
    }

    async fn dispatch(
        &self,
        command: NetworkPlanCommand,
    ) -> Result<NetworkPlanStatus, NetworkDispatchError>;

    /// Dispatch a fresh execution attempt after the authoritative agent has
    /// proved that the historical command was never admitted. Implementations
    /// must atomically supersede the historical durable work before sending
    /// the successor to the agent.
    async fn dispatch_superseding(
        &self,
        command: NetworkPlanCommand,
        _historical_command_id: String,
        _historical_revision: u64,
    ) -> Result<NetworkPlanStatus, NetworkDispatchError> {
        let _ = command;
        Err(NetworkDispatchError::Rejected(
            "atomic historical work supersession is unsupported by this dispatcher".to_owned(),
        ))
    }

    /// Replays an already-durable successor that was committed before a
    /// controller crash but had not yet reached the agent. The command ID is
    /// retained while its execution envelope is refreshed under current
    /// authority.
    async fn dispatch_existing_successor(
        &self,
        command: NetworkPlanCommand,
        _successor_command_id: String,
    ) -> Result<NetworkPlanStatus, NetworkDispatchError> {
        let _ = command;
        Err(NetworkDispatchError::Rejected(
            "durable recovery successor replay is unsupported by this dispatcher".to_owned(),
        ))
    }

    /// Observe a historical command using current control ownership. This
    /// operation is read-only with respect to the provider and must never
    /// resubmit the stored command as a mutation.
    async fn observe_command(
        &self,
        _target_host_id: &str,
        _target: NetworkAgentIdentity,
        _command_id: Uuid,
    ) -> Result<Option<NetworkPlanStatus>, NetworkDispatchError> {
        Err(NetworkDispatchError::Rejected(
            "historical command observation is unsupported by this dispatcher".to_owned(),
        ))
    }
}

#[derive(Debug, Error)]
pub enum NetworkDispatchError {
    #[error("network plan transport is unavailable")]
    Unavailable,
    #[error("network plan was rejected: {0}")]
    Rejected(String),
    #[error("network plan transport failed: {0}")]
    Transport(String),
}

const JOURNAL_FILE: &str = "accepted-network-plans.json";

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct NetworkAgentIdentity {
    pub agent_id: String,
    pub agent_epoch: String,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct NetworkControllerLease {
    pub controller_id: String,
    pub controller_epoch: String,
    pub fencing_token: u64,
}

#[derive(Debug, Clone, Copy, Default, PartialEq, Eq, Serialize, Deserialize)]
pub enum NetworkPlanAction {
    #[default]
    Apply,
    Remove,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct NetworkPlanCommand {
    pub command_id: Uuid,
    pub operation_id: Uuid,
    pub idempotency_key: String,
    #[serde(default)]
    pub action: NetworkPlanAction,
    pub target: NetworkAgentIdentity,
    pub controller: NetworkControllerLease,
    pub deadline_unix_ms: u64,
    pub plan: NodeNetworkPlan,
}

impl NetworkPlanCommand {
    pub fn fingerprint(&self) -> &str {
        &self.plan.fingerprint_sha256
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
struct AcceptedPlan {
    command_id: Uuid,
    operation_id: Uuid,
    idempotency_key: String,
    #[serde(default)]
    action: NetworkPlanAction,
    plan: NodeNetworkPlan,
    target: NetworkAgentIdentity,
    controller: NetworkControllerLease,
    status: NetworkPlanStatus,
}

#[derive(Debug, Default, Serialize, Deserialize)]
struct Journal {
    plans: Vec<AcceptedPlan>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum PlanAdmission {
    Accepted,
    Replayed,
    ReplayedUnknown,
    RequiresObservation,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum NetworkPlanStatus {
    Accepted,
    Applying,
    Succeeded,
    Unknown,
}

#[derive(Debug, Error)]
pub enum NetworkExecutionError {
    #[error("network execution journal failed: {0}")]
    Io(#[from] io::Error),
    #[error("network execution journal is corrupt")]
    CorruptJournal,
    #[error("network plan command is invalid")]
    InvalidCommand,
    #[error("network plan command targets a fenced agent epoch")]
    StaleAgentEpoch,
    #[error("network plan command has a stale controller lease")]
    StaleControllerLease,
    #[error("network plan command deadline has expired")]
    DeadlineExpired,
    #[error("network plan identity was replayed with a different payload")]
    ConflictingReplay,
    #[error("network mutation outcome is unknown and requires observation")]
    MutationOutcomeUnknown(String),
    #[error("network command is not present in the durable journal")]
    UnknownCommand,
}

/// Durable admission boundary for a node-local network executor.
#[derive(Debug)]
pub struct NetworkPlanExecutor {
    root: PathBuf,
    agent: NetworkAgentIdentity,
    lease: Mutex<NetworkControllerLease>,
    journal_lock: Mutex<()>,
}

impl NetworkPlanExecutor {
    pub fn open(
        root: impl Into<PathBuf>,
        agent: NetworkAgentIdentity,
        lease: NetworkControllerLease,
    ) -> Result<Self, NetworkExecutionError> {
        let root = root.into();
        fs::create_dir_all(&root)?;
        let executor = Self {
            root,
            agent,
            lease: Mutex::new(lease),
            journal_lock: Mutex::new(()),
        };
        let _ = executor.load()?;
        Ok(executor)
    }

    pub fn admit(
        &self,
        command: &NetworkPlanCommand,
        now_unix_ms: u64,
    ) -> Result<PlanAdmission, NetworkExecutionError> {
        let lease = self.controller_lease()?;
        self.admit_with_authority(command, now_unix_ms, &lease)
    }

    /// Durably admits a command against the authority snapshot held by the
    /// authenticated agent control path. Dynamic-lease agents call this while
    /// synchronizing with authority updates; provider execution happens only
    /// after this durable journal boundary and does not revalidate the lease.
    pub fn admit_with_authority(
        &self,
        command: &NetworkPlanCommand,
        now_unix_ms: u64,
        authority: &NetworkControllerLease,
    ) -> Result<PlanAdmission, NetworkExecutionError> {
        self.validate(command, now_unix_ms, authority)?;
        let _guard = self
            .journal_lock
            .lock()
            .map_err(|_| NetworkExecutionError::CorruptJournal)?;
        let mut journal = self.load()?;
        if let Some(existing) = journal
            .plans
            .iter()
            .find(|existing| existing.command_id == command.command_id)
        {
            if existing.plan.fingerprint_sha256 == command.fingerprint()
                && existing.operation_id == command.operation_id
                && existing.idempotency_key == command.idempotency_key
                && existing.action == command.action
                && existing.plan.plan_id == command.plan.plan_id
                && existing.target == command.target
            {
                return Ok(match existing.status {
                    NetworkPlanStatus::Accepted | NetworkPlanStatus::Applying => {
                        PlanAdmission::RequiresObservation
                    }
                    NetworkPlanStatus::Succeeded => PlanAdmission::Replayed,
                    NetworkPlanStatus::Unknown => PlanAdmission::ReplayedUnknown,
                });
            }
            return Err(NetworkExecutionError::ConflictingReplay);
        }
        if journal.plans.iter().any(|existing| {
            existing.operation_id == command.operation_id
                && existing.plan.plan_id == command.plan.plan_id
                && existing.action == command.action
        }) {
            return Err(NetworkExecutionError::ConflictingReplay);
        }
        if command.plan.operation_id != command.operation_id
            || command.plan.deadline_unix_ms != command.deadline_unix_ms
        {
            return Err(NetworkExecutionError::InvalidCommand);
        }
        if command.deadline_unix_ms < now_unix_ms {
            return Err(NetworkExecutionError::DeadlineExpired);
        }
        journal.plans.push(AcceptedPlan {
            command_id: command.command_id,
            operation_id: command.operation_id,
            idempotency_key: command.idempotency_key.clone(),
            action: command.action,
            plan: command.plan.clone(),
            target: command.target.clone(),
            controller: command.controller.clone(),
            status: NetworkPlanStatus::Accepted,
        });
        self.store(&journal)?;
        Ok(PlanAdmission::Accepted)
    }

    pub fn agent_id(&self) -> &str {
        &self.agent.agent_id
    }

    pub fn agent_epoch(&self) -> &str {
        &self.agent.agent_epoch
    }

    /// Replace the controller authority used for new mutations. The caller
    /// is responsible for validating the takeover lease and its expiry.
    pub fn set_controller_lease(
        &self,
        lease: NetworkControllerLease,
    ) -> Result<(), NetworkExecutionError> {
        *self
            .lease
            .lock()
            .map_err(|_| NetworkExecutionError::CorruptJournal)? = lease;
        Ok(())
    }

    pub fn controller_lease(&self) -> Result<NetworkControllerLease, NetworkExecutionError> {
        self.lease
            .lock()
            .map_err(|_| NetworkExecutionError::CorruptJournal)
            .map(|lease| lease.clone())
    }

    pub fn state_root(&self) -> &Path {
        &self.root
    }

    pub fn accepted(&self, command_id: Uuid) -> Result<bool, NetworkExecutionError> {
        let _guard = self
            .journal_lock
            .lock()
            .map_err(|_| NetworkExecutionError::CorruptJournal)?;
        Ok(self
            .load()?
            .plans
            .iter()
            .any(|plan| plan.command_id == command_id))
    }

    /// Returns durable mutations that are not yet terminally succeeded. A
    /// restarted agent uses this inventory to observe before attempting any
    /// retry, including when the controller lease has been taken over.
    pub fn pending(&self) -> Result<Vec<(Uuid, NetworkPlanStatus)>, NetworkExecutionError> {
        let _guard = self
            .journal_lock
            .lock()
            .map_err(|_| NetworkExecutionError::CorruptJournal)?;
        Ok(self
            .load()?
            .plans
            .into_iter()
            .filter(|plan| plan.status != NetworkPlanStatus::Succeeded)
            .map(|plan| (plan.command_id, plan.status))
            .collect())
    }

    /// Observes every pending mutation after restart. No provider mutation is
    /// issued by this method; an unresolved observation remains `Unknown`.
    pub fn reconcile_pending<R: NetworkPlanRealizer>(
        &self,
        realizer: &mut R,
    ) -> Result<Vec<(Uuid, NetworkPlanStatus)>, NetworkExecutionError> {
        let pending = self.pending()?;
        pending
            .into_iter()
            .map(|(command_id, _)| {
                self.reconcile(command_id, realizer)
                    .map(|status| (command_id, status))
            })
            .collect()
    }

    pub fn execute<R: NetworkPlanRealizer>(
        &self,
        command: &NetworkPlanCommand,
        now_unix_ms: u64,
        realizer: &mut R,
    ) -> Result<PlanAdmission, NetworkExecutionError>
    where
        R::Error: std::fmt::Display,
    {
        let lease = self.controller_lease()?;
        let admission = self.admit_with_authority(command, now_unix_ms, &lease)?;
        if admission != PlanAdmission::Accepted {
            return Ok(admission);
        }
        self.execute_admitted(command, realizer)?;
        Ok(PlanAdmission::Accepted)
    }

    /// Executes a command whose immutable identity has already crossed the
    /// durable admission boundary. Authority expiry or takeover after that
    /// point prevents further admissions but does not cancel this operation.
    pub fn execute_admitted<R: NetworkPlanRealizer>(
        &self,
        command: &NetworkPlanCommand,
        realizer: &mut R,
    ) -> Result<(), NetworkExecutionError>
    where
        R::Error: std::fmt::Display,
    {
        self.set_status(command.command_id, NetworkPlanStatus::Applying)?;
        let result = match command.action {
            NetworkPlanAction::Apply => realizer.realize(&command.plan),
            NetworkPlanAction::Remove => realizer.remove(&command.plan),
        };
        match result {
            Ok(()) => {
                self.set_status(command.command_id, NetworkPlanStatus::Succeeded)?;
                Ok(())
            }
            Err(error) => {
                self.set_status(command.command_id, NetworkPlanStatus::Unknown)?;
                Err(NetworkExecutionError::MutationOutcomeUnknown(
                    error.to_string(),
                ))
            }
        }
    }

    pub fn reconcile<R: NetworkPlanRealizer>(
        &self,
        command_id: Uuid,
        realizer: &mut R,
    ) -> Result<NetworkPlanStatus, NetworkExecutionError> {
        let _guard = self
            .journal_lock
            .lock()
            .map_err(|_| NetworkExecutionError::CorruptJournal)?;
        let mut journal = self.load()?;
        let status = {
            let record = journal
                .plans
                .iter_mut()
                .find(|plan| plan.command_id == command_id)
                .ok_or(NetworkExecutionError::UnknownCommand)?;
            // A terminal REMOVE is only historical execution evidence. Realm
            // deletion requires fresh provider evidence that owned state is
            // still absent, so deliberately re-run the read-only removal
            // observation even when the journal previously recorded success.
            if record.status == NetworkPlanStatus::Succeeded
                && record.action == NetworkPlanAction::Apply
            {
                return Ok(record.status);
            }
            let observed = match record.action {
                NetworkPlanAction::Apply => realizer.observe(&record.plan),
                NetworkPlanAction::Remove => realizer.observe_removed(&record.plan),
            };
            record.status = match observed {
                Ok(true) => NetworkPlanStatus::Succeeded,
                Ok(false) | Err(_) => NetworkPlanStatus::Unknown,
            };
            record.status
        };
        self.store(&journal)?;
        Ok(status)
    }

    fn set_status(
        &self,
        command_id: Uuid,
        status: NetworkPlanStatus,
    ) -> Result<(), NetworkExecutionError> {
        let _guard = self
            .journal_lock
            .lock()
            .map_err(|_| NetworkExecutionError::CorruptJournal)?;
        let mut journal = self.load()?;
        let record = journal
            .plans
            .iter_mut()
            .find(|plan| plan.command_id == command_id)
            .ok_or(NetworkExecutionError::UnknownCommand)?;
        record.status = status;
        self.store(&journal)
    }

    pub fn status(&self, command_id: Uuid) -> Result<NetworkPlanStatus, NetworkExecutionError> {
        let _guard = self
            .journal_lock
            .lock()
            .map_err(|_| NetworkExecutionError::CorruptJournal)?;
        self.load()?
            .plans
            .into_iter()
            .find(|plan| plan.command_id == command_id)
            .map(|plan| plan.status)
            .ok_or(NetworkExecutionError::UnknownCommand)
    }

    fn validate(
        &self,
        command: &NetworkPlanCommand,
        _now_unix_ms: u64,
        authority: &NetworkControllerLease,
    ) -> Result<(), NetworkExecutionError> {
        if command.idempotency_key.trim().is_empty()
            || command.target.agent_id.trim().is_empty()
            || command.target.agent_epoch.trim().is_empty()
            || command.controller.controller_id.trim().is_empty()
            || command.controller.controller_epoch.trim().is_empty()
            || command.controller.fencing_token == 0
            || command.plan.node_id.trim().is_empty()
            || if let Some(fabric) = command.plan.fabric.as_ref() {
                fabric.local_host != command.plan.node_id
            } else {
                command.plan.node_id != command.target.agent_id
            }
            || command.plan.fingerprint_sha256.len() != 64
            || !command
                .plan
                .fingerprint_sha256
                .bytes()
                .all(|byte| byte.is_ascii_hexdigit())
        {
            return Err(NetworkExecutionError::InvalidCommand);
        }
        let expected_fingerprint = crate::canonical_plan_fingerprint(&command.plan)
            .map_err(|_| NetworkExecutionError::InvalidCommand)?;
        if command.plan.fingerprint_sha256 != expected_fingerprint {
            return Err(NetworkExecutionError::InvalidCommand);
        }
        command
            .plan
            .validate_fabric()
            .map_err(|_| NetworkExecutionError::InvalidCommand)?;
        if let Some(gateway) = &command.plan.gateway {
            crate::gateway::validate_plan(gateway)
                .map_err(|_| NetworkExecutionError::InvalidCommand)?;
        }
        if command.target != self.agent {
            return Err(NetworkExecutionError::StaleAgentEpoch);
        }
        if command.controller != *authority {
            return Err(NetworkExecutionError::StaleControllerLease);
        }
        Ok(())
    }

    fn journal_path(&self) -> PathBuf {
        self.root.join(JOURNAL_FILE)
    }

    fn load(&self) -> Result<Journal, NetworkExecutionError> {
        let path = self.journal_path();
        match fs::read(path) {
            Ok(bytes) => {
                serde_json::from_slice(&bytes).map_err(|_| NetworkExecutionError::CorruptJournal)
            }
            Err(error) if error.kind() == io::ErrorKind::NotFound => Ok(Journal::default()),
            Err(error) => Err(error.into()),
        }
    }

    fn store(&self, journal: &Journal) -> Result<(), NetworkExecutionError> {
        let path = self.journal_path();
        let temporary = path.with_extension("json.tmp");
        let bytes = serde_json::to_vec_pretty(journal)
            .map_err(|_| NetworkExecutionError::CorruptJournal)?;
        let mut file = File::create(&temporary)?;
        file.write_all(&bytes)?;
        file.sync_all()?;
        fs::rename(temporary, path)?;
        #[cfg(unix)]
        File::open(&self.root)?.sync_all()?;
        Ok(())
    }
}

/// A provider-specific realization is intentionally a narrow seam.  It does
/// not receive tenant authorization or allocate public identities.
pub trait NetworkPlanRealizer {
    type Error;

    fn realize(&mut self, plan: &NodeNetworkPlan) -> Result<(), Self::Error>;

    fn remove(&mut self, plan: &NodeNetworkPlan) -> Result<(), Self::Error>;

    fn observe(&mut self, _plan: &NodeNetworkPlan) -> Result<bool, Self::Error> {
        Ok(false)
    }

    fn observe_removed(&mut self, plan: &NodeNetworkPlan) -> Result<bool, Self::Error> {
        self.observe(plan).map(|present| !present)
    }
}

/// The Slice 2 flat-network realization. It owns only the bridge, TAPs and
/// DHCP process recorded under the supplied execution roots. Routed/NAT/policy
/// intents are deliberately rejected here until their Linux provider slice is
/// activated, so a flat agent cannot silently broaden its capability claim.
pub struct FlatNetworkRealizer {
    network: HostNetworkManager,
    dhcp: DhcpService,
    dnsmasq_binary: PathBuf,
    supervisor: Option<DnsmasqSupervisor>,
}

#[derive(Debug, Error)]
pub enum FlatNetworkError {
    #[error("flat network host realization failed: {0}")]
    Host(#[from] HostNetworkError),
    #[error("flat network DHCP realization failed: {0}")]
    Dhcp(#[from] DhcpError),
    #[error("flat network plan contains an unsupported routed intent")]
    UnsupportedIntent,
    #[error("flat network plan has no address realm")]
    MissingRealm,
    #[error("flat network observation found an unresolved owned endpoint")]
    MissingEndpoint,
}

impl FlatNetworkRealizer {
    pub fn open(
        network: HostNetworkConfig,
        network_ownership_root: impl Into<PathBuf>,
        dhcp_root: impl Into<PathBuf>,
        dnsmasq_binary: impl Into<PathBuf>,
    ) -> Result<Self, FlatNetworkError> {
        Self::open_with_tap_access(
            network,
            network_ownership_root,
            dhcp_root,
            dnsmasq_binary,
            None,
        )
    }

    pub fn open_with_tap_access(
        network: HostNetworkConfig,
        network_ownership_root: impl Into<PathBuf>,
        dhcp_root: impl Into<PathBuf>,
        dnsmasq_binary: impl Into<PathBuf>,
        tap_access: Option<crate::TapAccess>,
    ) -> Result<Self, FlatNetworkError> {
        let dnsmasq_binary = dnsmasq_binary.into();
        let dhcp = DhcpService::open(dhcp_root)?;
        let supervisor = dhcp.adopt_supervisor(&dnsmasq_binary)?;
        Ok(Self {
            network: HostNetworkManager::with_ownership_root(network, network_ownership_root)?
                .with_tap_access(tap_access)?,
            dhcp,
            dnsmasq_binary,
            supervisor,
        })
    }

    fn unsupported(intent: &NetworkPlanIntent) -> bool {
        matches!(
            intent,
            NetworkPlanIntent::Route(_)
                | NetworkPlanIntent::Gateway(_)
                | NetworkPlanIntent::Egress(_)
                | NetworkPlanIntent::PublicAddressBinding(_)
                | NetworkPlanIntent::PolicyDefault(_)
                | NetworkPlanIntent::Policy(_)
        )
    }
}

impl NetworkPlanRealizer for FlatNetworkRealizer {
    type Error = FlatNetworkError;

    fn realize(&mut self, plan: &NodeNetworkPlan) -> Result<(), Self::Error> {
        if plan.intents.iter().any(Self::unsupported) {
            return Err(FlatNetworkError::UnsupportedIntent);
        }
        let (prefix, gateway) = plan
            .intents
            .iter()
            .find_map(|intent| match intent {
                NetworkPlanIntent::AddressRealm {
                    prefix, gateway, ..
                } => Some((prefix, *gateway)),
                _ => None,
            })
            .ok_or(FlatNetworkError::MissingRealm)?;
        self.network.ensure_bridge()?;
        self.network.ensure_gateway(GatewaySpec {
            address: gateway,
            prefix_len: prefix.prefix_len,
        })?;
        self.dhcp.configure(DhcpConfig {
            subnet: format!("{}/{}", prefix.network, prefix.prefix_len),
            gateway,
            dns: Vec::new(),
            interface: self
                .network
                .bridge_name()
                .ok_or(FlatNetworkError::MissingRealm)?,
            lease_seconds: 3600,
        })?;
        for intent in &plan.intents {
            if let NetworkPlanIntent::EndpointAttachment {
                endpoint_id,
                mac,
                fixed_ip,
                ..
            } = intent
            {
                let endpoint_id = endpoint_id.to_string();
                self.network.ensure_tap(&TapSpec {
                    instance_id: plan.plan_id.to_string(),
                    port_id: endpoint_id.clone(),
                    mac: mac.clone(),
                })?;
                self.dhcp.upsert_binding(DhcpBinding {
                    port_id: endpoint_id,
                    mac: mac.clone(),
                    address: *fixed_ip,
                })?;
            }
        }
        match self.supervisor.as_mut() {
            Some(supervisor) => self.dhcp.reload(supervisor)?,
            None => self.supervisor = Some(self.dhcp.start(&self.dnsmasq_binary)?),
        }
        Ok(())
    }

    fn remove(&mut self, plan: &NodeNetworkPlan) -> Result<(), Self::Error> {
        for intent in &plan.intents {
            if let NetworkPlanIntent::EndpointAttachment {
                endpoint_id, mac, ..
            } = intent
            {
                self.dhcp.remove_binding(&endpoint_id.to_string())?;
                self.network.delete_tap(&TapSpec {
                    instance_id: plan.plan_id.to_string(),
                    port_id: endpoint_id.to_string(),
                    mac: mac.clone(),
                })?;
            }
        }
        if let Some(supervisor) = self.supervisor.as_mut() {
            supervisor.stop()?;
            self.supervisor = None;
        }
        self.network.cleanup_if_unused()?;
        Ok(())
    }

    fn observe(&mut self, plan: &NodeNetworkPlan) -> Result<bool, Self::Error> {
        for intent in &plan.intents {
            if let NetworkPlanIntent::EndpointAttachment { endpoint_id, .. } = intent {
                let spec = TapSpec {
                    instance_id: plan.plan_id.to_string(),
                    port_id: endpoint_id.to_string(),
                    mac: match intent {
                        NetworkPlanIntent::EndpointAttachment { mac, .. } => mac.clone(),
                        _ => unreachable!(),
                    },
                };
                self.network
                    .resolve_owned_tap(&spec)
                    .map_err(FlatNetworkError::Host)?;
                if self.dhcp.binding(&endpoint_id.to_string()).is_none() {
                    return Err(FlatNetworkError::MissingEndpoint);
                }
            }
        }
        Ok(true)
    }
}

pub fn journal_path(root: &Path) -> PathBuf {
    root.join(JOURNAL_FILE)
}

#[cfg(test)]
#[allow(clippy::expect_used)]
mod tests {
    use super::*;
    use crate::compile_node_network_plan;
    use o3k_domain::{
        AddressRealm, EndpointIntent, Ipv4Prefix, NetworkCapability, NetworkIntent,
        NetworkProtocol, PolicyAction, PolicyDirection, PolicyIntent, PortRange, RouteIntent,
    };
    use std::{collections::HashSet, net::Ipv4Addr};

    fn plan() -> NodeNetworkPlan {
        let prefix =
            |ip: &str, length| Ipv4Prefix::new(ip.parse().expect("ip"), length).expect("prefix");
        let intent = NetworkIntent {
            id: Uuid::from_u128(1),
            project_id: "project-a".into(),
            realm: AddressRealm {
                id: Uuid::from_u128(2),
                network_id: Uuid::from_u128(1),
                project_id: "project-a".into(),
                prefix: prefix("10.0.0.0", 24),
                overlapping_prefixes: false,
            },
            address_pools: vec![],
            endpoints: vec![EndpointIntent {
                id: Uuid::from_u128(3),
                project_id: "project-a".into(),
                realm_id: Uuid::from_u128(2),
                mac: "02:00:00:00:00:03".into(),
                fixed_ip: Ipv4Addr::new(10, 0, 0, 3),
                generation: 1,
            }],
            routes: vec![RouteIntent {
                destination: prefix("0.0.0.0", 0),
                next_hop: Some(Ipv4Addr::new(10, 0, 0, 1)),
            }],
            gateways: vec![],
            egress: vec![],
            public_addresses: vec![],
            policies: vec![PolicyIntent {
                id: Uuid::from_u128(10),
                endpoint_id: Uuid::from_u128(3),
                direction: PolicyDirection::Egress,
                protocol: NetworkProtocol::Tcp,
                ports: Some(PortRange {
                    start: 443,
                    end: 443,
                }),
                source: None,
                destination: Some(prefix("0.0.0.0", 0)),
                action: PolicyAction::Allow,
            }],
            generation: 1,
            state: o3k_domain::NetworkIntentState::Requested,
        };
        let capabilities = [
            NetworkCapability::Ipv4,
            NetworkCapability::EndpointAttachment,
            NetworkCapability::Routing,
            NetworkCapability::StatefulPolicy,
        ]
        .into_iter()
        .collect::<HashSet<_>>();
        compile_node_network_plan(
            &intent,
            "node-a",
            Uuid::from_u128(4),
            100,
            &capabilities,
            &[],
        )
        .expect("plan")
    }

    fn command() -> NetworkPlanCommand {
        NetworkPlanCommand {
            command_id: Uuid::from_u128(10),
            operation_id: Uuid::from_u128(4),
            idempotency_key: "idempotency-1".into(),
            action: NetworkPlanAction::Apply,
            target: NetworkAgentIdentity {
                agent_id: "node-a".into(),
                agent_epoch: "epoch-1".into(),
            },
            controller: NetworkControllerLease {
                controller_id: "controller-a".into(),
                controller_epoch: "epoch-1".into(),
                fencing_token: 7,
            },
            deadline_unix_ms: 100,
            plan: plan(),
        }
    }

    fn fabric_for_other_agent(mut value: NodeNetworkPlan) -> NetworkPlanCommand {
        use o3k_domain::{
            EndpointLocation, FabricEndpointRoute, FabricPeer, FabricProviderKind,
            NamespacedRoutedFabricPlan, RealmEncapsulationBinding, RealmEndpointDirectory,
        };
        let prefix =
            |ip: &str, length| Ipv4Prefix::new(ip.parse().expect("ip"), length).expect("prefix");
        value.node_id = "host-a".to_owned();
        let fabric = NamespacedRoutedFabricPlan {
            local_host: "host-a".to_owned(),
            local_fabric_transport_ip: Ipv4Addr::new(198, 18, 0, 1),
            local_fabric_generation: 2,
            local_underlay_mtu: 1500,
            local_fabric_mtu: 1440,
            realm_id: Uuid::from_u128(22),
            realm_prefix: prefix("10.0.0.0", 24),
            encapsulation: RealmEncapsulationBinding {
                fabric_domain_id: Uuid::from_u128(100),
                realm_id: Uuid::from_u128(22),
                provider_kind: FabricProviderKind::Vxlan,
                provider_segment_id: 101,
                binding_generation: 1,
            },
            directory_generation: 3,
            directory: RealmEndpointDirectory {
                realm_id: Uuid::from_u128(22),
                prefix: prefix("10.0.0.0", 24),
                directory_generation: 3,
                proxy_mac: "02:11:22:33:44:55".to_owned(),
                entries: vec![EndpointLocation {
                    endpoint_id: Uuid::from_u128(33),
                    project_id: "project-a".to_owned(),
                    realm_id: Uuid::from_u128(22),
                    fixed_ip: Ipv4Addr::new(10, 0, 0, 3),
                    mac: "02:00:00:00:00:03".to_owned(),
                    selected_host: "host-b".to_owned(),
                    endpoint_generation: 4,
                    placement_generation: 5,
                }],
            },
            proxy_mac: "02:11:22:33:44:55".to_owned(),
            tenant_mtu: 1390,
            policy_generation: 1,
            policies: Vec::new(),
            policy_defaults: Vec::new(),
            public_bindings: Vec::new(),
            routes: vec![FabricEndpointRoute {
                realm_id: Uuid::from_u128(22),
                destination: prefix("10.0.0.3", 32),
                endpoint_id: Uuid::from_u128(33),
                target_host: "host-b".to_owned(),
                target_fabric_transport_ip: Ipv4Addr::new(198, 18, 0, 2),
                endpoint_generation: 4,
                placement_generation: 5,
                realm_binding_generation: 1,
                fabric_generation: 6,
            }],
            peers: vec![FabricPeer {
                host_id: "host-b".to_owned(),
                public_key: "public-key".to_owned(),
                underlay_endpoint: "192.0.2.2:65001".to_owned(),
                fabric_transport_ip: Ipv4Addr::new(198, 18, 0, 2),
                fabric_generation: 6,
            }],
        };
        value = value
            .with_fabric(fabric)
            .expect("valid host-bound fabric plan");
        let mut result = command();
        result.target.agent_id = "network-agent-a".to_owned();
        result.plan = value;
        result
    }

    #[derive(Default)]
    struct RecordingRealizer {
        calls: usize,
        observed: bool,
    }

    impl NetworkPlanRealizer for RecordingRealizer {
        type Error = &'static str;

        fn realize(&mut self, _plan: &NodeNetworkPlan) -> Result<(), Self::Error> {
            self.calls += 1;
            Ok(())
        }

        fn remove(&mut self, _plan: &NodeNetworkPlan) -> Result<(), Self::Error> {
            self.calls += 1;
            Ok(())
        }

        fn observe(&mut self, _plan: &NodeNetworkPlan) -> Result<bool, Self::Error> {
            Ok(self.observed)
        }
    }

    #[test]
    fn equivalent_command_replays_after_executor_restart() -> Result<(), Box<dyn std::error::Error>>
    {
        let root = tempfile_path("replay");
        let command = command();
        let executor =
            NetworkPlanExecutor::open(&root, command.target.clone(), command.controller.clone())?;
        let mut realizer = RecordingRealizer {
            observed: true,
            ..Default::default()
        };
        assert_eq!(
            executor.execute(&command, 1, &mut realizer)?,
            PlanAdmission::Accepted
        );
        assert_eq!(realizer.calls, 1);
        drop(executor);
        let restarted =
            NetworkPlanExecutor::open(&root, command.target.clone(), command.controller.clone())?;
        assert_eq!(restarted.admit(&command, 2)?, PlanAdmission::Replayed);
        assert!(restarted.accepted(command.command_id)?);
        let _ = fs::remove_dir_all(root);
        Ok(())
    }

    #[test]
    fn fabric_plan_host_identity_is_distinct_from_agent_identity()
    -> Result<(), Box<dyn std::error::Error>> {
        let root = tempfile_path("fabric-host-agent-identity");
        let command = fabric_for_other_agent(plan());
        let executor =
            NetworkPlanExecutor::open(&root, command.target.clone(), command.controller.clone())?;
        let mut realizer = RecordingRealizer::default();
        assert_eq!(
            executor.execute(&command, 1, &mut realizer)?,
            PlanAdmission::Accepted
        );
        assert_eq!(realizer.calls, 1);
        let _ = fs::remove_dir_all(root);
        Ok(())
    }

    #[test]
    fn equivalent_command_replays_after_controller_takeover()
    -> Result<(), Box<dyn std::error::Error>> {
        let root = tempfile_path("controller-takeover-replay");
        let command = command();
        let first =
            NetworkPlanExecutor::open(&root, command.target.clone(), command.controller.clone())?;
        let mut realizer = RecordingRealizer {
            observed: true,
            ..Default::default()
        };
        assert_eq!(first.admit(&command, 1)?, PlanAdmission::Accepted);
        drop(first);

        let mut takeover = command.clone();
        takeover.controller = NetworkControllerLease {
            controller_id: "controller-b".into(),
            controller_epoch: "epoch-2".into(),
            fencing_token: 8,
        };
        let second =
            NetworkPlanExecutor::open(&root, takeover.target.clone(), takeover.controller.clone())?;
        assert_eq!(
            second.admit(&takeover, 2)?,
            PlanAdmission::RequiresObservation
        );
        assert_eq!(
            second.reconcile(takeover.command_id, &mut realizer)?,
            NetworkPlanStatus::Succeeded
        );
        let _ = fs::remove_dir_all(root);
        Ok(())
    }

    #[test]
    fn remove_action_calls_cleanup_and_reconciles_absence() -> Result<(), Box<dyn std::error::Error>>
    {
        let root = tempfile_path("remove-action");
        let mut command = command();
        command.action = NetworkPlanAction::Remove;
        let executor =
            NetworkPlanExecutor::open(&root, command.target.clone(), command.controller.clone())?;
        let mut realizer = RecordingRealizer {
            calls: 0,
            observed: false,
        };
        assert_eq!(
            executor.execute(&command, 1, &mut realizer)?,
            PlanAdmission::Accepted
        );
        assert_eq!(realizer.calls, 1);
        assert_eq!(
            executor.reconcile(command.command_id, &mut realizer)?,
            NetworkPlanStatus::Succeeded
        );
        let _ = fs::remove_dir_all(root);
        Ok(())
    }

    #[test]
    fn conflicting_payload_and_stale_identity_fail_closed() -> Result<(), Box<dyn std::error::Error>>
    {
        let root = tempfile_path("fences");
        let command = command();
        let executor =
            NetworkPlanExecutor::open(&root, command.target.clone(), command.controller.clone())?;
        executor.admit(&command, 1)?;
        let mut conflict = command.clone();
        conflict.plan.fingerprint_sha256 = "0".repeat(64);
        assert!(matches!(
            executor.admit(&conflict, 1),
            Err(NetworkExecutionError::InvalidCommand)
        ));
        let mut stale = command.clone();
        stale.target.agent_epoch = "epoch-0".into();
        assert!(matches!(
            executor.admit(&stale, 1),
            Err(NetworkExecutionError::StaleAgentEpoch)
        ));
        let _ = fs::remove_dir_all(root);
        Ok(())
    }

    #[test]
    fn semantic_payload_change_with_reused_fingerprint_is_rejected() {
        let root = tempfile_path("fingerprint");
        let command = command();
        let executor =
            NetworkPlanExecutor::open(&root, command.target.clone(), command.controller.clone())
                .expect("executor");
        let mut tampered = command.clone();
        tampered.command_id = Uuid::from_u128(11);
        tampered.operation_id = Uuid::from_u128(5);
        tampered.plan.operation_id = tampered.operation_id;
        if let Some(NetworkPlanIntent::Policy(policy)) = tampered
            .plan
            .intents
            .iter_mut()
            .find(|intent| matches!(intent, NetworkPlanIntent::Policy(_)))
        {
            policy.ports = Some(o3k_domain::PortRange {
                start: 8443,
                end: 8443,
            });
        }
        assert!(matches!(
            executor.admit(&tampered, 1),
            Err(NetworkExecutionError::InvalidCommand)
        ));
        let _ = fs::remove_dir_all(root);
    }

    #[test]
    fn deadline_is_checked_before_journaling() -> Result<(), Box<dyn std::error::Error>> {
        let root = tempfile_path("deadline");
        let command = command();
        let executor =
            NetworkPlanExecutor::open(&root, command.target.clone(), command.controller.clone())?;
        assert!(matches!(
            executor.admit(&command, 101),
            Err(NetworkExecutionError::DeadlineExpired)
        ));
        assert!(!executor.accepted(command.command_id)?);
        let _ = fs::remove_dir_all(root);
        Ok(())
    }

    #[test]
    fn failed_realization_is_unknown_until_observation_resolves_it()
    -> Result<(), Box<dyn std::error::Error>> {
        struct FailingRealizer {
            observed: bool,
        }

        impl NetworkPlanRealizer for FailingRealizer {
            type Error = &'static str;

            fn realize(&mut self, _plan: &NodeNetworkPlan) -> Result<(), Self::Error> {
                Err("transport interrupted")
            }

            fn remove(&mut self, _plan: &NodeNetworkPlan) -> Result<(), Self::Error> {
                Err("transport interrupted")
            }

            fn observe(&mut self, _plan: &NodeNetworkPlan) -> Result<bool, Self::Error> {
                Ok(self.observed)
            }
        }

        let root = tempfile_path("unknown");
        let command = command();
        let executor =
            NetworkPlanExecutor::open(&root, command.target.clone(), command.controller.clone())?;
        let mut realizer = FailingRealizer { observed: false };
        assert!(matches!(
            executor.execute(&command, 1, &mut realizer),
            Err(NetworkExecutionError::MutationOutcomeUnknown(_))
        ));
        assert_eq!(
            executor.admit(&command, 2)?,
            PlanAdmission::ReplayedUnknown,
            "a duplicate must not mutate while the outcome is unknown"
        );
        realizer.observed = true;
        assert_eq!(
            executor.reconcile(command.command_id, &mut realizer)?,
            NetworkPlanStatus::Succeeded
        );
        let _ = fs::remove_dir_all(root);
        Ok(())
    }

    #[test]
    fn restarted_executor_reconciles_pending_state_after_lease_takeover()
    -> Result<(), Box<dyn std::error::Error>> {
        struct InterruptedRealizer {
            observed: bool,
        }

        impl NetworkPlanRealizer for InterruptedRealizer {
            type Error = &'static str;

            fn realize(&mut self, _plan: &NodeNetworkPlan) -> Result<(), Self::Error> {
                Err("interrupted")
            }

            fn remove(&mut self, _plan: &NodeNetworkPlan) -> Result<(), Self::Error> {
                Err("interrupted")
            }

            fn observe(&mut self, _plan: &NodeNetworkPlan) -> Result<bool, Self::Error> {
                Ok(self.observed)
            }
        }

        let root = tempfile_path("takeover");
        let command = command();
        let executor =
            NetworkPlanExecutor::open(&root, command.target.clone(), command.controller.clone())?;
        let mut realizer = InterruptedRealizer { observed: false };
        assert!(matches!(
            executor.execute(&command, 1, &mut realizer),
            Err(NetworkExecutionError::MutationOutcomeUnknown(_))
        ));
        drop(executor);
        let mut takeover = command.controller.clone();
        takeover.controller_epoch = "epoch-2".to_owned();
        takeover.fencing_token = 8;
        let restarted = NetworkPlanExecutor::open(&root, command.target, takeover)?;
        assert_eq!(restarted.pending()?.len(), 1);
        realizer.observed = true;
        let recovered = restarted.reconcile_pending(&mut realizer)?;
        assert_eq!(
            recovered,
            vec![(command.command_id, NetworkPlanStatus::Succeeded)]
        );
        assert!(restarted.pending()?.is_empty());
        let _ = fs::remove_dir_all(root);
        Ok(())
    }

    fn tempfile_path(label: &str) -> PathBuf {
        std::env::temp_dir().join(format!("o3k-network-executor-{label}-{}", Uuid::new_v4()))
    }
}
