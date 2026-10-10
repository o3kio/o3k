use async_trait::async_trait;
use o3k_network;
use o3k_network_protocol;
use serde::Deserialize;
use std::collections::{BTreeMap, BTreeSet};
use std::path::PathBuf;
use std::sync::Arc;
use tracing;
use uuid::Uuid;

#[derive(Debug, Clone, Deserialize)]
#[serde(deny_unknown_fields)]
struct NetworkAgentControlTarget {
    host_id: String,
    agent_id: String,
    agent_epoch: String,
    endpoint: String,
    tls_server_name: String,
}

#[derive(Clone)]
struct NetworkAgentTransport {
    endpoint: String,
    server_name: String,
}

#[derive(Clone)]
pub(crate) struct NetworkAgentDispatcher {
    legacy_target: Option<NetworkAgentTransport>,
    /// Indexed by stable host identity. Network-agent IDs and epochs belong
    /// only to this independent execution directory.
    fabric_targets: BTreeMap<String, NetworkAgentControlTarget>,
    control: Option<NetworkAgentControlLease>,
    control_lock: Arc<tokio::sync::Mutex<()>>,
    pub(crate) ca_certificate: PathBuf,
    pub(crate) client_certificate: PathBuf,
    pub(crate) client_key: PathBuf,
    #[cfg(test)]
    pre_supersession_gate: Option<(Arc<tokio::sync::Notify>, Arc<tokio::sync::Notify>)>,
    #[cfg(test)]
    supersession_gate: Option<(Arc<tokio::sync::Notify>, Arc<tokio::sync::Notify>)>,
    #[cfg(test)]
    result_persistence_gate: Option<(Arc<tokio::sync::Notify>, Arc<tokio::sync::Notify>)>,
}

#[derive(Clone)]
struct NetworkAgentControlLease {
    coordination: Arc<dyn o3k_store::CoordinationRepository>,
    durable: Arc<dyn o3k_store::DurableStore>,
    controller_id: o3k_store::ControllerId,
    controller_epoch: o3k_store::ControllerEpoch,
}

#[derive(Clone)]
enum FabricWorkDispatch {
    New,
    Supersede { command_id: String, revision: u64 },
    ExistingSuccessor { command_id: String },
}

struct RealmPlanAttempt<'a> {
    operation_id: Uuid,
    deadline_unix_ms: u64,
    lease: &'a RealmReconciliationLease,
    historical: Option<&'a o3k_store::NetworkPlanWorkRecord>,
}

struct LatestRealmHostWork {
    record: o3k_store::NetworkPlanWorkRecord,
    command: o3k_network::NetworkPlanCommand,
}

/// Durable plan history is the cleanup authority when a host disappears from
/// the current canonical endpoint directory. Realm generation, rather than
/// history listing order, selects the latest ownership-relevant host command
/// (including Apply/Remove/Apply).
fn latest_realm_host_work(
    history: Vec<o3k_store::NetworkPlanWorkRecord>,
    realm_id: Uuid,
) -> Result<BTreeMap<String, LatestRealmHostWork>, String> {
    let mut latest: BTreeMap<String, (u64, LatestRealmHostWork)> = BTreeMap::new();
    for record in history {
        let command: o3k_network::NetworkPlanCommand = serde_json::from_slice(&record.snapshot)
            .map_err(|_| format!("durable network plan {} is corrupt", record.command_id))?;
        let Some(fabric) = command.plan.fabric.as_ref() else {
            continue;
        };
        if fabric.realm_id != realm_id {
            continue;
        }
        let command_id = Uuid::parse_str(&record.command_id).map_err(|_| {
            format!(
                "durable Fabric command {} has an invalid ID",
                record.command_id
            )
        })?;
        if command.command_id != command_id
            || command.operation_id != record.operation_id
            || command.idempotency_key != record.idempotency_key
            || command.target.agent_id != record.target_agent_id
            || command.plan.node_id != record.target_host_id
            || fabric.local_host != record.target_host_id
        {
            return Err(format!(
                "durable Fabric plan {} has conflicting cleanup ownership",
                record.command_id
            ));
        }
        let generation = command
            .plan
            .resource_generations
            .get(&realm_id)
            .copied()
            .ok_or_else(|| {
                format!(
                    "durable Fabric work {} lacks Realm generation",
                    record.command_id
                )
            })?;
        let host_id = record.target_host_id.clone();
        match latest.get(&host_id) {
            Some((current_generation, _current)) if *current_generation > generation => {}
            Some((current_generation, current)) if *current_generation == generation => {
                if current.record.command_id != record.command_id
                    && current.command.action != command.action
                {
                    return Err(format!(
                        "durable Fabric host {host_id} has conflicting Apply/Remove history at Realm generation {generation}"
                    ));
                }
                if current.record.command_id != record.command_id {
                    return Err(format!(
                        "durable Fabric host {host_id} has ambiguous same-generation command history at Realm generation {generation}"
                    ));
                }
            }
            _ => {
                latest.insert(
                    host_id,
                    (generation, LatestRealmHostWork { record, command }),
                );
            }
        }
    }
    Ok(latest
        .into_iter()
        .map(|(host, (_, latest))| (host, latest))
        .collect())
}

fn realm_host_may_still_own(work: &LatestRealmHostWork) -> bool {
    !(work.command.action == o3k_network::NetworkPlanAction::Remove
        && work.record.state == o3k_store::NetworkPlanWorkState::Succeeded)
}

fn recovery_successor_parent(record: &o3k_store::NetworkPlanWorkRecord) -> Option<&str> {
    record
        .idempotency_key
        .split_once(":successor-of:")
        .map(|(_, suffix)| suffix.split(":agent-epoch:").next().unwrap_or(suffix))
}

fn execution_command_id_for_agent_epoch(command_id: Uuid, agent_epoch: &str) -> Uuid {
    Uuid::new_v5(
        &command_id,
        format!("execution-agent-epoch:{agent_epoch}").as_bytes(),
    )
}

const NETWORK_AGENT_CONTROL_TTL: std::time::Duration = std::time::Duration::from_secs(15);
// Deliberately shorter than the coordination lease. The agent independently
// stops accepting mutations if renewal is lost, even while a stale controller
// still believes its database lease is current.
const NETWORK_AGENT_REMOTE_LEASE: std::time::Duration = std::time::Duration::from_secs(8);

pub(crate) fn network_dispatcher_from_env(
    coordination: Arc<dyn o3k_store::CoordinationRepository>,
    durable: Arc<dyn o3k_store::DurableStore>,
    controller_id: o3k_store::ControllerId,
    controller_epoch: o3k_store::ControllerEpoch,
) -> Result<Option<Arc<dyn o3k_network::NetworkPlanDispatcher>>, Box<dyn std::error::Error>> {
    let names = [
        "O3K_NETWORK_AGENT_ENDPOINT",
        "O3K_NETWORK_AGENT_SERVER_NAME",
        "O3K_NETWORK_AGENT_CA",
        "O3K_NETWORK_AGENT_CLIENT_CERT",
        "O3K_NETWORK_AGENT_CLIENT_KEY",
    ];
    let values = names
        .iter()
        .map(|name| std::env::var(name).ok())
        .collect::<Vec<_>>();
    let directory_json = std::env::var("O3K_NETWORK_AGENT_DIRECTORY").ok();
    if values.iter().all(Option::is_none) && directory_json.is_none() {
        return Ok(None);
    }
    let credentials_configured = values[2..].iter().all(Option::is_some);
    if !credentials_configured {
        return Err("O3K network agent CA, client certificate, and client key are required".into());
    }
    let (legacy_target, fabric_targets) = match (values[0].as_ref(), values[1].as_ref(), directory_json) {
        (Some(endpoint), Some(server_name), None) => (
            Some(NetworkAgentTransport { endpoint: endpoint.clone(), server_name: server_name.clone() }),
            BTreeMap::new(),
        ),
        (None, None, Some(json)) => {
            let configured: Vec<NetworkAgentControlTarget> = serde_json::from_str(&json)?;
            let mut targets = BTreeMap::new();
            let mut agent_ids = std::collections::BTreeSet::new();
            for target in configured {
                if !o3k_provider::is_valid_host_id(&target.host_id)
                    || target.agent_id.trim().is_empty()
                    || target.agent_epoch.trim().is_empty()
                    || !target.endpoint.starts_with("https://")
                    || target.tls_server_name.trim().is_empty()
                    || !agent_ids.insert(target.agent_id.clone())
                    || targets.insert(target.host_id.clone(), target).is_some()
                {
                    return Err("O3K_NETWORK_AGENT_DIRECTORY contains an invalid or duplicate target".into());
                }
            }
            if targets.is_empty() {
                return Err("O3K_NETWORK_AGENT_DIRECTORY must contain at least one target".into());
            }
            (None, targets)
        }
        _ => return Err("configure either the legacy single-agent endpoint or O3K_NETWORK_AGENT_DIRECTORY, not both".into()),
    };
    Ok(Some(Arc::new(NetworkAgentDispatcher {
        legacy_target,
        fabric_targets,
        control: Some(NetworkAgentControlLease {
            coordination,
            durable,
            controller_id,
            controller_epoch,
        }),
        control_lock: Arc::new(tokio::sync::Mutex::new(())),
        ca_certificate: PathBuf::from(values[2].as_ref().ok_or("missing network agent CA")?),
        client_certificate: PathBuf::from(
            values[3]
                .as_ref()
                .ok_or("missing network agent client certificate")?,
        ),
        client_key: PathBuf::from(
            values[4]
                .as_ref()
                .ok_or("missing network agent client key")?,
        ),
        #[cfg(test)]
        pre_supersession_gate: None,
        #[cfg(test)]
        supersession_gate: None,
        #[cfg(test)]
        result_persistence_gate: None,
    })))
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct FabricHostEnrollmentConfig {
    host_id: String,
    agent_id: String,
    public_key: String,
    underlay_endpoint: String,
    fabric_transport_ip: String,
    provider_version: String,
    fabric_generation: u64,
    underlay_mtu: u16,
    fabric_mtu: u16,
    administrative_state: String,
}

/// Loads operator-enrolled, non-secret host identities into canonical durable
/// state. A conflicting current identity is rejected; rotating one requires
/// an explicit successor generation in configuration.
pub(crate) async fn enroll_fabric_hosts_from_env(
    network: &o3k_network::NetworkService,
) -> Result<(), Box<dyn std::error::Error>> {
    let Some(json) = std::env::var("O3K_FABRIC_HOST_IDENTITIES").ok() else {
        return Ok(());
    };
    let configured: Vec<FabricHostEnrollmentConfig> = serde_json::from_str(&json)?;
    if configured.is_empty() {
        return Err("O3K_FABRIC_HOST_IDENTITIES must not be an empty list".into());
    }
    let mut host_ids = std::collections::BTreeSet::new();
    for host in configured {
        if !host_ids.insert(host.host_id.clone()) {
            return Err("O3K_FABRIC_HOST_IDENTITIES has duplicate stable host IDs".into());
        }
        let identity = o3k_store::FabricHostTransportIdentityRecord {
            host_id: host.host_id,
            agent_id: host.agent_id,
            public_key: host.public_key,
            underlay_endpoint: host.underlay_endpoint,
            fabric_transport_ip: host.fabric_transport_ip.parse()?,
            provider_version: host.provider_version,
            fabric_generation: host.fabric_generation,
            underlay_mtu: host.underlay_mtu,
            fabric_mtu: host.fabric_mtu,
            administrative_state: host.administrative_state,
        };
        let current = network
            .list_fabric_host_transport_identities()
            .await?
            .into_iter()
            .find(|current| current.host_id == identity.host_id);
        let expected_generation = match current {
            None => None,
            Some(current) if current == identity => Some(identity.fabric_generation),
            Some(current) if identity.fabric_generation == current.fabric_generation + 1 => {
                Some(current.fabric_generation)
            }
            Some(_) => return Err("Fabric host identity conflicts with durable generation".into()),
        };
        network
            .enroll_fabric_host_transport_identity(&identity, expected_generation)
            .await?;
    }
    Ok(())
}

pub(crate) async fn validate_fabric_control_targets(
    network: &o3k_network::NetworkService,
    dispatcher: &dyn o3k_network::NetworkPlanDispatcher,
) -> Result<(), Box<dyn std::error::Error>> {
    let identities = network.list_fabric_host_transport_identities().await?;
    let configured = dispatcher.configured_target_hosts();
    let configured_set = configured.iter().cloned().collect::<BTreeSet<_>>();
    if configured_set.len() != configured.len() || configured_set.is_empty() {
        return Err("Fabric requires a non-empty, unique network-agent target directory".into());
    }
    let enrolled = identities
        .iter()
        .filter(|identity| identity.administrative_state == "enabled")
        .map(|identity| identity.host_id.clone())
        .collect::<BTreeSet<_>>();
    if enrolled != configured_set {
        return Err(
            "enabled Fabric hosts and network-agent targets must have identical host IDs".into(),
        );
    }
    for host_id in configured_set {
        if !o3k_provider::is_valid_host_id(&host_id)
            || dispatcher.target_for_host(&host_id).await?.is_none()
        {
            return Err("Fabric host has an invalid or unresolved network-agent target".into());
        }
    }
    Ok(())
}

#[derive(Clone)]
pub(crate) struct FabricRealmReconciler {
    pub(crate) network: o3k_network::NetworkService,
    pub(crate) coordination: Arc<dyn o3k_store::CoordinationRepository>,
    pub(crate) durable: Arc<dyn o3k_store::DurableStore>,
    pub(crate) registry: Arc<dyn o3k_provider::AgentNodeRegistry>,
    pub(crate) dispatcher: Arc<dyn o3k_network::NetworkPlanDispatcher>,
    pub(crate) controller: o3k_network::NetworkControllerLease,
    pub(crate) fabric_domain_id: Uuid,
    pub(crate) network_external_realm_id: Option<Uuid>,
    pub(crate) public_allocator: Option<Arc<o3k_network::PublicAddressAllocator>>,
    pub(crate) reconciliation_locks:
        Arc<std::sync::Mutex<BTreeMap<Uuid, std::sync::Weak<tokio::sync::Mutex<()>>>>>,
}

const FABRIC_REALM_LEASE_TTL: std::time::Duration = std::time::Duration::from_secs(30);
const FABRIC_REALM_LEASE_RENEWAL: std::time::Duration = std::time::Duration::from_secs(8);

struct RealmReconciliationLease {
    coordination: Arc<dyn o3k_store::CoordinationRepository>,
    work_key: String,
    controller_id: o3k_store::ControllerId,
    controller_epoch: o3k_store::ControllerEpoch,
    fencing_token: u64,
    valid: Arc<std::sync::atomic::AtomicBool>,
    renewal: tokio::task::JoinHandle<()>,
}

struct AgentControlLeaseGuard {
    coordination: Arc<dyn o3k_store::CoordinationRepository>,
    work_key: String,
    controller_id: o3k_store::ControllerId,
    controller_epoch: o3k_store::ControllerEpoch,
    fencing_token: u64,
    valid: Arc<std::sync::atomic::AtomicBool>,
    renewal: tokio::task::JoinHandle<()>,
}

impl AgentControlLeaseGuard {
    fn start(
        coordination: Arc<dyn o3k_store::CoordinationRepository>,
        work_key: String,
        controller_id: o3k_store::ControllerId,
        controller_epoch: o3k_store::ControllerEpoch,
        fencing_token: u64,
    ) -> Self {
        let valid = Arc::new(std::sync::atomic::AtomicBool::new(true));
        let renewal = {
            let coordination = coordination.clone();
            let work_key = work_key.clone();
            let controller_id = controller_id.clone();
            let controller_epoch = controller_epoch.clone();
            let valid = valid.clone();
            tokio::spawn(async move {
                let mut interval = tokio::time::interval(NETWORK_AGENT_CONTROL_TTL / 3);
                interval.tick().await;
                loop {
                    interval.tick().await;
                    match coordination
                        .renew_work_lease(
                            &work_key,
                            &controller_id,
                            &controller_epoch,
                            fencing_token,
                            NETWORK_AGENT_CONTROL_TTL,
                        )
                        .await
                    {
                        Ok(true) => {}
                        Ok(false) | Err(_) => {
                            valid.store(false, std::sync::atomic::Ordering::Release);
                            break;
                        }
                    }
                }
            })
        };
        Self {
            coordination,
            work_key,
            controller_id,
            controller_epoch,
            fencing_token,
            valid,
            renewal,
        }
    }

    async fn assert_current(&self) -> Result<(), o3k_network::NetworkDispatchError> {
        if !self.valid.load(std::sync::atomic::Ordering::Acquire)
            || !self
                .coordination
                .renew_work_lease(
                    &self.work_key,
                    &self.controller_id,
                    &self.controller_epoch,
                    self.fencing_token,
                    NETWORK_AGENT_CONTROL_TTL,
                )
                .await
                .map_err(|_| o3k_network::NetworkDispatchError::Unavailable)?
        {
            self.valid
                .store(false, std::sync::atomic::Ordering::Release);
            return Err(o3k_network::NetworkDispatchError::Unavailable);
        }
        Ok(())
    }
}

impl Drop for AgentControlLeaseGuard {
    fn drop(&mut self) {
        self.valid
            .store(false, std::sync::atomic::Ordering::Release);
        self.renewal.abort();
        let coordination = self.coordination.clone();
        let work_key = self.work_key.clone();
        let controller_id = self.controller_id.clone();
        let controller_epoch = self.controller_epoch.clone();
        let token = self.fencing_token;
        if let Ok(runtime) = tokio::runtime::Handle::try_current() {
            runtime.spawn(async move {
                let _ = coordination
                    .relinquish_work_lease_preserving_fence(
                        &work_key,
                        &controller_id,
                        &controller_epoch,
                        token,
                    )
                    .await;
            });
        }
    }
}

impl RealmReconciliationLease {
    async fn acquire(
        coordination: Arc<dyn o3k_store::CoordinationRepository>,
        controller: &o3k_network::NetworkControllerLease,
        realm_id: Uuid,
    ) -> Result<Self, String> {
        let controller_id = o3k_store::ControllerId::new(controller.controller_id.clone());
        let controller_epoch = o3k_store::ControllerEpoch::new(controller.controller_epoch.clone());
        let work_key = format!("fabric-realm:{realm_id}");
        let lease = match coordination
            .acquire_work_lease(
                &work_key,
                "fabric_reconciliation",
                &controller_id,
                &controller_epoch,
                FABRIC_REALM_LEASE_TTL,
            )
            .await
            .map_err(|error| error.to_string())?
        {
            o3k_store::LeaseAcquireOutcome::Acquired { lease } => lease,
            o3k_store::LeaseAcquireOutcome::Busy { .. } => {
                return Err(format!(
                    "realm {realm_id} reconciliation is owned by another controller"
                ));
            }
        };
        let valid = Arc::new(std::sync::atomic::AtomicBool::new(true));
        let renewal = {
            let coordination = coordination.clone();
            let controller_id = controller_id.clone();
            let controller_epoch = controller_epoch.clone();
            let work_key = work_key.clone();
            let valid = valid.clone();
            let token = lease.fencing_token;
            tokio::spawn(async move {
                let mut interval = tokio::time::interval(FABRIC_REALM_LEASE_RENEWAL);
                interval.tick().await;
                loop {
                    interval.tick().await;
                    match coordination
                        .renew_work_lease(
                            &work_key,
                            &controller_id,
                            &controller_epoch,
                            token,
                            FABRIC_REALM_LEASE_TTL,
                        )
                        .await
                    {
                        Ok(true) => {}
                        Ok(false) | Err(_) => {
                            valid.store(false, std::sync::atomic::Ordering::Release);
                            break;
                        }
                    }
                }
            })
        };
        Ok(Self {
            coordination,
            work_key,
            controller_id,
            controller_epoch,
            fencing_token: lease.fencing_token,
            valid,
            renewal,
        })
    }

    async fn assert_current(&self) -> Result<(), String> {
        if !self.valid.load(std::sync::atomic::Ordering::Acquire) {
            return Err("Fabric realm reconciliation lease was lost".to_owned());
        }
        let renewed = self
            .coordination
            .renew_work_lease(
                &self.work_key,
                &self.controller_id,
                &self.controller_epoch,
                self.fencing_token,
                FABRIC_REALM_LEASE_TTL,
            )
            .await
            .map_err(|error| error.to_string())?;
        if !renewed {
            self.valid
                .store(false, std::sync::atomic::Ordering::Release);
            return Err("Fabric realm reconciliation lease was fenced".to_owned());
        }
        Ok(())
    }

    async fn relinquish(&self) -> Result<(), String> {
        self.valid
            .store(false, std::sync::atomic::Ordering::Release);
        self.renewal.abort();
        let released = self
            .coordination
            .relinquish_work_lease_preserving_fence(
                &self.work_key,
                &self.controller_id,
                &self.controller_epoch,
                self.fencing_token,
            )
            .await
            .map_err(|error| error.to_string())?;
        if !released {
            return Err("Fabric realm reconciliation lease was lost before relinquish".to_owned());
        }
        Ok(())
    }
}

impl Drop for RealmReconciliationLease {
    fn drop(&mut self) {
        self.valid
            .store(false, std::sync::atomic::Ordering::Release);
        self.renewal.abort();
        let coordination = self.coordination.clone();
        let work_key = self.work_key.clone();
        let controller_id = self.controller_id.clone();
        let controller_epoch = self.controller_epoch.clone();
        let fencing_token = self.fencing_token;
        if let Ok(runtime) = tokio::runtime::Handle::try_current() {
            runtime.spawn(async move {
                let _ = coordination
                    .relinquish_work_lease_preserving_fence(
                        &work_key,
                        &controller_id,
                        &controller_epoch,
                        fencing_token,
                    )
                    .await;
            });
        }
    }
}

fn fabric_identity(
    identity: &o3k_store::FabricHostTransportIdentityRecord,
) -> o3k_domain::FabricHostIdentity {
    o3k_domain::FabricHostIdentity {
        host_id: identity.host_id.clone(),
        public_key: identity.public_key.clone(),
        underlay_endpoint: identity.underlay_endpoint.clone(),
        fabric_transport_ip: identity.fabric_transport_ip,
        provider_version: identity.provider_version.clone(),
        fabric_generation: identity.fabric_generation,
        underlay_mtu: identity.underlay_mtu,
        fabric_mtu: identity.fabric_mtu,
    }
}

impl FabricRealmReconciler {
    async fn current_compute_for_host(
        &self,
        host_id: &str,
    ) -> Result<o3k_provider::AgentNodeSnapshot, String> {
        if !o3k_provider::is_valid_host_id(host_id) {
            return Err("stable host ID is malformed".to_owned());
        }
        let matches = self.registry.snapshots_for_host(host_id).await;
        let [snapshot] = matches.as_slice() else {
            return Err(if matches.is_empty() {
                format!("stable host {host_id} has no current compute agent")
            } else {
                format!("multiple current compute agents claim stable host {host_id}")
            });
        };
        if snapshot.host_id != host_id
            || snapshot.availability != o3k_provider::AgentAvailability::Available
            || snapshot.administrative_state == o3k_provider::AgentAdministrativeState::Disabled
        {
            return Err(format!(
                "compute representation for host {host_id} is stale or unavailable"
            ));
        }
        Ok(snapshot.clone())
    }

    fn local_realm_lock(&self, realm_id: Uuid) -> Arc<tokio::sync::Mutex<()>> {
        let mut locks = self
            .reconciliation_locks
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        locks.retain(|_, lock| lock.strong_count() > 0);
        if let Some(lock) = locks.get(&realm_id).and_then(std::sync::Weak::upgrade) {
            return lock;
        }
        let lock = Arc::new(tokio::sync::Mutex::new(()));
        locks.insert(realm_id, Arc::downgrade(&lock));
        lock
    }

    /// Confirms that the compute placement identity has a unique, current
    /// stable-host mapping. The returned host ID is the only identity written
    /// into Fabric binding state; compute ID/epoch remain in the VM command.
    pub(crate) async fn validate_compute_placement(
        &self,
        selected: &o3k_provider::AgentNodeSnapshot,
    ) -> Result<String, String> {
        if !o3k_provider::is_valid_host_id(&selected.host_id) {
            return Err("selected compute agent has no valid stable host identity".to_owned());
        }
        let current = self.current_compute_for_host(&selected.host_id).await?;
        if current.agent_id != selected.agent_id
            || current.agent_epoch != selected.agent_epoch
            || current.host_id != selected.host_id
            || current.administrative_state != o3k_provider::AgentAdministrativeState::Enabled
        {
            return Err(format!(
                "selected compute host identity or epoch is stale/ineligible (selected agent={} host={} epoch={}; current agent={} host={} epoch={} state={:?})",
                selected.agent_id,
                selected.host_id,
                selected.agent_epoch,
                current.agent_id,
                current.host_id,
                current.agent_epoch,
                current.administrative_state
            ));
        }
        let identities = self
            .network
            .list_fabric_host_transport_identities()
            .await
            .map_err(|error| error.to_string())?;
        let matches = identities
            .iter()
            .filter(|identity| identity.host_id == selected.host_id)
            .collect::<Vec<_>>();
        let [identity] = matches.as_slice() else {
            return Err(
                "selected stable host has missing or ambiguous Fabric enrollment".to_owned(),
            );
        };
        if identity.administrative_state != "enabled" {
            return Err("selected stable host is not enabled for Fabric".to_owned());
        }
        if self
            .dispatcher
            .target_for_host(&selected.host_id)
            .await
            .map_err(|error| error.to_string())?
            .is_none()
        {
            return Err("selected stable host has no network-agent control target".to_owned());
        }
        Ok(selected.host_id.clone())
    }

    /// Recovers durable command history independently of active endpoint
    /// discovery. This is required for remove commands belonging to a realm
    /// whose final endpoint has already been deleted canonically.
    async fn observe_realm_history(&self, realm_id: Uuid) -> Result<(), String> {
        let local_lock = self.local_realm_lock(realm_id);
        let _local_guard = local_lock.lock().await;
        let lease = RealmReconciliationLease::acquire(
            self.coordination.clone(),
            &self.controller,
            realm_id,
        )
        .await?;
        let result = self
            .observe_realm_history_under_lease(realm_id, &lease)
            .await;
        let release = lease.relinquish().await;
        match (result, release) {
            (Err(error), _) => Err(error),
            (Ok(()), Err(error)) => Err(error),
            (Ok(()), Ok(())) => Ok(()),
        }
    }

    async fn observe_realm_history_under_lease(
        &self,
        realm_id: Uuid,
        lease: &RealmReconciliationLease,
    ) -> Result<(), String> {
        let not_found = self.observe_unresolved_realm_work(realm_id, lease).await?;
        for record in not_found {
            let historical: o3k_network::NetworkPlanCommand =
                serde_json::from_slice(&record.snapshot).map_err(|_| {
                    format!(
                        "historical command {} has a corrupt snapshot",
                        record.command_id
                    )
                })?;
            if historical.action != o3k_network::NetworkPlanAction::Remove {
                return Err(format!(
                    "historical apply {} awaits current canonical realm derivation",
                    record.command_id
                ));
            }
            let realms = self
                .network
                .list_active_realms_for_reconciliation()
                .await
                .map_err(|error| error.to_string())?;
            let still_populated = if let Some(realm) = realms.iter().find(|r| r.id == realm_id) {
                self.network
                    .list_canonical_endpoints_for_project(&realm.project_id, realm_id)
                    .await
                    .map_err(|error| error.to_string())?
                    .iter()
                    .any(|endpoint| endpoint.state == "active")
            } else {
                false
            };
            if still_populated {
                return Err(format!(
                    "historical remove {} conflicts with current populated realm state",
                    record.command_id
                ));
            }
            let target = self
                .dispatcher
                .target_for_host(&record.target_host_id)
                .await
                .map_err(|error| error.to_string())?
                .ok_or_else(|| {
                    format!(
                        "network-agent target for host {} is unavailable",
                        record.target_host_id
                    )
                })?;
            if target.agent_id != record.target_agent_id {
                return Err(format!(
                    "historical command {} belongs to a different network-agent identity",
                    record.command_id
                ));
            }
            let deadline = super::unix_time_millis().saturating_add(30_000);
            let status = if recovery_successor_parent(&record).is_some() {
                let mut successor = historical;
                successor.target.agent_epoch = target.agent_epoch;
                successor.deadline_unix_ms = deadline;
                successor.plan.deadline_unix_ms = deadline;
                self.dispatcher
                    .dispatch_existing_successor(successor, record.command_id.clone())
                    .await
            } else {
                let mut successor = historical;
                successor.target = target;
                successor.controller = self.controller.clone();
                successor.operation_id = Uuid::new_v5(
                    &successor.operation_id,
                    format!("recovery-remove:{}", successor.plan.fingerprint_sha256).as_bytes(),
                );
                successor.command_id = Uuid::new_v5(
                    &Uuid::parse_str(&record.command_id)
                        .map_err(|_| "bad historical command ID")?,
                    b"superseding-removal",
                );
                successor.idempotency_key = format!("{}:recovery", successor.idempotency_key);
                successor.deadline_unix_ms = deadline;
                successor.plan.operation_id = successor.operation_id;
                successor.plan.deadline_unix_ms = deadline;
                if let Some(fabric) = successor.plan.fabric.take() {
                    successor.plan = successor
                        .plan
                        .with_fabric(fabric)
                        .map_err(|error| error.to_string())?;
                }
                self.dispatcher
                    .dispatch_superseding(successor, record.command_id.clone(), record.revision)
                    .await
            }
            .map_err(|error| error.to_string())?;
            lease.assert_current().await?;
            if status != o3k_network::NetworkPlanStatus::Succeeded {
                return Err(format!(
                    "successor cleanup for historical command {} is not observed successful",
                    record.command_id
                ));
            }
        }
        Ok(())
    }

    /// Completes the supported subnet deletion workflow. Durable plan
    /// snapshots identify every host that may still own this Realm; provider
    /// observations prove absence before the canonical VNI binding is
    /// released. Runtime observations never expand the cleanup target set.
    pub(crate) async fn delete_subnet_for_project(
        &self,
        project_id: &str,
        realm_id: Uuid,
    ) -> Result<(), String> {
        let local_lock = self.local_realm_lock(realm_id);
        let _local_guard = local_lock.lock().await;
        let lease = RealmReconciliationLease::acquire(
            self.coordination.clone(),
            &self.controller,
            realm_id,
        )
        .await?;
        let result = async {
            // Atomically reject remaining canonical dependents and fence the
            // Realm before inspecting/removing provider state. If historical
            // endpoint cleanup is still running or ambiguous, the durable
            // deleting state blocks new attachments and startup recovery can
            // resume this same operation.
            self.network
                .begin_canonical_realm_deletion_for_project(project_id, realm_id)
                .await
                .map_err(|error| format!("cannot begin AddressRealm deletion: {error}"))?;
            lease.assert_current().await?;
            self.observe_realm_history_under_lease(realm_id, &lease)
                .await?;

            let realm = self
                .network
                .get_canonical_realm_for_project(project_id, realm_id)
                .await
                .map_err(|error| format!("cannot read deleting AddressRealm: {error}"))?;
            if realm.state != "deleting" {
                return Err("AddressRealm did not enter deleting state".to_owned());
            }
            let bindings = self
                .network
                .list_realm_bindings_for_reconciliation(realm_id)
                .await
                .map_err(|error| error.to_string())?;
            let history = self
                .durable
                .list_network_plan_work_history()
                .await
                .map_err(|error| format!("cannot load durable Fabric cleanup history: {error}"))?;
            let by_host = latest_realm_host_work(history, realm_id)?;

            // A bound v3 Realm must have durable host plan history. With no
            // binding there is no current VNI to release, but any retained
            // host snapshots are still observed before finalization.
            if !bindings.is_empty() && by_host.is_empty() {
                return Err("bound AddressRealm has no durable provider cleanup targets".to_owned());
            }
            for binding in &bindings {
                if binding.state != "active" && binding.state != "deleting" {
                    return Err("AddressRealm encapsulation binding is not current".to_owned());
                }
            }

            let enrolled = self
                .network
                .list_fabric_host_transport_identities()
                .await
                .map_err(|error| error.to_string())?;
            for (host_id, latest) in by_host {
                if !realm_host_may_still_own(&latest) {
                    continue;
                }
                lease.assert_current().await?;
                // Prefer an already-issued removal command; otherwise use a
                // durable Apply snapshot as the exact ownership identity from
                // which to derive a new idempotent Remove command.
                // Realm generation establishes host-plan order: an older
                // successful Remove may have been followed by a later Apply.
                let selected = latest.record;
                let mut historical = latest.command;
                let fabric = historical
                    .plan
                    .fabric
                    .as_ref()
                    .ok_or_else(|| "durable cleanup plan lacks Fabric identity".to_owned())?;
                if fabric.realm_id != realm_id || fabric.local_host != host_id {
                    return Err("durable cleanup plan does not match its host target".to_owned());
                }
                if !bindings.is_empty()
                    && !bindings.iter().any(|binding| {
                        fabric.encapsulation.fabric_domain_id.to_string()
                            == binding.fabric_domain_id
                            && fabric.encapsulation.realm_id == binding.realm_id
                            && fabric.encapsulation.provider_segment_id
                                == u32::try_from(binding.provider_segment_id).unwrap_or_default()
                            && fabric.encapsulation.binding_generation == binding.binding_generation
                    })
                {
                    return Err("durable plan does not match the current VNI binding".to_owned());
                }
                let identity = enrolled
                    .iter()
                    .find(|identity| identity.host_id == host_id)
                    .ok_or_else(|| {
                        format!("cleanup target {host_id} has no current Fabric identity")
                    })?;
                if identity.administrative_state != "enabled"
                    || identity.fabric_generation != fabric.local_fabric_generation
                {
                    return Err(format!(
                        "cleanup target {host_id} has stale or disabled Fabric identity"
                    ));
                }
                let target = self
                    .dispatcher
                    .target_for_host(&host_id)
                    .await
                    .map_err(|error| error.to_string())?
                    .ok_or_else(|| format!("cleanup host {host_id} has no network-agent target"))?;
                if target.agent_id != selected.target_agent_id {
                    return Err(format!(
                        "cleanup history for {host_id} belongs to a different network agent"
                    ));
                }

                let realm_delete_key = format!(
                    "fabric-realm-delete:{realm_id}:{host_id}:{}",
                    realm.generation
                );
                // The dispatcher scopes execution identity to the enrolled
                // agent epoch. Compare the durable command identity, rather
                // than its pre-dispatch semantic key, so a completed Realm
                // REMOVE is observed and reused after retry/restart.
                let execution_realm_delete_key = format!(
                    "{realm_delete_key}:agent-epoch:{}",
                    selected.target_agent_epoch
                );
                let is_current_realm_remove = historical.action
                    == o3k_network::NetworkPlanAction::Remove
                    && historical.idempotency_key == execution_realm_delete_key;
                if historical.action == o3k_network::NetworkPlanAction::Remove {
                    let command_id = Uuid::parse_str(&selected.command_id)
                        .map_err(|_| "durable cleanup command ID is malformed")?;
                    let history_status = self
                        .dispatcher
                        .observe_command(&host_id, target.clone(), command_id)
                        .await
                        .map_err(|error| format!("provider removal observation failed: {error}"))?;
                    match history_status {
                        Some(o3k_network::NetworkPlanStatus::Succeeded)
                            if is_current_realm_remove =>
                        {
                            continue;
                        }
                        Some(o3k_network::NetworkPlanStatus::Succeeded) => {
                            // This may be an endpoint-level REMOVE from the
                            // final port deletion. Its successful observation
                            // does not prove the host's realm bridge/VXLAN and
                            // shared provider state are absent; issue the
                            // generation-specific Realm removal below.
                        }
                        Some(o3k_network::NetworkPlanStatus::Applying)
                        | Some(o3k_network::NetworkPlanStatus::Unknown) => {
                            return Err(format!(
                                "provider removal on {host_id} is not proven absent"
                            ));
                        }
                        None => {
                            // not_found proves only that this historical
                            // command was not admitted. A fresh Remove below
                            // is safe and uses the same accepted plan identity.
                        }
                        Some(o3k_network::NetworkPlanStatus::Accepted) => {
                            return Err(format!("provider removal on {host_id} is still running"));
                        }
                    }
                }

                let deadline = super::unix_time_millis().saturating_add(30_000);
                let operation_id = Uuid::new_v5(
                    &realm_id,
                    format!("realm-delete:{}:{}", realm.generation, host_id).as_bytes(),
                );
                historical.action = o3k_network::NetworkPlanAction::Remove;
                historical.target = target;
                historical.controller = self.controller.clone();
                historical.operation_id = operation_id;
                historical.command_id = Uuid::new_v5(
                    &operation_id,
                    format!("remove:{}:{}", host_id, historical.plan.fingerprint_sha256).as_bytes(),
                );
                historical.idempotency_key = realm_delete_key;
                historical.deadline_unix_ms = deadline;
                historical.plan.operation_id = operation_id;
                historical.plan.plan_id = operation_id;
                historical.plan.deadline_unix_ms = deadline;
                if let Some(fabric) = historical.plan.fabric.take() {
                    historical.plan = historical
                        .plan
                        .with_fabric(fabric)
                        .map_err(|error| error.to_string())?;
                }
                lease.assert_current().await?;
                let status = self
                    .dispatcher
                    .dispatch(historical.clone())
                    .await
                    .map_err(|error| format!("provider Remove dispatch failed: {error}"))?;
                if status != o3k_network::NetworkPlanStatus::Succeeded {
                    return Err(format!("provider Remove on {host_id} is not successful"));
                }
                lease.assert_current().await?;
                let execution_command_id = execution_command_id_for_agent_epoch(
                    historical.command_id,
                    &historical.target.agent_epoch,
                );
                let final_observation = self
                    .dispatcher
                    .observe_command(&host_id, historical.target, execution_command_id)
                    .await
                    .map_err(|error| format!("provider absence observation failed: {error}"))?;
                match final_observation {
                    Some(o3k_network::NetworkPlanStatus::Succeeded) => {}
                    _ => return Err(format!("provider absence on {host_id} is not proven")),
                }
            }

            let observations = bindings
                .into_iter()
                .map(o3k_network::RealmCleanupObservation::Absent)
                .collect();
            match self
                .network
                .observe_canonical_realm_cleanup_for_project(project_id, realm_id, observations)
                .await
                .map_err(|error| format!("cannot finalize AddressRealm cleanup: {error}"))?
            {
                o3k_network::RealmCleanupProgress::Removed { .. } => {}
                o3k_network::RealmCleanupProgress::Deleting { .. }
                | o3k_network::RealmCleanupProgress::AwaitingObservation { .. } => {
                    return Err(
                        "provider absence was not accepted for AddressRealm cleanup".to_owned()
                    );
                }
            }
            self.network
                .delete_subnet_for_project(project_id, realm_id)
                .await
                .map_err(|error| format!("cannot remove compatibility subnet metadata: {error}"))?;
            lease.assert_current().await?;
            Ok(())
        }
        .await;
        let release = lease.relinquish().await;
        match (result, release) {
            (Err(error), _) => Err(error),
            (Ok(()), Err(error)) => Err(error),
            (Ok(()), Ok(())) => Ok(()),
        }
    }

    pub(crate) async fn reconcile_realm(
        &self,
        project_id: &str,
        network_id: Uuid,
        operation_id: Uuid,
        deadline_unix_ms: u64,
    ) -> Result<(), String> {
        self.reconcile_realm_internal(project_id, network_id, operation_id, deadline_unix_ms, None)
            .await
    }

    pub(crate) async fn reconcile_realm_after_unbind(
        &self,
        project_id: &str,
        network_id: Uuid,
        operation_id: Uuid,
        deadline_unix_ms: u64,
        departing_host_id: &str,
    ) -> Result<(), String> {
        self.reconcile_realm_internal(
            project_id,
            network_id,
            operation_id,
            deadline_unix_ms,
            Some(departing_host_id),
        )
        .await
    }

    /// Reconstructs the complete desired realm directory from canonical
    /// endpoints plus accepted port bindings, then sends one host-local v3
    /// plan to each current participating agent.
    async fn reconcile_realm_internal(
        &self,
        project_id: &str,
        network_id: Uuid,
        _operation_id: Uuid,
        deadline_unix_ms: u64,
        _departing_host_id: Option<&str>,
    ) -> Result<(), String> {
        let realms = self
            .network
            .list_canonical_realms_for_project(project_id, network_id)
            .await
            .map_err(|error| error.to_string())?
            .into_iter()
            .filter(|realm| realm.state == "active")
            .collect::<Vec<_>>();
        let [realm_record] = realms.as_slice() else {
            return Err(
                "Fabric v3 requires exactly one active AddressRealm per network".to_owned(),
            );
        };
        let local_lock = self.local_realm_lock(realm_record.id);
        let _local_guard = local_lock.lock().await;
        let _realm_lease = RealmReconciliationLease::acquire(
            self.coordination.clone(),
            &self.controller,
            realm_record.id,
        )
        .await?;
        let result = async {
            let not_found = self
                .observe_unresolved_realm_work(realm_record.id, &_realm_lease)
                .await?;
            let (prefix_address, prefix_len) = realm_record
                .prefix
                .split_once('/')
                .ok_or_else(|| "canonical AddressRealm prefix is malformed".to_owned())?;
            let prefix = o3k_domain::Ipv4Prefix::new(
                prefix_address
                    .parse()
                    .map_err(|_| "canonical AddressRealm IPv4 prefix is malformed")?,
                prefix_len
                    .parse()
                    .map_err(|_| "canonical AddressRealm prefix length is malformed")?,
            )
            .ok_or_else(|| "canonical AddressRealm prefix is invalid".to_owned())?;
            let realm = o3k_domain::AddressRealm {
                id: realm_record.id,
                network_id,
                project_id: project_id.to_owned(),
                prefix,
                overlapping_prefixes: realm_record.overlapping_prefixes,
            };
            let endpoints = self
                .network
                .list_canonical_endpoints_for_project(project_id, realm.id)
                .await
                .map_err(|error| error.to_string())?;
            let identities = self
                .network
                .list_fabric_host_transport_identities()
                .await
                .map_err(|error| error.to_string())?;
            let mut transport_by_host = BTreeMap::new();
            for identity in identities {
                if !o3k_provider::is_valid_host_id(&identity.host_id)
                    || transport_by_host
                        .insert(identity.host_id.clone(), identity)
                        .is_some()
                {
                    return Err(
                        "Fabric host identities have an invalid or duplicate host ID".to_owned(),
                    );
                }
            }
            let mut locations = Vec::new();
            let mut participants_by_host = BTreeMap::new();
            let mut selected_ports = BTreeMap::new();
            for endpoint in endpoints
                .into_iter()
                .filter(|endpoint| endpoint.state == "active")
            {
                let port = self
                    .network
                    .get_port_for_project(project_id, endpoint.id)
                    .await
                    .map_err(|error| error.to_string())?;
                let Some(host_id) = port.binding_host.as_deref() else {
                    continue;
                };
                if port.binding_state.as_deref() == Some("down") {
                    continue;
                }
                if port.binding_generation == 0 {
                    return Err("selected Fabric endpoint lacks placement generation".to_owned());
                }
                let _compute = self.current_compute_for_host(host_id).await?;
                let identity = transport_by_host
                    .get(host_id)
                    .ok_or_else(|| "selected endpoint host lacks Fabric enrollment".to_owned())?;
                if identity.administrative_state != "enabled" {
                    return Err(
                        "selected endpoint host is disabled or draining for Fabric".to_owned()
                    );
                }
                let fabric_identity = fabric_identity(identity);
                match participants_by_host.get(&fabric_identity.host_id) {
                    Some(existing) if existing != &fabric_identity => {
                        return Err("conflicting Fabric identities resolve to one host".to_owned());
                    }
                    Some(_) => {}
                    None => {
                        participants_by_host
                            .insert(fabric_identity.host_id.clone(), fabric_identity);
                    }
                }
                locations.push(o3k_domain::EndpointLocation {
                    endpoint_id: endpoint.id,
                    project_id: endpoint.project_id,
                    realm_id: endpoint.realm_id,
                    fixed_ip: endpoint.fixed_ip,
                    mac: endpoint.mac,
                    selected_host: host_id.to_owned(),
                    endpoint_generation: endpoint.generation,
                    placement_generation: port.binding_generation,
                });
                selected_ports.insert(endpoint.id, port);
            }
            let mut participants = participants_by_host.values().cloned().collect::<Vec<_>>();
            participants.sort_by(|left, right| left.host_id.cmp(&right.host_id));
            let selected_subnets = selected_ports
                .values()
                .map(|port| {
                    port.subnet_id
                        .ok_or_else(|| "Fabric endpoint has no subnet".to_owned())
                })
                .collect::<Result<BTreeSet<_>, _>>()?;
            if selected_subnets.len() > 1 {
                return Err("Fabric AddressRealm endpoints do not resolve to one subnet".to_owned());
            }
            let realm_subnet = if let Some(subnet_id) = selected_subnets.iter().next() {
                let subnet = self
                    .network
                    .get_subnet_for_project(project_id, *subnet_id)
                    .await
                    .map_err(|error| error.to_string())?;
                if subnet.network_id != network_id
                    || subnet.gateway_ip == prefix.network
                    || !prefix.contains(subnet.gateway_ip)
                {
                    return Err(
                        "Fabric subnet configuration conflicts with its AddressRealm".to_owned(),
                    );
                }
                Some(subnet)
            } else {
                None
            };
            let binding = self
                .network
                .ensure_vxlan_realm_binding(self.fabric_domain_id, realm_record)
                .await
                .map_err(|error| error.to_string())?;
            let mut all_policies = self
                .network
                .list_policies_for_project(project_id, network_id)
                .await
                .map_err(|error| error.to_string())?;
            all_policies.sort_by_key(|policy| policy.id);
            locations.sort_by_key(|endpoint| endpoint.endpoint_id);
            let mut policy_defaults = BTreeMap::new();
            for endpoint in &locations {
                policy_defaults.insert(
                    endpoint.endpoint_id,
                    self.network
                        .policy_defaults_for_endpoint(project_id, endpoint.endpoint_id)
                        .await
                        .map_err(|error| error.to_string())?,
                );
            }
            let mut semantic_identity = format!(
                "realm:{}:{}:binding:{:?}:{}:{}:dhcp:{:?}:action:{}",
                realm.id,
                realm_record.generation,
                binding.provider_kind,
                binding.provider_segment_id,
                binding.binding_generation,
                realm_subnet.as_ref().map(|subnet| (
                    subnet.enable_dhcp,
                    subnet.gateway_ip,
                    subnet.cidr.as_str(),
                )),
                if participants.is_empty() {
                    "remove"
                } else {
                    "apply"
                }
            );
            for endpoint in &locations {
                semantic_identity.push_str(&format!(
                    "|endpoint:{}:{}:{}:{}:{}:{}:{}",
                    endpoint.endpoint_id,
                    endpoint.project_id,
                    endpoint.fixed_ip,
                    endpoint.mac,
                    endpoint.selected_host,
                    endpoint.endpoint_generation,
                    endpoint.placement_generation
                ));
            }
            for participant in &participants {
                semantic_identity.push_str(&format!(
                    "|host:{}:{}:{}:{}:{}:{}",
                    participant.host_id,
                    participant.fabric_generation,
                    participant.fabric_transport_ip,
                    participant.public_key,
                    participant.underlay_endpoint,
                    participant.fabric_mtu
                ));
            }
            for policy in &all_policies {
                semantic_identity.push_str(&format!(
                    "|policy:{}:{}:{:?}:{:?}:{:?}:{:?}:{:?}",
                    policy.id,
                    policy.endpoint_id,
                    policy.direction,
                    policy.protocol,
                    policy.ports,
                    policy.source,
                    policy.destination
                ));
            }
            for (endpoint_id, defaults) in &policy_defaults {
                semantic_identity.push_str(&format!("|policy-default:{endpoint_id}:{defaults:?}"));
            }
            let operation_id = Uuid::new_v5(&realm.id, semantic_identity.as_bytes());
            let history = self
                .durable
                .list_network_plan_work_history()
                .await
                .map_err(|error| format!("cannot load durable Realm host history: {error}"))?;
            let latest_by_host = latest_realm_host_work(history, realm.id)?;
            let retiring_hosts = latest_by_host
                .iter()
                .filter(|(host_id, work)| {
                    !participants_by_host.contains_key(*host_id) && realm_host_may_still_own(work)
                })
                .map(|(host_id, work)| (host_id.clone(), work))
                .collect::<Vec<_>>();
            let directory = o3k_domain::RealmEndpointDirectory::build(
                &realm,
                locations.clone(),
                &[],
                realm_record.generation,
            )
            .map_err(|error| error.to_string())?;
            let realm_generations = BTreeMap::from([(realm.id, realm_record.generation)]);

            // Durable history, rather than an unbind callback argument, owns
            // retiring-host discovery. Dispatch all retirements first so a
            // leaving DHCP authority is observed absent before survivors can
            // select a replacement.
            for (host_id, latest) in retiring_hosts {
                _realm_lease.assert_current().await?;
                let historical_fabric = latest
                    .command
                    .plan
                    .fabric
                    .as_ref()
                    .ok_or_else(|| "historical host plan lacks Fabric identity".to_owned())?;
                let identity_record = transport_by_host.get(&host_id).ok_or_else(|| {
                    format!("retiring host {host_id} has no current Fabric enrollment")
                })?;
                if identity_record.fabric_generation != historical_fabric.local_fabric_generation {
                    return Err(format!(
                        "retiring host {host_id} has a stale Fabric generation"
                    ));
                }
                if historical_fabric.encapsulation.fabric_domain_id != self.fabric_domain_id
                    || historical_fabric.encapsulation.realm_id != realm.id
                    || historical_fabric.encapsulation.provider_segment_id
                        != binding.provider_segment_id
                    || historical_fabric.encapsulation.binding_generation
                        != binding.binding_generation
                {
                    return Err(format!(
                        "retiring host {host_id} history conflicts with the current Realm VNI binding"
                    ));
                }
                let identity = fabric_identity(identity_record);
                let tenant_mtu = identity.fabric_mtu.checked_sub(50).ok_or_else(|| {
                    "retiring Fabric host MTU is below the tenant minimum".to_owned()
                })?;
                let mut remove_participants = participants.clone();
                remove_participants.push(identity.clone());
                remove_participants.sort_by(|left, right| left.host_id.cmp(&right.host_id));
                let fabric = directory
                    .compile_fabric_plan(
                        &identity,
                        &remove_participants,
                        tenant_mtu,
                        &binding,
                    )
                    .map_err(|error| error.to_string())?;
                let plan = o3k_network::NodeNetworkPlan {
                    schema_version: o3k_network::NODE_NETWORK_PLAN_SCHEMA_VERSION,
                    plan_id: Uuid::new_v5(
                        &operation_id,
                        format!("fabric-realm-remove:{}:{}", realm.id, identity.host_id).as_bytes(),
                    ),
                    node_id: identity.host_id.clone(),
                    operation_id,
                    deadline_unix_ms,
                    resource_generations: realm_generations.clone(),
                    intents: Vec::new(),
                    fabric: None,
                    gateway: None,
                    fingerprint_sha256: String::new(),
                }
                .with_fabric(fabric)
                .map_err(|error| error.to_string())?;
                let target = self
                    .dispatcher
                    .target_for_host(&host_id)
                    .await
                    .map_err(|error| error.to_string())?
                    .ok_or_else(|| format!("retiring host {host_id} has no network-agent target"))?;
                if target.agent_id != latest.record.target_agent_id {
                    return Err(format!("retiring host {host_id} network-agent identity changed"));
                }
                self.dispatch_realm_plan(
                    (&target, &host_id),
                    plan,
                    o3k_network::NetworkPlanAction::Remove,
                    RealmPlanAttempt {
                        operation_id,
                        deadline_unix_ms,
                        lease: &_realm_lease,
                        historical: not_found.iter().find(|record| {
                            record.target_host_id == host_id
                                && record.target_agent_id == target.agent_id
                        }),
                    },
                )
                .await?;
            }
            if participants.is_empty() {
                if latest_by_host.is_empty() {
                    return Err("Fabric realm has no participants or durable provider history".to_owned());
                }
                return Ok(());
            }
            let realm_subnet = realm_subnet
                .ok_or_else(|| "active Fabric endpoints have no subnet DHCP settings".to_owned())?;
            let plan_set = o3k_network::compile_fabric_realm_plans(
                &realm,
                locations,
                &participants,
                &binding,
                realm_record.generation,
                operation_id,
                deadline_unix_ms,
            )
            .map_err(|error| error.to_string())?;
            let external_realm = if let Some(external_network_id) = self.network_external_realm_id {
                let external_realms = self
                    .network
                    .list_canonical_realms_for_project(project_id, external_network_id)
                    .await
                    .map_err(|error| error.to_string())?
                    .into_iter()
                    .filter(|realm| realm.state == "active")
                    .collect::<Vec<_>>();
                match external_realms.as_slice() {
                    [realm] => Some(realm.id),
                    _ => {
                        return Err(
                            "configured external AddressRealm is missing or ambiguous".to_owned()
                        );
                    }
                }
            } else {
                None
            };
            for (host_id, mut plan) in plan_set.plans {
                let local_endpoints = plan_set
                    .directory
                    .entries
                    .iter()
                    .filter(|entry| entry.selected_host == host_id)
                    .collect::<Vec<_>>();
                for endpoint in local_endpoints {
                    let port = selected_ports.get(&endpoint.endpoint_id).ok_or_else(|| {
                        "local Fabric endpoint lost its placement record".to_owned()
                    })?;
                    let subnet_id = port
                        .subnet_id
                        .ok_or_else(|| "Fabric endpoint has no subnet".to_owned())?;
                    let subnet = self
                        .network
                        .get_subnet_for_project(project_id, subnet_id)
                        .await
                        .map_err(|error| error.to_string())?;
                    let policies = all_policies
                        .iter()
                        .filter(|policy| policy.endpoint_id == endpoint.endpoint_id)
                        .cloned()
                        .collect();
                    let defaults = policy_defaults
                        .get(&endpoint.endpoint_id)
                        .cloned()
                        .ok_or_else(|| {
                            "local Fabric endpoint policy defaults disappeared".to_owned()
                        })?;
                    let public_address = self
                        .public_allocator
                        .as_ref()
                        .map(|allocator| {
                            allocator
                                .list(project_id)
                                .map_err(|error| error.to_string())
                        })
                        .transpose()?
                        .and_then(|bindings| {
                            bindings
                                .into_iter()
                                .find(|allocation| {
                                    allocation.endpoint_id == Some(endpoint.endpoint_id)
                                })
                                .map(|allocation| allocation.public_address)
                        });
                    let attachment = o3k_network::compile_attachment_plan_with_defaults(
                        o3k_network::AttachmentPlanInput {
                            endpoint_id: endpoint.endpoint_id,
                            realm_id: realm.id,
                            project_id,
                            mac: &endpoint.mac,
                            fixed_ip: endpoint.fixed_ip,
                            subnet_cidr: &subnet.cidr,
                            node_id: &host_id,
                            operation_id,
                            deadline_unix_ms,
                            public_address,
                            external_realm_id: external_realm,
                            policies,
                        },
                        defaults,
                    )
                    .map_err(|error| error.to_string())?;
                    plan.intents.extend(attachment.intents);
                }
                let fabric = plan
                    .fabric
                    .take()
                    .ok_or_else(|| "compiled realm plan has no Fabric payload".to_owned())?;
                let fabric = o3k_domain::NamespacedRoutedFabricPlan {
                    dhcp: Some(o3k_domain::FabricDhcpIntent {
                        enabled: realm_subnet.enable_dhcp,
                        gateway: realm_subnet.gateway_ip,
                    }),
                    ..fabric
                };
                plan = plan
                    .with_fabric(fabric)
                    .map_err(|error| error.to_string())?;
                let _compute = self.current_compute_for_host(&host_id).await?;
                _realm_lease.assert_current().await?;
                let target = self
                    .dispatcher
                    .target_for_host(&host_id)
                    .await
                    .map_err(|error| error.to_string())?
                    .ok_or_else(|| format!("host {host_id} has no network-agent control target"))?;
                let historical = not_found.iter().find(|record| {
                    record.target_host_id == host_id && record.target_agent_id == target.agent_id
                });
                self.dispatch_realm_plan(
                    (&target, &host_id),
                    plan,
                    o3k_network::NetworkPlanAction::Apply,
                    RealmPlanAttempt {
                        operation_id,
                        deadline_unix_ms,
                        lease: &_realm_lease,
                        historical,
                    },
                )
                .await?;
                _realm_lease.assert_current().await?;
            }
            Ok(())
        }
        .await;
        let release = _realm_lease.relinquish().await;
        match (result, release) {
            (Err(error), _) => Err(error),
            (Ok(()), Err(error)) => Err(error),
            (Ok(()), Ok(())) => Ok(()),
        }
    }

    async fn observe_unresolved_realm_work(
        &self,
        realm_id: Uuid,
        realm_lease: &RealmReconciliationLease,
    ) -> Result<Vec<o3k_store::NetworkPlanWorkRecord>, String> {
        let mut not_found = Vec::new();
        for record in self
            .durable
            .list_unresolved_network_plan_work()
            .await
            .map_err(|error| error.to_string())?
        {
            let command: o3k_network::NetworkPlanCommand = serde_json::from_slice(&record.snapshot)
                .map_err(|_| {
                    format!(
                        "unresolved network command {} has a corrupt snapshot",
                        record.command_id
                    )
                })?;
            if !command
                .plan
                .fabric
                .as_ref()
                .is_some_and(|fabric| fabric.realm_id == realm_id)
            {
                continue;
            }
            let command_id = Uuid::parse_str(&record.command_id)
                .map_err(|_| "unresolved network command ID is malformed".to_owned())?;
            if command.command_id != command_id
                || command.target.agent_id != record.target_agent_id
                || command.plan.node_id != record.target_host_id
            {
                return Err(format!(
                    "unresolved network command {} target does not match its durable work row",
                    record.command_id
                ));
            }
            let target = self
                .dispatcher
                .target_for_host(&record.target_host_id)
                .await
                .map_err(|error| error.to_string())?
                .ok_or_else(|| format!("target host {} is not enrolled", record.target_host_id))?;
            if target.agent_id != record.target_agent_id {
                return Err(format!(
                    "historical network-agent identity for host {} is no longer current",
                    record.target_host_id
                ));
            }
            realm_lease.assert_current().await?;
            let status = self
                .dispatcher
                .observe_command(&record.target_host_id, target, command_id)
                .await
                .map_err(|error| error.to_string())?;
            realm_lease.assert_current().await?;
            let next = match status {
                Some(o3k_network::NetworkPlanStatus::Succeeded) => {
                    o3k_store::NetworkPlanWorkState::Succeeded
                }
                Some(o3k_network::NetworkPlanStatus::Unknown) => {
                    o3k_store::NetworkPlanWorkState::UnknownOutcome
                }
                Some(o3k_network::NetworkPlanStatus::Applying) => continue,
                None => {
                    not_found.push(record.clone());
                    continue;
                }
                Some(_) => return Err("invalid historical command observation".to_owned()),
            };
            let outcome: &[u8] = match status {
                Some(o3k_network::NetworkPlanStatus::Succeeded) => b"observed_succeeded",
                Some(o3k_network::NetworkPlanStatus::Unknown) => b"observation_unknown",
                Some(o3k_network::NetworkPlanStatus::Applying) => unreachable!(),
                None => unreachable!("not-found work returns before transition"),
                Some(_) => unreachable!(),
            };
            if record.state != next {
                realm_lease.assert_current().await?;
                self.durable
                    .update_network_plan_work_under_lease(
                        &realm_lease.work_key,
                        &realm_lease.controller_id.0,
                        &realm_lease.controller_epoch.0,
                        realm_lease.fencing_token,
                        &record.command_id,
                        record.revision,
                        next,
                        Some(outcome),
                    )
                    .await
                    .map_err(|error| error.to_string())?;
                realm_lease.assert_current().await?;
            }
            if status == Some(o3k_network::NetworkPlanStatus::Unknown) {
                return Err(format!(
                    "historical command {} remains unknown",
                    record.command_id
                ));
            }
        }
        Ok(not_found)
    }

    async fn dispatch_realm_plan(
        &self,
        target: (&o3k_network::NetworkAgentIdentity, &str),
        plan: o3k_network::NodeNetworkPlan,
        action: o3k_network::NetworkPlanAction,
        attempt: RealmPlanAttempt<'_>,
    ) -> Result<(), String> {
        let RealmPlanAttempt {
            operation_id,
            deadline_unix_ms,
            lease: realm_lease,
            historical,
        } = attempt;
        let (agent, host_id) = target;
        if plan.node_id != host_id
            || plan
                .fabric
                .as_ref()
                .is_none_or(|fabric| fabric.local_host != host_id)
        {
            return Err("Fabric plan host does not match its dispatch target".to_owned());
        }
        if agent.agent_id.trim().is_empty() || agent.agent_epoch.trim().is_empty() {
            return Err("Fabric plan target has an invalid network-agent identity".to_owned());
        }
        let realm_id = plan
            .fabric
            .as_ref()
            .map(|fabric| fabric.realm_id)
            .ok_or_else(|| "missing Fabric plan".to_owned())?;
        let generation = plan
            .fabric
            .as_ref()
            .map(|fabric| fabric.directory_generation)
            .unwrap_or_default();
        let action_key = match action {
            o3k_network::NetworkPlanAction::Apply => "apply",
            o3k_network::NetworkPlanAction::Remove => "remove",
        };
        let command_id = Uuid::new_v5(
            &operation_id,
            format!("fabric-realm-command:{action_key}:{realm_id}:{host_id}:{generation}")
                .as_bytes(),
        );
        // Check realm ownership after resolving/locking the target agent and
        // immediately before crossing into the agent's durable admission
        // boundary. Durable work transitions are transactionally fenced by
        // the same realm lease in NetworkAgentDispatcher.
        realm_lease.assert_current().await?;
        let command = o3k_network::NetworkPlanCommand {
            command_id,
            operation_id,
            idempotency_key: format!(
                "fabric-realm:{action_key}:{realm_id}:{host_id}:{generation}:{operation_id}"
            ),
            action,
            target: agent.clone(),
            controller: self.controller.clone(),
            deadline_unix_ms,
            plan,
        };
        let status = if let Some(historical) = historical {
            if recovery_successor_parent(historical).is_some() {
                let mut successor: o3k_network::NetworkPlanCommand =
                    serde_json::from_slice(&historical.snapshot)
                        .map_err(|_| "durable recovery successor snapshot is corrupt")?;
                if successor.action != action
                    || successor.plan.fingerprint_sha256 != command.plan.fingerprint_sha256
                {
                    return Err(
                        "durable recovery successor differs from current canonical plan".to_owned(),
                    );
                }
                successor.target = command.target.clone();
                successor.deadline_unix_ms = deadline_unix_ms;
                successor.plan.deadline_unix_ms = deadline_unix_ms;
                self.dispatcher
                    .dispatch_existing_successor(successor, historical.command_id.clone())
                    .await
            } else {
                self.dispatcher
                    .dispatch_superseding(
                        command,
                        historical.command_id.clone(),
                        historical.revision,
                    )
                    .await
            }
        } else {
            self.dispatcher.dispatch(command).await
        }
        .map_err(|error| error.to_string())?;
        realm_lease.assert_current().await?;
        if status != o3k_network::NetworkPlanStatus::Succeeded {
            return Err("Fabric realm plan outcome is not observed successful".to_owned());
        }
        Ok(())
    }
}

#[async_trait::async_trait]
impl crate::native_adapters::resource::RealmDeletionWorkflow for FabricRealmReconciler {
    async fn delete_subnet(&self, project_id: &str, realm_id: Uuid) -> Result<(), String> {
        self.delete_subnet_for_project(project_id, realm_id).await
    }
}

#[async_trait::async_trait]
impl o3k_api::RealmDeletionWorkflow for FabricRealmReconciler {
    async fn delete_subnet(&self, project_id: &str, realm_id: Uuid) -> Result<(), String> {
        self.delete_subnet_for_project(project_id, realm_id).await
    }
}

/// Replays durable history as observation only, then rediscovers active
/// canonical realms through the same reconciler used by endpoint lifecycle.
/// Registration notifications wake the scan; the bounded interval also
/// retries transiently unavailable agents and observes enrollment generation
/// changes that arrive through durable configuration reload.
pub(crate) fn spawn_fabric_recovery(
    reconciler: Arc<FabricRealmReconciler>,
    durable: Arc<dyn o3k_store::DurableStore>,
    registration_notify: Arc<tokio::sync::Notify>,
) -> tokio::task::JoinHandle<()> {
    tokio::spawn(async move {
        let mut retry = tokio::time::interval(std::time::Duration::from_secs(15));
        retry.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Delay);
        // Consume the interval's immediate first tick; scans below run now,
        // then on either a wake event or the bounded retry cadence.
        retry.tick().await;
        loop {
            recover_fabric_state(&reconciler, durable.as_ref()).await;
            tokio::select! {
                _ = registration_notify.notified() => {},
                _ = retry.tick() => {},
            }
        }
    })
}

async fn recover_fabric_state(
    reconciler: &FabricRealmReconciler,
    durable: &dyn o3k_store::DurableStore,
) {
    let unresolved = match durable.list_unresolved_network_plan_work().await {
        Ok(work) => {
            let mut realm_ids = BTreeSet::new();
            for record in work {
                let command = match serde_json::from_slice::<o3k_network::NetworkPlanCommand>(
                    &record.snapshot,
                ) {
                    Ok(command) => command,
                    Err(_) => {
                        tracing::error!(command_id = %record.command_id, "unresolved network command snapshot is corrupt; preserving fail-closed state");
                        return;
                    }
                };
                if let Some(fabric) = command.plan.fabric.as_ref() {
                    realm_ids.insert(fabric.realm_id);
                }
            }
            realm_ids
        }
        Err(error) => {
            tracing::error!(%error, "cannot list unresolved Fabric work; skipping realm mutation this cycle");
            return;
        }
    };

    // Historical work is authoritative even when the last canonical
    // endpoint has disappeared and active-realm discovery therefore has
    // nothing to return. Observe it first; an ambiguous/not-found command
    // remains fail-closed in observe_unresolved_realm_work.
    for realm_id in unresolved {
        if let Err(error) = reconciler.observe_realm_history(realm_id).await {
            tracing::warn!(realm_id = %realm_id, %error, "historical Fabric work remains unresolved");
        }
    }

    let deleting_realms = match reconciler
        .network
        .list_deleting_realms_for_reconciliation()
        .await
    {
        Ok(realms) => realms,
        Err(error) => {
            tracing::error!(%error, "cannot discover AddressRealms awaiting provider cleanup");
            return;
        }
    };
    for realm in deleting_realms {
        if let Err(error) = reconciler
            .delete_subnet_for_project(&realm.project_id, realm.id)
            .await
        {
            tracing::warn!(realm_id = %realm.id, %error, "AddressRealm deletion remains pending provider observation");
        }
    }

    let realms = match reconciler
        .network
        .list_active_realms_for_reconciliation()
        .await
    {
        Ok(realms) => realms,
        Err(error) => {
            tracing::error!(%error, "cannot discover canonical active AddressRealms");
            return;
        }
    };
    for realm in realms {
        let realm_id = realm.id;
        let endpoints = match reconciler
            .network
            .list_canonical_endpoints_for_project(&realm.project_id, realm.id)
            .await
        {
            Ok(endpoints) => endpoints,
            Err(error) => {
                tracing::warn!(realm_id = %realm_id, %error, "cannot read canonical realm endpoints");
                continue;
            }
        };
        if !endpoints.iter().any(|endpoint| endpoint.state == "active") {
            continue;
        }
        let mut identity = format!("realm:{}:{}", realm.id, realm.generation);
        let mut endpoint_state = Vec::new();
        for endpoint in endpoints
            .iter()
            .filter(|endpoint| endpoint.state == "active")
        {
            let Ok(port) = reconciler
                .network
                .get_port_for_project(&realm.project_id, endpoint.id)
                .await
            else {
                endpoint_state.push(format!(
                    "{}:{}:unavailable",
                    endpoint.id, endpoint.generation
                ));
                continue;
            };
            endpoint_state.push(format!(
                "{}:{}:{}:{}:{}",
                endpoint.id,
                endpoint.generation,
                port.binding_host.as_deref().unwrap_or("unbound"),
                port.binding_generation,
                port.binding_state.as_deref().unwrap_or("unset")
            ));
        }
        endpoint_state.sort();
        identity.push_str(&format!("|{}", endpoint_state.join("|")));
        if let Ok(hosts) = reconciler
            .network
            .list_fabric_host_transport_identities()
            .await
        {
            let mut host_state = hosts
                .into_iter()
                .filter(|host| {
                    endpoint_state
                        .iter()
                        .any(|entry| entry.contains(&host.agent_id))
                })
                .map(|host| format!("{}:{}", host.host_id, host.fabric_generation))
                .collect::<Vec<_>>();
            host_state.sort();
            identity.push_str(&format!("|hosts:{}", host_state.join("|")));
        }
        let operation_id = Uuid::new_v5(&realm.id, identity.as_bytes());
        if let Err(error) = reconciler
            .reconcile_realm(
                &realm.project_id,
                realm.network_id,
                operation_id,
                crate::composition::unix_time_millis().saturating_add(30_000),
            )
            .await
        {
            tracing::warn!(realm_id = %realm_id, %error, "Fabric realm startup reconciliation did not converge");
        }
    }
}

impl NetworkAgentDispatcher {
    async fn dispatch_inner(
        &self,
        mut command: o3k_network::NetworkPlanCommand,
        dispatch_work: FabricWorkDispatch,
    ) -> Result<o3k_network::NetworkPlanStatus, o3k_network::NetworkDispatchError> {
        let transport = self.transport_for(&command)?;
        let dynamic_fabric = command.plan.fabric.is_some();
        let realm_id = command.plan.fabric.as_ref().map(|fabric| fabric.realm_id);
        let _control_guard = if dynamic_fabric {
            Some(self.control_lock.lock().await)
        } else {
            None
        };
        let (controller_lease, work): (
            Option<o3k_network_protocol::proto::ControllerLease>,
            Option<(o3k_store::NetworkPlanWorkRecord, AgentControlLeaseGuard)>,
        ) = if dynamic_fabric {
            let control = self.control.as_ref().ok_or_else(|| {
                o3k_network::NetworkDispatchError::Rejected(
                    "Fabric v3 requires coordination-backed network-agent control ownership"
                        .to_owned(),
                )
            })?;
            let realm_id = realm_id.ok_or_else(|| {
                o3k_network::NetworkDispatchError::Rejected("missing Fabric realm".to_owned())
            })?;
            for unresolved in control
                .durable
                .list_unresolved_network_plan_work()
                .await
                .map_err(|_| o3k_network::NetworkDispatchError::Unavailable)?
            {
                let prior: o3k_network::NetworkPlanCommand =
                    serde_json::from_slice(&unresolved.snapshot)
                        .map_err(|_| o3k_network::NetworkDispatchError::Unavailable)?;
                if prior
                    .plan
                    .fabric
                    .as_ref()
                    .is_some_and(|fabric| fabric.realm_id == realm_id)
                {
                    let allowed_id = match &dispatch_work {
                        FabricWorkDispatch::Supersede { command_id, .. }
                        | FabricWorkDispatch::ExistingSuccessor { command_id } => Some(command_id),
                        FabricWorkDispatch::New => None,
                    };
                    if allowed_id.is_some_and(|id| id == &unresolved.command_id) {
                        continue;
                    }
                    return Err(o3k_network::NetworkDispatchError::Unavailable);
                }
            }
            let work_key = format!("network-agent:{}", command.target.agent_id);
            let acquired = control
                .coordination
                .acquire_work_lease(
                    &work_key,
                    "network_agent_control",
                    &control.controller_id,
                    &control.controller_epoch,
                    NETWORK_AGENT_CONTROL_TTL,
                )
                .await
                .map_err(|_| o3k_network::NetworkDispatchError::Unavailable)?;
            let lease = match acquired {
                o3k_store::LeaseAcquireOutcome::Acquired { lease } => lease,
                o3k_store::LeaseAcquireOutcome::Busy { .. } => {
                    return Err(o3k_network::NetworkDispatchError::Unavailable);
                }
            };
            let agent_control_lease = AgentControlLeaseGuard::start(
                control.coordination.clone(),
                work_key.clone(),
                control.controller_id.clone(),
                control.controller_epoch.clone(),
                lease.fencing_token,
            );
            let still_owner = control
                .coordination
                .inspect_work_lease(&work_key)
                .await
                .map_err(|_| o3k_network::NetworkDispatchError::Unavailable)?
                .is_some_and(|current| {
                    current.owner_controller_id == control.controller_id
                        && current.owner_controller_epoch == control.controller_epoch
                        && current.fencing_token == lease.fencing_token
                });
            if !still_owner {
                return Err(o3k_network::NetworkDispatchError::Unavailable);
            }
            // Keep execution identity stable across controller takeovers.
            // A changed agent epoch gets a fresh immutable attempt because an
            // agent restart/reenrollment creates a new execution boundary;
            // controller epoch and fencing token remain envelope authority.
            let semantic_command_id = command.command_id;
            let semantic_idempotency_key = command.idempotency_key.clone();
            command.controller = o3k_network::NetworkControllerLease {
                controller_id: control.controller_id.to_string(),
                controller_epoch: control.controller_epoch.to_string(),
                fencing_token: lease.fencing_token,
            };
            match &dispatch_work {
                FabricWorkDispatch::New => {
                    command.command_id = execution_command_id_for_agent_epoch(
                        semantic_command_id,
                        &command.target.agent_epoch,
                    );
                    command.idempotency_key = format!(
                        "{semantic_idempotency_key}:agent-epoch:{}",
                        command.target.agent_epoch
                    );
                }
                FabricWorkDispatch::Supersede { command_id, .. } => {
                    let historical_id = Uuid::parse_str(command_id).map_err(|_| {
                        o3k_network::NetworkDispatchError::Rejected(
                            "historical network command ID is malformed".to_owned(),
                        )
                    })?;
                    command.command_id = Uuid::new_v5(
                        &historical_id,
                        format!(
                            "recovery-successor:{}:{}:{}",
                            command.target.agent_epoch,
                            command.action as u8,
                            command.plan.fingerprint_sha256
                        )
                        .as_bytes(),
                    );
                    command.idempotency_key = format!(
                        "{semantic_idempotency_key}:successor-of:{command_id}:agent-epoch:{}",
                        command.target.agent_epoch
                    );
                }
                FabricWorkDispatch::ExistingSuccessor { command_id } => {
                    command.command_id = Uuid::parse_str(command_id).map_err(|_| {
                        o3k_network::NetworkDispatchError::Rejected(
                            "successor network command ID is malformed".to_owned(),
                        )
                    })?;
                }
            }
            let now = super::unix_time_millis();
            if command.deadline_unix_ms <= now {
                return Err(o3k_network::NetworkDispatchError::Rejected(
                    "network plan deadline has expired".to_owned(),
                ));
            }
            let work_record = o3k_store::NetworkPlanWorkRecord {
                command_id: command.command_id.to_string(),
                operation_id: command.operation_id,
                idempotency_key: command.idempotency_key.clone(),
                target_host_id: command.plan.node_id.clone(),
                target_agent_id: command.target.agent_id.clone(),
                target_agent_epoch: command.target.agent_epoch.clone(),
                controller_id: command.controller.controller_id.clone(),
                controller_epoch: command.controller.controller_epoch.clone(),
                fencing_token: command.controller.fencing_token,
                deadline_unix_ms: command.deadline_unix_ms,
                fingerprint_sha256: command.plan.fingerprint_sha256.clone(),
                snapshot: serde_json::to_vec(&command).map_err(|error| {
                    o3k_network::NetworkDispatchError::Rejected(error.to_string())
                })?,
                state: o3k_store::NetworkPlanWorkState::Pending,
                revision: 0,
                outcome: None,
            };
            let persisted = if let FabricWorkDispatch::Supersede {
                command_id: old_command_id,
                revision: old_revision,
            } = &dispatch_work
            {
                #[cfg(test)]
                if let Some((reached, proceed)) = &self.pre_supersession_gate {
                    reached.notify_one();
                    proceed.notified().await;
                }
                self.supersede_fabric_work(realm_id, old_command_id, *old_revision, &work_record)
                    .await?
                    .1
            } else {
                self.insert_fabric_work(realm_id, &work_record).await?
            };
            if !persisted.same_desired_identity(&work_record) {
                return Err(o3k_network::NetworkDispatchError::Rejected(
                    "network plan work command identity conflict".to_owned(),
                ));
            }
            // A prior attempt may have been rejected before admission and
            // atomically superseded after an authoritative `not_found`
            // observation. If that durable successor already converged the
            // exact same desired plan, this fresh lifecycle entry can reuse
            // that proof rather than trying to reopen the immutable terminal
            // historical command (which would remain failed forever).
            if persisted.state == o3k_store::NetworkPlanWorkState::Failed
                && let Some(outcome) = persisted.outcome.as_deref()
                && let Ok(outcome) = serde_json::from_slice::<serde_json::Value>(outcome)
                && outcome["classification"] == "superseded_not_admitted"
                && let Some(successor_id) = outcome["successor_command_id"].as_str()
            {
                let successor = control
                    .durable
                    .get_network_plan_work(successor_id)
                    .await
                    .map_err(|_| o3k_network::NetworkDispatchError::Unavailable)?;
                let successor_command: o3k_network::NetworkPlanCommand =
                    serde_json::from_slice(&successor.snapshot).map_err(|_| {
                        o3k_network::NetworkDispatchError::Rejected(
                            "superseding network plan snapshot is corrupt".to_owned(),
                        )
                    })?;
                let same_plan = successor.target_host_id == work_record.target_host_id
                    && successor.target_agent_id == work_record.target_agent_id
                    && successor.target_agent_epoch == work_record.target_agent_epoch
                    && successor.fingerprint_sha256 == work_record.fingerprint_sha256
                    && successor_command.action == command.action
                    && successor_command.target == command.target
                    && successor_command
                        .plan
                        .fabric
                        .as_ref()
                        .zip(command.plan.fabric.as_ref())
                        .is_some_and(|(accepted, desired)| {
                            accepted.realm_id == desired.realm_id
                                && accepted.local_host == desired.local_host
                        })
                    && successor_command.plan.fingerprint_sha256 == command.plan.fingerprint_sha256;
                if same_plan && successor.state == o3k_store::NetworkPlanWorkState::Succeeded {
                    return Ok(o3k_network::NetworkPlanStatus::Succeeded);
                }
                if same_plan
                    && matches!(
                        successor.state,
                        o3k_store::NetworkPlanWorkState::Pending
                            | o3k_store::NetworkPlanWorkState::Accepted
                            | o3k_store::NetworkPlanWorkState::Running
                            | o3k_store::NetworkPlanWorkState::Retryable
                            | o3k_store::NetworkPlanWorkState::UnknownOutcome
                    )
                {
                    return Err(o3k_network::NetworkDispatchError::Unavailable);
                }
            }
            #[cfg(test)]
            if matches!(&dispatch_work, FabricWorkDispatch::Supersede { .. })
                && let Some((committed, continue_dispatch)) = &self.supersession_gate
            {
                // The test gate sits after the atomic old-row/successor
                // transaction and before the first network-agent RPC. It
                // allows the test to inspect the committed rows and stop the
                // service to exercise restart recovery at this boundary.
                committed.notify_one();
                continue_dispatch.notified().await;
            }
            if persisted.state == o3k_store::NetworkPlanWorkState::Succeeded {
                return Ok(o3k_network::NetworkPlanStatus::Succeeded);
            }
            let runnable = if matches!(&dispatch_work, FabricWorkDispatch::ExistingSuccessor { .. })
                && persisted.state != o3k_store::NetworkPlanWorkState::Pending
            {
                if !matches!(
                    persisted.state,
                    o3k_store::NetworkPlanWorkState::Accepted
                        | o3k_store::NetworkPlanWorkState::Running
                        | o3k_store::NetworkPlanWorkState::Retryable
                        | o3k_store::NetworkPlanWorkState::UnknownOutcome
                ) {
                    return Err(o3k_network::NetworkDispatchError::Rejected(
                        "durable successor is not safely retryable".to_owned(),
                    ));
                }
                if persisted.state == o3k_store::NetworkPlanWorkState::Retryable {
                    persisted
                } else {
                    self.transition_fabric_work(
                        realm_id,
                        &persisted.command_id,
                        persisted.revision,
                        o3k_store::NetworkPlanWorkState::Retryable,
                        Some(b"agent_observation_not_found"),
                    )
                    .await?
                }
            } else if persisted.state == o3k_store::NetworkPlanWorkState::Pending {
                persisted
            } else {
                return Err(o3k_network::NetworkDispatchError::Rejected(
                    "network plan command is unresolved and requires observation before retry"
                        .to_owned(),
                ));
            };
            let running = self
                .transition_fabric_work(
                    realm_id,
                    &runnable.command_id,
                    runnable.revision,
                    o3k_store::NetworkPlanWorkState::Running,
                    None,
                )
                .await?;
            let remote_expiry = now
                .saturating_add(NETWORK_AGENT_REMOTE_LEASE.as_millis().min(u64::MAX as u128) as u64)
                .min(command.deadline_unix_ms);
            (
                Some(o3k_network_protocol::proto::ControllerLease {
                    controller_id: command.controller.controller_id.clone(),
                    controller_epoch: command.controller.controller_epoch.clone(),
                    fencing_token: command.controller.fencing_token,
                    lease_expiry_unix_ms: remote_expiry,
                }),
                Some((running, agent_control_lease)),
            )
        } else {
            (None, None)
        };
        let client = match o3k_network_protocol::NetworkAgentClient::connect(
            &transport.endpoint,
            &transport.server_name,
            &self.ca_certificate,
            &self.client_certificate,
            &self.client_key,
        )
        .await
        {
            Ok(client) => client,
            Err(error) => {
                if let Some((current, lease_guard)) = &work
                    && lease_guard.assert_current().await.is_ok()
                    && let Some(realm_id) = realm_id
                {
                    let _ = self
                        .transition_fabric_work(
                            realm_id,
                            &current.command_id,
                            current.revision,
                            o3k_store::NetworkPlanWorkState::Retryable,
                            Some(b"transport_connection_failed_before_command_send"),
                        )
                        .await;
                }
                return Err(o3k_network::NetworkDispatchError::Transport(
                    error.to_string(),
                ));
            }
        };
        let command_id = command.command_id.to_string();
        if let Some((_, lease_guard)) = &work {
            lease_guard.assert_current().await?;
        }
        let result = client
            .execute_with_lease(
                o3k_network_protocol::proto::Register {
                    agent_id: command.target.agent_id.clone(),
                    agent_epoch: command.target.agent_epoch.clone(),
                },
                o3k_network_protocol::proto::NetworkCommand {
                    command_id: command_id.clone(),
                    operation_id: command.operation_id.to_string(),
                    idempotency_key: command.idempotency_key,
                    agent_id: command.target.agent_id,
                    agent_epoch: command.target.agent_epoch,
                    controller_id: command.controller.controller_id,
                    controller_epoch: command.controller.controller_epoch,
                    fencing_token: command.controller.fencing_token,
                    deadline_unix_ms: command.deadline_unix_ms,
                    plan_json: serde_json::to_string(&command.plan).map_err(|error| {
                        o3k_network::NetworkDispatchError::Rejected(error.to_string())
                    })?,
                    remove: matches!(command.action, o3k_network::NetworkPlanAction::Remove),
                },
                controller_lease,
            )
            .await
            .map_err(|error| {
                tracing::warn!(
                    command_id = %command_id,
                    operation_id = %command.operation_id,
                    error = %error,
                    "network agent dispatch failed"
                );
                o3k_network::NetworkDispatchError::Transport(error.to_string())
            });
        let result = match result {
            Ok(result) => result,
            Err(error) => {
                if let Some((current, lease_guard)) = &work {
                    let outcome = error.to_string();
                    if lease_guard.assert_current().await.is_ok()
                        && let Some(realm_id) = realm_id
                    {
                        let _ = self
                            .transition_fabric_work(
                                realm_id,
                                &current.command_id,
                                current.revision,
                                o3k_store::NetworkPlanWorkState::UnknownOutcome,
                                Some(outcome.as_bytes()),
                            )
                            .await;
                    }
                }
                return Err(error);
            }
        };
        #[cfg(test)]
        if let Some((received, persist)) = &self.result_persistence_gate {
            received.notify_one();
            persist.notified().await;
        }
        if let Some((_, lease_guard)) = &work {
            lease_guard.assert_current().await?;
        }
        tracing::debug!(
            command_id = %command_id,
            operation_id = %command.operation_id,
            status = %result.status,
            replayed = result.replayed,
            error_code = %result.error_code,
            "network agent dispatch completed"
        );
        let status = match result.status.as_str() {
            "succeeded" | "replayed" | "recovered" => o3k_network::NetworkPlanStatus::Succeeded,
            "unknown" | "requires_observation" => o3k_network::NetworkPlanStatus::Unknown,
            other => {
                if let Some((current, lease_guard)) = &work {
                    lease_guard.assert_current().await?;
                    let outcome = if result.error_code.is_empty() {
                        other.to_owned()
                    } else {
                        result.error_code.clone()
                    };
                    if let Some(realm_id) = realm_id {
                        let _ = self
                            .transition_fabric_work(
                                realm_id,
                                &current.command_id,
                                current.revision,
                                o3k_store::NetworkPlanWorkState::Failed,
                                Some(outcome.as_bytes()),
                            )
                            .await;
                    }
                }
                return Err(o3k_network::NetworkDispatchError::Rejected(
                    if result.error_code.is_empty() {
                        other.to_owned()
                    } else {
                        result.error_code
                    },
                ));
            }
        };
        if let Some((current, lease_guard)) = work {
            lease_guard.assert_current().await?;
            let next = if status == o3k_network::NetworkPlanStatus::Succeeded {
                o3k_store::NetworkPlanWorkState::Succeeded
            } else {
                o3k_store::NetworkPlanWorkState::UnknownOutcome
            };
            self.transition_fabric_work(
                realm_id.ok_or(o3k_network::NetworkDispatchError::Unavailable)?,
                &current.command_id,
                current.revision,
                next,
                Some(result.status.as_bytes()),
            )
            .await?;
        }
        Ok(status)
    }
}

#[async_trait]
impl o3k_network::NetworkPlanDispatcher for NetworkAgentDispatcher {
    async fn target_for_host(
        &self,
        host_id: &str,
    ) -> Result<Option<o3k_network::NetworkAgentIdentity>, o3k_network::NetworkDispatchError> {
        let Some(target) = self.fabric_targets.get(host_id) else {
            if !self.fabric_targets.is_empty() {
                return Err(o3k_network::NetworkDispatchError::Rejected(
                    "stable host has no target in the Fabric network-agent directory".to_owned(),
                ));
            }
            return Ok(None);
        };
        Ok(Some({
            o3k_network::NetworkAgentIdentity {
                agent_id: target.agent_id.clone(),
                agent_epoch: target.agent_epoch.clone(),
            }
        }))
    }

    fn configured_target_hosts(&self) -> Vec<String> {
        self.fabric_targets.keys().cloned().collect()
    }

    async fn dispatch(
        &self,
        command: o3k_network::NetworkPlanCommand,
    ) -> Result<o3k_network::NetworkPlanStatus, o3k_network::NetworkDispatchError> {
        self.dispatch_inner(command, FabricWorkDispatch::New).await
    }

    async fn dispatch_superseding(
        &self,
        command: o3k_network::NetworkPlanCommand,
        historical_command_id: String,
        historical_revision: u64,
    ) -> Result<o3k_network::NetworkPlanStatus, o3k_network::NetworkDispatchError> {
        self.dispatch_inner(
            command,
            FabricWorkDispatch::Supersede {
                command_id: historical_command_id,
                revision: historical_revision,
            },
        )
        .await
    }

    async fn dispatch_existing_successor(
        &self,
        command: o3k_network::NetworkPlanCommand,
        successor_command_id: String,
    ) -> Result<o3k_network::NetworkPlanStatus, o3k_network::NetworkDispatchError> {
        self.dispatch_inner(
            command,
            FabricWorkDispatch::ExistingSuccessor {
                command_id: successor_command_id,
            },
        )
        .await
    }

    async fn observe_command(
        &self,
        target_host_id: &str,
        target: o3k_network::NetworkAgentIdentity,
        command_id: Uuid,
    ) -> Result<Option<o3k_network::NetworkPlanStatus>, o3k_network::NetworkDispatchError> {
        let _control_guard = self.control_lock.lock().await;
        let control = self.control.as_ref().ok_or_else(|| {
            o3k_network::NetworkDispatchError::Rejected(
                "historical Fabric command observation requires coordination ownership".to_owned(),
            )
        })?;
        let configured = self.fabric_targets.get(target_host_id).ok_or_else(|| {
            o3k_network::NetworkDispatchError::Rejected(
                "historical target agent is not enrolled".to_owned(),
            )
        })?;
        if configured.agent_id != target.agent_id || configured.agent_epoch != target.agent_epoch {
            return Err(o3k_network::NetworkDispatchError::Rejected(
                "historical target does not match enrolled host identity".to_owned(),
            ));
        }
        let key = format!("network-agent:{}", target.agent_id);
        let lease = match control
            .coordination
            .acquire_work_lease(
                &key,
                "network_agent_control",
                &control.controller_id,
                &control.controller_epoch,
                NETWORK_AGENT_CONTROL_TTL,
            )
            .await
            .map_err(|_| o3k_network::NetworkDispatchError::Unavailable)?
        {
            o3k_store::LeaseAcquireOutcome::Acquired { lease } => lease,
            o3k_store::LeaseAcquireOutcome::Busy { .. } => {
                return Err(o3k_network::NetworkDispatchError::Unavailable);
            }
        };
        let lease_guard = AgentControlLeaseGuard::start(
            control.coordination.clone(),
            key.clone(),
            control.controller_id.clone(),
            control.controller_epoch.clone(),
            lease.fencing_token,
        );
        lease_guard.assert_current().await?;
        let current = control
            .coordination
            .inspect_work_lease(&key)
            .await
            .map_err(|_| o3k_network::NetworkDispatchError::Unavailable)?;
        if !current.is_some_and(|current| {
            current.owner_controller_id == control.controller_id
                && current.owner_controller_epoch == control.controller_epoch
                && current.fencing_token == lease.fencing_token
        }) {
            return Err(o3k_network::NetworkDispatchError::Unavailable);
        }
        let now = super::unix_time_millis();
        let client = o3k_network_protocol::NetworkAgentClient::connect(
            &configured.endpoint,
            &configured.tls_server_name,
            &self.ca_certificate,
            &self.client_certificate,
            &self.client_key,
        )
        .await
        .map_err(|error| o3k_network::NetworkDispatchError::Transport(error.to_string()))?;
        let result = client
            .observe_with_lease(
                o3k_network_protocol::proto::Register {
                    agent_id: target.agent_id.clone(),
                    agent_epoch: target.agent_epoch,
                },
                o3k_network_protocol::proto::ControllerLease {
                    controller_id: control.controller_id.to_string(),
                    controller_epoch: control.controller_epoch.to_string(),
                    fencing_token: lease.fencing_token,
                    lease_expiry_unix_ms: now.saturating_add(
                        NETWORK_AGENT_REMOTE_LEASE.as_millis().min(u64::MAX as u128) as u64,
                    ),
                },
                command_id.to_string(),
            )
            .await
            .map_err(|error| o3k_network::NetworkDispatchError::Transport(error.to_string()))?;
        lease_guard.assert_current().await?;
        let status = match result.status.as_str() {
            "succeeded" => Some(o3k_network::NetworkPlanStatus::Succeeded),
            "unknown" => Some(o3k_network::NetworkPlanStatus::Unknown),
            "running" | "accepted" => Some(o3k_network::NetworkPlanStatus::Applying),
            "not_found" => None,
            other => {
                return Err(o3k_network::NetworkDispatchError::Rejected(
                    if result.error_code.is_empty() {
                        other.to_owned()
                    } else {
                        result.error_code
                    },
                ));
            }
        };
        Ok(status)
    }
}

impl NetworkAgentDispatcher {
    async fn fabric_work_fence(
        &self,
        realm_id: Uuid,
    ) -> Result<
        (Arc<dyn o3k_store::DurableStore>, String, String, u64),
        o3k_network::NetworkDispatchError,
    > {
        let control = self
            .control
            .as_ref()
            .ok_or(o3k_network::NetworkDispatchError::Unavailable)?;
        let work_key = format!("fabric-realm:{realm_id}");
        let lease = control
            .coordination
            .inspect_work_lease(&work_key)
            .await
            .map_err(|_| o3k_network::NetworkDispatchError::Unavailable)?
            .ok_or(o3k_network::NetworkDispatchError::Unavailable)?;
        if lease.owner_controller_id != control.controller_id
            || lease.owner_controller_epoch != control.controller_epoch
        {
            return Err(o3k_network::NetworkDispatchError::Unavailable);
        }
        Ok((
            control.durable.clone(),
            work_key,
            control.controller_id.0.clone(),
            lease.fencing_token,
        ))
    }

    async fn insert_fabric_work(
        &self,
        realm_id: Uuid,
        work: &o3k_store::NetworkPlanWorkRecord,
    ) -> Result<o3k_store::NetworkPlanWorkRecord, o3k_network::NetworkDispatchError> {
        let (durable, work_key, controller_id, token) = self.fabric_work_fence(realm_id).await?;
        let control = self
            .control
            .as_ref()
            .ok_or(o3k_network::NetworkDispatchError::Unavailable)?;
        durable
            .insert_network_plan_work_under_lease(
                &work_key,
                &controller_id,
                &control.controller_epoch.0,
                token,
                work,
            )
            .await
            .map_err(|error| o3k_network::NetworkDispatchError::Rejected(error.to_string()))
    }

    async fn supersede_fabric_work(
        &self,
        realm_id: Uuid,
        old_command_id: &str,
        old_revision: u64,
        successor: &o3k_store::NetworkPlanWorkRecord,
    ) -> Result<
        (
            o3k_store::NetworkPlanWorkRecord,
            o3k_store::NetworkPlanWorkRecord,
        ),
        o3k_network::NetworkDispatchError,
    > {
        let (durable, work_key, controller_id, token) = self.fabric_work_fence(realm_id).await?;
        let control = self
            .control
            .as_ref()
            .ok_or(o3k_network::NetworkDispatchError::Unavailable)?;
        durable
            .supersede_network_plan_work_under_lease(
                &work_key,
                &controller_id,
                &control.controller_epoch.0,
                token,
                old_command_id,
                old_revision,
                successor,
            )
            .await
            .map_err(|error| o3k_network::NetworkDispatchError::Rejected(error.to_string()))
    }

    async fn transition_fabric_work(
        &self,
        realm_id: Uuid,
        command_id: &str,
        revision: u64,
        state: o3k_store::NetworkPlanWorkState,
        outcome: Option<&[u8]>,
    ) -> Result<o3k_store::NetworkPlanWorkRecord, o3k_network::NetworkDispatchError> {
        let (durable, work_key, controller_id, token) = self.fabric_work_fence(realm_id).await?;
        let control = self
            .control
            .as_ref()
            .ok_or(o3k_network::NetworkDispatchError::Unavailable)?;
        durable
            .update_network_plan_work_under_lease(
                &work_key,
                &controller_id,
                &control.controller_epoch.0,
                token,
                command_id,
                revision,
                state,
                outcome,
            )
            .await
            .map_err(|error| o3k_network::NetworkDispatchError::Rejected(error.to_string()))
    }

    fn transport_for(
        &self,
        command: &o3k_network::NetworkPlanCommand,
    ) -> Result<NetworkAgentTransport, o3k_network::NetworkDispatchError> {
        let target_host = command
            .plan
            .fabric
            .as_ref()
            .map_or(command.plan.node_id.as_str(), |fabric| {
                fabric.local_host.as_str()
            });
        if let Some(target) = self.fabric_targets.get(target_host).filter(|target| {
            target.agent_id == command.target.agent_id
                && target.agent_epoch == command.target.agent_epoch
        }) {
            return Ok(NetworkAgentTransport {
                endpoint: target.endpoint.clone(),
                server_name: target.tls_server_name.clone(),
            });
        }
        if command.plan.fabric.is_some() || !self.fabric_targets.is_empty() {
            return Err(o3k_network::NetworkDispatchError::Rejected(
                "network plan target does not resolve to its enrolled host control endpoint"
                    .to_owned(),
            ));
        }
        self.legacy_target.clone().ok_or_else(|| {
            o3k_network::NetworkDispatchError::Rejected(
                "legacy network agent endpoint is not configured".to_owned(),
            )
        })
    }
}

pub(crate) fn public_allocator_from_env(
    data_dir: &std::path::Path,
) -> Result<Option<o3k_network::PublicAddressAllocator>, Box<dyn std::error::Error>> {
    let cidr = std::env::var("O3K_PUBLIC_POOL_CIDR").ok();
    let first = std::env::var("O3K_PUBLIC_POOL_FIRST").ok();
    let last = std::env::var("O3K_PUBLIC_POOL_LAST").ok();
    if cidr.is_none() && first.is_none() && last.is_none() {
        return Ok(None);
    }
    let cidr = cidr.ok_or("O3K_PUBLIC_POOL_CIDR is required")?;
    let first = first.ok_or("O3K_PUBLIC_POOL_FIRST is required")?.parse()?;
    let last = last.ok_or("O3K_PUBLIC_POOL_LAST is required")?.parse()?;
    let (network, prefix_len) = cidr
        .split_once('/')
        .ok_or("O3K_PUBLIC_POOL_CIDR must be IPv4/prefix-length")?;
    let prefix = o3k_domain::Ipv4Prefix::new(network.parse()?, prefix_len.parse()?)
        .ok_or("O3K_PUBLIC_POOL_CIDR is invalid")?;
    Ok(Some(o3k_network::PublicAddressAllocator::open(
        data_dir.join("public-addresses"),
        o3k_network::PublicAddressPool {
            prefix,
            first_usable: first,
            last_usable: last,
        },
    )?))
}

/// Projects terminal compute outcomes into the durable port binding state of
/// the network control plane. Wired only for the agent provider profile,
/// where the resolver records binding intent at create dispatch.
#[derive(Clone)]
pub(crate) struct NetworkBindingProjector {
    pub(crate) network: o3k_network::NetworkService,
    pub(crate) registry: Arc<dyn o3k_provider::AgentNodeRegistry>,
    pub(crate) network_dispatcher: Option<Arc<dyn o3k_network::NetworkPlanDispatcher>>,
    pub(crate) network_controller: o3k_network::NetworkControllerLease,
    pub(crate) network_external_realm_id: Option<Uuid>,
    pub(crate) network_agent: Option<o3k_network::NetworkAgentIdentity>,
    pub(crate) fabric_reconciler: Option<Arc<FabricRealmReconciler>>,
    pub(crate) public_allocator: Option<Arc<o3k_network::PublicAddressAllocator>>,
    /// Terminal compute observations can be delivered more than once. Keep
    /// the read/dispatch/unbind sequence single-flight so a concurrent
    /// observation cannot construct a different remove plan while policy
    /// resources are being destroyed.
    pub(crate) unbind_lock: Arc<tokio::sync::Mutex<()>>,
}

impl NetworkBindingProjector {
    /// Resolves the canonical AddressRealm id of the configured external pool
    /// network. The canonical egress identity is the realm id, matching
    /// `compile_l3_gateway_intents`' egress identity so the routed provider
    /// sees one coherent external realm across the flat and gateway paths.
    /// Returns `None` only when no external pool network was configured. A
    /// configured pool must resolve to exactly one active canonical Realm;
    /// missing or ambiguous identity is returned as an error.
    async fn resolve_external_realm_route_id(
        &self,
        project_id: &str,
    ) -> Result<Option<Uuid>, std::io::Error> {
        let Some(network_id) = self.network_external_realm_id else {
            return Ok(None);
        };
        let realms = self
            .network
            .list_canonical_realms_for_project(project_id, network_id)
            .await
            .map_err(|error| std::io::Error::other(error.to_string()))?;
        select_active_external_realm(&realms)
            .map(Some)
            .map_err(std::io::Error::other)
    }

    async fn remove_public_binding(
        &self,
        project_id: &str,
        allocation_id: Uuid,
    ) -> Result<(), String> {
        let Some(dispatcher) = self.network_dispatcher.as_ref() else {
            return Ok(());
        };
        let Some(binding) = self
            .public_allocator
            .as_ref()
            .ok_or_else(|| "public allocator is not configured".to_owned())?
            .get(project_id, allocation_id)
            .map_err(|error| error.to_string())?
            .endpoint_id
            .map(|endpoint_id| (endpoint_id, allocation_id))
        else {
            return Ok(());
        };
        let _guard = self.unbind_lock.lock().await;
        let allocator = self
            .public_allocator
            .as_ref()
            .ok_or_else(|| "public allocator is not configured".to_owned())?;
        let allocation = allocator
            .get(project_id, binding.1)
            .map_err(|error| error.to_string())?;
        let port = self
            .network
            .get_port_for_project(project_id, binding.0)
            .await
            .map_err(|error| error.to_string())?;
        let Some(host) = port.binding_host.as_deref() else {
            return Ok(());
        };
        let agent = match dispatcher
            .target_for_host(host)
            .await
            .map_err(|error| error.to_string())?
        {
            Some(target) => target,
            None => {
                if let Some(configured) = self.network_agent.as_ref() {
                    if configured.agent_id != host {
                        return Err("bound network agent identity changed".to_owned());
                    }
                    configured.clone()
                } else {
                    let snapshot = self
                        .registry
                        .snapshot(host)
                        .await
                        .ok_or_else(|| "network agent snapshot unavailable".to_owned())?;
                    o3k_network::NetworkAgentIdentity {
                        agent_id: snapshot.agent_id,
                        agent_epoch: snapshot.agent_epoch,
                    }
                }
            }
        };
        let subnet_id = port
            .subnet_id
            .ok_or_else(|| "bound port has no subnet".to_owned())?;
        let subnet = self
            .network
            .get_subnet_for_project(project_id, subnet_id)
            .await
            .map_err(|error| error.to_string())?;
        let realms = self
            .network
            .list_canonical_realms_for_project(project_id, port.network_id)
            .await
            .map_err(|error| error.to_string())?;
        let realm_id = select_active_external_realm(&realms).map_err(str::to_owned)?;
        let external_realm_route_id = self
            .resolve_external_realm_route_id(project_id)
            .await
            .map_err(|error| error.to_string())?;
        let operation_id = Uuid::new_v5(
            &Uuid::NAMESPACE_URL,
            format!(
                "o3k:native:network:public-remove:{allocation_id}:{}",
                allocation.generation
            )
            .as_bytes(),
        );
        let deadline_unix_ms = super::unix_time_millis().saturating_add(30_000);
        let plan = o3k_network::compile_attachment_plan(o3k_network::AttachmentPlanInput {
            endpoint_id: binding.0,
            realm_id,
            project_id,
            mac: &port.mac_address,
            fixed_ip: port.fixed_ip,
            subnet_cidr: &subnet.cidr,
            node_id: host,
            operation_id,
            deadline_unix_ms,
            public_address: Some(allocation.public_address),
            external_realm_id: external_realm_route_id,
            policies: Vec::new(),
        })
        .map_err(|error| error.to_string())?;
        let command_id = Uuid::new_v5(
            &Uuid::NAMESPACE_URL,
            format!("o3k:native:network:public-remove-command:{operation_id}").as_bytes(),
        );
        let status = dispatcher
            .dispatch(o3k_network::NetworkPlanCommand {
                command_id,
                operation_id,
                idempotency_key: format!("o3k:native:network:public-remove:{allocation_id}"),
                action: o3k_network::NetworkPlanAction::Remove,
                target: agent,
                controller: self.network_controller.clone(),
                deadline_unix_ms,
                plan,
            })
            .await
            .map_err(|error| error.to_string())?;
        if status != o3k_network::NetworkPlanStatus::Succeeded {
            return Err("public binding removal requires observed provider success".to_owned());
        }
        Ok(())
    }
}

#[async_trait]
impl crate::native_adapters::resource::PublicAddressWorkflow for NetworkBindingProjector {
    async fn remove(&self, project_id: &str, allocation_id: Uuid) -> Result<(), String> {
        self.remove_public_binding(project_id, allocation_id).await
    }
}

fn select_active_external_realm(
    realms: &[o3k_store::CanonicalAddressRealmRecord],
) -> Result<Uuid, &'static str> {
    let active: Vec<_> = realms
        .iter()
        .filter(|realm| realm.state == "active")
        .collect();
    match active.as_slice() {
        [realm] => Ok(realm.id),
        [] => Err("configured external network has no active canonical AddressRealm"),
        _ => Err("configured external network has multiple active canonical AddressRealms"),
    }
}

#[cfg(test)]
#[allow(clippy::expect_used)]
mod dispatcher_tests {
    use super::*;
    use async_trait::async_trait;
    use o3k_network::NetworkPlanDispatcher as _;
    use o3k_store::{CoordinationRepository, DurableStore};
    use std::sync::Mutex;
    use tokio_stream::wrappers::TcpListenerStream;
    use tonic::transport::Server;
    use tower::ServiceExt;

    // These recovery tests use the shared destructive PostgreSQL test
    // database. Keep their reset-and-exercise sequence exclusive even when
    // the test runner schedules lib tests concurrently.
    static PRODUCTION_MTLS_POSTGRES_TEST_LOCK: tokio::sync::Mutex<()> =
        tokio::sync::Mutex::const_new(());

    async fn production_mtls_postgres_test_guard() -> tokio::sync::MutexGuard<'static, ()> {
        PRODUCTION_MTLS_POSTGRES_TEST_LOCK.lock().await
    }

    /// A test compute execution boundary that asks the same production
    /// `DaemonCreateResolver` used by the agent provider to resolve the
    /// request before delegating the synthetic VM operation to the fake.
    /// The HTTP router, ComputeService lifecycle, placement and Fabric path
    /// remain production; only hypervisor execution is controlled here.
    #[derive(Clone)]
    struct HttpResolvedComputeProvider {
        inner: o3k_provider::FakeComputeProvider,
        resolver: Arc<super::super::compute::DaemonCreateResolver>,
        registry: o3k_compute_agent::NodeRegistry,
        resolver_errors: Arc<Mutex<Vec<String>>>,
        lifecycle_events: Arc<Mutex<Vec<String>>>,
    }

    #[async_trait]
    impl o3k_provider::ComputeProvider for HttpResolvedComputeProvider {
        async fn capabilities(
            &self,
        ) -> Result<o3k_provider::Capabilities, o3k_provider::ProviderError> {
            self.inner.capabilities().await
        }

        async fn create_instance(
            &self,
            request: o3k_provider::CreateInstanceRequest,
        ) -> Result<o3k_provider::Operation, o3k_provider::ProviderError> {
            let target = request
                .placement_provider_id
                .as_deref()
                .ok_or(o3k_provider::ProviderError::InvalidRequest)?;
            let node = o3k_provider::AgentNodeRegistry::snapshot(&self.registry, target)
                .await
                .ok_or(o3k_provider::ProviderError::NotFound)?;
            self.lifecycle_events
                .lock()
                .map_err(|_| o3k_provider::ProviderError::StaleState)?
                .push(format!(
                    "compute_selected:{}:{}:{}",
                    node.agent_id, node.agent_epoch, node.host_id
                ));
            if let Err(error) = self.resolver.resolve_network(&request, &node).await {
                self.resolver_errors
                    .lock()
                    .map_err(|_| o3k_provider::ProviderError::StaleState)?
                    .push(error.to_string());
                return Err(error);
            }
            self.lifecycle_events
                .lock()
                .map_err(|_| o3k_provider::ProviderError::StaleState)?
                .push(format!(
                    "compute_admit:{}:{}:{}",
                    node.agent_id, node.agent_epoch, node.host_id
                ));
            self.inner.create_instance(request).await
        }

        async fn get_instance(
            &self,
            provider_instance_id: &str,
        ) -> Result<o3k_provider::Instance, o3k_provider::ProviderError> {
            self.inner.get_instance(provider_instance_id).await
        }

        async fn delete_instance(
            &self,
            request: o3k_provider::DeleteInstanceRequest,
        ) -> Result<o3k_provider::Operation, o3k_provider::ProviderError> {
            self.inner.delete_instance(request).await
        }

        async fn action_instance(
            &self,
            provider_instance_id: &str,
            action: o3k_provider::InstanceAction,
            operation_id: Uuid,
            idempotency_key: &str,
        ) -> Result<o3k_provider::Operation, o3k_provider::ProviderError> {
            self.inner
                .action_instance(provider_instance_id, action, operation_id, idempotency_key)
                .await
        }

        async fn get_operation(
            &self,
            provider_operation_id: Uuid,
        ) -> Result<o3k_provider::Operation, o3k_provider::ProviderError> {
            self.inner.get_operation(provider_operation_id).await
        }
    }

    #[derive(Clone)]
    struct HttpFabricRealizer {
        plans: Arc<Mutex<Vec<o3k_network::NodeNetworkPlan>>>,
        removes: Arc<Mutex<Vec<o3k_network::NodeNetworkPlan>>>,
        removed_is_proven: Arc<std::sync::atomic::AtomicBool>,
        lifecycle_events: Arc<Mutex<Vec<String>>>,
    }

    impl Default for HttpFabricRealizer {
        fn default() -> Self {
            Self {
                plans: Arc::default(),
                removes: Arc::default(),
                removed_is_proven: Arc::new(std::sync::atomic::AtomicBool::new(true)),
                lifecycle_events: Arc::default(),
            }
        }
    }

    impl o3k_network::NetworkPlanRealizer for HttpFabricRealizer {
        type Error = String;

        fn realize(&mut self, plan: &o3k_network::NodeNetworkPlan) -> Result<(), Self::Error> {
            self.lifecycle_events
                .lock()
                .map_err(|_| "lifecycle event log poisoned".to_owned())?
                .push(format!("fabric_realized:{}", plan.node_id));
            self.plans
                .lock()
                .map_err(|_| "realizer plan log poisoned".to_owned())?
                .push(plan.clone());
            Ok(())
        }

        fn remove(&mut self, plan: &o3k_network::NodeNetworkPlan) -> Result<(), Self::Error> {
            self.lifecycle_events
                .lock()
                .map_err(|_| "lifecycle event log poisoned".to_owned())?
                .push(format!("fabric_remove_mutated:{}", plan.node_id));
            self.removes
                .lock()
                .map_err(|_| "realizer removal log poisoned".to_owned())?
                .push(plan.clone());
            Ok(())
        }

        fn observe(&mut self, _plan: &o3k_network::NodeNetworkPlan) -> Result<bool, Self::Error> {
            Ok(true)
        }

        fn observe_removed(
            &mut self,
            plan: &o3k_network::NodeNetworkPlan,
        ) -> Result<bool, Self::Error> {
            let absent = self
                .removed_is_proven
                .load(std::sync::atomic::Ordering::SeqCst);
            if absent {
                self.lifecycle_events
                    .lock()
                    .map_err(|_| "lifecycle event log poisoned".to_owned())?
                    .push(format!("fabric_remove_absent:{}", plan.node_id));
            }
            Ok(absent)
        }
    }

    async fn http_json(
        app: &axum::Router,
        method: axum::http::Method,
        uri: &str,
        token: &str,
        body: Option<serde_json::Value>,
    ) -> Result<(axum::http::StatusCode, serde_json::Value), Box<dyn std::error::Error>> {
        use axum::body::Body;
        use axum::http::{Request, header};
        use tower::ServiceExt;

        let mut request = Request::builder()
            .method(method)
            .uri(uri)
            .header("x-auth-token", token)
            .header("authorization", format!("Bearer {token}"));
        let body = if let Some(body) = body {
            request = request.header(header::CONTENT_TYPE, "application/json");
            Body::from(serde_json::to_vec(&body)?)
        } else {
            Body::empty()
        };
        let response = app.clone().oneshot(request.body(body)?).await?;
        let status = response.status();
        let bytes = axum::body::to_bytes(response.into_body(), 256 * 1024).await?;
        let value = if bytes.is_empty() {
            serde_json::Value::Null
        } else {
            serde_json::from_slice(&bytes).unwrap_or_else(
                |_| serde_json::json!({"body": String::from_utf8_lossy(&bytes).to_string()}),
            )
        };
        Ok((status, value))
    }

    async fn wait_for_http_fabric_plan(
        logs: &BTreeMap<String, Arc<std::sync::Mutex<Vec<o3k_network::NodeNetworkPlan>>>>,
        agent_id: &str,
        host_id: &str,
        expected_peers: &BTreeSet<String>,
    ) -> Result<o3k_network::NodeNetworkPlan, Box<dyn std::error::Error>> {
        let wait = async {
            loop {
                let plan = logs
                    .get(agent_id)
                    .ok_or_else(|| std::io::Error::other("missing agent plan log"))?
                    .lock()
                    .map_err(|_| std::io::Error::other("agent plan log poisoned"))?
                    .last()
                    .cloned();
                if let Some(plan) = plan {
                    let fabric = plan.fabric.as_ref();
                    let peers = fabric.map(|fabric| {
                        fabric
                            .peers
                            .iter()
                            .map(|peer| peer.host_id.clone())
                            .collect::<BTreeSet<_>>()
                    });
                    if fabric.is_some_and(|fabric| fabric.local_host == host_id)
                        && peers.as_ref() == Some(expected_peers)
                    {
                        return Ok::<_, std::io::Error>(plan);
                    }
                }
                tokio::time::sleep(std::time::Duration::from_millis(20)).await;
            }
        };
        match tokio::time::timeout(std::time::Duration::from_secs(10), wait).await {
            Ok(result) => Ok(result?),
            Err(_) => {
                let latest = logs
                    .iter()
                    .map(|(id, entries)| {
                        let state = entries
                            .lock()
                            .map(|plans| {
                                plans.last().map(|plan| {
                                    let peers = plan.fabric.as_ref().map(|fabric| {
                                        fabric
                                            .peers
                                            .iter()
                                            .map(|peer| peer.host_id.clone())
                                            .collect::<Vec<_>>()
                                    });
                                    (
                                        plan.fabric
                                            .as_ref()
                                            .map(|fabric| fabric.local_host.clone()),
                                        peers,
                                    )
                                })
                            })
                            .ok()
                            .flatten();
                        (id.clone(), state)
                    })
                    .collect::<Vec<_>>();
                Err(std::io::Error::other(format!(
                    "timed out waiting for {agent_id} on {host_id} with HER peers {expected_peers:?}; latest plans: {latest:?}"
                ))
                .into())
            }
        }
    }

    fn test_inventory() -> BTreeMap<String, o3k_placement::Inventory> {
        BTreeMap::from([
            (
                o3k_placement::VCPU.to_owned(),
                o3k_placement::Inventory {
                    total: 1,
                    reserved: 0,
                    allocation_ratio: 1.0,
                    used: 0,
                },
            ),
            (
                o3k_placement::MEMORY_MB.to_owned(),
                o3k_placement::Inventory {
                    total: 512,
                    reserved: 0,
                    allocation_ratio: 1.0,
                    used: 0,
                },
            ),
            (
                o3k_placement::DISK_GB.to_owned(),
                o3k_placement::Inventory {
                    total: 10,
                    reserved: 0,
                    allocation_ratio: 1.0,
                    used: 0,
                },
            ),
        ])
    }

    #[tokio::test]
    async fn fabric_reconcile_and_delete_share_realm_single_flight_without_global_serialization()
    -> Result<(), Box<dyn std::error::Error>> {
        let root = std::env::temp_dir().join(format!("o3kd-realm-lock-{}", Uuid::now_v7()));
        let store = Arc::new(o3k_store::testkit::open_memory().await?);
        let network = o3k_network::NetworkService::open_for_test(&root, store.clone()).await?;
        let durable: Arc<dyn DurableStore> = store.clone();
        let coordination: Arc<dyn CoordinationRepository> = store;
        let reconciler = FabricRealmReconciler {
            network,
            coordination,
            durable,
            registry: Arc::new(o3k_compute_agent::NodeRegistry::default()),
            dispatcher: Arc::new(dispatcher()),
            controller: o3k_network::NetworkControllerLease {
                controller_id: "single-flight-controller".to_owned(),
                controller_epoch: "epoch-1".to_owned(),
                fencing_token: 1,
            },
            fabric_domain_id: Uuid::from_u128(991),
            network_external_realm_id: None,
            public_allocator: None,
            reconciliation_locks: Arc::new(std::sync::Mutex::new(BTreeMap::new())),
        };

        let realm_a = Uuid::from_u128(101);
        let realm_b = Uuid::from_u128(202);
        // Both endpoint reconciliation and subnet deletion call this same
        // per-realm lock factory, so they cannot interleave for Realm A.
        let reconcile_lock = reconciler.local_realm_lock(realm_a);
        let delete_lock = reconciler.local_realm_lock(realm_a);
        assert!(Arc::ptr_eq(&reconcile_lock, &delete_lock));
        let held = reconcile_lock.lock().await;
        assert!(delete_lock.try_lock().is_err());

        // An unrelated Realm must remain runnable while Realm A is held.
        let other_realm_lock = reconciler.local_realm_lock(realm_b);
        assert!(other_realm_lock.try_lock().is_ok());
        drop(held);
        assert!(delete_lock.try_lock().is_ok());
        let _ = std::fs::remove_dir_all(root);
        Ok(())
    }

    #[tokio::test]
    async fn supported_http_server_lifecycle_dispatches_incremental_fabric_plans_over_mtls()
    -> Result<(), Box<dyn std::error::Error>> {
        use axum::http::{Method, StatusCode};
        use o3k_store::{DurableStore as _, NetworkRepository as _};

        let root = std::env::temp_dir().join(format!("o3kd-http-fabric-{}", Uuid::now_v7()));
        std::fs::create_dir_all(&root)?;
        // This exact HTTP-to-mTLS lifecycle can be run against either the
        // default isolated SQLite store or a caller-provisioned pristine
        // PostgreSQL database. The explicit variable avoids accidentally
        // directing ordinary unit runs at a shared development database.
        let sqlite_path = root.join("control.sqlite");
        let store = Arc::new(match std::env::var("O3K_TEST_FABRIC_HTTP_POSTGRES_URL") {
            Ok(url) => o3k_store::unified::O3kStore::connect_postgres(&url).await?,
            Err(_) => o3k_store::unified::O3kStore::connect_sqlite_file(&sqlite_path).await?,
        });
        let identity = o3k_identity::testkit::test_service_with_projects(
            "http://127.0.0.1:8080",
            vec![o3k_identity::ExtraProjectSeed {
                project_id: "project-a".to_owned(),
                project_name: "project-a".to_owned(),
                user_id: "user-a".to_owned(),
                user_name: "user-a".to_owned(),
                password: o3k_identity::Secret::new("password-a".to_owned()),
            }],
        )
        .await?;
        let network =
            o3k_network::NetworkService::open_for_test(root.join("network"), store.clone()).await?;
        let registry = Arc::new(o3k_compute_agent::NodeRegistry::default());
        let hosts = [
            (
                "compute-a",
                "compute-agent-a",
                "compute-epoch-a",
                "network-agent-a",
                "network-epoch-a",
                "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA=",
                11_u8,
            ),
            (
                "compute-b",
                "compute-agent-b",
                "compute-epoch-b",
                "network-agent-b",
                "network-epoch-b",
                "AQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQE=",
                12_u8,
            ),
            (
                "compute-c",
                "compute-agent-c",
                "compute-epoch-c",
                "network-agent-c",
                "network-epoch-c",
                "AgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgI=",
                13_u8,
            ),
        ];
        let mut server_tasks = Vec::new();
        let mut target_map = BTreeMap::new();
        let mut realizer_logs = BTreeMap::new();
        let mut removal_logs = BTreeMap::new();
        let mut absence_flags = BTreeMap::new();
        let lifecycle_events = Arc::new(Mutex::new(Vec::new()));
        let agent_d_realizer = HttpFabricRealizer {
            lifecycle_events: lifecycle_events.clone(),
            ..HttpFabricRealizer::default()
        };
        let agent_d_plans = agent_d_realizer.plans.clone();
        let agent_d_removes = agent_d_realizer.removes.clone();
        let agent_d_absence = agent_d_realizer.removed_is_proven.clone();
        let agent_d_journal = root.join("agent-agent-d");
        let agent_d_executor = o3k_network::NetworkPlanExecutor::open(
            &agent_d_journal,
            o3k_network::NetworkAgentIdentity {
                agent_id: "network-agent-d".to_owned(),
                agent_epoch: "network-epoch-d".to_owned(),
            },
            o3k_network::NetworkControllerLease {
                controller_id: String::new(),
                controller_epoch: String::new(),
                fencing_token: 0,
            },
        )?;
        let agent_d_service = o3k_network_bin::agent::NetworkAgentService::new_dynamic(
            agent_d_executor,
            agent_d_realizer.clone(),
        )?;
        let agent_d_listener = tokio::net::TcpListener::bind("127.0.0.1:0").await?;
        let agent_d_address = agent_d_listener.local_addr()?;
        let _agent_d_server_task =
            start_mtls_network_agent(agent_d_listener, agent_d_service).await?;
        target_map.insert(
            "compute-d".to_owned(),
            NetworkAgentControlTarget {
                host_id: "compute-d".to_owned(),
                agent_id: "network-agent-d".to_owned(),
                agent_epoch: "network-epoch-d".to_owned(),
                endpoint: format!("https://{agent_d_address}"),
                tls_server_name: "o3k-control-plane".to_owned(),
            },
        );
        for (
            host_id,
            compute_agent_id,
            compute_epoch,
            network_agent_id,
            network_epoch,
            public_key,
            octet,
        ) in hosts
        {
            network
                .enroll_fabric_host_transport_identity(
                    &o3k_store::FabricHostTransportIdentityRecord {
                        host_id: host_id.to_owned(),
                        agent_id: format!("legacy-fabric-record-{host_id}"),
                        public_key: public_key.to_owned(),
                        underlay_endpoint: format!("192.0.2.{octet}:65001"),
                        fabric_transport_ip: std::net::Ipv4Addr::new(198, 18, 1, octet),
                        provider_version: "0.1.5".to_owned(),
                        fabric_generation: 1,
                        underlay_mtu: 1500,
                        fabric_mtu: 1440,
                        administrative_state: "enabled".to_owned(),
                    },
                    None,
                )
                .await?;
            registry
                .register(&o3k_compute_agent::proto::RegisterRequest {
                    agent_id: compute_agent_id.to_owned(),
                    agent_epoch: compute_epoch.to_owned(),
                    software_version: "http-fabric-test".to_owned(),
                    host_label: host_id.to_owned(),
                    supported_versions: vec![o3k_compute_agent::PROTOCOL_VERSION],
                    capabilities: Some(o3k_compute_agent::proto::Capabilities::default()),
                })
                .await?;

            let realizer = HttpFabricRealizer {
                lifecycle_events: lifecycle_events.clone(),
                ..HttpFabricRealizer::default()
            };
            realizer_logs.insert(network_agent_id.to_owned(), realizer.plans.clone());
            removal_logs.insert(network_agent_id.to_owned(), realizer.removes.clone());
            absence_flags.insert(
                network_agent_id.to_owned(),
                realizer.removed_is_proven.clone(),
            );
            let executor = o3k_network::NetworkPlanExecutor::open(
                root.join(format!("agent-{network_agent_id}")),
                o3k_network::NetworkAgentIdentity {
                    agent_id: network_agent_id.to_owned(),
                    agent_epoch: network_epoch.to_owned(),
                },
                o3k_network::NetworkControllerLease {
                    controller_id: String::new(),
                    controller_epoch: String::new(),
                    fencing_token: 0,
                },
            )?;
            let service =
                o3k_network_bin::agent::NetworkAgentService::new_dynamic(executor, realizer)?;
            let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await?;
            let address = listener.local_addr()?;
            server_tasks.push(start_mtls_network_agent(listener, service).await?);
            target_map.insert(
                host_id.to_owned(),
                NetworkAgentControlTarget {
                    host_id: host_id.to_owned(),
                    agent_id: network_agent_id.to_owned(),
                    agent_epoch: network_epoch.to_owned(),
                    endpoint: format!("https://{address}"),
                    tls_server_name: "o3k-control-plane".to_owned(),
                },
            );
        }
        let durable: Arc<dyn DurableStore> = store.clone();
        let coordination: Arc<dyn CoordinationRepository> = store.clone();
        let controller_id = "http-fabric-controller";
        let controller_epoch = "epoch-1";
        let dispatcher = Arc::new(NetworkAgentDispatcher {
            legacy_target: None,
            fabric_targets: target_map,
            control: Some(NetworkAgentControlLease {
                coordination: coordination.clone(),
                durable: durable.clone(),
                controller_id: o3k_store::ControllerId::new(controller_id),
                controller_epoch: o3k_store::ControllerEpoch::new(controller_epoch),
            }),
            control_lock: Arc::new(tokio::sync::Mutex::new(())),
            ca_certificate: network_fixture("ca.pem"),
            client_certificate: network_fixture("agent-chain.pem"),
            client_key: network_fixture("agent-key-pkcs8.pem"),
            pre_supersession_gate: None,
            supersession_gate: None,
            result_persistence_gate: None,
        });
        let fabric_reconciler = Arc::new(FabricRealmReconciler {
            network: network.clone(),
            coordination: coordination.clone(),
            durable: durable.clone(),
            registry: registry.clone(),
            dispatcher: dispatcher.clone(),
            controller: o3k_network::NetworkControllerLease {
                controller_id: controller_id.to_owned(),
                controller_epoch: controller_epoch.to_owned(),
                fencing_token: 1,
            },
            fabric_domain_id: Uuid::from_u128(991),
            network_external_realm_id: None,
            public_allocator: None,
            reconciliation_locks: Arc::new(std::sync::Mutex::new(BTreeMap::new())),
        });
        let image = o3k_image::ImageService::open_for_test(
            root.join("images"),
            o3k_image::DEFAULT_MAX_UPLOAD_BYTES,
            store.clone(),
        )
        .await?;
        let config_drive = o3k_config_drive::ConfigDriveStore::open(root.join("config-drive"))?;
        let resolver = Arc::new(super::super::compute::DaemonCreateResolver {
            store: store.clone(),
            image,
            network: network.clone(),
            config_drive,
            network_dispatcher: None,
            fabric_reconciler: Some(fabric_reconciler.clone()),
            network_controller: o3k_network::NetworkControllerLease {
                controller_id: controller_id.to_owned(),
                controller_epoch: controller_epoch.to_owned(),
                fencing_token: 1,
            },
            network_external_realm_id: None,
            network_agent: None,
            public_allocator: None,
        });
        let placement =
            o3k_placement::PlacementLedger::open(root.join("placement"), store.clone()).await?;
        let placement_for_negative_tests = placement.clone();
        for (_, compute_agent_id, _, _, _, _, _) in hosts {
            placement
                .register_provider(compute_agent_id, test_inventory())
                .await?;
        }
        let resolver_errors = Arc::new(Mutex::new(Vec::new()));
        let compute_provider = HttpResolvedComputeProvider {
            inner: o3k_provider::FakeComputeProvider::new(),
            resolver,
            registry: (*registry).clone(),
            resolver_errors: resolver_errors.clone(),
            lifecycle_events: lifecycle_events.clone(),
        };
        let projector: Arc<dyn o3k_compute::PortBindingProjector> =
            Arc::new(NetworkBindingProjector {
                network: network.clone(),
                registry: registry.clone(),
                network_dispatcher: None,
                network_controller: o3k_network::NetworkControllerLease {
                    controller_id: controller_id.to_owned(),
                    controller_epoch: controller_epoch.to_owned(),
                    fencing_token: 1,
                },
                network_external_realm_id: None,
                network_agent: None,
                fabric_reconciler: Some(fabric_reconciler.clone()),
                public_allocator: None,
                unbind_lock: Arc::new(tokio::sync::Mutex::new(())),
            });
        let compute =
            o3k_compute::ComputeService::new_for_test(store.clone(), Arc::new(compute_provider))
                .with_scheduler(o3k_scheduler::Scheduler::new(placement))
                .with_agent_registry(registry.clone())
                .with_binding_projector(projector);
        let create_reconciler = compute.spawn_create_convergence_reconciler(1);
        let lifecycle_reconciler = compute.spawn_lifecycle_convergence_reconciler(1);
        let orphan_reconciler = compute.spawn_orphan_endpoint_reconciler(1);
        let app = o3k_api::router_with_state(
            o3k_api::AppState::new()
                .with_identity(identity)
                .with_compute(compute)
                .with_network(network.clone())
                .with_realm_deletion_workflow(
                    fabric_reconciler.clone() as Arc<dyn o3k_api::RealmDeletionWorkflow>
                ),
        );
        // Keystone's token is deliberately only held in process memory.
        let response = app.clone().oneshot(
            axum::http::Request::builder()
                .method(Method::POST)
                .uri("/v3/auth/tokens")
                .header(axum::http::header::CONTENT_TYPE, "application/json")
                .body(axum::body::Body::from(serde_json::json!({
                    "auth": {"identity":{"methods":["password"],"password":{"user":{"name":"user-a","password":"password-a"}}},"scope":{"project":{"name":"project-a"}}}
                }).to_string()))?
        ).await?;
        assert_eq!(response.status(), StatusCode::CREATED);
        let token = response
            .headers()
            .get("x-subject-token")
            .ok_or("missing token")?
            .to_str()?
            .to_owned();

        let run = Uuid::now_v7().simple().to_string();
        let (status, network_json) = http_json(
            &app,
            Method::POST,
            "/v2.0/networks",
            &token,
            Some(serde_json::json!({"network":{"name":format!("fabric-http-{run}")}})),
        )
        .await?;
        assert_eq!(status, StatusCode::CREATED, "{network_json}");
        let network_id = network_json["network"]["id"]
            .as_str()
            .ok_or("network id")?
            .to_owned();
        let (status, subnet_json) = http_json(&app, Method::POST, "/v2.0/subnets", &token,
            Some(serde_json::json!({"subnet":{"network_id":network_id,"name":format!("fabric-subnet-{run}"),"cidr":"10.77.0.0/24","gateway_ip":"10.77.0.1"}}))).await?;
        assert_eq!(status, StatusCode::CREATED, "{subnet_json}");
        let mut port_ids = Vec::new();
        for n in 0..3 {
            let (status, port_json) = http_json(&app, Method::POST, "/v2.0/ports", &token,
                Some(serde_json::json!({"port":{"network_id":network_id,"name":format!("fabric-port-{run}-{n}")}}))).await?;
            assert_eq!(status, StatusCode::CREATED, "{port_json}");
            port_ids.push(
                port_json["port"]["id"]
                    .as_str()
                    .ok_or("port id")?
                    .to_owned(),
            );
        }
        let mut server_ids = Vec::new();
        for (n, port_id) in port_ids.iter().enumerate() {
            let body = serde_json::json!({"server":{"name":format!("fabric-server-{run}-{n}"),"image":{"id":"image-a"},"flavor":{"id":"00000000-0000-0000-0000-000000000001"},"networks":[{"port":port_id}]}});
            let (status, response) = http_json(
                &app,
                Method::POST,
                "/v2.1/project-a/servers",
                &token,
                Some(body),
            )
            .await?;
            assert_eq!(status, StatusCode::ACCEPTED, "server {n}: {response}");
            server_ids.push(
                response["server"]["id"]
                    .as_str()
                    .ok_or("server id")?
                    .to_owned(),
            );
            for (host, _, _, network_agent, _, _, _) in hosts {
                let expected_min = match (n, host) {
                    (0, "compute-a") => 1,
                    (1, "compute-a") => 2,
                    (1, "compute-b") => 1,
                    (2, "compute-a") => 3,
                    (2, "compute-b") => 2,
                    (2, "compute-c") => 1,
                    _ => 0,
                };
                if expected_min != 0 {
                    let expected_peers: BTreeSet<_> = (0..=n)
                        .map(|index| format!("compute-{}", ['a', 'b', 'c'][index]))
                        .filter(|participant| participant != host)
                        .collect();
                    let plan = wait_for_http_fabric_plan(
                        &realizer_logs,
                        network_agent,
                        host,
                        &expected_peers,
                    )
                    .await
                    .map_err(|error| {
                        let details = resolver_errors
                            .lock()
                            .map(|errors| errors.clone())
                            .unwrap_or_default();
                        std::io::Error::other(format!("{error}; resolver errors: {details:?}"))
                    })?;
                    let fabric = plan.fabric.as_ref().ok_or("missing Fabric plan")?;
                    assert_eq!(fabric.local_host, host, "host-specific API-derived plan");
                    let peers: BTreeSet<_> = fabric
                        .peers
                        .iter()
                        .map(|peer| peer.host_id.clone())
                        .collect();
                    assert_eq!(
                        peers, expected_peers,
                        "incremental HER for {network_agent} after endpoint {n}"
                    );
                }
            }
            if n == 0 {
                let events = lifecycle_events
                    .lock()
                    .map_err(|_| "lifecycle event log poisoned")?
                    .clone();
                let selected = events
                    .iter()
                    .position(|event| {
                        event == "compute_selected:compute-agent-a:compute-epoch-a:compute-a"
                    })
                    .ok_or("compute A placement event")?;
                let realized = events
                    .iter()
                    .position(|event| event == "fabric_realized:compute-a")
                    .ok_or("Fabric A realization event")?;
                let admitted = events
                    .iter()
                    .position(|event| {
                        event == "compute_admit:compute-agent-a:compute-epoch-a:compute-a"
                    })
                    .ok_or("compute A admission event")?;
                assert!(
                    selected < realized && realized < admitted,
                    "compute placement must resolve host-a, Fabric must realize via its network agent, then compute may admit the VM: {events:?}"
                );
                let history = store.list_network_plan_work_history().await?;
                assert!(
                    history.iter().any(|work| {
                        work.target_host_id == "compute-a"
                            && work.target_agent_id == "network-agent-a"
                            && work.target_agent_epoch == "network-epoch-a"
                    }),
                    "Fabric work must target network-agent-a at its own epoch"
                );
            }
        }
        let realm = store
            .list_canonical_realms("project-a", &Uuid::parse_str(&network_id)?)
            .await?;
        assert_eq!(realm.len(), 1);
        let realm_id = realm[0].id;
        assert_eq!(
            store
                .list_canonical_endpoints("project-a", &realm_id)
                .await?
                .len(),
            3
        );
        let binding = store
            .get_canonical_realm_binding(&Uuid::from_u128(991).to_string(), &realm_id)
            .await?
            .ok_or("VNI binding")?;
        for (agent, logs) in &realizer_logs {
            let plans = logs.lock().map_err(|_| "plan log poisoned")?;
            let plan = plans.last().ok_or("missing dispatched plan")?;
            let fabric = plan.fabric.as_ref().ok_or("missing fabric plan")?;
            assert_eq!(fabric.realm_id, realm_id);
            assert_eq!(
                fabric.encapsulation.provider_segment_id,
                binding.provider_segment_id as u32
            );
            let expected_host = hosts
                .iter()
                .find(|(_, _, _, network_agent, _, _, _)| network_agent == agent)
                .map(|(host, _, _, _, _, _, _)| *host)
                .ok_or("network agent has no host mapping")?;
            assert_eq!(fabric.local_host, expected_host);
            let peer_ids: BTreeSet<_> = fabric
                .peers
                .iter()
                .map(|peer| peer.host_id.clone())
                .collect();
            let own = fabric.local_host.as_str();
            let expected: BTreeSet<String> = ["compute-a", "compute-b", "compute-c"]
                .into_iter()
                .filter(|host| *host != own)
                .map(str::to_owned)
                .collect();
            assert_eq!(peer_ids, expected);
        }
        let observed_hosts: BTreeSet<_> = realizer_logs
            .values()
            .filter_map(|logs| logs.lock().ok().and_then(|plans| plans.last().cloned()))
            .filter_map(|plan| plan.fabric.map(|fabric| fabric.local_host))
            .collect();
        assert_eq!(
            observed_hosts,
            BTreeSet::from([
                "compute-a".to_owned(),
                "compute-b".to_owned(),
                "compute-c".to_owned(),
            ])
        );
        assert!(
            dispatcher
                .transport_for(&fabric_command("network-agent-b", "compute-a"))
                .is_err(),
            "a Fabric plan for compute-a must not route to agent-b or fall back to a legacy target"
        );

        // Simulate a controller context restart without another tenant write.
        // Startup recovery must consume the durable HTTP-created state and
        // regenerate host plans through the same concrete target transports.
        let restarted_reconciler = (*fabric_reconciler).clone();
        recover_fabric_state(&restarted_reconciler, store.as_ref()).await;
        for (agent, logs) in &realizer_logs {
            let plans = logs.lock().map_err(|_| "plan log poisoned")?;
            let fabric = plans
                .last()
                .and_then(|plan| plan.fabric.as_ref())
                .ok_or("recovered plan")?;
            let expected_host = hosts
                .iter()
                .find(|(_, _, _, network_agent, _, _, _)| network_agent == agent)
                .map(|(host, _, _, _, _, _, _)| *host)
                .ok_or("network agent has no host mapping")?;
            assert_eq!(fabric.local_host, expected_host);
        }

        // Public readback stays on the compatibility API surface.
        for uri in [
            format!("/v2.0/networks/{network_id}"),
            format!(
                "/v2.0/subnets/{}",
                subnet_json["subnet"]["id"].as_str().ok_or("subnet id")?
            ),
        ] {
            let (status, body) = http_json(&app, Method::GET, &uri, &token, None).await?;
            assert_eq!(status, StatusCode::OK, "{uri}: {body}");
        }
        for port in &port_ids {
            let (status, body) = http_json(
                &app,
                Method::GET,
                &format!("/v2.0/ports/{port}"),
                &token,
                None,
            )
            .await?;
            assert_eq!(status, StatusCode::OK, "{body}");
        }
        for server in &server_ids {
            let (status, body) = http_json(
                &app,
                Method::GET,
                &format!("/v2.1/project-a/servers/{server}"),
                &token,
                None,
            )
            .await?;
            assert_eq!(status, StatusCode::OK, "{body}");
        }

        let work_before_c_delete = store
            .list_network_plan_work_history()
            .await?
            .into_iter()
            .map(|work| work.command_id)
            .collect::<BTreeSet<_>>();
        let (status, attached_port_before_delete) = http_json(
            &app,
            Method::GET,
            &format!("/v2.0/ports/{}", port_ids[2]),
            &token,
            None,
        )
        .await?;
        assert_eq!(status, StatusCode::OK, "{attached_port_before_delete}");
        let original_port_mac = attached_port_before_delete["port"]["mac_address"]
            .as_str()
            .ok_or("port MAC before server deletion")?
            .to_owned();
        let original_fixed_ip = attached_port_before_delete["port"]["fixed_ips"][0]["ip_address"]
            .as_str()
            .ok_or("port fixed IP before server deletion")?
            .to_owned();
        let event_count_before_c_delete = lifecycle_events
            .lock()
            .map_err(|_| "lifecycle event log poisoned")?
            .len();
        let (status, body) = http_json(
            &app,
            Method::DELETE,
            &format!("/v2.1/project-a/servers/{}", server_ids[2]),
            &token,
            None,
        )
        .await?;
        assert!(
            status == StatusCode::ACCEPTED || status == StatusCode::NO_CONTENT,
            "delete server C: {status} {body}"
        );
        let c_delete_work_result =
            tokio::time::timeout(std::time::Duration::from_secs(10), async {
                loop {
                    let history = store.list_network_plan_work_history().await?;
                    let work = history
                        .into_iter()
                        .filter(|work| !work_before_c_delete.contains(&work.command_id))
                        .map(|work| {
                            let command: o3k_network::NetworkPlanCommand =
                                serde_json::from_slice(&work.snapshot)?;
                            Ok::<_, Box<dyn std::error::Error>>((work, command))
                        })
                        .collect::<Result<Vec<_>, _>>()?;
                    if work.iter().any(|(_, command)| {
                        command.action == o3k_network::NetworkPlanAction::Remove
                            && command.plan.node_id == "compute-c"
                            && command
                                .plan
                                .fabric
                                .as_ref()
                                .is_some_and(|fabric| fabric.realm_id == realm_id)
                    }) {
                        return Ok::<_, Box<dyn std::error::Error>>(work);
                    }
                    tokio::time::sleep(std::time::Duration::from_millis(50)).await;
                }
            })
            .await;
        let c_delete_work = match c_delete_work_result {
            Ok(result) => result?,
            Err(_) => {
                let port = network
                    .get_port_for_project("project-a", Uuid::parse_str(&port_ids[2])?)
                    .await?;
                let server = store.get_resource(Uuid::parse_str(&server_ids[2])?).await;
                let history = store.list_network_plan_work_history().await?;
                let events = lifecycle_events
                    .lock()
                    .map(|events| events.clone())
                    .unwrap_or_default();
                return Err(std::io::Error::other(format!(
                    "server C delete did not create durable C Remove work; port={port:?}, server={server:?}, history_len={}, events={events:?}",
                    history.len()
                )).into());
            }
        };
        let retirement_sequence = c_delete_work
            .iter()
            .filter(|(_, command)| {
                command
                    .plan
                    .fabric
                    .as_ref()
                    .is_some_and(|fabric| fabric.realm_id == realm_id)
            })
            .map(|(work, command)| {
                assert_eq!(
                    work.state,
                    o3k_store::NetworkPlanWorkState::Succeeded,
                    "request-driven Realm transition must wait for observed work success"
                );
                (
                    command.plan.node_id.as_str(),
                    command.action,
                    work.target_agent_id.as_str(),
                    command
                        .plan
                        .resource_generations
                        .get(&realm_id)
                        .copied()
                        .unwrap_or_default(),
                )
            })
            .collect::<Vec<_>>();
        let c_remove_index = retirement_sequence
            .iter()
            .position(|(host, action, agent, _)| {
                *host == "compute-c"
                    && *action == o3k_network::NetworkPlanAction::Remove
                    && *agent == "network-agent-c"
            })
            .ok_or("durable C Remove work missing after server delete")?;
        let c_remove_generation = retirement_sequence[c_remove_index].3;
        assert_eq!(
            retirement_sequence[c_remove_index].2, "network-agent-c",
            "C Remove must target the durable network agent"
        );
        let removal_events = lifecycle_events
            .lock()
            .map_err(|_| "lifecycle event log poisoned")?
            .iter()
            .skip(event_count_before_c_delete)
            .cloned()
            .collect::<Vec<_>>();
        let c_absent_index = removal_events
            .iter()
            .position(|event| event == "fabric_remove_absent:compute-c")
            .ok_or_else(|| format!("C Remove absence was not observed: {removal_events:?}"))?;
        for (host, agent) in [
            ("compute-a", "network-agent-a"),
            ("compute-b", "network-agent-b"),
        ] {
            assert!(
                retirement_sequence
                    .iter()
                    .any(|(candidate, action, target, generation)| {
                        *candidate == host
                            && *action == o3k_network::NetworkPlanAction::Apply
                            && *target == agent
                            && *generation == c_remove_generation
                    }),
                "durable survivor Apply missing for {host}: {retirement_sequence:?}"
            );
            let apply_event = format!("fabric_realized:{host}");
            let apply_event_index = removal_events
                .iter()
                .position(|event| event == &apply_event)
                .ok_or_else(|| format!("{host} Apply execution missing: {removal_events:?}"))?;
            assert!(
                c_absent_index < apply_event_index,
                "C provider absence must be observed before {host} Apply: {removal_events:?}"
            );
        }
        let (status, detached_port) = http_json(
            &app,
            Method::GET,
            &format!("/v2.0/ports/{}", port_ids[2]),
            &token,
            None,
        )
        .await?;
        assert_eq!(status, StatusCode::OK, "{detached_port}");
        assert_eq!(detached_port["port"]["id"], port_ids[2]);
        assert_eq!(detached_port["port"]["mac_address"], original_port_mac);
        assert_eq!(
            detached_port["port"]["fixed_ips"][0]["ip_address"],
            original_fixed_ip
        );
        assert_eq!(
            detached_port["port"]["status"], "DOWN",
            "an explicitly unbound caller-owned endpoint projects Neutron DOWN"
        );
        assert_eq!(detached_port["port"]["device_id"], "");
        assert!(
            detached_port["port"]["binding:host_id"].is_null(),
            "server deletion must detach the caller-owned port"
        );
        let detached_record = network
            .get_port_for_project("project-a", Uuid::parse_str(&port_ids[2])?)
            .await?;
        assert_eq!(detached_record.binding_host, None);
        assert_eq!(detached_record.binding_state.as_deref(), Some("down"));
        for agent in ["network-agent-a", "network-agent-b"] {
            let plans = realizer_logs[agent]
                .lock()
                .map_err(|_| "plan log poisoned")?;
            let fabric = plans
                .last()
                .and_then(|plan| plan.fabric.as_ref())
                .ok_or("withdrawal plan")?;
            let peers: BTreeSet<_> = fabric
                .peers
                .iter()
                .map(|peer| peer.host_id.clone())
                .collect();
            let expected = if agent == "network-agent-a" {
                BTreeSet::from(["compute-b".to_owned()])
            } else {
                BTreeSet::from(["compute-a".to_owned()])
            };
            assert_eq!(peers, expected, "C must be withdrawn from {agent} HER");
        }
        assert!(
            !removal_logs["network-agent-c"]
                .lock()
                .map_err(|_| "remove log poisoned")?
                .is_empty(),
            "server C removal must remove its local endpoint realization"
        );

        // These are caller-created Neutron ports, so deleting their server
        // detaches them but preserves the ports. Remove C through the
        // supported Neutron API to retire the canonical endpoint itself.
        let (status, body) = http_json(
            &app,
            Method::DELETE,
            &format!("/v2.0/ports/{}", port_ids[2]),
            &token,
            None,
        )
        .await?;
        assert!(
            status == StatusCode::NO_CONTENT || status == StatusCode::ACCEPTED,
            "delete detached port C: {status} {body}"
        );
        let active_endpoints = store
            .list_canonical_endpoints("project-a", &realm_id)
            .await?
            .into_iter()
            .filter(|endpoint| endpoint.state == "active")
            .count();
        assert_eq!(
            active_endpoints, 2,
            "HTTP port deletion retires C from canonical Fabric membership"
        );
        tokio::time::timeout(std::time::Duration::from_secs(10), async {
            loop {
                let active = store
                    .list_canonical_endpoints("project-a", &realm_id)
                    .await
                    .map_err(|error| error.to_string())?
                    .into_iter()
                    .filter(|endpoint| endpoint.state == "active")
                    .count();
                if active == 2 {
                    return Ok::<(), String>(());
                }
                tokio::time::sleep(std::time::Duration::from_millis(100)).await;
            }
        })
        .await
        .map_err(|_| "port C canonical endpoint did not retire after HTTP deletion")??;

        for server in &server_ids[..2] {
            let (status, body) = http_json(
                &app,
                Method::DELETE,
                &format!("/v2.1/project-a/servers/{server}"),
                &token,
                None,
            )
            .await?;
            assert!(
                status == StatusCode::ACCEPTED || status == StatusCode::NO_CONTENT,
                "delete server: {status} {body}"
            );
        }
        for port in &port_ids[..2] {
            let (status, body) = http_json(
                &app,
                Method::DELETE,
                &format!("/v2.0/ports/{port}"),
                &token,
                None,
            )
            .await?;
            assert!(
                status == StatusCode::NO_CONTENT || status == StatusCode::ACCEPTED,
                "delete port: {status} {body}"
            );
        }
        assert!(
            store
                .list_canonical_endpoints("project-a", &realm_id)
                .await?
                .is_empty(),
            "supported server/port deletion must remove every canonical endpoint"
        );
        for agent in ["network-agent-a", "network-agent-b", "network-agent-c"] {
            assert!(
                !removal_logs[agent]
                    .lock()
                    .map_err(|_| "remove log poisoned")?
                    .is_empty(),
                "final endpoint teardown must dispatch provider removal to {agent}"
            );
        }
        assert!(
            store
                .get_canonical_realm_binding(&Uuid::from_u128(991).to_string(), &realm_id)
                .await?
                .is_some(),
            "active subnet retains its durable VNI binding until realm teardown"
        );

        // Exercise two failure-closed HTTP attachment cases against a fourth
        // independently routed mTLS network agent. This target is deliberately
        // not Fabric-enrolled for the first request. After observing that
        // rejection, enroll it, then restart only the compute agent epoch to
        // prove network realization remains targeted to its independent identity.
        for agent in ["compute-agent-a", "compute-agent-b", "compute-agent-c"] {
            placement_for_negative_tests
                .set_state(agent, o3k_placement::ProviderState::Unavailable)
                .await?;
        }
        placement_for_negative_tests
            .register_provider("compute-agent-d", test_inventory())
            .await?;
        registry
            .register(&o3k_compute_agent::proto::RegisterRequest {
                agent_id: "compute-agent-d".to_owned(),
                agent_epoch: "compute-epoch-d-1".to_owned(),
                software_version: "http-fabric-test".to_owned(),
                host_label: "compute-d".to_owned(),
                supported_versions: vec![o3k_compute_agent::PROTOCOL_VERSION],
                capabilities: Some(o3k_compute_agent::proto::Capabilities::default()),
            })
            .await?;
        realizer_logs.insert("network-agent-d".to_owned(), agent_d_plans.clone());
        removal_logs.insert("network-agent-d".to_owned(), agent_d_removes.clone());
        absence_flags.insert("network-agent-d".to_owned(), agent_d_absence.clone());
        let d_identity = o3k_store::FabricHostTransportIdentityRecord {
            host_id: "compute-d".to_owned(),
            // Deprecated compatibility metadata; stable host_id is authoritative.
            agent_id: "legacy-fabric-record-compute-d".to_owned(),
            public_key: "AwMDAwMDAwMDAwMDAwMDAwMDAwMDAwMDAwMDAwMDAwM=".to_owned(),
            underlay_endpoint: "192.0.2.14:65001".to_owned(),
            fabric_transport_ip: std::net::Ipv4Addr::new(198, 18, 1, 14),
            provider_version: "0.1.5".to_owned(),
            fabric_generation: 1,
            underlay_mtu: 1500,
            fabric_mtu: 1440,
            administrative_state: "enabled".to_owned(),
        };
        let create_port =
            |name: String| serde_json::json!({"port":{"network_id":network_id,"name":name}});
        let resolver_error_start = resolver_errors
            .lock()
            .map_err(|_| "resolver errors poisoned")?
            .len();
        let (status, missing_port) = http_json(
            &app,
            Method::POST,
            "/v2.0/ports",
            &token,
            Some(create_port(format!("fabric-missing-identity-{run}"))),
        )
        .await?;
        assert_eq!(status, StatusCode::CREATED, "{missing_port}");
        let missing_port_id = missing_port["port"]["id"]
            .as_str()
            .ok_or("missing-identity port id")?
            .to_owned();
        let (status, missing_server) = http_json(
            &app,
            Method::POST,
            "/v2.1/project-a/servers",
            &token,
            Some(serde_json::json!({"server":{"name":format!("fabric-missing-identity-server-{run}"),"image":{"id":"image-a"},"flavor":{"id":"00000000-0000-0000-0000-000000000001"},"networks":[{"port":missing_port_id}]}})),
        )
        .await?;
        assert_eq!(status, StatusCode::CONFLICT, "{missing_server}");
        assert!(
            resolver_errors
                .lock()
                .map_err(|_| "resolver errors poisoned")?
                .len()
                > resolver_error_start,
            "supported server attachment must reach Fabric identity validation"
        );
        assert!(
            network
                .list_fabric_host_transport_identities()
                .await?
                .iter()
                .all(|identity| identity.host_id != "compute-d"),
            "O3K must not invent a missing Fabric identity"
        );
        assert!(
            agent_d_plans
                .lock()
                .map_err(|_| "agent-d plan log poisoned")?
                .is_empty(),
            "missing Fabric identity must fail before provider mutation"
        );
        let (status, unbound_port) = http_json(
            &app,
            Method::GET,
            &format!("/v2.0/ports/{missing_port_id}"),
            &token,
            None,
        )
        .await?;
        assert_eq!(status, StatusCode::OK, "{unbound_port}");
        assert!(
            unbound_port["port"]["binding:host_id"].is_null(),
            "missing Fabric identity must be rejected before port binding"
        );
        let (status, body) = http_json(
            &app,
            Method::DELETE,
            &format!("/v2.0/ports/{missing_port_id}"),
            &token,
            None,
        )
        .await?;
        assert_eq!(status, StatusCode::NO_CONTENT, "{body}");
        network
            .enroll_fabric_host_transport_identity(&d_identity, None)
            .await?;

        // Restart only the compute execution process. Fabric remains assigned
        // to the same stable host and must continue to use the independent
        // network-agent identity and epoch.
        registry
            .register(&o3k_compute_agent::proto::RegisterRequest {
                agent_id: "compute-agent-d".to_owned(),
                agent_epoch: "compute-epoch-d-2".to_owned(),
                software_version: "http-fabric-test".to_owned(),
                host_label: "compute-d".to_owned(),
                supported_versions: vec![o3k_compute_agent::PROTOCOL_VERSION],
                capabilities: Some(o3k_compute_agent::proto::Capabilities::default()),
            })
            .await?;
        let plans_before_compute_restart = agent_d_plans
            .lock()
            .map_err(|_| "agent-d plan log poisoned")?
            .len();
        let (status, restart_port) = http_json(
            &app,
            Method::POST,
            "/v2.0/ports",
            &token,
            Some(create_port(format!("fabric-compute-restart-{run}"))),
        )
        .await?;
        assert_eq!(status, StatusCode::CREATED, "{restart_port}");
        let restart_port_id = restart_port["port"]["id"]
            .as_str()
            .ok_or("compute-restart port id")?
            .to_owned();
        let (status, restarted_server) = http_json(
            &app,
            Method::POST,
            "/v2.1/project-a/servers",
            &token,
            Some(serde_json::json!({"server":{"name":format!("fabric-compute-restart-server-{run}"),"image":{"id":"image-a"},"flavor":{"id":"00000000-0000-0000-0000-000000000001"},"networks":[{"port":restart_port_id}]}})),
        )
        .await?;
        assert_eq!(status, StatusCode::ACCEPTED, "{restarted_server}");
        let restarted_server_id = restarted_server["server"]["id"]
            .as_str()
            .ok_or("compute-restart server id")?
            .to_owned();
        tokio::time::timeout(std::time::Duration::from_secs(10), async {
            loop {
                let (status, body) = http_json(
                    &app,
                    Method::GET,
                    &format!("/v2.1/project-a/servers/{restarted_server_id}"),
                    &token,
                    None,
                )
                .await?;
                if status == StatusCode::OK && body["server"]["status"] == "ACTIVE" {
                    break Ok::<(), Box<dyn std::error::Error>>(());
                }
                tokio::time::sleep(std::time::Duration::from_millis(50)).await;
            }
        })
        .await
        .map_err(|_| "compute-agent restart did not complete HTTP server creation")??;
        let d_work = store.list_network_plan_work_history().await?;
        assert!(
            d_work.iter().any(|work| {
                work.target_host_id == "compute-d"
                    && work.target_agent_id == "network-agent-d"
                    && work.target_agent_epoch == "network-epoch-d"
            }),
            "Fabric work must retain the network-agent identity/epoch across compute-agent restart"
        );
        assert!(
            agent_d_plans
                .lock()
                .map_err(|_| "agent-d plan log poisoned")?
                .len()
                > plans_before_compute_restart,
            "the unchanged network agent must realize the endpoint after compute-agent restart"
        );
        let (status, body) = http_json(
            &app,
            Method::DELETE,
            &format!("/v2.1/project-a/servers/{restarted_server_id}"),
            &token,
            None,
        )
        .await?;
        assert!(
            status == StatusCode::ACCEPTED || status == StatusCode::NO_CONTENT,
            "{body}"
        );
        let (status, body) = http_json(
            &app,
            Method::DELETE,
            &format!("/v2.0/ports/{restart_port_id}"),
            &token,
            None,
        )
        .await?;
        assert!(
            status == StatusCode::NO_CONTENT || status == StatusCode::ACCEPTED,
            "{body}"
        );
        // Two current compute agents may not claim one stable host. The
        // scheduler can select the registered compute provider, but Fabric
        // must reject the ambiguous host join before binding or network-agent
        // dispatch.
        registry
            .register(&o3k_compute_agent::proto::RegisterRequest {
                agent_id: "compute-agent-d-shadow".to_owned(),
                agent_epoch: "compute-epoch-d-shadow".to_owned(),
                software_version: "http-fabric-test".to_owned(),
                host_label: "compute-d".to_owned(),
                supported_versions: vec![o3k_compute_agent::PROTOCOL_VERSION],
                capabilities: Some(o3k_compute_agent::proto::Capabilities::default()),
            })
            .await?;
        let plans_before_ambiguous_host = agent_d_plans
            .lock()
            .map_err(|_| "agent-d plan log poisoned")?
            .len();
        let (status, ambiguous_port) = http_json(
            &app,
            Method::POST,
            "/v2.0/ports",
            &token,
            Some(create_port(format!("fabric-ambiguous-host-{run}"))),
        )
        .await?;
        assert_eq!(status, StatusCode::CREATED, "{ambiguous_port}");
        let ambiguous_port_id = ambiguous_port["port"]["id"]
            .as_str()
            .ok_or("ambiguous-host port ID")?
            .to_owned();
        let (status, ambiguous_server) = http_json(
            &app,
            Method::POST,
            "/v2.1/project-a/servers",
            &token,
            Some(serde_json::json!({"server":{"name":format!("fabric-ambiguous-host-server-{run}"),"image":{"id":"image-a"},"flavor":{"id":"00000000-0000-0000-0000-000000000001"},"networks":[{"port":ambiguous_port_id}]}})),
        )
        .await?;
        assert_eq!(status, StatusCode::CONFLICT, "{ambiguous_server}");
        assert_eq!(
            agent_d_plans
                .lock()
                .map_err(|_| "agent-d plan log poisoned")?
                .len(),
            plans_before_ambiguous_host,
            "ambiguous host identity must fail before Fabric mutation"
        );
        let (status, unbound_port) = http_json(
            &app,
            Method::GET,
            &format!("/v2.0/ports/{ambiguous_port_id}"),
            &token,
            None,
        )
        .await?;
        assert_eq!(status, StatusCode::OK, "{unbound_port}");
        assert!(
            unbound_port["port"]["binding:host_id"].is_null(),
            "ambiguous host identity must fail before port binding"
        );
        let (status, body) = http_json(
            &app,
            Method::DELETE,
            &format!("/v2.0/ports/{ambiguous_port_id}"),
            &token,
            None,
        )
        .await?;
        assert_eq!(status, StatusCode::NO_CONTENT, "{body}");
        for agent in ["compute-agent-a", "compute-agent-b", "compute-agent-c"] {
            placement_for_negative_tests
                .set_state(agent, o3k_placement::ProviderState::Enabled)
                .await?;
        }
        let subnet_id = subnet_json["subnet"]["id"].as_str().ok_or("subnet id")?;
        // Endpoint departure has already removed every local provider owner.
        // Deleting the empty Realm must observe that durable history and must
        // not issue duplicate Remove mutations.
        let remove_counts_before_delete: BTreeMap<_, _> = removal_logs
            .iter()
            .map(|(agent, logs)| {
                Ok::<_, Box<dyn std::error::Error>>((
                    agent.clone(),
                    logs.lock().map_err(|_| "remove log poisoned")?.len(),
                ))
            })
            .collect::<Result<_, _>>()?;
        assert!(
            latest_realm_host_work(store.list_network_plan_work_history().await?, realm_id)?
                .values()
                .all(|work| !realm_host_may_still_own(work)),
            "all provider owners must have been observed absent before Realm deletion"
        );
        set_realm_delete_failpoint(
            store.as_ref(),
            &sqlite_path,
            realm_id,
            RealmDeleteFailpoint::Binding,
            true,
        )
        .await?;
        let (status, body) = http_json(
            &app,
            Method::DELETE,
            &format!("/v2.0/subnets/{subnet_id}"),
            &token,
            None,
        )
        .await?;
        assert_eq!(
            status,
            StatusCode::CONFLICT,
            "injected pre-binding failure must not report subnet DELETE success: {body}"
        );
        let deleting_realm = network
            .get_canonical_realm_for_project("project-a", realm_id)
            .await?;
        assert_eq!(
            deleting_realm.state, "deleting",
            "subnet DELETE conflict response did not leave the canonical Realm deleting: {body}"
        );
        assert!(
            store
                .get_canonical_realm_binding(&Uuid::from_u128(991).to_string(), &realm_id)
                .await?
                .is_some(),
            "VNI binding must remain when the deletion transaction is interrupted"
        );
        assert_eq!(
            store
                .list_canonical_pools("project-a", &realm_id)
                .await?
                .len(),
            1,
            "Realm pools must remain when the deletion transaction is interrupted"
        );
        // Fault after provider absence but before VNI binding removal. The
        // supported DELETE must leave the durable Realm/binding intact and a
        // retry must resume without issuing another provider mutation.
        assert!(
            store
                .get_canonical_realm_binding(&Uuid::from_u128(991).to_string(), &realm_id)
                .await?
                .is_some(),
            "binding must remain when its deletion transaction fails"
        );
        set_realm_delete_failpoint(
            store.as_ref(),
            &sqlite_path,
            realm_id,
            RealmDeleteFailpoint::Binding,
            false,
        )
        .await?;

        // Fault after the binding and pools have been removed but before the
        // canonical Realm row is finalized. Restart recovery must finish from
        // that durable intermediate state without recreating the VNI or
        // repeating provider Remove.
        set_realm_delete_failpoint(
            store.as_ref(),
            &sqlite_path,
            realm_id,
            RealmDeleteFailpoint::Finalize,
            true,
        )
        .await?;
        let (finalize_failure_status, finalize_failure_body) = http_json(
            &app,
            Method::DELETE,
            &format!("/v2.0/subnets/{subnet_id}"),
            &token,
            None,
        )
        .await?;
        assert_eq!(
            finalize_failure_status,
            StatusCode::CONFLICT,
            "injected post-binding crash must not return DELETE success: {finalize_failure_body}"
        );
        let binding_after_finalize_failure = store
            .get_canonical_realm_binding(&Uuid::from_u128(991).to_string(), &realm_id)
            .await?;
        assert!(
            binding_after_finalize_failure.is_none(),
            "binding deletion must remain committed before interrupted Realm finalization; binding={binding_after_finalize_failure:?}; response={finalize_failure_body}"
        );
        assert!(
            store
                .list_canonical_pools("project-a", &realm_id)
                .await?
                .is_empty(),
            "pool cleanup must remain committed before interrupted Realm finalization"
        );
        assert_eq!(
            network
                .get_canonical_realm_for_project("project-a", realm_id)
                .await?
                .state,
            "deleting",
            "interrupted Realm finalization must preserve deleting state"
        );
        set_realm_delete_failpoint(
            store.as_ref(),
            &sqlite_path,
            realm_id,
            RealmDeleteFailpoint::Finalize,
            false,
        )
        .await?;
        // Recreate the controller-side reconciler with a successor epoch while
        // keeping all three mTLS agents and their durable journals running.
        // No tenant mutation is issued to trigger deletion recovery.
        let mut restarted_dispatcher = (*dispatcher).clone();
        if let Some(control) = restarted_dispatcher.control.as_mut() {
            control.controller_id = o3k_store::ControllerId::new("http-fabric-controller-b");
            control.controller_epoch = o3k_store::ControllerEpoch::new("epoch-2");
        }
        let restarted_controller = o3k_network::NetworkControllerLease {
            controller_id: "http-fabric-controller-b".to_owned(),
            controller_epoch: "epoch-2".to_owned(),
            fencing_token: 2,
        };
        let restarted_reconciler = FabricRealmReconciler {
            network: network.clone(),
            coordination: coordination.clone(),
            durable: durable.clone(),
            registry: registry.clone(),
            dispatcher: Arc::new(restarted_dispatcher),
            controller: restarted_controller,
            fabric_domain_id: Uuid::from_u128(991),
            network_external_realm_id: None,
            public_allocator: None,
            reconciliation_locks: Arc::new(std::sync::Mutex::new(BTreeMap::new())),
        };
        tokio::time::timeout(std::time::Duration::from_secs(30), async {
            loop {
                recover_fabric_state(&restarted_reconciler, store.as_ref()).await;
                if store
                    .list_canonical_realms("project-a", &Uuid::parse_str(&network_id)?)
                    .await?
                    .is_empty()
                {
                    break Ok::<(), Box<dyn std::error::Error>>(());
                }
                tokio::time::sleep(std::time::Duration::from_millis(100)).await;
            }
        })
        .await
        .map_err(|_| "deleting AddressRealm did not finalize within 30 seconds")??;
        for (agent, logs) in &removal_logs {
            assert_eq!(
                logs.lock().map_err(|_| "remove log poisoned")?.len(),
                remove_counts_before_delete[agent],
                "Realm teardown must not repeat endpoint departure Remove mutations ({agent}); before={}",
                remove_counts_before_delete[agent]
            );
        }
        let (status, body) = http_json(
            &app,
            Method::GET,
            &format!("/v2.0/subnets/{subnet_id}"),
            &token,
            None,
        )
        .await?;
        assert_eq!(
            status,
            StatusCode::NOT_FOUND,
            "recovery should finalize deleted subnet: {body}"
        );
        let (status, body) = http_json(
            &app,
            Method::GET,
            &format!("/v2.0/networks/{network_id}"),
            &token,
            None,
        )
        .await?;
        assert_eq!(
            status,
            StatusCode::OK,
            "network survives subnet deletion: {body}"
        );
        assert!(
            store
                .list_canonical_realms("project-a", &Uuid::parse_str(&network_id)?)
                .await?
                .is_empty(),
            "AddressRealm must be absent after supported subnet deletion"
        );
        assert!(
            store
                .get_canonical_realm_binding(&Uuid::from_u128(991).to_string(), &realm_id)
                .await?
                .is_none(),
            "VNI binding must be released only after provider absence"
        );
        assert!(
            store
                .list_canonical_pools("project-a", &realm_id)
                .await?
                .is_empty(),
            "AddressRealm pools must be removed after provider absence"
        );
        assert!(
            store.list_unresolved_network_plan_work().await?.is_empty(),
            "successful Realm deletion must leave no unresolved Fabric cleanup work"
        );
        let (status, body) = http_json(
            &app,
            Method::DELETE,
            &format!("/v2.0/networks/{network_id}"),
            &token,
            None,
        )
        .await?;
        assert!(
            status == StatusCode::NO_CONTENT || status == StatusCode::ACCEPTED,
            "delete network: {status} {body}"
        );
        for task in server_tasks {
            task.abort();
        }
        for task in [create_reconciler, lifecycle_reconciler, orphan_reconciler] {
            task.abort();
        }
        let _ = std::fs::remove_dir_all(&root);
        Ok(())
    }

    fn dispatcher() -> NetworkAgentDispatcher {
        NetworkAgentDispatcher {
            legacy_target: None,
            control: None,
            control_lock: Arc::new(tokio::sync::Mutex::new(())),
            fabric_targets: BTreeMap::from([
                (
                    "compute-a".to_owned(),
                    NetworkAgentControlTarget {
                        host_id: "compute-a".to_owned(),
                        agent_id: "agent-a".to_owned(),
                        agent_epoch: "epoch-1".to_owned(),
                        endpoint: "https://10.0.0.1:7443".to_owned(),
                        tls_server_name: "compute-a.internal".to_owned(),
                    },
                ),
                (
                    "compute-b".to_owned(),
                    NetworkAgentControlTarget {
                        host_id: "compute-b".to_owned(),
                        agent_id: "agent-b".to_owned(),
                        agent_epoch: "epoch-1".to_owned(),
                        endpoint: "https://10.0.0.2:7443".to_owned(),
                        tls_server_name: "compute-b.internal".to_owned(),
                    },
                ),
            ]),
            ca_certificate: PathBuf::new(),
            client_certificate: PathBuf::new(),
            client_key: PathBuf::new(),
            pre_supersession_gate: None,
            supersession_gate: None,
            result_persistence_gate: None,
        }
    }

    fn command(agent_id: &str, host_id: &str) -> o3k_network::NetworkPlanCommand {
        o3k_network::NetworkPlanCommand {
            command_id: Uuid::now_v7(),
            operation_id: Uuid::now_v7(),
            idempotency_key: "dispatch-test".to_owned(),
            action: o3k_network::NetworkPlanAction::Apply,
            target: o3k_network::NetworkAgentIdentity {
                agent_id: agent_id.to_owned(),
                agent_epoch: "epoch-1".to_owned(),
            },
            controller: o3k_network::NetworkControllerLease {
                controller_id: "controller".to_owned(),
                controller_epoch: "epoch-1".to_owned(),
                fencing_token: 1,
            },
            deadline_unix_ms: u64::MAX,
            plan: o3k_network::NodeNetworkPlan {
                schema_version: o3k_network::NODE_NETWORK_PLAN_SCHEMA_VERSION,
                plan_id: Uuid::now_v7(),
                node_id: host_id.to_owned(),
                operation_id: Uuid::now_v7(),
                deadline_unix_ms: u64::MAX,
                resource_generations: BTreeMap::new(),
                intents: Vec::new(),
                fabric: None,
                gateway: None,
                fingerprint_sha256: String::new(),
            },
        }
    }

    fn fabric_command(agent_id: &str, host_id: &str) -> o3k_network::NetworkPlanCommand {
        let mut command = command(agent_id, host_id);
        let realm = o3k_domain::AddressRealm {
            id: Uuid::from_u128(800),
            network_id: Uuid::from_u128(801),
            project_id: "project-a".to_owned(),
            prefix: o3k_domain::Ipv4Prefix::new(std::net::Ipv4Addr::new(10, 80, 0, 0), 24)
                .expect("realm prefix"),
            overlapping_prefixes: false,
        };
        let directory = o3k_domain::RealmEndpointDirectory::build(
            &realm,
            vec![o3k_domain::EndpointLocation {
                endpoint_id: Uuid::from_u128(802),
                project_id: "project-a".to_owned(),
                realm_id: realm.id,
                fixed_ip: std::net::Ipv4Addr::new(10, 80, 0, 10),
                mac: "02:00:00:00:00:10".to_owned(),
                selected_host: host_id.to_owned(),
                endpoint_generation: 1,
                placement_generation: 1,
            }],
            &[],
            1,
        )
        .expect("directory");
        let identity = o3k_domain::FabricHostIdentity {
            host_id: host_id.to_owned(),
            public_key: "public-key".to_owned(),
            underlay_endpoint: "198.18.0.1:65001".to_owned(),
            fabric_transport_ip: std::net::Ipv4Addr::new(198, 18, 0, 1),
            provider_version: "0.1.5".to_owned(),
            fabric_generation: 1,
            underlay_mtu: 1500,
            fabric_mtu: 1440,
        };
        let binding = o3k_domain::RealmEncapsulationBinding {
            fabric_domain_id: Uuid::from_u128(803),
            realm_id: realm.id,
            provider_kind: o3k_domain::FabricProviderKind::Vxlan,
            provider_segment_id: 1001,
            binding_generation: 1,
        };
        command.plan.fabric = Some(
            directory
                .compile_fabric_plan(&identity, std::slice::from_ref(&identity), 1390, &binding)
                .expect("Fabric plan"),
        );
        command
    }

    fn host_work_record(
        mut command: o3k_network::NetworkPlanCommand,
        realm_generation: u64,
        state: o3k_store::NetworkPlanWorkState,
    ) -> o3k_store::NetworkPlanWorkRecord {
        command.plan.operation_id = command.operation_id;
        let realm_id = command
            .plan
            .fabric
            .as_ref()
            .expect("Fabric history fixture")
            .realm_id;
        command
            .plan
            .resource_generations
            .insert(realm_id, realm_generation);
        command.idempotency_key = format!("history:{}", command.command_id);
        o3k_store::NetworkPlanWorkRecord {
            command_id: command.command_id.to_string(),
            operation_id: command.operation_id,
            idempotency_key: command.idempotency_key.clone(),
            target_host_id: command.plan.node_id.clone(),
            target_agent_id: command.target.agent_id.clone(),
            target_agent_epoch: command.target.agent_epoch.clone(),
            controller_id: command.controller.controller_id.clone(),
            controller_epoch: command.controller.controller_epoch.clone(),
            fencing_token: command.controller.fencing_token,
            deadline_unix_ms: command.deadline_unix_ms,
            fingerprint_sha256: command.plan.fingerprint_sha256.clone(),
            snapshot: serde_json::to_vec(&command).expect("command fixture serializes"),
            state,
            revision: 0,
            outcome: None,
        }
    }

    #[test]
    fn latest_apply_after_successful_remove_restores_retirement_obligation() {
        let mut apply_g4 = fabric_command("agent-c", "compute-c");
        apply_g4.action = o3k_network::NetworkPlanAction::Apply;
        let mut remove_g5 = fabric_command("agent-c", "compute-c");
        remove_g5.action = o3k_network::NetworkPlanAction::Remove;
        let mut apply_g6 = fabric_command("agent-c", "compute-c");
        apply_g6.action = o3k_network::NetworkPlanAction::Apply;
        let realm_id = apply_g4
            .plan
            .fabric
            .as_ref()
            .expect("Fabric fixture")
            .realm_id;

        let latest = latest_realm_host_work(
            vec![
                host_work_record(apply_g4, 4, o3k_store::NetworkPlanWorkState::Succeeded),
                host_work_record(
                    remove_g5.clone(),
                    5,
                    o3k_store::NetworkPlanWorkState::Succeeded,
                ),
                host_work_record(apply_g6, 6, o3k_store::NetworkPlanWorkState::Succeeded),
            ],
            realm_id,
        )
        .expect("durable host history parses");
        let c_latest = latest.get("compute-c").expect("host C history");
        assert_eq!(
            c_latest.command.action,
            o3k_network::NetworkPlanAction::Apply
        );
        assert!(realm_host_may_still_own(c_latest));

        let removed = latest_realm_host_work(
            vec![host_work_record(
                remove_g5,
                5,
                o3k_store::NetworkPlanWorkState::Succeeded,
            )],
            realm_id,
        )
        .expect("Remove history parses");
        assert!(!realm_host_may_still_own(
            removed.get("compute-c").expect("host C removal")
        ));
    }

    #[derive(Clone, Default)]
    struct MtlSRecoveryRealizer {
        removals: Arc<std::sync::atomic::AtomicUsize>,
        realizations: Arc<std::sync::atomic::AtomicUsize>,
        unknown_remove: bool,
    }

    impl o3k_network::NetworkPlanRealizer for MtlSRecoveryRealizer {
        type Error = String;

        fn realize(&mut self, _plan: &o3k_network::NodeNetworkPlan) -> Result<(), Self::Error> {
            self.realizations
                .fetch_add(1, std::sync::atomic::Ordering::AcqRel);
            Ok(())
        }

        fn remove(&mut self, _plan: &o3k_network::NodeNetworkPlan) -> Result<(), Self::Error> {
            self.removals
                .fetch_add(1, std::sync::atomic::Ordering::AcqRel);
            if self.unknown_remove {
                Err("controlled ambiguous remove outcome".to_owned())
            } else {
                Ok(())
            }
        }

        fn observe(&mut self, _plan: &o3k_network::NodeNetworkPlan) -> Result<bool, Self::Error> {
            Ok(false)
        }

        fn observe_removed(
            &mut self,
            _plan: &o3k_network::NodeNetworkPlan,
        ) -> Result<bool, Self::Error> {
            Ok(!self.unknown_remove)
        }
    }

    #[derive(Clone)]
    struct BlockingMtlSRecoveryRealizer {
        entered: Arc<tokio::sync::Notify>,
        released: Arc<(std::sync::Mutex<bool>, std::sync::Condvar)>,
        removals: Arc<std::sync::atomic::AtomicUsize>,
    }

    impl o3k_network::NetworkPlanRealizer for BlockingMtlSRecoveryRealizer {
        type Error = String;

        fn realize(&mut self, _plan: &o3k_network::NodeNetworkPlan) -> Result<(), Self::Error> {
            Ok(())
        }

        fn remove(&mut self, _plan: &o3k_network::NodeNetworkPlan) -> Result<(), Self::Error> {
            self.removals
                .fetch_add(1, std::sync::atomic::Ordering::AcqRel);
            self.entered.notify_one();
            let (released, wake) = &*self.released;
            let mut released = released.lock().map_err(|_| "release lock poisoned")?;
            while !*released {
                released = wake.wait(released).map_err(|_| "release lock poisoned")?;
            }
            Ok(())
        }

        fn observe(&mut self, _plan: &o3k_network::NodeNetworkPlan) -> Result<bool, Self::Error> {
            Ok(false)
        }

        fn observe_removed(
            &mut self,
            _plan: &o3k_network::NodeNetworkPlan,
        ) -> Result<bool, Self::Error> {
            Ok(true)
        }
    }

    fn network_fixture(name: &str) -> PathBuf {
        PathBuf::from(env!("CARGO_MANIFEST_DIR"))
            .join("../../crates/o3k-compute-agent/tests/fixtures")
            .join(name)
    }

    #[derive(Clone, Copy)]
    enum RealmDeleteFailpoint {
        Binding,
        Finalize,
    }

    async fn set_realm_delete_failpoint(
        store: &o3k_store::unified::O3kStore,
        sqlite_path: &std::path::Path,
        realm_id: Uuid,
        failpoint: RealmDeleteFailpoint,
        enabled: bool,
    ) -> Result<(), Box<dyn std::error::Error>> {
        let (trigger, table, column, function) = match failpoint {
            RealmDeleteFailpoint::Binding => (
                "o3k_test_block_realm_binding_delete",
                "canonical_realm_encapsulation_bindings",
                "realm_id",
                "o3k_test_block_realm_binding_delete_fn",
            ),
            RealmDeleteFailpoint::Finalize => (
                "o3k_test_block_realm_finalize",
                "canonical_address_realms",
                "id",
                "o3k_test_block_realm_finalize_fn",
            ),
        };
        let realm_id = realm_id.to_string();
        match store {
            o3k_store::unified::O3kStore::Postgres(postgres) => {
                let pool = postgres.pool();
                if enabled {
                    sqlx::query(&format!("DROP TRIGGER IF EXISTS {trigger} ON {table}"))
                        .execute(pool)
                        .await?;
                    sqlx::query(&format!(
                        "CREATE OR REPLACE FUNCTION {function}() RETURNS trigger LANGUAGE plpgsql AS $$ BEGIN IF OLD.{column} = TG_ARGV[0] THEN RAISE EXCEPTION 'injected AddressRealm deletion interruption'; END IF; RETURN OLD; END $$"
                    ))
                    .execute(pool)
                    .await?;
                    sqlx::query(&format!(
                        "CREATE TRIGGER {trigger} BEFORE DELETE ON {table} FOR EACH ROW EXECUTE FUNCTION {function}('{realm_id}')"
                    ))
                    .execute(pool)
                    .await?;
                } else {
                    sqlx::query(&format!("DROP TRIGGER IF EXISTS {trigger} ON {table}"))
                        .execute(pool)
                        .await?;
                    sqlx::query(&format!("DROP FUNCTION IF EXISTS {function}()"))
                        .execute(pool)
                        .await?;
                }
            }
            o3k_store::unified::O3kStore::Sqlite(_) => {
                let sqlite_url = format!("sqlite://{}", sqlite_path.display());
                let pool = sqlx::SqlitePool::connect(&sqlite_url).await?;
                if enabled {
                    sqlx::query(&format!(
                        "CREATE TRIGGER {trigger} BEFORE DELETE ON {table} WHEN OLD.{column} = '{realm_id}' BEGIN SELECT RAISE(ABORT, 'injected AddressRealm deletion interruption'); END"
                    ))
                    .execute(&pool)
                    .await?;
                } else {
                    sqlx::query(&format!("DROP TRIGGER IF EXISTS {trigger}"))
                        .execute(&pool)
                        .await?;
                }
                pool.close().await;
            }
        }
        Ok(())
    }

    async fn start_mtls_network_agent<R>(
        listener: tokio::net::TcpListener,
        service: o3k_network_bin::agent::NetworkAgentService<R>,
    ) -> Result<
        tokio::task::JoinHandle<Result<(), tonic::transport::Error>>,
        Box<dyn std::error::Error>,
    >
    where
        R: o3k_network::NetworkPlanRealizer + Send + 'static,
        R::Error: std::fmt::Display,
    {
        let tls = o3k_service_sdk::tls::server(
            network_fixture("ca.pem"),
            network_fixture("server-chain.pem"),
            network_fixture("server-key.pem"),
        )?;
        Ok(tokio::spawn(async move {
            Server::builder()
                .tls_config(tls)
                .expect("test mTLS configuration")
                .add_service(
                    o3k_network_bin::agent::proto::network_agent_server::NetworkAgentServer::new(
                        service,
                    ),
                )
                .serve_with_incoming(TcpListenerStream::new(listener))
                .await
        }))
    }

    fn mtls_dispatcher(
        address: std::net::SocketAddr,
        store: Arc<o3k_store::unified::O3kStore>,
        supersession_gate: Option<(Arc<tokio::sync::Notify>, Arc<tokio::sync::Notify>)>,
    ) -> NetworkAgentDispatcher {
        mtls_dispatcher_as(address, store, "controller", "epoch-1", supersession_gate)
    }

    fn mtls_dispatcher_as(
        address: std::net::SocketAddr,
        store: Arc<o3k_store::unified::O3kStore>,
        controller_id: &str,
        controller_epoch: &str,
        supersession_gate: Option<(Arc<tokio::sync::Notify>, Arc<tokio::sync::Notify>)>,
    ) -> NetworkAgentDispatcher {
        let durable: Arc<dyn DurableStore> = store.clone();
        let coordination: Arc<dyn CoordinationRepository> = store;
        NetworkAgentDispatcher {
            legacy_target: None,
            fabric_targets: BTreeMap::from([(
                "compute-c".to_owned(),
                NetworkAgentControlTarget {
                    host_id: "compute-c".to_owned(),
                    agent_id: "agent-c".to_owned(),
                    agent_epoch: "epoch-1".to_owned(),
                    endpoint: format!("https://{address}"),
                    tls_server_name: "o3k-control-plane".to_owned(),
                },
            )]),
            control: Some(NetworkAgentControlLease {
                coordination,
                durable,
                controller_id: o3k_store::ControllerId::new(controller_id),
                controller_epoch: o3k_store::ControllerEpoch::new(controller_epoch),
            }),
            control_lock: Arc::new(tokio::sync::Mutex::new(())),
            ca_certificate: network_fixture("ca.pem"),
            client_certificate: network_fixture("agent-chain.pem"),
            client_key: network_fixture("agent-key-pkcs8.pem"),
            pre_supersession_gate: None,
            supersession_gate,
            result_persistence_gate: None,
        }
    }

    async fn durable_removal_command(
        store: &o3k_store::unified::O3kStore,
    ) -> Result<o3k_store::NetworkPlanWorkRecord, Box<dyn std::error::Error>> {
        let realm_id = Uuid::from_u128(800);
        let controller_id = o3k_store::ControllerId::new("controller");
        let controller_epoch = o3k_store::ControllerEpoch::new("epoch-1");
        let realm_key = format!("fabric-realm:{realm_id}");
        let lease = match store
            .acquire_work_lease(
                &realm_key,
                "fabric_reconciliation",
                &controller_id,
                &controller_epoch,
                FABRIC_REALM_LEASE_TTL,
            )
            .await?
        {
            o3k_store::LeaseAcquireOutcome::Acquired { lease } => lease,
            o3k_store::LeaseAcquireOutcome::Busy { .. } => {
                return Err("test realm unexpectedly busy".into());
            }
        };
        let mut old = fabric_command("agent-c", "compute-c");
        old.action = o3k_network::NetworkPlanAction::Remove;
        old.idempotency_key = format!("test-remove:{}", old.command_id);
        old.deadline_unix_ms = super::super::unix_time_millis().saturating_add(60_000);
        old.plan.operation_id = old.operation_id;
        old.plan.deadline_unix_ms = old.deadline_unix_ms;
        old.plan.fingerprint_sha256 = o3k_network::canonical_plan_fingerprint(&old.plan)?;
        let work = o3k_store::NetworkPlanWorkRecord {
            command_id: old.command_id.to_string(),
            operation_id: old.operation_id,
            idempotency_key: old.idempotency_key.clone(),
            target_host_id: old.plan.node_id.clone(),
            target_agent_id: old.target.agent_id.clone(),
            target_agent_epoch: old.target.agent_epoch.clone(),
            controller_id: controller_id.0.clone(),
            controller_epoch: controller_epoch.0.clone(),
            fencing_token: lease.fencing_token,
            deadline_unix_ms: old.deadline_unix_ms,
            fingerprint_sha256: old.plan.fingerprint_sha256.clone(),
            snapshot: serde_json::to_vec(&old)?,
            state: o3k_store::NetworkPlanWorkState::Pending,
            revision: 0,
            outcome: None,
        };
        store
            .insert_network_plan_work_under_lease(
                &realm_key,
                &controller_id.0,
                &controller_epoch.0,
                lease.fencing_token,
                &work,
            )
            .await?;
        let running = store
            .update_network_plan_work_under_lease(
                &realm_key,
                &controller_id.0,
                &controller_epoch.0,
                lease.fencing_token,
                &work.command_id,
                0,
                o3k_store::NetworkPlanWorkState::Running,
                None,
            )
            .await?;
        if !store
            .relinquish_work_lease_preserving_fence(
                &realm_key,
                &controller_id,
                &controller_epoch,
                lease.fencing_token,
            )
            .await?
        {
            return Err("test realm lease relinquishment failed".into());
        }
        Ok(running)
    }

    #[tokio::test]
    async fn target_aware_dispatch_resolves_each_host_independently() {
        let dispatcher = dispatcher();
        let a = dispatcher
            .transport_for(&fabric_command("agent-a", "compute-a"))
            .expect("host A target");
        let b = dispatcher
            .transport_for(&fabric_command("agent-b", "compute-b"))
            .expect("host B target");
        assert_eq!(a.endpoint, "https://10.0.0.1:7443");
        assert_eq!(b.endpoint, "https://10.0.0.2:7443");
        assert_ne!(a.server_name, b.server_name);
        let target = dispatcher
            .target_for_host("compute-a")
            .await
            .expect("host target lookup")
            .expect("registered target");
        assert_eq!(target.agent_id, "agent-a");
        assert_eq!(target.agent_epoch, "epoch-1");
    }

    #[test]
    fn target_aware_dispatch_rejects_unknown_or_mismatched_hosts() {
        let dispatcher = dispatcher();
        assert!(
            dispatcher
                .transport_for(&fabric_command("agent-b", "compute-a"))
                .is_err()
        );
        assert!(
            dispatcher
                .transport_for(&fabric_command("unregistered", "compute-c"))
                .is_err()
        );
        let mut stale_network_epoch = fabric_command("agent-a", "compute-a");
        stale_network_epoch.target.agent_epoch = "network-epoch-stale".to_owned();
        assert!(
            dispatcher.transport_for(&stale_network_epoch).is_err(),
            "network target epoch mismatch must fail independently of compute epoch"
        );
    }

    #[tokio::test]
    async fn network_agent_epoch_rotation_is_independent_of_compute_identity() {
        let mut dispatcher = dispatcher();
        dispatcher
            .fabric_targets
            .get_mut("compute-a")
            .expect("host A target")
            .agent_epoch = "network-epoch-2".to_owned();

        let current = dispatcher
            .target_for_host("compute-a")
            .await
            .expect("host target lookup")
            .expect("registered target");
        assert_eq!(current.agent_id, "agent-a");
        assert_eq!(current.agent_epoch, "network-epoch-2");

        let stale = fabric_command("agent-a", "compute-a");
        assert!(
            dispatcher.transport_for(&stale).is_err(),
            "a command fenced to the old network-agent epoch must not be replayed to its successor"
        );

        let mut successor = fabric_command("agent-a", "compute-a");
        successor.target.agent_epoch = "network-epoch-2".to_owned();
        assert_eq!(
            dispatcher
                .transport_for(&successor)
                .expect("current network epoch")
                .endpoint,
            "https://10.0.0.1:7443"
        );
        // Compute identity is intentionally absent from this mapping: rotating
        // the network process epoch cannot rewrite host placement or the
        // independently fenced compute command identity.
        assert_eq!(successor.plan.node_id, "compute-a");
    }

    #[derive(Default)]
    struct RecordingDispatcher {
        commands: Mutex<Vec<o3k_network::NetworkPlanCommand>>,
        unavailable_hosts: Mutex<BTreeSet<String>>,
        not_found: Mutex<BTreeSet<String>>,
        durable: Mutex<Option<Arc<dyn o3k_store::DurableStore>>>,
        coordination: Mutex<Option<Arc<dyn o3k_store::CoordinationRepository>>>,
        commit_only: std::sync::atomic::AtomicBool,
        last_successor: Mutex<Option<String>>,
        provider_mutations: std::sync::atomic::AtomicUsize,
    }

    #[async_trait]
    impl o3k_network::NetworkPlanDispatcher for RecordingDispatcher {
        async fn target_for_host(
            &self,
            host_id: &str,
        ) -> Result<Option<o3k_network::NetworkAgentIdentity>, o3k_network::NetworkDispatchError>
        {
            if self
                .unavailable_hosts
                .lock()
                .map_err(|_| o3k_network::NetworkDispatchError::Unavailable)?
                .contains(host_id)
            {
                return Ok(None);
            }
            let suffix = host_id.strip_prefix("compute-").ok_or_else(|| {
                o3k_network::NetworkDispatchError::Rejected("unknown test host".to_owned())
            })?;
            Ok(Some(o3k_network::NetworkAgentIdentity {
                agent_id: format!("agent-{suffix}"),
                agent_epoch: "network-epoch-1".to_owned(),
            }))
        }

        fn configured_target_hosts(&self) -> Vec<String> {
            vec![
                "compute-a".to_owned(),
                "compute-b".to_owned(),
                "compute-c".to_owned(),
            ]
        }

        async fn dispatch(
            &self,
            command: o3k_network::NetworkPlanCommand,
        ) -> Result<o3k_network::NetworkPlanStatus, o3k_network::NetworkDispatchError> {
            self.commands
                .lock()
                .map_err(|_| o3k_network::NetworkDispatchError::Rejected("poisoned".to_owned()))?
                .push(command);
            Ok(o3k_network::NetworkPlanStatus::Succeeded)
        }

        async fn dispatch_superseding(
            &self,
            mut command: o3k_network::NetworkPlanCommand,
            historical_command_id: String,
            historical_revision: u64,
        ) -> Result<o3k_network::NetworkPlanStatus, o3k_network::NetworkDispatchError> {
            let realm_id = command
                .plan
                .fabric
                .as_ref()
                .map(|fabric| fabric.realm_id)
                .ok_or_else(|| {
                    o3k_network::NetworkDispatchError::Rejected("missing realm".into())
                })?;
            let coordination = self
                .coordination
                .lock()
                .map_err(|_| o3k_network::NetworkDispatchError::Unavailable)?
                .clone()
                .ok_or(o3k_network::NetworkDispatchError::Unavailable)?;
            let durable = self
                .durable
                .lock()
                .map_err(|_| o3k_network::NetworkDispatchError::Unavailable)?
                .clone()
                .ok_or(o3k_network::NetworkDispatchError::Unavailable)?;
            let key = format!("fabric-realm:{realm_id}");
            let lease = coordination
                .inspect_work_lease(&key)
                .await
                .map_err(|_| o3k_network::NetworkDispatchError::Unavailable)?
                .ok_or(o3k_network::NetworkDispatchError::Unavailable)?;
            let old_id = Uuid::parse_str(&historical_command_id)
                .map_err(|_| o3k_network::NetworkDispatchError::Rejected("bad old id".into()))?;
            command.command_id = Uuid::new_v5(
                &old_id,
                format!("test-successor:{}", command.plan.fingerprint_sha256).as_bytes(),
            );
            command.controller = o3k_network::NetworkControllerLease {
                controller_id: lease.owner_controller_id.to_string(),
                controller_epoch: lease.owner_controller_epoch.to_string(),
                fencing_token: lease.fencing_token,
            };
            let successor = o3k_store::NetworkPlanWorkRecord {
                command_id: command.command_id.to_string(),
                operation_id: command.operation_id,
                idempotency_key: format!(
                    "{}:successor-of:{historical_command_id}:agent-epoch:{}",
                    command.idempotency_key, command.target.agent_epoch
                ),
                target_host_id: command.plan.node_id.clone(),
                target_agent_id: command.target.agent_id.clone(),
                target_agent_epoch: command.target.agent_epoch.clone(),
                controller_id: lease.owner_controller_id.to_string(),
                controller_epoch: lease.owner_controller_epoch.to_string(),
                fencing_token: lease.fencing_token,
                deadline_unix_ms: command.deadline_unix_ms,
                fingerprint_sha256: command.plan.fingerprint_sha256.clone(),
                snapshot: serde_json::to_vec(&command).map_err(|error| {
                    o3k_network::NetworkDispatchError::Rejected(error.to_string())
                })?,
                state: o3k_store::NetworkPlanWorkState::Pending,
                revision: 0,
                outcome: None,
            };
            durable
                .supersede_network_plan_work_under_lease(
                    &key,
                    &lease.owner_controller_id.0,
                    &lease.owner_controller_epoch.0,
                    lease.fencing_token,
                    &historical_command_id,
                    historical_revision,
                    &successor,
                )
                .await
                .map_err(|error| o3k_network::NetworkDispatchError::Rejected(error.to_string()))?;
            *self
                .last_successor
                .lock()
                .map_err(|_| o3k_network::NetworkDispatchError::Unavailable)? =
                Some(successor.command_id.clone());
            if self
                .commit_only
                .swap(false, std::sync::atomic::Ordering::AcqRel)
            {
                return Err(o3k_network::NetworkDispatchError::Transport(
                    "injected crash after atomic supersession commit".to_owned(),
                ));
            }
            let running = durable
                .update_network_plan_work_under_lease(
                    &key,
                    &lease.owner_controller_id.0,
                    &lease.owner_controller_epoch.0,
                    lease.fencing_token,
                    &successor.command_id,
                    0,
                    o3k_store::NetworkPlanWorkState::Running,
                    None,
                )
                .await
                .map_err(|error| o3k_network::NetworkDispatchError::Rejected(error.to_string()))?;
            durable
                .update_network_plan_work_under_lease(
                    &key,
                    &lease.owner_controller_id.0,
                    &lease.owner_controller_epoch.0,
                    lease.fencing_token,
                    &successor.command_id,
                    running.revision,
                    o3k_store::NetworkPlanWorkState::Succeeded,
                    Some(b"test observed success"),
                )
                .await
                .map_err(|error| o3k_network::NetworkDispatchError::Rejected(error.to_string()))?;
            self.commands
                .lock()
                .map_err(|_| o3k_network::NetworkDispatchError::Unavailable)?
                .push(command);
            self.provider_mutations
                .fetch_add(1, std::sync::atomic::Ordering::AcqRel);
            Ok(o3k_network::NetworkPlanStatus::Succeeded)
        }

        async fn dispatch_existing_successor(
            &self,
            mut command: o3k_network::NetworkPlanCommand,
            successor_command_id: String,
        ) -> Result<o3k_network::NetworkPlanStatus, o3k_network::NetworkDispatchError> {
            let realm_id = command
                .plan
                .fabric
                .as_ref()
                .map(|fabric| fabric.realm_id)
                .ok_or_else(|| {
                    o3k_network::NetworkDispatchError::Rejected("missing realm".to_owned())
                })?;
            let coordination = self
                .coordination
                .lock()
                .map_err(|_| o3k_network::NetworkDispatchError::Unavailable)?
                .clone()
                .ok_or(o3k_network::NetworkDispatchError::Unavailable)?;
            let lease = coordination
                .inspect_work_lease(&format!("fabric-realm:{realm_id}"))
                .await
                .map_err(|_| o3k_network::NetworkDispatchError::Unavailable)?
                .ok_or(o3k_network::NetworkDispatchError::Unavailable)?;
            command.controller = o3k_network::NetworkControllerLease {
                controller_id: lease.owner_controller_id.to_string(),
                controller_epoch: lease.owner_controller_epoch.to_string(),
                fencing_token: lease.fencing_token,
            };
            let durable = self
                .durable
                .lock()
                .map_err(|_| o3k_network::NetworkDispatchError::Unavailable)?
                .clone()
                .ok_or(o3k_network::NetworkDispatchError::Unavailable)?;
            let record = durable
                .get_network_plan_work(&successor_command_id)
                .await
                .map_err(|_| o3k_network::NetworkDispatchError::Unavailable)?;
            command.command_id = Uuid::parse_str(&successor_command_id).map_err(|_| {
                o3k_network::NetworkDispatchError::Rejected("bad successor id".to_owned())
            })?;
            if record.state == o3k_store::NetworkPlanWorkState::Succeeded {
                return Ok(o3k_network::NetworkPlanStatus::Succeeded);
            }
            if record.state != o3k_store::NetworkPlanWorkState::Pending {
                return Err(o3k_network::NetworkDispatchError::Unavailable);
            }
            let running = durable
                .update_network_plan_work_under_lease(
                    &format!("fabric-realm:{realm_id}"),
                    &lease.owner_controller_id.0,
                    &lease.owner_controller_epoch.0,
                    command.controller.fencing_token,
                    &successor_command_id,
                    record.revision,
                    o3k_store::NetworkPlanWorkState::Running,
                    None,
                )
                .await
                .map_err(|_| o3k_network::NetworkDispatchError::Unavailable)?;
            durable
                .update_network_plan_work_under_lease(
                    &format!("fabric-realm:{realm_id}"),
                    &lease.owner_controller_id.0,
                    &lease.owner_controller_epoch.0,
                    command.controller.fencing_token,
                    &successor_command_id,
                    running.revision,
                    o3k_store::NetworkPlanWorkState::Succeeded,
                    Some(b"test observed success"),
                )
                .await
                .map_err(|_| o3k_network::NetworkDispatchError::Unavailable)?;
            self.commands
                .lock()
                .map_err(|_| o3k_network::NetworkDispatchError::Unavailable)?
                .push(command);
            self.provider_mutations
                .fetch_add(1, std::sync::atomic::Ordering::AcqRel);
            Ok(o3k_network::NetworkPlanStatus::Succeeded)
        }

        async fn observe_command(
            &self,
            _target_host_id: &str,
            _target: o3k_network::NetworkAgentIdentity,
            command_id: Uuid,
        ) -> Result<Option<o3k_network::NetworkPlanStatus>, o3k_network::NetworkDispatchError>
        {
            if self
                .not_found
                .lock()
                .map_err(|_| o3k_network::NetworkDispatchError::Unavailable)?
                .contains(&command_id.to_string())
            {
                Ok(None)
            } else {
                Ok(Some(o3k_network::NetworkPlanStatus::Succeeded))
            }
        }
    }

    fn host_identity(
        host_id: &str,
        agent_id: &str,
        public_key: &str,
        octet: u8,
    ) -> o3k_store::FabricHostTransportIdentityRecord {
        o3k_store::FabricHostTransportIdentityRecord {
            host_id: host_id.to_owned(),
            agent_id: agent_id.to_owned(),
            public_key: public_key.to_owned(),
            underlay_endpoint: format!("192.0.2.{octet}:65001"),
            fabric_transport_ip: std::net::Ipv4Addr::new(198, 18, 0, octet),
            provider_version: "0.1.5".to_owned(),
            fabric_generation: 1,
            underlay_mtu: 1500,
            fabric_mtu: 1440,
            administrative_state: "enabled".to_owned(),
        }
    }

    #[tokio::test]
    async fn canonical_network_lifecycle_derives_and_dispatches_three_host_her()
    -> Result<(), Box<dyn std::error::Error>> {
        let root = std::env::temp_dir().join(format!("o3kd-fabric-reconcile-{}", Uuid::now_v7()));
        std::fs::create_dir_all(&root)?;
        let store = Arc::new(o3k_store::testkit::open_memory().await?);
        let repository: Arc<dyn o3k_store::NetworkRepository> = store.clone();
        let network =
            o3k_network::NetworkService::open_for_test(root.join("network"), repository).await?;
        let network_record = network
            .create_network_for_project("project-a", "tenant-a".to_owned())
            .await?;
        let subnet = network
            .create_subnet_for_project(
                "project-a",
                network_record.id,
                "tenant-a-subnet".to_owned(),
                "10.90.0.0/24".to_owned(),
                None,
                None,
                None,
            )
            .await?;
        let endpoints = [
            (
                "compute-a",
                "agent-a",
                "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA=",
                1_u8,
            ),
            (
                "compute-b",
                "agent-b",
                "AQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQE=",
                2_u8,
            ),
            (
                "compute-c",
                "agent-c",
                "AgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgI=",
                3_u8,
            ),
        ];
        let registry = Arc::new(o3k_compute_agent::NodeRegistry::default());
        for (host_id, agent_id, public_key, octet) in endpoints.iter().copied() {
            network
                .enroll_fabric_host_transport_identity(
                    &host_identity(host_id, agent_id, public_key, octet),
                    None,
                )
                .await?;
            registry
                .register(&o3k_compute_agent::proto::RegisterRequest {
                    agent_id: agent_id.to_owned(),
                    agent_epoch: "epoch-1".to_owned(),
                    software_version: "test".to_owned(),
                    host_label: host_id.to_owned(),
                    supported_versions: vec![o3k_compute_agent::PROTOCOL_VERSION],
                    capabilities: Some(o3k_compute_agent::proto::Capabilities::default()),
                })
                .await?;
        }
        let dispatcher = Arc::new(RecordingDispatcher::default());
        *dispatcher
            .durable
            .lock()
            .map_err(|_| "recording durable lock poisoned")? = Some(store.clone());
        let coordination: Arc<dyn o3k_store::CoordinationRepository> = store.clone();
        *dispatcher
            .coordination
            .lock()
            .map_err(|_| "recording coordination lock poisoned")? = Some(coordination);
        let reconciler = FabricRealmReconciler {
            network: network.clone(),
            coordination: store.clone(),
            durable: store.clone(),
            registry,
            dispatcher: dispatcher.clone(),
            controller: o3k_network::NetworkControllerLease {
                controller_id: "controller".to_owned(),
                controller_epoch: "epoch-1".to_owned(),
                fencing_token: 1,
            },
            fabric_domain_id: Uuid::from_u128(990),
            network_external_realm_id: None,
            public_allocator: None,
            reconciliation_locks: Arc::new(std::sync::Mutex::new(BTreeMap::new())),
        };
        let mut port_by_host = BTreeMap::new();
        for (index, (host_id, _network_agent_id, _, _)) in endpoints.iter().copied().enumerate() {
            let port = network
                .create_port_for_project("project-a", network_record.id, format!("port-{host_id}"))
                .await?;
            assert_eq!(port.subnet_id, Some(subnet.id));
            network
                .record_fabric_binding_intent("project-a", port.id, host_id)
                .await?;
            port_by_host.insert(host_id.to_owned(), port.id);
            reconciler
                .reconcile_realm(
                    "project-a",
                    network_record.id,
                    Uuid::from_u128(991 + index as u128),
                    crate::composition::unix_time_millis().saturating_add(30_000),
                )
                .await?;
        }
        {
            let commands = dispatcher
                .commands
                .lock()
                .map_err(|_| "recording dispatcher poisoned")?;
            assert_eq!(commands.len(), 6);
            for (expected_entries, commands_for_addition) in [
                (1, &commands[0..1]),
                (2, &commands[1..3]),
                (3, &commands[3..6]),
            ] {
                let mut addition_hosts = std::collections::BTreeSet::new();
                for command in commands_for_addition {
                    let fabric = command
                        .plan
                        .fabric
                        .as_ref()
                        .ok_or("missing Fabric v3 plan")?;
                    let dhcp = fabric.dhcp.ok_or("missing canonical DHCP intent")?;
                    assert!(dhcp.enabled, "created DHCP-enabled subnet must propagate");
                    assert_eq!(dhcp.gateway, subnet.gateway_ip);
                    assert_eq!(command.plan.node_id, fabric.local_host);
                    assert_eq!(fabric.directory.entries.len(), expected_entries);
                    assert_eq!(fabric.peers.len(), expected_entries - 1);
                    addition_hosts.insert(fabric.local_host.clone());
                }
                let expected = endpoints[..expected_entries]
                    .iter()
                    .map(|(host_id, _, _, _)| (*host_id).to_owned())
                    .collect::<std::collections::BTreeSet<_>>();
                assert_eq!(addition_hosts, expected);
            }
        }

        // A second endpoint on C keeps C in Realm membership when only the
        // first endpoint departs. The host-level Remove is required only
        // after C's final endpoint leaves.
        let c_second_port = network
            .create_port_for_project(
                "project-a",
                network_record.id,
                "port-compute-c-second".to_owned(),
            )
            .await?;
        network
            .record_fabric_binding_intent("project-a", c_second_port.id, "compute-c")
            .await?;
        reconciler
            .reconcile_realm(
                "project-a",
                network_record.id,
                Uuid::from_u128(994),
                crate::composition::unix_time_millis().saturating_add(30_000),
            )
            .await?;
        let c_first_port = port_by_host["compute-c"];
        network
            .advance_fabric_realm_generation("project-a", network_record.id)
            .await?;
        network
            .project_binding_observation("project-a", c_first_port, "compute-c", "down")
            .await?;
        reconciler
            .reconcile_realm(
                "project-a",
                network_record.id,
                Uuid::from_u128(995),
                crate::composition::unix_time_millis().saturating_add(30_000),
            )
            .await?;
        assert!(
            !dispatcher
                .commands
                .lock()
                .map_err(|_| "recording dispatcher poisoned")?
                .iter()
                .any(|command| {
                    command.plan.node_id == "compute-c"
                        && command.action == o3k_network::NetworkPlanAction::Remove
                }),
            "removing one endpoint must not remove C while C2 remains bound"
        );
        let latest_c_apply = dispatcher
            .commands
            .lock()
            .map_err(|_| "recording dispatcher poisoned")?
            .iter()
            .rev()
            .find(|command| command.plan.node_id == "compute-c")
            .cloned()
            .ok_or("C Apply after one endpoint departure")?;
        assert_eq!(latest_c_apply.action, o3k_network::NetworkPlanAction::Apply);
        assert_eq!(
            latest_c_apply
                .plan
                .fabric
                .as_ref()
                .ok_or("C Fabric plan")?
                .directory
                .entries
                .len(),
            3,
            "C remains a participant while its second endpoint is active"
        );
        network.unbind_port("project-a", c_first_port).await?;

        // Seed the fake dispatcher with the durable ownership history the
        // production dispatcher writes on successful Apply. Retirement must
        // be derivable from this journal alone after canonical C is down.
        let realm_key = format!("fabric-realm:{}", subnet.id);
        let controller_id = o3k_store::ControllerId::new("controller");
        let controller_epoch = o3k_store::ControllerEpoch::new("epoch-1");
        let lease = match store
            .acquire_work_lease(
                &realm_key,
                "fabric_reconciliation",
                &controller_id,
                &controller_epoch,
                FABRIC_REALM_LEASE_TTL,
            )
            .await?
        {
            o3k_store::LeaseAcquireOutcome::Acquired { lease } => lease,
            o3k_store::LeaseAcquireOutcome::Busy { .. } => {
                return Err("realm unexpectedly busy while seeding durable Apply history".into());
            }
        };
        let mut latest_apply_by_host = BTreeMap::new();
        for command in dispatcher
            .commands
            .lock()
            .map_err(|_| "recording dispatcher poisoned")?
            .iter()
            .filter(|command| command.action == o3k_network::NetworkPlanAction::Apply)
        {
            let generation = command
                .plan
                .resource_generations
                .get(&subnet.id)
                .copied()
                .unwrap_or_default();
            let host = command.plan.node_id.clone();
            if latest_apply_by_host
                .get(&host)
                .is_none_or(|(latest_generation, _)| generation >= *latest_generation)
            {
                latest_apply_by_host.insert(host, (generation, command.clone()));
            }
        }
        for (_, mut command) in latest_apply_by_host.into_values() {
            command.controller = o3k_network::NetworkControllerLease {
                controller_id: controller_id.0.clone(),
                controller_epoch: controller_epoch.0.clone(),
                fencing_token: lease.fencing_token,
            };
            command.plan.operation_id = command.operation_id;
            let work = o3k_store::NetworkPlanWorkRecord {
                command_id: command.command_id.to_string(),
                operation_id: command.operation_id,
                idempotency_key: command.idempotency_key.clone(),
                target_host_id: command.plan.node_id.clone(),
                target_agent_id: command.target.agent_id.clone(),
                target_agent_epoch: command.target.agent_epoch.clone(),
                controller_id: controller_id.0.clone(),
                controller_epoch: controller_epoch.0.clone(),
                fencing_token: lease.fencing_token,
                deadline_unix_ms: command.deadline_unix_ms,
                fingerprint_sha256: command.plan.fingerprint_sha256.clone(),
                snapshot: serde_json::to_vec(&command)?,
                state: o3k_store::NetworkPlanWorkState::Pending,
                revision: 0,
                outcome: None,
            };
            store
                .insert_network_plan_work_under_lease(
                    &realm_key,
                    &controller_id.0,
                    &controller_epoch.0,
                    lease.fencing_token,
                    &work,
                )
                .await
                .map_err(|error| {
                    format!("cannot seed retirement work {}: {error}", work.command_id)
                })?;
            let running = store
                .update_network_plan_work_under_lease(
                    &realm_key,
                    &controller_id.0,
                    &controller_epoch.0,
                    lease.fencing_token,
                    &work.command_id,
                    0,
                    o3k_store::NetworkPlanWorkState::Running,
                    None,
                )
                .await
                .map_err(|error| {
                    format!(
                        "cannot mark retirement work {} running: {error}",
                        work.command_id
                    )
                })?;
            store
                .update_network_plan_work_under_lease(
                    &realm_key,
                    &controller_id.0,
                    &controller_epoch.0,
                    lease.fencing_token,
                    &work.command_id,
                    running.revision,
                    o3k_store::NetworkPlanWorkState::Succeeded,
                    Some(b"succeeded"),
                )
                .await
                .map_err(|error| {
                    format!(
                        "cannot mark retirement work {} succeeded: {error}",
                        work.command_id
                    )
                })?;
        }
        assert!(
            store
                .relinquish_work_lease_preserving_fence(
                    &realm_key,
                    &controller_id,
                    &controller_epoch,
                    lease.fencing_token,
                )
                .await?
        );

        // Unbinding the final endpoint on C keeps the binding tombstone until
        // the full directory has withdrawn C from A/B HER and C has received
        // an owned realm removal plan.
        let departing_port = c_second_port.id;
        network
            .advance_fabric_realm_generation("project-a", network_record.id)
            .await?;
        network
            .project_binding_observation("project-a", departing_port, "compute-c", "down")
            .await?;
        dispatcher
            .unavailable_hosts
            .lock()
            .map_err(|_| "recording unavailable-host lock poisoned")?
            .insert("compute-c".to_owned());
        let before_unavailable_reconcile = dispatcher
            .commands
            .lock()
            .map_err(|_| "recording dispatcher poisoned")?
            .len();
        // This is the controller-crash window: canonical departure is
        // recorded, but no Remove work exists yet. Startup recovery must
        // derive C from durable Apply history and stay pending while C is
        // unreachable.
        recover_fabric_state(&reconciler, store.as_ref()).await;
        assert_eq!(
            dispatcher
                .commands
                .lock()
                .map_err(|_| "recording dispatcher poisoned")?
                .len(),
            before_unavailable_reconcile,
            "survivor Apply must not overtake a retiring host that cannot be reached"
        );
        dispatcher
            .unavailable_hosts
            .lock()
            .map_err(|_| "recording unavailable-host lock poisoned")?
            .remove("compute-c");
        // On reconnect, ordinary startup reconciliation derives C's
        // retirement from durable Apply history without an API mutation or
        // ephemeral departing-host hint.
        reconciler
            .reconcile_realm(
                "project-a",
                network_record.id,
                Uuid::from_u128(993),
                crate::composition::unix_time_millis().saturating_add(30_000),
            )
            .await?;
        network.unbind_port("project-a", departing_port).await?;
        {
            let commands = dispatcher
                .commands
                .lock()
                .map_err(|_| "recording dispatcher poisoned")?;
            let retirement = &commands[before_unavailable_reconcile..];
            assert_eq!(retirement.len(), 3);
            assert_eq!(retirement[0].target.agent_id, "agent-c");
            assert_eq!(retirement[0].action, o3k_network::NetworkPlanAction::Remove);
            let withdrawn = retirement[1..]
                .iter()
                .map(|command| {
                    let fabric = command.plan.fabric.as_ref().expect("Fabric plan");
                    assert_eq!(command.action, o3k_network::NetworkPlanAction::Apply);
                    assert_eq!(fabric.directory.entries.len(), 2);
                    assert_eq!(fabric.peers.len(), 1);
                    fabric.local_host.clone()
                })
                .collect::<std::collections::BTreeSet<_>>();
            assert_eq!(
                withdrawn,
                ["compute-a", "compute-b"]
                    .into_iter()
                    .map(str::to_owned)
                    .collect()
            );
        }
        let lease_after_retirement = match store
            .acquire_work_lease(
                &realm_key,
                "fabric_reconciliation",
                &controller_id,
                &controller_epoch,
                FABRIC_REALM_LEASE_TTL,
            )
            .await?
        {
            o3k_store::LeaseAcquireOutcome::Acquired { lease } => lease,
            o3k_store::LeaseAcquireOutcome::Busy { .. } => {
                return Err("realm unexpectedly busy after retirement".into());
            }
        };
        let retirement_commands = dispatcher
            .commands
            .lock()
            .map_err(|_| "recording dispatcher poisoned")?[before_unavailable_reconcile..]
            .to_vec();
        for mut command in retirement_commands {
            command.controller = o3k_network::NetworkControllerLease {
                controller_id: controller_id.0.clone(),
                controller_epoch: controller_epoch.0.clone(),
                fencing_token: lease_after_retirement.fencing_token,
            };
            command.plan.operation_id = command.operation_id;
            let work = o3k_store::NetworkPlanWorkRecord {
                command_id: command.command_id.to_string(),
                operation_id: command.operation_id,
                idempotency_key: command.idempotency_key.clone(),
                target_host_id: command.plan.node_id.clone(),
                target_agent_id: command.target.agent_id.clone(),
                target_agent_epoch: command.target.agent_epoch.clone(),
                controller_id: controller_id.0.clone(),
                controller_epoch: controller_epoch.0.clone(),
                fencing_token: lease_after_retirement.fencing_token,
                deadline_unix_ms: command.deadline_unix_ms,
                fingerprint_sha256: command.plan.fingerprint_sha256.clone(),
                snapshot: serde_json::to_vec(&command)?,
                state: o3k_store::NetworkPlanWorkState::Pending,
                revision: 0,
                outcome: None,
            };
            store
                .insert_network_plan_work_under_lease(
                    &realm_key,
                    &controller_id.0,
                    &controller_epoch.0,
                    lease_after_retirement.fencing_token,
                    &work,
                )
                .await
                .map_err(|error| {
                    format!("cannot seed retirement work {}: {error}", work.command_id)
                })?;
            let running = store
                .update_network_plan_work_under_lease(
                    &realm_key,
                    &controller_id.0,
                    &controller_epoch.0,
                    lease_after_retirement.fencing_token,
                    &work.command_id,
                    0,
                    o3k_store::NetworkPlanWorkState::Running,
                    None,
                )
                .await
                .map_err(|error| {
                    format!(
                        "cannot mark retirement work {} running: {error}",
                        work.command_id
                    )
                })?;
            store
                .update_network_plan_work_under_lease(
                    &realm_key,
                    &controller_id.0,
                    &controller_epoch.0,
                    lease_after_retirement.fencing_token,
                    &work.command_id,
                    running.revision,
                    o3k_store::NetworkPlanWorkState::Succeeded,
                    Some(b"succeeded"),
                )
                .await
                .map_err(|error| {
                    format!(
                        "cannot mark retirement work {} succeeded: {error}",
                        work.command_id
                    )
                })?;
        }
        assert!(
            store
                .relinquish_work_lease_preserving_fence(
                    &realm_key,
                    &controller_id,
                    &controller_epoch,
                    lease_after_retirement.fencing_token,
                )
                .await?
        );
        // A controller restart must recover from durable canonical state
        // without another endpoint mutation. After C's supported unbind, a
        // startup scan should recreate the current A/B realm plan set.
        dispatcher
            .commands
            .lock()
            .map_err(|_| "recording dispatcher poisoned")?
            .clear();
        let durable_realms = network.list_active_realms_for_reconciliation().await?;
        assert_eq!(durable_realms.len(), 1, "canonical realm missing");
        assert_eq!(durable_realms[0].id, subnet.id);
        recover_fabric_state(&reconciler, store.as_ref()).await;
        let first_startup = dispatcher
            .commands
            .lock()
            .map_err(|_| "recording dispatcher poisoned")?
            .iter()
            .map(|command| {
                (
                    command.operation_id,
                    command.plan.plan_id,
                    command.plan.fingerprint_sha256.clone(),
                    command.target.agent_id.clone(),
                )
            })
            .collect::<Vec<_>>();
        dispatcher
            .commands
            .lock()
            .map_err(|_| "recording dispatcher poisoned")?
            .clear();
        reconciler
            .reconcile_realm("project-a", network_record.id, Uuid::new_v4(), u64::MAX)
            .await?;
        {
            let commands = dispatcher
                .commands
                .lock()
                .map_err(|_| "recording dispatcher poisoned")?;
            assert_eq!(commands.len(), 2);
            let second_startup = commands
                .iter()
                .map(|command| {
                    (
                        command.operation_id,
                        command.plan.plan_id,
                        command.plan.fingerprint_sha256.clone(),
                        command.target.agent_id.clone(),
                    )
                })
                .collect::<Vec<_>>();
            assert_eq!(second_startup, first_startup);
            let hosts = commands
                .iter()
                .map(|command| {
                    let fabric = command.plan.fabric.as_ref().expect("Fabric plan");
                    assert_eq!(fabric.directory.entries.len(), 2);
                    assert_eq!(fabric.peers.len(), 1);
                    fabric.local_host.clone()
                })
                .collect::<std::collections::BTreeSet<_>>();
            assert_eq!(
                hosts,
                ["compute-a", "compute-b"]
                    .into_iter()
                    .map(str::to_owned)
                    .collect()
            );
        }

        let _ = std::fs::remove_dir_all(root);
        Ok(())
    }

    #[tokio::test]
    async fn production_mtls_recovery_reuses_final_endpoint_successor_after_restart()
    -> Result<(), Box<dyn std::error::Error>> {
        let _postgres_test_guard = production_mtls_postgres_test_guard().await;
        let root = std::env::temp_dir().join(format!("o3kd-mtls-recovery-{}", Uuid::now_v7()));
        std::fs::create_dir_all(&root)?;
        let store = if let Ok(database_url) = std::env::var("O3K_DATABASE_URL") {
            o3k_store::conformance::assert_destructive_postgres_test_database(&database_url)
                .map_err(|error| format!("unsafe recovery test database: {error}"))?;
            let postgres = o3k_store::PostgresStore::connect(&database_url).await?;
            postgres.clean_tables_for_testing().await?;
            Arc::new(o3k_store::unified::O3kStore::Postgres(postgres))
        } else {
            Arc::new(o3k_store::unified::O3kStore::connect_sqlite_memory().await?)
        };
        let network_repository: Arc<dyn o3k_store::NetworkRepository> = store.clone();
        let network =
            o3k_network::NetworkService::open_for_test(root.join("network"), network_repository)
                .await?;
        let historical = durable_removal_command(store.as_ref()).await?;
        let registry = Arc::new(o3k_compute_agent::NodeRegistry::default());
        registry
            .register(&o3k_compute_agent::proto::RegisterRequest {
                agent_id: "agent-c".to_owned(),
                agent_epoch: "epoch-1".to_owned(),
                software_version: "test".to_owned(),
                host_label: "compute-c".to_owned(),
                supported_versions: vec![o3k_compute_agent::PROTOCOL_VERSION],
                capabilities: Some(o3k_compute_agent::proto::Capabilities::default()),
            })
            .await?;

        let realizer = MtlSRecoveryRealizer::default();
        let removals = realizer.removals.clone();
        let journal_root = root.join("agent-journal");
        let executor = o3k_network::NetworkPlanExecutor::open(
            &journal_root,
            o3k_network::NetworkAgentIdentity {
                agent_id: "agent-c".to_owned(),
                agent_epoch: "epoch-1".to_owned(),
            },
            o3k_network::NetworkControllerLease {
                controller_id: String::new(),
                controller_epoch: String::new(),
                fencing_token: 0,
            },
        )?;
        let service = o3k_network_bin::agent::NetworkAgentService::new_dynamic(executor, realizer)?;
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await?;
        let address = listener.local_addr()?;
        let server_task = start_mtls_network_agent(listener, service.clone()).await?;
        let endpoint = format!("https://{address}");
        assert!(
            o3k_network_protocol::NetworkAgentClient::connect(
                &endpoint,
                "wrong-server-name",
                network_fixture("ca.pem"),
                network_fixture("agent-chain.pem"),
                network_fixture("agent-key-pkcs8.pem"),
            )
            .await
            .is_err(),
            "the client must validate the server certificate name"
        );
        let wrong_client = o3k_network_protocol::NetworkAgentClient::connect(
            &endpoint,
            "o3k-control-plane",
            network_fixture("ca.pem"),
            network_fixture("server-chain.pem"),
            network_fixture("server-key.pem"),
        )
        .await?;
        let rejected = wrong_client
            .observe_with_lease(
                o3k_network_protocol::proto::Register {
                    agent_id: "agent-c".to_owned(),
                    agent_epoch: "epoch-1".to_owned(),
                },
                o3k_network_protocol::proto::ControllerLease {
                    controller_id: "controller".to_owned(),
                    controller_epoch: "epoch-1".to_owned(),
                    fencing_token: 1,
                    lease_expiry_unix_ms: super::super::unix_time_millis() + 60_000,
                },
                Uuid::now_v7().to_string(),
            )
            .await;
        assert!(
            rejected.is_err(),
            "the server must reject a non-client-auth certificate"
        );
        let committed = Arc::new(tokio::sync::Notify::new());
        let continue_dispatch = Arc::new(tokio::sync::Notify::new());
        let dispatcher = Arc::new(mtls_dispatcher(
            address,
            store.clone(),
            Some((committed.clone(), continue_dispatch.clone())),
        ));
        let dispatcher_trait: Arc<dyn o3k_network::NetworkPlanDispatcher> = dispatcher.clone();
        let reconciler = Arc::new(FabricRealmReconciler {
            network: network.clone(),
            coordination: store.clone(),
            durable: store.clone(),
            registry: registry.clone(),
            dispatcher: dispatcher_trait,
            controller: o3k_network::NetworkControllerLease {
                controller_id: "controller".to_owned(),
                controller_epoch: "epoch-1".to_owned(),
                fencing_token: 0,
            },
            fabric_domain_id: Uuid::from_u128(990),
            network_external_realm_id: None,
            public_allocator: None,
            reconciliation_locks: Arc::new(std::sync::Mutex::new(BTreeMap::new())),
        });

        // Startup recovery observes historical X over mTLS. The agent journal
        // has no X, so production reconciliation invokes concrete atomic
        // supersession. The gate pauses after that commit and before the
        // concrete dispatcher opens the successor command stream.
        let recovery_reconciler = reconciler.clone();
        let recovery_store = store.clone();
        let recovery = tokio::spawn(async move {
            recover_fabric_state(&recovery_reconciler, recovery_store.as_ref()).await;
        });
        tokio::time::timeout(std::time::Duration::from_secs(5), committed.notified()).await?;
        let terminal = store.get_network_plan_work(&historical.command_id).await?;
        assert_eq!(terminal.state, o3k_store::NetworkPlanWorkState::Failed);
        let outcome: serde_json::Value = serde_json::from_slice(
            terminal
                .outcome
                .as_deref()
                .ok_or("atomic supersession did not record its outcome")?,
        )?;
        assert_eq!(outcome["classification"], "superseded_not_admitted");
        let successor_id = outcome["successor_command_id"]
            .as_str()
            .ok_or("atomic supersession omitted successor command")?
            .to_owned();
        let successor = store.get_network_plan_work(&successor_id).await?;
        assert_eq!(successor.state, o3k_store::NetworkPlanWorkState::Pending);
        let unresolved = store.list_unresolved_network_plan_work().await?;
        assert_eq!(unresolved.len(), 1);
        assert_eq!(unresolved[0].command_id, successor_id);

        // Simulate controller/process loss after transaction commit but before
        // the concrete dispatcher is allowed to make its first RPC. The agent
        // remains running; only the controller recovery task is interrupted.
        recovery.abort();
        let _ = recovery.await;
        let after_controller_crash = store.get_network_plan_work(&successor_id).await?;
        assert_eq!(
            after_controller_crash.state,
            o3k_store::NetworkPlanWorkState::Pending
        );
        assert_eq!(
            removals.load(std::sync::atomic::Ordering::Acquire),
            0,
            "no mutation may occur before successor RPC admission"
        );

        // Run the production startup reconciler again through the same live
        // agent. It must reuse the one durable successor and dispatch it over
        // the concrete mTLS transport.
        let restarted_dispatcher = Arc::new(mtls_dispatcher(address, store.clone(), None));
        let dispatcher_trait: Arc<dyn o3k_network::NetworkPlanDispatcher> = restarted_dispatcher;
        let restarted_reconciler = FabricRealmReconciler {
            network,
            coordination: store.clone(),
            durable: store.clone(),
            registry,
            dispatcher: dispatcher_trait,
            controller: o3k_network::NetworkControllerLease {
                controller_id: "controller".to_owned(),
                controller_epoch: "epoch-1".to_owned(),
                fencing_token: 0,
            },
            fabric_domain_id: Uuid::from_u128(990),
            network_external_realm_id: None,
            public_allocator: None,
            reconciliation_locks: Arc::new(std::sync::Mutex::new(BTreeMap::new())),
        };
        tokio::time::timeout(std::time::Duration::from_secs(10), async {
            loop {
                recover_fabric_state(&restarted_reconciler, store.as_ref()).await;
                let current = store.get_network_plan_work(&successor_id).await?;
                if current.state == o3k_store::NetworkPlanWorkState::Succeeded {
                    break Ok::<(), o3k_store::StoreError>(());
                }
                tokio::time::sleep(std::time::Duration::from_millis(25)).await;
            }
        })
        .await??;
        let successor = store.get_network_plan_work(&successor_id).await?;
        assert_eq!(successor.state, o3k_store::NetworkPlanWorkState::Succeeded);
        assert_eq!(
            removals.load(std::sync::atomic::Ordering::Acquire),
            1,
            "the durable successor must invoke exactly one provider remove"
        );
        assert!(store.list_unresolved_network_plan_work().await?.is_empty());
        server_task.abort();
        let _ = server_task.await;
        let _ = std::fs::remove_dir_all(root);
        Ok(())
    }

    #[tokio::test]
    async fn production_mtls_two_controller_supersession_is_realm_fenced()
    -> Result<(), Box<dyn std::error::Error>> {
        let _postgres_test_guard = production_mtls_postgres_test_guard().await;
        let root =
            std::env::temp_dir().join(format!("o3kd-mtls-two-controller-{}", Uuid::now_v7()));
        std::fs::create_dir_all(&root)?;
        let store = if let Ok(database_url) = std::env::var("O3K_DATABASE_URL") {
            o3k_store::conformance::assert_destructive_postgres_test_database(&database_url)
                .map_err(|error| format!("unsafe recovery test database: {error}"))?;
            let postgres = o3k_store::PostgresStore::connect(&database_url).await?;
            postgres.clean_tables_for_testing().await?;
            Arc::new(o3k_store::unified::O3kStore::Postgres(postgres))
        } else {
            Arc::new(o3k_store::unified::O3kStore::connect_sqlite_memory().await?)
        };
        let network_repository: Arc<dyn o3k_store::NetworkRepository> = store.clone();
        let network =
            o3k_network::NetworkService::open_for_test(root.join("network"), network_repository)
                .await?;
        let historical = durable_removal_command(store.as_ref()).await?;
        let registry = Arc::new(o3k_compute_agent::NodeRegistry::default());
        registry
            .register(&o3k_compute_agent::proto::RegisterRequest {
                agent_id: "agent-c".to_owned(),
                agent_epoch: "epoch-1".to_owned(),
                software_version: "test".to_owned(),
                host_label: "compute-c".to_owned(),
                supported_versions: vec![o3k_compute_agent::PROTOCOL_VERSION],
                capabilities: Some(o3k_compute_agent::proto::Capabilities::default()),
            })
            .await?;

        let realizer = MtlSRecoveryRealizer::default();
        let removals = realizer.removals.clone();
        let executor = o3k_network::NetworkPlanExecutor::open(
            root.join("agent-journal"),
            o3k_network::NetworkAgentIdentity {
                agent_id: "agent-c".to_owned(),
                agent_epoch: "epoch-1".to_owned(),
            },
            o3k_network::NetworkControllerLease {
                controller_id: String::new(),
                controller_epoch: String::new(),
                fencing_token: 0,
            },
        )?;
        let service = o3k_network_bin::agent::NetworkAgentService::new_dynamic(executor, realizer)?;
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await?;
        let address = listener.local_addr()?;
        let server = start_mtls_network_agent(listener, service).await?;

        let reached = Arc::new(tokio::sync::Notify::new());
        let proceed = Arc::new(tokio::sync::Notify::new());
        let mut dispatcher_a =
            mtls_dispatcher_as(address, store.clone(), "controller-a", "epoch-a", None);
        dispatcher_a.pre_supersession_gate = Some((reached.clone(), proceed.clone()));
        let dispatcher_a: Arc<dyn o3k_network::NetworkPlanDispatcher> = Arc::new(dispatcher_a);
        let controller_a = o3k_network::NetworkControllerLease {
            controller_id: "controller-a".to_owned(),
            controller_epoch: "epoch-a".to_owned(),
            fencing_token: 0,
        };
        let reconciler_a = Arc::new(FabricRealmReconciler {
            network: network.clone(),
            coordination: store.clone(),
            durable: store.clone(),
            registry: registry.clone(),
            dispatcher: dispatcher_a,
            controller: controller_a,
            fabric_domain_id: Uuid::from_u128(990),
            network_external_realm_id: None,
            public_allocator: None,
            reconciliation_locks: Arc::new(std::sync::Mutex::new(BTreeMap::new())),
        });

        let recovery_a = {
            let reconciler = reconciler_a.clone();
            let store = store.clone();
            tokio::spawn(async move { recover_fabric_state(&reconciler, store.as_ref()).await })
        };
        tokio::time::timeout(std::time::Duration::from_secs(5), reached.notified()).await?;
        let realm_key = format!("fabric-realm:{}", Uuid::from_u128(800));
        let lease_a = store
            .inspect_work_lease(&realm_key)
            .await?
            .ok_or("controller A lost realm lease before supersession gate")?;
        assert_eq!(lease_a.owner_controller_id.0, "controller-a");
        assert!(
            store
                .relinquish_work_lease_preserving_fence(
                    &realm_key,
                    &o3k_store::ControllerId::new("controller-a"),
                    &o3k_store::ControllerEpoch::new("epoch-a"),
                    lease_a.fencing_token,
                )
                .await?
        );
        let lease_b = match store
            .acquire_work_lease(
                &realm_key,
                "fabric_reconciliation",
                &o3k_store::ControllerId::new("controller-b"),
                &o3k_store::ControllerEpoch::new("epoch-b"),
                FABRIC_REALM_LEASE_TTL,
            )
            .await?
        {
            o3k_store::LeaseAcquireOutcome::Acquired { lease } => lease,
            o3k_store::LeaseAcquireOutcome::Busy { .. } => {
                return Err("controller B could not take over relinquished realm lease".into());
            }
        };
        assert!(lease_b.fencing_token > lease_a.fencing_token);
        // Let A reach the actual fenced atomic supersession store operation.
        proceed.notify_one();
        tokio::time::timeout(std::time::Duration::from_secs(5), recovery_a).await??;
        assert_eq!(
            store
                .get_network_plan_work(&historical.command_id)
                .await?
                .state,
            o3k_store::NetworkPlanWorkState::Running,
            "stale A must not terminalize the historical row"
        );
        assert_eq!(store.list_unresolved_network_plan_work().await?.len(), 1);
        assert_eq!(removals.load(std::sync::atomic::Ordering::Acquire), 0);

        let dispatcher_b: Arc<dyn o3k_network::NetworkPlanDispatcher> = Arc::new(
            mtls_dispatcher_as(address, store.clone(), "controller-b", "epoch-b", None),
        );
        let reconciler_b = FabricRealmReconciler {
            network,
            coordination: store.clone(),
            durable: store.clone(),
            registry,
            dispatcher: dispatcher_b,
            controller: o3k_network::NetworkControllerLease {
                controller_id: "controller-b".to_owned(),
                controller_epoch: "epoch-b".to_owned(),
                fencing_token: 0,
            },
            fabric_domain_id: Uuid::from_u128(990),
            network_external_realm_id: None,
            public_allocator: None,
            reconciliation_locks: Arc::new(std::sync::Mutex::new(BTreeMap::new())),
        };
        tokio::time::timeout(std::time::Duration::from_secs(10), async {
            loop {
                recover_fabric_state(&reconciler_b, store.as_ref()).await;
                if store.list_unresolved_network_plan_work().await?.is_empty() {
                    break Ok::<(), o3k_store::StoreError>(());
                }
                tokio::time::sleep(std::time::Duration::from_millis(25)).await;
            }
        })
        .await??;
        let terminal = store.get_network_plan_work(&historical.command_id).await?;
        let outcome: serde_json::Value = serde_json::from_slice(
            terminal
                .outcome
                .as_deref()
                .ok_or("supersession outcome missing")?,
        )?;
        let successor_id = outcome["successor_command_id"]
            .as_str()
            .ok_or("successor command missing")?;
        assert_eq!(terminal.state, o3k_store::NetworkPlanWorkState::Failed);
        assert_eq!(
            store.get_network_plan_work(successor_id).await?.state,
            o3k_store::NetworkPlanWorkState::Succeeded
        );
        assert_eq!(removals.load(std::sync::atomic::Ordering::Acquire), 1);
        server.abort();
        let _ = server.await;
        let _ = std::fs::remove_dir_all(root);
        Ok(())
    }

    #[tokio::test]
    async fn production_mtls_not_found_crash_before_supersession_retries_safely()
    -> Result<(), Box<dyn std::error::Error>> {
        let _postgres_test_guard = production_mtls_postgres_test_guard().await;
        let root = std::env::temp_dir().join(format!("o3kd-mtls-precommit-{}", Uuid::now_v7()));
        std::fs::create_dir_all(&root)?;
        let store = if let Ok(database_url) = std::env::var("O3K_DATABASE_URL") {
            o3k_store::conformance::assert_destructive_postgres_test_database(&database_url)
                .map_err(|error| format!("unsafe recovery test database: {error}"))?;
            let postgres = o3k_store::PostgresStore::connect(&database_url).await?;
            postgres.clean_tables_for_testing().await?;
            Arc::new(o3k_store::unified::O3kStore::Postgres(postgres))
        } else {
            Arc::new(o3k_store::unified::O3kStore::connect_sqlite_memory().await?)
        };
        let network_repository: Arc<dyn o3k_store::NetworkRepository> = store.clone();
        let network =
            o3k_network::NetworkService::open_for_test(root.join("network"), network_repository)
                .await?;
        let historical = durable_removal_command(store.as_ref()).await?;
        let registry = Arc::new(o3k_compute_agent::NodeRegistry::default());
        registry
            .register(&o3k_compute_agent::proto::RegisterRequest {
                agent_id: "agent-c".to_owned(),
                agent_epoch: "epoch-1".to_owned(),
                software_version: "test".to_owned(),
                host_label: "compute-c".to_owned(),
                supported_versions: vec![o3k_compute_agent::PROTOCOL_VERSION],
                capabilities: Some(o3k_compute_agent::proto::Capabilities::default()),
            })
            .await?;

        let realizer = MtlSRecoveryRealizer::default();
        let removals = realizer.removals.clone();
        let executor = o3k_network::NetworkPlanExecutor::open(
            root.join("agent-journal"),
            o3k_network::NetworkAgentIdentity {
                agent_id: "agent-c".to_owned(),
                agent_epoch: "epoch-1".to_owned(),
            },
            o3k_network::NetworkControllerLease {
                controller_id: String::new(),
                controller_epoch: String::new(),
                fencing_token: 0,
            },
        )?;
        let service = o3k_network_bin::agent::NetworkAgentService::new_dynamic(executor, realizer)?;
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await?;
        let address = listener.local_addr()?;
        let server = start_mtls_network_agent(listener, service).await?;
        let reached = Arc::new(tokio::sync::Notify::new());
        let proceed = Arc::new(tokio::sync::Notify::new());
        let mut first_dispatcher =
            mtls_dispatcher_as(address, store.clone(), "controller-a", "epoch-a", None);
        first_dispatcher.pre_supersession_gate = Some((reached.clone(), proceed));
        let first_dispatcher: Arc<dyn o3k_network::NetworkPlanDispatcher> =
            Arc::new(first_dispatcher);
        let first_reconciler = Arc::new(FabricRealmReconciler {
            network: network.clone(),
            coordination: store.clone(),
            durable: store.clone(),
            registry: registry.clone(),
            dispatcher: first_dispatcher,
            controller: o3k_network::NetworkControllerLease {
                controller_id: "controller-a".to_owned(),
                controller_epoch: "epoch-a".to_owned(),
                fencing_token: 0,
            },
            fabric_domain_id: Uuid::from_u128(990),
            network_external_realm_id: None,
            public_allocator: None,
            reconciliation_locks: Arc::new(std::sync::Mutex::new(BTreeMap::new())),
        });
        let first_store = store.clone();
        let first = tokio::spawn(async move {
            recover_fabric_state(&first_reconciler, first_store.as_ref()).await;
        });

        // The production reconciler has observed not_found over mTLS and is
        // paused immediately before its fenced atomic supersession call.
        tokio::time::timeout(std::time::Duration::from_secs(5), reached.notified()).await?;
        first.abort();
        let _ = first.await;
        assert_eq!(
            store
                .get_network_plan_work(&historical.command_id)
                .await?
                .state,
            o3k_store::NetworkPlanWorkState::Running
        );
        assert_eq!(store.list_unresolved_network_plan_work().await?.len(), 1);
        assert_eq!(removals.load(std::sync::atomic::Ordering::Acquire), 0);

        // A cancelled controller task may leave its realm lease to expire.
        // Relinquish that exact owned lease to model a clean process handoff;
        // the preserved token makes B's successor fence strictly higher.
        let realm_key = format!("fabric-realm:{}", Uuid::from_u128(800));
        let lease_a = store
            .inspect_work_lease(&realm_key)
            .await?
            .ok_or("controller A realm lease missing after interruption")?;
        assert_eq!(lease_a.owner_controller_id.0, "controller-a");
        assert!(
            store
                .relinquish_work_lease_preserving_fence(
                    &realm_key,
                    &lease_a.owner_controller_id,
                    &lease_a.owner_controller_epoch,
                    lease_a.fencing_token,
                )
                .await?
        );

        let second_dispatcher: Arc<dyn o3k_network::NetworkPlanDispatcher> = Arc::new(
            mtls_dispatcher_as(address, store.clone(), "controller-b", "epoch-b", None),
        );
        let second_reconciler = FabricRealmReconciler {
            network,
            coordination: store.clone(),
            durable: store.clone(),
            registry,
            dispatcher: second_dispatcher,
            controller: o3k_network::NetworkControllerLease {
                controller_id: "controller-b".to_owned(),
                controller_epoch: "epoch-b".to_owned(),
                fencing_token: 0,
            },
            fabric_domain_id: Uuid::from_u128(990),
            network_external_realm_id: None,
            public_allocator: None,
            reconciliation_locks: Arc::new(std::sync::Mutex::new(BTreeMap::new())),
        };
        tokio::time::timeout(std::time::Duration::from_secs(10), async {
            loop {
                recover_fabric_state(&second_reconciler, store.as_ref()).await;
                if store.list_unresolved_network_plan_work().await?.is_empty() {
                    break Ok::<(), o3k_store::StoreError>(());
                }
                tokio::time::sleep(std::time::Duration::from_millis(25)).await;
            }
        })
        .await??;
        let terminal = store.get_network_plan_work(&historical.command_id).await?;
        assert_eq!(terminal.state, o3k_store::NetworkPlanWorkState::Failed);
        let outcome: serde_json::Value = serde_json::from_slice(
            terminal
                .outcome
                .as_deref()
                .ok_or("recovery did not persist supersession outcome")?,
        )?;
        let successor_id = outcome["successor_command_id"]
            .as_str()
            .ok_or("recovery did not create a successor")?;
        assert_eq!(
            store.get_network_plan_work(successor_id).await?.state,
            o3k_store::NetworkPlanWorkState::Succeeded
        );
        assert_eq!(store.list_unresolved_network_plan_work().await?.len(), 0);
        assert_eq!(
            removals.load(std::sync::atomic::Ordering::Acquire),
            1,
            "pre-commit crash recovery must produce one provider mutation"
        );
        server.abort();
        let _ = server.await;
        let _ = std::fs::remove_dir_all(root);
        Ok(())
    }

    #[tokio::test]
    async fn production_mtls_unknown_final_removal_is_not_superseded()
    -> Result<(), Box<dyn std::error::Error>> {
        let _postgres_test_guard = production_mtls_postgres_test_guard().await;
        let root = std::env::temp_dir().join(format!("o3kd-mtls-unknown-{}", Uuid::now_v7()));
        std::fs::create_dir_all(&root)?;
        let store = if let Ok(database_url) = std::env::var("O3K_DATABASE_URL") {
            o3k_store::conformance::assert_destructive_postgres_test_database(&database_url)
                .map_err(|error| format!("unsafe recovery test database: {error}"))?;
            let postgres = o3k_store::PostgresStore::connect(&database_url).await?;
            postgres.clean_tables_for_testing().await?;
            Arc::new(o3k_store::unified::O3kStore::Postgres(postgres))
        } else {
            Arc::new(o3k_store::unified::O3kStore::connect_sqlite_memory().await?)
        };
        let network_repository: Arc<dyn o3k_store::NetworkRepository> = store.clone();
        let network =
            o3k_network::NetworkService::open_for_test(root.join("network"), network_repository)
                .await?;
        let historical = durable_removal_command(store.as_ref()).await?;
        let command: o3k_network::NetworkPlanCommand =
            serde_json::from_slice(&historical.snapshot)?;
        let realm_key = format!("fabric-realm:{}", Uuid::from_u128(800));
        let controller_id = o3k_store::ControllerId::new("controller");
        let controller_epoch = o3k_store::ControllerEpoch::new("epoch-1");
        let realm_lease = match store
            .acquire_work_lease(
                &realm_key,
                "fabric_reconciliation",
                &controller_id,
                &controller_epoch,
                FABRIC_REALM_LEASE_TTL,
            )
            .await?
        {
            o3k_store::LeaseAcquireOutcome::Acquired { lease } => lease,
            o3k_store::LeaseAcquireOutcome::Busy { .. } => {
                return Err("test realm unexpectedly busy".into());
            }
        };
        // The seeded row models a command whose admission outcome was lost.
        // Send that exact durable successor through the production dispatcher
        // and mTLS service; the controlled provider reports an ambiguous
        // remove outcome so the agent journal remains unknown.
        let registry = Arc::new(o3k_compute_agent::NodeRegistry::default());
        registry
            .register(&o3k_compute_agent::proto::RegisterRequest {
                agent_id: "agent-c".to_owned(),
                agent_epoch: "epoch-1".to_owned(),
                software_version: "test".to_owned(),
                host_label: "compute-c".to_owned(),
                supported_versions: vec![o3k_compute_agent::PROTOCOL_VERSION],
                capabilities: Some(o3k_compute_agent::proto::Capabilities::default()),
            })
            .await?;
        let realizer = MtlSRecoveryRealizer {
            unknown_remove: true,
            ..MtlSRecoveryRealizer::default()
        };
        let removals = realizer.removals.clone();
        let service_executor = o3k_network::NetworkPlanExecutor::open(
            root.join("agent-journal"),
            o3k_network::NetworkAgentIdentity {
                agent_id: "agent-c".to_owned(),
                agent_epoch: "epoch-1".to_owned(),
            },
            o3k_network::NetworkControllerLease {
                controller_id: String::new(),
                controller_epoch: String::new(),
                fencing_token: 0,
            },
        )?;
        let service =
            o3k_network_bin::agent::NetworkAgentService::new_dynamic(service_executor, realizer)?;
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await?;
        let address = listener.local_addr()?;
        let server = start_mtls_network_agent(listener, service).await?;
        let dispatcher = Arc::new(mtls_dispatcher(address, store.clone(), None));
        let dispatch_result = dispatcher
            .dispatch_existing_successor(command.clone(), historical.command_id.clone())
            .await?;
        assert_eq!(dispatch_result, o3k_network::NetworkPlanStatus::Unknown);
        let admitted = store.get_network_plan_work(&historical.command_id).await?;
        assert_eq!(
            admitted.state,
            o3k_store::NetworkPlanWorkState::UnknownOutcome
        );
        assert_eq!(removals.load(std::sync::atomic::Ordering::Acquire), 1);
        assert!(
            store
                .relinquish_work_lease_preserving_fence(
                    &realm_key,
                    &controller_id,
                    &controller_epoch,
                    realm_lease.fencing_token,
                )
                .await?
        );

        let dispatcher_trait: Arc<dyn o3k_network::NetworkPlanDispatcher> = dispatcher;
        let reconciler = FabricRealmReconciler {
            network,
            coordination: store.clone(),
            durable: store.clone(),
            registry,
            dispatcher: dispatcher_trait,
            controller: o3k_network::NetworkControllerLease {
                controller_id: "controller".to_owned(),
                controller_epoch: "epoch-1".to_owned(),
                fencing_token: 0,
            },
            fabric_domain_id: Uuid::from_u128(990),
            network_external_realm_id: None,
            public_allocator: None,
            reconciliation_locks: Arc::new(std::sync::Mutex::new(BTreeMap::new())),
        };
        recover_fabric_state(&reconciler, store.as_ref()).await;
        let after_recovery = store.get_network_plan_work(&historical.command_id).await?;
        assert_eq!(
            after_recovery.state,
            o3k_store::NetworkPlanWorkState::UnknownOutcome
        );
        assert_eq!(
            store.list_unresolved_network_plan_work().await?.len(),
            1,
            "unknown admitted final removal must remain unresolved without a successor"
        );
        assert_eq!(
            removals.load(std::sync::atomic::Ordering::Acquire),
            1,
            "observation of unknown removal must not repeat provider mutation"
        );
        server.abort();
        let _ = server.await;
        let _ = std::fs::remove_dir_all(root);
        Ok(())
    }

    #[tokio::test]
    async fn production_mtls_admitted_remove_finishes_across_controller_takeover()
    -> Result<(), Box<dyn std::error::Error>> {
        let root =
            std::env::temp_dir().join(format!("o3kd-mtls-running-takeover-{}", Uuid::now_v7()));
        std::fs::create_dir_all(&root)?;
        let store = Arc::new(o3k_store::unified::O3kStore::connect_sqlite_memory().await?);
        let historical = durable_removal_command(store.as_ref()).await?;
        let historical_command: o3k_network::NetworkPlanCommand =
            serde_json::from_slice(&historical.snapshot)?;
        let realm_key = format!("fabric-realm:{}", Uuid::from_u128(800));
        let controller_a = o3k_store::ControllerId::new("controller-a");
        let epoch_a = o3k_store::ControllerEpoch::new("epoch-a");
        let realm_lease_a = match store
            .acquire_work_lease(
                &realm_key,
                "fabric_reconciliation",
                &controller_a,
                &epoch_a,
                FABRIC_REALM_LEASE_TTL,
            )
            .await?
        {
            o3k_store::LeaseAcquireOutcome::Acquired { lease } => lease,
            o3k_store::LeaseAcquireOutcome::Busy { .. } => {
                return Err("controller A could not acquire realm lease".into());
            }
        };
        let entered = Arc::new(tokio::sync::Notify::new());
        let released = Arc::new((std::sync::Mutex::new(false), std::sync::Condvar::new()));
        let removals = Arc::new(std::sync::atomic::AtomicUsize::new(0));
        let service = o3k_network_bin::agent::NetworkAgentService::new_dynamic(
            o3k_network::NetworkPlanExecutor::open(
                root.join("agent-journal"),
                o3k_network::NetworkAgentIdentity {
                    agent_id: "agent-c".to_owned(),
                    agent_epoch: "epoch-1".to_owned(),
                },
                o3k_network::NetworkControllerLease {
                    controller_id: String::new(),
                    controller_epoch: String::new(),
                    fencing_token: 0,
                },
            )?,
            BlockingMtlSRecoveryRealizer {
                entered: entered.clone(),
                released: released.clone(),
                removals: removals.clone(),
            },
        )?;
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await?;
        let address = listener.local_addr()?;
        let server = start_mtls_network_agent(listener, service).await?;
        let dispatcher_a = Arc::new(mtls_dispatcher_as(
            address,
            store.clone(),
            "controller-a",
            "epoch-a",
            None,
        ));
        let dispatch_task = {
            let dispatcher = dispatcher_a.clone();
            let command = historical_command.clone();
            let old_id = historical.command_id.clone();
            tokio::spawn(async move {
                dispatcher
                    .dispatch_existing_successor(command, old_id)
                    .await
            })
        };
        tokio::time::timeout(std::time::Duration::from_secs(5), entered.notified()).await?;
        assert_eq!(removals.load(std::sync::atomic::Ordering::Acquire), 1);
        let agent_key = "network-agent:agent-c";
        let agent_lease_a = store
            .inspect_work_lease(agent_key)
            .await?
            .ok_or("controller A agent lease missing after admission")?;
        assert_eq!(agent_lease_a.owner_controller_id.0, "controller-a");
        assert!(
            store
                .relinquish_work_lease_preserving_fence(
                    agent_key,
                    &controller_a,
                    &epoch_a,
                    agent_lease_a.fencing_token,
                )
                .await?
        );
        assert!(
            store
                .relinquish_work_lease_preserving_fence(
                    &realm_key,
                    &controller_a,
                    &epoch_a,
                    realm_lease_a.fencing_token,
                )
                .await?
        );
        let controller_b = o3k_store::ControllerId::new("controller-b");
        let epoch_b = o3k_store::ControllerEpoch::new("epoch-b");
        let realm_lease_b = match store
            .acquire_work_lease(
                &realm_key,
                "fabric_reconciliation",
                &controller_b,
                &epoch_b,
                FABRIC_REALM_LEASE_TTL,
            )
            .await?
        {
            o3k_store::LeaseAcquireOutcome::Acquired { lease } => lease,
            o3k_store::LeaseAcquireOutcome::Busy { .. } => {
                return Err("controller B could not take over realm lease".into());
            }
        };
        assert!(realm_lease_b.fencing_token > realm_lease_a.fencing_token);
        let network_repository: Arc<dyn o3k_store::NetworkRepository> = store.clone();
        let network =
            o3k_network::NetworkService::open_for_test(root.join("network"), network_repository)
                .await?;
        let registry = Arc::new(o3k_compute_agent::NodeRegistry::default());
        registry
            .register(&o3k_compute_agent::proto::RegisterRequest {
                agent_id: "agent-c".to_owned(),
                agent_epoch: "epoch-1".to_owned(),
                software_version: "test".to_owned(),
                host_label: "compute-c".to_owned(),
                supported_versions: vec![o3k_compute_agent::PROTOCOL_VERSION],
                capabilities: Some(o3k_compute_agent::proto::Capabilities::default()),
            })
            .await?;
        let dispatcher_b: Arc<dyn o3k_network::NetworkPlanDispatcher> = Arc::new(
            mtls_dispatcher_as(address, store.clone(), "controller-b", "epoch-b", None),
        );
        let reconciler_b = FabricRealmReconciler {
            network,
            coordination: store.clone(),
            durable: store.clone(),
            registry,
            dispatcher: dispatcher_b.clone(),
            controller: o3k_network::NetworkControllerLease {
                controller_id: "controller-b".to_owned(),
                controller_epoch: "epoch-b".to_owned(),
                fencing_token: 0,
            },
            fabric_domain_id: Uuid::from_u128(990),
            network_external_realm_id: None,
            public_allocator: None,
            reconciliation_locks: Arc::new(std::sync::Mutex::new(BTreeMap::new())),
        };
        // Production recovery observes X while it is still executing. It must
        // leave the durable row unresolved and must not supersede it.
        recover_fabric_state(&reconciler_b, store.as_ref()).await;
        assert_eq!(
            store
                .get_network_plan_work(&historical.command_id)
                .await?
                .state,
            o3k_store::NetworkPlanWorkState::Running
        );
        assert_eq!(store.list_unresolved_network_plan_work().await?.len(), 1);
        assert_eq!(removals.load(std::sync::atomic::Ordering::Acquire), 1);

        {
            let (state, wake) = &*released;
            *state.lock().map_err(|_| "release lock poisoned")? = true;
            wake.notify_all();
        }
        let old_controller_result =
            tokio::time::timeout(std::time::Duration::from_secs(5), dispatch_task).await?;
        assert!(old_controller_result?.is_err());
        tokio::time::timeout(std::time::Duration::from_secs(10), async {
            loop {
                recover_fabric_state(&reconciler_b, store.as_ref()).await;
                if store.list_unresolved_network_plan_work().await?.is_empty() {
                    break Ok::<(), o3k_store::StoreError>(());
                }
                tokio::time::sleep(std::time::Duration::from_millis(25)).await;
            }
        })
        .await??;
        assert_eq!(
            store
                .get_network_plan_work(&historical.command_id)
                .await?
                .state,
            o3k_store::NetworkPlanWorkState::Succeeded
        );
        assert_eq!(removals.load(std::sync::atomic::Ordering::Acquire), 1);
        // Recovery's RAII realm lease may already have relinquished this
        // ownership while settling X; no cleanup transition is required.
        server.abort();
        let _ = server.await;
        let _ = std::fs::remove_dir_all(root);
        Ok(())
    }

    #[tokio::test]
    async fn production_mtls_observes_success_after_controller_crash_before_result_persist()
    -> Result<(), Box<dyn std::error::Error>> {
        let root = std::env::temp_dir().join(format!("o3kd-mtls-after-agent-{}", Uuid::now_v7()));
        std::fs::create_dir_all(&root)?;
        let store = Arc::new(o3k_store::unified::O3kStore::connect_sqlite_memory().await?);
        let network_repository: Arc<dyn o3k_store::NetworkRepository> = store.clone();
        let network =
            o3k_network::NetworkService::open_for_test(root.join("network"), network_repository)
                .await?;
        let historical = durable_removal_command(store.as_ref()).await?;
        let registry = Arc::new(o3k_compute_agent::NodeRegistry::default());
        registry
            .register(&o3k_compute_agent::proto::RegisterRequest {
                agent_id: "agent-c".to_owned(),
                agent_epoch: "epoch-1".to_owned(),
                software_version: "test".to_owned(),
                host_label: "compute-c".to_owned(),
                supported_versions: vec![o3k_compute_agent::PROTOCOL_VERSION],
                capabilities: Some(o3k_compute_agent::proto::Capabilities::default()),
            })
            .await?;
        let realizer = MtlSRecoveryRealizer::default();
        let removals = realizer.removals.clone();
        let journal_root = root.join("agent-journal");
        let executor = o3k_network::NetworkPlanExecutor::open(
            &journal_root,
            o3k_network::NetworkAgentIdentity {
                agent_id: "agent-c".to_owned(),
                agent_epoch: "epoch-1".to_owned(),
            },
            o3k_network::NetworkControllerLease {
                controller_id: String::new(),
                controller_epoch: String::new(),
                fencing_token: 0,
            },
        )?;
        let service = o3k_network_bin::agent::NetworkAgentService::new_dynamic(executor, realizer)?;
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await?;
        let address = listener.local_addr()?;
        let server = start_mtls_network_agent(listener, service).await?;
        let received = Arc::new(tokio::sync::Notify::new());
        let persist = Arc::new(tokio::sync::Notify::new());
        let mut dispatcher = mtls_dispatcher(address, store.clone(), None);
        dispatcher.result_persistence_gate = Some((received.clone(), persist));
        let dispatcher_trait: Arc<dyn o3k_network::NetworkPlanDispatcher> = Arc::new(dispatcher);
        let reconciler = Arc::new(FabricRealmReconciler {
            network,
            coordination: store.clone(),
            durable: store.clone(),
            registry,
            dispatcher: dispatcher_trait,
            controller: o3k_network::NetworkControllerLease {
                controller_id: "controller".to_owned(),
                controller_epoch: "epoch-1".to_owned(),
                fencing_token: 0,
            },
            fabric_domain_id: Uuid::from_u128(990),
            network_external_realm_id: None,
            public_allocator: None,
            reconciliation_locks: Arc::new(std::sync::Mutex::new(BTreeMap::new())),
        });

        // Recovery sees X as not_found, atomically creates Y, sends Y through
        // the production mTLS path, and pauses only after the actual agent
        // response. At this point the agent journal and provider have settled
        // Y, while the controller work row intentionally remains Running.
        let running_reconciler = reconciler.clone();
        let running_store = store.clone();
        let recovery = tokio::spawn(async move {
            recover_fabric_state(&running_reconciler, running_store.as_ref()).await;
        });
        tokio::time::timeout(std::time::Duration::from_secs(5), received.notified()).await?;
        let historical_row = store.get_network_plan_work(&historical.command_id).await?;
        let outcome: serde_json::Value = serde_json::from_slice(
            historical_row
                .outcome
                .as_deref()
                .ok_or("superseded historical row has no outcome")?,
        )?;
        let successor_id = outcome["successor_command_id"]
            .as_str()
            .ok_or("supersession omitted successor ID")?;
        let pending_successor = store.get_network_plan_work(successor_id).await?;
        assert_eq!(
            pending_successor.state,
            o3k_store::NetworkPlanWorkState::Running
        );
        assert_eq!(removals.load(std::sync::atomic::Ordering::Acquire), 1);
        let observer_executor = o3k_network::NetworkPlanExecutor::open(
            &journal_root,
            o3k_network::NetworkAgentIdentity {
                agent_id: "agent-c".to_owned(),
                agent_epoch: "epoch-1".to_owned(),
            },
            o3k_network::NetworkControllerLease {
                controller_id: String::new(),
                controller_epoch: String::new(),
                fencing_token: 0,
            },
        )?;
        assert_eq!(
            observer_executor.status(Uuid::parse_str(successor_id)?)?,
            o3k_network::NetworkPlanStatus::Succeeded,
            "agent's durable journal must show Y settled before controller result persistence"
        );

        recovery.abort();
        let _ = recovery.await;
        let restarted_dispatcher = Arc::new(mtls_dispatcher(address, store.clone(), None));
        let dispatcher_trait: Arc<dyn o3k_network::NetworkPlanDispatcher> = restarted_dispatcher;
        let restarted_reconciler = FabricRealmReconciler {
            network: reconciler.network.clone(),
            coordination: store.clone(),
            durable: store.clone(),
            registry: reconciler.registry.clone(),
            dispatcher: dispatcher_trait,
            controller: o3k_network::NetworkControllerLease {
                controller_id: "controller".to_owned(),
                controller_epoch: "epoch-2".to_owned(),
                fencing_token: 0,
            },
            fabric_domain_id: Uuid::from_u128(990),
            network_external_realm_id: None,
            public_allocator: None,
            reconciliation_locks: Arc::new(std::sync::Mutex::new(BTreeMap::new())),
        };
        recover_fabric_state(&restarted_reconciler, store.as_ref()).await;
        assert_eq!(
            store.get_network_plan_work(successor_id).await?.state,
            o3k_store::NetworkPlanWorkState::Succeeded,
            "successor controller must observe and terminalize the admitted command"
        );
        assert_eq!(
            store.list_unresolved_network_plan_work().await?.len(),
            0,
            "observation should settle the existing successor without another work row"
        );
        assert_eq!(
            removals.load(std::sync::atomic::Ordering::Acquire),
            1,
            "controller restart must not repeat the provider mutation"
        );
        server.abort();
        let _ = server.await;
        let _ = std::fs::remove_dir_all(root);
        Ok(())
    }

    #[tokio::test]
    async fn production_mtls_agent_takeover_rejects_stale_controller_after_restart()
    -> Result<(), Box<dyn std::error::Error>> {
        let root = std::env::temp_dir().join(format!("o3kd-mtls-fencing-{}", Uuid::now_v7()));
        std::fs::create_dir_all(&root)?;
        let store = Arc::new(o3k_store::unified::O3kStore::connect_sqlite_memory().await?);
        let historical = durable_removal_command(store.as_ref()).await?;
        let command: o3k_network::NetworkPlanCommand =
            serde_json::from_slice(&historical.snapshot)?;
        let controller_a = o3k_store::ControllerId::new("controller-a");
        let epoch_a = o3k_store::ControllerEpoch::new("epoch-a");
        let realm_key = format!("fabric-realm:{}", Uuid::from_u128(800));
        let realm_lease = match store
            .acquire_work_lease(
                &realm_key,
                "fabric_reconciliation",
                &controller_a,
                &epoch_a,
                FABRIC_REALM_LEASE_TTL,
            )
            .await?
        {
            o3k_store::LeaseAcquireOutcome::Acquired { lease } => lease,
            o3k_store::LeaseAcquireOutcome::Busy { .. } => {
                return Err("test realm unexpectedly busy".into());
            }
        };
        let realizer = MtlSRecoveryRealizer::default();
        let removals = realizer.removals.clone();
        let realizations = realizer.realizations.clone();
        let journal_root = root.join("agent-journal");
        let executor = o3k_network::NetworkPlanExecutor::open(
            &journal_root,
            o3k_network::NetworkAgentIdentity {
                agent_id: "agent-c".to_owned(),
                agent_epoch: "epoch-1".to_owned(),
            },
            o3k_network::NetworkControllerLease {
                controller_id: String::new(),
                controller_epoch: String::new(),
                fencing_token: 0,
            },
        )?;
        let service =
            o3k_network_bin::agent::NetworkAgentService::new_dynamic(executor, realizer.clone())?;
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await?;
        let address = listener.local_addr()?;
        let server = start_mtls_network_agent(listener, service).await?;
        let dispatcher_a =
            mtls_dispatcher_as(address, store.clone(), "controller-a", "epoch-a", None);
        assert_eq!(
            dispatcher_a
                .dispatch_existing_successor(command, historical.command_id.clone())
                .await?,
            o3k_network::NetworkPlanStatus::Succeeded
        );
        assert!(
            store
                .relinquish_work_lease_preserving_fence(
                    &realm_key,
                    &controller_a,
                    &epoch_a,
                    realm_lease.fencing_token,
                )
                .await?
        );

        // Controller B acquires a strictly higher network-agent fence using
        // the concrete target-aware dispatcher and observes the completed
        // command over mTLS, without restarting the agent.
        let dispatcher_b =
            mtls_dispatcher_as(address, store.clone(), "controller-b", "epoch-b", None);
        let target = o3k_network::NetworkAgentIdentity {
            agent_id: "agent-c".to_owned(),
            agent_epoch: "epoch-1".to_owned(),
        };
        assert_eq!(
            dispatcher_b
                .observe_command(
                    "compute-c",
                    target.clone(),
                    Uuid::parse_str(&historical.command_id)?
                )
                .await?,
            Some(o3k_network::NetworkPlanStatus::Succeeded)
        );

        let realm_key = format!("fabric-realm:{}", Uuid::from_u128(800));
        let controller_b = o3k_store::ControllerId::new("controller-b");
        let epoch_b = o3k_store::ControllerEpoch::new("epoch-b");
        let realm_lease_b = match store
            .acquire_work_lease(
                &realm_key,
                "fabric_reconciliation",
                &controller_b,
                &epoch_b,
                FABRIC_REALM_LEASE_TTL,
            )
            .await?
        {
            o3k_store::LeaseAcquireOutcome::Acquired { lease } => lease,
            o3k_store::LeaseAcquireOutcome::Busy { .. } => {
                return Err("controller B could not acquire realm lease".into());
            }
        };
        let mut current_command: o3k_network::NetworkPlanCommand =
            serde_json::from_slice(&historical.snapshot)?;
        current_command.command_id = Uuid::now_v7();
        current_command.operation_id = Uuid::now_v7();
        current_command.action = o3k_network::NetworkPlanAction::Apply;
        current_command.idempotency_key = format!("takeover-apply:{}", current_command.command_id);
        current_command.plan.operation_id = current_command.operation_id;
        current_command.plan.fingerprint_sha256 =
            o3k_network::canonical_plan_fingerprint(&current_command.plan)?;
        assert_eq!(
            dispatcher_b.dispatch(current_command.clone()).await?,
            o3k_network::NetworkPlanStatus::Succeeded,
            "the current B authority must admit a real mutation through the target-aware dispatcher"
        );
        assert_eq!(realizations.load(std::sync::atomic::Ordering::Acquire), 1);

        let old_client = o3k_network_protocol::NetworkAgentClient::connect(
            &format!("https://{address}"),
            "o3k-control-plane",
            network_fixture("ca.pem"),
            network_fixture("agent-chain.pem"),
            network_fixture("agent-key-pkcs8.pem"),
        )
        .await?;
        let stale_request = old_client
            .execute_with_lease(
                o3k_network_protocol::proto::Register {
                    agent_id: target.agent_id.clone(),
                    agent_epoch: target.agent_epoch.clone(),
                },
                o3k_network_protocol::proto::NetworkCommand {
                    command_id: Uuid::now_v7().to_string(),
                    operation_id: Uuid::now_v7().to_string(),
                    idempotency_key: "stale-controller-mutation".to_owned(),
                    agent_id: target.agent_id.clone(),
                    agent_epoch: target.agent_epoch.clone(),
                    controller_id: "controller-a".to_owned(),
                    controller_epoch: "epoch-a".to_owned(),
                    fencing_token: 1,
                    deadline_unix_ms: super::super::unix_time_millis() + 60_000,
                    plan_json: serde_json::to_string(&current_command.plan)?,
                    remove: true,
                },
                Some(o3k_network_protocol::proto::ControllerLease {
                    controller_id: "controller-a".to_owned(),
                    controller_epoch: "epoch-a".to_owned(),
                    fencing_token: 1,
                    lease_expiry_unix_ms: super::super::unix_time_millis() + 60_000,
                }),
            )
            .await;
        assert!(
            stale_request.is_err(),
            "agent must reject a later stale controller mutation over mTLS"
        );
        assert_eq!(
            removals.load(std::sync::atomic::Ordering::Acquire),
            1,
            "stale mutation must not reach the provider after B takeover"
        );
        assert!(
            store
                .relinquish_work_lease_preserving_fence(
                    &realm_key,
                    &controller_b,
                    &epoch_b,
                    realm_lease_b.fencing_token,
                )
                .await?
        );

        server.abort();
        let _ = server.await;
        let restarted_executor = o3k_network::NetworkPlanExecutor::open(
            &journal_root,
            target.clone(),
            o3k_network::NetworkControllerLease {
                controller_id: String::new(),
                controller_epoch: String::new(),
                fencing_token: 0,
            },
        )?;
        let restarted_service =
            o3k_network_bin::agent::NetworkAgentService::new_dynamic(restarted_executor, realizer)?;
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await?;
        let address = listener.local_addr()?;
        let restarted_server = start_mtls_network_agent(listener, restarted_service).await?;
        let restarted_dispatcher_b =
            mtls_dispatcher_as(address, store.clone(), "controller-b", "epoch-b", None);
        assert_eq!(
            restarted_dispatcher_b
                .observe_command(
                    "compute-c",
                    target.clone(),
                    Uuid::parse_str(&historical.command_id)?,
                )
                .await?,
            Some(o3k_network::NetworkPlanStatus::Succeeded)
        );
        let stale_after_restart = o3k_network_protocol::NetworkAgentClient::connect(
            &format!("https://{address}"),
            "o3k-control-plane",
            network_fixture("ca.pem"),
            network_fixture("agent-chain.pem"),
            network_fixture("agent-key-pkcs8.pem"),
        )
        .await?
        .observe_with_lease(
            o3k_network_protocol::proto::Register {
                agent_id: target.agent_id,
                agent_epoch: target.agent_epoch,
            },
            o3k_network_protocol::proto::ControllerLease {
                controller_id: "controller-a".to_owned(),
                controller_epoch: "epoch-a".to_owned(),
                fencing_token: 1,
                lease_expiry_unix_ms: super::super::unix_time_millis() + 60_000,
            },
            historical.command_id,
        )
        .await;
        assert!(stale_after_restart.is_err());
        assert_eq!(
            removals.load(std::sync::atomic::Ordering::Acquire),
            1,
            "agent restart and takeover must not duplicate the provider mutation"
        );
        restarted_server.abort();
        let _ = restarted_server.await;
        let _ = std::fs::remove_dir_all(root);
        Ok(())
    }
}

#[async_trait]
impl o3k_compute::PortBindingProjector for NetworkBindingProjector {
    async fn project_create_outcome(
        &self,
        project_id: &str,
        port_id: &str,
        succeeded: bool,
    ) -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
        let port_id = port_id.parse::<Uuid>().map_err(|error| {
            std::io::Error::new(
                std::io::ErrorKind::InvalidInput,
                format!("invalid port id {port_id:?}: {error}"),
            )
        })?;
        // Every terminal outcome and terminal unbind share the same durable
        // binding. Keep the dispatch/projection sequence in the same
        // single-flight boundary as unbind so they cannot cross between the
        // binding read and intent update.
        let _guard = self.unbind_lock.lock().await;
        let state = if succeeded {
            o3k_network::PortBindingState::Bound
        } else {
            o3k_network::PortBindingState::Error
        };
        if succeeded {
            self.dispatch_unbound_port(project_id, port_id).await?;
        }
        self.network
            .project_create_outcome(project_id, port_id, state)
            .await
            .map(|_| ())
            .map_err(|error| std::io::Error::other(error.to_string()))?;
        Ok(())
    }

    async fn unbind_port(
        &self,
        project_id: &str,
        port_id: &str,
        operation_id: uuid::Uuid,
    ) -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
        let port_id = port_id.parse::<Uuid>().map_err(|error| {
            std::io::Error::new(
                std::io::ErrorKind::InvalidInput,
                format!("invalid port id {port_id:?}: {error}"),
            )
        })?;
        let _guard = self.unbind_lock.lock().await;
        let port = match self.network.get_port_for_project(project_id, port_id).await {
            Ok(port) => port,
            // A concurrent equivalent server delete can finish releasing a
            // server-owned endpoint before this request reaches its unbind
            // seat. The endpoint's absence is already the desired terminal
            // state, so do not turn an idempotent delete replay into HTTP 500.
            // Other lookup failures still fail closed.
            Err(o3k_network::NetworkError::NotFound) => return Ok(()),
            Err(error) => return Err(std::io::Error::other(error.to_string()).into()),
        };
        let v3_reconciler = self.fabric_reconciler.as_ref();
        if v3_reconciler.is_none()
            && let (Some(dispatcher), Some(host)) = (
                self.network_dispatcher.as_ref(),
                port.binding_host.as_deref(),
            )
        {
            let agent = if let Some(configured) = self.network_agent.as_ref() {
                if configured.agent_id != host {
                    return Err(
                        std::io::Error::other("bound network agent identity changed").into(),
                    );
                }
                configured.clone()
            } else {
                let snapshot =
                    self.registry.snapshot(host).await.ok_or_else(|| {
                        std::io::Error::other("network agent snapshot unavailable")
                    })?;
                o3k_network::NetworkAgentIdentity {
                    agent_id: snapshot.agent_id,
                    agent_epoch: snapshot.agent_epoch,
                }
            };
            let subnet_id = port
                .subnet_id
                .ok_or_else(|| std::io::Error::other("bound port has no subnet"))?;
            let subnet = self
                .network
                .get_subnet_for_project(project_id, subnet_id)
                .await
                .map_err(|error| std::io::Error::other(error.to_string()))?;
            let external_realm_route_id = self.resolve_external_realm_route_id(project_id).await?;
            let deadline_unix_ms = super::unix_time_millis().saturating_add(30_000);
            let plan = o3k_network::compile_attachment_plan(o3k_network::AttachmentPlanInput {
                endpoint_id: port.id,
                realm_id: port.network_id,
                project_id,
                mac: &port.mac_address,
                fixed_ip: port.fixed_ip,
                subnet_cidr: &subnet.cidr,
                node_id: host,
                operation_id,
                deadline_unix_ms,
                public_address: None,
                external_realm_id: external_realm_route_id,
                // Removal must remain stable while Terraform/OpenStack
                // destroys policy resources concurrently.  The agent removes
                // the endpoint-scoped realization; including a mutable policy
                // snapshot here would reuse the deterministic remove command
                // with a different fingerprint and be rejected as a replay.
                policies: Vec::new(),
            })
            .map_err(|error| std::io::Error::other(error.to_string()))?;
            let command_id = Uuid::new_v5(
                &Uuid::NAMESPACE_URL,
                format!("o3k:network:remove-command:{operation_id}:{port_id}").as_bytes(),
            );
            let status = dispatcher
                .dispatch(o3k_network::NetworkPlanCommand {
                    command_id,
                    operation_id,
                    idempotency_key: format!(
                        "o3k:network:remove:{project_id}:{port_id}:{operation_id}"
                    ),
                    action: o3k_network::NetworkPlanAction::Remove,
                    target: agent,
                    controller: self.network_controller.clone(),
                    deadline_unix_ms,
                    plan,
                })
                .await
                .map_err(|error| std::io::Error::other(error.to_string()))?;
            if status != o3k_network::NetworkPlanStatus::Succeeded {
                return Err(std::io::Error::other(
                    "network removal requires observation before unbinding",
                )
                .into());
            }
        }
        if let (Some(host), Some(reconciler)) = (port.binding_host.as_deref(), v3_reconciler) {
            // Keep the selected host durable as a down tombstone until every
            // affected realm plan has converged. A retry can therefore still
            // identify and withdraw the departing host after an unknown
            // dispatch outcome or controller restart.
            if port.binding_state.as_deref() != Some("down") {
                self.network
                    .advance_fabric_realm_generation(project_id, port.network_id)
                    .await
                    .map_err(|error| std::io::Error::other(error.to_string()))?;
                self.network
                    .project_binding_observation(project_id, port_id, host, "down")
                    .await
                    .map_err(|error| std::io::Error::other(error.to_string()))?;
            }
            reconciler
                .reconcile_realm_after_unbind(
                    project_id,
                    port.network_id,
                    operation_id,
                    super::unix_time_millis().saturating_add(30_000),
                    host,
                )
                .await
                .map_err(std::io::Error::other)?;
        }
        match self.network.unbind_port(project_id, port_id).await {
            Ok(_) | Err(o3k_network::NetworkError::NotFound) => {}
            Err(error) => return Err(std::io::Error::other(error.to_string()).into()),
        }
        Ok(())
    }

    /// Releases the endpoint once its binding is cleared and its server is
    /// terminally deleted. Only an endpoint carrying O3K's reserved
    /// server-owned identity is removed: a port the caller created and supplied
    /// itself is preserved, and so is a port of any other project. An endpoint
    /// that is already gone is success.
    ///
    /// The counts are projected into the compute boundary's report type so the
    /// #1035 orphan repair sweep can log exactly what it discovered and
    /// repaired; the ownership decision itself stays in the network service.
    async fn release_server_owned_endpoint(
        &self,
        project_id: &str,
        port_id: &str,
    ) -> Result<o3k_compute::ServerEndpointRelease, Box<dyn std::error::Error + Send + Sync>> {
        let port_id = port_id.parse::<Uuid>().map_err(|error| {
            std::io::Error::new(
                std::io::ErrorKind::InvalidInput,
                format!("invalid port id {port_id:?}: {error}"),
            )
        })?;
        let report = self
            .network
            .cleanup_server_owned_ports_for_project(project_id, &[port_id])
            .await
            .map_err(|error| std::io::Error::other(error.to_string()))?;
        Ok(o3k_compute::ServerEndpointRelease {
            discovered: report.discovered,
            released: report.released,
            preserved: report.preserved,
            absent: report.absent,
        })
    }

    async fn port_binding(
        &self,
        project_id: &str,
        port_id: &str,
    ) -> Result<Option<o3k_compute::PortBindingInfo>, Box<dyn std::error::Error + Send + Sync>>
    {
        let port_id = port_id.parse::<Uuid>().map_err(|error| {
            std::io::Error::new(
                std::io::ErrorKind::InvalidInput,
                format!("invalid port id {port_id:?}: {error}"),
            )
        })?;
        let port = match self.network.get_port_for_project(project_id, port_id).await {
            Ok(port) => port,
            Err(o3k_network::NetworkError::NotFound) => return Ok(None),
            Err(error) => return Err(std::io::Error::other(error.to_string()).into()),
        };
        Ok(Some(o3k_compute::PortBindingInfo {
            server_owned: o3k_network::is_server_owned_endpoint_name(project_id, &port.name),
            binding_state: port.binding_state,
        }))
    }
}

impl NetworkBindingProjector {
    /// The agent-provider resolver dispatches before compute mutation.  Other
    /// providers (notably the portable fake/TestLab provider) complete the
    /// server operation without that resolver, so the terminal binding
    /// projection is the safe point at which to admit their network plan.
    /// This is deliberately limited to an explicitly configured network
    /// agent; without one, the historical binding projection remains a
    /// control-plane-only observation.
    async fn dispatch_unbound_port(
        &self,
        project_id: &str,
        port_id: Uuid,
    ) -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
        let Some(dispatcher) = self.network_dispatcher.as_ref() else {
            return Ok(());
        };
        let Some(agent) = self.network_agent.as_ref() else {
            return Ok(());
        };
        let port = self
            .network
            .get_port_for_project(project_id, port_id)
            .await
            .map_err(|error| std::io::Error::other(error.to_string()))?;
        // `down` is a durable explicit-unbind tombstone.  Do not recreate a
        // host-side binding from a late compute-create callback after the
        // server has already been deleted.
        if port.binding_host.is_some() || port.binding_state.as_deref() == Some("down") {
            return Ok(());
        }
        let subnet_id = port
            .subnet_id
            .ok_or_else(|| std::io::Error::other("network port has no subnet"))?;
        let subnet = self
            .network
            .get_subnet_for_project(project_id, subnet_id)
            .await
            .map_err(|error| std::io::Error::other(error.to_string()))?;
        self.network
            .record_binding_intent(project_id, port_id, &agent.agent_id)
            .await
            .map_err(|error| std::io::Error::other(error.to_string()))?;
        let external_realm_route_id = self.resolve_external_realm_route_id(project_id).await?;
        let policies = self
            .network
            .list_policies_for_project(project_id, port.network_id)
            .await
            .map_err(|error| std::io::Error::other(error.to_string()))?
            .into_iter()
            .filter(|policy| policy.endpoint_id == port.id)
            .collect();
        let policy_defaults = self
            .network
            .policy_defaults_for_endpoint(project_id, port.id)
            .await
            .map_err(|error| std::io::Error::other(error.to_string()))?;
        let public_address = self
            .public_allocator
            .as_ref()
            .map(|allocator| {
                allocator
                    .list(project_id)
                    .map_err(|error| std::io::Error::other(error.to_string()))
            })
            .transpose()?
            .and_then(|bindings| {
                bindings
                    .into_iter()
                    .find(|binding| binding.endpoint_id == Some(port.id))
                    .map(|binding| binding.public_address)
            });
        let operation_id = Uuid::new_v5(
            &Uuid::NAMESPACE_URL,
            format!("o3k:network:terminal-binding:{project_id}:{port_id}").as_bytes(),
        );
        let deadline_unix_ms = super::unix_time_millis().saturating_add(30_000);
        let plan = o3k_network::compile_attachment_plan_with_defaults(
            o3k_network::AttachmentPlanInput {
                endpoint_id: port.id,
                realm_id: port.network_id,
                project_id,
                mac: &port.mac_address,
                fixed_ip: port.fixed_ip,
                subnet_cidr: &subnet.cidr,
                node_id: &agent.agent_id,
                operation_id,
                deadline_unix_ms,
                public_address,
                external_realm_id: external_realm_route_id,
                policies,
            },
            policy_defaults,
        )
        .map_err(|error| std::io::Error::other(error.to_string()))?;
        let command_id = Uuid::new_v5(
            &Uuid::NAMESPACE_URL,
            format!("o3k:network:terminal-binding-command:{operation_id}").as_bytes(),
        );
        let status = dispatcher
            .dispatch(o3k_network::NetworkPlanCommand {
                command_id,
                operation_id,
                idempotency_key: format!("o3k:network:terminal-binding:{project_id}:{port_id}"),
                action: o3k_network::NetworkPlanAction::Apply,
                target: agent.clone(),
                controller: self.network_controller.clone(),
                deadline_unix_ms,
                plan,
            })
            .await
            .map_err(|error| std::io::Error::other(error.to_string()))?;
        if status != o3k_network::NetworkPlanStatus::Succeeded {
            return Err(std::io::Error::other(
                "network binding requires observed provider success",
            )
            .into());
        }
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::select_active_external_realm;
    use o3k_store::CanonicalAddressRealmRecord;
    use uuid::Uuid;

    fn realm(id: u128, state: &str) -> CanonicalAddressRealmRecord {
        CanonicalAddressRealmRecord {
            id: Uuid::from_u128(id),
            network_id: Uuid::from_u128(100),
            project_id: "project".to_owned(),
            prefix: "198.51.100.0/24".to_owned(),
            overlapping_prefixes: false,
            generation: 1,
            state: state.to_owned(),
        }
    }

    #[test]
    fn external_realm_selection_requires_exactly_one_active_realm() {
        let records = [realm(1, "active"), realm(2, "retired")];
        assert_eq!(
            select_active_external_realm(&records),
            Ok(Uuid::from_u128(1))
        );
    }

    #[test]
    fn external_realm_selection_fails_closed_without_active_realm() {
        assert_eq!(
            select_active_external_realm(&[realm(1, "retired")]),
            Err("configured external network has no active canonical AddressRealm")
        );
    }

    #[test]
    fn external_realm_selection_fails_closed_on_ambiguity() {
        assert_eq!(
            select_active_external_realm(&[realm(1, "active"), realm(2, "active")]),
            Err("configured external network has multiple active canonical AddressRealms")
        );
    }
}
