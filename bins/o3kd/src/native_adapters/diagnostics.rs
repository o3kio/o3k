//! Production `o3kd` projection of canonical O3K diagnostics (#903).
//!
//! This adapter implements the bounded, read-only [`DiagnosticsReader`] port
//! by projecting canonical authority only:
//!
//! - services   -> shared lifecycle [`ManifestRegistry`];
//! - providers  -> agent [`AgentNodeRegistry`] + durable placement store;
//! - capacity   -> placement store capacity aggregate + agent observation clock;
//! - control-plane liveness -> coordination store `controller_sessions`;
//! - locations  -> canonical [`LocationRegistry`] (topology only).
//!
//! It never forwards node identity, agent epoch, capabilities, provider
//! secrets/connection strings, controller service principals, session ids,
//! manifest digests, or raw provider/controller error text. Freshness is a
//! first-class property: a stale or never-observed source is never reported
//! as `healthy`.

use std::collections::HashMap;
use std::sync::{Arc, RwLock};
use std::time::{SystemTime, UNIX_EPOCH};

use o3k_kernel::{ControllerRegistration, ControllerState, ManifestRegistry};
use o3k_native_api::diagnostics::{
    CapacityDiagnostics, CapacityDimension, ComponentCounts, ControlPlaneStatus,
    ControllerDiagnostics, DIAGNOSTICS_VERSION, DiagnosticReason, DiagnosticStatus,
    DiagnosticsError, DiagnosticsPage, DiagnosticsReader, DiagnosticsSummary, LocationDiagnostics,
    MAX_CAPACITY_CLASSES, ProviderCapacityDimension, ProviderDiagnostics, ServiceDiagnostics,
    StatusCounts, encode_cursor, sort_dimensions, validate_capacity_class_count,
};
use o3k_provider::{
    AgentAdministrativeState, AgentAvailability, AgentNodeRegistry, AgentNodeSnapshot,
};
use o3k_store::unified::O3kStore;
use o3k_store::{CoordinationRepository, PlacementRepository, StoreError};

/// Lease horizon for agent heartbeats. An agent whose last authenticated
/// heartbeat is older than this is projected as `stale`, never `healthy`.
pub const AGENT_LEASE_MS: i64 = 15_000;

/// Upper bound on the number of services projected in one pass. Service
/// collections are registry-backed (process-internal and small). The bound is
/// enforced fail-closed: a registry exceeding it yields a corrupt-state error
/// rather than a silently truncated projection.
pub const MAX_SERVICES: usize = 256;

/// Freshness threshold for external-controller observation. The composition
/// probe re-checks external controllers every 15s; a controller whose last
/// confirmed observation is older than five probe intervals must not be
/// reported healthy. In-process services are configuration-authoritative and
/// are intentionally exempt from this gate.
pub const SERVICE_OBSERVATION_THRESHOLD_MS: i64 = 75_000;

/// Upper bound on the provider fleet the aggregate projection will read in one
/// pass. Provider fleets are the set of hypervisors (bounded by the placement
/// authority); the aggregate fails closed above this bound rather than
/// truncating. A fleet larger than this is itself a scale anomaly.
pub const MAX_PROVIDERS: usize = 65_536;

/// Unix milliseconds since the UNIX epoch. Falls back to `0` only if the
/// system clock precedes the epoch, which cannot happen on supported hosts.
pub(crate) fn now_unix_ms() -> i64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map_or(0, |duration| duration.as_millis() as i64)
}

fn availability_str(availability: AgentAvailability) -> &'static str {
    match availability {
        AgentAvailability::Available => "available",
        AgentAvailability::Unavailable => "unavailable",
    }
}

/// Provider status precedence, from most to least severe. This ordering is the
/// authority for both the per-provider list and the summary count and must
/// never report a provider as `healthy` from durable placement state alone:
///
/// 1. no agent snapshot        -> Unknown / NeverObserved (restart before
///    re-observation is never reported healthy from durable state);
/// 2. agent administratively Disabled -> Unavailable / AdministrativelyDisabled;
/// 3. durable state `Deleted`  -> Unavailable / AdministrativelyDisabled;
/// 4. durable `Draining` or agent Draining -> Degraded / Draining;
/// 5. agent Unavailable        -> Stale / HeartbeatLost when the last
///    heartbeat is older than the lease, else Unavailable / HeartbeatLost;
/// 6. last heartbeat stale     -> Stale / ObservationStale;
/// 7. durable state `Unavailable` (scheduler out-of-service) while the agent
///    reports healthy -> Unavailable / AdministrativelyDisabled (the durable
///    authority dominates a healthy-looking agent);
/// 8. unrecognized durable state (corrupt authority) -> Unknown / no reason
///    (mirrors the store's corrupt-state handling; never reported healthy);
/// 9. live snapshot with no observation time -> Unknown / NeverObserved (the
///    registry could not supply a timestamp; never reported healthy);
/// 10. otherwise                -> Healthy.
#[allow(clippy::needless_pass_by_value)]
fn provider_status(
    snap: Option<&AgentNodeSnapshot>,
    record_state: &str,
    observed: Option<i64>,
    now: i64,
) -> (DiagnosticStatus, Option<DiagnosticReason>) {
    let Some(snap) = snap else {
        return (
            DiagnosticStatus::Unknown,
            Some(DiagnosticReason::NeverObserved),
        );
    };
    if snap.administrative_state == AgentAdministrativeState::Disabled {
        return (
            DiagnosticStatus::Unavailable,
            Some(DiagnosticReason::AdministrativelyDisabled),
        );
    }
    if record_state == "Deleted" {
        return (
            DiagnosticStatus::Unavailable,
            Some(DiagnosticReason::AdministrativelyDisabled),
        );
    }
    if record_state == "Draining" || snap.administrative_state == AgentAdministrativeState::Draining
    {
        return (DiagnosticStatus::Degraded, Some(DiagnosticReason::Draining));
    }
    if snap.availability == AgentAvailability::Unavailable {
        if observed.is_some_and(|observed| now - observed > AGENT_LEASE_MS) {
            return (
                DiagnosticStatus::Stale,
                Some(DiagnosticReason::HeartbeatLost),
            );
        }
        return (
            DiagnosticStatus::Unavailable,
            Some(DiagnosticReason::HeartbeatLost),
        );
    }
    if observed.is_some_and(|observed| now - observed > AGENT_LEASE_MS) {
        return (
            DiagnosticStatus::Stale,
            Some(DiagnosticReason::ObservationStale),
        );
    }
    // A durable out-of-service state is authoritative even when the agent
    // currently reports healthy (e.g. operator drain via set_state).
    if record_state == "Unavailable" {
        return (
            DiagnosticStatus::Unavailable,
            Some(DiagnosticReason::AdministrativelyDisabled),
        );
    }
    // Any durable state outside the four canonical values is corrupt; never
    // report it healthy (mirrors capacity_summary's corrupt-state handling).
    if !matches!(
        record_state,
        "Enabled" | "Draining" | "Unavailable" | "Deleted"
    ) {
        return (DiagnosticStatus::Unknown, None);
    }
    // A live snapshot with no observation time cannot be confirmed fresh.
    // The `AgentNodeRegistry` contract is explicit: a registry that cannot
    // supply an observation time returns `None`, which is projected as
    // `unknown` — never as `healthy`.
    if observed.is_none() {
        return (
            DiagnosticStatus::Unknown,
            Some(DiagnosticReason::NeverObserved),
        );
    }
    (DiagnosticStatus::Healthy, None)
}

/// Service status mapping from the canonical controller lifecycle state.
fn service_status(state: ControllerState) -> (DiagnosticStatus, Option<DiagnosticReason>) {
    match state {
        ControllerState::Ready => (DiagnosticStatus::Healthy, None),
        ControllerState::NotReady => (
            DiagnosticStatus::Unavailable,
            Some(DiagnosticReason::ReadinessFailed),
        ),
        ControllerState::Incompatible => (
            DiagnosticStatus::Degraded,
            Some(DiagnosticReason::ProtocolIncompatible),
        ),
        ControllerState::Disabled => (
            DiagnosticStatus::Unavailable,
            Some(DiagnosticReason::AdministrativelyDisabled),
        ),
        ControllerState::Declared => (
            DiagnosticStatus::Unknown,
            Some(DiagnosticReason::NeverObserved),
        ),
    }
}

/// Service status including the observation-freshness gate for external
/// controllers.
///
/// In-process services are process-authoritative configuration: their
/// readiness is a fact of the running composition, not an observation, so it
/// cannot go stale here. External controllers are observation-probed; a
/// controller that last reported Ready but has not been re-confirmed within
/// the freshness threshold must be projected as `stale`, never as a
/// last-known-good `healthy`.
fn service_status_with_freshness(
    registration: &ControllerRegistration,
    observed_at: i64,
    now: i64,
) -> (DiagnosticStatus, Option<DiagnosticReason>) {
    let (status, reason) = service_status(registration.state);
    let is_external = registration.session.is_some();
    if is_external
        && status == DiagnosticStatus::Healthy
        && now.saturating_sub(observed_at) > SERVICE_OBSERVATION_THRESHOLD_MS
    {
        return (
            DiagnosticStatus::Stale,
            Some(DiagnosticReason::ObservationStale),
        );
    }
    (status, reason)
}

/// Tolerant parsing of a control-plane heartbeat timestamp: RFC3339 first,
/// then the SQLite `datetime('now')` `%Y-%m-%d %H:%M:%S` (UTC) form. On
/// failure returns `None` (the heartbeat is not projected).
fn parse_timestamp(value: &str) -> Option<i64> {
    if let Ok(dt) = chrono::DateTime::parse_from_rfc3339(value) {
        return Some(dt.timestamp_millis());
    }
    if let Ok(naive) = chrono::NaiveDateTime::parse_from_str(value, "%Y-%m-%d %H:%M:%S") {
        return Some(naive.and_utc().timestamp_millis());
    }
    None
}

/// Canonical placement resource classes advertised by the contract. The
/// projection only exposes these placement-authoritative dimensions; any other
/// class stored in the durable authority is not advertised.
const CANONICAL_CAPACITY_CLASSES: [&str; 3] = ["VCPU", "MEMORY_MB", "DISK_GB"];

fn is_canonical_class(resource_class: &str) -> bool {
    CANONICAL_CAPACITY_CLASSES.contains(&resource_class)
}

/// Capacity unit label for a resource class.
fn unit_for(resource_class: &str) -> &'static str {
    match resource_class {
        "VCPU" => "count",
        "MEMORY_MB" => "mib",
        "DISK_GB" => "gib",
        _ => "count",
    }
}

/// Maps a durable store error to the bounded diagnostics error vocabulary.
fn map_store_error(error: StoreError) -> DiagnosticsError {
    match error {
        StoreError::Corrupt(_) => DiagnosticsError::Corrupt,
        _ => DiagnosticsError::Unavailable,
    }
}

fn map_capacity_store_error(operation: &'static str, error: StoreError) -> DiagnosticsError {
    let error_kind = if matches!(error, StoreError::Corrupt(_)) {
        "corrupt"
    } else {
        "store"
    };
    tracing::error!(
        event = "operator_diagnostics_capacity_store_failure",
        operation,
        error_kind,
        "capacity diagnostics store operation failed"
    );
    map_store_error(error)
}

/// Worst-wins combination of two component-class aggregate statuses.
fn worst_status(left: DiagnosticStatus, right: DiagnosticStatus) -> DiagnosticStatus {
    fn rank(status: DiagnosticStatus) -> u8 {
        match status {
            DiagnosticStatus::Unavailable => 5,
            DiagnosticStatus::Degraded => 4,
            DiagnosticStatus::Stale => 3,
            DiagnosticStatus::Unknown => 2,
            DiagnosticStatus::Healthy => 1,
        }
    }
    if rank(left) >= rank(right) {
        left
    } else {
        right
    }
}

/// Production adapter that projects canonical O3K authority into the operator
/// diagnostics contract.
pub struct DiagnosticsReaderAdapter {
    registry: Arc<RwLock<ManifestRegistry>>,
    agents: Arc<dyn AgentNodeRegistry>,
    store: Arc<O3kStore>,
    locations: o3k_kernel::LocationRegistry,
    started_at_unix_ms: i64,
    observations: Arc<RwLock<HashMap<String, i64>>>,
}

impl DiagnosticsReaderAdapter {
    /// Creates a new adapter. Observations start empty; every service is
    /// treated as observed at process start until the composition probe task
    /// records a fresh timestamp.
    #[must_use]
    pub fn new(
        registry: Arc<RwLock<ManifestRegistry>>,
        agents: Arc<dyn AgentNodeRegistry>,
        store: Arc<O3kStore>,
        locations: o3k_kernel::LocationRegistry,
    ) -> Self {
        Self {
            registry,
            agents,
            store,
            locations,
            started_at_unix_ms: now_unix_ms(),
            observations: Arc::new(RwLock::new(HashMap::new())),
        }
    }

    /// Exposes the shared service-observation map to the composition probe
    /// task, which writes fresh observation timestamps for every controller.
    pub fn observations(&self) -> Arc<RwLock<HashMap<String, i64>>> {
        self.observations.clone()
    }

    fn service_observed_at(&self, service_id: &str) -> i64 {
        self.observations
            .read()
            .ok()
            .and_then(|observations| observations.get(service_id).copied())
            .unwrap_or(self.started_at_unix_ms)
    }

    async fn control_plane_status(&self) -> ControlPlaneStatus {
        let sessions = match self.store.list_active_controller_sessions().await {
            Ok(sessions) => sessions,
            Err(_) => {
                // The coordination authority could not be read, not "never
                // observed" — report it as an unavailable dependency.
                return ControlPlaneStatus {
                    status: DiagnosticStatus::Unavailable,
                    active_sessions: 0,
                    observed_at_unix_ms: None,
                    reason: Some(DiagnosticReason::DependencyUnavailable),
                };
            }
        };
        let active_sessions = sessions.len() as u64;
        let observed_at_unix_ms = sessions
            .iter()
            .filter_map(|session| parse_timestamp(&session.heartbeat_at))
            .max();
        if active_sessions > 0 {
            ControlPlaneStatus {
                status: DiagnosticStatus::Healthy,
                active_sessions,
                observed_at_unix_ms,
                reason: None,
            }
        } else {
            ControlPlaneStatus {
                status: DiagnosticStatus::Unavailable,
                active_sessions,
                observed_at_unix_ms,
                reason: Some(DiagnosticReason::NeverObserved),
            }
        }
    }
}

#[async_trait::async_trait]
impl DiagnosticsReader for DiagnosticsReaderAdapter {
    async fn summary(&self) -> Result<DiagnosticsSummary, DiagnosticsError> {
        let now = now_unix_ms();

        // Services: iterate the registry directly (bounded, process-internal)
        // and count by projected status. This deliberately does not call
        // `services()` with pagination. The bound is enforced fail-closed.
        let mut services = ComponentCounts::default();
        {
            let reg = self
                .registry
                .read()
                .map_err(|_| DiagnosticsError::Corrupt)?;
            if reg.all().len() > MAX_SERVICES {
                return Err(DiagnosticsError::Corrupt);
            }
            for manifest in reg.all() {
                let (status, _) = reg
                    .controller(&manifest.service_id)
                    .map(|registration| {
                        service_status_with_freshness(
                            registration,
                            self.service_observed_at(&manifest.service_id),
                            now,
                        )
                    })
                    .unwrap_or((
                        DiagnosticStatus::Unknown,
                        Some(DiagnosticReason::NeverObserved),
                    ));
                services.total += 1;
                match status {
                    DiagnosticStatus::Healthy => services.healthy += 1,
                    DiagnosticStatus::Degraded => services.degraded += 1,
                    DiagnosticStatus::Unavailable => services.unavailable += 1,
                    DiagnosticStatus::Stale => services.stale += 1,
                    DiagnosticStatus::Unknown => services.unknown += 1,
                }
            }
        }

        // Providers: iterate the durable placement provider set (the
        // authority for "which providers exist") and overlay agent liveness,
        // so a durably draining/deleted provider is never reported healthy.
        // This mirrors `providers()` exactly; the durable state list is a
        // lightweight id+state read and the agent registry is in-memory.
        let agents = self.agents.all().await;
        let mut agent_map: HashMap<&str, (&AgentNodeSnapshot, Option<i64>)> = HashMap::new();
        for agent in &agents {
            let observed = self.agents.observed_at_unix_ms(&agent.agent_id).await;
            agent_map.insert(agent.agent_id.as_str(), (agent, observed));
        }
        let states = self
            .store
            .list_provider_states(None, MAX_PROVIDERS + 1)
            .await
            .map_err(map_store_error)?;
        if states.len() > MAX_PROVIDERS {
            // The provider aggregate would exceed the fleet bound; fail closed
            // rather than silently truncate the aggregate.
            return Err(DiagnosticsError::Corrupt);
        }
        let mut providers = ComponentCounts::default();
        for record in &states {
            let (snap, observed) = agent_map
                .get(record.id.as_str())
                .map(|(snap, observed)| (Some(*snap), *observed))
                .unwrap_or((None, None));
            let (status, _) = provider_status(snap, &record.state, observed, now);
            providers.total += 1;
            match status {
                DiagnosticStatus::Healthy => providers.healthy += 1,
                DiagnosticStatus::Degraded => providers.degraded += 1,
                DiagnosticStatus::Unavailable => providers.unavailable += 1,
                DiagnosticStatus::Stale => providers.stale += 1,
                DiagnosticStatus::Unknown => providers.unknown += 1,
            }
        }

        let control_plane = self.control_plane_status().await;
        let locations = LocationDiagnostics {
            configured: !self.locations.is_empty(),
            regions: self.locations.len() as u64,
            availability_domains: self
                .locations
                .regions()
                .iter()
                .map(|region| region.availability_domains.len() as u64)
                .sum(),
        };

        let status = worst_status(services.aggregate(), providers.aggregate());

        Ok(DiagnosticsSummary {
            version: DIAGNOSTICS_VERSION.to_owned(),
            evaluated_at_unix_ms: now,
            status,
            counts: StatusCounts {
                services,
                providers,
            },
            control_plane: Some(control_plane),
            locations,
        })
    }

    async fn services(
        &self,
        limit: usize,
        after: Option<&str>,
    ) -> Result<DiagnosticsPage<ServiceDiagnostics>, DiagnosticsError> {
        let reg = self
            .registry
            .read()
            .map_err(|_| DiagnosticsError::Corrupt)?;
        if reg.all().len() > MAX_SERVICES {
            return Err(DiagnosticsError::Corrupt);
        }
        let now = now_unix_ms();
        let mut manifests = reg.all();
        manifests.sort_by(|left, right| left.service_id.cmp(&right.service_id));

        let mut items: Vec<ServiceDiagnostics> = Vec::with_capacity(limit + 1);
        for manifest in manifests
            .into_iter()
            .filter(|manifest| match after {
                Some(after) => manifest.service_id.as_str() > after,
                None => true,
            })
            .take(limit + 1)
        {
            let service_id = manifest.service_id.clone();
            let registration = reg.controller(&service_id);
            let lifecycle_state = reg
                .lifecycle_state(&service_id)
                .map_or_else(|| "declared".to_owned(), |state| state.to_string());
            let (status, reason) = registration
                .map(|registration| {
                    service_status_with_freshness(
                        registration,
                        self.service_observed_at(&manifest.service_id),
                        now,
                    )
                })
                .unwrap_or((
                    DiagnosticStatus::Unknown,
                    Some(DiagnosticReason::NeverObserved),
                ));
            let observed_at = Some(self.service_observed_at(&manifest.service_id));
            let controller = registration.map(|registration| {
                let manifest_controller = manifest.controller.as_ref();
                let protocol_version = registration
                    .health
                    .as_ref()
                    .map(|health| health.protocol_version.to_string())
                    .or_else(|| {
                        manifest_controller.map(|controller| controller.protocol_version.clone())
                    })
                    .unwrap_or_default();
                let healthy = registration
                    .health
                    .as_ref()
                    .map(|health| health.healthy)
                    .unwrap_or(registration.state == ControllerState::Ready);
                ControllerDiagnostics {
                    mode: manifest_controller
                        .map(|controller| controller.mode.clone())
                        .unwrap_or_default(),
                    protocol: manifest_controller
                        .map(|controller| controller.protocol.clone())
                        .unwrap_or_default(),
                    protocol_version,
                    healthy,
                    session_generation: registration
                        .session
                        .as_ref()
                        .map(|session| session.session_generation),
                }
            });
            items.push(ServiceDiagnostics {
                service_id,
                namespace: manifest.namespace.clone(),
                service_version: manifest.service_version.clone(),
                ownership: manifest.ownership.to_string(),
                lifecycle_state,
                status,
                observed_at_unix_ms: observed_at,
                reason,
                controller,
            });
        }

        let has_more = items.len() > limit;
        if has_more {
            items.truncate(limit);
        }
        let next_cursor = if has_more {
            items.last().map(|item| encode_cursor(&item.service_id))
        } else {
            None
        };

        Ok(DiagnosticsPage {
            items,
            has_more,
            next_cursor,
        })
    }

    async fn providers(
        &self,
        limit: usize,
        after: Option<&str>,
    ) -> Result<DiagnosticsPage<ProviderDiagnostics>, DiagnosticsError> {
        let records = self
            .store
            .list_providers_bounded(after, limit + 1)
            .await
            .map_err(map_store_error)?;
        let now = now_unix_ms();
        let has_more = records.len() > limit;
        let take = if has_more { limit } else { records.len() };

        let mut items = Vec::with_capacity(take);
        for record in records.into_iter().take(take) {
            if !validate_capacity_class_count(record.inventories.len()) {
                // A provider with more resource classes than the contract
                // bound would violate the schema and is corrupt durable state.
                return Err(DiagnosticsError::Corrupt);
            }
            let provider_id = record.id.clone();
            let snap = self.agents.snapshot(&provider_id).await;
            let observed = self.agents.observed_at_unix_ms(&provider_id).await;
            let (status, reason) = provider_status(snap.as_ref(), &record.state, observed, now);
            let availability = snap
                .as_ref()
                .map(|snap| availability_str(snap.availability))
                .unwrap_or("unobserved")
                .to_owned();
            let capacity = record
                .inventories
                .iter()
                .filter(|inventory| is_canonical_class(&inventory.resource_class))
                .map(|inventory| {
                    let allocatable =
                        ((inventory.total as f64) * inventory.allocation_ratio).floor() as u64;
                    ProviderCapacityDimension {
                        resource_class: inventory.resource_class.clone(),
                        total: inventory.total,
                        reserved: inventory.reserved,
                        allocated: inventory.used,
                        available: allocatable
                            .saturating_sub(inventory.reserved)
                            .saturating_sub(inventory.used),
                    }
                })
                .collect();
            items.push(ProviderDiagnostics {
                provider_id,
                state: record.state,
                availability,
                status,
                observed_at_unix_ms: observed,
                reason,
                capacity,
            });
        }

        let next_cursor = if has_more {
            items.last().map(|item| encode_cursor(&item.provider_id))
        } else {
            None
        };

        Ok(DiagnosticsPage {
            items,
            has_more,
            next_cursor,
        })
    }

    async fn capacity(&self) -> Result<CapacityDiagnostics, DiagnosticsError> {
        let summary = self
            .store
            .capacity_summary(MAX_CAPACITY_CLASSES)
            .await
            .map_err(|error| map_capacity_store_error("capacity_summary", error))?;
        let agents = self.agents.all().await;
        let now = now_unix_ms();

        // Fleet status comes from the durable provider set plus agent
        // liveness, exactly like the providers list and summary, so a durably
        // draining/deleted provider can never be reported healthy here.
        let mut agent_map: HashMap<&str, (&AgentNodeSnapshot, Option<i64>)> = HashMap::new();
        for agent in &agents {
            let observed = self.agents.observed_at_unix_ms(&agent.agent_id).await;
            agent_map.insert(agent.agent_id.as_str(), (agent, observed));
        }
        let states = self
            .store
            .list_provider_states(None, MAX_PROVIDERS + 1)
            .await
            .map_err(|error| map_capacity_store_error("list_provider_states", error))?;
        if states.len() > MAX_PROVIDERS {
            // The capacity aggregate would exceed the fleet bound; fail closed
            // rather than silently truncate.
            tracing::error!(
                event = "operator_diagnostics_capacity_projection_failure",
                operation = "provider_bound",
                error_kind = "provider_bound_exceeded",
                provider_count = states.len(),
                "capacity diagnostics provider bound exceeded"
            );
            return Err(DiagnosticsError::Corrupt);
        }

        let mut max_observed: Option<i64> = None;
        let mut fleet = ComponentCounts::default();
        for record in &states {
            let (snap, observed) = agent_map
                .get(record.id.as_str())
                .map(|(snap, observed)| (Some(*snap), *observed))
                .unwrap_or((None, None));
            if let Some(observed) = observed {
                max_observed = Some(max_observed.map_or(observed, |max| max.max(observed)));
            }
            let (status, _) = provider_status(snap, &record.state, observed, now);
            fleet.total += 1;
            match status {
                DiagnosticStatus::Healthy => fleet.healthy += 1,
                DiagnosticStatus::Degraded => fleet.degraded += 1,
                DiagnosticStatus::Unavailable => fleet.unavailable += 1,
                DiagnosticStatus::Stale => fleet.stale += 1,
                DiagnosticStatus::Unknown => fleet.unknown += 1,
            }
        }

        // Dimensions, with `available` derived through the shared saturating
        // helper. A negative remainder (drifted/corrupt durable state) is a
        // capacity invariant violation and degrades the whole capacity status.
        // Only the canonical placement classes are advertised; any other
        // class stored in the durable authority is not projected.
        let mut dimensions: Vec<CapacityDimension> = summary
            .classes
            .iter()
            .filter(|class| is_canonical_class(&class.resource_class))
            .map(|class| {
                CapacityDimension {
                    resource_class: class.resource_class.clone(),
                    unit: unit_for(&class.resource_class).to_owned(),
                    allocatable: class.allocatable,
                    reserved: class.reserved,
                    allocated: class.allocated,
                    available: 0,
                }
                .with_available()
            })
            .collect();
        sort_dimensions(&mut dimensions);
        let over_allocated = dimensions.iter().any(|dimension| {
            // Raw invariant: `allocated > allocatable - reserved`. Evaluated
            // in signed arithmetic so an over-reservation (`reserved >
            // allocatable`, e.g. a corrupt durable value) also degrades rather
            // than being masked by saturating subtraction. `available` itself
            // still clamps to zero (never negative).
            (i128::from(dimension.allocated))
                > (i128::from(dimension.allocatable) - i128::from(dimension.reserved))
        });

        let (status, reason) = if states.is_empty() {
            // Capacity authority is not populated at all.
            (
                DiagnosticStatus::Unknown,
                Some(DiagnosticReason::NeverObserved),
            )
        } else if max_observed.is_none() || now - max_observed.unwrap_or(now) > AGENT_LEASE_MS {
            // Durable last-known values without any fresh agent observation are
            // never reported healthy (covers process restart before
            // re-observation, and a fleet that has stopped reporting).
            (
                DiagnosticStatus::Stale,
                Some(DiagnosticReason::ObservationStale),
            )
        } else if over_allocated || summary.providers_over_allocated > 0 {
            // The durable capacity invariant was violated (either in the
            // aggregate, or on an individual provider masked by another
            // provider's slack); never present this as healthy.
            (DiagnosticStatus::Degraded, None)
        } else if fleet.degraded > 0
            || fleet.unavailable > 0
            || fleet.stale > 0
            || fleet.unknown > 0
        {
            // Partial provider failure: at least one provider is down, stale,
            // or never observed even though another produced a fresh
            // observation. A never-observed provider means the fleet is not
            // fully healthy, so capacity is never reported healthy.
            (DiagnosticStatus::Degraded, None)
        } else {
            (DiagnosticStatus::Healthy, None)
        };

        Ok(CapacityDiagnostics {
            version: DIAGNOSTICS_VERSION.to_owned(),
            status,
            observed_at_unix_ms: max_observed,
            reason,
            providers_enabled: summary.providers_enabled,
            providers_draining: summary.providers_draining,
            providers_unavailable: summary.providers_unavailable,
            providers_deleted: summary.providers_deleted,
            dimensions,
        })
    }
}

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]
mod tests {
    use super::*;
    use o3k_provider::{AgentCapabilities, AgentEpochLease};

    #[allow(clippy::type_complexity)]
    struct FakeAgents {
        nodes: Arc<tokio::sync::Mutex<HashMap<String, (AgentNodeSnapshot, Option<i64>)>>>,
    }

    #[async_trait::async_trait]
    impl AgentNodeRegistry for FakeAgents {
        async fn all(&self) -> Vec<AgentNodeSnapshot> {
            self.nodes
                .lock()
                .await
                .values()
                .map(|(snapshot, _)| snapshot.clone())
                .collect()
        }
        async fn snapshot(&self, agent_id: &str) -> Option<AgentNodeSnapshot> {
            self.nodes
                .lock()
                .await
                .get(agent_id)
                .map(|(snapshot, _)| snapshot.clone())
        }
        async fn lease_current_epoch(
            &self,
            _agent_id: &str,
            _agent_epoch: &str,
        ) -> Option<Box<dyn AgentEpochLease>> {
            None
        }
        fn subscribe_events(&self) -> tokio::sync::broadcast::Receiver<o3k_provider::AgentEvent> {
            tokio::sync::broadcast::channel(1).1
        }
        async fn observed_at_unix_ms(&self, agent_id: &str) -> Option<i64> {
            self.nodes
                .lock()
                .await
                .get(agent_id)
                .and_then(|(_, observed)| *observed)
        }
    }

    fn capabilities() -> AgentCapabilities {
        AgentCapabilities {
            agent_provider_name: "test".to_owned(),
            agent_provider_version: "1".to_owned(),
            max_vcpus: 8,
            max_memory_mib: 8192,
            max_disk_gb: 100,
            lifecycle_actions: vec![],
            console_log: false,
            flags: vec![],
        }
    }

    fn snapshot(
        agent_id: &str,
        availability: AgentAvailability,
        administrative_state: AgentAdministrativeState,
    ) -> AgentNodeSnapshot {
        AgentNodeSnapshot {
            agent_id: agent_id.to_owned(),
            host_id: agent_id.to_owned(),
            agent_epoch: "epoch-1".to_owned(),
            availability,
            administrative_state,
            capabilities: capabilities(),
        }
    }

    fn fake_agents(nodes: HashMap<String, (AgentNodeSnapshot, Option<i64>)>) -> Arc<FakeAgents> {
        Arc::new(FakeAgents {
            nodes: Arc::new(tokio::sync::Mutex::new(nodes)),
        })
    }

    fn inventory(
        resource_class: &str,
        total: u64,
        reserved: u64,
        allocation_ratio: f64,
        used: u64,
    ) -> o3k_store::PlacementInventoryRecord {
        o3k_store::PlacementInventoryRecord {
            resource_class: resource_class.to_owned(),
            total,
            reserved,
            allocation_ratio,
            used,
        }
    }

    #[tokio::test]
    async fn provider_never_observed_is_unknown_even_when_durable_state_enabled() {
        let store = Arc::new(
            o3k_store::unified::O3kStore::connect_sqlite_memory()
                .await
                .expect("store"),
        );
        store
            .register_provider("provider-a", &[inventory("VCPU", 8, 1, 1.0, 2)])
            .await
            .expect("register provider");
        let adapter = DiagnosticsReaderAdapter::new(
            Arc::new(RwLock::new(ManifestRegistry::new())),
            fake_agents(HashMap::new()),
            store,
            o3k_kernel::LocationRegistry::default(),
        );

        let page = adapter.providers(10, None).await.expect("providers");
        assert_eq!(page.items.len(), 1);
        assert_eq!(page.items[0].provider_id, "provider-a");
        assert_eq!(page.items[0].status, DiagnosticStatus::Unknown);
        assert_eq!(page.items[0].reason, Some(DiagnosticReason::NeverObserved));
        assert_eq!(page.items[0].availability, "unobserved");
    }

    #[tokio::test]
    async fn provider_healthy_when_agent_observed_fresh() {
        let store = Arc::new(
            o3k_store::unified::O3kStore::connect_sqlite_memory()
                .await
                .expect("store"),
        );
        store
            .register_provider("provider-a", &[inventory("VCPU", 8, 1, 1.0, 2)])
            .await
            .expect("register provider");
        let observed = now_unix_ms();
        let agents = fake_agents(HashMap::from([(
            "provider-a".to_owned(),
            (
                snapshot(
                    "provider-a",
                    AgentAvailability::Available,
                    AgentAdministrativeState::Enabled,
                ),
                Some(observed),
            ),
        )]));
        let adapter = DiagnosticsReaderAdapter::new(
            Arc::new(RwLock::new(ManifestRegistry::new())),
            agents,
            store,
            o3k_kernel::LocationRegistry::default(),
        );

        let page = adapter.providers(10, None).await.expect("providers");
        assert_eq!(page.items.len(), 1);
        assert_eq!(page.items[0].status, DiagnosticStatus::Healthy);
        assert_eq!(page.items[0].reason, None);
        assert_eq!(page.items[0].availability, "available");
    }

    #[tokio::test]
    async fn provider_stale_when_heartbeat_older_than_lease() {
        let store = Arc::new(
            o3k_store::unified::O3kStore::connect_sqlite_memory()
                .await
                .expect("store"),
        );
        store
            .register_provider("provider-a", &[inventory("VCPU", 8, 1, 1.0, 2)])
            .await
            .expect("register provider");
        let observed = now_unix_ms() - AGENT_LEASE_MS - 1_000;
        let agents = fake_agents(HashMap::from([(
            "provider-a".to_owned(),
            (
                snapshot(
                    "provider-a",
                    AgentAvailability::Available,
                    AgentAdministrativeState::Enabled,
                ),
                Some(observed),
            ),
        )]));
        let adapter = DiagnosticsReaderAdapter::new(
            Arc::new(RwLock::new(ManifestRegistry::new())),
            agents,
            store,
            o3k_kernel::LocationRegistry::default(),
        );

        let page = adapter.providers(10, None).await.expect("providers");
        assert_eq!(page.items[0].status, DiagnosticStatus::Stale);
        assert_eq!(
            page.items[0].reason,
            Some(DiagnosticReason::ObservationStale)
        );
    }

    #[tokio::test]
    async fn provider_draining_is_degraded() {
        let store = Arc::new(
            o3k_store::unified::O3kStore::connect_sqlite_memory()
                .await
                .expect("store"),
        );
        store
            .register_provider("provider-a", &[inventory("VCPU", 8, 1, 1.0, 2)])
            .await
            .expect("register provider");
        store
            .set_provider_state("provider-a", "Draining")
            .await
            .expect("set state");
        let agents = fake_agents(HashMap::from([(
            "provider-a".to_owned(),
            (
                snapshot(
                    "provider-a",
                    AgentAvailability::Available,
                    AgentAdministrativeState::Enabled,
                ),
                Some(now_unix_ms()),
            ),
        )]));
        let adapter = DiagnosticsReaderAdapter::new(
            Arc::new(RwLock::new(ManifestRegistry::new())),
            agents,
            store,
            o3k_kernel::LocationRegistry::default(),
        );

        let page = adapter.providers(10, None).await.expect("providers");
        assert_eq!(page.items[0].status, DiagnosticStatus::Degraded);
        assert_eq!(page.items[0].reason, Some(DiagnosticReason::Draining));
    }

    #[tokio::test]
    async fn provider_disabled_is_unavailable() {
        let store = Arc::new(
            o3k_store::unified::O3kStore::connect_sqlite_memory()
                .await
                .expect("store"),
        );
        store
            .register_provider("provider-a", &[inventory("VCPU", 8, 1, 1.0, 2)])
            .await
            .expect("register provider");
        let agents = fake_agents(HashMap::from([(
            "provider-a".to_owned(),
            (
                snapshot(
                    "provider-a",
                    AgentAvailability::Available,
                    AgentAdministrativeState::Disabled,
                ),
                Some(now_unix_ms()),
            ),
        )]));
        let adapter = DiagnosticsReaderAdapter::new(
            Arc::new(RwLock::new(ManifestRegistry::new())),
            agents,
            store,
            o3k_kernel::LocationRegistry::default(),
        );

        let page = adapter.providers(10, None).await.expect("providers");
        assert_eq!(page.items[0].status, DiagnosticStatus::Unavailable);
        assert_eq!(
            page.items[0].reason,
            Some(DiagnosticReason::AdministrativelyDisabled)
        );
    }

    #[tokio::test]
    async fn capacity_unknown_when_no_providers() {
        let store = Arc::new(
            o3k_store::unified::O3kStore::connect_sqlite_memory()
                .await
                .expect("store"),
        );
        let adapter = DiagnosticsReaderAdapter::new(
            Arc::new(RwLock::new(ManifestRegistry::new())),
            fake_agents(HashMap::new()),
            store,
            o3k_kernel::LocationRegistry::default(),
        );
        let capacity = adapter.capacity().await.expect("capacity");
        assert_eq!(capacity.status, DiagnosticStatus::Unknown);
        assert_eq!(capacity.reason, Some(DiagnosticReason::NeverObserved));
    }

    #[tokio::test]
    async fn capacity_stale_when_providers_exist_but_no_fresh_observation() {
        let store = Arc::new(
            o3k_store::unified::O3kStore::connect_sqlite_memory()
                .await
                .expect("store"),
        );
        store
            .register_provider("provider-a", &[inventory("VCPU", 8, 1, 1.0, 2)])
            .await
            .expect("register provider");
        let adapter = DiagnosticsReaderAdapter::new(
            Arc::new(RwLock::new(ManifestRegistry::new())),
            fake_agents(HashMap::new()),
            store,
            o3k_kernel::LocationRegistry::default(),
        );
        let capacity = adapter.capacity().await.expect("capacity");
        assert_eq!(capacity.status, DiagnosticStatus::Stale);
        assert_eq!(capacity.reason, Some(DiagnosticReason::ObservationStale));
    }

    #[tokio::test]
    async fn capacity_arithmetic_is_saturating() {
        let store = Arc::new(
            o3k_store::unified::O3kStore::connect_sqlite_memory()
                .await
                .expect("store"),
        );
        store
            .register_provider(
                "provider-a",
                &[
                    inventory("VCPU", 8, 1, 1.0, 2),
                    // Over-allocated class must clamp to zero, never wrap.
                    inventory("MEMORY_MB", 2, 5, 1.0, 9),
                ],
            )
            .await
            .expect("register provider");
        let observed = now_unix_ms();
        let agents = fake_agents(HashMap::from([(
            "provider-a".to_owned(),
            (
                snapshot(
                    "provider-a",
                    AgentAvailability::Available,
                    AgentAdministrativeState::Enabled,
                ),
                Some(observed),
            ),
        )]));
        let adapter = DiagnosticsReaderAdapter::new(
            Arc::new(RwLock::new(ManifestRegistry::new())),
            agents,
            store,
            o3k_kernel::LocationRegistry::default(),
        );

        let page = adapter.providers(10, None).await.expect("providers");
        let capacity = adapter.capacity().await.expect("capacity");
        // The MEMORY_MB class is over-reserved (reserved 5 > allocatable 2), a
        // corrupt durable invariant: the raw over-allocation rule degrades the
        // whole capacity status while `available` still clamps to zero.
        assert_eq!(capacity.status, DiagnosticStatus::Degraded);

        let vcpu = capacity
            .dimensions
            .iter()
            .find(|dimension| dimension.resource_class == "VCPU")
            .expect("VCPU dimension");
        // register_provider recomputes `used` from durable allocations, so the
        // input `used` is zeroed: allocatable = floor(8 * 1.0) = 8, reserved = 1,
        // available = 8 - 1 - 0 = 7.
        assert_eq!(vcpu.allocatable, 8);
        assert_eq!(vcpu.available, 7);
        assert_eq!(vcpu.unit, "count");

        let memory = capacity
            .dimensions
            .iter()
            .find(|dimension| dimension.resource_class == "MEMORY_MB")
            .expect("MEMORY_MB dimension");
        // Over-allocated class (total 2, reserved 5) must clamp to zero.
        assert_eq!(memory.available, 0, "negative remainder must clamp to zero");
        assert_eq!(memory.unit, "mib");

        let provider_vcpu = page.items[0]
            .capacity
            .iter()
            .find(|dimension| dimension.resource_class == "VCPU")
            .expect("provider VCPU dimension");
        assert_eq!(provider_vcpu.available, 7);
    }

    #[test]
    fn service_declared_is_unknown_ready_is_healthy() {
        let (status, reason) = service_status(ControllerState::Declared);
        assert_eq!(status, DiagnosticStatus::Unknown);
        assert_eq!(reason, Some(DiagnosticReason::NeverObserved));

        let (status, reason) = service_status(ControllerState::Ready);
        assert_eq!(status, DiagnosticStatus::Healthy);
        assert_eq!(reason, None);

        let (status, reason) = service_status(ControllerState::NotReady);
        assert_eq!(status, DiagnosticStatus::Unavailable);
        assert_eq!(reason, Some(DiagnosticReason::ReadinessFailed));
    }

    #[test]
    fn provider_status_unknown_when_no_snapshot_despite_enabled_durable_state() {
        let (status, reason) = provider_status(None, "Enabled", Some(now_unix_ms()), now_unix_ms());
        assert_eq!(status, DiagnosticStatus::Unknown);
        assert_eq!(reason, Some(DiagnosticReason::NeverObserved));
    }

    #[test]
    fn provider_status_unrecognized_durable_state_is_never_healthy() {
        // A corrupt durable state (outside the four canonical values) must
        // never be projected healthy, mirroring the store's corrupt handling.
        let (status, reason) = provider_status(
            Some(&snapshot(
                "provider-a",
                AgentAvailability::Available,
                AgentAdministrativeState::Enabled,
            )),
            "BogusState",
            Some(now_unix_ms()),
            now_unix_ms(),
        );
        assert_eq!(status, DiagnosticStatus::Unknown);
        assert_eq!(reason, None);
    }

    #[test]
    fn provider_status_live_snapshot_without_observation_time_is_never_healthy() {
        // A live snapshot with no observation timestamp must be unknown, never
        // healthy (the AgentNodeRegistry contract: None -> unknown).
        let (status, reason) = provider_status(
            Some(&snapshot(
                "provider-a",
                AgentAvailability::Available,
                AgentAdministrativeState::Enabled,
            )),
            "Enabled",
            None,
            now_unix_ms(),
        );
        assert_eq!(status, DiagnosticStatus::Unknown);
        assert_eq!(reason, Some(DiagnosticReason::NeverObserved));
    }

    #[test]
    fn parse_timestamp_accepts_rfc3339_and_sqlite_datetime() {
        assert!(parse_timestamp("2026-09-11T10:00:00Z").is_some());
        assert!(parse_timestamp("2026-09-11 10:00:00").is_some());
        assert!(parse_timestamp("garbage").is_none());
    }

    #[tokio::test]
    async fn provider_lifecycle_never_observed_stale_recovery_never_fabricates() {
        let store = Arc::new(
            o3k_store::unified::O3kStore::connect_sqlite_memory()
                .await
                .expect("store"),
        );
        store
            .register_provider("provider-a", &[inventory("VCPU", 8, 1, 1.0, 2)])
            .await
            .expect("register provider");
        let agents = fake_agents(HashMap::new());
        let adapter = DiagnosticsReaderAdapter::new(
            Arc::new(RwLock::new(ManifestRegistry::new())),
            agents.clone(),
            store,
            o3k_kernel::LocationRegistry::default(),
        );

        // Restart: durable placement state exists but no agent is observed yet.
        // The provider must NOT be reported healthy from durable state alone.
        let page = adapter.providers(10, None).await.expect("providers");
        assert_eq!(page.items[0].status, DiagnosticStatus::Unknown);
        assert_eq!(page.items[0].reason, Some(DiagnosticReason::NeverObserved));

        // Agent registers with a fresh heartbeat -> healthy.
        agents.nodes.lock().await.insert(
            "provider-a".to_owned(),
            (
                snapshot(
                    "provider-a",
                    AgentAvailability::Available,
                    AgentAdministrativeState::Enabled,
                ),
                Some(now_unix_ms()),
            ),
        );
        let page = adapter.providers(10, None).await.expect("providers");
        assert_eq!(page.items[0].status, DiagnosticStatus::Healthy);

        // Heartbeat stops -> the provider becomes stale, never stays healthy.
        agents.nodes.lock().await.insert(
            "provider-a".to_owned(),
            (
                snapshot(
                    "provider-a",
                    AgentAvailability::Unavailable,
                    AgentAdministrativeState::Enabled,
                ),
                Some(now_unix_ms() - AGENT_LEASE_MS - 1_000),
            ),
        );
        let page = adapter.providers(10, None).await.expect("providers");
        assert_eq!(page.items[0].status, DiagnosticStatus::Stale);
        assert_eq!(page.items[0].reason, Some(DiagnosticReason::HeartbeatLost));

        // Recovery: a fresh observation restores health through the same adapter.
        agents.nodes.lock().await.insert(
            "provider-a".to_owned(),
            (
                snapshot(
                    "provider-a",
                    AgentAvailability::Available,
                    AgentAdministrativeState::Enabled,
                ),
                Some(now_unix_ms()),
            ),
        );
        let page = adapter.providers(10, None).await.expect("providers");
        assert_eq!(page.items[0].status, DiagnosticStatus::Healthy);
        assert_eq!(page.items[0].reason, None);
    }

    #[test]
    fn service_lifecycle_tracks_controller_health_transitions() {
        // Declared -> unknown.
        let (status, _) = service_status(ControllerState::Declared);
        assert_eq!(status, DiagnosticStatus::Unknown);
        // Healthy controller -> healthy.
        let (status, _) = service_status(ControllerState::Ready);
        assert_eq!(status, DiagnosticStatus::Healthy);
        // Reported unhealthy -> unavailable (never a stale healthy).
        let (status, reason) = service_status(ControllerState::NotReady);
        assert_eq!(status, DiagnosticStatus::Unavailable);
        assert_eq!(reason, Some(DiagnosticReason::ReadinessFailed));
        // Recovery -> healthy.
        let (status, _) = service_status(ControllerState::Ready);
        assert_eq!(status, DiagnosticStatus::Healthy);
    }

    fn external_session(service: &str, generation: u64) -> o3k_kernel::ControllerSession {
        o3k_kernel::ControllerSession {
            service_id: service.to_owned(),
            namespace: service.to_owned(),
            service_principal: o3k_kernel::ServicePrincipal::new(
                o3k_kernel::PrincipalId::new_unchecked(format!("{service}-controller")),
                format!("{service}-controller"),
                service,
            ),
            session_id: uuid::Uuid::new_v4(),
            session_generation: generation,
            protocol_version: o3k_kernel::ProtocolVersion::new(1, 0),
            manifest_digest: "digest".to_owned(),
            manifest_generation: generation,
            started_at: String::new(),
        }
    }

    #[test]
    fn external_controller_with_stale_observation_is_not_healthy() {
        // An external controller that last reported Ready but has not been
        // re-confirmed within the freshness threshold is stale, never a
        // last-known-good healthy.
        let registration = ControllerRegistration {
            service_id: "compute".to_owned(),
            namespace: "compute".to_owned(),
            session: Some(external_session("compute", 1)),
            state: ControllerState::Ready,
            health: None,
        };
        let (status, reason) = service_status_with_freshness(
            &registration,
            now_unix_ms() - SERVICE_OBSERVATION_THRESHOLD_MS - 1_000,
            now_unix_ms(),
        );
        assert_eq!(status, DiagnosticStatus::Stale);
        assert_eq!(reason, Some(DiagnosticReason::ObservationStale));
    }

    #[test]
    fn in_process_service_readiness_is_configuration_not_observation() {
        // In-process services (no transport session) are process-authoritative
        // configuration; an old observation does not make them stale.
        let registration = ControllerRegistration {
            service_id: "compute".to_owned(),
            namespace: "compute".to_owned(),
            session: None,
            state: ControllerState::Ready,
            health: None,
        };
        let (status, reason) = service_status_with_freshness(
            &registration,
            now_unix_ms() - SERVICE_OBSERVATION_THRESHOLD_MS - 1_000,
            now_unix_ms(),
        );
        assert_eq!(status, DiagnosticStatus::Healthy);
        assert_eq!(reason, None);
    }

    #[tokio::test]
    async fn summary_and_capacity_reflect_durable_draining() {
        let store = Arc::new(
            o3k_store::unified::O3kStore::connect_sqlite_memory()
                .await
                .expect("store"),
        );
        store
            .register_provider("provider-a", &[inventory("VCPU", 8, 1, 1.0, 2)])
            .await
            .expect("register provider");
        store
            .set_provider_state("provider-a", "Draining")
            .await
            .expect("set state");
        let agents = fake_agents(HashMap::from([(
            "provider-a".to_owned(),
            (
                snapshot(
                    "provider-a",
                    AgentAvailability::Available,
                    AgentAdministrativeState::Enabled,
                ),
                Some(now_unix_ms()),
            ),
        )]));
        let adapter = DiagnosticsReaderAdapter::new(
            Arc::new(RwLock::new(ManifestRegistry::new())),
            agents,
            store,
            o3k_kernel::LocationRegistry::default(),
        );

        // A durably draining provider with a live agent must be degraded, not
        // healthy, in the aggregate and in capacity.
        let summary = adapter.summary().await.expect("summary");
        assert_eq!(summary.counts.providers.total, 1);
        assert_eq!(summary.counts.providers.degraded, 1);
        assert_eq!(summary.counts.providers.healthy, 0);

        let capacity = adapter.capacity().await.expect("capacity");
        assert_eq!(capacity.status, DiagnosticStatus::Degraded);
    }

    #[tokio::test]
    async fn capacity_over_allocated_is_degraded_not_healthy() {
        let store = Arc::new(
            o3k_store::unified::O3kStore::connect_sqlite_memory()
                .await
                .expect("store"),
        );
        store
            .register_provider("provider-a", &[inventory("VCPU", 8, 0, 1.0, 0)])
            .await
            .expect("register provider");
        // Over-allocate beyond allocatable (8) — a drift/corruption scenario.
        store
            .commit_allocation(
                "provider-a",
                1,
                &o3k_store::PlacementAllocationRecord {
                    id: "alloc-1".to_owned(),
                    provider_id: "provider-a".to_owned(),
                    consumer_id: "consumer-1".to_owned(),
                    resources: vec![o3k_store::PlacementResourceRecord {
                        resource_class: "VCPU".to_owned(),
                        amount: 100,
                    }],
                },
            )
            .await
            .expect("commit allocation");
        let agents = fake_agents(HashMap::from([(
            "provider-a".to_owned(),
            (
                snapshot(
                    "provider-a",
                    AgentAvailability::Available,
                    AgentAdministrativeState::Enabled,
                ),
                Some(now_unix_ms()),
            ),
        )]));
        let adapter = DiagnosticsReaderAdapter::new(
            Arc::new(RwLock::new(ManifestRegistry::new())),
            agents,
            store,
            o3k_kernel::LocationRegistry::default(),
        );

        let capacity = adapter.capacity().await.expect("capacity");
        assert_eq!(capacity.status, DiagnosticStatus::Degraded);
        let vcpu = capacity
            .dimensions
            .iter()
            .find(|dimension| dimension.resource_class == "VCPU")
            .expect("VCPU dimension");
        // available must never be negative; over-allocation degrades the status.
        assert_eq!(vcpu.available, 0);
    }

    #[tokio::test]
    async fn capacity_with_never_observed_provider_is_not_healthy() {
        let store = Arc::new(
            o3k_store::unified::O3kStore::connect_sqlite_memory()
                .await
                .expect("store"),
        );
        store
            .register_provider("provider-a", &[inventory("VCPU", 8, 1, 1.0, 2)])
            .await
            .expect("register a");
        store
            .register_provider("provider-b", &[inventory("VCPU", 4, 1, 1.0, 1)])
            .await
            .expect("register b");
        // Only provider-a is observed; provider-b is never observed.
        let agents = fake_agents(HashMap::from([(
            "provider-a".to_owned(),
            (
                snapshot(
                    "provider-a",
                    AgentAvailability::Available,
                    AgentAdministrativeState::Enabled,
                ),
                Some(now_unix_ms()),
            ),
        )]));
        let adapter = DiagnosticsReaderAdapter::new(
            Arc::new(RwLock::new(ManifestRegistry::new())),
            agents,
            store,
            o3k_kernel::LocationRegistry::default(),
        );

        // A fresh provider alongside a never-observed provider must not make
        // the fleet (or capacity) healthy — it is a partial/degraded state.
        let summary = adapter.summary().await.expect("summary");
        assert_eq!(summary.counts.providers.total, 2);
        assert_eq!(summary.counts.providers.healthy, 1);
        assert_eq!(summary.counts.providers.unknown, 1);
        assert_eq!(
            summary.counts.providers.aggregate(),
            DiagnosticStatus::Degraded
        );

        let capacity = adapter.capacity().await.expect("capacity");
        assert_eq!(capacity.status, DiagnosticStatus::Degraded);
    }

    #[tokio::test]
    async fn provider_durably_unavailable_is_not_healthy_even_with_live_agent() {
        let store = Arc::new(
            o3k_store::unified::O3kStore::connect_sqlite_memory()
                .await
                .expect("store"),
        );
        store
            .register_provider("provider-a", &[inventory("VCPU", 8, 1, 1.0, 2)])
            .await
            .expect("register provider");
        store
            .set_provider_state("provider-a", "Unavailable")
            .await
            .expect("set state");
        let agents = fake_agents(HashMap::from([(
            "provider-a".to_owned(),
            (
                snapshot(
                    "provider-a",
                    AgentAvailability::Available,
                    AgentAdministrativeState::Enabled,
                ),
                Some(now_unix_ms()),
            ),
        )]));
        let adapter = DiagnosticsReaderAdapter::new(
            Arc::new(RwLock::new(ManifestRegistry::new())),
            agents,
            store,
            o3k_kernel::LocationRegistry::default(),
        );

        let page = adapter.providers(10, None).await.expect("providers");
        assert_eq!(page.items[0].status, DiagnosticStatus::Unavailable);
        assert_eq!(
            page.items[0].reason,
            Some(DiagnosticReason::AdministrativelyDisabled)
        );
    }

    #[tokio::test]
    async fn capacity_masked_provider_over_allocation_is_degraded() {
        let store = Arc::new(
            o3k_store::unified::O3kStore::connect_sqlite_memory()
                .await
                .expect("store"),
        );
        // provider-a has huge slack; provider-b is over-allocated beyond its
        // own allocatable. In the aggregate the slack masks provider-b, so
        // only the per-provider over-allocation signal can catch it.
        store
            .register_provider("provider-a", &[inventory("VCPU", 1000, 1, 1.0, 2)])
            .await
            .expect("register a");
        store
            .register_provider("provider-b", &[inventory("VCPU", 4, 0, 1.0, 0)])
            .await
            .expect("register b");
        store
            .commit_allocation(
                "provider-b",
                1,
                &o3k_store::PlacementAllocationRecord {
                    id: "alloc-b".to_owned(),
                    provider_id: "provider-b".to_owned(),
                    consumer_id: "consumer-b".to_owned(),
                    resources: vec![o3k_store::PlacementResourceRecord {
                        resource_class: "VCPU".to_owned(),
                        amount: 100,
                    }],
                },
            )
            .await
            .expect("commit allocation");
        let agents = fake_agents(HashMap::from([
            (
                "provider-a".to_owned(),
                (
                    snapshot(
                        "provider-a",
                        AgentAvailability::Available,
                        AgentAdministrativeState::Enabled,
                    ),
                    Some(now_unix_ms()),
                ),
            ),
            (
                "provider-b".to_owned(),
                (
                    snapshot(
                        "provider-b",
                        AgentAvailability::Available,
                        AgentAdministrativeState::Enabled,
                    ),
                    Some(now_unix_ms()),
                ),
            ),
        ]));
        let adapter = DiagnosticsReaderAdapter::new(
            Arc::new(RwLock::new(ManifestRegistry::new())),
            agents,
            store.clone(),
            o3k_kernel::LocationRegistry::default(),
        );

        let capacity = adapter.capacity().await.expect("capacity");
        assert_eq!(capacity.status, DiagnosticStatus::Degraded);
        // The durable aggregate must report the over-allocated provider.
        let summary = store
            .capacity_summary(MAX_CAPACITY_CLASSES)
            .await
            .expect("summary");
        assert_eq!(summary.providers_over_allocated, 1);
    }

    #[tokio::test]
    async fn capacity_only_advertises_canonical_classes_but_non_canonical_over_allocation_still_degrades()
     {
        let store = Arc::new(
            o3k_store::unified::O3kStore::connect_sqlite_memory()
                .await
                .expect("store"),
        );
        // One canonical class plus one non-canonical class in the durable
        // authority. Only the canonical class may be advertised.
        store
            .register_provider(
                "provider-a",
                &[
                    inventory("VCPU", 8, 1, 1.0, 2),
                    inventory("GPU", 4, 0, 1.0, 0),
                ],
            )
            .await
            .expect("register provider");
        let agents = fake_agents(HashMap::from([(
            "provider-a".to_owned(),
            (
                snapshot(
                    "provider-a",
                    AgentAvailability::Available,
                    AgentAdministrativeState::Enabled,
                ),
                Some(now_unix_ms()),
            ),
        )]));
        let adapter = DiagnosticsReaderAdapter::new(
            Arc::new(RwLock::new(ManifestRegistry::new())),
            agents,
            store.clone(),
            o3k_kernel::LocationRegistry::default(),
        );

        let capacity = adapter.capacity().await.expect("capacity");
        assert!(
            capacity
                .dimensions
                .iter()
                .all(|d| d.resource_class == "VCPU"),
            "non-canonical class must not be advertised"
        );
        assert!(
            capacity
                .dimensions
                .iter()
                .any(|d| d.resource_class == "VCPU")
        );

        let page = adapter.providers(10, None).await.expect("providers");
        assert!(
            page.items[0]
                .capacity
                .iter()
                .all(|d| d.resource_class == "VCPU"),
            "non-canonical class must not appear in provider capacity"
        );

        // A non-canonical class over-allocated beyond its allocatable is still
        // a corrupt durable invariant and must degrade the whole capacity.
        store
            .commit_allocation(
                "provider-a",
                1,
                &o3k_store::PlacementAllocationRecord {
                    id: "alloc-gpu".to_owned(),
                    provider_id: "provider-a".to_owned(),
                    consumer_id: "consumer-1".to_owned(),
                    resources: vec![o3k_store::PlacementResourceRecord {
                        resource_class: "GPU".to_owned(),
                        amount: 100,
                    }],
                },
            )
            .await
            .expect("commit allocation");
        let capacity = adapter.capacity().await.expect("capacity");
        assert_eq!(capacity.status, DiagnosticStatus::Degraded);
    }
}
