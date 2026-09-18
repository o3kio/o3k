//! Agent inventory management: capability mapping, Placement sync, periodic publication.
//!
//! These are composition-root adapters, not ComputeService methods. The inventory
//! publisher is wired from o3kd's composition root and does not require the full
//! ComputeService to be constructed first.

use o3k_placement;
use o3k_provider::{
    AgentAdministrativeState, AgentAvailability, AgentCapabilities, AgentNodeRegistry,
    AgentNodeSnapshot,
};
use o3k_scheduler::SchedulerError;
use std::collections::BTreeMap;
use std::sync::Arc;
use std::time::Duration;

pub fn agent_inventory(
    capabilities: &AgentCapabilities,
) -> BTreeMap<String, o3k_placement::Inventory> {
    BTreeMap::from([
        (
            o3k_placement::VCPU.to_owned(),
            o3k_placement::Inventory {
                total: capabilities.max_vcpus,
                reserved: 0,
                allocation_ratio: 1.0,
                used: 0,
            },
        ),
        (
            o3k_placement::MEMORY_MB.to_owned(),
            o3k_placement::Inventory {
                total: capabilities.max_memory_mib,
                reserved: 0,
                allocation_ratio: 1.0,
                used: 0,
            },
        ),
        (
            o3k_placement::DISK_GB.to_owned(),
            o3k_placement::Inventory {
                total: capabilities.max_disk_gb,
                reserved: 0,
                allocation_ratio: 1.0,
                used: 0,
            },
        ),
    ])
}

fn agent_provider_state(snapshot: &AgentNodeSnapshot) -> o3k_placement::ProviderState {
    if snapshot.availability != AgentAvailability::Available
        || snapshot.administrative_state == AgentAdministrativeState::Disabled
        || snapshot.capabilities.max_vcpus == 0
        || snapshot.capabilities.max_memory_mib == 0
        || snapshot.capabilities.max_disk_gb == 0
    {
        o3k_placement::ProviderState::Unavailable
    } else if snapshot.administrative_state == AgentAdministrativeState::Draining {
        o3k_placement::ProviderState::Draining
    } else {
        o3k_placement::ProviderState::Enabled
    }
}

/// Synchronizes the current authenticated agent snapshots into Placement.
/// The stable agent ID is the Placement provider ID, so reconnects update the
/// same provider and preserve durable allocations.
pub async fn sync_agent_inventory(
    registry: &dyn AgentNodeRegistry,
    placement: &o3k_placement::PlacementLedger,
) -> Result<(), SchedulerError> {
    for snapshot in registry.all().await {
        // A BuildingBlock drain or removal is a durable operator gate in
        // Placement. An agent heartbeat can still report its own desired state
        // as Enabled until the control stream receives that projection; never
        // let the periodic capability publisher reopen a durably draining or
        // deleted provider.
        let published_state = match placement.provider(&snapshot.agent_id).await {
            Ok(provider)
                if matches!(
                    provider.state,
                    o3k_placement::ProviderState::Draining | o3k_placement::ProviderState::Deleted
                ) && agent_provider_state(&snapshot)
                    == o3k_placement::ProviderState::Enabled =>
            {
                provider.state
            }
            _ => agent_provider_state(&snapshot),
        };
        placement
            .sync_provider(
                &snapshot.agent_id,
                agent_inventory(&snapshot.capabilities),
                published_state,
            )
            .await?;
    }
    Ok(())
}

/// Starts the bounded periodic inventory publisher used by `o3kd`.
/// `registration` is woken by every successful agent registration, so a
/// freshly registered agent's capacity is published immediately instead of
/// waiting up to one tick (issue #606); the 5 s tick remains the steady-state
/// sync.
pub fn spawn_agent_inventory_publisher(
    registry: Arc<dyn AgentNodeRegistry>,
    placement: o3k_placement::PlacementLedger,
    registration: Arc<tokio::sync::Notify>,
) -> tokio::task::JoinHandle<()> {
    tokio::spawn(async move {
        let mut interval = tokio::time::interval(Duration::from_secs(5));
        loop {
            tokio::select! {
                _ = interval.tick() => {}
                _ = registration.notified() => {}
            }
            if let Err(error) = sync_agent_inventory(registry.as_ref(), &placement).await {
                tracing::warn!(%error, "agent inventory publication failed");
            }
        }
    })
}
