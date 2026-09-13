//! Deterministic first-fit Nova scheduling backed by Placement allocations.

pub mod types;

use std::collections::{BTreeMap, BTreeSet};

use o3k_placement::{
    Allocation, CandidateRequest, DISK_GB, MEMORY_MB, PlacementError, PlacementLedger,
    ProviderState, VCPU,
};

pub use types::{Flavor, ScheduleDecision, SchedulerError};

#[derive(Clone)]
pub struct Scheduler {
    placement: PlacementLedger,
}

impl Scheduler {
    pub fn new(placement: PlacementLedger) -> Self {
        Self { placement }
    }

    pub async fn schedule(
        &self,
        server_id: &str,
        flavor: Flavor,
    ) -> Result<ScheduleDecision, SchedulerError> {
        self.schedule_internal(server_id, flavor, None).await
    }

    /// Schedules only on the explicitly named provider/agent identity.
    /// Placement provider IDs must be bound to the same identity by the
    /// control-plane integration layer before a command is dispatched.
    pub async fn schedule_for_agent(
        &self,
        agent_id: &str,
        server_id: &str,
        flavor: Flavor,
    ) -> Result<ScheduleDecision, SchedulerError> {
        if agent_id.trim().is_empty() {
            return Err(SchedulerError::InvalidFlavor);
        }
        self.schedule_internal(
            server_id,
            flavor,
            Some(&BTreeSet::from([agent_id.to_owned()])),
        )
        .await
    }

    /// Schedules only on the currently eligible agent identities supplied by
    /// the control-plane registry. Placement remains authoritative for
    /// provider state, capacity, generation, and atomic allocation.
    pub async fn schedule_for_agents(
        &self,
        agent_ids: &BTreeSet<String>,
        server_id: &str,
        flavor: Flavor,
    ) -> Result<ScheduleDecision, SchedulerError> {
        self.schedule_internal(server_id, flavor, Some(agent_ids))
            .await
    }

    /// Schedules using generic Placement constraints. The request is read
    /// first to produce a deterministic candidate list; each candidate is
    /// then claimed through the existing durable intent + generation-fenced
    /// commit path.
    pub async fn schedule_with_constraints(
        &self,
        server_id: &str,
        flavor: Flavor,
        mut constraints: CandidateRequest,
    ) -> Result<ScheduleDecision, SchedulerError> {
        if server_id.is_empty() || flavor.vcpus == 0 || flavor.memory_mb == 0 {
            return Err(SchedulerError::InvalidFlavor);
        }
        constraints.resources = BTreeMap::from([
            (VCPU.to_owned(), flavor.vcpus),
            (MEMORY_MB.to_owned(), flavor.memory_mb),
        ]);
        if flavor.disk_gb > 0 {
            constraints
                .resources
                .insert(DISK_GB.to_owned(), flavor.disk_gb);
        }
        if constraints.limit == 0 {
            constraints.limit = o3k_placement::MAX_CANDIDATE_LIMIT;
        }
        let resources = constraints.resources.clone();
        for candidate in self.placement.candidates(&constraints).await? {
            let intent = self
                .placement
                .begin_allocation_intent(
                    &candidate.provider_id,
                    &format!("allocation-{server_id}"),
                    server_id,
                    resources.clone(),
                )
                .await?;
            match self
                .placement
                .commit_allocation_intent(&intent, candidate.generation)
                .await
            {
                Ok(allocation) => {
                    return Ok(ScheduleDecision {
                        provider_id: candidate.provider_id,
                        allocation_id: intent.allocation_id,
                        allocation,
                    });
                }
                Err(
                    PlacementError::StaleGeneration
                    | PlacementError::OverCapacity
                    | PlacementError::NotSchedulable,
                ) => {
                    self.placement.abandon_allocation_intent(&intent).await?;
                }
                Err(error) => return Err(SchedulerError::Placement(error)),
            }
        }
        Err(SchedulerError::NoValidHost)
    }

    async fn schedule_internal(
        &self,
        server_id: &str,
        flavor: Flavor,
        selected_providers: Option<&BTreeSet<String>>,
    ) -> Result<ScheduleDecision, SchedulerError> {
        if server_id.is_empty() || flavor.vcpus == 0 || flavor.memory_mb == 0 {
            return Err(SchedulerError::InvalidFlavor);
        }
        let mut candidates = self
            .placement
            .providers()
            .await?
            .into_iter()
            .filter(|provider| {
                selected_providers.is_none_or(|selected| selected.contains(&provider.id))
                    && provider.state == ProviderState::Enabled
                    && provider
                        .inventories
                        .get(VCPU)
                        .is_some_and(|v| v.available() >= flavor.vcpus)
                    && provider
                        .inventories
                        .get(MEMORY_MB)
                        .is_some_and(|v| v.available() >= flavor.memory_mb)
                    && provider
                        .inventories
                        .get(DISK_GB)
                        .is_some_and(|v| v.available() >= flavor.disk_gb)
            })
            .collect::<Vec<_>>();
        candidates.sort_by(|left, right| {
            let left_free = left
                .inventories
                .values()
                .map(|v| v.available())
                .sum::<u64>();
            let right_free = right
                .inventories
                .values()
                .map(|v| v.available())
                .sum::<u64>();
            right_free
                .cmp(&left_free)
                .then_with(|| left.id.cmp(&right.id))
        });
        let resources = BTreeMap::from([
            (VCPU.to_owned(), flavor.vcpus),
            (MEMORY_MB.to_owned(), flavor.memory_mb),
            (DISK_GB.to_owned(), flavor.disk_gb),
        ]);
        for candidate in candidates {
            let intent = match self
                .placement
                .begin_allocation_intent(
                    &candidate.id,
                    &format!("allocation-{server_id}"),
                    server_id,
                    resources.clone(),
                )
                .await
            {
                Ok(intent) => intent,
                Err(error) => return Err(SchedulerError::Placement(error)),
            };
            match self
                .placement
                .commit_allocation_intent(&intent, candidate.generation)
                .await
            {
                Ok(allocation) => {
                    return Ok(ScheduleDecision {
                        provider_id: candidate.id,
                        allocation_id: intent.allocation_id,
                        allocation,
                    });
                }
                Err(
                    PlacementError::StaleGeneration
                    | PlacementError::OverCapacity
                    | PlacementError::NotSchedulable,
                ) => {
                    self.placement.abandon_allocation_intent(&intent).await?;
                    continue;
                }
                Err(error) => return Err(SchedulerError::Placement(error)),
            }
        }
        Err(SchedulerError::NoValidHost)
    }

    pub async fn release_terminal(
        &self,
        decision: &ScheduleDecision,
    ) -> Result<(), SchedulerError> {
        self.placement
            .release(&decision.provider_id, &decision.allocation_id)
            .await
            .map_err(SchedulerError::Placement)
    }

    /// Validates an existing durable allocation without changing Placement.
    /// Read-only lifecycle and recovery queries must use this path instead of
    /// scheduling again, which could reserve capacity a second time.
    pub async fn validate_allocation(
        &self,
        provider_id: &str,
        allocation_id: &str,
        consumer_id: &str,
    ) -> Result<Allocation, SchedulerError> {
        let provider = self.placement.provider(provider_id).await?;
        if provider.state == ProviderState::Deleted {
            return Err(SchedulerError::NoValidHost);
        }
        let allocation = provider
            .allocations
            .get(allocation_id)
            .ok_or(SchedulerError::AllocationMismatch)?;
        if allocation.provider_id != provider_id || allocation.consumer_id != consumer_id {
            return Err(SchedulerError::AllocationMismatch);
        }
        Ok(allocation.clone())
    }
    pub async fn retain_unknown(&self, _: &ScheduleDecision) -> Result<(), SchedulerError> {
        Ok(())
    }
}

#[cfg(test)]
#[allow(clippy::expect_used)]
mod tests {
    use super::*;
    use o3k_placement::Inventory;
    use std::sync::Arc;
    use uuid::Uuid;

    fn inv(vcpu: u64) -> BTreeMap<String, Inventory> {
        BTreeMap::from([
            (
                VCPU.to_owned(),
                Inventory {
                    total: vcpu,
                    reserved: 0,
                    allocation_ratio: 1.0,
                    used: 0,
                },
            ),
            (
                MEMORY_MB.to_owned(),
                Inventory {
                    total: 4096,
                    reserved: 0,
                    allocation_ratio: 1.0,
                    used: 0,
                },
            ),
            (
                DISK_GB.to_owned(),
                Inventory {
                    total: 100,
                    reserved: 0,
                    allocation_ratio: 1.0,
                    used: 0,
                },
            ),
        ])
    }

    async fn test_scheduler() -> (Scheduler, std::path::PathBuf) {
        let root = std::env::temp_dir().join(format!("o3k-scheduler-{}", Uuid::now_v7()));
        let store = o3k_store::testkit::open_memory().await.expect("store");
        let repository: Arc<dyn o3k_store::PlacementRepository> = Arc::new(store);
        let ledger = PlacementLedger::open(&root, repository)
            .await
            .expect("ledger");
        (Scheduler::new(ledger), root)
    }

    #[tokio::test]
    async fn deterministic_selection_and_terminal_release() -> Result<(), SchedulerError> {
        let (scheduler, root) = test_scheduler().await;
        scheduler
            .placement
            .register_provider("node-b", inv(4))
            .await?;
        scheduler
            .placement
            .register_provider("node-a", inv(4))
            .await?;
        let decision = scheduler
            .schedule(
                "server-1",
                Flavor {
                    vcpus: 1,
                    memory_mb: 512,
                    disk_gb: 1,
                },
            )
            .await?;
        assert_eq!(decision.provider_id, "node-a");
        assert_eq!(
            scheduler
                .placement
                .allocation_intent(&decision.allocation_id)
                .await?,
            None
        );
        scheduler.release_terminal(&decision).await?;
        assert_eq!(
            scheduler
                .placement
                .provider("node-a")
                .await?
                .allocations
                .len(),
            0
        );
        std::fs::remove_dir_all(root)
            .map_err(|error| SchedulerError::Placement(PlacementError::Storage(error)))?;
        Ok(())
    }

    #[tokio::test]
    async fn constrained_schedule_uses_generic_traits_and_fenced_commit()
    -> Result<(), SchedulerError> {
        let (scheduler, root) = test_scheduler().await;
        let a = scheduler
            .placement
            .register_provider("provider-a", inv(4))
            .await?;
        scheduler
            .placement
            .update_provider_hierarchy(
                &a.id,
                a.generation,
                None,
                BTreeSet::from(["COMPUTE".to_owned()]),
                BTreeSet::from(["rack-a".to_owned()]),
                Some("az-1"),
            )
            .await?;
        let b = scheduler
            .placement
            .register_provider("provider-b", inv(4))
            .await?;
        scheduler
            .placement
            .update_provider_hierarchy(
                &b.id,
                b.generation,
                None,
                BTreeSet::from(["COMPUTE".to_owned(), "SPECIAL_X".to_owned()]),
                BTreeSet::from(["rack-b".to_owned()]),
                Some("az-1"),
            )
            .await?;
        let request = o3k_placement::CandidateRequest {
            required_traits: BTreeSet::from(["SPECIAL_X".to_owned()]),
            limit: 4,
            ..Default::default()
        };
        let decision = scheduler
            .schedule_with_constraints(
                "server-special",
                Flavor {
                    vcpus: 1,
                    memory_mb: 512,
                    disk_gb: 1,
                },
                request,
            )
            .await?;
        assert_eq!(decision.provider_id, "provider-b");
        assert!(
            scheduler
                .placement
                .allocation_intent(&decision.allocation_id)
                .await?
                .is_none()
        );
        std::fs::remove_dir_all(root).ok();
        Ok(())
    }

    #[tokio::test]
    async fn unavailable_and_insufficient_hosts_are_skipped() -> Result<(), SchedulerError> {
        let (scheduler, root) = test_scheduler().await;
        scheduler
            .placement
            .register_provider("node-a", inv(1))
            .await?;
        scheduler
            .placement
            .set_state("node-a", ProviderState::Unavailable)
            .await?;
        assert!(matches!(
            scheduler
                .schedule(
                    "server-1",
                    Flavor {
                        vcpus: 2,
                        memory_mb: 512,
                        disk_gb: 1
                    }
                )
                .await,
            Err(SchedulerError::NoValidHost)
        ));
        std::fs::remove_dir_all(root)
            .map_err(|error| SchedulerError::Placement(PlacementError::Storage(error)))?;
        Ok(())
    }

    #[tokio::test]
    async fn agent_targeted_schedule_never_falls_back_to_another_provider()
    -> Result<(), SchedulerError> {
        let (scheduler, root) = test_scheduler().await;
        scheduler
            .placement
            .register_provider("agent-a", inv(4))
            .await?;
        scheduler
            .placement
            .register_provider("agent-b", inv(4))
            .await?;
        let decision = scheduler
            .schedule_for_agent(
                "agent-b",
                "server-1",
                Flavor {
                    vcpus: 1,
                    memory_mb: 512,
                    disk_gb: 1,
                },
            )
            .await?;
        assert_eq!(decision.provider_id, "agent-b");
        scheduler.release_terminal(&decision).await?;
        assert!(matches!(
            scheduler
                .schedule_for_agent(
                    "missing-agent",
                    "server-2",
                    Flavor {
                        vcpus: 1,
                        memory_mb: 512,
                        disk_gb: 1,
                    }
                )
                .await,
            Err(SchedulerError::NoValidHost)
        ));
        std::fs::remove_dir_all(root)
            .map_err(|error| SchedulerError::Placement(PlacementError::Storage(error)))?;
        Ok(())
    }

    #[tokio::test]
    async fn eligible_agent_set_is_fail_closed_and_deterministic() -> Result<(), SchedulerError> {
        let (scheduler, root) = test_scheduler().await;
        scheduler
            .placement
            .register_provider("agent-a", inv(4))
            .await?;
        scheduler
            .placement
            .register_provider("agent-b", inv(4))
            .await?;

        let eligible = BTreeSet::from(["agent-b".to_owned()]);
        let decision = scheduler
            .schedule_for_agents(
                &eligible,
                "server-1",
                Flavor {
                    vcpus: 1,
                    memory_mb: 512,
                    disk_gb: 1,
                },
            )
            .await?;
        assert_eq!(decision.provider_id, "agent-b");
        scheduler.release_terminal(&decision).await?;

        assert!(matches!(
            scheduler
                .schedule_for_agents(
                    &BTreeSet::new(),
                    "server-2",
                    Flavor {
                        vcpus: 1,
                        memory_mb: 512,
                        disk_gb: 1,
                    }
                )
                .await,
            Err(SchedulerError::NoValidHost)
        ));
        std::fs::remove_dir_all(root)
            .map_err(|error| SchedulerError::Placement(PlacementError::Storage(error)))?;
        Ok(())
    }

    #[tokio::test]
    async fn existing_allocation_validation_is_read_only_and_fenced() -> Result<(), SchedulerError>
    {
        let (scheduler, root) = test_scheduler().await;
        scheduler
            .placement
            .register_provider("agent-a", inv(4))
            .await?;
        let decision = scheduler
            .schedule(
                "server-1",
                Flavor {
                    vcpus: 1,
                    memory_mb: 512,
                    disk_gb: 1,
                },
            )
            .await?;
        let before = scheduler.placement.provider("agent-a").await?;
        assert_eq!(
            scheduler
                .validate_allocation("agent-a", &decision.allocation_id, "server-1")
                .await?,
            decision.allocation
        );
        let after = scheduler.placement.provider("agent-a").await?;
        assert_eq!(before, after);
        assert!(matches!(
            scheduler
                .validate_allocation("agent-a", &decision.allocation_id, "server-2")
                .await,
            Err(SchedulerError::AllocationMismatch)
        ));
        std::fs::remove_dir_all(root)
            .map_err(|error| SchedulerError::Placement(PlacementError::Storage(error)))?;
        Ok(())
    }

    #[tokio::test]
    async fn scheduler_concurrent_attempts_never_over_allocate() -> Result<(), SchedulerError> {
        let (scheduler, root) = test_scheduler().await;
        scheduler
            .placement
            .register_provider("node-a", inv(2))
            .await?;
        let flavor = Flavor {
            vcpus: 2,
            memory_mb: 2048,
            disk_gb: 1,
        };
        let first = tokio::spawn({
            let scheduler = scheduler.clone();
            async move { scheduler.schedule("server-1", flavor).await }
        });
        let second = tokio::spawn({
            let scheduler = scheduler.clone();
            async move { scheduler.schedule("server-2", flavor).await }
        });
        let (first, second) = tokio::join!(first, second);
        let first = first.expect("first scheduler task panicked");
        let second = second.expect("second scheduler task panicked");
        let mut scheduled = 0;
        let mut rejected = 0;
        for result in [first, second] {
            match result {
                Ok(_) => scheduled += 1,
                Err(SchedulerError::NoValidHost) => rejected += 1,
                Err(error) => return Err(error),
            }
        }
        assert_eq!(scheduled, 1);
        assert_eq!(rejected, 1);
        let provider = scheduler.placement.provider("node-a").await?;
        assert_eq!(provider.allocations.len(), 1);
        assert_eq!(provider.inventories[VCPU].used, 2);
        std::fs::remove_dir_all(root)
            .map_err(|error| SchedulerError::Placement(PlacementError::Storage(error)))?;
        Ok(())
    }
}
