use std::collections::{BTreeMap, BTreeSet};
use std::sync::Arc;

use o3k_kernel::{
    AuthContext, BuildingBlock, BuildingBlockState, DrainBlocker, DrainBlockerKind,
    LocationRegistry, PrincipalKind,
};
use o3k_native_api::building_block::{BuildingBlockReader, BuildingBlockView, CapacityDimension};
use o3k_placement::{PlacementLedger, ProviderState};
use o3k_provider::AgentNodeRegistry;
use o3k_store::{AuditEventRecord, BuildingBlockRecord, ComputeRepository, O3kStore};

pub struct BuildingBlockAdapter {
    pub store: Arc<O3kStore>,
    pub placement: PlacementLedger,
    pub agents: Arc<dyn AgentNodeRegistry>,
    pub locations: LocationRegistry,
}

fn now() -> String {
    chrono::Utc::now().to_rfc3339()
}

impl BuildingBlockAdapter {
    /// Project lifecycle gates into Placement, which remains the scheduling
    /// authority. The projection must be durable before a drain races with a
    /// new create.
    async fn project_provider_state(
        &self,
        block: &BuildingBlock,
        state: ProviderState,
    ) -> Result<(), String> {
        for provider_id in &block.resource_provider_ids {
            self.placement
                .set_state(provider_id, state)
                .await
                .map_err(|error| error.to_string())?;
        }
        Ok(())
    }

    fn resource_matches_provider_ids(
        kind: &str,
        resource: &o3k_store::ResourceRecord,
        ids: &BTreeSet<&str>,
    ) -> Result<bool, String> {
        if kind == "compute_instance" {
            // Placement lives in the durable create intent and names the
            // BuildingBlock's resource provider. The execution provider
            // identity may still be unset while terminal lifecycle
            // projection is converging.
            let intent = serde_json::from_str::<o3k_provider::CreateInstanceRequest>(
                &resource.desired_state,
            )
            .map_err(|error| format!("invalid compute instance desired state: {error}"))?;
            return Ok(intent
                .placement_provider_id
                .is_some_and(|provider_id| ids.contains(provider_id.as_str())));
        }

        Ok(resource
            .provider_id
            .as_deref()
            .is_some_and(|provider_id| ids.contains(provider_id)))
    }

    async fn view(&self, block: BuildingBlock) -> Result<BuildingBlockView, String> {
        // References are part of the durable BuildingBlock identity.  Validate
        // them on every projection as well as on enrollment so a provider,
        // topology, profile, or execution identity change cannot turn an
        // invalid record into an apparently schedulable view.
        self.validate_references(&block).await?;
        let providers = self
            .placement
            .providers()
            .await
            .map_err(|e| e.to_string())?;
        let ids: BTreeSet<&str> = block
            .resource_provider_ids
            .iter()
            .map(String::as_str)
            .collect();
        let mut capabilities = BTreeSet::new();
        let mut dimensions: BTreeMap<String, (u64, u64)> = BTreeMap::new();
        for provider in providers.iter().filter(|p| ids.contains(p.id.as_str())) {
            capabilities.extend(provider.traits.iter().cloned());
            for (name, inventory) in &provider.inventories {
                let total = inventory.total;
                let available = inventory.available();
                let entry = dimensions.entry(name.clone()).or_default();
                entry.0 = entry.0.saturating_add(total);
                entry.1 = entry.1.saturating_add(available);
            }
        }
        let agent_available = self
            .agents
            .snapshot(&block.execution_identity)
            .await
            .map(|s| {
                for flag in s.capabilities.flags.iter().filter(|f| f.supported) {
                    capabilities.insert(flag.name.clone());
                }
                matches!(s.availability, o3k_provider::AgentAvailability::Available)
            });
        let capacity = dimensions
            .into_iter()
            .map(|(resource, (total, available))| CapacityDimension {
                resource,
                total,
                available,
            })
            .collect();
        Ok(BuildingBlockView {
            block,
            capabilities: capabilities.into_iter().collect(),
            capacity,
            agent_available,
        })
    }

    fn audit(&self, block: &BuildingBlock, auth: &AuthContext, action: &str) -> AuditEventRecord {
        AuditEventRecord {
            event_id: format!("building-block:{}:{}", block.id, block.generation),
            timestamp: now(),
            request_id: auth.request_id().to_owned(),
            audit_id: auth.audit_id().to_owned(),
            principal_id: auth.principal().id().to_string(),
            principal_kind: match auth.principal().kind() {
                PrincipalKind::User => "user",
                PrincipalKind::Service => "service",
            }
            .to_owned(),
            effective_scope: auth.effective_scope().id().as_str().to_owned(),
            service: "building_block".to_owned(),
            action: format!("building_block:{action}"),
            resource_type: Some("building_block:building_block".to_owned()),
            resource_id: Some(block.id.clone()),
            owner_scope: None,
            operation_id: None,
            outcome: "succeeded".to_owned(),
            reason_category: None,
        }
    }

    async fn validate_references(&self, block: &BuildingBlock) -> Result<(), String> {
        block.validate().map_err(|e| e.to_string())?;
        let providers = self
            .placement
            .providers()
            .await
            .map_err(|e| e.to_string())?;
        let known: BTreeSet<&str> = providers.iter().map(|p| p.id.as_str()).collect();
        if block
            .resource_provider_ids
            .iter()
            .any(|id| !known.contains(id.as_str()))
        {
            return Err("unknown resource provider".into());
        }
        if let Some(fd) = &block.failure_domain_id
            && !self.locations.contains_failure_domain(fd)
        {
            return Err("unknown failure domain".into());
        }
        if let Some(profile) = &block.cloud_profile_id
            && self
                .store
                .get_cloud_profile(profile)
                .await
                .map_err(|e| e.to_string())?
                .is_none()
        {
            return Err("unknown cloud profile".into());
        }
        if self
            .agents
            .snapshot(&block.execution_identity)
            .await
            .is_none()
        {
            return Err("unknown execution identity".into());
        }
        Ok(())
    }

    async fn derived_blockers(&self, block: &BuildingBlock) -> Result<Vec<DrainBlocker>, String> {
        let ids: BTreeSet<&str> = block
            .resource_provider_ids
            .iter()
            .map(String::as_str)
            .collect();
        let mut counts = [0u64; 3];
        for kind in [
            "compute_instance",
            "volume",
            "storage_volume",
            "attachment",
            "volume_attachment",
        ] {
            for resource in self
                .store
                .list_resources_by_kind(kind)
                .await
                .map_err(|e| e.to_string())?
            {
                if Self::resource_matches_provider_ids(kind, &resource, &ids)? {
                    let index = if kind == "compute_instance" {
                        0
                    } else if kind.contains("attachment") {
                        2
                    } else {
                        1
                    };
                    counts[index] = counts[index].saturating_add(1);
                }
            }
        }
        Ok([
            DrainBlockerKind::Workload,
            DrainBlockerKind::LocalStorage,
            DrainBlockerKind::Attachment,
        ]
        .into_iter()
        .enumerate()
        .filter_map(|(i, kind)| {
            (counts[i] > 0).then_some(DrainBlocker {
                kind,
                count: counts[i],
            })
        })
        .collect())
    }
}

#[async_trait::async_trait]
impl BuildingBlockReader for BuildingBlockAdapter {
    async fn get(&self, id: &str) -> Result<Option<BuildingBlockView>, String> {
        let Some(record) = self
            .store
            .get_building_block(id)
            .await
            .map_err(|e| e.to_string())?
        else {
            return Ok(None);
        };
        let block = record.block().map_err(|e| e.to_string())?;
        Ok(Some(self.view(block).await?))
    }

    async fn list(&self) -> Result<Vec<BuildingBlockView>, String> {
        let records = self
            .store
            .list_building_blocks()
            .await
            .map_err(|e| e.to_string())?;
        let mut out = Vec::with_capacity(records.len());
        for record in records {
            let block = record.block().map_err(|e| e.to_string())?;
            // Removed is a terminal tombstone, not a live management object:
            // the operator list must not present it as schedulable topology
            // (the P15.7 remove/rejoin/replace journey asserts absence after
            // a canonical remove). The durable record stays for audit.
            if block.state == BuildingBlockState::Removed {
                continue;
            }
            out.push(self.view(block).await?);
        }
        Ok(out)
    }

    async fn enroll(
        &self,
        block: BuildingBlock,
        auth: &AuthContext,
    ) -> Result<BuildingBlockView, String> {
        self.validate_references(&block).await?;
        let record = BuildingBlockRecord::from_block(&block, now()).map_err(|e| e.to_string())?;
        let existing = self
            .store
            .get_building_block(&block.id)
            .await
            .map_err(|e| e.to_string())?;
        if let Some(old) = existing {
            let old_block = old.block().map_err(|e| e.to_string())?;
            if old_block == block {
                return self.view(block).await;
            }
            return Err("building block already exists".into());
        }
        self.store
            .upsert_building_block_with_audit(
                &record,
                None,
                &self.audit(&block, auth, "EnrollBuildingBlock"),
            )
            .await
            .map_err(|e| e.to_string())?;
        self.view(block).await
    }

    async fn transition(
        &self,
        id: &str,
        target: BuildingBlockState,
        expected_generation: u64,
        _blockers: Vec<DrainBlocker>,
        auth: &AuthContext,
    ) -> Result<BuildingBlockView, String> {
        let current = self
            .store
            .get_building_block(id)
            .await
            .map_err(|e| e.to_string())?
            .ok_or_else(|| "building block not found".to_owned())?;
        let old = current.block().map_err(|e| e.to_string())?;
        if old.generation != expected_generation {
            return Err("stale generation".into());
        }
        let blockers = if matches!(
            target,
            BuildingBlockState::Draining | BuildingBlockState::Removed
        ) {
            self.derived_blockers(&old).await?
        } else {
            Vec::new()
        };
        let next = old
            .transition(target, blockers)
            .map_err(|e| e.to_string())?;
        let record = BuildingBlockRecord::from_block(&next, now()).map_err(|e| e.to_string())?;
        // Close capacity before recording a drain/unavailable/removal
        // transition. If the block write fails, remaining closed is
        // fail-safe and prevents new work from entering the requested drain.
        let projected_state = match target {
            BuildingBlockState::Enrolling => Some(ProviderState::Unavailable),
            BuildingBlockState::Ready => None,
            BuildingBlockState::Unavailable | BuildingBlockState::Failed => {
                Some(ProviderState::Unavailable)
            }
            BuildingBlockState::Draining => Some(ProviderState::Draining),
            BuildingBlockState::Removed => Some(ProviderState::Deleted),
        };
        if let Some(state) = projected_state {
            self.project_provider_state(&old, state).await?;
        }
        self.store
            .upsert_building_block_with_audit(
                &record,
                Some(old.generation),
                &self.audit(&next, auth, "ManageBuildingBlock"),
            )
            .await
            .map_err(|e| e.to_string())?;
        // Capacity is reopened only after the durable block reaches Ready.
        if target == BuildingBlockState::Ready {
            self.project_provider_state(&next, ProviderState::Enabled)
                .await?;
        }
        self.view(next).await
    }
}

#[cfg(test)]
mod tests {
    use super::BuildingBlockAdapter;
    use o3k_kernel::{AuthContext, OwnershipScope, Principal, PrincipalId, ServicePrincipal};
    use o3k_native_api::building_block::BuildingBlockReader;
    use o3k_provider::{
        AgentAdministrativeState, AgentAvailability, AgentCapabilities, AgentEpochLease,
        AgentEvent, AgentNodeRegistry, AgentNodeSnapshot,
    };
    use o3k_store::ResourceRecord;
    use std::collections::{BTreeMap, BTreeSet, HashMap};
    use std::sync::Arc;
    use uuid::Uuid;

    struct FakeAgents {
        snapshots: HashMap<String, AgentNodeSnapshot>,
    }

    #[async_trait::async_trait]
    impl AgentNodeRegistry for FakeAgents {
        async fn all(&self) -> Vec<AgentNodeSnapshot> {
            self.snapshots.values().cloned().collect()
        }
        async fn snapshot(&self, agent_id: &str) -> Option<AgentNodeSnapshot> {
            self.snapshots.get(agent_id).cloned()
        }
        async fn lease_current_epoch(
            &self,
            _agent_id: &str,
            _agent_epoch: &str,
        ) -> Option<Box<dyn AgentEpochLease>> {
            None
        }
        fn subscribe_events(&self) -> tokio::sync::broadcast::Receiver<AgentEvent> {
            tokio::sync::broadcast::channel(1).1
        }
    }

    fn snapshot(agent_id: &str) -> AgentNodeSnapshot {
        AgentNodeSnapshot {
            agent_id: agent_id.to_owned(),
            agent_epoch: "epoch-1".to_owned(),
            availability: AgentAvailability::Available,
            administrative_state: AgentAdministrativeState::Enabled,
            capabilities: AgentCapabilities {
                agent_provider_name: "test".to_owned(),
                agent_provider_version: "1".to_owned(),
                max_vcpus: 8,
                max_memory_mib: 8192,
                max_disk_gb: 100,
                lifecycle_actions: vec![],
                console_log: false,
                flags: vec![],
            },
        }
    }

    fn operator_context() -> AuthContext {
        AuthContext::new(
            Principal::Service(ServicePrincipal::new(
                PrincipalId::new_unchecked("o3k-test"),
                "o3k-test",
                "cloud-kernel",
            )),
            OwnershipScope::project(
                o3k_kernel::ScopeId::new_unchecked("admin"),
                Some("admin".into()),
                Some("default".into()),
            ),
            vec!["admin".into(), "operator".into()],
            0,
            u64::MAX,
            "building-block-test",
            Uuid::now_v7().to_string(),
            None,
        )
    }

    #[tokio::test]
    async fn removed_block_leaves_operator_list_but_stays_durable()
    -> Result<(), Box<dyn std::error::Error>> {
        let store = Arc::new(o3k_store::O3kStore::connect_sqlite_memory().await?);
        let placement = o3k_placement::PlacementLedger::open(
            std::env::temp_dir().join(format!("o3k-bb-list-{}", Uuid::now_v7())),
            store.clone(),
        )
        .await?;
        for agent in ["agent-a", "agent-b"] {
            placement
                .register_provider(
                    agent,
                    BTreeMap::from([(
                        "VCPU".to_owned(),
                        o3k_placement::Inventory {
                            total: 4,
                            reserved: 0,
                            allocation_ratio: 1.0,
                            used: 0,
                        },
                    )]),
                )
                .await?;
        }
        let agents = FakeAgents {
            snapshots: HashMap::from([
                ("agent-a".to_owned(), snapshot("agent-a")),
                ("agent-b".to_owned(), snapshot("agent-b")),
            ]),
        };
        let adapter = BuildingBlockAdapter {
            store: store.clone(),
            placement,
            agents: Arc::new(agents),
            locations: o3k_kernel::LocationRegistry::default(),
        };
        let auth = operator_context();

        let block_a = o3k_kernel::BuildingBlock::enrolling(
            "block-a",
            "agent-a",
            vec!["agent-a".to_owned()],
            None,
            None,
        )?;
        let block_b = o3k_kernel::BuildingBlock::enrolling(
            "block-b",
            "agent-b",
            vec!["agent-b".to_owned()],
            None,
            None,
        )?;
        adapter.enroll(block_a, &auth).await?;
        adapter.enroll(block_b, &auth).await?;
        let ready = adapter
            .transition(
                "block-a",
                o3k_kernel::BuildingBlockState::Ready,
                1,
                vec![],
                &auth,
            )
            .await?;
        adapter
            .transition(
                "block-a",
                o3k_kernel::BuildingBlockState::Draining,
                ready.block.generation,
                vec![],
                &auth,
            )
            .await?;
        let draining = store
            .get_building_block("block-a")
            .await?
            .ok_or("block-a missing")?
            .block()?;
        adapter
            .transition(
                "block-a",
                o3k_kernel::BuildingBlockState::Removed,
                draining.generation,
                vec![],
                &auth,
            )
            .await?;

        // The durable tombstone stays for audit...
        let tombstone = store
            .get_building_block("block-a")
            .await?
            .ok_or("removed block-a tombstone missing")?
            .block()?;
        assert_eq!(tombstone.state, o3k_kernel::BuildingBlockState::Removed);
        // ...but the operator list must present only live management objects.
        let listed: BTreeSet<String> = adapter
            .list()
            .await?
            .into_iter()
            .map(|view| view.block.id)
            .collect();
        assert_eq!(listed, BTreeSet::from(["block-b".to_owned()]));
        Ok(())
    }

    #[test]
    fn compute_blocker_matches_before_provider_identity_projection() {
        let resource = ResourceRecord {
            id: Uuid::new_v4(),
            kind: "compute_instance".to_owned(),
            project_id: "project-a".to_owned(),
            generation: 1,
            observed_generation: 1,
            desired_state: serde_json::json!({
                "operation_id": Uuid::new_v4(),
                "o3k_server_id": Uuid::new_v4(),
                "name": "workload-a",
                "vcpus": 1,
                "memory_mib": 512,
                "idempotency_key": "create-workload-a",
                "placement_provider_id": "agent-a",
            })
            .to_string(),
            observed_state: "ACTIVE".to_owned(),
            provider_id: None,
        };

        let block_provider_ids = BTreeSet::from(["agent-a"]);
        assert!(matches!(
            BuildingBlockAdapter::resource_matches_provider_ids(
                "compute_instance",
                &resource,
                &block_provider_ids,
            ),
            Ok(true)
        ));
    }

    #[test]
    fn malformed_compute_intent_fails_closed_for_drain_blockers() {
        let resource = ResourceRecord {
            id: Uuid::new_v4(),
            kind: "compute_instance".to_owned(),
            project_id: "project-a".to_owned(),
            generation: 1,
            observed_generation: 1,
            desired_state: "not-json".to_owned(),
            observed_state: "ACTIVE".to_owned(),
            provider_id: None,
        };

        let result = BuildingBlockAdapter::resource_matches_provider_ids(
            "compute_instance",
            &resource,
            &BTreeSet::from(["agent-a"]),
        );
        assert!(result.is_err());
    }
}
