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
    ) -> bool {
        if kind == "compute_instance" {
            // ResourceRecord.provider_id is the execution provider's instance
            // identity (for example, the libvirt domain UUID). Placement lives
            // in the durable create intent and names the BuildingBlock's
            // resource provider instead.
            if resource.provider_id.is_none() {
                return false;
            }
            return serde_json::from_str::<o3k_provider::CreateInstanceRequest>(
                &resource.desired_state,
            )
            .ok()
            .and_then(|intent| intent.placement_provider_id)
            .is_some_and(|provider_id| ids.contains(provider_id.as_str()));
        }

        resource
            .provider_id
            .as_deref()
            .is_some_and(|provider_id| ids.contains(provider_id))
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
                if Self::resource_matches_provider_ids(kind, &resource, &ids) {
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
            out.push(
                self.view(record.block().map_err(|e| e.to_string())?)
                    .await?,
            );
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
    use o3k_store::ResourceRecord;
    use std::collections::BTreeSet;
    use uuid::Uuid;

    #[test]
    fn compute_blocker_matches_placement_provider_not_instance_identity() {
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
            provider_id: Some("libvirt-domain-uuid".to_owned()),
        };
        let block_provider_ids = BTreeSet::from(["agent-a"]);
        let instance_provider_ids = BTreeSet::from(["libvirt-domain-uuid"]);

        assert!(BuildingBlockAdapter::resource_matches_provider_ids(
            "compute_instance",
            &resource,
            &block_provider_ids,
        ));
        assert!(!BuildingBlockAdapter::resource_matches_provider_ids(
            "compute_instance",
            &resource,
            &instance_provider_ids,
        ));
    }
}
