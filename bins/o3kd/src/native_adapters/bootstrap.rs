use std::{
    collections::{BTreeMap, BTreeSet},
    sync::Arc,
};

use async_trait::async_trait;
use chrono::Utc;
use sha2::{Digest, Sha256};
use uuid::Uuid;

use o3k_kernel::{
    AuthContext, BootstrapPhase, BootstrapState, BuildingBlock, BuildingBlockState, OwnershipScope,
    Principal, PrincipalId, ScopeId, ServicePrincipal,
};
use o3k_native_api::bootstrap::{
    BootstrapFailure, BootstrapWorkflow, ClientConfig, InitRequest, InitResponse, JoinRequest,
    JoinResponse,
};
use o3k_native_api::building_block::BuildingBlockReader;
use o3k_placement::{Inventory, PlacementLedger};
use o3k_store::{BootstrapRepository, BootstrapStateRecord, EnrollmentGrantRecord, O3kStore};

use crate::native_adapters::BuildingBlockAdapter;

const STATE_ID: &str = "default";
const GRANT_TTL_MS: u64 = 5 * 60 * 1000;

pub struct BootstrapAdapter {
    pub store: Arc<O3kStore>,
    pub placement: PlacementLedger,
    pub agents: Arc<o3k_compute_agent::NodeRegistry>,
    pub locations: o3k_kernel::LocationRegistry,
    pub bootstrap_secret: Option<String>,
    pub lock: Arc<tokio::sync::Mutex<()>>,
    /// Runtime readiness projection.  The durable bootstrap row remains the
    /// authority; this handle only publishes its latest phase to the
    /// independent readiness gate after a successful durable write.
    pub readiness: o3k_api::AppState,
}

fn now_ms() -> u64 {
    Utc::now().timestamp_millis().max(0) as u64
}
fn digest(value: &str) -> String {
    Sha256::digest(value.as_bytes())
        .iter()
        .map(|byte| format!("{byte:02x}"))
        .collect()
}
fn cert_digest(value: &str) -> String {
    digest(value)
}
fn client_config(profile: &str) -> ClientConfig {
    ClientConfig {
        api_url: std::env::var("O3K_API_URL")
            .unwrap_or_else(|_| "http://127.0.0.1:18080/o3k/v1".into()),
        discovery_path: "/services".into(),
        profile_id: profile.into(),
    }
}

async fn record_bootstrap_audit(
    store: &O3kStore,
    event_id: String,
    action: &str,
    resource_id: Option<String>,
    reason: &str,
) -> Result<(), BootstrapFailure> {
    let result = store
        .insert_audit_event(&o3k_store::AuditEventRecord {
            event_id,
            timestamp: Utc::now().to_rfc3339(),
            request_id: Uuid::now_v7().to_string(),
            audit_id: Uuid::now_v7().to_string(),
            principal_id: "o3k-bootstrap".into(),
            principal_kind: "service".into(),
            effective_scope: "admin".into(),
            service: "cloud-kernel".into(),
            action: action.into(),
            resource_type: Some("cloud:bootstrap".into()),
            resource_id,
            owner_scope: Some("admin".into()),
            operation_id: None,
            outcome: "succeeded".into(),
            reason_category: Some(reason.into()),
        })
        .await;
    match result {
        Ok(()) | Err(o3k_store::StoreError::AuditEventConflict) => Ok(()),
        Err(_) => Err(BootstrapFailure::Internal),
    }
}

async fn enroll_joined_building_block(
    adapter: &BuildingBlockAdapter,
    expected: BuildingBlock,
) -> Result<(), String> {
    let current = match adapter.get(&expected.id).await? {
        Some(view) => {
            let block = &view.block;
            if block.execution_identity != expected.execution_identity
                || block.resource_provider_ids != expected.resource_provider_ids
                || block.failure_domain_id != expected.failure_domain_id
                || block.cloud_profile_id != expected.cloud_profile_id
                || !matches!(
                    block.state,
                    BuildingBlockState::Enrolling | BuildingBlockState::Ready
                )
            {
                return Err("building block conflicts with authenticated join".into());
            }
            view
        }
        None => adapter.enroll(expected, &principal_context()).await?,
    };
    match current.block.state {
        BuildingBlockState::Ready => Ok(()),
        BuildingBlockState::Enrolling => {
            adapter
                .transition(
                    &current.block.id,
                    BuildingBlockState::Ready,
                    current.block.generation,
                    Vec::new(),
                    &principal_context(),
                )
                .await?;
            Ok(())
        }
        _ => Err("building block is not eligible to become ready".into()),
    }
}

async fn ensure_joined_building_block_ready(
    adapter: &BuildingBlockAdapter,
    id: &str,
) -> Result<(), String> {
    let current = adapter
        .get(id)
        .await?
        .ok_or_else(|| "joined building block is missing".to_owned())?;
    match current.block.state {
        BuildingBlockState::Ready => Ok(()),
        BuildingBlockState::Enrolling => {
            adapter
                .transition(
                    id,
                    BuildingBlockState::Ready,
                    current.block.generation,
                    Vec::new(),
                    &principal_context(),
                )
                .await?;
            Ok(())
        }
        _ => Err("joined building block is not ready".into()),
    }
}

fn principal_context() -> AuthContext {
    AuthContext::new(
        Principal::Service(ServicePrincipal::new(
            PrincipalId::new_unchecked("o3k-bootstrap"),
            "o3k-bootstrap",
            "cloud-kernel",
        )),
        OwnershipScope::project(
            ScopeId::new_unchecked("admin"),
            Some("admin".into()),
            Some("default".into()),
        ),
        vec!["admin".into(), "operator".into()],
        0,
        u64::MAX,
        "bootstrap",
        Uuid::now_v7().to_string(),
        None,
    )
}

fn state_from_record(record: BootstrapStateRecord) -> Result<BootstrapState, BootstrapFailure> {
    let phase = match record.phase.as_str() {
        "uninitialized" => BootstrapPhase::Uninitialized,
        "initialized" => BootstrapPhase::Initialized,
        "enrolling" => BootstrapPhase::Enrolling,
        "ready" => BootstrapPhase::Ready,
        "failed" => BootstrapPhase::Failed,
        _ => return Err(BootstrapFailure::Internal),
    };
    let enrolled_agents =
        serde_json::from_str(&record.enrolled_agents).map_err(|_| BootstrapFailure::Internal)?;
    Ok(BootstrapState {
        generation: record.generation,
        phase,
        cloud_identity_id: record.cloud_identity_id,
        cloud_profile_id: record.cloud_profile_id,
        enrolled_agents,
    })
}
fn state_record(state: &BootstrapState) -> Result<BootstrapStateRecord, BootstrapFailure> {
    Ok(BootstrapStateRecord {
        state_id: STATE_ID.into(),
        generation: state.generation,
        phase: serde_json::to_string(&state.phase)
            .map_err(|_| BootstrapFailure::Internal)?
            .trim_matches('"')
            .into(),
        cloud_identity_id: state.cloud_identity_id.clone(),
        cloud_profile_id: state.cloud_profile_id.clone(),
        enrolled_agents: serde_json::to_string(&state.enrolled_agents)
            .map_err(|_| BootstrapFailure::Internal)?,
        updated_at: Utc::now().to_rfc3339(),
    })
}

fn parse_inventory(values: &BTreeMap<String, u64>) -> BTreeMap<String, Inventory> {
    values
        .iter()
        .map(|(name, total)| {
            (
                name.clone(),
                Inventory {
                    total: *total,
                    reserved: 0,
                    allocation_ratio: 1.0,
                    used: 0,
                },
            )
        })
        .collect()
}

fn parse_capabilities(
    value: &serde_json::Value,
) -> Result<o3k_compute_agent::proto::Capabilities, BootstrapFailure> {
    let object = value.as_object();
    let string = |name: &str, default: &str| {
        object
            .and_then(|o| o.get(name))
            .and_then(serde_json::Value::as_str)
            .unwrap_or(default)
            .to_owned()
    };
    let u32_value = |name: &str| {
        object
            .and_then(|o| o.get(name))
            .and_then(serde_json::Value::as_u64)
            .map(u32::try_from)
            .transpose()
            .map_err(|_| BootstrapFailure::Invalid)
            .map(|v| v.unwrap_or_default())
    };
    let u64_value = |name: &str| {
        Ok(object
            .and_then(|o| o.get(name))
            .and_then(serde_json::Value::as_u64)
            .unwrap_or_default())
    };
    let strings = |name: &str| {
        object
            .and_then(|o| o.get(name))
            .and_then(serde_json::Value::as_array)
            .map(|items| {
                items
                    .iter()
                    .map(|item| {
                        item.as_str()
                            .map(str::to_owned)
                            .ok_or(BootstrapFailure::Invalid)
                    })
                    .collect::<Result<Vec<_>, _>>()
            })
            .transpose()
            .map(|v| v.unwrap_or_default())
    };
    let flags = object
        .and_then(|o| o.get("flags"))
        .and_then(serde_json::Value::as_array)
        .map(|items| {
            items
                .iter()
                .map(|item| {
                    let item = item.as_object().ok_or(BootstrapFailure::Invalid)?;
                    Ok(o3k_compute_agent::proto::CapabilityFlag {
                        name: item
                            .get("name")
                            .and_then(serde_json::Value::as_str)
                            .ok_or(BootstrapFailure::Invalid)?
                            .to_owned(),
                        supported: item
                            .get("supported")
                            .and_then(serde_json::Value::as_bool)
                            .ok_or(BootstrapFailure::Invalid)?,
                        bounded_value: item
                            .get("bounded_value")
                            .and_then(serde_json::Value::as_str)
                            .unwrap_or_default()
                            .to_owned(),
                    })
                })
                .collect::<Result<Vec<_>, BootstrapFailure>>()
        })
        .transpose()
        .map(|v| v.unwrap_or_default())?;
    Ok(o3k_compute_agent::proto::Capabilities {
        architecture: string("architecture", "unknown"),
        agent_provider_name: string("provider_name", "o3k-bootstrap"),
        agent_provider_version: string("provider_version", "1"),
        max_vcpus: u32_value("max_vcpus")?,
        max_memory_mib: u64_value("max_memory_mib")?,
        disk_formats: strings("disk_formats")?,
        lifecycle_actions: strings("lifecycle_actions")?,
        console_log: object
            .and_then(|o| o.get("console_log"))
            .and_then(serde_json::Value::as_bool)
            .unwrap_or(false),
        max_console_log_bytes: u64_value("max_console_log_bytes")?,
        flags,
        max_disk_gb: u64_value("max_disk_gb")?,
    })
}

#[async_trait]
impl BootstrapWorkflow for BootstrapAdapter {
    async fn init(
        &self,
        request: InitRequest,
        bootstrap_secret: Option<&str>,
    ) -> Result<InitResponse, BootstrapFailure> {
        let configured = self
            .bootstrap_secret
            .as_deref()
            .ok_or(BootstrapFailure::Unauthorized)?;
        if bootstrap_secret != Some(configured) {
            return Err(BootstrapFailure::Unauthorized);
        }
        let _guard = self.lock.lock().await;
        let init_request_id = request.request_id.clone();
        let profile_id = request.profile_id.unwrap_or_else(|| "default".into());
        if request
            .agent_id
            .as_deref()
            .is_some_and(|agent| agent.trim().is_empty())
        {
            return Err(BootstrapFailure::Invalid);
        }
        // `init` is intentionally repeatable for an already bootstrapped
        // cloud.  The disposable TestLab bootstrap performs one canonical
        // init before the P15.7 journey enrolls additional real hosts.  Do
        // not rewrite an existing profile with an unconditional
        // `expected_generation = None`: the store must reject that stale
        // write, and turning that rejection into a 409 makes a valid
        // idempotent init unusable.  Reuse the durable profile after
        // validating it instead; only a genuinely fresh profile is inserted.
        let profile = if let Some(record) = self
            .store
            .get_cloud_profile(&profile_id)
            .await
            .map_err(|_| BootstrapFailure::Internal)?
        {
            let profile = record.profile().map_err(|_| BootstrapFailure::Internal)?;
            if profile.profile_id != profile_id {
                return Err(BootstrapFailure::Conflict);
            }
            profile
        } else {
            let mut profile = o3k_kernel::CloudProfile::implicit_default();
            profile.profile_id = profile_id.clone();
            let record =
                o3k_store::CloudProfileRecord::from_profile(&profile, Utc::now().to_rfc3339())
                    .map_err(|_| BootstrapFailure::Internal)?;
            self.store
                .upsert_cloud_profile(&record, None)
                .await
                .map_err(|_| BootstrapFailure::Conflict)?;
            profile
        };
        let cloud_identity_id = "cloud-default";
        let mut state = self
            .store
            .get_bootstrap_state(STATE_ID)
            .await
            .map_err(|_| BootstrapFailure::Internal)?
            .map(state_from_record)
            .transpose()?
            .unwrap_or_else(BootstrapState::uninitialized);
        state
            .initialize(cloud_identity_id, &profile.profile_id)
            .map_err(|_| BootstrapFailure::Conflict)?;
        self.store
            .upsert_bootstrap_state(&state_record(&state)?)
            .await
            .map_err(|_| BootstrapFailure::Internal)?;
        self.readiness.set_bootstrap_ready(state.is_ready());
        record_bootstrap_audit(
            &self.store,
            format!(
                "bootstrap-init-{}-{}",
                profile.profile_id,
                init_request_id.unwrap_or_else(|| Uuid::now_v7().to_string())
            ),
            "cloud-kernel:Init",
            Some(profile.profile_id.clone()),
            "bootstrap_initialized",
        )
        .await?;
        let issued_at = now_ms();
        let expires_at = issued_at.saturating_add(GRANT_TTL_MS);
        let raw = format!("{}.{}", Uuid::new_v4(), Uuid::new_v4());
        let grant_id = raw.split('.').next().unwrap_or_default().to_owned();
        self.store
            .insert_enrollment_grant(&EnrollmentGrantRecord {
                grant_id,
                agent_id: request.agent_id.unwrap_or_else(|| "*".into()),
                token_digest: digest(&raw),
                issued_at_unix_ms: issued_at,
                expires_at_unix_ms: expires_at,
                used_at_unix_ms: None,
            })
            .await
            .map_err(|_| BootstrapFailure::Internal)?;
        Ok(InitResponse {
            phase: "initialized".into(),
            cloud_identity_id: cloud_identity_id.into(),
            cloud_profile_id: profile.profile_id.clone(),
            enrollment_token: Some(raw),
            enrollment_expires_at_unix_ms: Some(expires_at),
            ready: state.is_ready(),
            config: client_config(&profile.profile_id),
        })
    }

    async fn join(&self, request: JoinRequest) -> Result<JoinResponse, BootstrapFailure> {
        if request.agent_id.trim().is_empty()
            || request.agent_epoch.trim().is_empty()
            || request.enrollment_token.trim().is_empty()
            || request.certificate.trim().is_empty()
        {
            return Err(BootstrapFailure::Invalid);
        }
        if request.inventories.is_empty() {
            return Err(BootstrapFailure::Invalid);
        }
        let _guard = self.lock.lock().await;
        let fingerprint = cert_digest(&request.certificate);
        let mut state = self
            .store
            .get_bootstrap_state(STATE_ID)
            .await
            .map_err(|_| BootstrapFailure::Internal)?
            .map(state_from_record)
            .transpose()?
            .ok_or(BootstrapFailure::Unavailable)?;
        if let Some(region) = request.region.as_deref() {
            if !self.locations.contains_region(region) {
                return Err(BootstrapFailure::Invalid);
            }
            if let Some(az) = request.availability_domain.as_deref()
                && !self
                    .locations
                    .availability_domains_of(region)
                    .iter()
                    .any(|candidate| candidate.id == az)
            {
                return Err(BootstrapFailure::Invalid);
            }
        } else if request.availability_domain.is_some() {
            return Err(BootstrapFailure::Invalid);
        }
        let adapter = BuildingBlockAdapter {
            store: self.store.clone(),
            placement: self.placement.clone(),
            agents: self.agents.clone(),
            locations: self.locations.clone(),
        };
        if let Some(old) = state.enrolled_agents.get(&request.agent_id) {
            if old != &fingerprint {
                return Err(BootstrapFailure::Conflict);
            }
            // Re-project the durable enrolled identity into the live agent
            // registry when no live registration exists — e.g. after an
            // o3kd restart or an uninstall/reinstall cycle, where the
            // canonical join legitimately arrives before the compute agent
            // reconnects (the installer defers the agent start until after
            // the join). Without this the BuildingBlock readiness view
            // rejects the joined block with "unknown execution identity"
            // and every reinstall deadlocks at the join (issue #971). The
            // request certificate was authenticated above against the
            // durable enrolled fingerprint, so the projection can only
            // restore the durable truth, never mint a new identity. When a
            // live registration already exists (plain rerun), leave it
            // untouched: replacing it would trip the epoch lease fence.
            if self.agents.snapshot(&request.agent_id).await.is_none()
                && let (Ok(capabilities), Ok(certificate_der)) = (
                    parse_capabilities(&request.capabilities),
                    o3k_compute_agent::certificate_der(request.certificate.as_bytes()),
                )
            {
                let _ = self
                    .agents
                    .register_prepared(
                        &request.agent_id,
                        &request.agent_epoch,
                        &certificate_der,
                        capabilities,
                    )
                    .await;
            }
            // Replayed joins still project the durable canonical phase into
            // the live readiness gate (for example after a transient runtime
            // failure), without changing any other readiness input.
            self.readiness.set_bootstrap_ready(state.is_ready());
            let block_id = Uuid::new_v5(
                &Uuid::NAMESPACE_URL,
                format!("o3k:building-block:{}", request.agent_id).as_bytes(),
            )
            .to_string();
            ensure_joined_building_block_ready(&adapter, &block_id)
                .await
                .map_err(|error| {
                    tracing::warn!(
                        target: "o3kd::bootstrap",
                        agent_id = %request.agent_id,
                        error = %error,
                        "replayed bootstrap join has no ready building block"
                    );
                    BootstrapFailure::Conflict
                })?;
            return Ok(JoinResponse {
                phase: "ready".into(),
                agent_id: request.agent_id.clone(),
                execution_identity: request.agent_id.clone(),
                certificate_fingerprint: fingerprint,
                resource_provider_id: request.agent_id.clone(),
                building_block_id: block_id,
                ready: true,
                config: client_config(&state.cloud_profile_id),
            });
        }
        let (grant_id, _) = request
            .enrollment_token
            .split_once('.')
            .ok_or(BootstrapFailure::Unauthorized)?;
        let grant = self
            .store
            .get_enrollment_grant(grant_id)
            .await
            .map_err(|_| BootstrapFailure::Internal)?
            .ok_or(BootstrapFailure::Unauthorized)?;
        if grant.agent_id != "*" && grant.agent_id != request.agent_id {
            return Err(BootstrapFailure::Unauthorized);
        }
        if grant.token_digest != digest(&request.enrollment_token)
            || grant.used_at_unix_ms.is_some()
            || now_ms() >= grant.expires_at_unix_ms
        {
            return Err(BootstrapFailure::Unauthorized);
        }
        let capabilities = parse_capabilities(&request.capabilities)?;
        let certificate_der = o3k_compute_agent::certificate_der(request.certificate.as_bytes())
            .map_err(|_| BootstrapFailure::Invalid)?;
        self.agents
            .register_prepared(
                &request.agent_id,
                &request.agent_epoch,
                &certificate_der,
                capabilities,
            )
            .await
            .map_err(|_| BootstrapFailure::Unauthorized)?;
        let provider = self
            .placement
            .register_provider_hierarchical(
                &request.agent_id,
                parse_inventory(&request.inventories),
                None,
                BTreeSet::new(),
                request.failure_domain_id.iter().cloned().collect(),
                request.region.as_deref(),
            )
            .await
            .map_err(|error| {
                // Keep the public problem deliberately generic, but leave a
                // non-secret operator diagnostic identifying which canonical
                // authority rejected enrollment. Protected TestLab evidence
                // can then distinguish provider conflicts from block-store
                // conflicts without exposing tokens or certificates.
                tracing::warn!(
                    target: "o3kd::bootstrap",
                    agent_id = %request.agent_id,
                    error = %error,
                    "bootstrap provider registration rejected"
                );
                BootstrapFailure::Conflict
            })?;
        let block_id = Uuid::new_v5(
            &Uuid::NAMESPACE_URL,
            format!("o3k:building-block:{}", request.agent_id).as_bytes(),
        )
        .to_string();
        let block = BuildingBlock::enrolling(
            block_id.clone(),
            request.agent_id.clone(),
            vec![provider.id.clone()],
            request.failure_domain_id.clone(),
            Some(state.cloud_profile_id.clone()),
        )
        .map_err(|_| BootstrapFailure::Invalid)?;
        enroll_joined_building_block(&adapter, block)
            .await
            .map_err(|error| {
                tracing::warn!(
                    target: "o3kd::bootstrap",
                    agent_id = %request.agent_id,
                    error = %error,
                    "bootstrap building-block readiness rejected"
                );
                BootstrapFailure::Conflict
            })?;
        state
            .begin_enrollment()
            .map_err(|_| BootstrapFailure::Conflict)?;
        state
            .record_agent(&request.agent_id, &fingerprint)
            .map_err(|_| BootstrapFailure::Conflict)?;
        self.store
            .upsert_bootstrap_state(&state_record(&state)?)
            .await
            .map_err(|_| BootstrapFailure::Internal)?;
        self.readiness.set_bootstrap_ready(state.is_ready());
        // Mark the grant consumed only after all bounded provider/lifecycle
        // side effects and the durable enrolled projection have succeeded.
        // A crash before this point can safely replay through the durable
        // agent projection; a replay after it is rejected as single-use.
        self.store
            .consume_enrollment_grant(grant_id, &digest(&request.enrollment_token), now_ms())
            .await
            .map_err(|_| BootstrapFailure::Unauthorized)?;
        record_bootstrap_audit(
            &self.store,
            format!("bootstrap-join-{}", request.agent_id),
            "cloud-kernel:Join",
            Some(request.agent_id.clone()),
            "agent_enrolled",
        )
        .await?;
        Ok(JoinResponse {
            phase: "ready".into(),
            agent_id: request.agent_id.clone(),
            execution_identity: request.agent_id,
            certificate_fingerprint: fingerprint,
            resource_provider_id: provider.id,
            building_block_id: block_id,
            ready: true,
            config: client_config(&state.cloud_profile_id),
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use o3k_store::BootstrapRepository;

    #[tokio::test]
    async fn init_join_projects_live_and_restart_readiness()
    -> Result<(), Box<dyn std::error::Error>> {
        let store = Arc::new(o3k_store::O3kStore::connect_sqlite_memory().await?);
        let placement = o3k_placement::PlacementLedger::open(
            std::env::temp_dir().join(format!("o3k-bootstrap-{}", Uuid::now_v7())),
            store.clone(),
        )
        .await?;
        let readiness = o3k_api::AppState::new();
        readiness.set_runtime_ready(true);
        readiness.set_bootstrap_ready(false);
        let adapter = BootstrapAdapter {
            store: store.clone(),
            placement,
            agents: Arc::new(o3k_compute_agent::NodeRegistry::default()),
            locations: o3k_kernel::LocationRegistry::default(),
            bootstrap_secret: Some("secret".to_owned()),
            lock: Arc::new(tokio::sync::Mutex::new(())),
            readiness: readiness.clone(),
        };

        let init = adapter
            .init(
                InitRequest {
                    profile_id: None,
                    request_id: Some("test-init".to_owned()),
                    agent_id: Some("node-test".to_owned()),
                },
                Some("secret"),
            )
            .await
            .map_err(|error| format!("init failed: {error:?}"))?;
        assert_eq!(init.phase, "initialized");
        assert!(!readiness.is_ready());

        let join = adapter
            .join(JoinRequest {
                enrollment_token: init.enrollment_token.ok_or("missing grant")?,
                agent_id: "node-test".to_owned(),
                agent_epoch: "epoch-1".to_owned(),
                certificate: String::from_utf8(include_bytes!("../../../../crates/o3k-compute-agent/tests/fixtures/agent.pem").to_vec())?,
                region: None,
                availability_domain: None,
                failure_domain_id: None,
                capabilities: serde_json::json!({"architecture":"x86_64","provider_name":"o3k-compute","provider_version":"test"}),
                inventories: BTreeMap::from([(String::from("VCPU"), 2), (String::from("MEMORY_MB"), 1024)]),
            })
            .await
            .map_err(|error| format!("join failed: {error:?}"))?;
        let first_block = store
            .get_building_block(&join.building_block_id)
            .await?
            .ok_or("building block missing after successful join")?
            .block()?;
        assert_eq!(first_block.state, o3k_kernel::BuildingBlockState::Ready);
        let first_generation = first_block.generation;
        assert!(readiness.is_ready());
        let durable = store
            .get_bootstrap_state("default")
            .await?
            .ok_or("bootstrap state missing")?;
        assert_eq!(durable.phase, "ready");

        let replay = adapter
            .join(JoinRequest {
                enrollment_token: "already-consumed-grant".into(),
                agent_id: "node-test".into(),
                agent_epoch: "epoch-1".into(),
                certificate: String::from_utf8(include_bytes!("../../../../crates/o3k-compute-agent/tests/fixtures/agent.pem").to_vec())?,
                region: None,
                availability_domain: None,
                failure_domain_id: None,
                capabilities: serde_json::json!({"architecture":"x86_64","provider_name":"o3k-compute","provider_version":"test"}),
                inventories: BTreeMap::from([(String::from("VCPU"), 2), (String::from("MEMORY_MB"), 1024)]),
            })
            .await
            .map_err(|error| format!("replayed join failed: {error:?}"))?;
        assert_eq!(replay.building_block_id, join.building_block_id);
        let replayed_block = store
            .get_building_block(&replay.building_block_id)
            .await?
            .ok_or("building block missing after replayed join")?
            .block()?;
        assert_eq!(replayed_block.state, o3k_kernel::BuildingBlockState::Ready);
        assert_eq!(replayed_block.generation, first_generation);

        // A disposable bootstrap may have already initialized this same
        // profile before a later journey enrolls another host.  Repeating
        // init must issue a new, host-bound grant without conflicting on the
        // profile's optimistic-concurrency generation.
        let repeat = adapter
            .init(
                InitRequest {
                    profile_id: None,
                    request_id: Some("test-init-repeat".to_owned()),
                    agent_id: Some("node-second".to_owned()),
                },
                Some("secret"),
            )
            .await
            .map_err(|error| format!("repeat init failed: {error:?}"))?;
        assert_eq!(repeat.phase, "initialized");
        let second_token = repeat.enrollment_token.ok_or("missing second grant")?;

        adapter
            .join(JoinRequest {
                enrollment_token: second_token,
                agent_id: "node-second".to_owned(),
                agent_epoch: "epoch-2".to_owned(),
                certificate: String::from_utf8(include_bytes!("../../../../crates/o3k-compute-agent/tests/fixtures/agent.pem").to_vec())?,
                region: None,
                availability_domain: None,
                failure_domain_id: None,
                capabilities: serde_json::json!({"architecture":"x86_64","provider_name":"o3k-compute","provider_version":"test"}),
                inventories: BTreeMap::from([(String::from("VCPU"), 2), (String::from("MEMORY_MB"), 1024)]),
            })
            .await
            .map_err(|error| format!("second join failed: {error:?}"))?;

        // A newly created runtime reconstructs the bootstrap gate from the
        // durable phase; no restart is needed for the preceding transition,
        // and a restart does not lose it.
        let restarted = o3k_api::AppState::new();
        restarted.set_runtime_ready(true);
        restarted.set_bootstrap_ready(durable.phase == "ready");
        assert!(restarted.is_ready());

        // Reinstall/restart convergence (issue #971): a NEW runtime over the
        // SAME durable store starts with an EMPTY live agent registry (the
        // compute agent has not reconnected yet — the installer defers its
        // start until after the join). A replayed join must re-project the
        // durable enrolled identity into the live registry instead of
        // failing the joined BuildingBlock readiness with "unknown execution
        // identity".
        let restarted_readiness = o3k_api::AppState::new();
        restarted_readiness.set_runtime_ready(true);
        restarted_readiness.set_bootstrap_ready(false);
        let restarted_adapter = BootstrapAdapter {
            store: store.clone(),
            placement: o3k_placement::PlacementLedger::open(
                std::env::temp_dir().join(format!("o3k-bootstrap-restart-{}", Uuid::now_v7())),
                store.clone(),
            )
            .await?,
            agents: Arc::new(o3k_compute_agent::NodeRegistry::default()),
            locations: o3k_kernel::LocationRegistry::default(),
            bootstrap_secret: Some("secret".to_owned()),
            lock: Arc::new(tokio::sync::Mutex::new(())),
            readiness: restarted_readiness.clone(),
        };
        assert!(
            restarted_adapter
                .agents
                .snapshot("node-test")
                .await
                .is_none(),
            "fresh runtime must start with an empty live registry"
        );
        let reinstall_replay = restarted_adapter
            .join(JoinRequest {
                enrollment_token: "reinstall-replay-grant".into(),
                agent_id: "node-test".into(),
                agent_epoch: "epoch-3".into(),
                certificate: String::from_utf8(include_bytes!("../../../../crates/o3k-compute-agent/tests/fixtures/agent.pem").to_vec())?,
                region: None,
                availability_domain: None,
                failure_domain_id: None,
                capabilities: serde_json::json!({"architecture":"x86_64","provider_name":"o3k-compute","provider_version":"test"}),
                inventories: BTreeMap::from([(String::from("VCPU"), 2), (String::from("MEMORY_MB"), 1024)]),
            })
            .await
            .map_err(|error| format!("reinstall replay join failed: {error:?}"))?;
        assert_eq!(reinstall_replay.building_block_id, join.building_block_id);
        assert_eq!(reinstall_replay.phase, "ready");
        assert!(restarted_readiness.is_ready());
        assert!(
            restarted_adapter
                .agents
                .snapshot("node-test")
                .await
                .is_some(),
            "replayed join must re-project the durable identity into the live registry"
        );
        Ok(())
    }
}
