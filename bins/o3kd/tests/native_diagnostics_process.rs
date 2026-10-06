//! Real-adapter, real-router HTTP journey for the native operator diagnostics
//! endpoints (#903). Proves the production `o3kd` diagnostics adapter
//! (`o3kd::native_adapters::DiagnosticsReaderAdapter`) serves
//! `/o3k/v1/operator/diagnostics{,/services,/providers,/capacity}` over the
//! real production `o3k_api::router_with_state` with the real
//! `StaticAuthorizer`, and that a controlled provider failure flows
//! healthy -> stale/degraded -> healthy without leaking secrets.
#![allow(clippy::expect_used, clippy::panic)]

use axum::body::Body;
use axum::http::{Request, StatusCode, header};
use o3k_kernel::{
    AuthContext, ControllerSession, ManifestRegistry, OwnershipScope, Principal, PrincipalId,
    ProtocolVersion, ScopeId, ScopeKind, ServicePrincipal, UserPrincipal,
};
use o3k_native_api::auth::TokenIssuer;
use o3k_native_api::pagination::CursorConfig;
use o3k_provider::{
    AgentAdministrativeState, AgentAvailability, AgentCapabilities, AgentEpochLease, AgentEvent,
    AgentNodeRegistry, AgentNodeSnapshot,
};
use o3k_store::PlacementInventoryRecord;
use o3k_store::PlacementRepository;
use serde_json::Value;
use std::collections::HashMap;
use std::sync::Arc;
use tower::ServiceExt;

const ENDPOINTS: [&str; 4] = [
    "/o3k/v1/operator/diagnostics",
    "/o3k/v1/operator/diagnostics/services",
    "/o3k/v1/operator/diagnostics/providers",
    "/o3k/v1/operator/diagnostics/capacity",
];

/// Secret-safety vocabulary: the adapter must never leak node identity, agent
/// epoch, credentials, or connection strings in any 200 body.
const SECRETS: [&str; 7] = [
    "node-",
    "node_id",
    "agent_epoch",
    "password",
    "Bearer secret",
    "private_key",
    "postgres://",
];

type TestResult = Result<(), Box<dyn std::error::Error>>;

fn now_unix_ms() -> i64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|duration| duration.as_millis() as i64)
        .unwrap_or(0)
}

fn session(service: &str) -> ControllerSession {
    ControllerSession {
        service_id: service.to_owned(),
        namespace: service.to_owned(),
        service_principal: ServicePrincipal::new(
            PrincipalId::new_unchecked(format!("{service}-controller")),
            format!("{service}-controller"),
            service,
        ),
        session_id: uuid::Uuid::new_v4(),
        session_generation: 1,
        protocol_version: ProtocolVersion::new(1, 0),
        manifest_digest: format!("native-diagnostics-{service}"),
        manifest_generation: 1,
        started_at: "2026-09-11T00:00:00Z".to_owned(),
    }
}

fn auth_context(scope_id: &str, scope_kind: ScopeKind, roles: &[&str]) -> AuthContext {
    AuthContext::new(
        Principal::User(UserPrincipal::new(
            PrincipalId::new_unchecked("user-1"),
            "user-1",
            None,
        )),
        OwnershipScope::new(ScopeId::new_unchecked(scope_id), scope_kind, None, None),
        roles.iter().map(|role| (*role).to_owned()).collect(),
        1,
        2,
        "audit-test",
        "request-test",
        None,
    )
}

/// A mock `TokenIssuer` returning crafted `AuthContext`s keyed by token string:
/// a system operator, a plain tenant, and a project-scoped caller carrying the
/// role name "operator" (which must still be denied: authority is scope-based).
#[derive(Clone)]
struct TestIssuer {
    operator: AuthContext,
    tenant: AuthContext,
    operator_role: AuthContext,
}

#[async_trait::async_trait]
impl TokenIssuer for TestIssuer {
    async fn issue_native(
        &self,
        _request: &o3k_native_api::auth::NativeTokenRequestV1,
    ) -> Result<(String, Value), o3k_native_api::error::ProblemDetails> {
        Err(o3k_native_api::error::ProblemDetails::unauthorized())
    }

    async fn auth_context(
        &self,
        token: &str,
    ) -> Result<AuthContext, o3k_native_api::error::ProblemDetails> {
        match token {
            "operator-token" => Ok(self.operator.clone()),
            "tenant-token" => Ok(self.tenant.clone()),
            "operator-role-token" => Ok(self.operator_role.clone()),
            _ => Err(o3k_native_api::error::ProblemDetails::unauthorized()),
        }
    }
}

/// A fake `AgentNodeRegistry` backed by an in-memory map so the test can drive
/// provider availability/heartbeat state and observe healthy -> stale ->
/// healthy transitions through the real adapter.
#[derive(Clone)]
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

    fn subscribe_events(&self) -> tokio::sync::broadcast::Receiver<AgentEvent> {
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

fn snapshot(availability: AgentAvailability) -> AgentNodeSnapshot {
    AgentNodeSnapshot {
        agent_id: "provider-a".to_owned(),
        host_id: "host-a".to_owned(),
        agent_epoch: "epoch-1".to_owned(),
        availability,
        administrative_state: AgentAdministrativeState::Enabled,
        capabilities: capabilities(),
    }
}

/// A fresh agent map: `provider-a` is available with a current heartbeat.
fn fresh_agents() -> Arc<FakeAgents> {
    Arc::new(FakeAgents {
        nodes: Arc::new(tokio::sync::Mutex::new(HashMap::from([(
            "provider-a".to_owned(),
            (snapshot(AgentAvailability::Available), Some(now_unix_ms())),
        )]))),
    })
}

async fn build_runtime(
    agents: Arc<FakeAgents>,
) -> Result<axum::Router, Box<dyn std::error::Error>> {
    let store = o3k_store::unified::O3kStore::connect_sqlite_memory().await?;
    build_runtime_with_store_and_provider_count(agents, store, 1).await
}

async fn build_runtime_with_store_and_provider_count(
    agents: Arc<FakeAgents>,
    store: o3k_store::unified::O3kStore,
    provider_count: usize,
) -> Result<axum::Router, Box<dyn std::error::Error>> {
    let store = Arc::new(store);
    for index in 0..provider_count {
        let provider_id = format!("provider-{}", (b'a' + index as u8) as char);
        store
            .register_provider(
                &provider_id,
                &[PlacementInventoryRecord {
                    resource_class: "VCPU".to_owned(),
                    total: 8,
                    reserved: 1,
                    allocation_ratio: 1.0,
                    used: 2,
                }],
            )
            .await?;
    }

    // One shared registry is handed to both the adapter and the native state so
    // the diagnostics projection reads the same controller set the router sees.
    let mut manifests = ManifestRegistry::new();
    manifests.seed_core()?;
    manifests.register_controller("compute", session("compute"))?;
    manifests.activate_controller("compute")?;
    let registry = Arc::new(std::sync::RwLock::new(manifests));

    let adapter = Arc::new(o3kd::native_adapters::DiagnosticsReaderAdapter::new(
        registry.clone(),
        agents.clone(),
        store,
        o3k_kernel::LocationRegistry::default(),
    ));

    let token_issuer: Arc<dyn TokenIssuer> = Arc::new(TestIssuer {
        operator: auth_context("system", ScopeKind::System, &["operator"]),
        tenant: auth_context("project-a", ScopeKind::Project, &["member"]),
        operator_role: auth_context("project-b", ScopeKind::Project, &["operator"]),
    });

    let native = o3k_native_api::NativeApiState::new(
        Some(registry.read().expect("registry lock").clone()),
        CursorConfig::new(b"test-only-native-cursor-key-at-least-32-bytes".to_vec())
            .expect("test cursor key"),
        Some(token_issuer),
        None,
        None,
        None,
    )?
    .with_diagnostics_reader(adapter)
    .with_authorizer(Arc::new(o3k_kernel::StaticAuthorizer::standard()));

    Ok(o3k_api::router_with_state(
        o3k_api::AppState::new().with_native_api(native),
    ))
}

/// Narrow PostgreSQL reproduction hook. It is ignored by ordinary CI and is
/// run explicitly with a disposable, run-scoped database URL when incident
/// evidence does not identify which capacity store operation failed.
#[tokio::test]
#[ignore = "requires an explicitly disposable PostgreSQL URL"]
async fn diagnostics_http_postgres_capacity_narrow_reproduction() -> TestResult {
    let url = std::env::var("O3K_P15_7_NARROW_PG_URL")?;
    let store = o3k_store::unified::O3kStore::connect_postgres(&url).await?;
    let app = build_runtime_with_store_and_provider_count(fresh_agents(), store, 5).await?;
    let (status, body) = get(
        &app,
        "/o3k/v1/operator/diagnostics/capacity",
        "operator-token",
    )
    .await?;
    assert_eq!(
        status,
        StatusCode::OK,
        "narrow PostgreSQL capacity failed: {body}"
    );
    eprintln!("narrow PostgreSQL capacity status={status} body={body}");
    Ok(())
}

async fn get(
    app: &axum::Router,
    uri: &str,
    token: &str,
) -> Result<(StatusCode, String), Box<dyn std::error::Error>> {
    let response = app
        .clone()
        .oneshot(
            Request::builder()
                .uri(uri)
                .header(header::AUTHORIZATION, format!("Bearer {token}"))
                .body(Body::empty())?,
        )
        .await?;
    let status = response.status();
    let bytes = axum::body::to_bytes(response.into_body(), 64 * 1024).await?;
    Ok((status, String::from_utf8_lossy(&bytes).into_owned()))
}

/// A plain tenant, and a project-scoped caller holding an `operator` role name,
/// are both denied every diagnostics endpoint: authority is scope-based.
#[tokio::test]
async fn diagnostics_http_denies_project_scoped_callers_even_with_operator_role() -> TestResult {
    let agents = fresh_agents();
    let app = build_runtime(agents).await?;
    for uri in ENDPOINTS {
        for token in ["tenant-token", "operator-role-token"] {
            let (status, _) = get(&app, uri, token).await?;
            assert_eq!(status, StatusCode::FORBIDDEN, "{uri} token={token}");
        }
    }
    Ok(())
}

/// The system operator reaches all four endpoints, the providers page reports
/// the registered provider as healthy, the summary carries the v1 envelope, and
/// no 200 body leaks node identity, agent epoch, or credential material.
#[tokio::test]
async fn diagnostics_http_system_operator_healthy_journey_with_secret_safety() -> TestResult {
    let agents = fresh_agents();
    let app = build_runtime(agents).await?;

    for uri in ENDPOINTS {
        let (status, body) = get(&app, uri, "operator-token").await?;
        assert_eq!(status, StatusCode::OK, "{uri}");
        let value: Value = serde_json::from_str(&body)?;
        if uri.ends_with("/services") || uri.ends_with("/providers") {
            assert!(value.get("items").is_some(), "{uri}");
            assert!(value.get("has_more").is_some(), "{uri}");
        } else {
            assert_eq!(value["version"], "v1", "{uri}");
            assert!(value.get("status").is_some(), "{uri}");
        }
        for secret in SECRETS {
            assert!(!body.contains(secret), "{secret:?} leaked into {uri}");
        }
    }

    // The providers page surfaces the durable + observed provider as healthy.
    let (status, body) = get(
        &app,
        "/o3k/v1/operator/diagnostics/providers",
        "operator-token",
    )
    .await?;
    assert_eq!(status, StatusCode::OK);
    let value: Value = serde_json::from_str(&body)?;
    let item = &value["items"][0];
    assert_eq!(item["provider_id"], "provider-a", "{body}");
    assert_eq!(item["status"], "healthy", "{body}");

    // The summary envelope reports a stable status value with the v1 version.
    let (_, body) = get(&app, "/o3k/v1/operator/diagnostics", "operator-token").await?;
    let value: Value = serde_json::from_str(&body)?;
    assert_eq!(value["version"], "v1");
    let status = value["status"].as_str().ok_or("summary status")?;
    assert!(
        ["healthy", "degraded", "unavailable", "stale", "unknown"].contains(&status),
        "unexpected summary status {status}: {body}"
    );
    Ok(())
}

/// A controlled provider failure (agent unavailable with a heartbeat older than
/// the lease) flows the provider to `stale`, drives the summary away from
/// `healthy`, and recovers to `healthy` once the agent reports a fresh
/// observation — all through the same real adapter and router.
#[tokio::test]
async fn diagnostics_http_provider_failure_degrades_then_recovers() -> TestResult {
    let agents = fresh_agents();
    let app = build_runtime(agents.clone()).await?;

    // Healthy baseline.
    let (_, body) = get(
        &app,
        "/o3k/v1/operator/diagnostics/providers",
        "operator-token",
    )
    .await?;
    let value: Value = serde_json::from_str(&body)?;
    assert_eq!(value["items"][0]["status"], "healthy", "{body}");

    // Degradation: heartbeat lost, older than the 15s lease.
    let lease = o3kd::native_adapters::diagnostics::AGENT_LEASE_MS;
    {
        let mut nodes = agents.nodes.lock().await;
        nodes.insert(
            "provider-a".to_owned(),
            (
                snapshot(AgentAvailability::Unavailable),
                Some(now_unix_ms() - lease - 1_000),
            ),
        );
    }
    let (status, body) = get(
        &app,
        "/o3k/v1/operator/diagnostics/providers",
        "operator-token",
    )
    .await?;
    assert_eq!(status, StatusCode::OK);
    let value: Value = serde_json::from_str(&body)?;
    assert_eq!(value["items"][0]["status"], "stale", "{body}");

    let (_, body) = get(&app, "/o3k/v1/operator/diagnostics", "operator-token").await?;
    let value: Value = serde_json::from_str(&body)?;
    assert_ne!(
        value["status"].as_str(),
        Some("healthy"),
        "summary must not report healthy while a provider is down: {body}"
    );

    // Recovery: a fresh observation restores health through the same adapter.
    {
        let mut nodes = agents.nodes.lock().await;
        nodes.insert(
            "provider-a".to_owned(),
            (snapshot(AgentAvailability::Available), Some(now_unix_ms())),
        );
    }
    let (_, body) = get(
        &app,
        "/o3k/v1/operator/diagnostics/providers",
        "operator-token",
    )
    .await?;
    let value: Value = serde_json::from_str(&body)?;
    assert_eq!(value["items"][0]["status"], "healthy", "{body}");
    Ok(())
}
