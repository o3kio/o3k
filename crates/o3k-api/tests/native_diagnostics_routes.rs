//! End-to-end routing and authorization for the native operator diagnostics
//! endpoints (#903), mounted by the production `o3k_api::router_with_state`
//! under `/o3k/v1/operator/diagnostics`.
//!
//! Covers the Phase 27 authorization negatives (project-scoped callers are
//! denied even when they hold an `operator` role name) and the positive
//! system-operator path, plus the secret-safety guarantee that no 200 body
//! leaks node identity, agent epoch, or credential material.

use axum::body::{Body, to_bytes};
use http::{Method, Request, StatusCode};
use o3k_kernel::{
    AuthContext, OwnershipScope, Principal, PrincipalId, ScopeId, ScopeKind, UserPrincipal,
};
use serde_json::Value;
use std::sync::{
    Arc,
    atomic::{AtomicUsize, Ordering},
};
use tower::ServiceExt;

use o3k_native_api::diagnostics::{
    CapacityDiagnostics, DiagnosticReason, DiagnosticStatus, DiagnosticsError, DiagnosticsPage,
    DiagnosticsReader, DiagnosticsSummary, LocationDiagnostics, ProviderDiagnostics,
    ServiceDiagnostics, StatusCounts,
};

type TestResult = Result<(), Box<dyn std::error::Error>>;

#[derive(Clone)]
struct TestIssuer {
    operator: AuthContext,
    tenant: AuthContext,
    operator_role: AuthContext,
}

#[async_trait::async_trait]
impl o3k_native_api::auth::TokenIssuer for TestIssuer {
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
        ISSUER_REQUEST_ID,
        None,
    )
}

/// A tiny, benign diagnostics authority. None of the returned values carry
/// node identity, agent epoch, credentials, or connection strings.
struct FakeDiagnosticsReader;

#[async_trait::async_trait]
impl DiagnosticsReader for FakeDiagnosticsReader {
    async fn summary(&self) -> Result<DiagnosticsSummary, DiagnosticsError> {
        Ok(DiagnosticsSummary {
            version: o3k_native_api::diagnostics::DIAGNOSTICS_VERSION.to_owned(),
            evaluated_at_unix_ms: 1_700_000_000_000,
            status: DiagnosticStatus::Healthy,
            counts: StatusCounts::default(),
            control_plane: None,
            locations: LocationDiagnostics {
                configured: true,
                regions: 1,
                availability_domains: 1,
            },
        })
    }

    async fn services(
        &self,
        _limit: usize,
        _after: Option<&str>,
    ) -> Result<DiagnosticsPage<ServiceDiagnostics>, DiagnosticsError> {
        Ok(DiagnosticsPage {
            items: vec![ServiceDiagnostics {
                service_id: "compute".to_owned(),
                namespace: "compute".to_owned(),
                service_version: "0.4.0".to_owned(),
                ownership: "o3k-implemented".to_owned(),
                lifecycle_state: "ready".to_owned(),
                status: DiagnosticStatus::Healthy,
                observed_at_unix_ms: Some(1_700_000_000_000),
                reason: None,
                controller: None,
            }],
            has_more: false,
            next_cursor: None,
        })
    }

    async fn providers(
        &self,
        _limit: usize,
        _after: Option<&str>,
    ) -> Result<DiagnosticsPage<ProviderDiagnostics>, DiagnosticsError> {
        Ok(DiagnosticsPage {
            items: vec![ProviderDiagnostics {
                provider_id: "compute-1".to_owned(),
                state: "Enabled".to_owned(),
                availability: "available".to_owned(),
                status: DiagnosticStatus::Healthy,
                observed_at_unix_ms: Some(1_700_000_000_000),
                reason: None,
                capacity: vec![],
            }],
            has_more: false,
            next_cursor: None,
        })
    }

    async fn capacity(&self) -> Result<CapacityDiagnostics, DiagnosticsError> {
        Ok(CapacityDiagnostics {
            version: o3k_native_api::diagnostics::DIAGNOSTICS_VERSION.to_owned(),
            status: DiagnosticStatus::Degraded,
            observed_at_unix_ms: Some(1_700_000_000_000),
            reason: Some(DiagnosticReason::ReportedUnhealthy),
            providers_enabled: 1,
            providers_draining: 0,
            providers_unavailable: 0,
            providers_deleted: 0,
            dimensions: vec![],
        })
    }
}

/// Request ID baked into the TestIssuer's AuthContext.
const ISSUER_REQUEST_ID: &str = "request-test";

/// Correlation ID sent as `x-request-id` on every test request; handlers must
/// echo it. It must differ from `ISSUER_REQUEST_ID` so correlation assertions
/// prove the header value is propagated rather than the issuer default.
const REQUEST_ID: &str = "pp6-query-correlation";

fn router() -> Result<axum::Router, Box<dyn std::error::Error>> {
    router_with_diagnostics_reader(Some(Arc::new(FakeDiagnosticsReader)))
}

fn router_with_diagnostics_reader(
    diagnostics_reader: Option<Arc<dyn DiagnosticsReader>>,
) -> Result<axum::Router, Box<dyn std::error::Error>> {
    let native = o3k_native_api::NativeApiState::new(
        None,
        o3k_native_api::pagination::CursorConfig::default(),
        Some(Arc::new(TestIssuer {
            operator: auth_context("system", ScopeKind::System, &["operator"]),
            tenant: auth_context("project-a", ScopeKind::Project, &["member"]),
            operator_role: auth_context("project-b", ScopeKind::Project, &["operator"]),
        })),
        None,
        None,
        None,
    )?;
    let native = match diagnostics_reader {
        Some(reader) => native.with_diagnostics_reader(reader),
        None => native,
    }
    .with_authorizer(Arc::new(o3k_kernel::StaticAuthorizer::standard()));
    Ok(o3k_api::router_with_state(
        o3k_api::AppState::new().with_native_api(native),
    ))
}

async fn get(uri: &str, token: &str) -> Result<(StatusCode, String), Box<dyn std::error::Error>> {
    get_from_router(router()?, uri, token).await
}

async fn get_from_router(
    router: axum::Router,
    uri: &str,
    token: &str,
) -> Result<(StatusCode, String), Box<dyn std::error::Error>> {
    request_from_router(router, Method::GET, uri, token).await
}

async fn request_from_router(
    router: axum::Router,
    method: Method,
    uri: &str,
    token: &str,
) -> Result<(StatusCode, String), Box<dyn std::error::Error>> {
    let response = router
        .oneshot(
            Request::builder()
                .method(method)
                .uri(uri)
                .header("authorization", format!("Bearer {token}"))
                .header("x-request-id", REQUEST_ID)
                .body(Body::empty())?,
        )
        .await?;
    let status = response.status();
    let bytes = to_bytes(response.into_body(), 8192).await?;
    Ok((status, String::from_utf8_lossy(&bytes).into_owned()))
}

const ENDPOINTS: [&str; 4] = [
    "/o3k/v1/operator/diagnostics",
    "/o3k/v1/operator/diagnostics/services",
    "/o3k/v1/operator/diagnostics/providers",
    "/o3k/v1/operator/diagnostics/capacity",
];

#[tokio::test]
async fn native_diagnostics_routes_deny_project_scoped_callers_even_with_operator_role()
-> TestResult {
    for uri in ENDPOINTS {
        // A plain tenant with no operator role is denied.
        let (status, _) = get(uri, "tenant-token").await?;
        assert_eq!(status, StatusCode::FORBIDDEN, "{uri}");

        // A project-scoped caller holding an `operator` role NAME is still
        // denied: diagnostics authority is scope-based, not role-string-based.
        let (status, _) = get(uri, "operator-role-token").await?;
        assert_eq!(status, StatusCode::FORBIDDEN, "{uri}");
    }
    Ok(())
}

#[tokio::test]
async fn native_diagnostics_routes_system_operator_reaches_all_endpoints_without_secret_leak()
-> TestResult {
    let secrets = ["node_id", "agent_epoch", "password", "token", "secret"];

    // The summary endpoint returns the canonical version/status envelope.
    let (status, body) = get("/o3k/v1/operator/diagnostics", "operator-token").await?;
    assert_eq!(status, StatusCode::OK);
    let value: Value = serde_json::from_str(&body)?;
    assert_eq!(value["version"], "v1");
    assert!(value.get("status").is_some());

    for uri in ENDPOINTS {
        let (status, body) = get(uri, "operator-token").await?;
        assert_eq!(status, StatusCode::OK, "{uri}");
        let value: Value = serde_json::from_str(&body)?;
        // The summary and capacity routes carry the version/status envelope;
        // the services and providers routes return a bounded page instead.
        if uri.ends_with("/services") || uri.ends_with("/providers") {
            assert!(value.get("items").is_some(), "{uri}");
            assert!(value.get("has_more").is_some(), "{uri}");
        } else {
            assert_eq!(value["version"], "v1", "{uri}");
            assert!(value.get("status").is_some(), "{uri}");
        }
        for secret in secrets {
            assert!(!body.contains(secret), "{secret:?} leaked into {uri}");
        }
    }
    Ok(())
}

#[derive(Default)]
struct DiagnosticsReadCounts([AtomicUsize; 4]);

struct CountingDiagnosticsReader {
    reads: Arc<DiagnosticsReadCounts>,
}

#[async_trait::async_trait]
impl DiagnosticsReader for CountingDiagnosticsReader {
    async fn summary(&self) -> Result<DiagnosticsSummary, DiagnosticsError> {
        self.reads.0[0].fetch_add(1, Ordering::SeqCst);
        FakeDiagnosticsReader.summary().await
    }

    async fn services(
        &self,
        limit: usize,
        after: Option<&str>,
    ) -> Result<DiagnosticsPage<ServiceDiagnostics>, DiagnosticsError> {
        self.reads.0[1].fetch_add(1, Ordering::SeqCst);
        FakeDiagnosticsReader.services(limit, after).await
    }

    async fn providers(
        &self,
        limit: usize,
        after: Option<&str>,
    ) -> Result<DiagnosticsPage<ProviderDiagnostics>, DiagnosticsError> {
        self.reads.0[2].fetch_add(1, Ordering::SeqCst);
        FakeDiagnosticsReader.providers(limit, after).await
    }

    async fn capacity(&self) -> Result<CapacityDiagnostics, DiagnosticsError> {
        self.reads.0[3].fetch_add(1, Ordering::SeqCst);
        FakeDiagnosticsReader.capacity().await
    }
}

#[tokio::test]
async fn native_diagnostics_get_routes_call_only_their_read_projection() -> TestResult {
    // SPEC-0045 exposes diagnostics as a read-only projection. Exercise the
    // production router and ensure each GET reaches only its matching reader
    // operation, with no cross-route or repeated projection calls.
    let reads = Arc::new(DiagnosticsReadCounts::default());
    let reader = Arc::new(CountingDiagnosticsReader {
        reads: reads.clone(),
    });
    let router = router_with_diagnostics_reader(Some(reader))?;

    for (index, uri) in ENDPOINTS.into_iter().enumerate() {
        let (status, _) = get_from_router(router.clone(), uri, "operator-token").await?;
        assert_eq!(status, StatusCode::OK, "{uri}");
        for (read_index, count) in reads.0.iter().enumerate() {
            let expected = usize::from(read_index == index);
            assert_eq!(count.load(Ordering::SeqCst), expected, "{uri}");
            count.store(0, Ordering::SeqCst);
        }
    }
    Ok(())
}

#[tokio::test]
async fn unavailable_diagnostics_authority_returns_request_correlation_without_details()
-> TestResult {
    for uri in ENDPOINTS {
        let (status, body) =
            get_from_router(router_with_diagnostics_reader(None)?, uri, "operator-token").await?;
        assert_eq!(status, StatusCode::SERVICE_UNAVAILABLE, "{uri}");
        let value: Value = serde_json::from_str(&body)?;
        assert_eq!(value["code"], "NOT_AVAILABLE", "{uri}");
        assert_eq!(value["request_id"], REQUEST_ID, "{uri}");
        assert!(value.get("detail").is_none(), "{uri}");
        assert!(!body.contains("secret"), "secret detail leaked into {uri}");
        assert!(
            !body.contains("password"),
            "credential detail leaked into {uri}"
        );
    }
    Ok(())
}

#[tokio::test]
async fn native_diagnostics_query_errors_are_correlated_and_redacted() -> TestResult {
    assert_ne!(REQUEST_ID, ISSUER_REQUEST_ID);
    // `eA` is the unpadded URL-safe encoding of one ASCII `x` byte.
    let oversized_cursor = "eA".repeat(513);
    for endpoint in [
        "/o3k/v1/operator/diagnostics/services",
        "/o3k/v1/operator/diagnostics/providers",
    ] {
        for (query, code) in [
            ("?limit=201", "BAD_REQUEST"),
            ("?cursor=", "INVALID_CURSOR"),
            ("?cursor=not-base64", "INVALID_CURSOR"),
            (&format!("?cursor={oversized_cursor}"), "INVALID_CURSOR"),
            ("?limit=1&limit=2", "BAD_REQUEST"),
            ("?cursor=YQ&cursor=Yg", "INVALID_CURSOR"),
            ("?%6cimit=201", "BAD_REQUEST"),
        ] {
            let (status, body) = get(&format!("{endpoint}{query}"), "operator-token").await?;
            assert_eq!(status, StatusCode::BAD_REQUEST, "{endpoint}{query}");
            let value: Value = serde_json::from_str(&body)?;
            assert_eq!(value["code"], code);
            assert_eq!(value["request_id"], REQUEST_ID);
            assert!(value.get("detail").is_none());
            assert!(!body.contains("not-base64"));
        }
    }
    Ok(())
}

#[tokio::test]
async fn native_diagnostics_malformed_limit_is_authorized_before_validation() -> TestResult {
    assert_ne!(REQUEST_ID, ISSUER_REQUEST_ID);
    for (endpoint, code) in [
        (
            "/o3k/v1/operator/diagnostics/services?limit=abc",
            "BAD_REQUEST",
        ),
        (
            "/o3k/v1/operator/diagnostics/providers?limit=abc",
            "BAD_REQUEST",
        ),
        (
            "/o3k/v1/operator/diagnostics/services?limit=1&limit=2",
            "BAD_REQUEST",
        ),
        (
            "/o3k/v1/operator/diagnostics/providers?limit=1&limit=2",
            "BAD_REQUEST",
        ),
        (
            "/o3k/v1/operator/diagnostics/services?cursor=YQ&cursor=Yg",
            "INVALID_CURSOR",
        ),
        (
            "/o3k/v1/operator/diagnostics/providers?cursor=YQ&cursor=Yg",
            "INVALID_CURSOR",
        ),
    ] {
        let (status, body) = get(endpoint, "tenant-token").await?;
        assert_eq!(status, StatusCode::FORBIDDEN, "{endpoint}");
        let value: Value = serde_json::from_str(&body)?;
        assert_eq!(value["code"], "FORBIDDEN");

        let (status, body) = get(endpoint, "operator-token").await?;
        assert_eq!(status, StatusCode::BAD_REQUEST, "{endpoint}");
        let value: Value = serde_json::from_str(&body)?;
        assert_eq!(value["code"], code);
        assert_eq!(value["request_id"], REQUEST_ID);
        assert!(value.get("detail").is_none());
        assert!(!body.contains("abc"));
    }
    for endpoint in [
        "/o3k/v1/operator/diagnostics/services?%63ursor=cHJvdmlkZXItNDI",
        "/o3k/v1/operator/diagnostics/providers?%63ursor=cHJvdmlkZXItNDI",
    ] {
        let (status, body) = get(endpoint, "operator-token").await?;
        assert_eq!(status, StatusCode::OK, "{endpoint}");
        assert!(body.contains("items"));
    }
    Ok(())
}

#[tokio::test]
async fn native_diagnostics_routes_are_read_only_for_mutating_methods() -> TestResult {
    // SPEC-0045 exposes a read-only projection.  Exercise the production
    // router with every common mutation verb so a future route change cannot
    // accidentally turn diagnostics into a write surface.
    for uri in ENDPOINTS {
        for method in [Method::POST, Method::PUT, Method::PATCH, Method::DELETE] {
            let (status, body) =
                request_from_router(router()?, method.clone(), uri, "operator-token").await?;
            assert_eq!(status, StatusCode::METHOD_NOT_ALLOWED, "{method} {uri}");
            assert!(
                body.is_empty(),
                "mutation response exposed a body: {method} {uri}"
            );
        }
    }
    Ok(())
}
