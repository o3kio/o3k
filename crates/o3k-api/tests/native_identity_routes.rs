use axum::body::{Body, to_bytes};
use http::{Request, StatusCode};
use o3k_kernel::{
    AuthContext, OwnershipScope, Principal, PrincipalId, ScopeId, ScopeKind, UserPrincipal,
};
use serde_json::Value;
use std::sync::Arc;
use tower::ServiceExt;

#[derive(Clone)]
struct TestIssuer {
    operator: AuthContext,
    tenant: AuthContext,
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
        "request-test",
        None,
    )
}

fn native_router_with_iam() -> Result<axum::Router, String> {
    let native = o3k_native_api::NativeApiState::new(
        None,
        o3k_native_api::pagination::CursorConfig::default(),
        Some(Arc::new(TestIssuer {
            operator: auth_context("system", ScopeKind::System, &["operator"]),
            tenant: auth_context("project-a", ScopeKind::Project, &["member"]),
        })),
        None,
        None,
        None,
    )?
    .with_authorizer(Arc::new(o3k_kernel::StaticAuthorizer::standard()));
    Ok(o3k_api::router_with_state(
        o3k_api::AppState::new().with_native_api(native),
    ))
}

#[tokio::test]
async fn federated_scope_route_reaches_native_identity_handler()
-> Result<(), Box<dyn std::error::Error>> {
    let request = Request::builder()
        .method("POST")
        .uri("/o3k/v1/identity/scopes")
        .header("content-type", "application/json")
        .body(Body::from(r#"{"federated":{"access_token":"opaque"}}"#))?;
    let state = o3k_api::AppState::new().with_native_api(Default::default());
    let response = o3k_api::router_with_state(state).oneshot(request).await?;

    assert_eq!(response.status(), StatusCode::SERVICE_UNAVAILABLE);
    let body: Value = serde_json::from_slice(&to_bytes(response.into_body(), 4096).await?)?;
    assert_eq!(body["title"], "Not Available");
    assert_eq!(body["detail"], "IAM is not configured");
    Ok(())
}

#[tokio::test]
async fn production_router_mounts_operator_profile_with_canonical_auth()
-> Result<(), Box<dyn std::error::Error>> {
    let response = native_router_with_iam()?
        .clone()
        .oneshot(
            Request::builder()
                .uri("/o3k/v1/operator/profile")
                .header("authorization", "Bearer operator-token")
                .body(Body::empty())?,
        )
        .await?;
    assert_eq!(response.status(), StatusCode::OK);
    let body: Value = serde_json::from_slice(&to_bytes(response.into_body(), 4096).await?)?;
    assert_eq!(body["profile"], "operator-console");
    assert_eq!(body["scope"], "system");

    let response = native_router_with_iam()?
        .clone()
        .oneshot(
            Request::builder()
                .uri("/o3k/v1/operator/profile")
                .header("authorization", "Bearer tenant-token")
                .body(Body::empty())?,
        )
        .await?;
    assert_eq!(response.status(), StatusCode::FORBIDDEN);

    let response = native_router_with_iam()?
        .clone()
        .oneshot(
            Request::builder()
                .uri("/o3k/v1/operator/profile")
                .header("authorization", "Bearer invalid-token")
                .body(Body::empty())?,
        )
        .await?;
    assert_eq!(response.status(), StatusCode::UNAUTHORIZED);

    let response = native_router_with_iam()?
        .oneshot(
            Request::builder()
                .uri("/o3k/v1/operator/profile")
                .body(Body::empty())?,
        )
        .await?;
    assert_eq!(response.status(), StatusCode::UNAUTHORIZED);
    Ok(())
}

#[tokio::test]
async fn production_router_mounts_building_block_collection_route()
-> Result<(), Box<dyn std::error::Error>> {
    // A missing route would return 404 before authentication.  Reaching the
    // native handler proves the production composition includes the canonical
    // BuildingBlock collection endpoint used by the real-host journey.
    let response = native_router_with_iam()?
        .oneshot(
            Request::builder()
                .uri("/o3k/v1/operator/building-blocks")
                .body(Body::empty())?,
        )
        .await?;
    assert_eq!(response.status(), StatusCode::UNAUTHORIZED);
    Ok(())
}
