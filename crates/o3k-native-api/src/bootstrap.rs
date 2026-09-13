//! Production-oriented Cloud Kernel init/join protocol.

use async_trait::async_trait;
use axum::{
    Json,
    extract::{Request, State},
    response::{IntoResponse, Response},
};
use serde::{Deserialize, Serialize};

use crate::{
    NativeApiState,
    error::{ErrorCode, ProblemDetails},
};

#[derive(Debug, Clone, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct InitRequest {
    #[serde(default)]
    pub profile_id: Option<String>,
    #[serde(default)]
    pub request_id: Option<String>,
    /// When known, bind the one-time grant to the prepared host identity.
    /// Omitting it is an explicit operator-mediated wildcard enrollment flow.
    #[serde(default)]
    pub agent_id: Option<String>,
}

#[derive(Debug, Clone, Serialize)]
pub struct InitResponse {
    pub phase: String,
    pub cloud_identity_id: String,
    pub cloud_profile_id: String,
    pub enrollment_token: Option<String>,
    pub enrollment_expires_at_unix_ms: Option<u64>,
    pub ready: bool,
    pub config: ClientConfig,
}

#[derive(Debug, Clone, Serialize)]
pub struct ClientConfig {
    pub api_url: String,
    pub discovery_path: String,
    pub profile_id: String,
}

#[derive(Debug, Clone, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct JoinRequest {
    pub enrollment_token: String,
    pub agent_id: String,
    pub agent_epoch: String,
    pub certificate: String,
    #[serde(default)]
    pub region: Option<String>,
    #[serde(default)]
    pub availability_domain: Option<String>,
    #[serde(default)]
    pub failure_domain_id: Option<String>,
    #[serde(default)]
    pub capabilities: serde_json::Value,
    #[serde(default)]
    pub inventories: std::collections::BTreeMap<String, u64>,
}

#[derive(Debug, Clone, Serialize)]
pub struct JoinResponse {
    pub phase: String,
    pub agent_id: String,
    pub execution_identity: String,
    pub certificate_fingerprint: String,
    pub resource_provider_id: String,
    pub building_block_id: String,
    pub ready: bool,
    pub config: ClientConfig,
}

#[async_trait]
pub trait BootstrapWorkflow: Send + Sync {
    async fn init(
        &self,
        request: InitRequest,
        bootstrap_secret: Option<&str>,
    ) -> Result<InitResponse, BootstrapFailure>;
    async fn join(&self, request: JoinRequest) -> Result<JoinResponse, BootstrapFailure>;
}

#[derive(Debug, Clone, Copy)]
pub enum BootstrapFailure {
    Unauthorized,
    Conflict,
    Invalid,
    Unavailable,
    Internal,
}

fn fail(error: BootstrapFailure) -> Response {
    let code = match error {
        BootstrapFailure::Unauthorized => ErrorCode::Unauthorized,
        BootstrapFailure::Conflict => ErrorCode::Conflict,
        BootstrapFailure::Invalid => ErrorCode::BadRequest,
        BootstrapFailure::Unavailable => ErrorCode::NotAvailable,
        BootstrapFailure::Internal => ErrorCode::InternalError,
    };
    ProblemDetails::new(code).into_response()
}

pub async fn init(State(state): State<NativeApiState>, request: Request) -> Response {
    let Some(workflow) = state.bootstrap_workflow.as_ref() else {
        return fail(BootstrapFailure::Unavailable);
    };
    let secret = request
        .headers()
        .get("x-o3k-bootstrap-secret")
        .and_then(|value| value.to_str().ok())
        .map(str::to_owned);
    let (parts, body) = request.into_parts();
    let bytes = match axum::body::to_bytes(body, 1024 * 1024).await {
        Ok(bytes) => bytes,
        Err(_) => return fail(BootstrapFailure::Invalid),
    };
    let payload: InitRequest = match serde_json::from_slice(&bytes) {
        Ok(payload) => payload,
        Err(_) => return fail(BootstrapFailure::Invalid),
    };
    // Keep request metadata out of the workflow payload; the secret is only
    // borrowed for verification and is never emitted in a response/log.
    let _ = parts;
    match workflow.init(payload, secret.as_deref()).await {
        Ok(response) => Json(response).into_response(),
        Err(error) => fail(error),
    }
}

pub async fn join(
    State(state): State<NativeApiState>,
    Json(request): Json<JoinRequest>,
) -> Response {
    let Some(workflow) = state.bootstrap_workflow.as_ref() else {
        return fail(BootstrapFailure::Unavailable);
    };
    match workflow.join(request).await {
        Ok(response) => Json(response).into_response(),
        Err(error) => fail(error),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use axum::body::Body;
    use axum::http::{Request, StatusCode};
    use std::sync::Arc;
    use tower::ServiceExt;

    struct TestWorkflow;

    #[async_trait]
    impl BootstrapWorkflow for TestWorkflow {
        async fn init(
            &self,
            _request: InitRequest,
            secret: Option<&str>,
        ) -> Result<InitResponse, BootstrapFailure> {
            if secret != Some("secret") {
                return Err(BootstrapFailure::Unauthorized);
            }
            Err(BootstrapFailure::Internal)
        }

        async fn join(&self, _request: JoinRequest) -> Result<JoinResponse, BootstrapFailure> {
            Err(BootstrapFailure::Unauthorized)
        }
    }

    fn state() -> Result<NativeApiState, String> {
        NativeApiState::new(
            None,
            crate::pagination::CursorConfig::default(),
            None,
            None,
            None,
            None,
        )
        .map(|state| state.with_bootstrap_workflow(Arc::new(TestWorkflow)))
    }

    #[tokio::test]
    async fn init_requires_bootstrap_secret() -> Result<(), Box<dyn std::error::Error>> {
        let response = crate::router(state()?)
            .oneshot(
                Request::post("/bootstrap/init")
                    .header("content-type", "application/json")
                    .body(Body::from("{}"))?,
            )
            .await?;
        assert_eq!(response.status(), StatusCode::UNAUTHORIZED);
        Ok(())
    }

    #[tokio::test]
    async fn init_does_not_expose_secret_or_accept_malformed_json()
    -> Result<(), Box<dyn std::error::Error>> {
        let response = crate::router(state()?)
            .oneshot(
                Request::post("/bootstrap/init")
                    .header("x-o3k-bootstrap-secret", "secret")
                    .header("content-type", "application/json")
                    .body(Body::from("not-json"))?,
            )
            .await?;
        assert_eq!(response.status(), StatusCode::BAD_REQUEST);
        Ok(())
    }
}
