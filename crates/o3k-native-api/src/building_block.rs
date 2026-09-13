//! Native BuildingBlock lifecycle and operator discovery API (P15.5).
//!
//! BuildingBlocks own durable lifecycle and references only. Capacity and
//! capabilities are projected by the application from Placement and the
//! authenticated execution registry.

use axum::{
    Json,
    extract::{Path, State},
    response::{IntoResponse, Response},
};
use o3k_kernel::{
    ActionId, AuthContext, AuthorizationDecision, AuthorizationRequest, BuildingBlock,
    BuildingBlockState, PrincipalKind, ResourceTarget, ResourceType,
};
use serde::{Deserialize, Serialize};

use crate::{
    NativeApiState,
    auth::BearerAuth,
    error::{ErrorCode, ProblemDetails},
};

pub const ACTION_READ: &str = "ReadBuildingBlock";
pub const ACTION_MANAGE: &str = "ManageBuildingBlock";
pub const ACTION_ENROLL: &str = "EnrollBuildingBlock";

#[derive(Debug, Clone, Serialize)]
pub struct BuildingBlockView {
    pub block: BuildingBlock,
    pub capabilities: Vec<String>,
    pub capacity: Vec<CapacityDimension>,
    pub agent_available: Option<bool>,
}

#[derive(Debug, Clone, Serialize)]
pub struct CapacityDimension {
    pub resource: String,
    pub total: u64,
    pub available: u64,
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct EnrollRequest {
    pub block: BuildingBlock,
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ActionRequest {
    pub expected_generation: u64,
    #[serde(default)]
    pub blockers: Vec<o3k_kernel::DrainBlocker>,
}

#[async_trait::async_trait]
pub trait BuildingBlockReader: Send + Sync {
    async fn get(&self, id: &str) -> Result<Option<BuildingBlockView>, String>;
    async fn list(&self) -> Result<Vec<BuildingBlockView>, String>;
    async fn enroll(
        &self,
        block: BuildingBlock,
        auth: &AuthContext,
    ) -> Result<BuildingBlockView, String>;
    async fn transition(
        &self,
        id: &str,
        target: BuildingBlockState,
        expected_generation: u64,
        blockers: Vec<o3k_kernel::DrainBlocker>,
        auth: &AuthContext,
    ) -> Result<BuildingBlockView, String>;
}

fn authorize(state: &NativeApiState, auth: &AuthContext, action: &str) -> bool {
    state.authorizer.as_ref().is_some_and(|authorizer| {
        matches!(
            authorizer.authorize(&AuthorizationRequest {
                auth_context: auth,
                action: ActionId::new_unchecked("building_block", action),
                resource_target: ResourceTarget::collection(
                    ResourceType::new_unchecked("building_block", "building_block"),
                    None
                ),
            }),
            AuthorizationDecision::Allow
        )
    })
}

fn error(code: ErrorCode, request: &str) -> Response {
    ProblemDetails::new(code)
        .with_request_id(request)
        .into_response()
}

pub async fn list(auth: BearerAuth, State(state): State<NativeApiState>) -> Response {
    let request = uuid::Uuid::now_v7().to_string();
    if !authorize(&state, &auth.0, ACTION_READ) {
        return error(ErrorCode::Forbidden, &request);
    }
    let Some(reader) = state.building_block_reader.as_ref() else {
        return error(ErrorCode::NotAvailable, &request);
    };
    match reader.list().await {
        Ok(view) => Json(view).into_response(),
        Err(_) => error(ErrorCode::InternalError, &request),
    }
}

pub async fn show(
    auth: BearerAuth,
    State(state): State<NativeApiState>,
    Path(id): Path<String>,
) -> Response {
    let request = uuid::Uuid::now_v7().to_string();
    if !authorize(&state, &auth.0, ACTION_READ) {
        return error(ErrorCode::Forbidden, &request);
    }
    let Some(reader) = state.building_block_reader.as_ref() else {
        return error(ErrorCode::NotAvailable, &request);
    };
    match reader.get(&id).await {
        Ok(Some(view)) => Json(view).into_response(),
        Ok(None) => error(ErrorCode::ResourceNotFound, &request),
        Err(_) => error(ErrorCode::InternalError, &request),
    }
}

pub async fn enroll(
    auth: BearerAuth,
    State(state): State<NativeApiState>,
    Json(request_body): Json<EnrollRequest>,
) -> Response {
    let request = uuid::Uuid::now_v7().to_string();
    if auth.0.principal().kind() != PrincipalKind::Service
        || !authorize(&state, &auth.0, ACTION_ENROLL)
    {
        return error(ErrorCode::Forbidden, &request);
    }
    let Some(reader) = state.building_block_reader.as_ref() else {
        return error(ErrorCode::NotAvailable, &request);
    };
    match reader.enroll(request_body.block, &auth.0).await {
        Ok(view) => (axum::http::StatusCode::CREATED, Json(view)).into_response(),
        Err(_) => error(ErrorCode::Conflict, &request),
    }
}

pub async fn action(
    auth: BearerAuth,
    State(state): State<NativeApiState>,
    Path((id, action_name)): Path<(String, String)>,
    Json(body): Json<ActionRequest>,
) -> Response {
    let request = uuid::Uuid::now_v7().to_string();
    if !authorize(&state, &auth.0, ACTION_MANAGE) {
        return error(ErrorCode::Forbidden, &request);
    }
    let target = match action_name.as_str() {
        "ready" => BuildingBlockState::Ready,
        "unavailable" => BuildingBlockState::Unavailable,
        "drain" | "draining" => BuildingBlockState::Draining,
        "remove" | "removed" => BuildingBlockState::Removed,
        "fail" | "failed" => BuildingBlockState::Failed,
        _ => return error(ErrorCode::BadRequest, &request),
    };
    let Some(reader) = state.building_block_reader.as_ref() else {
        return error(ErrorCode::NotAvailable, &request);
    };
    match reader
        .transition(
            &id,
            target,
            body.expected_generation,
            body.blockers,
            &auth.0,
        )
        .await
    {
        Ok(view) => Json(view).into_response(),
        Err(_) => error(ErrorCode::Conflict, &request),
    }
}
