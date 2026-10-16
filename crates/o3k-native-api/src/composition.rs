//! Operator CloudProfile API. Desired composition is deliberately separate
//! from observed ManifestRegistry/Catalog projections.
use crate::{
    NativeApiState,
    auth::BearerAuth,
    error::{ErrorCode, ProblemDetails},
};
use axum::{
    Json,
    extract::{Path, State, rejection::JsonRejection},
    response::{IntoResponse, Response},
};
use o3k_kernel::{
    ActionId, AuthContext, AuthorizationDecision, AuthorizationRequest, CloudProfile,
    ResourceTarget, ResourceType,
};
use serde::{Deserialize, Serialize};

pub const ACTION_READ: &str = "ReadCloudProfile";
pub const ACTION_MANAGE: &str = "ManageCloudProfile";

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum CompositionWriteError {
    BadRequest,
    Conflict,
    NotAvailable,
    Internal,
}

#[derive(Debug, Clone, Serialize)]
pub struct CloudProfileView {
    pub profile: CloudProfile,
    pub consumable: Option<bool>,
    pub drift: Option<Vec<o3k_kernel::CompositionDrift>>,
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ProfileWrite {
    pub profile: CloudProfile,
    pub expected_generation: Option<u64>,
}

#[async_trait::async_trait]
pub trait CompositionReader: Send + Sync {
    async fn get(&self, profile_id: &str) -> Result<Option<CloudProfile>, String>;
    async fn put(
        &self,
        profile: CloudProfile,
        expected_generation: Option<u64>,
        auth: &AuthContext,
    ) -> Result<CloudProfile, CompositionWriteError>;
    async fn reconcile(
        &self,
        profile_id: &str,
        auth: &AuthContext,
    ) -> Result<CloudProfileView, String>;
}

fn authorize(state: &NativeApiState, auth: &AuthContext, action: &str) -> bool {
    state.authorizer.as_ref().is_some_and(|authorizer| {
        matches!(
            authorizer.authorize(&AuthorizationRequest {
                auth_context: auth,
                action: ActionId::new_unchecked("composition", action),
                resource_target: ResourceTarget::collection(
                    ResourceType::new_unchecked("composition", "cloud_profile"),
                    None
                )
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

pub async fn show(
    auth: BearerAuth,
    State(state): State<NativeApiState>,
    Path(id): Path<String>,
) -> Response {
    let request = uuid::Uuid::now_v7().to_string();
    if !authorize(&state, &auth.0, ACTION_READ) {
        return error(ErrorCode::Forbidden, &request);
    }
    let Some(reader) = state.composition_reader.as_ref() else {
        return error(ErrorCode::NotAvailable, &request);
    };
    match reader.get(&id).await {
        Ok(Some(profile)) => Json(CloudProfileView {
            profile,
            consumable: None,
            drift: None,
        })
        .into_response(),
        Ok(None) => error(ErrorCode::ResourceNotFound, &request),
        Err(_) => error(ErrorCode::InternalError, &request),
    }
}

pub async fn put(
    auth: BearerAuth,
    State(state): State<NativeApiState>,
    Path(id): Path<String>,
    body: Result<Json<ProfileWrite>, JsonRejection>,
) -> Response {
    let correlation = auth.0.request_id().to_owned();
    if !authorize(&state, &auth.0, ACTION_MANAGE) {
        return error(ErrorCode::Forbidden, &correlation);
    }
    let Json(request) = match body {
        Ok(request) => request,
        // Keep axum's status (400 syntax, 415 content type, 422 data) so this
        // route matches the rest of the native surface, but never echo the
        // rejection text: serde messages can quote request input.
        Err(rejection) => {
            return (
                rejection.status(),
                [(
                    axum::http::header::CONTENT_TYPE,
                    "text/plain; charset=utf-8",
                )],
                "invalid request body",
            )
                .into_response();
        }
    };
    if request.profile.profile_id != id {
        return error(ErrorCode::BadRequest, &correlation);
    }
    let Some(reader) = state.composition_reader.as_ref() else {
        return error(ErrorCode::NotAvailable, &correlation);
    };
    match reader
        .put(request.profile, request.expected_generation, &auth.0)
        .await
    {
        Ok(profile) => (
            axum::http::StatusCode::OK,
            Json(CloudProfileView {
                profile,
                consumable: None,
                drift: None,
            }),
        )
            .into_response(),
        Err(CompositionWriteError::BadRequest) => error(ErrorCode::BadRequest, &correlation),
        Err(CompositionWriteError::Conflict) => error(ErrorCode::Conflict, &correlation),
        Err(CompositionWriteError::NotAvailable) => error(ErrorCode::NotAvailable, &correlation),
        Err(CompositionWriteError::Internal) => error(ErrorCode::InternalError, &correlation),
    }
}

pub async fn reconcile(
    auth: BearerAuth,
    State(state): State<NativeApiState>,
    Path(id): Path<String>,
) -> Response {
    let correlation = uuid::Uuid::now_v7().to_string();
    if !authorize(&state, &auth.0, ACTION_MANAGE) {
        return error(ErrorCode::Forbidden, &correlation);
    }
    let Some(reader) = state.composition_reader.as_ref() else {
        return error(ErrorCode::NotAvailable, &correlation);
    };
    match reader.reconcile(&id, &auth.0).await {
        Ok(view) => Json(view).into_response(),
        Err(_) => error(ErrorCode::InternalError, &correlation),
    }
}
