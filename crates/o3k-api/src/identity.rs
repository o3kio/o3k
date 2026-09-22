//! Keystone-compatible identity protocol adapter: token issue, validate,
//! and check handlers.

use std::time::SystemTime;

use axum::{
    Json,
    extract::{Path, State, rejection::JsonRejection},
    http::{HeaderMap, HeaderValue, StatusCode, header},
    response::IntoResponse,
};
use o3k_identity::{AuthError, TokenRequest};
use serde::Serialize;

use crate::{AppState, error::keystone_error};

pub(crate) async fn issue_token(
    State(state): State<AppState>,
    request: Result<Json<TokenRequest>, JsonRejection>,
) -> impl IntoResponse {
    let Ok(Json(request)) = request else {
        return keystone_error(
            StatusCode::BAD_REQUEST,
            "Bad Request",
            "invalid authentication request",
        );
    };
    let Some(service) = state.identity else {
        return keystone_error(
            StatusCode::SERVICE_UNAVAILABLE,
            "Service Unavailable",
            "identity is not configured",
        );
    };
    match service.issue(&request, SystemTime::now()) {
        Ok((value, response)) => {
            let Ok(subject_token) = HeaderValue::from_str(&value) else {
                return keystone_error(
                    StatusCode::INTERNAL_SERVER_ERROR,
                    "Internal Server Error",
                    "token could not be encoded",
                );
            };
            (
                StatusCode::CREATED,
                [
                    (
                        header::HeaderName::from_static("x-subject-token"),
                        subject_token,
                    ),
                    (header::VARY, HeaderValue::from_static("X-Auth-Token")),
                ],
                Json(response),
            )
                .into_response()
        }
        Err(AuthError::InvalidRequest) => keystone_error(
            StatusCode::BAD_REQUEST,
            "Bad Request",
            "invalid authentication request",
        ),
        Err(AuthError::Unauthorized) => keystone_error(
            StatusCode::UNAUTHORIZED,
            "Unauthorized",
            "The request has not been authenticated.",
        ),
        Err(AuthError::InvalidToken | AuthError::ExpiredToken | AuthError::WeakSigningKey) => {
            keystone_error(
                StatusCode::UNAUTHORIZED,
                "Unauthorized",
                "The request has not been authenticated.",
            )
        }
        Err(AuthError::IdentityUnavailable) => keystone_error(
            StatusCode::SERVICE_UNAVAILABLE,
            "Service Unavailable",
            "identity is not configured",
        ),
    }
}

pub(crate) async fn validate_token(
    State(state): State<AppState>,
    headers: HeaderMap,
) -> impl IntoResponse {
    let Some(service) = state.identity else {
        return keystone_error(
            StatusCode::SERVICE_UNAVAILABLE,
            "Service Unavailable",
            "identity is not configured",
        );
    };

    let token = headers
        .get("x-subject-token")
        .or_else(|| headers.get("x-auth-token"))
        .and_then(|v| v.to_str().ok());

    let Some(token) = token else {
        return keystone_error(
            StatusCode::BAD_REQUEST,
            "Bad Request",
            "X-Subject-Token header is required",
        );
    };

    match service.verify_details(token, SystemTime::now()) {
        Ok(response) => {
            let Ok(subject_token) = HeaderValue::from_str(token) else {
                return keystone_error(
                    StatusCode::INTERNAL_SERVER_ERROR,
                    "Internal Server Error",
                    "token could not be encoded",
                );
            };
            (
                StatusCode::OK,
                [
                    (
                        header::HeaderName::from_static("x-subject-token"),
                        subject_token,
                    ),
                    (header::VARY, HeaderValue::from_static("X-Auth-Token")),
                ],
                Json(response),
            )
                .into_response()
        }
        Err(_) => keystone_error(StatusCode::NOT_FOUND, "Not Found", "Could not find token"),
    }
}

pub(crate) async fn check_token(
    State(state): State<AppState>,
    headers: HeaderMap,
) -> impl IntoResponse {
    let Some(service) = state.identity else {
        return StatusCode::SERVICE_UNAVAILABLE.into_response();
    };

    let token = headers
        .get("x-subject-token")
        .or_else(|| headers.get("x-auth-token"))
        .and_then(|v| v.to_str().ok());

    let Some(token) = token else {
        return StatusCode::BAD_REQUEST.into_response();
    };

    match service.verify(token, SystemTime::now()) {
        Ok(_) => {
            let Ok(subject_token) = HeaderValue::from_str(token) else {
                return StatusCode::INTERNAL_SERVER_ERROR.into_response();
            };
            (
                StatusCode::OK,
                [
                    (
                        header::HeaderName::from_static("x-subject-token"),
                        subject_token,
                    ),
                    (header::VARY, HeaderValue::from_static("X-Auth-Token")),
                ],
            )
                .into_response()
        }
        Err(_) => StatusCode::NOT_FOUND.into_response(),
    }
}

#[derive(Debug, Serialize)]
struct AuthorizedProject {
    id: String,
    name: String,
    domain_id: String,
    enabled: bool,
}

#[derive(Debug, Serialize)]
struct AuthorizedProjectsResponse {
    projects: Vec<AuthorizedProject>,
}

/// Extracts the presented token, validates it, and returns the identity
/// service together with the verified subject. Missing, malformed, expired,
/// and unknown tokens all map to the same generic 401, and the token is never
/// echoed.
// Axum handlers consume the concrete response directly; boxing this error would
// add conversions across every OpenStack adapter without changing behavior.
#[allow(clippy::result_large_err)]
fn authenticated_subject(
    state: &AppState,
    headers: &HeaderMap,
) -> Result<
    (
        std::sync::Arc<o3k_identity::TokenService>,
        o3k_identity::VerifiedToken,
    ),
    axum::response::Response,
> {
    let Some(service) = &state.identity else {
        return Err(keystone_error(
            StatusCode::SERVICE_UNAVAILABLE,
            "Service Unavailable",
            "identity is not configured",
        ));
    };
    let token = headers
        .get("x-auth-token")
        .or_else(|| headers.get("x-subject-token"))
        .and_then(|value| value.to_str().ok())
        .ok_or_else(unauthenticated)?;
    service
        .verify(token, SystemTime::now())
        .map(|verified| (service.clone(), verified))
        .map_err(|_| unauthenticated())
}

fn authorized_projects_response(
    service: &o3k_identity::TokenService,
    user_id: &str,
) -> axum::response::Response {
    let projects = service
        .authorized_projects(user_id)
        .into_iter()
        .map(|project| AuthorizedProject {
            id: project.id,
            name: project.name,
            domain_id: project.domain_id,
            enabled: project.enabled,
        })
        .collect();
    (
        StatusCode::OK,
        Json(AuthorizedProjectsResponse { projects }),
    )
        .into_response()
}

/// `GET /v3/auth/projects` — the projects the authenticated subject may scope
/// a token into. OpenStack clients (Horizon's `openstack_auth`) call this with
/// an unscoped token to discover the user's projects before re-scoping.
pub(crate) async fn list_auth_projects(
    State(state): State<AppState>,
    headers: HeaderMap,
) -> impl IntoResponse {
    let (service, verified) = match authenticated_subject(&state, &headers) {
        Ok(subject) => subject,
        Err(response) => return response,
    };
    authorized_projects_response(&service, &verified.user_id)
}

/// `GET /v3/users/{user_id}/projects` — the same capability as
/// `/v3/auth/projects`, under the route `keystoneclient` actually issues for
/// `projects.list(user=...)`. Only the caller's own subject is readable: any
/// other id is a bounded 403 that never distinguishes an unknown user from a
/// foreign one.
pub(crate) async fn list_user_projects(
    State(state): State<AppState>,
    Path(user_id): Path<String>,
    headers: HeaderMap,
) -> impl IntoResponse {
    let (service, verified) = match authenticated_subject(&state, &headers) {
        Ok(subject) => subject,
        Err(response) => return response,
    };
    if user_id != verified.user_id {
        return forbidden();
    }
    authorized_projects_response(&service, &verified.user_id)
}

fn unauthenticated() -> axum::response::Response {
    keystone_error(
        StatusCode::UNAUTHORIZED,
        "Unauthorized",
        "The request has not been authenticated.",
    )
}

fn forbidden() -> axum::response::Response {
    keystone_error(
        StatusCode::FORBIDDEN,
        "Forbidden",
        "You are not authorized to perform the requested action.",
    )
}
