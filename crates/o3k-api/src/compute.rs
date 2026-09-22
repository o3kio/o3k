//! Nova-compatible compute protocol adapter: flavor/keypair/server/action
//! handlers, wire models, microversion helpers, and error mapping.

use std::sync::Arc;

use axum::{
    Json,
    extract::{Path, Query, State, rejection::JsonRejection},
    http::{HeaderMap, StatusCode, Uri},
    response::IntoResponse,
};
use o3k_compute::{ComputeError, ComputeService, Flavor, Server};
use o3k_console::ConsoleError;
use o3k_domain::{ServerId, ServerState};
use o3k_network::NetworkService;
use o3k_provider::{ConfigDriveRequest, InstanceAction};
use serde::Serialize;

use crate::{
    AppState, CONSOLE_AGENT_DISPATCH_TIMEOUT,
    auth::require_auth_context,
    error::keystone_error,
    image::image_error,
    network::network_error,
    pagination::{CollectionLink, CollectionPage},
};

#[derive(Serialize)]
pub(crate) struct FlavorResponse {
    id: String,
    name: String,
    vcpus: u32,
    ram: u64,
    disk: u64,
}
#[derive(Serialize)]
pub(crate) struct FlavorListResponse {
    flavors: Vec<FlavorResponse>,
}
#[derive(Serialize)]
pub(crate) struct FlavorEnvelope {
    flavor: FlavorResponse,
}

pub(crate) fn flavor_response(flavor: Flavor) -> FlavorResponse {
    FlavorResponse {
        id: flavor.id.to_string(),
        name: flavor.name,
        vcpus: flavor.vcpus,
        ram: flavor.ram_mib,
        disk: flavor.disk_gib,
    }
}

#[derive(serde::Deserialize)]
pub(crate) struct CreateServerEnvelope {
    server: CreateServerRequest,
}
#[derive(serde::Deserialize)]
pub(crate) struct CreateServerRequest {
    name: String,
    #[serde(alias = "imageRef")]
    image: Option<IdReference>,
    #[serde(alias = "flavorRef")]
    flavor: Option<IdReference>,
    networks: Option<Vec<NetworkReference>>,
    config_drive: Option<bool>,
    user_data: Option<String>,
    vendor_data: Option<String>,
    ssh_public_key: Option<String>,
    key_name: Option<String>,
}

pub(crate) fn config_drive_ssh_public_key(
    explicit: Option<String>,
    keypair: Option<String>,
) -> Result<String, &'static str> {
    explicit
        .or(keypair)
        .filter(|value| !value.trim().is_empty())
        .ok_or("key_name or ssh_public_key is required when config_drive is enabled")
}

#[derive(serde::Deserialize)]
#[serde(untagged)]
pub(crate) enum IdReference {
    Object { id: String },
    String(String),
}

impl IdReference {
    fn into_id(self) -> String {
        match self {
            Self::Object { id } | Self::String(id) => id,
        }
    }
}
#[derive(serde::Deserialize)]
pub(crate) struct NetworkReference {
    uuid: Option<String>,
    port: Option<String>,
}
#[derive(Serialize)]
pub(crate) struct ServerEnvelope {
    server: ServerResponse,
}
#[derive(Serialize)]
pub(crate) struct ServerListResponse {
    servers: Vec<ServerResponse>,
    // Emitted only for a paginating client (`limit` supplied); a plain listing
    // keeps its existing byte-shape.
    #[serde(skip_serializing_if = "Option::is_none")]
    servers_links: Option<Vec<CollectionLink>>,
}

/// The `limit`/`marker` members of the shared `/servers` and `/servers/detail`
/// collection. Every other query parameter the pinned Nova client sends
/// (`sort_key`, `sort_dir`, `project_id`, `all_tenants`, `search_opts`,
/// `is_public`, `device_id`) is ignored by serde and must keep being accepted.
#[derive(serde::Deserialize)]
pub(crate) struct ServerListQuery {
    #[serde(default)]
    limit: Option<String>,
    #[serde(default)]
    marker: Option<String>,
}
#[derive(Serialize)]
pub(crate) struct ServerResponse {
    id: String,
    name: String,
    status: String,
    tenant_id: String,
    project_id: String,
    image: IdResponse,
    flavor: IdResponse,
    addresses: serde_json::Value,
    key_name: Option<String>,
    config_drive: bool,
    // Nova servers always carry a metadata object; public clients (for
    // example openstackclient 6.6 `_prep_server_detail`) pop it
    // unconditionally. O3K does not model server metadata yet, so the
    // representation is always the empty object.
    metadata: serde_json::Value,
    tags: Vec<String>,
    // Nova's extended server attribute reporting the selected compute host.
    // O3K projects the durable scheduler placement provider identity, never a
    // display name; null only when no placement decision was recorded.
    #[serde(rename = "OS-EXT-SRV-ATTR:host")]
    host: Option<String>,
}

#[derive(serde::Deserialize)]
pub(crate) struct UpdateServerEnvelope {
    server: UpdateServerRequest,
}

#[derive(serde::Deserialize)]
pub(crate) struct UpdateServerRequest {
    name: Option<String>,
}
#[derive(Serialize)]
pub(crate) struct IdResponse {
    id: String,
}

/// Projects the canonical server lifecycle state into the Nova status string
/// of the current response shape. Nova/OpenStack status strings live here,
/// in the API crate; the canonical domain model and the persisted values are
/// separate projections owned by `o3k-domain` and `o3k-store`.
pub(crate) fn nova_status(state: ServerState) -> &'static str {
    match state {
        // The canonical `Requested` state is an internal pre-execution
        // intent. Nova has no such status, and upstream clients must observe
        // an in-progress status while realization is in flight, so it is
        // exposed through Nova's build status.
        ServerState::Requested => "BUILD",
        ServerState::Building => "BUILD",
        ServerState::Active => "ACTIVE",
        ServerState::Stopping => "STOPPING",
        ServerState::Stopped => "SHUTOFF",
        ServerState::Starting => "STARTING",
        ServerState::Rebooting => "REBOOTING",
        ServerState::Deleting => "DELETING",
        ServerState::Deleted => "DELETED",
        ServerState::Error => "ERROR",
    }
}

pub(crate) async fn server_response(
    server: Server,
    network_service: Option<&NetworkService>,
) -> ServerResponse {
    let mut addresses = serde_json::Map::new();
    if let Some(network_service) = network_service {
        for port_id in &server.network_ids {
            let Ok(port_id) = port_id.parse::<uuid::Uuid>() else {
                continue;
            };
            let Ok(port) = network_service
                .get_port_for_project(&server.project_id, port_id)
                .await
            else {
                continue;
            };
            let network_name = network_service
                .get_network_for_project(&server.project_id, port.network_id)
                .await
                .map(|network| network.name)
                .unwrap_or_else(|_| port.network_id.to_string());
            // Nova's addresses object is keyed by the network name.  The
            // OpenStack provider uses that key to correlate the refreshed
            // address with the configured port and preserve its port ID.
            // Keep this projection independent of the port's origin: using
            // the network UUID for user-created ports makes an unchanged
            // instance appear to lose its network and forces replacement.
            let address_key = network_name;
            let address_list = addresses
                .entry(address_key)
                .or_insert_with(|| serde_json::Value::Array(Vec::new()));
            if let Some(address_list) = address_list.as_array_mut() {
                address_list.push(serde_json::json!({
                    "version": 4,
                    "addr": port.fixed_ip.to_string(),
                    "OS-EXT-IPS-MAC:mac_addr": port.mac_address,
                    "OS-EXT-IPS:type": "fixed"
                }));
            }
        }
    }
    ServerResponse {
        id: server.id.to_string(),
        name: server.name,
        status: nova_status(server.state).to_owned(),
        tenant_id: server.project_id.clone(),
        project_id: server.project_id,
        image: IdResponse {
            id: server.image_id,
        },
        flavor: IdResponse {
            id: server.flavor_id.to_string(),
        },
        addresses: serde_json::Value::Object(addresses),
        key_name: server.key_name,
        config_drive: server.config_drive,
        metadata: serde_json::Value::Object(serde_json::Map::new()),
        tags: Vec::new(),
        host: server.host,
    }
}

#[derive(serde::Deserialize)]
pub(crate) struct CreateKeypairEnvelope {
    keypair: CreateKeypairRequest,
}

#[derive(serde::Deserialize)]
pub(crate) struct CreateKeypairRequest {
    name: String,
    public_key: Option<String>,
    #[serde(rename = "type")]
    key_type: Option<String>,
}

#[derive(Serialize)]
pub(crate) struct KeypairEnvelope {
    keypair: KeypairResponse,
}

#[derive(Serialize)]
pub(crate) struct KeypairListResponse {
    keypairs: Vec<KeypairEnvelope>,
}

#[derive(Serialize)]
pub(crate) struct KeypairResponse {
    name: String,
    id: String,
    user_id: String,
    public_key: String,
    fingerprint: String,
    #[serde(rename = "type")]
    key_type: String,
    created_at: String,
}

pub(crate) fn keypair_response(keypair: o3k_compute::Keypair) -> KeypairResponse {
    KeypairResponse {
        name: keypair.name,
        id: keypair.id.to_string(),
        user_id: keypair.user_id,
        public_key: keypair.public_key,
        fingerprint: keypair.fingerprint,
        key_type: "ssh".to_owned(),
        created_at: keypair.created_at,
    }
}

pub(crate) fn compute_error(error: ComputeError) -> axum::response::Response {
    match error {
        ComputeError::Unauthorized => keystone_error(
            StatusCode::UNAUTHORIZED,
            "Unauthorized",
            "The request has not been authenticated.",
        ),
        ComputeError::NotFound => keystone_error(
            StatusCode::NOT_FOUND,
            "Not Found",
            "compute resource was not found",
        ),
        ComputeError::Conflict => keystone_error(
            StatusCode::CONFLICT,
            "Conflict",
            "compute operation conflicts with current state",
        ),
        ComputeError::Scheduler(_) => keystone_error(
            StatusCode::CONFLICT,
            "Conflict",
            "compute host could not satisfy placement requirements",
        ),
        ComputeError::InvalidRequest => keystone_error(
            StatusCode::BAD_REQUEST,
            "Bad Request",
            "invalid compute request",
        ),
        ComputeError::QuotaExceeded {
            ref key,
            limit,
            used,
            requested,
        } => {
            let message = format!(
                "Quota exceeded for {key}: limit {limit}, used {used}, requested {requested}"
            );
            keystone_error(StatusCode::FORBIDDEN, "Forbidden", message)
        }
        ComputeError::Store(o3k_store::StoreError::KeypairNotFound) => {
            keystone_error(StatusCode::NOT_FOUND, "Not Found", "keypair was not found")
        }
        ComputeError::Store(o3k_store::StoreError::KeypairAlreadyExists) => keystone_error(
            StatusCode::CONFLICT,
            "Conflict",
            "compute resource already exists or conflicts with current state",
        ),
        ComputeError::Store(o3k_store::StoreError::KeypairInUse) => keystone_error(
            StatusCode::CONFLICT,
            "Conflict",
            "keypair is still attached to a server",
        ),
        ComputeError::Store(o3k_store::StoreError::KeypairOwnershipConflict) => {
            // Concealed: foreign keypairs are already indistinguishable from
            // missing ones at the project-scoped lookup (lifecycle keypair
            // resolution), so this mapping must not disclose ownership either.
            keystone_error(StatusCode::NOT_FOUND, "Not Found", "keypair was not found")
        }
        ComputeError::Store(o3k_store::StoreError::InvalidKeypair(_)) => {
            keystone_error(StatusCode::BAD_REQUEST, "Bad Request", "invalid public key")
        }
        ComputeError::Store(_)
        | ComputeError::Reconcile(_)
        | ComputeError::Provider(_)
        | ComputeError::EndpointRelease(_)
        | ComputeError::Metering(_) => keystone_error(
            StatusCode::INTERNAL_SERVER_ERROR,
            "Internal Server Error",
            "compute service is unavailable",
        ),
        ComputeError::Unavailable => keystone_error(
            StatusCode::SERVICE_UNAVAILABLE,
            "Service Unavailable",
            "compute service is unavailable",
        ),
    }
}

pub(crate) fn cached_console_response(
    console: &o3k_console::ConsoleService,
    id: uuid::Uuid,
    offset: u64,
    length: usize,
) -> Option<axum::response::Response> {
    console.read_from(id, offset, length).ok().map(|chunk| {
        (
            StatusCode::OK,
            Json(serde_json::json!({
                "output": String::from_utf8_lossy(&chunk.bytes)
            })),
        )
            .into_response()
    })
}

pub(crate) fn should_query_live_console(offset: u64) -> bool {
    offset == 0
}

#[allow(clippy::result_large_err)]
pub(crate) fn project_auth_context(
    state: &AppState,
    headers: &axum::http::HeaderMap,
    project_id: &str,
) -> Result<o3k_kernel::AuthContext, axum::response::Response> {
    let auth = require_auth_context(state, headers)?;
    if auth.effective_scope().id().as_str() != project_id {
        return Err(keystone_error(
            StatusCode::NOT_FOUND,
            "Not Found",
            "compute resource was not found",
        ));
    }
    Ok(auth)
}

#[allow(clippy::result_large_err)]
pub(crate) fn compute_service(
    state: &AppState,
) -> Result<&Arc<ComputeService>, axum::response::Response> {
    state.compute.as_ref().ok_or_else(|| {
        keystone_error(
            StatusCode::SERVICE_UNAVAILABLE,
            "Service Unavailable",
            "compute service is not configured",
        )
    })
}

pub(crate) async fn list_flavors(
    State(state): State<AppState>,
    headers: axum::http::HeaderMap,
    Path(project_id): Path<String>,
) -> axum::response::Response {
    let auth = match project_auth_context(&state, &headers, &project_id) {
        Ok(value) => value,
        Err(response) => return response,
    };
    let service = match compute_service(&state) {
        Ok(value) => value,
        Err(response) => return response,
    };
    match service.flavors_for_auth(&auth).await {
        Ok(flavors) => Json(FlavorListResponse {
            flavors: flavors.into_iter().map(flavor_response).collect(),
        })
        .into_response(),
        Err(error) => compute_error(error),
    }
}

#[derive(serde::Deserialize)]
pub(crate) struct CreateFlavorEnvelope {
    flavor: CreateFlavorRequest,
}

#[derive(serde::Deserialize)]
pub(crate) struct CreateFlavorRequest {
    name: String,
    vcpus: u32,
    ram: u64,
    disk: u64,
}

pub(crate) async fn create_flavor(
    State(state): State<AppState>,
    headers: axum::http::HeaderMap,
    Path(project_id): Path<String>,
    request: Result<Json<CreateFlavorEnvelope>, JsonRejection>,
) -> axum::response::Response {
    let auth = match project_auth_context(&state, &headers, &project_id) {
        Ok(value) => value,
        Err(response) => return response,
    };
    let service = match compute_service(&state) {
        Ok(value) => value,
        Err(response) => return response,
    };
    let Ok(Json(body)) = request else {
        return keystone_error(
            StatusCode::BAD_REQUEST,
            "Bad Request",
            "invalid flavor request",
        );
    };
    match service
        .create_flavor_for_auth(
            &auth,
            body.flavor.name,
            body.flavor.vcpus,
            body.flavor.ram,
            body.flavor.disk,
        )
        .await
    {
        Ok(flavor) => (
            StatusCode::CREATED,
            Json(FlavorEnvelope {
                flavor: flavor_response(flavor),
            }),
        )
            .into_response(),
        Err(error) => compute_error(error),
    }
}

pub(crate) async fn show_flavor(
    State(state): State<AppState>,
    headers: axum::http::HeaderMap,
    Path((project_id, id)): Path<(String, uuid::Uuid)>,
) -> axum::response::Response {
    let auth = match project_auth_context(&state, &headers, &project_id) {
        Ok(value) => value,
        Err(response) => return response,
    };
    let service = match compute_service(&state) {
        Ok(value) => value,
        Err(response) => return response,
    };
    match service.flavor_for_auth(&auth, id).await {
        Ok(flavor) => Json(FlavorEnvelope {
            flavor: flavor_response(flavor),
        })
        .into_response(),
        Err(error) => compute_error(error),
    }
}

/// Returns the standard Nova extra-specs collection for a flavor. O3K's
/// bounded flavor model has no custom extra specifications, so the read-only
/// compatibility projection is an empty collection. The flavor lookup still
/// performs normal project authorization and existence checks.
pub(crate) async fn list_flavor_extra_specs(
    State(state): State<AppState>,
    headers: axum::http::HeaderMap,
    Path((project_id, id)): Path<(String, uuid::Uuid)>,
) -> axum::response::Response {
    let auth = match project_auth_context(&state, &headers, &project_id) {
        Ok(value) => value,
        Err(response) => return response,
    };
    let service = match compute_service(&state) {
        Ok(value) => value,
        Err(response) => return response,
    };
    match service.flavor_for_auth(&auth, id).await {
        Ok(_) => Json(serde_json::json!({"extra_specs": {}})).into_response(),
        Err(error) => compute_error(error),
    }
}

pub(crate) async fn delete_flavor(
    State(state): State<AppState>,
    headers: axum::http::HeaderMap,
    Path((project_id, id)): Path<(String, uuid::Uuid)>,
) -> axum::response::Response {
    let auth = match project_auth_context(&state, &headers, &project_id) {
        Ok(value) => value,
        Err(response) => return response,
    };
    let service = match compute_service(&state) {
        Ok(value) => value,
        Err(response) => return response,
    };
    match service.delete_flavor_for_auth(&auth, id).await {
        Ok(()) => StatusCode::NO_CONTENT.into_response(),
        Err(error) => compute_error(error),
    }
}

pub(crate) async fn list_keypairs(
    State(state): State<AppState>,
    headers: axum::http::HeaderMap,
    Path(project_id): Path<String>,
) -> axum::response::Response {
    let auth = match project_auth_context(&state, &headers, &project_id) {
        Ok(value) => value,
        Err(response) => return response,
    };
    let service = match compute_service(&state) {
        Ok(value) => value,
        Err(response) => return response,
    };
    match service.list_keypairs_for_auth(&auth).await {
        Ok(keypairs) => Json(KeypairListResponse {
            keypairs: keypairs
                .into_iter()
                .map(|keypair| KeypairEnvelope {
                    keypair: keypair_response(keypair),
                })
                .collect(),
        })
        .into_response(),
        Err(error) => compute_error(error),
    }
}

pub(crate) async fn create_keypair(
    State(state): State<AppState>,
    headers: axum::http::HeaderMap,
    Path(project_id): Path<String>,
    request: Result<Json<CreateKeypairEnvelope>, JsonRejection>,
) -> axum::response::Response {
    let auth = match project_auth_context(&state, &headers, &project_id) {
        Ok(value) => value,
        Err(response) => return response,
    };
    let service = match compute_service(&state) {
        Ok(value) => value,
        Err(response) => return response,
    };
    let Ok(Json(body)) = request else {
        return keystone_error(
            StatusCode::BAD_REQUEST,
            "Bad Request",
            "invalid keypair request",
        );
    };
    if body
        .keypair
        .key_type
        .as_deref()
        .is_some_and(|key_type| key_type != "ssh")
    {
        return keystone_error(
            StatusCode::BAD_REQUEST,
            "Bad Request",
            "unsupported keypair type",
        );
    }
    let Some(public_key) = body.keypair.public_key else {
        return keystone_error(
            StatusCode::BAD_REQUEST,
            "Bad Request",
            "public_key is required",
        );
    };
    match service
        .create_keypair_for_auth(&auth, body.keypair.name, public_key)
        .await
    {
        Ok(keypair) => (
            StatusCode::OK,
            Json(KeypairEnvelope {
                keypair: keypair_response(keypair),
            }),
        )
            .into_response(),
        Err(error) => compute_error(error),
    }
}

pub(crate) async fn show_keypair(
    State(state): State<AppState>,
    headers: axum::http::HeaderMap,
    Path((project_id, name)): Path<(String, String)>,
) -> axum::response::Response {
    let auth = match project_auth_context(&state, &headers, &project_id) {
        Ok(value) => value,
        Err(response) => return response,
    };
    let service = match compute_service(&state) {
        Ok(value) => value,
        Err(response) => return response,
    };
    match service.show_keypair_for_auth(&auth, &name).await {
        Ok(keypair) => Json(KeypairEnvelope {
            keypair: keypair_response(keypair),
        })
        .into_response(),
        Err(error) => compute_error(error),
    }
}

pub(crate) async fn delete_keypair(
    State(state): State<AppState>,
    headers: axum::http::HeaderMap,
    Path((project_id, name)): Path<(String, String)>,
) -> axum::response::Response {
    let auth = match project_auth_context(&state, &headers, &project_id) {
        Ok(value) => value,
        Err(response) => return response,
    };
    let service = match compute_service(&state) {
        Ok(value) => value,
        Err(response) => return response,
    };
    match service.delete_keypair_for_auth(&auth, &name).await {
        Ok(()) => StatusCode::NO_CONTENT.into_response(),
        Err(error) => compute_error(error),
    }
}

pub(crate) async fn create_server(
    State(state): State<AppState>,
    headers: axum::http::HeaderMap,
    Path(project_id): Path<String>,
    request: Result<Json<CreateServerEnvelope>, JsonRejection>,
) -> axum::response::Response {
    let auth = match project_auth_context(&state, &headers, &project_id) {
        Ok(value) => value,
        Err(response) => return response,
    };
    let service = match compute_service(&state) {
        Ok(value) => value,
        Err(response) => return response,
    };
    let Ok(Json(body)) = request else {
        return keystone_error(
            StatusCode::BAD_REQUEST,
            "Bad Request",
            "invalid server request",
        );
    };
    let config_drive = if body.server.config_drive == Some(true) {
        let keypair_public_key = if body.server.ssh_public_key.is_none() {
            if let Some(key_name) = body.server.key_name.as_deref() {
                match service.show_keypair_for_auth(&auth, key_name).await {
                    Ok(keypair) => Some(keypair.public_key),
                    Err(error) => return compute_error(error),
                }
            } else {
                None
            }
        } else {
            None
        };
        let ssh_public_key = match config_drive_ssh_public_key(
            body.server.ssh_public_key.clone(),
            keypair_public_key,
        ) {
            Ok(value) => value,
            Err(message) => return keystone_error(StatusCode::BAD_REQUEST, "Bad Request", message),
        };
        let user_data = body
            .server
            .user_data
            .clone()
            .unwrap_or_default()
            .into_bytes();
        let vendor_data = body.server.vendor_data.clone().map(String::into_bytes);
        if let Err(error) = o3k_config_drive::validate_input_bounds(
            &ssh_public_key,
            &user_data,
            vendor_data.as_deref(),
        ) {
            tracing::debug!(%error, "config-drive request rejected by input bounds");
            return keystone_error(
                StatusCode::BAD_REQUEST,
                "Bad Request",
                "config-drive input exceeds configured limits",
            );
        }
        Some(ConfigDriveRequest {
            user_data,
            vendor_data,
            ssh_public_key,
        })
    } else {
        None
    };
    let Some(image) = body
        .server
        .image
        .map(IdReference::into_id)
        .filter(|reference| !reference.trim().is_empty())
    else {
        return keystone_error(StatusCode::BAD_REQUEST, "Bad Request", "image is required");
    };
    let Some(flavor) = body
        .server
        .flavor
        .map(IdReference::into_id)
        .and_then(|reference| reference.parse().ok())
    else {
        return keystone_error(StatusCode::BAD_REQUEST, "Bad Request", "flavor is required");
    };
    let Some(networks) = body.server.networks else {
        return keystone_error(
            StatusCode::BAD_REQUEST,
            "Bad Request",
            "network is required",
        );
    };
    if networks.is_empty()
        || networks.iter().any(|network| {
            network
                .port
                .as_deref()
                .or(network.uuid.as_deref())
                .is_none_or(str::is_empty)
        })
    {
        return keystone_error(
            StatusCode::BAD_REQUEST,
            "Bad Request",
            "network is required",
        );
    }
    if let Some(image_service) = state.image.as_ref() {
        let image_id = match image.parse::<uuid::Uuid>() {
            Ok(value) => value,
            Err(_) => {
                return keystone_error(
                    StatusCode::BAD_REQUEST,
                    "Bad Request",
                    "image must be a UUID when image validation is enabled",
                );
            }
        };
        match image_service.get(&auth, image_id).await {
            Ok(record) if record.status == o3k_image::ImageStatus::Active => {}
            Ok(_) => {
                return keystone_error(StatusCode::CONFLICT, "Conflict", "image is not active");
            }
            Err(error) => return image_error(error),
        }
    }
    let idempotency = headers
        .get("x-openstack-request-id")
        .and_then(|value| value.to_str().ok())
        .unwrap_or(&body.server.name)
        .to_owned();
    let server_id = ComputeService::server_id_for_create(&project_id, &idempotency);
    let mut owned_network_ids = Vec::new();
    let mut network_ids = Vec::with_capacity(networks.len());
    if let Some(network_service) = state.network.as_ref() {
        for network in networks {
            if let Some(port) = network.port {
                let port_id = match port.parse::<uuid::Uuid>() {
                    Ok(value) => value,
                    Err(_) => {
                        return keystone_error(
                            StatusCode::BAD_REQUEST,
                            "Bad Request",
                            "port references must be UUIDs",
                        );
                    }
                };
                if let Err(error) = network_service.get_port(&auth, port_id).await {
                    return network_error(error);
                }
                network_ids.push(port);
            } else if let Some(network_id) = network.uuid {
                let network_id = match network_id.parse::<uuid::Uuid>() {
                    Ok(value) => value,
                    Err(_) => {
                        return keystone_error(
                            StatusCode::BAD_REQUEST,
                            "Bad Request",
                            "network references must be UUIDs",
                        );
                    }
                };
                if network_service.get_network(&auth, network_id).await.is_ok() {
                    // Nova's bounded P13 profile supplies a Network UUID, not
                    // a pre-created Port UUID. Resolve the single admitted
                    // Realm through the canonical Network service and create
                    // exactly one canonical Endpoint before accepting the
                    // Server.
                    let port_name = format!("o3k-server:{project_id}:{idempotency}");
                    let port = match network_service
                        .create_port_for_project(&project_id, network_id, port_name)
                        .await
                    {
                        Ok(port) => port,
                        Err(error) => return network_error(error),
                    };
                    network_ids.push(port.id.to_string());
                    owned_network_ids.push(port.id.to_string());
                } else if network_service.get_port(&auth, network_id).await.is_ok() {
                    // Preserve the existing bounded compatibility path for
                    // callers that explicitly supply an already-created Port.
                    network_ids.push(network_id.to_string());
                } else {
                    return keystone_error(
                        StatusCode::NOT_FOUND,
                        "Not Found",
                        "network resource was not found",
                    );
                }
            }
        }
    } else {
        network_ids = networks
            .into_iter()
            .filter_map(|network| network.port.or(network.uuid))
            .collect();
    }
    if network_ids.is_empty() {
        return keystone_error(
            StatusCode::BAD_REQUEST,
            "Bad Request",
            "network is required",
        );
    }
    let result = service
        .create_server_for_auth(
            &auth,
            o3k_compute::ServerCreateInput {
                user_id: auth.principal().id().as_str().to_owned(),
                project_id: auth.effective_scope().id().as_str().to_owned(),
                name: body.server.name,
                image_id: image,
                flavor_id: flavor,
                network_ids,
                key_name: body.server.key_name,
                config_drive,
                idempotency_key: idempotency,
            },
        )
        .await;
    match result {
        Ok(server) => {
            if let Some(network_service) = state.network.as_ref() {
                let _mutation_guard = state.network_mutation_lock.lock().await;
                let mut cleanup_failed = false;
                for port_id in &owned_network_ids {
                    if !server.network_ids.iter().any(|id| id == port_id)
                        && let Ok(port_id) = port_id.parse()
                        && let Err(error) = network_service
                            .delete_port_for_project(&project_id, port_id)
                            .await
                    {
                        cleanup_failed = true;
                        tracing::error!(
                            %error,
                            %port_id,
                            "server create cleanup could not remove unused endpoint"
                        );
                    }
                }
                if cleanup_failed {
                    return keystone_error(
                        StatusCode::INTERNAL_SERVER_ERROR,
                        "Internal Server Error",
                        "server network cleanup failed",
                    );
                }
            }
            (
                StatusCode::ACCEPTED,
                Json(ServerEnvelope {
                    server: server_response(server, state.network.as_deref()).await,
                }),
            )
                .into_response()
        }
        Err(error) => {
            if let Some(network_service) = state.network.as_ref() {
                let _mutation_guard = state.network_mutation_lock.lock().await;
                // The durable canonical outcome decides whether the request's
                // endpoints may be released — not the error being reported. A
                // create that is live, in flight, or inconclusive keeps its
                // endpoints so a real guest never loses its network dependency.
                let dependency = match service
                    .create_dependency_state_for_auth(&auth, ServerId::from_uuid(server_id))
                    .await
                {
                    Ok(dependency) => dependency,
                    Err(lookup_error) => {
                        tracing::error!(
                            %lookup_error,
                            %server_id,
                            "server create outcome could not be checked before endpoint compensation"
                        );
                        return keystone_error(
                            StatusCode::INTERNAL_SERVER_ERROR,
                            "Internal Server Error",
                            "server create outcome could not be recovered",
                        );
                    }
                };
                if dependency.disposition == o3k_compute::CreateDependencyDisposition::Preserve {
                    tracing::warn!(
                        server_id = %server_id,
                        "retaining server endpoints for the durable create outcome"
                    );
                    return compute_error(error);
                }
                // Compensate the request-owned endpoints *and* the endpoints the
                // durable create intent still names: a terminally failed create
                // may have allocated them in an earlier attempt, and the shared
                // ownership rule releases only O3K server-owned endpoints of
                // this project, so a caller-supplied endpoint is never removed.
                let mut candidates = owned_network_ids
                    .iter()
                    .filter_map(|port_id| port_id.parse().ok())
                    .collect::<Vec<uuid::Uuid>>();
                for port_id in &dependency.network_ids {
                    if let Ok(port_id) = port_id.parse::<uuid::Uuid>()
                        && !candidates.contains(&port_id)
                    {
                        candidates.push(port_id);
                    }
                }
                if let Err(cleanup_error) = network_service
                    .cleanup_server_owned_ports_for_project(&project_id, &candidates)
                    .await
                {
                    tracing::error!(
                        %cleanup_error,
                        %server_id,
                        "server create compensation could not remove owned endpoints"
                    );
                    return keystone_error(
                        StatusCode::INTERNAL_SERVER_ERROR,
                        "Internal Server Error",
                        "server network compensation failed",
                    );
                }
            }
            compute_error(error)
        }
    }
}

pub(crate) async fn list_servers(
    State(state): State<AppState>,
    headers: axum::http::HeaderMap,
    Path(project_id): Path<String>,
    Query(query): Query<ServerListQuery>,
    request_uri: Uri,
) -> axum::response::Response {
    let auth = match project_auth_context(&state, &headers, &project_id) {
        Ok(value) => value,
        Err(response) => return response,
    };
    let service = match compute_service(&state) {
        Ok(value) => value,
        Err(response) => return response,
    };
    let page = match CollectionPage::parse(query.limit.as_deref(), query.marker.as_deref()) {
        Ok(value) => value,
        Err(response) => return response,
    };
    match service.list_servers_for_auth(&auth).await {
        Ok(mut servers) => {
            let links = page.apply(&mut servers, |server| server.id.as_uuid(), &request_uri);
            let mut server_responses = Vec::with_capacity(servers.len());
            for server in servers {
                server_responses.push(server_response(server, state.network.as_deref()).await);
            }
            Json(ServerListResponse {
                servers: server_responses,
                servers_links: links,
            })
            .into_response()
        }
        Err(error) => compute_error(error),
    }
}

pub(crate) async fn show_server(
    State(state): State<AppState>,
    headers: axum::http::HeaderMap,
    Path((project_id, id)): Path<(String, uuid::Uuid)>,
) -> axum::response::Response {
    let auth = match project_auth_context(&state, &headers, &project_id) {
        Ok(value) => value,
        Err(response) => return response,
    };
    let service = match compute_service(&state) {
        Ok(value) => value,
        Err(response) => return response,
    };
    match service
        .show_server_for_auth(&auth, ServerId::from_uuid(id))
        .await
    {
        Ok(server) => Json(ServerEnvelope {
            server: server_response(server, state.network.as_deref()).await,
        })
        .into_response(),
        Err(error) => compute_error(error),
    }
}

pub(crate) async fn update_server(
    State(state): State<AppState>,
    headers: axum::http::HeaderMap,
    Path((project_id, id)): Path<(String, uuid::Uuid)>,
    request: Result<Json<UpdateServerEnvelope>, JsonRejection>,
) -> axum::response::Response {
    let auth = match project_auth_context(&state, &headers, &project_id) {
        Ok(value) => value,
        Err(response) => return response,
    };
    let service = match compute_service(&state) {
        Ok(value) => value,
        Err(response) => return response,
    };
    let Ok(Json(body)) = request else {
        return keystone_error(
            StatusCode::BAD_REQUEST,
            "Bad Request",
            "invalid server update",
        );
    };
    let Some(name) = body.server.name else {
        return keystone_error(StatusCode::BAD_REQUEST, "Bad Request", "name is required");
    };
    match service
        .update_server_name_for_auth(&auth, ServerId::from_uuid(id), name)
        .await
    {
        Ok(server) => Json(ServerEnvelope {
            server: server_response(server, state.network.as_deref()).await,
        })
        .into_response(),
        Err(error) => compute_error(error),
    }
}

pub(crate) async fn show_server_metadata(
    State(state): State<AppState>,
    headers: axum::http::HeaderMap,
    Path((project_id, id)): Path<(String, uuid::Uuid)>,
) -> axum::response::Response {
    let auth = match project_auth_context(&state, &headers, &project_id) {
        Ok(value) => value,
        Err(response) => return response,
    };
    let service = match compute_service(&state) {
        Ok(value) => value,
        Err(response) => return response,
    };
    match service
        .show_server_for_auth(&auth, ServerId::from_uuid(id))
        .await
    {
        Ok(_) => Json(serde_json::json!({"metadata": {}})).into_response(),
        Err(error) => compute_error(error),
    }
}

pub(crate) async fn delete_server(
    State(state): State<AppState>,
    headers: axum::http::HeaderMap,
    Path((project_id, id)): Path<(String, uuid::Uuid)>,
) -> axum::response::Response {
    let auth = match project_auth_context(&state, &headers, &project_id) {
        Ok(value) => value,
        Err(response) => return response,
    };
    let service = match compute_service(&state) {
        Ok(value) => value,
        Err(response) => return response,
    };
    let _mutation_guard = state.network_mutation_lock.lock().await;
    let owned_ports = match service
        .server_network_ids_for_auth(&auth, ServerId::from_uuid(id))
        .await
    {
        Ok(network_ids) => network_ids
            .iter()
            .filter_map(|port_id| port_id.parse::<uuid::Uuid>().ok())
            .collect::<Vec<_>>(),
        Err(ComputeError::NotFound) => Vec::new(),
        Err(error) => return compute_error(error),
    };
    match service
        .delete_server_for_auth(&auth, ServerId::from_uuid(id))
        .await
    {
        Ok(()) => {
            if let Some(console) = state.console.as_ref()
                && let Err(error) = console.cleanup(id)
            {
                tracing::warn!(%error, server_id = %id, "deleted server console cleanup failed");
                return keystone_error(
                    StatusCode::INTERNAL_SERVER_ERROR,
                    "Internal Server Error",
                    "server console cleanup failed",
                );
            }
            if let Some(network_service) = state.network.as_ref()
                && let Err(error) = network_service
                    .cleanup_server_owned_ports_for_project(&project_id, &owned_ports)
                    .await
            {
                tracing::error!(%error, %id, "server-owned endpoint cleanup failed");
                return keystone_error(
                    StatusCode::INTERNAL_SERVER_ERROR,
                    "Internal Server Error",
                    "server network cleanup failed",
                );
            }
            StatusCode::NO_CONTENT.into_response()
        }
        Err(error) => compute_error(error),
    }
}

pub(crate) async fn server_action(
    State(state): State<AppState>,
    headers: axum::http::HeaderMap,
    Path((project_id, id)): Path<(String, uuid::Uuid)>,
    request: Result<Json<serde_json::Value>, JsonRejection>,
) -> axum::response::Response {
    let auth = match project_auth_context(&state, &headers, &project_id) {
        Ok(value) => value,
        Err(response) => return response,
    };
    let service = match compute_service(&state) {
        Ok(value) => value,
        Err(response) => return response,
    };
    let Ok(Json(body)) = request else {
        return keystone_error(
            StatusCode::BAD_REQUEST,
            "Bad Request",
            "invalid server action",
        );
    };
    let action = match body
        .as_object()
        .and_then(|object| object.keys().next())
        .map(String::as_str)
    {
        Some("os-getConsoleOutput") => {
            let Some(console) = state.console.as_ref() else {
                return keystone_error(
                    StatusCode::SERVICE_UNAVAILABLE,
                    "Service Unavailable",
                    "console output is not configured",
                );
            };
            if let Err(error) = service
                .show_server_for_auth(&auth, ServerId::from_uuid(id))
                .await
            {
                return compute_error(error);
            }
            let options = body
                .get("os-getConsoleOutput")
                .and_then(serde_json::Value::as_object);
            let offset = match options.and_then(|value| value.get("offset")) {
                None => Ok(0),
                Some(value) => value.as_u64().ok_or(()),
            };
            let Ok(offset) = offset else {
                return keystone_error(
                    StatusCode::BAD_REQUEST,
                    "Bad Request",
                    "console output offset is invalid",
                );
            };
            let length = match options.and_then(|value| value.get("length")) {
                None => Ok(o3k_console::MAX_CONSOLE_BYTES as u64),
                Some(value) => value.as_u64().ok_or(()),
            };
            let Ok(length) = length else {
                return keystone_error(
                    StatusCode::BAD_REQUEST,
                    "Bad Request",
                    "console output length is invalid",
                );
            };
            let Ok(length) = usize::try_from(length) else {
                return keystone_error(
                    StatusCode::BAD_REQUEST,
                    "Bad Request",
                    "console output length is invalid",
                );
            };
            if length == 0 {
                return (StatusCode::OK, Json(serde_json::json!({"output": ""}))).into_response();
            }
            if should_query_live_console(offset)
                && let Some(registry) = state.agent_registry.as_ref()
            {
                match service
                    .placement_provider_id(
                        auth.effective_scope().id().as_str(),
                        ServerId::from_uuid(id),
                    )
                    .await
                {
                    Ok(Some(agent_id)) => {
                        let Some(node) = registry.snapshot(&agent_id).await else {
                            return keystone_error(
                                StatusCode::SERVICE_UNAVAILABLE,
                                "Service Unavailable",
                                "compute agent is not registered",
                            );
                        };
                        let operation_id = uuid::Uuid::now_v7().to_string();
                        let command = match o3k_compute_agent::build_console_log_command(
                            &agent_id,
                            &node.agent_epoch,
                            &operation_id,
                            &id.to_string(),
                            offset,
                            length.min(o3k_console::MAX_CONSOLE_BYTES) as u32,
                        ) {
                            Ok(command) => command,
                            Err(_) => {
                                return keystone_error(
                                    StatusCode::BAD_REQUEST,
                                    "Bad Request",
                                    "console output bounds are invalid",
                                );
                            }
                        };
                        if let Ok(op_uuid) = uuid::Uuid::parse_str(&operation_id) {
                            let _ = registry.persist_pending_command(&command, op_uuid).await;
                        }
                        let dispatch_started = std::time::Instant::now();
                        tracing::info!(
                            server_id = %id,
                            agent_id = %agent_id,
                            %operation_id,
                            offset,
                            length,
                            "console dispatch start"
                        );
                        let observation = match registry
                            .dispatch_command_and_wait(command, CONSOLE_AGENT_DISPATCH_TIMEOUT)
                            .await
                        {
                            Ok(observation) => {
                                tracing::info!(
                                    server_id = %id,
                                    %operation_id,
                                    console_bytes = observation.console_log_bytes.len(),
                                    console_offset = observation.console_log_offset,
                                    complete = observation.console_log_complete,
                                    truncated = observation.console_log_truncated,
                                    elapsed_ms = dispatch_started.elapsed().as_millis(),
                                    "console dispatch observation received"
                                );
                                observation
                            }
                            Err(error) => {
                                tracing::warn!(
                                    %error,
                                    server_id = %id,
                                    %operation_id,
                                    elapsed_ms = dispatch_started.elapsed().as_millis(),
                                    "agent console query failed"
                                );
                                if let Some(response) =
                                    cached_console_response(console, id, offset, length)
                                {
                                    tracing::info!(
                                        server_id = %id,
                                        %operation_id,
                                        "console dispatch fell back to cached output"
                                    );
                                    return response;
                                }
                                return keystone_error(
                                    StatusCode::SERVICE_UNAVAILABLE,
                                    "Service Unavailable",
                                    "compute agent console output is unavailable",
                                );
                            }
                        };
                        if let Err(error) = console.write_chunk(
                            id,
                            observation.console_log_offset,
                            &observation.console_log_bytes,
                        ) {
                            tracing::warn!(
                                %error,
                                server_id = %id,
                                %operation_id,
                                "agent console observation persistence failed"
                            );
                        }
                        if let Some(response) = cached_console_response(console, id, offset, length)
                        {
                            return response;
                        }
                        return keystone_error(
                            StatusCode::SERVICE_UNAVAILABLE,
                            "Service Unavailable",
                            "compute agent console output could not be persisted",
                        );
                    }
                    Ok(None) => {}
                    Err(error) => return compute_error(error),
                }
            }
            return match console.read_from(id, offset, length) {
                Ok(chunk) => (
                    StatusCode::OK,
                    Json(serde_json::json!({"output": String::from_utf8_lossy(&chunk.bytes)})),
                )
                    .into_response(),
                Err(ConsoleError::NotFound) => {
                    tracing::info!(
                        server_id = %id,
                        offset,
                        "no persisted console output; returning empty response"
                    );
                    (StatusCode::OK, Json(serde_json::json!({"output": ""}))).into_response()
                }
                Err(_) => keystone_error(
                    StatusCode::INTERNAL_SERVER_ERROR,
                    "Internal Server Error",
                    "console output is unavailable",
                ),
            };
        }
        Some("os-start") => InstanceAction::Start,
        Some("os-stop") => InstanceAction::Stop,
        Some("reboot") | Some("os-reboot") => InstanceAction::Reboot,
        _ => {
            return keystone_error(
                StatusCode::BAD_REQUEST,
                "Bad Request",
                "unsupported server action",
            );
        }
    };
    match service
        .action_for_auth(&auth, ServerId::from_uuid(id), action)
        .await
    {
        Ok(server) => (
            StatusCode::ACCEPTED,
            Json(ServerEnvelope {
                server: server_response(server, state.network.as_deref()).await,
            }),
        )
            .into_response(),
        Err(error) => compute_error(error),
    }
}
/// Whether the caller negotiated Nova microversion 2.89 for this request.
/// Mirrors the parsing in `microversion_middleware`: the caller may use
/// `OpenStack-API-Version: compute 2.89` or `X-OpenStack-Nova-API-Version:
/// 2.89`. The operation-scoped 2.89 profile is GET-only on the volume
/// attachment routes; this helper is used to select the 2.89 response shape.
pub(crate) fn requested_compute_289(headers: &HeaderMap) -> bool {
    let os_api_ver = headers
        .get("OpenStack-API-Version")
        .and_then(|h| h.to_str().ok());
    let nova_api_ver = headers
        .get("X-OpenStack-Nova-API-Version")
        .and_then(|h| h.to_str().ok());
    let mut compute_version: Option<&str> = None;
    if let Some(val) = os_api_ver {
        for part in val.split(',') {
            let tokens: Vec<&str> = part.split_whitespace().collect();
            if tokens.len() == 2 && tokens[0].eq_ignore_ascii_case("compute") {
                compute_version = Some(tokens[1]);
                break;
            }
        }
    }
    if compute_version.is_none()
        && let Some(val) = nova_api_ver
    {
        let trimmed = val.trim();
        if !trimmed.is_empty() {
            compute_version = Some(trimmed);
        }
    }
    compute_version == Some("2.89")
}

#[cfg(test)]
mod tests {

    use super::{Server, ServerId, ServerState, server_response, should_query_live_console};
    use crate::CONSOLE_AGENT_DISPATCH_TIMEOUT;
    use std::time::Duration;
    use uuid::Uuid;

    #[test]
    fn live_console_queries_are_limited_to_the_snapshot_offset() {
        assert!(should_query_live_console(0));
        assert!(!should_query_live_console(1));
        assert!(!should_query_live_console(u64::MAX));
    }

    #[test]
    fn live_console_agent_budget_matches_public_request_budget() {
        assert_eq!(CONSOLE_AGENT_DISPATCH_TIMEOUT, Duration::from_secs(15));
    }

    #[test]
    fn unsupported_config_drive_requests_are_explicitly_recognized() -> Result<(), serde_json::Error>
    {
        let request = serde_json::json!({
            "name": "server",
            "image": {"id": "image"},
            "flavor": {"id": "1"},
            "networks": [{"uuid": "network"}],
            "config_drive": true
        });
        let parsed: super::CreateServerRequest = serde_json::from_value(request)?;
        assert_eq!(parsed.config_drive, Some(true));
        Ok(())
    }

    #[test]
    fn nova_server_reference_aliases_accept_standard_cli_wire_fields()
    -> Result<(), serde_json::Error> {
        let request = serde_json::json!({
            "name": "server",
            "imageRef": "image-id",
            "flavorRef": "550e8400-e29b-41d4-a716-446655440000",
            "networks": [{"port": "550e8400-e29b-41d4-a716-446655440001"}]
        });
        let parsed: super::CreateServerRequest = serde_json::from_value(request)?;
        assert_eq!(parsed.config_drive, None);
        assert!(
            matches!(parsed.image, Some(super::IdReference::String(value)) if value == "image-id")
        );
        assert!(
            matches!(parsed.flavor, Some(super::IdReference::String(value)) if value == "550e8400-e29b-41d4-a716-446655440000")
        );
        assert_eq!(
            parsed
                .networks
                .as_ref()
                .and_then(|items| items[0].port.as_deref()),
            Some("550e8400-e29b-41d4-a716-446655440001")
        );
        Ok(())
    }

    #[test]
    fn config_drive_key_name_falls_back_to_the_project_keypair() {
        assert_eq!(
            super::config_drive_ssh_public_key(
                None,
                Some("ssh-ed25519 AAAA generated-by-keypair".to_owned())
            )
            .as_deref(),
            Ok("ssh-ed25519 AAAA generated-by-keypair")
        );
        assert!(super::config_drive_ssh_public_key(None, None).is_err());
    }

    #[tokio::test]
    async fn server_response_reports_requested_config_drive_without_exposing_payload()
    -> Result<(), serde_json::Error> {
        let server = Server {
            id: ServerId::from_uuid(Uuid::nil()),
            name: "server".to_owned(),
            project_id: "project".to_owned(),
            flavor_id: Uuid::nil(),
            image_id: "image".to_owned(),
            state: ServerState::Active,
            key_name: Some("key".to_owned()),
            config_drive: true,
            network_ids: Vec::new(),
            host: None,
        };
        let response = server_response(server, None).await;
        let value = serde_json::to_value(response)?;
        assert_eq!(value.get("config_drive"), Some(&serde_json::json!(true)));
        assert!(value.get("user_data").is_none());
        assert!(value.get("ssh_public_key").is_none());
        assert_eq!(
            value.get("OS-EXT-SRV-ATTR:host"),
            Some(&serde_json::Value::Null)
        );
        Ok(())
    }

    #[tokio::test]
    async fn server_response_reports_the_durable_placement_host() -> Result<(), serde_json::Error> {
        let server = Server {
            id: ServerId::from_uuid(Uuid::nil()),
            name: "server".to_owned(),
            project_id: "project".to_owned(),
            flavor_id: Uuid::nil(),
            image_id: "image".to_owned(),
            state: ServerState::Active,
            key_name: None,
            config_drive: false,
            network_ids: Vec::new(),
            host: Some("node-a".to_owned()),
        };
        let response = server_response(server, None).await;
        let value = serde_json::to_value(response)?;
        assert_eq!(
            value.get("OS-EXT-SRV-ATTR:host"),
            Some(&serde_json::json!("node-a"))
        );
        Ok(())
    }

    #[test]
    fn canonical_server_states_project_to_the_nova_response_shape() {
        let expected = [
            (ServerState::Requested, "BUILD"),
            (ServerState::Building, "BUILD"),
            (ServerState::Active, "ACTIVE"),
            (ServerState::Stopping, "STOPPING"),
            (ServerState::Stopped, "SHUTOFF"),
            (ServerState::Starting, "STARTING"),
            (ServerState::Rebooting, "REBOOTING"),
            (ServerState::Deleting, "DELETING"),
            (ServerState::Deleted, "DELETED"),
            (ServerState::Error, "ERROR"),
        ];
        assert_eq!(expected.len(), 10);
        for (state, status) in expected {
            assert_eq!(
                super::nova_status(state),
                status,
                "{state:?} must project to {status}"
            );
        }
    }

    #[tokio::test]
    async fn server_response_projects_the_canonical_state_as_status()
    -> Result<(), serde_json::Error> {
        let server = Server {
            id: ServerId::from_uuid(Uuid::nil()),
            name: "server".to_owned(),
            project_id: "project".to_owned(),
            flavor_id: Uuid::nil(),
            image_id: "image".to_owned(),
            state: ServerState::Stopped,
            key_name: None,
            config_drive: false,
            network_ids: Vec::new(),
            host: None,
        };
        let value = serde_json::to_value(server_response(server, None).await)?;
        assert_eq!(value.get("status"), Some(&serde_json::json!("SHUTOFF")));
        Ok(())
    }
}
