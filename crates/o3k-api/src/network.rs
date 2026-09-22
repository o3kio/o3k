//! Neutron-compatible network protocol adapter: network/subnet/port
//! handlers, wire models, and error mapping.

use std::{net::Ipv4Addr, sync::Arc};

use axum::{
    Json,
    extract::{Path, Query, State, rejection::JsonRejection},
    http::StatusCode,
    response::IntoResponse,
};
use o3k_domain::{NetworkProtocol, PolicyAction, PolicyDirection, PolicyIntent, PortRange};
use o3k_kernel::AuthContext;
use o3k_network::{
    NetworkError, NetworkRecord, NetworkService, PortRecord, PublicAddressAllocator,
    PublicAddressBinding, PublicAddressError, SubnetRecord,
};
use uuid::Uuid;

use crate::{
    AppState,
    auth::require_auth_context,
    error::keystone_error,
    pagination::{CollectionLink, CollectionPage},
};

#[derive(serde::Deserialize)]
pub(crate) struct RouterRequestBody {
    router: RouterRequest,
}
#[derive(serde::Deserialize)]
pub(crate) struct RouterRequest {
    name: String,
    #[serde(default)]
    enable_snat: Option<bool>,
    #[serde(default)]
    external_realm_id: Option<Uuid>,
    #[serde(default)]
    /// `None` means omitted; `Some(None)` is an explicit Neutron clear.
    external_gateway_info: Option<Option<ExternalGatewayInfo>>,
}
#[derive(serde::Deserialize)]
pub(crate) struct ExternalGatewayInfo {
    network_id: Option<Uuid>,
    #[serde(default)]
    enable_snat: Option<bool>,
}
#[derive(serde::Serialize)]
pub(crate) struct RouterEnvelope {
    router: RouterResponse,
}
#[derive(serde::Serialize)]
pub(crate) struct RouterList {
    routers: Vec<RouterResponse>,
}
#[derive(serde::Serialize)]
pub(crate) struct RouterResponse {
    id: String,
    name: String,
    project_id: String,
    tenant_id: String,
    status: String,
    admin_state_up: bool,
    enable_snat: bool,
    external_gateway_info: Option<ExternalGatewayInfoResponse>,
}
#[derive(serde::Serialize)]
pub(crate) struct ExternalGatewayInfoResponse {
    network_id: String,
    enable_snat: bool,
}
#[derive(serde::Deserialize)]
pub(crate) struct RouterInterfaceRequestBody {
    #[serde(default)]
    router_interface: Option<RouterInterfaceRequest>,
    #[serde(default)]
    realm_id: Option<Uuid>,
    #[serde(default)]
    subnet_id: Option<Uuid>,
    #[serde(default)]
    port_id: Option<Uuid>,
}
#[derive(serde::Deserialize)]
pub(crate) struct RouterInterfaceRequest {
    #[serde(default)]
    realm_id: Option<Uuid>,
    #[serde(default)]
    subnet_id: Option<Uuid>,
    #[serde(default)]
    port_id: Option<Uuid>,
}
impl RouterInterfaceRequestBody {
    fn into_request(self) -> RouterInterfaceRequest {
        self.router_interface.unwrap_or(RouterInterfaceRequest {
            realm_id: self.realm_id,
            subnet_id: self.subnet_id,
            port_id: self.port_id,
        })
    }
}
#[derive(serde::Serialize)]
pub(crate) struct RouterInterfaceResponse {
    #[serde(rename = "port_id")]
    port_id: String,
    #[serde(rename = "router_id")]
    router_id: String,
    subnet_id: String,
}
#[derive(serde::Serialize)]
pub(crate) struct RouterInterfaceRemovalResponse {
    subnet_id: String,
    tenant_id: String,
    port_id: String,
    id: String,
}
async fn router_response(
    service: &NetworkService,
    project: &str,
    g: o3k_store::CanonicalL3GatewayRecord,
) -> Result<RouterResponse, NetworkError> {
    let external_network_id = match g.external_realm_id {
        Some(realm_id) => Some(
            service
                .get_canonical_realm_for_project(project, realm_id)
                .await?
                .network_id,
        ),
        None => None,
    };
    Ok(RouterResponse {
        id: g.id.to_string(),
        name: g.name,
        project_id: g.project_id.clone(),
        tenant_id: g.project_id,
        status: g.state.to_ascii_uppercase(),
        admin_state_up: true,
        enable_snat: g.enable_snat,
        external_gateway_info: external_network_id.map(|id| ExternalGatewayInfoResponse {
            network_id: id.to_string(),
            enable_snat: g.enable_snat,
        }),
    })
}

async fn external_realm_for_router(
    service: &NetworkService,
    project: &str,
    request: &RouterRequest,
) -> Result<Option<Uuid>, NetworkError> {
    if let Some(realm_id) = request.external_realm_id {
        return Ok(Some(realm_id));
    }
    let Some(Some(info)) = request.external_gateway_info.as_ref() else {
        return Ok(None);
    };
    let Some(network_id) = info.network_id else {
        return Err(NetworkError::InvalidRequest);
    };
    let realms = service
        .list_canonical_realms_for_project(project, network_id)
        .await?;
    realms
        .into_iter()
        .next()
        .map(|realm| Some(realm.id))
        .ok_or(NetworkError::NotFound)
}

pub(crate) async fn list_routers(
    State(state): State<AppState>,
    headers: axum::http::HeaderMap,
) -> axum::response::Response {
    let auth = match require_auth_context(&state, &headers) {
        Ok(v) => v,
        Err(r) => return r,
    };
    let service = match network_service(&state) {
        Ok(v) => v,
        Err(r) => return r,
    };
    match service
        .list_l3_gateways_for_project(auth.effective_scope().id().as_str())
        .await
    {
        Ok(gateways) => {
            let mut routers = Vec::with_capacity(gateways.len());
            for gateway in gateways {
                match router_response(service, auth.effective_scope().id().as_str(), gateway).await
                {
                    Ok(router) => routers.push(router),
                    Err(error) => return network_error(error),
                }
            }
            Json(RouterList { routers }).into_response()
        }
        Err(error) => network_error(error),
    }
}

pub(crate) async fn create_router(
    State(state): State<AppState>,
    headers: axum::http::HeaderMap,
    request: Result<Json<RouterRequestBody>, JsonRejection>,
) -> axum::response::Response {
    let auth = match require_auth_context(&state, &headers) {
        Ok(v) => v,
        Err(r) => return r,
    };
    let Ok(Json(body)) = request else {
        return keystone_error(
            StatusCode::BAD_REQUEST,
            "Bad Request",
            "invalid router request",
        );
    };
    let service = match network_service(&state) {
        Ok(v) => v,
        Err(r) => return r,
    };
    let project = auth.effective_scope().id().as_str();
    let external_realm_id = match external_realm_for_router(service, project, &body.router).await {
        Ok(value) => value,
        Err(error) => return network_error(error),
    };
    let result = service
        .create_l3_gateway_for_project(
            project,
            body.router.name,
            external_realm_id,
            body.router
                .external_gateway_info
                .as_ref()
                .and_then(|info| info.as_ref())
                .and_then(|info| info.enable_snat)
                .or(body.router.enable_snat)
                .unwrap_or(true),
        )
        .await;
    match result {
        Ok(gateway) => {
            if state.network_dispatcher.is_some()
                && state.network_controller.is_some()
                && state.network_gateway_realization_enabled()
            {
                let snapshot = match service
                    .compile_l3_gateway_execution_plan_for_project(project, &gateway.id)
                    .await
                {
                    Ok(value) => value,
                    Err(error) => return network_error(error),
                };
                if let Err(response) = dispatch_l3_gateway_snapshot(
                    &state,
                    project,
                    snapshot,
                    o3k_network::NetworkPlanAction::Apply,
                    gateway.generation,
                )
                .await
                {
                    return response;
                }
            }
            match router_response(service, project, gateway).await {
                Ok(router) => {
                    (StatusCode::CREATED, Json(RouterEnvelope { router })).into_response()
                }
                Err(error) => network_error(error),
            }
        }
        Err(error) => network_error(error),
    }
}

pub(crate) async fn show_router(
    State(state): State<AppState>,
    headers: axum::http::HeaderMap,
    Path(id): Path<Uuid>,
) -> axum::response::Response {
    let auth = match require_auth_context(&state, &headers) {
        Ok(v) => v,
        Err(r) => return r,
    };
    let service = match network_service(&state) {
        Ok(v) => v,
        Err(r) => return r,
    };
    let project = auth.effective_scope().id().as_str();
    match service
        .get_l3_gateway_for_project(auth.effective_scope().id().as_str(), &id)
        .await
    {
        Ok(gateway) => match router_response(service, project, gateway).await {
            Ok(router) => Json(RouterEnvelope { router }).into_response(),
            Err(error) => network_error(error),
        },
        Err(error) => network_error(error),
    }
}

pub(crate) async fn update_router(
    State(state): State<AppState>,
    headers: axum::http::HeaderMap,
    Path(id): Path<Uuid>,
    request: Result<Json<RouterRequestBody>, JsonRejection>,
) -> axum::response::Response {
    let auth = match require_auth_context(&state, &headers) {
        Ok(v) => v,
        Err(r) => return r,
    };
    let Ok(Json(body)) = request else {
        return keystone_error(
            StatusCode::BAD_REQUEST,
            "Bad Request",
            "invalid router request",
        );
    };
    let service = match network_service(&state) {
        Ok(v) => v,
        Err(r) => return r,
    };
    let project = auth.effective_scope().id().as_str();
    let current = match service.get_l3_gateway_for_project(project, &id).await {
        Ok(v) => v,
        Err(e) => return network_error(e),
    };
    let external_realm_id = match body.router.external_gateway_info.as_ref() {
        Some(Some(_)) => match external_realm_for_router(service, project, &body.router).await {
            Ok(value) => value,
            Err(error) => return network_error(error),
        },
        Some(None) => None,
        None => match external_realm_for_router(service, project, &body.router).await {
            Ok(value) => value.or(current.external_realm_id),
            Err(error) => return network_error(error),
        },
    };
    match service
        .update_l3_gateway_for_project(
            project,
            &id,
            current.generation,
            body.router.name,
            external_realm_id,
            body.router
                .external_gateway_info
                .as_ref()
                .and_then(|info| info.as_ref())
                .and_then(|info| info.enable_snat)
                .or(body.router.enable_snat)
                .unwrap_or(current.enable_snat),
        )
        .await
    {
        Ok(gateway) => {
            if state.network_dispatcher.is_some()
                && state.network_controller.is_some()
                && state.network_gateway_realization_enabled()
            {
                let snapshot = match service
                    .compile_l3_gateway_execution_plan_for_project(project, &gateway.id)
                    .await
                {
                    Ok(value) => value,
                    Err(error) => return network_error(error),
                };
                if let Err(response) = dispatch_l3_gateway_snapshot(
                    &state,
                    project,
                    snapshot,
                    o3k_network::NetworkPlanAction::Apply,
                    gateway.generation,
                )
                .await
                {
                    return response;
                }
            }
            match router_response(service, project, gateway).await {
                Ok(router) => Json(RouterEnvelope { router }).into_response(),
                Err(error) => network_error(error),
            }
        }
        Err(error) => network_error(error),
    }
}

pub(crate) async fn delete_router(
    State(state): State<AppState>,
    headers: axum::http::HeaderMap,
    Path(id): Path<Uuid>,
) -> axum::response::Response {
    let auth = match require_auth_context(&state, &headers) {
        Ok(v) => v,
        Err(r) => return r,
    };
    let service = match network_service(&state) {
        Ok(v) => v,
        Err(r) => return r,
    };
    let project = auth.effective_scope().id().as_str();
    // In the bounded profile, host-side gateway realization is disabled, so
    // an accepted attachment deletion has no provider observation left to
    // await. Finish that durable deletion reservation before retrying the
    // router delete; otherwise the canonical gateway fence can transiently
    // report the router as still in use after interface DELETE succeeded.
    if !state.network_gateway_realization_enabled() {
        let attachments = match service.list_l3_gateway_attachments(project, &id).await {
            Ok(value) => value,
            Err(error) => return network_error(error),
        };
        for attachment in attachments
            .into_iter()
            .filter(|attachment| attachment.state == "deleting")
        {
            if let Err(error) = service
                .finalize_l3_gateway_realm_detachment_for_project(
                    project,
                    &attachment.id,
                    attachment.generation,
                )
                .await
            {
                return network_error(error);
            }
        }
    }
    let current = match service.get_l3_gateway_for_project(project, &id).await {
        Ok(value) => value,
        Err(error) => return network_error(error),
    };
    let deleting = match service
        .delete_l3_gateway_for_project(project, &id, current.generation)
        .await
    {
        Ok(value) => value,
        Err(error) => return network_error(error),
    };
    if state.network_dispatcher.is_some()
        && state.network_controller.is_some()
        && state.network_gateway_realization_enabled()
    {
        let snapshot = match service
            .compile_l3_gateway_execution_plan_for_project(project, &id)
            .await
        {
            Ok(snapshot) => snapshot,
            Err(error) => return network_error(error),
        };
        let dispatched = match dispatch_l3_gateway_snapshot(
            &state,
            project,
            snapshot,
            o3k_network::NetworkPlanAction::Remove,
            deleting.generation,
        )
        .await
        {
            Ok(value) => value,
            Err(response) => return response,
        };
        if dispatched
            && let Err(error) = service
                .finalize_l3_gateway_deletion_for_project(project, &id, deleting.generation)
                .await
        {
            return network_error(error);
        }
    } else if let Err(error) = service
        .finalize_l3_gateway_deletion_for_project(project, &id, deleting.generation)
        .await
    {
        return network_error(error);
    }
    // A successful dispatch means the network executor completed its
    // provider mutation and observation workflow. Without an execution
    // boundary, canonical deletion was finalized above because there is no
    // external realization that requires observation.
    StatusCode::ACCEPTED.into_response()
}

pub(crate) async fn add_router_interface(
    State(state): State<AppState>,
    headers: axum::http::HeaderMap,
    Path(id): Path<Uuid>,
    request: Result<Json<RouterInterfaceRequestBody>, JsonRejection>,
) -> axum::response::Response {
    let auth = match require_auth_context(&state, &headers) {
        Ok(v) => v,
        Err(r) => return r,
    };
    let Ok(Json(body)) = request else {
        return keystone_error(
            StatusCode::BAD_REQUEST,
            "Bad Request",
            "invalid router interface request",
        );
    };
    let body = body.into_request();
    let service = match network_service(&state) {
        Ok(v) => v,
        Err(r) => return r,
    };
    let project = auth.effective_scope().id().as_str();
    let requested_port_id = body.port_id;
    let realm_id = if let Some(realm_id) = body.realm_id {
        realm_id
    } else if let Some(port_id) = requested_port_id {
        let port = match service.get_port_for_project(project, port_id).await {
            Ok(value) => value,
            Err(error) => return network_error(error),
        };
        let subnet_id = port
            .subnet_id
            .ok_or_else(|| network_error(NetworkError::NotFound));
        let subnet_id = match subnet_id {
            Ok(value) => value,
            Err(response) => return response,
        };
        let subnet = match service.get_subnet_for_project(project, subnet_id).await {
            Ok(value) => value,
            Err(error) => return network_error(error),
        };
        let realms = match service
            .list_canonical_realms_for_project(project, subnet.network_id)
            .await
        {
            Ok(value) => value,
            Err(error) => return network_error(error),
        };
        let Some(realm) = realms.into_iter().find(|realm| realm.prefix == subnet.cidr) else {
            return network_error(NetworkError::NotFound);
        };
        realm.id
    } else if let Some(subnet_id) = body.subnet_id {
        let subnet = match service
            .get_subnet_for_project(auth.effective_scope().id().as_str(), subnet_id)
            .await
        {
            Ok(v) => v,
            Err(e) => return network_error(e),
        };
        let realms = match service
            .list_canonical_realms_for_project(
                auth.effective_scope().id().as_str(),
                subnet.network_id,
            )
            .await
        {
            Ok(v) => v,
            Err(e) => return network_error(e),
        };
        let Some(realm) = realms.into_iter().next() else {
            return network_error(NetworkError::NotFound);
        };
        realm.id
    } else {
        return network_error(NetworkError::InvalidRequest);
    };
    let response_subnet_id = body.subnet_id.unwrap_or(realm_id);
    match service
        .attach_l3_gateway_realm(auth.effective_scope().id().as_str(), &id, &realm_id)
        .await
    {
        Ok(a) => {
            let realm = match service.get_canonical_realm(&auth, a.realm_id).await {
                Ok(value) => value,
                Err(error) => return network_error(error),
            };
            let ports = match service
                .list_ports_for_project(auth.effective_scope().id().as_str())
                .await
            {
                Ok(value) => value,
                Err(error) => return network_error(error),
            };
            let mut provider_dispatched = false;
            for port in ports
                .into_iter()
                .filter(|port| port.network_id == realm.network_id)
            {
                let dispatched = match dispatch_policy_network_with_gateway(
                    &state,
                    project,
                    realm.network_id,
                    port.id,
                    Some(a.gateway_id),
                    o3k_network::NetworkPlanAction::Apply,
                )
                .await
                {
                    Ok(value) => value,
                    Err(response) => return response,
                };
                provider_dispatched |= dispatched;
            }
            if !provider_dispatched
                && state.network_dispatcher.is_some()
                && state.network_controller.is_some()
                && state.network_gateway_realization_enabled()
            {
                let snapshot = match service
                    .compile_l3_gateway_execution_plan_for_project(project, &a.gateway_id)
                    .await
                {
                    Ok(value) => value,
                    Err(error) => return network_error(error),
                };
                if let Err(response) = dispatch_l3_gateway_snapshot(
                    &state,
                    project,
                    snapshot,
                    o3k_network::NetworkPlanAction::Apply,
                    a.generation,
                )
                .await
                {
                    return response;
                }
            }
            (
                StatusCode::OK,
                Json(RouterInterfaceResponse {
                    port_id: requested_port_id.unwrap_or(a.id).to_string(),
                    router_id: a.gateway_id.to_string(),
                    subnet_id: response_subnet_id.to_string(),
                }),
            )
                .into_response()
        }
        Err(error) => network_error(error),
    }
}

pub(crate) async fn remove_router_interface(
    State(state): State<AppState>,
    headers: axum::http::HeaderMap,
    Path(id): Path<Uuid>,
    request: Result<Json<RouterInterfaceRequestBody>, JsonRejection>,
) -> axum::response::Response {
    let auth = match require_auth_context(&state, &headers) {
        Ok(v) => v,
        Err(r) => return r,
    };
    let Ok(Json(body)) = request else {
        return keystone_error(
            StatusCode::BAD_REQUEST,
            "Bad Request",
            "invalid router interface request",
        );
    };
    let body = body.into_request();
    let service = match network_service(&state) {
        Ok(v) => v,
        Err(r) => return r,
    };
    // Keep the canonical detach and every derived provider Apply in one
    // mutation epoch.  Port deletion takes the same lock, so it cannot
    // remove the endpoint between the detach snapshot and its dispatch.
    let _mutation_guard = state.network_mutation_lock.lock().await;
    let project = auth.effective_scope().id().as_str();
    let attachments = match service.list_l3_gateway_attachments(project, &id).await {
        Ok(v) => v,
        Err(e) => return network_error(e),
    };
    let realm_id = if let Some(realm_id) = body.realm_id {
        realm_id
    } else if let Some(port_id) = body.port_id {
        let port = match service.get_port_for_project(project, port_id).await {
            Ok(value) => value,
            Err(error) => return network_error(error),
        };
        let Some(subnet_id) = port.subnet_id else {
            return network_error(NetworkError::NotFound);
        };
        let subnet = match service.get_subnet_for_project(project, subnet_id).await {
            Ok(value) => value,
            Err(error) => return network_error(error),
        };
        let realms = match service
            .list_canonical_realms_for_project(project, subnet.network_id)
            .await
        {
            Ok(value) => value,
            Err(error) => return network_error(error),
        };
        let Some(realm) = realms.into_iter().find(|realm| realm.prefix == subnet.cidr) else {
            return network_error(NetworkError::NotFound);
        };
        realm.id
    } else if let Some(subnet_id) = body.subnet_id {
        let subnet = match service.get_subnet_for_project(project, subnet_id).await {
            Ok(value) => value,
            Err(error) => return network_error(error),
        };
        let realms = match service
            .list_canonical_realms_for_project(project, subnet.network_id)
            .await
        {
            Ok(value) => value,
            Err(error) => return network_error(error),
        };
        let Some(realm) = realms.into_iter().find(|realm| realm.prefix == subnet.cidr) else {
            return network_error(NetworkError::NotFound);
        };
        realm.id
    } else {
        Uuid::nil()
    };
    let Some(a) = attachments
        .into_iter()
        .find(|a| a.state == "active" && (a.realm_id == realm_id || body.port_id == Some(a.id)))
    else {
        return network_error(NetworkError::NotFound);
    };
    let realm = match service.get_canonical_realm(&auth, a.realm_id).await {
        Ok(value) => value,
        Err(error) => return network_error(error),
    };
    let result = service
        .detach_l3_gateway_realm(project, &a.id, a.generation)
        .await;
    match result {
        Ok(deleting) => {
            let ports = match service.list_ports_for_project(project).await {
                Ok(value) => value,
                Err(error) => return network_error(error),
            };
            let network_ports = ports
                .into_iter()
                .filter(|port| port.network_id == realm.network_id)
                .collect::<Vec<_>>();
            let mut provider_dispatched = false;
            for port in &network_ports {
                let dispatched = match dispatch_policy_network_with_gateway(
                    &state,
                    project,
                    realm.network_id,
                    port.id,
                    Some(a.gateway_id),
                    o3k_network::NetworkPlanAction::Apply,
                )
                .await
                {
                    Ok(value) => value,
                    Err(response) => return response,
                };
                provider_dispatched |= dispatched;
            }
            if !provider_dispatched
                && state.network_dispatcher.is_some()
                && state.network_controller.is_some()
                && state.network_gateway_realization_enabled()
            {
                let snapshot = match service
                    .compile_l3_gateway_execution_plan_for_project(project, &a.gateway_id)
                    .await
                {
                    Ok(value) => value,
                    Err(error) => return network_error(error),
                };
                if let Err(response) = dispatch_l3_gateway_snapshot(
                    &state,
                    project,
                    snapshot,
                    o3k_network::NetworkPlanAction::Apply,
                    deleting.generation,
                )
                .await
                {
                    return response;
                }
                provider_dispatched = true;
            }
            // With no execution boundary there is no external realization to
            // observe. Finalize the canonical relationship immediately; an
            // available boundary still requires a successful observation.
            // A deployment that deactivates host-side gateway realization has
            // no gateway snapshot to dispatch either, so canonical detachment
            // finalizes the same way.
            let no_execution_boundary = state.network_dispatcher.is_none()
                || state.network_controller.is_none()
                || !state.network_gateway_realization_enabled();
            if (provider_dispatched || no_execution_boundary)
                && let Err(error) = service
                    .finalize_l3_gateway_realm_detachment_for_project(
                        project,
                        &deleting.id,
                        deleting.generation,
                    )
                    .await
            {
                return network_error(error);
            }
            // The pinned provider extracts the successful response as an
            // InterfaceInfo.  Returning the canonical relationship fields is
            // therefore required even though the mutation itself is already
            // finalized at this compatibility boundary.
            (
                StatusCode::OK,
                Json(RouterInterfaceRemovalResponse {
                    subnet_id: body.subnet_id.unwrap_or(a.realm_id).to_string(),
                    tenant_id: project.to_owned(),
                    port_id: a.id.to_string(),
                    id: a.id.to_string(),
                }),
            )
                .into_response()
        }
        Err(error) => network_error(error),
    }
}

async fn dispatch_l3_gateway_snapshot(
    state: &AppState,
    project_id: &str,
    gateway: o3k_domain::L3GatewayExecutionPlan,
    action: o3k_network::NetworkPlanAction,
    generation: u64,
) -> Result<bool, axum::response::Response> {
    let Some(dispatcher) = state.network_dispatcher.as_ref() else {
        return Ok(false);
    };
    let Some(controller) = state.network_controller.as_ref() else {
        return Ok(false);
    };
    let Some(agent) = state.network_agent.as_ref() else {
        return Err(keystone_error(
            StatusCode::SERVICE_UNAVAILABLE,
            "Service Unavailable",
            "gateway provider agent is unavailable",
        ));
    };
    if gateway.project_id != project_id {
        return Err(keystone_error(
            StatusCode::BAD_REQUEST,
            "Bad Request",
            "gateway project ownership mismatch",
        ));
    }
    let fingerprint = o3k_network::gateway_plan_fingerprint(&gateway).map_err(|error| {
        keystone_error(StatusCode::BAD_REQUEST, "Bad Request", error.to_string())
    })?;
    let operation_id = Uuid::new_v5(
        &Uuid::NAMESPACE_URL,
        format!(
            "o3k:network:gateway:{action:?}:{project_id}:{}:{generation}:{fingerprint}",
            gateway.gateway_id
        )
        .as_bytes(),
    );
    let deadline_unix_ms = unix_time_millis().saturating_add(30_000);
    let plan = o3k_network::compile_l3_gateway_network_plan(
        gateway,
        &agent.agent_id,
        operation_id,
        deadline_unix_ms,
    )
    .map_err(|error| keystone_error(StatusCode::BAD_REQUEST, "Bad Request", error.to_string()))?;
    let command_id = Uuid::new_v5(
        &Uuid::NAMESPACE_URL,
        format!("o3k:network:gateway-command:{operation_id}").as_bytes(),
    );
    let status = dispatcher
        .dispatch(o3k_network::NetworkPlanCommand {
            command_id,
            operation_id,
            idempotency_key: format!(
                "o3k:network:gateway:{project_id}:{}:{generation}:{fingerprint}:{action:?}",
                plan.plan_id
            ),
            action,
            target: agent.clone(),
            controller: controller.clone(),
            deadline_unix_ms,
            plan,
        })
        .await
        .map_err(|error| {
            keystone_error(
                StatusCode::SERVICE_UNAVAILABLE,
                "Service Unavailable",
                error.to_string(),
            )
        })?;
    if status != o3k_network::NetworkPlanStatus::Succeeded {
        return Err(keystone_error(
            StatusCode::SERVICE_UNAVAILABLE,
            "Service Unavailable",
            "gateway realization requires observation",
        ));
    }
    Ok(true)
}

/// Resume durable gateway/attachment deletion reservations after a process
/// restart.  This pass is deliberately owned by the API composition root so
/// it runs after the network-agent execution boundary has been wired.  It
/// uses only canonical transitional rows and lets the provider/agent observe
/// convergence before finalizing those rows.
pub async fn recover_l3_gateway_operations(state: &AppState) {
    let (Some(service), Some(_dispatcher), Some(_controller)) = (
        state.network.as_ref(),
        state.network_dispatcher.as_ref(),
        state.network_controller.as_ref(),
    ) else {
        return;
    };
    let gateways = match service.list_deleting_l3_gateways().await {
        Ok(gateways) => gateways,
        Err(error) => {
            tracing::error!(%error, "failed to enumerate deleting L3 gateways during startup recovery");
            return;
        }
    };
    for gateway in gateways {
        let project = gateway.project_id.clone();
        let gateway_id = gateway.id;
        let generation = gateway.generation;
        let snapshot = match service
            .compile_l3_gateway_execution_plan_for_project(&project, &gateway_id)
            .await
        {
            Ok(snapshot) => snapshot,
            Err(error) => {
                tracing::warn!(%error, %gateway_id, "cannot reconstruct deleting gateway removal target");
                continue;
            }
        };
        match dispatch_l3_gateway_snapshot(
            state,
            &project,
            snapshot,
            o3k_network::NetworkPlanAction::Remove,
            generation,
        )
        .await
        {
            Ok(true) => {
                if let Err(error) = service
                    .finalize_l3_gateway_deletion_for_project(&project, &gateway_id, generation)
                    .await
                {
                    tracing::warn!(%error, %gateway_id, "gateway removal observed but canonical finalization is pending");
                }
            }
            Ok(false) => {
                tracing::warn!(%gateway_id, "gateway deletion remains pending without an execution boundary")
            }
            Err(_) => tracing::warn!(%gateway_id, "gateway deletion recovery did not converge"),
        }
    }
    let attachments = match service.list_deleting_l3_gateway_attachments().await {
        Ok(attachments) => attachments,
        Err(error) => {
            tracing::error!(%error, "failed to enumerate deleting L3 gateway attachments during startup recovery");
            return;
        }
    };
    for attachment in attachments {
        let gateway = match service
            .get_l3_gateway_for_project(&attachment.project_id, &attachment.gateway_id)
            .await
        {
            Ok(gateway) => gateway,
            Err(error) => {
                tracing::warn!(%error, attachment_id = %attachment.id, "cannot recover deleting gateway attachment");
                continue;
            }
        };
        let snapshot = match service
            .compile_l3_gateway_execution_plan_for_project(&attachment.project_id, &gateway.id)
            .await
        {
            Ok(snapshot) => snapshot,
            Err(error) => {
                tracing::warn!(%error, attachment_id = %attachment.id, "cannot reconstruct gateway attachment target");
                continue;
            }
        };
        match dispatch_l3_gateway_snapshot(
            state,
            &attachment.project_id,
            snapshot,
            o3k_network::NetworkPlanAction::Apply,
            attachment.generation,
        )
        .await
        {
            Ok(true) => {
                if let Err(error) = service
                    .finalize_l3_gateway_realm_detachment_for_project(
                        &attachment.project_id,
                        &attachment.id,
                        attachment.generation,
                    )
                    .await
                {
                    tracing::warn!(%error, attachment_id = %attachment.id, "attachment converged but canonical finalization is pending");
                }
            }
            Ok(false) => {
                tracing::warn!(attachment_id = %attachment.id, "attachment deletion remains pending without an execution boundary")
            }
            Err(_) => {
                tracing::warn!(attachment_id = %attachment.id, "attachment deletion recovery did not converge")
            }
        }
    }
    // Policy child deletion reservations use the same startup owner and the
    // same endpoint execution boundary.  The canonical rows are deliberately
    // finalized only after every affected endpoint has been dispatched; a
    // failed or unavailable endpoint leaves the child durably deleting.
    let deleting_attachments = match service.list_deleting_policy_attachments().await {
        Ok(attachments) => attachments,
        Err(error) => {
            tracing::error!(%error, "failed to enumerate deleting policy attachments during startup recovery");
            return;
        }
    };
    for attachment in deleting_attachments {
        let network_id = match service
            .network_id_for_canonical_endpoint(&attachment.project_id, &attachment.endpoint_id)
            .await
        {
            Ok(network_id) => network_id,
            Err(error) => {
                tracing::warn!(%error, attachment_id = %attachment.id, "cannot resolve policy attachment execution context");
                continue;
            }
        };
        match dispatch_policy_network_with_gateway(
            state,
            &attachment.project_id,
            network_id,
            attachment.endpoint_id,
            None,
            o3k_network::NetworkPlanAction::Apply,
        )
        .await
        {
            Ok(true) => {
                if let Err(error) = service
                    .finalize_policy_attachment_deletion_for_project(
                        &attachment.project_id,
                        attachment.id,
                        attachment.generation,
                    )
                    .await
                {
                    tracing::warn!(%error, attachment_id = %attachment.id, "policy attachment converged but canonical finalization is pending");
                }
            }
            Ok(false) => {
                tracing::warn!(attachment_id = %attachment.id, "policy attachment remains deleting without an execution boundary")
            }
            Err(_error) => {
                tracing::warn!(attachment_id = %attachment.id, "policy attachment recovery did not converge")
            }
        }
    }

    let deleting_rules = match service.list_deleting_policy_rules().await {
        Ok(rules) => rules,
        Err(error) => {
            tracing::error!(%error, "failed to enumerate deleting policy rules during startup recovery");
            return;
        }
    };
    for rule in deleting_rules {
        let endpoints = match service
            .affected_endpoints_for_canonical_policy(&rule.project_id, rule.policy_id)
            .await
        {
            Ok(endpoints) => endpoints,
            Err(error) => {
                tracing::warn!(%error, rule_id = %rule.id, "cannot resolve deleting policy rule endpoints");
                continue;
            }
        };
        let mut converged = true;
        for endpoint_id in endpoints {
            let network_id = match service
                .network_id_for_canonical_endpoint(&rule.project_id, &endpoint_id)
                .await
            {
                Ok(network_id) => network_id,
                Err(error) => {
                    tracing::warn!(%error, rule_id = %rule.id, %endpoint_id, "cannot resolve policy rule execution context");
                    converged = false;
                    continue;
                }
            };
            match dispatch_policy_network_with_gateway(
                state,
                &rule.project_id,
                network_id,
                endpoint_id,
                None,
                o3k_network::NetworkPlanAction::Apply,
            )
            .await
            {
                Ok(true) => {}
                Ok(false) => converged = false,
                Err(_error) => {
                    tracing::warn!(rule_id = %rule.id, %endpoint_id, "policy rule recovery did not converge");
                    converged = false;
                }
            }
        }
        if converged
            && let Err(error) = service
                .finalize_security_group_rule_deletion_for_project(
                    &rule.project_id,
                    rule.id,
                    rule.generation,
                )
                .await
        {
            tracing::warn!(%error, rule_id = %rule.id, "policy rule recovery converged but canonical finalization is pending");
        }
    }
}

#[derive(serde::Deserialize)]
pub(crate) struct NetworkRequestBody {
    network: CreateNetworkRequest,
}
#[derive(serde::Deserialize)]
pub(crate) struct CreateNetworkRequest {
    name: String,
}
#[derive(serde::Deserialize)]
pub(crate) struct UpdateNetworkRequestBody {
    network: UpdateNetworkRequest,
}
#[derive(serde::Deserialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct UpdateNetworkRequest {
    name: Option<String>,
    #[serde(default)]
    admin_state_up: Option<bool>,
}
#[derive(serde::Serialize)]
pub(crate) struct NetworkEnvelope {
    network: NetworkResponse,
}
#[derive(serde::Serialize)]
pub(crate) struct NetworkList {
    networks: Vec<NetworkResponse>,
    // Emitted only for a paginating client (`limit` supplied); a plain listing
    // keeps its existing byte-shape.
    #[serde(skip_serializing_if = "Option::is_none")]
    networks_links: Option<Vec<CollectionLink>>,
}
#[derive(serde::Serialize)]
pub(crate) struct NetworkResponse {
    id: String,
    name: String,
    project_id: String,
    tenant_id: String,
    status: String,
    admin_state_up: bool,
    mtu: u32,
    subnets: Vec<String>,
}

pub(crate) fn network_response(
    value: NetworkRecord,
    admin_state_up: bool,
    subnet_ids: Vec<Uuid>,
) -> NetworkResponse {
    NetworkResponse {
        id: value.id.to_string(),
        name: value.name,
        tenant_id: value.project_id.clone(),
        project_id: value.project_id.clone(),
        status: value.status,
        admin_state_up,
        mtu: 1500,
        subnets: subnet_ids.into_iter().map(|id| id.to_string()).collect(),
    }
}

#[derive(serde::Deserialize)]
pub(crate) struct UpdateSubnetRequestBody {
    subnet: UpdateSubnetRequest,
}

#[derive(serde::Deserialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct UpdateSubnetRequest {
    name: Option<String>,
    gateway_ip: Option<Ipv4Addr>,
    enable_dhcp: Option<bool>,
    network_id: Option<Uuid>,
    cidr: Option<String>,
    ip_version: Option<u8>,
}

async fn canonical_network_response(
    service: &NetworkService,
    value: NetworkRecord,
) -> Result<NetworkResponse, NetworkError> {
    let snapshot = service
        .reconstruct_canonical_network(&value.project_id, value.id)
        .await?;
    Ok(network_response(
        value,
        snapshot.network.admin_state_up,
        snapshot.realms.into_iter().map(|realm| realm.id).collect(),
    ))
}

#[derive(serde::Deserialize)]
pub(crate) struct SubnetRequestBody {
    subnet: CreateSubnetRequest,
}
#[derive(serde::Deserialize)]
pub(crate) struct CreateSubnetRequest {
    #[serde(default)]
    name: Option<String>,
    network_id: uuid::Uuid,
    cidr: String,
    #[serde(default)]
    ip_version: Option<u8>,
    gateway_ip: Option<Ipv4Addr>,
    #[serde(default)]
    enable_dhcp: Option<bool>,
    allocation_pools: Option<Vec<AllocationPool>>,
}
#[derive(serde::Deserialize)]
#[allow(dead_code)]
pub(crate) struct AllocationPool {
    start: Ipv4Addr,
    end: Ipv4Addr,
}
#[derive(serde::Serialize)]
pub(crate) struct SubnetEnvelope {
    subnet: SubnetResponse,
}
#[derive(serde::Serialize)]
pub(crate) struct SubnetList {
    subnets: Vec<SubnetResponse>,
}
#[derive(serde::Serialize)]
pub(crate) struct SubnetResponse {
    id: String,
    network_id: String,
    name: String,
    project_id: String,
    cidr: String,
    gateway_ip: Ipv4Addr,
    allocation_pools: Vec<AllocationPoolResponse>,
    tenant_id: String,
    ip_version: u8,
    enable_dhcp: bool,
    dns_nameservers: Vec<String>,
    host_routes: Vec<serde_json::Value>,
}
#[derive(serde::Serialize)]
pub(crate) struct AllocationPoolResponse {
    start: Ipv4Addr,
    end: Ipv4Addr,
}

pub(crate) fn subnet_response(value: SubnetRecord) -> SubnetResponse {
    SubnetResponse {
        id: value.id.to_string(),
        network_id: value.network_id.to_string(),
        name: value.name,
        project_id: value.project_id.clone(),
        cidr: value.cidr,
        gateway_ip: value.gateway_ip,
        allocation_pools: vec![AllocationPoolResponse {
            start: value.allocation_start,
            end: value.allocation_end,
        }],
        tenant_id: value.project_id,
        ip_version: value.ip_version,
        enable_dhcp: value.enable_dhcp,
        dns_nameservers: Vec::new(),
        host_routes: Vec::new(),
    }
}

#[derive(serde::Deserialize)]
pub(crate) struct PortRequestBody {
    port: CreatePortRequest,
}
#[derive(serde::Deserialize)]
pub(crate) struct UpdatePortRequestBody {
    port: UpdatePortRequest,
}
#[derive(serde::Deserialize)]
pub(crate) struct UpdatePortRequest {
    #[serde(default)]
    name: Option<String>,
    #[serde(default)]
    security_groups: Vec<uuid::Uuid>,
}
#[derive(serde::Deserialize)]
pub(crate) struct CreatePortRequest {
    #[serde(default)]
    name: Option<String>,
    network_id: uuid::Uuid,
    #[serde(default)]
    fixed_ips: Vec<FixedIpRequest>,
    #[serde(default)]
    no_fixed_ip: bool,
    #[serde(default)]
    security_groups: Vec<uuid::Uuid>,
}
#[derive(serde::Deserialize)]
pub(crate) struct FixedIpRequest {
    subnet_id: uuid::Uuid,
    #[serde(default)]
    ip_address: Option<Ipv4Addr>,
}
#[derive(serde::Serialize)]
pub(crate) struct PortEnvelope {
    port: PortResponse,
}
#[derive(serde::Serialize)]
pub(crate) struct PortList {
    ports: Vec<PortResponse>,
}
#[derive(serde::Serialize)]
pub(crate) struct PortResponse {
    id: String,
    network_id: String,
    project_id: String,
    name: String,
    mac_address: String,
    fixed_ips: Vec<FixedIpResponse>,
    status: String,
    security_groups: Vec<String>,
    tenant_id: String,
    admin_state_up: bool,
    device_id: String,
    device_owner: String,
    port_security_enabled: bool,
}
#[derive(serde::Serialize)]
pub(crate) struct FixedIpResponse {
    subnet_id: String,
    ip_address: Ipv4Addr,
}

#[derive(serde::Deserialize)]
pub(crate) struct NetworkPolicyQuery {
    network_id: Uuid,
}

#[derive(serde::Deserialize)]
pub(crate) struct NetworkQuery {
    id: Option<Uuid>,
    // Collection pagination members. Every other query parameter the pinned
    // Horizon client sends (`sort_key`, `sort_dir`, `shared`, ...) is ignored
    // by serde and must keep being accepted.
    #[serde(default)]
    limit: Option<String>,
    #[serde(default)]
    marker: Option<String>,
}

#[derive(serde::Deserialize)]
pub(crate) struct NetworkPolicyRequestBody {
    policy: NetworkPolicyRequest,
}

#[derive(serde::Deserialize)]
pub(crate) struct NetworkPolicyRequest {
    network_id: Uuid,
    endpoint_id: Uuid,
    direction: String,
    protocol: String,
    ports: Option<PolicyPortRange>,
    source: Option<String>,
    destination: Option<String>,
    action: String,
}

#[derive(serde::Deserialize, serde::Serialize)]
pub(crate) struct PolicyPortRange {
    start: u16,
    end: u16,
}

#[derive(serde::Deserialize)]
pub(crate) struct SecurityGroupRequestBody {
    security_group: SecurityGroupRequest,
}
#[derive(serde::Deserialize)]
pub(crate) struct SecurityGroupRequest {
    #[serde(default)]
    name: Option<String>,
    #[serde(default)]
    description: String,
    #[serde(default)]
    stateful: Option<bool>,
}
#[derive(serde::Serialize)]
pub(crate) struct SecurityGroupEnvelope {
    security_group: SecurityGroupResponse,
}
#[derive(serde::Serialize)]
pub(crate) struct SecurityGroupList {
    security_groups: Vec<SecurityGroupResponse>,
}
#[derive(serde::Serialize)]
pub(crate) struct SecurityGroupResponse {
    id: String,
    project_id: String,
    name: String,
    description: String,
    stateful: bool,
    security_group_rules: Vec<SecurityGroupRuleResponse>,
}
#[derive(serde::Deserialize)]
pub(crate) struct SecurityGroupRuleRequestBody {
    security_group_rule: SecurityGroupRuleRequest,
}
#[derive(serde::Deserialize)]
pub(crate) struct SecurityGroupRuleRequest {
    security_group_id: Uuid,
    direction: String,
    #[serde(default)]
    protocol: Option<String>,
    #[serde(default)]
    port_range_min: Option<u16>,
    #[serde(default)]
    port_range_max: Option<u16>,
    #[serde(default)]
    remote_ip_prefix: Option<String>,
    #[serde(default)]
    ethertype: Option<String>,
    #[serde(default)]
    remote_group_id: Option<Uuid>,
}
#[derive(serde::Serialize)]
pub(crate) struct SecurityGroupRuleResponse {
    id: String,
    project_id: String,
    security_group_id: String,
    direction: String,
    ethertype: &'static str,
    protocol: Option<String>,
    port_range_min: Option<u16>,
    port_range_max: Option<u16>,
    remote_ip_prefix: Option<String>,
    remote_group_id: Option<String>,
}
#[derive(serde::Serialize)]
pub(crate) struct SecurityGroupRuleEnvelope {
    security_group_rule: SecurityGroupRuleResponse,
}
#[derive(serde::Serialize)]
pub(crate) struct SecurityGroupRuleList {
    security_group_rules: Vec<SecurityGroupRuleResponse>,
}
#[derive(serde::Deserialize)]
pub(crate) struct SecurityGroupRuleQuery {
    #[serde(default)]
    security_group_id: Option<Uuid>,
}

#[derive(serde::Serialize)]
pub(crate) struct NetworkPolicyEnvelope {
    policy: NetworkPolicyResponse,
}

#[derive(serde::Serialize)]
pub(crate) struct NetworkPolicyList {
    policies: Vec<NetworkPolicyResponse>,
}

#[derive(serde::Serialize)]
pub(crate) struct NetworkPolicyResponse {
    id: String,
    network_id: String,
    endpoint_id: String,
    direction: &'static str,
    protocol: &'static str,
    ports: Option<PolicyPortRange>,
    source: Option<String>,
    destination: Option<String>,
    action: &'static str,
    status: &'static str,
}

fn policy_response(network_id: Uuid, policy: PolicyIntent) -> NetworkPolicyResponse {
    NetworkPolicyResponse {
        id: policy.id.to_string(),
        network_id: network_id.to_string(),
        endpoint_id: policy.endpoint_id.to_string(),
        direction: match policy.direction {
            PolicyDirection::Ingress => "ingress",
            PolicyDirection::Egress => "egress",
        },
        protocol: match policy.protocol {
            NetworkProtocol::Any => "any",
            NetworkProtocol::Tcp => "tcp",
            NetworkProtocol::Udp => "udp",
            NetworkProtocol::Icmp => "icmp",
        },
        ports: policy.ports.map(|ports| PolicyPortRange {
            start: ports.start,
            end: ports.end,
        }),
        source: policy
            .source
            .map(|prefix| format!("{}/{}", prefix.network, prefix.prefix_len)),
        destination: policy
            .destination
            .map(|prefix| format!("{}/{}", prefix.network, prefix.prefix_len)),
        action: match policy.action {
            PolicyAction::Allow => "allow",
            PolicyAction::Deny => "deny",
        },
        // The API mutation is durable intent. Host realization is reported by
        // the agent observation path, so this projection must not claim active
        // before that evidence exists.
        status: "pending",
    }
}

fn parse_policy_prefix(value: Option<String>) -> Result<Option<o3k_domain::Ipv4Prefix>, ()> {
    value
        .map(|value| {
            let (address, length) = value.split_once('/').ok_or(())?;
            let address = address.parse().map_err(|_| ())?;
            let length = length.parse().map_err(|_| ())?;
            o3k_domain::Ipv4Prefix::new(address, length).ok_or(())
        })
        .transpose()
}

fn parse_policy_request(
    request: NetworkPolicyRequest,
    id: Uuid,
) -> Result<(Uuid, PolicyIntent), ()> {
    let direction = match request.direction.as_str() {
        "ingress" => PolicyDirection::Ingress,
        "egress" => PolicyDirection::Egress,
        _ => return Err(()),
    };
    let protocol = match request.protocol.as_str() {
        "any" => NetworkProtocol::Any,
        "tcp" => NetworkProtocol::Tcp,
        "udp" => NetworkProtocol::Udp,
        "icmp" => NetworkProtocol::Icmp,
        _ => return Err(()),
    };
    let action = match request.action.as_str() {
        "allow" => PolicyAction::Allow,
        "deny" => PolicyAction::Deny,
        _ => return Err(()),
    };
    let source = parse_policy_prefix(request.source)?;
    let destination = parse_policy_prefix(request.destination)?;
    Ok((
        request.network_id,
        PolicyIntent {
            id,
            endpoint_id: request.endpoint_id,
            direction,
            protocol,
            ports: request.ports.map(|ports| PortRange {
                start: ports.start,
                end: ports.end,
            }),
            source,
            destination,
            action,
        },
    ))
}

async fn security_group_response(
    service: &NetworkService,
    project_id: &str,
    group: o3k_store::SecurityGroupRecord,
) -> Result<SecurityGroupResponse, NetworkError> {
    let rules = service
        .list_security_group_rules_for_project(project_id, group.id)
        .await?
        .into_iter()
        .map(security_group_rule_response)
        .collect();
    Ok(SecurityGroupResponse {
        id: group.id.to_string(),
        project_id: group.project_id,
        name: group.name,
        description: group.description,
        stateful: true,
        security_group_rules: rules,
    })
}

fn security_group_rule_response(
    rule: o3k_store::SecurityGroupRuleRecord,
) -> SecurityGroupRuleResponse {
    SecurityGroupRuleResponse {
        id: rule.id.to_string(),
        project_id: rule.project_id,
        security_group_id: rule.security_group_id.to_string(),
        direction: rule.direction,
        ethertype: "IPv4",
        protocol: (rule.protocol != "any").then_some(rule.protocol),
        port_range_min: rule.port_min,
        port_range_max: rule.port_max,
        remote_ip_prefix: rule.remote_ip_prefix,
        remote_group_id: None,
    }
}

pub(crate) async fn list_security_groups(
    State(state): State<AppState>,
    headers: axum::http::HeaderMap,
) -> axum::response::Response {
    let auth = match require_auth_context(&state, &headers) {
        Ok(value) => value,
        Err(response) => return response,
    };
    let service = match network_service(&state) {
        Ok(value) => value,
        Err(response) => return response,
    };
    let project = auth.effective_scope().id().as_str();
    let groups = match service.list_security_groups_for_project(project).await {
        Ok(groups) => groups,
        Err(error) => return network_error(error),
    };
    let mut responses = Vec::with_capacity(groups.len());
    for group in groups {
        match security_group_response(service, project, group).await {
            Ok(value) => responses.push(value),
            Err(error) => return network_error(error),
        }
    }
    Json(SecurityGroupList {
        security_groups: responses,
    })
    .into_response()
}

pub(crate) async fn create_security_group(
    State(state): State<AppState>,
    headers: axum::http::HeaderMap,
    request: Result<Json<SecurityGroupRequestBody>, JsonRejection>,
) -> axum::response::Response {
    let auth = match require_auth_context(&state, &headers) {
        Ok(value) => value,
        Err(response) => return response,
    };
    let Ok(Json(body)) = request else {
        return keystone_error(
            StatusCode::BAD_REQUEST,
            "Bad Request",
            "invalid security group request",
        );
    };
    let service = match network_service(&state) {
        Ok(value) => value,
        Err(response) => return response,
    };
    let project = auth.effective_scope().id().as_str();
    if body.security_group.stateful == Some(false) {
        return network_error(NetworkError::InvalidRequest);
    }
    let Some(name) = body.security_group.name else {
        return keystone_error(
            StatusCode::BAD_REQUEST,
            "Bad Request",
            "security group name is required",
        );
    };
    match service
        .create_security_group_for_project(project, name, body.security_group.description)
        .await
    {
        Ok(group) => match security_group_response(service, project, group).await {
            Ok(value) => (
                StatusCode::CREATED,
                Json(SecurityGroupEnvelope {
                    security_group: value,
                }),
            )
                .into_response(),
            Err(error) => network_error(error),
        },
        Err(error) => network_error(error),
    }
}

pub(crate) async fn show_security_group(
    State(state): State<AppState>,
    headers: axum::http::HeaderMap,
    Path(id): Path<Uuid>,
) -> axum::response::Response {
    let auth = match require_auth_context(&state, &headers) {
        Ok(value) => value,
        Err(response) => return response,
    };
    let service = match network_service(&state) {
        Ok(value) => value,
        Err(response) => return response,
    };
    let project = auth.effective_scope().id().as_str();
    let group = match service.get_security_group_for_project(project, id).await {
        Ok(value) => value,
        Err(error) => return network_error(error),
    };
    match security_group_response(service, project, group).await {
        Ok(value) => Json(SecurityGroupEnvelope {
            security_group: value,
        })
        .into_response(),
        Err(error) => network_error(error),
    }
}

pub(crate) async fn update_security_group(
    State(state): State<AppState>,
    headers: axum::http::HeaderMap,
    Path(id): Path<Uuid>,
    request: Result<Json<SecurityGroupRequestBody>, JsonRejection>,
) -> axum::response::Response {
    let auth = match require_auth_context(&state, &headers) {
        Ok(value) => value,
        Err(response) => return response,
    };
    let Ok(Json(body)) = request else {
        return keystone_error(
            StatusCode::BAD_REQUEST,
            "Bad Request",
            "invalid security group request",
        );
    };
    let service = match network_service(&state) {
        Ok(value) => value,
        Err(response) => return response,
    };
    let project = auth.effective_scope().id().as_str();
    if body.security_group.stateful == Some(false) {
        return network_error(NetworkError::InvalidRequest);
    }
    let current = match service.get_security_group_for_project(project, id).await {
        Ok(value) => value,
        Err(error) => return network_error(error),
    };
    let group = match service
        .update_security_group_for_project(
            project,
            id,
            body.security_group.name.unwrap_or(current.name),
            body.security_group.description,
        )
        .await
    {
        Ok(value) => value,
        Err(error) => return network_error(error),
    };
    match security_group_response(service, project, group).await {
        Ok(value) => Json(SecurityGroupEnvelope {
            security_group: value,
        })
        .into_response(),
        Err(error) => network_error(error),
    }
}

pub(crate) async fn delete_security_group(
    State(state): State<AppState>,
    headers: axum::http::HeaderMap,
    Path(id): Path<Uuid>,
) -> axum::response::Response {
    let auth = match require_auth_context(&state, &headers) {
        Ok(value) => value,
        Err(response) => return response,
    };
    let service = match network_service(&state) {
        Ok(value) => value,
        Err(response) => return response,
    };
    match service
        .delete_security_group_for_project(auth.effective_scope().id().as_str(), id)
        .await
    {
        Ok(()) => StatusCode::NO_CONTENT.into_response(),
        Err(error) => network_error(error),
    }
}

pub(crate) async fn list_security_group_rules(
    State(state): State<AppState>,
    headers: axum::http::HeaderMap,
    Query(query): Query<SecurityGroupRuleQuery>,
) -> axum::response::Response {
    let auth = match require_auth_context(&state, &headers) {
        Ok(value) => value,
        Err(response) => return response,
    };
    let service = match network_service(&state) {
        Ok(value) => value,
        Err(response) => return response,
    };
    let project = auth.effective_scope().id().as_str();
    let groups = match service.list_security_groups_for_project(project).await {
        Ok(groups) => groups,
        Err(error) => return network_error(error),
    };
    let mut rules = Vec::new();
    for group in groups {
        if query.security_group_id.is_none() || query.security_group_id == Some(group.id) {
            match service
                .list_security_group_rules_for_project(project, group.id)
                .await
            {
                Ok(values) => rules.extend(values.into_iter().map(security_group_rule_response)),
                Err(error) => return network_error(error),
            }
        }
    }
    Json(SecurityGroupRuleList {
        security_group_rules: rules,
    })
    .into_response()
}

pub(crate) async fn create_security_group_rule(
    State(state): State<AppState>,
    headers: axum::http::HeaderMap,
    request: Result<Json<SecurityGroupRuleRequestBody>, JsonRejection>,
) -> axum::response::Response {
    let auth = match require_auth_context(&state, &headers) {
        Ok(value) => value,
        Err(response) => return response,
    };
    let Ok(Json(body)) = request else {
        return keystone_error(
            StatusCode::BAD_REQUEST,
            "Bad Request",
            "invalid security group rule request",
        );
    };
    let input = body.security_group_rule;
    if input
        .ethertype
        .as_deref()
        .is_some_and(|value| value != "IPv4")
        || input.remote_group_id.is_some()
    {
        return network_error(NetworkError::InvalidRequest);
    }
    let service = match network_service(&state) {
        Ok(value) => value,
        Err(response) => return response,
    };
    let project = auth.effective_scope().id().as_str();
    let rule = match service
        .create_security_group_rule_for_project(
            project,
            input.security_group_id,
            input.direction,
            input.protocol.unwrap_or_else(|| "any".to_owned()),
            input.port_range_min,
            input.port_range_max,
            input.remote_ip_prefix,
        )
        .await
    {
        Ok(value) => value,
        Err(error) => return network_error(error),
    };
    if let Err(response) =
        dispatch_security_group_endpoints(&state, project, rule.security_group_id).await
    {
        return response;
    }
    (
        StatusCode::CREATED,
        Json(SecurityGroupRuleEnvelope {
            security_group_rule: security_group_rule_response(rule),
        }),
    )
        .into_response()
}

pub(crate) async fn show_security_group_rule(
    State(state): State<AppState>,
    headers: axum::http::HeaderMap,
    Path(id): Path<Uuid>,
) -> axum::response::Response {
    let auth = match require_auth_context(&state, &headers) {
        Ok(value) => value,
        Err(response) => return response,
    };
    let service = match network_service(&state) {
        Ok(value) => value,
        Err(response) => return response,
    };
    match service
        .get_security_group_rule_for_project(auth.effective_scope().id().as_str(), id)
        .await
    {
        Ok(rule) => Json(SecurityGroupRuleEnvelope {
            security_group_rule: security_group_rule_response(rule),
        })
        .into_response(),
        Err(error) => network_error(error),
    }
}

pub(crate) async fn delete_security_group_rule(
    State(state): State<AppState>,
    headers: axum::http::HeaderMap,
    Path(id): Path<Uuid>,
) -> axum::response::Response {
    let auth = match require_auth_context(&state, &headers) {
        Ok(value) => value,
        Err(response) => return response,
    };
    let service = match network_service(&state) {
        Ok(value) => value,
        Err(response) => return response,
    };
    let project = auth.effective_scope().id().as_str();
    let rule = match service
        .get_security_group_rule_for_project(project, id)
        .await
    {
        Ok(value) => value,
        Err(error) => return network_error(error),
    };
    let deleting_rule = match service
        .begin_security_group_rule_deletion_for_project(project, id)
        .await
    {
        Ok(value) => value,
        Err(error) => return network_error(error),
    };
    if let Err(response) =
        dispatch_security_group_endpoints(&state, project, rule.security_group_id).await
    {
        return response;
    }
    if let Err(error) = service
        .finalize_security_group_rule_deletion_for_project(project, id, deleting_rule.generation)
        .await
    {
        return network_error(error);
    }
    StatusCode::NO_CONTENT.into_response()
}

async fn dispatch_security_group_endpoints(
    state: &AppState,
    project_id: &str,
    group_id: Uuid,
) -> Result<(), axum::response::Response> {
    let service = network_service(state)?;
    let bindings = service
        .list_security_group_bindings_for_project(project_id, None)
        .await
        .map_err(network_error)?;
    for binding in bindings
        .into_iter()
        .filter(|binding| binding.security_group_id == group_id)
    {
        let port = service
            .get_port_for_project(project_id, binding.endpoint_id)
            .await
            .map_err(network_error)?;
        dispatch_policy_network(state, project_id, port.network_id, port.id).await?;
    }
    Ok(())
}

pub(crate) async fn list_network_policies(
    State(state): State<AppState>,
    headers: axum::http::HeaderMap,
    Query(query): Query<NetworkPolicyQuery>,
) -> axum::response::Response {
    let auth = match require_auth_context(&state, &headers) {
        Ok(value) => value,
        Err(response) => return response,
    };
    let service = match network_service(&state) {
        Ok(value) => value,
        Err(response) => return response,
    };
    match service
        .list_policies_for_project(auth.effective_scope().id().as_str(), query.network_id)
        .await
    {
        Ok(policies) => Json(NetworkPolicyList {
            policies: policies
                .into_iter()
                .map(|policy| policy_response(query.network_id, policy))
                .collect(),
        })
        .into_response(),
        Err(error) => network_error(error),
    }
}

pub(crate) async fn create_network_policy(
    State(state): State<AppState>,
    headers: axum::http::HeaderMap,
    request: Result<Json<NetworkPolicyRequestBody>, JsonRejection>,
) -> axum::response::Response {
    let auth = match require_auth_context(&state, &headers) {
        Ok(value) => value,
        Err(response) => return response,
    };
    let Ok(Json(body)) = request else {
        return keystone_error(
            StatusCode::BAD_REQUEST,
            "Bad Request",
            "invalid policy request",
        );
    };
    let request_identity = headers
        .get("idempotency-key")
        .or_else(|| headers.get("x-openstack-request-id"))
        .and_then(|value| value.to_str().ok())
        .filter(|value| !value.trim().is_empty())
        .map(str::to_owned)
        .unwrap_or_else(|| Uuid::now_v7().to_string());
    let policy_input = body.policy;
    let policy_id = Uuid::new_v5(
        &Uuid::NAMESPACE_URL,
        format!(
            "o3k:network:policy:{}:{}:{}:{}",
            auth.effective_scope().id(),
            policy_input.network_id,
            policy_input.endpoint_id,
            request_identity
        )
        .as_bytes(),
    );
    let (network_id, policy) = match parse_policy_request(policy_input, policy_id) {
        Ok(value) => value,
        Err(()) => {
            return keystone_error(
                StatusCode::BAD_REQUEST,
                "Bad Request",
                "invalid policy shape",
            );
        }
    };
    let service = match network_service(&state) {
        Ok(value) => value,
        Err(response) => return response,
    };
    let project_id = auth.effective_scope().id().as_str();
    let endpoint_id = policy.endpoint_id;
    let policy = match service
        .upsert_policy_for_project(project_id, network_id, policy)
        .await
    {
        Ok(value) => value,
        Err(error) => return network_error(error),
    };
    if let Err(response) =
        dispatch_policy_network(&state, project_id, network_id, endpoint_id).await
    {
        return response;
    }
    (
        StatusCode::CREATED,
        Json(NetworkPolicyEnvelope {
            policy: policy_response(network_id, policy),
        }),
    )
        .into_response()
}

pub(crate) async fn show_network_policy(
    State(state): State<AppState>,
    headers: axum::http::HeaderMap,
    Path(id): Path<Uuid>,
    Query(query): Query<NetworkPolicyQuery>,
) -> axum::response::Response {
    let auth = match require_auth_context(&state, &headers) {
        Ok(value) => value,
        Err(response) => return response,
    };
    let service = match network_service(&state) {
        Ok(value) => value,
        Err(response) => return response,
    };
    match service
        .list_policies_for_project(auth.effective_scope().id().as_str(), query.network_id)
        .await
    {
        Ok(policies) => match policies.into_iter().find(|policy| policy.id == id) {
            Some(policy) => Json(NetworkPolicyEnvelope {
                policy: policy_response(query.network_id, policy),
            })
            .into_response(),
            None => network_error(o3k_network::NetworkError::NotFound),
        },
        Err(error) => network_error(error),
    }
}

pub(crate) async fn update_network_policy(
    State(state): State<AppState>,
    headers: axum::http::HeaderMap,
    Path(id): Path<Uuid>,
    request: Result<Json<NetworkPolicyRequestBody>, JsonRejection>,
) -> axum::response::Response {
    let auth = match require_auth_context(&state, &headers) {
        Ok(value) => value,
        Err(response) => return response,
    };
    let Ok(Json(body)) = request else {
        return keystone_error(
            StatusCode::BAD_REQUEST,
            "Bad Request",
            "invalid policy request",
        );
    };
    let (network_id, policy) = match parse_policy_request(body.policy, id) {
        Ok(value) => value,
        Err(()) => {
            return keystone_error(
                StatusCode::BAD_REQUEST,
                "Bad Request",
                "invalid policy shape",
            );
        }
    };
    let service = match network_service(&state) {
        Ok(value) => value,
        Err(response) => return response,
    };
    let project_id = auth.effective_scope().id().as_str();
    let endpoint_id = policy.endpoint_id;
    let policy = match service
        .upsert_policy_for_project(project_id, network_id, policy)
        .await
    {
        Ok(value) => value,
        Err(error) => return network_error(error),
    };
    if let Err(response) =
        dispatch_policy_network(&state, project_id, network_id, endpoint_id).await
    {
        return response;
    }
    Json(NetworkPolicyEnvelope {
        policy: policy_response(network_id, policy),
    })
    .into_response()
}

pub(crate) async fn delete_network_policy(
    State(state): State<AppState>,
    headers: axum::http::HeaderMap,
    Path(id): Path<Uuid>,
    Query(query): Query<NetworkPolicyQuery>,
) -> axum::response::Response {
    let auth = match require_auth_context(&state, &headers) {
        Ok(value) => value,
        Err(response) => return response,
    };
    let service = match network_service(&state) {
        Ok(value) => value,
        Err(response) => return response,
    };
    let project_id = auth.effective_scope().id().as_str();
    let endpoint_id = match service
        .list_policies_for_project(project_id, query.network_id)
        .await
    {
        Ok(policies) => match policies.into_iter().find(|policy| policy.id == id) {
            Some(policy) => policy.endpoint_id,
            None => return network_error(o3k_network::NetworkError::NotFound),
        },
        Err(error) => return network_error(error),
    };
    if let Err(error) = service
        .delete_policy_for_project(project_id, query.network_id, id)
        .await
    {
        return network_error(error);
    }
    if let Err(response) =
        dispatch_policy_network(&state, project_id, query.network_id, endpoint_id).await
    {
        return response;
    }
    StatusCode::NO_CONTENT.into_response()
}

async fn dispatch_policy_network(
    state: &AppState,
    project_id: &str,
    network_id: Uuid,
    endpoint_id: Uuid,
) -> Result<(), axum::response::Response> {
    dispatch_policy_network_with_gateway(
        state,
        project_id,
        network_id,
        endpoint_id,
        None,
        o3k_network::NetworkPlanAction::Apply,
    )
    .await
    .map(|_| ())
}

async fn remove_policy_network(
    state: &AppState,
    project_id: &str,
    network_id: Uuid,
    endpoint_id: Uuid,
) -> Result<(), axum::response::Response> {
    dispatch_policy_network_with_gateway(
        state,
        project_id,
        network_id,
        endpoint_id,
        None,
        o3k_network::NetworkPlanAction::Remove,
    )
    .await
    .map(|_| ())
}

/// Dispatches a complete endpoint plan and, when requested, the complete
/// canonical gateway plan that must be rebuilt with it. The endpoint remains
/// the scheduling/agent selection unit; an interface mutation supplies the
/// exact gateway whose complete snapshot must be rebuilt.
async fn dispatch_policy_network_with_gateway(
    state: &AppState,
    project_id: &str,
    network_id: Uuid,
    endpoint_id: Uuid,
    gateway_id: Option<Uuid>,
    action: o3k_network::NetworkPlanAction,
) -> Result<bool, axum::response::Response> {
    let Some(dispatcher) = state.network_dispatcher.as_ref() else {
        return Ok(false);
    };
    let Some(controller) = state.network_controller.as_ref() else {
        return Ok(false);
    };
    let network = network_service(state)?;
    let ports = network
        .list_ports_for_project(project_id)
        .await
        .map_err(network_error)?;
    let port = ports
        .into_iter()
        .find(|port| port.network_id == network_id && port.id == endpoint_id)
        .ok_or_else(|| network_error(o3k_network::NetworkError::NotFound))?;
    // Policy intent is durable before an endpoint is scheduled.  Leave the
    // provider projection pending until the normal binding lifecycle can
    // dispatch the complete attachment plan.
    let Some(host) = port.binding_host.clone() else {
        return Ok(false);
    };
    let agent = if let Some(registry) = state.agent_registry.as_ref()
        && let Some(agent) = registry.snapshot(&host).await
    {
        o3k_network::NetworkAgentIdentity {
            agent_id: agent.agent_id,
            agent_epoch: agent.agent_epoch,
        }
    } else if let Some(agent) = state.network_agent.as_ref()
        && agent.agent_id == host
    {
        agent.clone()
    } else {
        return Err(keystone_error(
            StatusCode::SERVICE_UNAVAILABLE,
            "Service Unavailable",
            "selected network agent is unavailable",
        ));
    };
    let subnet_id = port.subnet_id.ok_or_else(|| {
        keystone_error(
            StatusCode::BAD_REQUEST,
            "Bad Request",
            "endpoint has no fixed subnet",
        )
    })?;
    let subnet = network
        .get_subnet_for_project(project_id, subnet_id)
        .await
        .map_err(network_error)?;
    let policies = network
        .list_policies_for_project(project_id, network_id)
        .await
        .map_err(network_error)?
        .into_iter()
        .filter(|policy| policy.endpoint_id == port.id)
        .collect();
    let policy_defaults = network
        .policy_defaults_for_endpoint(project_id, port.id)
        .await
        .map_err(network_error)?;
    let network_records = network
        .list_canonical_networks_for_project(project_id)
        .await
        .map_err(network_error)?;
    let mut all_realms = Vec::new();
    for network_record in network_records {
        all_realms.extend(
            network
                .list_canonical_realms_for_project(project_id, network_record.id)
                .await
                .map_err(network_error)?,
        );
    }
    let realms = all_realms
        .iter()
        .filter(|realm| realm.network_id == network_id)
        .cloned()
        .collect::<Vec<_>>();
    let external_realm_route_id =
        select_active_external_realm_for_network(&all_realms, state.network_external_realm_id)
            .map_err(|error| {
                keystone_error(
                    StatusCode::SERVICE_UNAVAILABLE,
                    "Service Unavailable",
                    error,
                )
            })?;
    let realm = realms
        .iter()
        .find(|realm| realm.prefix == subnet.cidr)
        .or_else(|| realms.first())
        .ok_or_else(|| network_error(NetworkError::NotFound))?;
    // Host-side gateway realization is a deployment switch. When it is not
    // activated, the canonical L3Gateway execution snapshot is not compiled
    // for the plan and only the Route/Egress intents derived from the
    // canonical gateway graph flow to the routed provider path.
    let gateway_realization_enabled = state.network_gateway_realization_enabled();
    let mut gateway_routes = Vec::new();
    let mut gateway_egress = Vec::new();
    let mut gateway_execution = None;
    let realm_map = all_realms
        .iter()
        .cloned()
        .map(|realm| (realm.id, realm))
        .collect::<std::collections::BTreeMap<_, _>>();
    let gateways = if let Some(gateway_id) = gateway_id {
        vec![
            network
                .get_l3_gateway_for_project(project_id, &gateway_id)
                .await
                .map_err(network_error)?,
        ]
    } else {
        network
            .list_l3_gateways_for_project(project_id)
            .await
            .map_err(network_error)?
    };
    for gateway in gateways {
        let attachments = network
            .list_l3_gateway_attachments(project_id, &gateway.id)
            .await
            .map_err(network_error)?;
        if gateway_realization_enabled
            && (attachments
                .iter()
                .any(|attachment| attachment.realm_id == realm.id && attachment.state == "active")
                || gateway_id == Some(gateway.id))
        {
            let compiled =
                o3k_network::compile_l3_gateway_execution_plan(&gateway, &attachments, &realm_map)
                    .map_err(|error| {
                        keystone_error(StatusCode::BAD_REQUEST, "Bad Request", error.to_string())
                    })?;
            if gateway_execution.replace(compiled).is_some() {
                return Err(keystone_error(
                    StatusCode::CONFLICT,
                    "Conflict",
                    "endpoint is attached to multiple L3 gateways",
                ));
            }
        }
        if let Ok(compiled) = o3k_network::compile_l3_gateway_intents(
            &gateway,
            &attachments,
            &all_realms,
            &std::collections::BTreeMap::new(),
        ) && let Some((routes, egress)) = compiled.get(&realm.id)
        {
            if gateway_execution.is_none() {
                gateway_routes.extend(routes.iter().cloned());
            }
            gateway_egress.extend(egress.iter().cloned());
        }
    }
    // Routed egress identity is the canonical AddressRealm id of the external
    // pool network. When a Router/L3Gateway contributes egress, the flat
    // attachment egress and every gateway egress must share one canonical
    // realm id; if that realm cannot be resolved, or the gateway-referenced
    // realm differs from the resolved pool realm, fail closed rather than
    // labeling a Network id (or a divergent realm) as external_realm_id (S3).
    // A pure-flat deployment with no router keeps its flat external identity.
    let flat_routed_realm_id = external_realm_route_id;
    if !routed_egress_realm_is_coherent(
        &gateway_egress,
        flat_routed_realm_id,
        state.network_external_realm_id.is_some(),
    ) {
        return Err(keystone_error(
            StatusCode::SERVICE_UNAVAILABLE,
            "Service Unavailable",
            "external pool network has no unambiguous canonical address realm for routed egress",
        ));
    }
    let deadline_unix_ms = unix_time_millis().saturating_add(30_000);
    let operation_id = match action {
        o3k_network::NetworkPlanAction::Apply => {
            // The same endpoint plan id is intentionally reusable, but its
            // operation identity must change whenever any semantic input to
            // the plan changes. In particular, detaching a RouterInterface
            // changes gateway Route/Egress intents while the endpoint policy
            // rows remain unchanged. Reusing the old policy-only identity
            // would make the executor classify the new plan as a conflicting
            // replay and strand provider cleanup.
            let identity = serde_json::to_vec(&(
                project_id,
                network_id,
                endpoint_id,
                realm.id,
                &port.mac_address,
                port.fixed_ip,
                &subnet.cidr,
                &host,
                external_realm_route_id.or(state.network_external_realm_id),
                &policies,
                &policy_defaults,
                &gateway_execution,
                &gateway_routes,
                &gateway_egress,
                gateway_realization_enabled,
            ))
            .map_err(|_| {
                keystone_error(
                    StatusCode::BAD_REQUEST,
                    "Bad Request",
                    "policy identity serialization failed",
                )
            })?;
            Uuid::new_v5(&Uuid::NAMESPACE_URL, &identity)
        }
        o3k_network::NetworkPlanAction::Remove => Uuid::new_v5(
            &Uuid::NAMESPACE_URL,
            format!("o3k:network:policy-remove:{project_id}:{network_id}:{endpoint_id}").as_bytes(),
        ),
    };
    let plan = o3k_network::compile_attachment_plan_with_defaults(
        o3k_network::AttachmentPlanInput {
            endpoint_id: port.id,
            realm_id: realm.id,
            project_id,
            mac: &port.mac_address,
            fixed_ip: port.fixed_ip,
            subnet_cidr: &subnet.cidr,
            node_id: &host,
            operation_id,
            deadline_unix_ms,
            public_address: None,
            // The canonical egress identity is the AddressRealm id of the
            // external pool's realm, matching the gateway-intent egress
            // identity (`compile_l3_gateway_intents` uses the canonical realm
            // id). When no Router contributes egress and the pool network
            // carries no realm, keep the configured flat external identity
            // unchanged (pure-flat deployments). Routed plans fail closed
            // above rather than conflating Network and Realm identities.
            external_realm_id: external_realm_route_id.or(state.network_external_realm_id),
            policies,
        },
        policy_defaults,
    )
    .map_err(|error| keystone_error(StatusCode::BAD_REQUEST, "Bad Request", error.to_string()))?;
    let plan = finalize_gateway_realization(
        plan,
        gateway_execution,
        gateway_routes,
        gateway_egress,
        gateway_realization_enabled,
    )
    .map_err(|error| keystone_error(StatusCode::BAD_REQUEST, "Bad Request", error.to_string()))?;
    let status = dispatcher
        .dispatch(o3k_network::NetworkPlanCommand {
            command_id: Uuid::new_v5(
                &Uuid::NAMESPACE_URL,
                format!("policy:{action:?}:{operation_id}").as_bytes(),
            ),
            operation_id,
            idempotency_key: format!(
                "o3k:network:policy:{project_id}:{network_id}:{action:?}:{operation_id}"
            ),
            action,
            target: agent,
            controller: controller.clone(),
            deadline_unix_ms,
            plan,
        })
        .await
        .map_err(|error| {
            keystone_error(
                StatusCode::SERVICE_UNAVAILABLE,
                "Service Unavailable",
                error.to_string(),
            )
        })?;
    if status != o3k_network::NetworkPlanStatus::Succeeded {
        return Err(keystone_error(
            StatusCode::SERVICE_UNAVAILABLE,
            "Service Unavailable",
            "policy realization requires observation",
        ));
    }
    if matches!(action, o3k_network::NetworkPlanAction::Apply) {
        network
            .mark_network_intent_active_for_project(project_id, network_id)
            .await
            .map_err(network_error)?;
    }
    Ok(true)
}

/// Applies the canonical L3Gateway decision to a complete endpoint plan: the
/// compiled gateway execution snapshot is attached only when host-side
/// gateway realization is activated, and the routed Route/Egress intents
/// derived from the canonical gateway graph are always kept so the routed
/// provider path preserves tenant egress/routing semantics.
fn finalize_gateway_realization(
    plan: o3k_network::NodeNetworkPlan,
    gateway_execution: Option<o3k_domain::L3GatewayExecutionPlan>,
    gateway_routes: Vec<o3k_domain::GatewayIntent>,
    gateway_egress: Vec<o3k_domain::EgressIntent>,
    gateway_realization_enabled: bool,
) -> Result<o3k_network::NodeNetworkPlan, o3k_network::NetworkPlanError> {
    let plan = if gateway_realization_enabled && let Some(gateway) = gateway_execution {
        plan.with_gateway(gateway)?
    } else {
        plan
    };
    o3k_network::add_l3_gateway_routing(plan, gateway_routes, gateway_egress)
}

/// Verifies the canonical routed-egress identity invariant (S3): when a
/// Router/L3Gateway contributes Egress intents, the flat attachment egress
/// and every gateway egress must share a single canonical AddressRealm id.
/// Callers that cannot resolve such a realm must fail closed rather than
/// labeling a Network id (or a divergent realm id) as the external realm.
pub(crate) fn routed_egress_realm_is_coherent(
    gateway_egress: &[o3k_domain::EgressIntent],
    flat_routed_realm_id: Option<Uuid>,
    external_network_configured: bool,
) -> bool {
    if gateway_egress.is_empty() || !external_network_configured {
        // Pure-flat deployment: the flat external identity is the boundary's
        // own; no Router forces a canonical realm id.
        return true;
    }
    let Some(flat) = flat_routed_realm_id else {
        return false;
    };
    gateway_egress
        .iter()
        .all(|egress| egress.external_realm_id == flat)
}

/// Resolves the configured external Network to its one active canonical
/// AddressRealm. A configured Network with no active Realm, or with multiple
/// active Realms, is ambiguous and must fail closed; the Network UUID is not a
/// substitute for the routed Realm identity.
pub(crate) fn select_active_external_realm_for_network(
    realms: &[o3k_store::CanonicalAddressRealmRecord],
    external_network_id: Option<Uuid>,
) -> Result<Option<Uuid>, &'static str> {
    let Some(external_network_id) = external_network_id else {
        return Ok(None);
    };
    let active: Vec<_> = realms
        .iter()
        .filter(|realm| realm.network_id == external_network_id && realm.state == "active")
        .collect();
    match active.as_slice() {
        [realm] => Ok(Some(realm.id)),
        [] => Err("configured external network has no active canonical AddressRealm"),
        _ => Err("configured external network has multiple active canonical AddressRealms"),
    }
}

pub(crate) fn port_response(value: PortRecord, security_groups: Vec<Uuid>) -> PortResponse {
    let project_id = value.project_id.clone();
    PortResponse {
        id: value.id.to_string(),
        network_id: value.network_id.to_string(),
        project_id: project_id.clone(),
        name: value.name,
        mac_address: value.mac_address,
        fixed_ips: value
            .subnet_id
            .map(|subnet_id| FixedIpResponse {
                subnet_id: subnet_id.to_string(),
                ip_address: value.fixed_ip,
            })
            .into_iter()
            .collect(),
        status: value.status,
        security_groups: security_groups
            .into_iter()
            .map(|id| id.to_string())
            .collect(),
        tenant_id: project_id,
        admin_state_up: true,
        device_id: String::new(),
        device_owner: String::new(),
        port_security_enabled: false,
    }
}

async fn router_interface_port(
    service: &NetworkService,
    auth: &AuthContext,
    port_id: Uuid,
) -> Result<Option<PortResponse>, NetworkError> {
    let project = auth.effective_scope().id().as_str();
    for gateway in service.list_l3_gateways_for_project(project).await? {
        for attachment in service
            .list_l3_gateway_attachments(project, &gateway.id)
            .await?
        {
            if attachment.id != port_id || attachment.state != "active" {
                continue;
            }
            let realm = service
                .get_canonical_realm(auth, attachment.realm_id)
                .await?;
            let subnet_id = service
                .list_subnets_for_project(project)
                .await?
                .into_iter()
                .find(|subnet| subnet.network_id == realm.network_id && subnet.cidr == realm.prefix)
                .map(|subnet| subnet.id)
                .unwrap_or(realm.id);
            let network = realm
                .prefix
                .split_once('/')
                .and_then(|(address, _)| address.parse::<Ipv4Addr>().ok())
                .and_then(|address| u32::from(address).checked_add(1).map(Ipv4Addr::from))
                .ok_or(NetworkError::InvalidRequest)?;
            let bytes = port_id.as_bytes();
            let mac_address = format!(
                "02:{:02x}:{:02x}:{:02x}:{:02x}:{:02x}",
                bytes[0], bytes[1], bytes[2], bytes[14], bytes[15]
            );
            return Ok(Some(PortResponse {
                id: port_id.to_string(),
                network_id: realm.network_id.to_string(),
                project_id: project.to_owned(),
                name: format!("router-interface-{}", attachment.id),
                mac_address,
                fixed_ips: vec![FixedIpResponse {
                    subnet_id: subnet_id.to_string(),
                    ip_address: network,
                }],
                status: "ACTIVE".to_owned(),
                security_groups: Vec::new(),
                tenant_id: project.to_owned(),
                admin_state_up: true,
                device_id: gateway.id.to_string(),
                device_owner: "network:router_interface".to_owned(),
                port_security_enabled: false,
            }));
        }
    }
    Ok(None)
}

pub(crate) fn network_error(error: NetworkError) -> axum::response::Response {
    match error {
        NetworkError::Unauthorized => keystone_error(
            StatusCode::UNAUTHORIZED,
            "Unauthorized",
            "The request has not been authenticated.",
        ),
        NetworkError::NotFound => keystone_error(
            StatusCode::NOT_FOUND,
            "Not Found",
            "network resource was not found",
        ),
        NetworkError::Conflict | NetworkError::PoolExhausted => keystone_error(
            StatusCode::CONFLICT,
            "Conflict",
            "network operation is not allowed",
        ),
        NetworkError::InvalidRequest => keystone_error(
            StatusCode::BAD_REQUEST,
            "Bad Request",
            "invalid network request",
        ),
        NetworkError::QuotaExceeded {
            ref key,
            limit,
            used,
            requested,
        } => {
            let message = format!(
                "Quota exceeded for {key}: limit {limit}, used {used}, requested {requested}"
            );
            keystone_error(StatusCode::CONFLICT, "Conflict", message)
        }
        NetworkError::Store(_) | NetworkError::CorruptMetadata(_) => keystone_error(
            StatusCode::INTERNAL_SERVER_ERROR,
            "Internal Server Error",
            "network storage is unavailable",
        ),
        NetworkError::AuditUnavailable => keystone_error(
            StatusCode::SERVICE_UNAVAILABLE,
            "Service Unavailable",
            "audit service is unavailable",
        ),
    }
}

#[derive(serde::Deserialize)]
pub(crate) struct FloatingIpRequestBody {
    floatingip: FloatingIpRequest,
}

#[derive(serde::Deserialize)]
pub(crate) struct FloatingIpRequest {
    #[serde(default)]
    floating_network_id: Option<uuid::Uuid>,
    #[serde(default)]
    port_id: Option<uuid::Uuid>,
}

#[derive(serde::Serialize)]
pub(crate) struct FloatingIpEnvelope {
    floatingip: FloatingIpResponse,
}

#[derive(serde::Serialize)]
pub(crate) struct FloatingIpList {
    floatingips: Vec<FloatingIpResponse>,
}

#[derive(serde::Serialize)]
pub(crate) struct FloatingIpResponse {
    id: String,
    project_id: String,
    floating_network_id: Option<String>,
    floating_ip_address: Ipv4Addr,
    port_id: Option<String>,
    status: &'static str,
}

fn floating_ip_response(
    binding: PublicAddressBinding,
    floating_network_id: Option<Uuid>,
) -> FloatingIpResponse {
    FloatingIpResponse {
        id: binding.allocation_id.to_string(),
        project_id: binding.project_id,
        floating_network_id: floating_network_id.map(|id| id.to_string()),
        floating_ip_address: binding.public_address,
        port_id: binding.endpoint_id.map(|id| id.to_string()),
        // Allocation/association is control-plane state only. Host realization
        // is a separate execution operation, so this projection must not claim
        // ACTIVE before an agent observation exists.
        status: "DOWN",
    }
}

fn unix_time_millis() -> u64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map_or(0, |duration| duration.as_millis() as u64)
}

fn public_error(error: PublicAddressError) -> axum::response::Response {
    let (status, title) = match error {
        PublicAddressError::NotFound => (StatusCode::NOT_FOUND, "Not Found"),
        PublicAddressError::NotOwner => (StatusCode::NOT_FOUND, "Not Found"),
        PublicAddressError::AssociationConflict
        | PublicAddressError::InUse
        | PublicAddressError::Exhausted => (StatusCode::CONFLICT, "Conflict"),
        PublicAddressError::InvalidPool
        | PublicAddressError::MissingEndpoint
        | PublicAddressError::MissingRealm => (StatusCode::BAD_REQUEST, "Bad Request"),
        PublicAddressError::CorruptState
        | PublicAddressError::Storage(_)
        | PublicAddressError::ForeignProviderState
        | PublicAddressError::ProviderCommandFailed => {
            (StatusCode::INTERNAL_SERVER_ERROR, "Internal Server Error")
        }
    };
    keystone_error(status, title, "floating IP operation failed")
}

#[allow(clippy::result_large_err)]
fn public_allocator(
    state: &AppState,
) -> Result<&Arc<PublicAddressAllocator>, axum::response::Response> {
    state.public_allocator.as_ref().ok_or_else(|| {
        keystone_error(
            StatusCode::SERVICE_UNAVAILABLE,
            "Service Unavailable",
            "floating IP service is not configured",
        )
    })
}

async fn dispatch_public_binding(
    state: &AppState,
    binding: &PublicAddressBinding,
    action: o3k_network::NetworkPlanAction,
) -> Result<(), axum::response::Response> {
    let Some(dispatcher) = state.network_dispatcher.as_ref() else {
        return Ok(());
    };
    let Some(controller) = state.network_controller.as_ref() else {
        return Ok(());
    };
    let Some(endpoint_id) = binding.endpoint_id else {
        return Ok(());
    };
    let network = network_service(state)?;
    let port = network
        .get_port_for_project(&binding.project_id, endpoint_id)
        .await
        .map_err(network_error)?;
    let Some(host) = port.binding_host.as_deref() else {
        return Ok(());
    };
    let agent = if let Some(registry) = state.agent_registry.as_ref()
        && let Some(agent) = registry.snapshot(host).await
    {
        o3k_network::NetworkAgentIdentity {
            agent_id: agent.agent_id,
            agent_epoch: agent.agent_epoch,
        }
    } else if let Some(agent) = state.network_agent.as_ref()
        && agent.agent_id == host
    {
        agent.clone()
    } else {
        return Err(keystone_error(
            StatusCode::SERVICE_UNAVAILABLE,
            "Service Unavailable",
            "selected network agent is unavailable",
        ));
    };
    let subnet_id = port.subnet_id.ok_or_else(|| {
        keystone_error(
            StatusCode::BAD_REQUEST,
            "Bad Request",
            "endpoint has no fixed subnet",
        )
    })?;
    let subnet = network
        .get_subnet_for_project(&binding.project_id, subnet_id)
        .await
        .map_err(network_error)?;
    let policies = network
        .list_policies_for_project(&binding.project_id, port.network_id)
        .await
        .map_err(network_error)?
        .into_iter()
        .filter(|policy| policy.endpoint_id == port.id)
        .collect();
    let policy_defaults = network
        .policy_defaults_for_endpoint(&binding.project_id, port.id)
        .await
        .map_err(network_error)?;
    let deadline_unix_ms = unix_time_millis().saturating_add(30_000);
    let operation_id = Uuid::new_v5(
        &Uuid::NAMESPACE_URL,
        format!(
            "o3k:network:public:{}:{}:{:?}",
            binding.allocation_id, binding.generation, action
        )
        .as_bytes(),
    );
    let plan = o3k_network::compile_attachment_plan_with_defaults(
        o3k_network::AttachmentPlanInput {
            endpoint_id,
            realm_id: port.network_id,
            project_id: &binding.project_id,
            mac: &port.mac_address,
            fixed_ip: port.fixed_ip,
            subnet_cidr: &subnet.cidr,
            node_id: host,
            operation_id,
            deadline_unix_ms,
            public_address: Some(binding.public_address),
            external_realm_id: state.network_external_realm_id,
            policies,
        },
        policy_defaults,
    )
    .map_err(|error| keystone_error(StatusCode::BAD_REQUEST, "Bad Request", error.to_string()))?;
    let command_id = Uuid::new_v5(
        &Uuid::NAMESPACE_URL,
        format!("o3k:network:public-command:{operation_id}").as_bytes(),
    );
    let status = dispatcher
        .dispatch(o3k_network::NetworkPlanCommand {
            command_id,
            operation_id,
            idempotency_key: format!(
                "o3k:network:public:{}:{}:{:?}",
                binding.allocation_id, binding.generation, action
            ),
            action,
            target: o3k_network::NetworkAgentIdentity {
                agent_id: agent.agent_id,
                agent_epoch: agent.agent_epoch,
            },
            controller: controller.clone(),
            deadline_unix_ms,
            plan,
        })
        .await
        .map_err(|error| {
            keystone_error(
                StatusCode::SERVICE_UNAVAILABLE,
                "Service Unavailable",
                error.to_string(),
            )
        })?;
    if status != o3k_network::NetworkPlanStatus::Succeeded {
        return Err(keystone_error(
            StatusCode::SERVICE_UNAVAILABLE,
            "Service Unavailable",
            "public address realization requires observation",
        ));
    }
    Ok(())
}

pub(crate) async fn list_floating_ips(
    State(state): State<AppState>,
    headers: axum::http::HeaderMap,
) -> axum::response::Response {
    let auth = match require_auth_context(&state, &headers) {
        Ok(value) => value,
        Err(response) => return response,
    };
    let allocator = match public_allocator(&state) {
        Ok(value) => value,
        Err(response) => return response,
    };
    match allocator.list(auth.effective_scope().id().as_str()) {
        Ok(values) => Json(FloatingIpList {
            floatingips: values
                .into_iter()
                .map(|value| floating_ip_response(value, state.network_external_realm_id))
                .collect(),
        })
        .into_response(),
        Err(error) => public_error(error),
    }
}

pub(crate) async fn create_floating_ip(
    State(state): State<AppState>,
    headers: axum::http::HeaderMap,
    request: Result<Json<FloatingIpRequestBody>, JsonRejection>,
) -> axum::response::Response {
    let auth = match require_auth_context(&state, &headers) {
        Ok(value) => value,
        Err(response) => return response,
    };
    // Serialize Floating IP allocation/realization with endpoint and router
    // mutations.  The provider snapshot includes the endpoint identity; an
    // unlocked concurrent port delete can otherwise let a stale public Apply
    // recreate nftables after the Floating IP has been removed.
    let _mutation_guard = state.network_mutation_lock.lock().await;
    let allocator = match public_allocator(&state) {
        Ok(value) => value,
        Err(response) => return response,
    };
    let Ok(Json(body)) = request else {
        return keystone_error(
            StatusCode::BAD_REQUEST,
            "Bad Request",
            "invalid floating IP request",
        );
    };
    let Some(external_realm_id) = state.network_external_realm_id else {
        return keystone_error(
            StatusCode::SERVICE_UNAVAILABLE,
            "Service Unavailable",
            "floating IP external network is not configured",
        );
    };
    if body.floatingip.floating_network_id != Some(external_realm_id) {
        return public_error(PublicAddressError::InvalidPool);
    }
    let operation_id = headers
        .get("x-openstack-request-id")
        .and_then(|value| value.to_str().ok())
        .filter(|value| !value.trim().is_empty())
        .map(str::to_owned)
        .unwrap_or_else(|| Uuid::now_v7().to_string());
    let project_id = auth.effective_scope().id().as_str();
    let endpoint = if let Some(port_id) = body.floatingip.port_id {
        let service = match network_service(&state) {
            Ok(value) => value,
            Err(response) => return response,
        };
        match service.get_port_for_project(project_id, port_id).await {
            Ok(value) => Some(value),
            Err(_) => return public_error(PublicAddressError::MissingEndpoint),
        }
    } else {
        None
    };
    let mut binding = match allocator.allocate(project_id, &operation_id) {
        Ok(value) => value,
        Err(error) => return public_error(error),
    };
    if let Some(port) = endpoint {
        let port_id = port.id;
        binding = match allocator.associate(project_id, binding.allocation_id, port_id) {
            Ok(value) => value,
            Err(error) => return public_error(error),
        };
        if let Err(response) =
            dispatch_public_binding(&state, &binding, o3k_network::NetworkPlanAction::Apply).await
        {
            return response;
        }
    }
    (
        StatusCode::CREATED,
        Json(FloatingIpEnvelope {
            floatingip: floating_ip_response(binding, state.network_external_realm_id),
        }),
    )
        .into_response()
}

pub(crate) async fn show_floating_ip(
    State(state): State<AppState>,
    headers: axum::http::HeaderMap,
    Path(id): Path<uuid::Uuid>,
) -> axum::response::Response {
    let auth = match require_auth_context(&state, &headers) {
        Ok(value) => value,
        Err(response) => return response,
    };
    let allocator = match public_allocator(&state) {
        Ok(value) => value,
        Err(response) => return response,
    };
    match allocator.get(auth.effective_scope().id().as_str(), id) {
        Ok(value) => Json(FloatingIpEnvelope {
            floatingip: floating_ip_response(value, state.network_external_realm_id),
        })
        .into_response(),
        Err(error) => public_error(error),
    }
}

pub(crate) async fn update_floating_ip(
    State(state): State<AppState>,
    headers: axum::http::HeaderMap,
    Path(id): Path<uuid::Uuid>,
    request: Result<Json<FloatingIpRequestBody>, JsonRejection>,
) -> axum::response::Response {
    let auth = match require_auth_context(&state, &headers) {
        Ok(value) => value,
        Err(response) => return response,
    };
    // Keep the canonical association change and its derived provider plan in
    // the same mutation epoch as endpoint deletion.
    let _mutation_guard = state.network_mutation_lock.lock().await;
    let allocator = match public_allocator(&state) {
        Ok(value) => value,
        Err(response) => return response,
    };
    let Ok(Json(body)) = request else {
        return keystone_error(
            StatusCode::BAD_REQUEST,
            "Bad Request",
            "invalid floating IP request",
        );
    };
    let project_id = auth.effective_scope().id().as_str();
    let result = match body.floatingip.port_id {
        Some(port_id) => {
            let service = match network_service(&state) {
                Ok(value) => value,
                Err(response) => return response,
            };
            if service
                .get_port_for_project(project_id, port_id)
                .await
                .is_err()
            {
                return public_error(PublicAddressError::MissingEndpoint);
            }
            let binding = match allocator.associate(project_id, id, port_id) {
                Ok(value) => value,
                Err(error) => return public_error(error),
            };
            if let Err(response) =
                dispatch_public_binding(&state, &binding, o3k_network::NetworkPlanAction::Apply)
                    .await
            {
                return response;
            }
            Ok(binding)
        }
        None => {
            let binding = match allocator.get(project_id, id) {
                Ok(value) => value,
                Err(error) => return public_error(error),
            };
            if let Err(response) =
                dispatch_public_binding(&state, &binding, o3k_network::NetworkPlanAction::Remove)
                    .await
            {
                return response;
            }
            allocator.disassociate(project_id, id)
        }
    };
    match result {
        Ok(value) => Json(FloatingIpEnvelope {
            floatingip: floating_ip_response(value, state.network_external_realm_id),
        })
        .into_response(),
        Err(error) => public_error(error),
    }
}

pub(crate) async fn delete_floating_ip(
    State(state): State<AppState>,
    headers: axum::http::HeaderMap,
    Path(id): Path<uuid::Uuid>,
) -> axum::response::Response {
    let auth = match require_auth_context(&state, &headers) {
        Ok(value) => value,
        Err(response) => return response,
    };
    // Hold the fence through provider removal and canonical release so a
    // concurrent endpoint mutation cannot recreate the public binding after
    // this delete has completed.
    let _mutation_guard = state.network_mutation_lock.lock().await;
    let allocator = match public_allocator(&state) {
        Ok(value) => value,
        Err(response) => return response,
    };
    let project_id = auth.effective_scope().id().as_str();
    let binding = match allocator.get(project_id, id) {
        Ok(value) => value,
        Err(error) => return public_error(error),
    };
    if let Err(response) =
        dispatch_public_binding(&state, &binding, o3k_network::NetworkPlanAction::Remove).await
    {
        return response;
    }
    // Neutron-compatible clients delete an associated floating IP directly.
    // Remove host realization first, then clear canonical association before
    // releasing the allocation.
    if let Err(error) = allocator.disassociate(project_id, id) {
        return public_error(error);
    }
    match allocator.release(project_id, id) {
        Ok(()) => StatusCode::NO_CONTENT.into_response(),
        Err(error) => public_error(error),
    }
}

#[allow(clippy::result_large_err)]
pub(crate) fn network_service(
    state: &AppState,
) -> Result<&Arc<NetworkService>, axum::response::Response> {
    state.network.as_ref().ok_or_else(|| {
        keystone_error(
            StatusCode::SERVICE_UNAVAILABLE,
            "Service Unavailable",
            "network service is not configured",
        )
    })
}

pub(crate) async fn list_extensions(
    State(state): State<AppState>,
    headers: axum::http::HeaderMap,
) -> axum::response::Response {
    if let Err(response) = require_auth_context(&state, &headers) {
        return response;
    }
    if let Err(response) = network_service(&state) {
        return response;
    }
    Json(serde_json::json!({"extensions": []})).into_response()
}

pub(crate) async fn create_network(
    State(state): State<AppState>,
    headers: axum::http::HeaderMap,
    request: Result<Json<NetworkRequestBody>, JsonRejection>,
) -> axum::response::Response {
    let auth = match require_auth_context(&state, &headers) {
        Ok(value) => value,
        Err(response) => return response,
    };
    let service = match network_service(&state) {
        Ok(value) => value,
        Err(response) => return response,
    };
    let Ok(Json(body)) = request else {
        return keystone_error(
            StatusCode::BAD_REQUEST,
            "Bad Request",
            "invalid network request",
        );
    };
    match service.create_network(&auth, body.network.name).await {
        Ok(value) => match canonical_network_response(service, value).await {
            Ok(network) => (StatusCode::CREATED, Json(NetworkEnvelope { network })).into_response(),
            Err(error) => network_error(error),
        },
        Err(error) => network_error(error),
    }
}

pub(crate) async fn list_networks(
    State(state): State<AppState>,
    headers: axum::http::HeaderMap,
    Query(query): Query<NetworkQuery>,
    request_uri: axum::http::Uri,
) -> axum::response::Response {
    let auth = match require_auth_context(&state, &headers) {
        Ok(value) => value,
        Err(response) => return response,
    };
    let service = match network_service(&state) {
        Ok(value) => value,
        Err(response) => return response,
    };
    let page = match CollectionPage::parse(query.limit.as_deref(), query.marker.as_deref()) {
        Ok(value) => value,
        Err(response) => return response,
    };
    match service.list_networks(&auth).await {
        Ok(mut values) => {
            values.retain(|value| query.id.is_none_or(|id| id == value.id));
            let links = page.apply(&mut values, |value| value.id, &request_uri);
            let mut networks = Vec::with_capacity(values.len());
            for value in values {
                match canonical_network_response(service, value).await {
                    Ok(network) => networks.push(network),
                    Err(error) => return network_error(error),
                }
            }
            Json(NetworkList {
                networks,
                networks_links: links,
            })
            .into_response()
        }
        Err(error) => network_error(error),
    }
}

pub(crate) async fn show_network(
    State(state): State<AppState>,
    headers: axum::http::HeaderMap,
    Path(id): Path<uuid::Uuid>,
) -> axum::response::Response {
    let auth = match require_auth_context(&state, &headers) {
        Ok(value) => value,
        Err(response) => return response,
    };
    let service = match network_service(&state) {
        Ok(value) => value,
        Err(response) => return response,
    };
    match service.get_network(&auth, id).await {
        Ok(value) => match canonical_network_response(service, value).await {
            Ok(network) => Json(NetworkEnvelope { network }).into_response(),
            Err(error) => network_error(error),
        },
        Err(error) => network_error(error),
    }
}

pub(crate) async fn update_network(
    State(state): State<AppState>,
    headers: axum::http::HeaderMap,
    Path(id): Path<uuid::Uuid>,
    request: Result<Json<UpdateNetworkRequestBody>, JsonRejection>,
) -> axum::response::Response {
    let auth = match require_auth_context(&state, &headers) {
        Ok(value) => value,
        Err(response) => return response,
    };
    let Ok(Json(body)) = request else {
        return keystone_error(
            StatusCode::BAD_REQUEST,
            "Bad Request",
            "invalid network request",
        );
    };
    let service = match network_service(&state) {
        Ok(value) => value,
        Err(response) => return response,
    };
    match service
        .update_network(&auth, id, body.network.name, body.network.admin_state_up)
        .await
    {
        Ok(value) => match canonical_network_response(service, value).await {
            Ok(network) => Json(NetworkEnvelope { network }).into_response(),
            Err(error) => network_error(error),
        },
        Err(error) => network_error(error),
    }
}

pub(crate) async fn delete_network(
    State(state): State<AppState>,
    headers: axum::http::HeaderMap,
    Path(id): Path<uuid::Uuid>,
) -> axum::response::Response {
    let auth = match require_auth_context(&state, &headers) {
        Ok(value) => value,
        Err(response) => return response,
    };
    let service = match network_service(&state) {
        Ok(value) => value,
        Err(response) => return response,
    };
    match service.delete_network(&auth, id).await {
        Ok(()) => StatusCode::NO_CONTENT.into_response(),
        Err(error) => network_error(error),
    }
}

pub(crate) async fn create_subnet(
    State(state): State<AppState>,
    headers: axum::http::HeaderMap,
    request: Result<Json<SubnetRequestBody>, JsonRejection>,
) -> axum::response::Response {
    let auth = match require_auth_context(&state, &headers) {
        Ok(value) => value,
        Err(response) => return response,
    };
    let service = match network_service(&state) {
        Ok(value) => value,
        Err(response) => return response,
    };
    let Ok(Json(body)) = request else {
        return keystone_error(
            StatusCode::BAD_REQUEST,
            "Bad Request",
            "invalid subnet request",
        );
    };
    if body
        .subnet
        .allocation_pools
        .as_ref()
        .is_some_and(|values| !values.is_empty())
    {
        return keystone_error(
            StatusCode::BAD_REQUEST,
            "Bad Request",
            "custom allocation pools are deferred by this profile",
        );
    }
    if body.subnet.ip_version.is_some_and(|value| value != 4) {
        return keystone_error(
            StatusCode::BAD_REQUEST,
            "Bad Request",
            "only IPv4 subnets are supported by this profile",
        );
    }
    let requested_dhcp = body.subnet.enable_dhcp;
    match service
        .create_subnet(
            &auth,
            body.subnet.network_id,
            body.subnet.name.unwrap_or_default(),
            body.subnet.cidr,
            body.subnet.gateway_ip,
            None,
            None,
        )
        .await
    {
        Ok(value) => {
            let value = if requested_dhcp.is_some() {
                match service
                    .update_subnet(
                        &auth,
                        value.id,
                        None,
                        None,
                        requested_dhcp,
                        None,
                        None,
                        None,
                    )
                    .await
                {
                    Ok(updated) => updated,
                    Err(error) => return network_error(error),
                }
            } else {
                value
            };
            (
                StatusCode::CREATED,
                Json(SubnetEnvelope {
                    subnet: subnet_response(value),
                }),
            )
                .into_response()
        }
        Err(error) => network_error(error),
    }
}

pub(crate) async fn update_subnet(
    State(state): State<AppState>,
    headers: axum::http::HeaderMap,
    Path(id): Path<uuid::Uuid>,
    request: Result<Json<UpdateSubnetRequestBody>, JsonRejection>,
) -> axum::response::Response {
    let auth = match require_auth_context(&state, &headers) {
        Ok(value) => value,
        Err(response) => return response,
    };
    let service = match network_service(&state) {
        Ok(value) => value,
        Err(response) => return response,
    };
    let Ok(Json(body)) = request else {
        return keystone_error(
            StatusCode::BAD_REQUEST,
            "Bad Request",
            "invalid subnet request",
        );
    };
    match service
        .update_subnet(
            &auth,
            id,
            body.subnet.name,
            body.subnet.gateway_ip,
            body.subnet.enable_dhcp,
            body.subnet.network_id,
            body.subnet.cidr,
            body.subnet.ip_version,
        )
        .await
    {
        Ok(value) => Json(SubnetEnvelope {
            subnet: subnet_response(value),
        })
        .into_response(),
        Err(error) => network_error(error),
    }
}

pub(crate) async fn list_subnets(
    State(state): State<AppState>,
    headers: axum::http::HeaderMap,
) -> axum::response::Response {
    let auth = match require_auth_context(&state, &headers) {
        Ok(value) => value,
        Err(response) => return response,
    };
    let service = match network_service(&state) {
        Ok(value) => value,
        Err(response) => return response,
    };
    match service.list_subnets(&auth).await {
        Ok(values) => Json(SubnetList {
            subnets: values.into_iter().map(subnet_response).collect(),
        })
        .into_response(),
        Err(error) => network_error(error),
    }
}

pub(crate) async fn show_subnet(
    State(state): State<AppState>,
    headers: axum::http::HeaderMap,
    Path(id): Path<uuid::Uuid>,
) -> axum::response::Response {
    let auth = match require_auth_context(&state, &headers) {
        Ok(value) => value,
        Err(response) => return response,
    };
    let service = match network_service(&state) {
        Ok(value) => value,
        Err(response) => return response,
    };
    match service.get_subnet(&auth, id).await {
        Ok(value) => Json(SubnetEnvelope {
            subnet: subnet_response(value),
        })
        .into_response(),
        Err(error) => network_error(error),
    }
}

pub(crate) async fn delete_subnet(
    State(state): State<AppState>,
    headers: axum::http::HeaderMap,
    Path(id): Path<uuid::Uuid>,
) -> axum::response::Response {
    let auth = match require_auth_context(&state, &headers) {
        Ok(value) => value,
        Err(response) => return response,
    };
    let service = match network_service(&state) {
        Ok(value) => value,
        Err(response) => return response,
    };
    match service.delete_subnet(&auth, id).await {
        Ok(()) => StatusCode::NO_CONTENT.into_response(),
        Err(error) => network_error(error),
    }
}

pub(crate) async fn create_port(
    State(state): State<AppState>,
    headers: axum::http::HeaderMap,
    request: Result<Json<PortRequestBody>, JsonRejection>,
) -> axum::response::Response {
    let auth = match require_auth_context(&state, &headers) {
        Ok(value) => value,
        Err(response) => return response,
    };
    let service = match network_service(&state) {
        Ok(value) => value,
        Err(response) => return response,
    };
    let Ok(Json(body)) = request else {
        return keystone_error(
            StatusCode::BAD_REQUEST,
            "Bad Request",
            "invalid port request",
        );
    };
    if body.port.no_fixed_ip || body.port.fixed_ips.len() > 1 {
        return keystone_error(
            StatusCode::BAD_REQUEST,
            "Bad Request",
            "this profile requires one canonical fixed IP",
        );
    }
    let fixed_ip = body
        .port
        .fixed_ips
        .into_iter()
        .next()
        .map(|value| (value.subnet_id, value.ip_address));
    let project = auth.effective_scope().id().as_str();
    let security_groups = body.port.security_groups;
    // Validate every requested security group belongs to the caller's project
    // BEFORE the port is created. A foreign or unknown group must not leave a
    // partially created port behind (fail-closed, non-disclosing 404).
    for group_id in &security_groups {
        if let Err(error) = service
            .get_security_group_for_project(project, *group_id)
            .await
        {
            return network_error(error);
        }
    }
    match service
        .create_port_with_fixed_ip(
            &auth,
            body.port.network_id,
            body.port.name.unwrap_or_default(),
            fixed_ip,
        )
        .await
    {
        Ok(value) => {
            if let Err(error) = service
                .replace_security_group_bindings_for_project(
                    auth.effective_scope().id().as_str(),
                    value.id,
                    security_groups.clone(),
                )
                .await
            {
                return network_error(error);
            }
            if !security_groups.is_empty()
                && let Err(response) =
                    dispatch_security_group_endpoints(&state, project, security_groups[0]).await
            {
                return response;
            }
            (
                StatusCode::CREATED,
                Json(PortEnvelope {
                    port: port_response(value, security_groups),
                }),
            )
                .into_response()
        }
        Err(error) => network_error(error),
    }
}

pub(crate) async fn list_ports(
    State(state): State<AppState>,
    headers: axum::http::HeaderMap,
) -> axum::response::Response {
    let auth = match require_auth_context(&state, &headers) {
        Ok(value) => value,
        Err(response) => return response,
    };
    let service = match network_service(&state) {
        Ok(value) => value,
        Err(response) => return response,
    };
    match service.list_ports(&auth).await {
        Ok(values) => {
            let mut ports = Vec::with_capacity(values.len());
            for value in values {
                let groups = service
                    .list_security_group_bindings_for_project(
                        auth.effective_scope().id().as_str(),
                        Some(value.id),
                    )
                    .await
                    .map_err(network_error);
                let groups = match groups {
                    Ok(bindings) => bindings
                        .into_iter()
                        .map(|binding| binding.security_group_id)
                        .collect(),
                    Err(response) => return response,
                };
                ports.push(port_response(value, groups));
            }
            Json(PortList { ports }).into_response()
        }
        Err(error) => network_error(error),
    }
}

pub(crate) async fn show_port(
    State(state): State<AppState>,
    headers: axum::http::HeaderMap,
    Path(id): Path<uuid::Uuid>,
) -> axum::response::Response {
    let auth = match require_auth_context(&state, &headers) {
        Ok(value) => value,
        Err(response) => return response,
    };
    let service = match network_service(&state) {
        Ok(value) => value,
        Err(response) => return response,
    };
    match service.get_port(&auth, id).await {
        Ok(value) => {
            let groups = match service
                .list_security_group_bindings_for_project(
                    auth.effective_scope().id().as_str(),
                    Some(value.id),
                )
                .await
            {
                Ok(bindings) => bindings
                    .into_iter()
                    .map(|binding| binding.security_group_id)
                    .collect(),
                Err(error) => return network_error(error),
            };
            Json(PortEnvelope {
                port: port_response(value, groups),
            })
            .into_response()
        }
        Err(NetworkError::NotFound) => match router_interface_port(service, &auth, id).await {
            Ok(Some(port)) => Json(PortEnvelope { port }).into_response(),
            Ok(None) => network_error(NetworkError::NotFound),
            Err(error) => network_error(error),
        },
        Err(error) => network_error(error),
    }
}

pub(crate) async fn update_port(
    State(state): State<AppState>,
    headers: axum::http::HeaderMap,
    Path(id): Path<uuid::Uuid>,
    request: Result<Json<UpdatePortRequestBody>, JsonRejection>,
) -> axum::response::Response {
    let auth = match require_auth_context(&state, &headers) {
        Ok(value) => value,
        Err(response) => return response,
    };
    let Ok(Json(body)) = request else {
        return keystone_error(
            StatusCode::BAD_REQUEST,
            "Bad Request",
            "invalid port request",
        );
    };
    let service = match network_service(&state) {
        Ok(value) => value,
        Err(response) => return response,
    };
    let project = auth.effective_scope().id().as_str();
    if let Err(error) = service.get_port_for_project(project, id).await {
        return network_error(error);
    }
    let security_groups = body.port.security_groups;
    if let Some(name) = body.port.name
        && let Err(error) = service
            .update_port_name_for_project(project, id, name)
            .await
    {
        return network_error(error);
    }
    let removed_attachments = match service
        .replace_security_group_bindings_for_project(project, id, security_groups.clone())
        .await
    {
        Ok(value) => value,
        Err(error) => return network_error(error),
    };
    let port = match service.get_port_for_project(project, id).await {
        Ok(value) => value,
        Err(error) => return network_error(error),
    };
    if let Err(response) = dispatch_policy_network(&state, project, port.network_id, id).await {
        return response;
    }
    for attachment in removed_attachments {
        if let Err(error) = service
            .finalize_policy_attachment_deletion_for_project(
                project,
                attachment.id,
                attachment.generation,
            )
            .await
        {
            return network_error(error);
        }
    }
    match service.get_port_for_project(project, id).await {
        Ok(value) => Json(PortEnvelope {
            port: port_response(value, security_groups),
        })
        .into_response(),
        Err(error) => network_error(error),
    }
}

pub(crate) async fn delete_port(
    State(state): State<AppState>,
    headers: axum::http::HeaderMap,
    Path(id): Path<uuid::Uuid>,
) -> axum::response::Response {
    let auth = match require_auth_context(&state, &headers) {
        Ok(value) => value,
        Err(response) => return response,
    };
    let service = match network_service(&state) {
        Ok(value) => value,
        Err(response) => return response,
    };
    // Serialize endpoint removal with RouterInterface-derived policy plans;
    // otherwise a stale concurrent Apply can follow this endpoint's Remove.
    let _mutation_guard = state.network_mutation_lock.lock().await;
    let project = auth.effective_scope().id().as_str();
    let port = match service.authorize_delete_port(&auth, id).await {
        Ok(value) => value,
        Err(error) => return network_error(error),
    };
    // Terraform may destroy an associated port before issuing the Floating IP
    // delete.  Remove the derived public realization while the endpoint
    // snapshot is still available; otherwise the provider cannot compile a
    // removal plan after the port has disappeared.
    if let Some(allocator) = state.public_allocator.as_ref() {
        let project = auth.effective_scope().id().as_str();
        let bindings = match allocator.list(project) {
            Ok(values) => values
                .into_iter()
                .filter(|binding| binding.endpoint_id == Some(id))
                .collect::<Vec<_>>(),
            Err(error) => return public_error(error),
        };
        for binding in bindings {
            if let Err(response) =
                dispatch_public_binding(&state, &binding, o3k_network::NetworkPlanAction::Remove)
                    .await
            {
                return response;
            }
            if let Err(error) = allocator.disassociate(project, binding.allocation_id) {
                return public_error(error);
            }
        }
    }
    if let Err(response) = remove_policy_network(&state, project, port.network_id, port.id).await {
        return response;
    }
    match service.delete_port(&auth, id).await {
        Ok(()) => StatusCode::NO_CONTENT.into_response(),
        Err(error) => network_error(error),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::AppState;
    use o3k_domain::{
        EgressIntent, GatewayIntent, Ipv4Prefix, L3GatewayExecutionAttachment,
        L3GatewayExecutionPlan, NetworkPlanIntent,
    };
    use o3k_network::{AttachmentPlanInput, compile_attachment_plan};
    use std::net::Ipv4Addr;

    const TEST_PROJECT: &str = "project-a";
    const TEST_NODE: &str = "compute-1";
    const TEST_REALM_PREFIX: &str = "10.0.0.0/24";

    fn endpoint_plan(realm_id: Uuid) -> Result<o3k_network::NodeNetworkPlan, String> {
        compile_attachment_plan(AttachmentPlanInput {
            endpoint_id: Uuid::now_v7(),
            realm_id,
            project_id: TEST_PROJECT,
            mac: "02:00:00:00:00:01",
            fixed_ip: Ipv4Addr::new(10, 0, 0, 10),
            subnet_cidr: TEST_REALM_PREFIX,
            node_id: TEST_NODE,
            operation_id: Uuid::now_v7(),
            deadline_unix_ms: 1,
            public_address: None,
            external_realm_id: None,
            policies: Vec::new(),
        })
        .map_err(|error| error.to_string())
    }

    fn realm_prefix() -> Result<Ipv4Prefix, String> {
        Ipv4Prefix::new(Ipv4Addr::new(10, 0, 0, 0), 24)
            .ok_or_else(|| "invalid realm prefix".to_owned())
    }

    fn gateway_execution_plan(realm_id: Uuid) -> Result<L3GatewayExecutionPlan, String> {
        Ok(L3GatewayExecutionPlan {
            gateway_id: Uuid::now_v7(),
            project_id: TEST_PROJECT.to_owned(),
            gateway_generation: 1,
            attachments: vec![L3GatewayExecutionAttachment {
                attachment_id: Uuid::now_v7(),
                attachment_generation: 1,
                realm_id,
                realm_generation: 1,
                realm_prefix: realm_prefix()?,
                gateway_address: Ipv4Addr::new(10, 0, 0, 1),
            }],
            external_realm_id: Some(Uuid::now_v7()),
            external_realm_prefix: Some(
                Ipv4Prefix::new(Ipv4Addr::new(198, 51, 100, 0), 24)
                    .ok_or_else(|| "invalid external prefix".to_owned())?,
            ),
            external_realm_generation: Some(1),
            enable_snat: true,
        })
    }

    fn gateway_routes() -> Result<Vec<GatewayIntent>, String> {
        Ok(vec![GatewayIntent {
            destination: Ipv4Prefix::new(Ipv4Addr::new(10, 1, 0, 0), 24)
                .ok_or_else(|| "invalid route destination prefix".to_owned())?,
            gateway: Ipv4Addr::new(10, 0, 0, 1),
            external: true,
        }])
    }

    fn gateway_egress(external_realm_id: Uuid) -> Vec<EgressIntent> {
        vec![EgressIntent {
            external_realm_id,
            enabled: true,
            nat: true,
        }]
    }

    fn has_routed_intents(plan: &o3k_network::NodeNetworkPlan) -> bool {
        plan.intents
            .iter()
            .any(|intent| matches!(intent, NetworkPlanIntent::Gateway(_)))
            && plan
                .intents
                .iter()
                .any(|intent| matches!(intent, NetworkPlanIntent::Egress(_)))
    }

    #[test]
    fn gateway_realization_enabled_attaches_snapshot_and_keeps_routed_intents()
    -> Result<(), Box<dyn std::error::Error>> {
        let realm_id = Uuid::now_v7();
        let gateway = gateway_execution_plan(realm_id)?;
        let external_realm_id = gateway
            .external_realm_id
            .ok_or_else(|| "missing external realm".to_owned())?;
        let realized = finalize_gateway_realization(
            endpoint_plan(realm_id)?,
            Some(gateway.clone()),
            gateway_routes()?,
            gateway_egress(external_realm_id),
            true,
        )
        .map_err(|error| error.to_string())?;
        assert_eq!(realized.gateway.as_ref(), Some(&gateway));
        assert!(has_routed_intents(&realized));
        Ok(())
    }

    #[test]
    fn gateway_realization_disabled_keeps_routed_intents_without_gateway_snapshot()
    -> Result<(), Box<dyn std::error::Error>> {
        let realm_id = Uuid::now_v7();
        let gateway = gateway_execution_plan(realm_id)?;
        let external_realm_id = gateway
            .external_realm_id
            .ok_or_else(|| "missing external realm".to_owned())?;
        let plan = endpoint_plan(realm_id)?;
        let routed_only = o3k_network::add_l3_gateway_routing(
            plan.clone(),
            gateway_routes()?,
            gateway_egress(external_realm_id),
        )
        .map_err(|error| error.to_string())?;
        let realized = finalize_gateway_realization(
            plan,
            Some(gateway),
            gateway_routes()?,
            gateway_egress(external_realm_id),
            false,
        )
        .map_err(|error| error.to_string())?;
        assert!(realized.gateway.is_none());
        assert!(has_routed_intents(&realized));
        assert_eq!(realized, routed_only);
        Ok(())
    }

    #[test]
    fn gateway_realization_defaults_to_enabled_on_app_state() {
        assert!(AppState::new().network_gateway_realization_enabled());
        assert!(
            !AppState::new()
                .with_network_gateway_realization(false)
                .network_gateway_realization_enabled()
        );
    }

    fn realm_a() -> Uuid {
        Uuid::from_u128(9)
    }

    fn realm_b() -> Uuid {
        Uuid::from_u128(10)
    }

    fn address_realm(
        id: Uuid,
        network_id: Uuid,
        state: &str,
    ) -> o3k_store::CanonicalAddressRealmRecord {
        o3k_store::CanonicalAddressRealmRecord {
            id,
            network_id,
            project_id: "project".to_owned(),
            prefix: "198.51.100.0/24".to_owned(),
            overlapping_prefixes: false,
            generation: 1,
            state: state.to_owned(),
        }
    }

    #[test]
    fn active_external_realm_selection_ignores_retired_realms() {
        let network_id = Uuid::from_u128(11);
        let selected = select_active_external_realm_for_network(
            &[
                address_realm(realm_a(), network_id, "retired"),
                address_realm(realm_b(), network_id, "active"),
            ],
            Some(network_id),
        );
        assert_eq!(selected, Ok(Some(realm_b())));
    }

    #[test]
    fn active_external_realm_selection_fails_closed_without_active_realm() {
        let network_id = Uuid::from_u128(11);
        assert_eq!(
            select_active_external_realm_for_network(
                &[address_realm(realm_a(), network_id, "retired")],
                Some(network_id),
            ),
            Err("configured external network has no active canonical AddressRealm")
        );
    }

    #[test]
    fn active_external_realm_selection_fails_closed_on_ambiguity() {
        let network_id = Uuid::from_u128(11);
        assert_eq!(
            select_active_external_realm_for_network(
                &[
                    address_realm(realm_a(), network_id, "active"),
                    address_realm(realm_b(), network_id, "active"),
                ],
                Some(network_id),
            ),
            Err("configured external network has multiple active canonical AddressRealms")
        );
    }

    #[test]
    fn routed_egress_realm_is_coherent_flat_only_accepts_any_external_identity() {
        // A pure-flat deployment (no Router egress) keeps its flat external
        // identity even when no canonical realm resolves.
        assert!(routed_egress_realm_is_coherent(&[], None, true));
        assert!(routed_egress_realm_is_coherent(&[], Some(realm_a()), true));
    }

    #[test]
    fn routed_egress_realm_is_coherent_unconfigured_external_is_accepted() {
        let egress = gateway_egress(realm_a());
        assert!(routed_egress_realm_is_coherent(&egress, None, false));
    }

    #[test]
    fn routed_egress_realm_is_coherent_matching_realm_is_accepted() {
        let egress = gateway_egress(realm_a());
        assert!(routed_egress_realm_is_coherent(
            &egress,
            Some(realm_a()),
            true
        ));
    }

    #[test]
    fn routed_egress_realm_is_coherent_unresolvable_realm_fails_closed() {
        // A Router contributes egress but the external pool network has no
        // canonical realm: must fail closed rather than labeling a Network id.
        let egress = gateway_egress(realm_a());
        assert!(!routed_egress_realm_is_coherent(&egress, None, true));
    }

    #[test]
    fn routed_egress_realm_is_coherent_divergent_realm_fails_closed() {
        // The gateway egress references a different realm than the pool's
        // canonical realm: the single-realm routed invariant is violated.
        let egress = gateway_egress(realm_b());
        assert!(!routed_egress_realm_is_coherent(
            &egress,
            Some(realm_a()),
            true
        ));
    }

    #[test]
    fn routed_egress_realm_is_coherent_multiple_gateways_require_single_realm() {
        let mut egress = gateway_egress(realm_a());
        egress.push(o3k_domain::EgressIntent {
            external_realm_id: realm_b(),
            enabled: true,
            nat: true,
        });
        assert!(!routed_egress_realm_is_coherent(
            &egress,
            Some(realm_a()),
            true
        ));
        let coherent = gateway_egress(realm_a());
        egress.pop();
        assert!(routed_egress_realm_is_coherent(
            &coherent,
            Some(realm_a()),
            true
        ));
    }
}
