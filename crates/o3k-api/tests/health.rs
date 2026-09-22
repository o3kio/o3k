use axum::body::{Body, HttpBody};
use http::{HeaderValue, Method, Request, StatusCode, header};
use o3k_compute::ComputeService;
use o3k_domain::Ipv4Prefix;
use o3k_identity::testkit::{test_service, test_service_with_projects};
use o3k_identity::{ExtraProjectSeed, Secret};
use o3k_image::{DEFAULT_MAX_UPLOAD_BYTES, ImageService};
use o3k_network::{
    NetworkPlanAction, NetworkPlanCommand, NetworkPlanDispatcher, NetworkPlanStatus,
    NetworkService, PublicAddressAllocator, PublicAddressPool,
};
use o3k_provider::{FailureInjection, FakeComputeProvider};
use serde_json::Value;
use std::sync::{Arc, Mutex};
use std::time::{Duration, SystemTime};
use tower::ServiceExt;

const ADMIN_PROJECT_ID: &str = "eba29e2d-53de-461d-ae91-ede7402713cb";

#[derive(Clone, Default)]
struct RecordingNetworkDispatcher {
    commands: Arc<Mutex<Vec<NetworkPlanCommand>>>,
}

#[async_trait::async_trait]
impl NetworkPlanDispatcher for RecordingNetworkDispatcher {
    async fn dispatch(
        &self,
        command: NetworkPlanCommand,
    ) -> Result<NetworkPlanStatus, o3k_network::NetworkDispatchError> {
        self.commands
            .lock()
            .map_err(|_| {
                o3k_network::NetworkDispatchError::Transport(
                    "recording dispatcher lock poisoned".to_owned(),
                )
            })?
            .push(command);
        Ok(NetworkPlanStatus::Succeeded)
    }
}

/// Native API token issuer backed by the real identity service, so the native
/// route exercises the same unscoped-token rejection boundary as the
/// OpenStack compatibility routes.
#[derive(Clone)]
struct IdentityBackedIssuer(Arc<o3k_identity::TokenService>);

#[async_trait::async_trait]
impl o3k_native_api::auth::TokenIssuer for IdentityBackedIssuer {
    async fn issue_native(
        &self,
        _request: &o3k_native_api::auth::NativeTokenRequestV1,
    ) -> Result<(String, Value), o3k_native_api::error::ProblemDetails> {
        Err(o3k_native_api::error::ProblemDetails::unauthorized())
    }

    async fn auth_context(
        &self,
        token: &str,
    ) -> Result<o3k_kernel::AuthContext, o3k_native_api::error::ProblemDetails> {
        self.0
            .auth_context(token, SystemTime::now())
            .map_err(|_| o3k_native_api::error::ProblemDetails::unauthorized())
    }
}

/// Password authentication body without a `scope` member.
fn unscoped_password_body() -> Value {
    unscoped_password_body_for("admin", "password")
}

fn unscoped_password_body_for(name: &str, password: &str) -> Value {
    serde_json::json!({
        "auth": {
            "identity": {
                "methods": ["password"],
                "password": {"user": {"name": name, "password": password}}
            }
        }
    })
}

/// Password authentication body scoped to the bootstrap project.
fn project_scoped_password_body() -> Value {
    serde_json::json!({
        "auth": {
            "identity": {
                "methods": ["password"],
                "password": {"user": {"name": "admin", "password": "password"}}
            },
            "scope": {"project": {"name": "admin"}}
        }
    })
}

async fn post_auth(
    router: &axum::Router,
    body: Value,
) -> Result<axum::response::Response, Box<dyn std::error::Error>> {
    Ok(router
        .clone()
        .oneshot(
            Request::builder()
                .method(Method::POST)
                .uri("/v3/auth/tokens")
                .header(header::CONTENT_TYPE, "application/json")
                .body(Body::from(body.to_string()))?,
        )
        .await?)
}

async fn issue_keystone_token(
    router: &axum::Router,
    body: Value,
) -> Result<(String, Value), Box<dyn std::error::Error>> {
    let response = post_auth(router, body).await?;
    assert_eq!(response.status(), StatusCode::CREATED);
    let token = response
        .headers()
        .get("x-subject-token")
        .ok_or("missing x-subject-token header")?
        .to_str()?
        .to_owned();
    let value: Value =
        serde_json::from_slice(&axum::body::to_bytes(response.into_body(), 16 * 1024).await?)?;
    Ok((token, value))
}

fn assert_unscoped_token_body(body: &Value) {
    assert_eq!(body["token"]["user"]["id"], "bootstrap-user");
    assert_eq!(body["token"]["methods"][0], "password");
    assert!(body["token"]["expires_at"].is_string());
    assert!(body["token"]["issued_at"].is_string());
    for absent in ["project", "roles", "catalog"] {
        assert!(
            body["token"].get(absent).is_none(),
            "unscoped token body must not contain {absent}: {body}"
        );
    }
}

#[tokio::test]
async fn health_endpoint_is_machine_readable() -> Result<(), Box<dyn std::error::Error>> {
    let request = Request::builder().uri("/healthz").body(Body::empty())?;
    let response = o3k_api::router().oneshot(request).await?;

    assert_eq!(response.status(), StatusCode::OK);
    let bytes = axum::body::to_bytes(response.into_body(), 1024).await?;
    let body: Value = serde_json::from_slice(&bytes)?;
    assert_eq!(body, serde_json::json!({"status": "ok"}));
    Ok(())
}

#[tokio::test]
async fn readiness_projects_independent_runtime_and_bootstrap_gates()
-> Result<(), Box<dyn std::error::Error>> {
    let state = o3k_api::AppState::new();
    state.set_runtime_ready(true);
    state.set_bootstrap_ready(false);
    let response = o3k_api::router_with_state(state.clone())
        .oneshot(Request::get("/readyz").body(Body::empty())?)
        .await?;
    assert_eq!(response.status(), StatusCode::SERVICE_UNAVAILABLE);

    // A durable bootstrap transition must not mask an unrelated runtime
    // failure, and it must become visible without replacing the other gate.
    state.set_bootstrap_ready(true);
    state.set_runtime_ready(false);
    let response = o3k_api::router_with_state(state.clone())
        .oneshot(Request::get("/readyz").body(Body::empty())?)
        .await?;
    assert_eq!(response.status(), StatusCode::SERVICE_UNAVAILABLE);

    state.set_runtime_ready(true);
    let response = o3k_api::router_with_state(state)
        .oneshot(Request::get("/readyz").body(Body::empty())?)
        .await?;
    assert_eq!(response.status(), StatusCode::OK);
    Ok(())
}

#[tokio::test]
async fn default_state_preserves_no_secret_readiness_behavior()
-> Result<(), Box<dyn std::error::Error>> {
    let state = o3k_api::AppState::new();
    state.set_runtime_ready(true);
    let response = o3k_api::router_with_state(state)
        .oneshot(Request::get("/readyz").body(Body::empty())?)
        .await?;
    assert_eq!(response.status(), StatusCode::OK);
    Ok(())
}

#[tokio::test]
async fn network_policy_api_persists_updates_and_deletes_canonical_intent()
-> Result<(), Box<dyn std::error::Error>> {
    let root = std::path::PathBuf::from(format!(
        "/tmp/o3k-api-network-policy-{}",
        uuid::Uuid::now_v7()
    ));
    let _ = std::fs::remove_dir_all(&root);
    let identity = test_service("http://127.0.0.1:8080").await?;
    let project_id = "eba29e2d-53de-461d-ae91-ede7402713cb";
    let store = std::sync::Arc::new(o3k_store::testkit::open_memory().await?);
    let network = NetworkService::open_for_test(root.join("network"), store).await?;
    let network_record = network
        .create_network_for_project(project_id, "policy-network".to_owned())
        .await?;
    network
        .create_subnet_for_project(
            project_id,
            network_record.id,
            "policy-subnet".to_owned(),
            "10.0.0.0/24".to_owned(),
            None,
            None,
            None,
        )
        .await?;
    let port = network
        .create_port_for_project(project_id, network_record.id, "policy-port".to_owned())
        .await?;
    network
        .record_binding_intent(project_id, port.id, "network-agent")
        .await?;
    let dispatcher = RecordingNetworkDispatcher::default();
    let commands = dispatcher.commands.clone();
    let state = o3k_api::AppState::new()
        .with_identity(identity)
        .with_network(network.clone())
        .with_network_dispatcher(
            Arc::new(dispatcher),
            o3k_network::NetworkControllerLease {
                controller_id: "controller-test".to_owned(),
                controller_epoch: "epoch-1".to_owned(),
                fencing_token: 1,
            },
        )
        .with_network_agent_identity(o3k_network::NetworkAgentIdentity {
            agent_id: "network-agent".to_owned(),
            agent_epoch: "network-epoch-1".to_owned(),
        });
    let auth = serde_json::json!({"auth":{"identity":{"methods":["password"],"password":{"user":{"name":"admin","password":"password"}}},"scope":{"project":{"name":"admin"}}}});
    let token_response = o3k_api::router_with_state(state.clone())
        .oneshot(
            Request::builder()
                .method(Method::POST)
                .uri("/v3/auth/tokens")
                .header(header::CONTENT_TYPE, "application/json")
                .body(Body::from(auth.to_string()))?,
        )
        .await?;
    let token = token_response
        .headers()
        .get("x-subject-token")
        .ok_or("token missing")?
        .to_str()?
        .to_owned();
    let create = serde_json::json!({
        "policy": {
            "network_id": network_record.id,
            "endpoint_id": port.id,
            "direction": "ingress",
            "protocol": "tcp",
            "ports": {"start": 8080, "end": 8080},
            "source": "198.51.100.0/24",
            "action": "deny"
        }
    });
    let created = o3k_api::router_with_state(state.clone())
        .oneshot(
            Request::builder()
                .method(Method::POST)
                .uri("/v2.0/network-policies")
                .header("x-auth-token", &token)
                .header(header::CONTENT_TYPE, "application/json")
                .header("idempotency-key", "policy-create-1")
                .body(Body::from(create.to_string()))?,
        )
        .await?;
    assert_eq!(created.status(), StatusCode::CREATED);
    assert_eq!(commands.lock().map_err(|_| "commands poisoned")?.len(), 1);
    assert!(
        commands.lock().map_err(|_| "commands poisoned")?[0]
            .plan
            .intents
            .iter()
            .any(|intent| matches!(intent, o3k_domain::NetworkPlanIntent::Policy(_)))
    );
    let created_body: Value =
        serde_json::from_slice(&axum::body::to_bytes(created.into_body(), 4096).await?)?;
    let policy_id = created_body["policy"]["id"]
        .as_str()
        .ok_or("policy id missing")?;

    let duplicate = o3k_api::router_with_state(state.clone())
        .oneshot(
            Request::builder()
                .method(Method::POST)
                .uri("/v2.0/network-policies")
                .header("x-auth-token", &token)
                .header(header::CONTENT_TYPE, "application/json")
                .header("idempotency-key", "policy-create-1")
                .body(Body::from(create.to_string()))?,
        )
        .await?;
    assert_eq!(duplicate.status(), StatusCode::CREATED);
    let duplicate_body: Value =
        serde_json::from_slice(&axum::body::to_bytes(duplicate.into_body(), 4096).await?)?;
    assert_eq!(duplicate_body["policy"]["id"], policy_id);

    let listed = o3k_api::router_with_state(state.clone())
        .oneshot(
            Request::builder()
                .uri(format!(
                    "/v2.0/network-policies?network_id={network_id}",
                    network_id = network_record.id
                ))
                .header("x-auth-token", &token)
                .body(Body::empty())?,
        )
        .await?;
    assert_eq!(listed.status(), StatusCode::OK);
    let listed_body: Value =
        serde_json::from_slice(&axum::body::to_bytes(listed.into_body(), 4096).await?)?;
    assert_eq!(listed_body["policies"].as_array().map(Vec::len), Some(1));

    let update = serde_json::json!({
        "policy": {
            "network_id": network_record.id,
            "endpoint_id": port.id,
            "direction": "ingress",
            "protocol": "tcp",
            "ports": {"start": 8080, "end": 8080},
            "source": "198.51.100.0/24",
            "action": "allow"
        }
    });
    let updated = o3k_api::router_with_state(state.clone())
        .oneshot(
            Request::builder()
                .method(Method::PUT)
                .uri(format!(
                    "/v2.0/network-policies/{policy_id}?network_id={network_id}",
                    network_id = network_record.id
                ))
                .header("x-auth-token", &token)
                .header(header::CONTENT_TYPE, "application/json")
                .body(Body::from(update.to_string()))?,
        )
        .await?;
    assert_eq!(updated.status(), StatusCode::OK);
    assert_eq!(commands.lock().map_err(|_| "commands poisoned")?.len(), 3);

    let deleted = o3k_api::router_with_state(state)
        .oneshot(
            Request::builder()
                .method(Method::DELETE)
                .uri(format!(
                    "/v2.0/network-policies/{policy_id}?network_id={network_id}",
                    network_id = network_record.id
                ))
                .header("x-auth-token", &token)
                .body(Body::empty())?,
        )
        .await?;
    assert_eq!(deleted.status(), StatusCode::NO_CONTENT);
    assert_eq!(commands.lock().map_err(|_| "commands poisoned")?.len(), 4);
    assert!(
        network
            .list_policies_for_project(project_id, network_record.id)
            .await?
            .is_empty()
    );
    let _ = std::fs::remove_dir_all(&root);
    Ok(())
}

#[tokio::test]
async fn floating_ip_lifecycle_is_project_scoped_and_idempotent()
-> Result<(), Box<dyn std::error::Error>> {
    let root =
        std::path::PathBuf::from(format!("/tmp/o3k-api-floating-ip-{}", uuid::Uuid::now_v7()));
    let _ = std::fs::remove_dir_all(&root);
    let identity = test_service("http://127.0.0.1:8080").await?;
    let project_id = "eba29e2d-53de-461d-ae91-ede7402713cb";
    let store = std::sync::Arc::new(o3k_store::testkit::open_memory().await?);
    let network = NetworkService::open_for_test(root.join("network"), store.clone()).await?;
    let network_record = network
        .create_network_for_project(project_id, "private".to_owned())
        .await?;
    network
        .create_subnet_for_project(
            project_id,
            network_record.id,
            "private-subnet".to_owned(),
            "10.0.0.0/29".to_owned(),
            None,
            None,
            None,
        )
        .await?;
    let port = network
        .create_port_for_project(project_id, network_record.id, "vm".to_owned())
        .await?;
    let prefix = Ipv4Prefix::new("198.51.100.0".parse()?, 29).ok_or("invalid pool")?;
    let allocator = PublicAddressAllocator::open(
        root.join("public"),
        PublicAddressPool {
            prefix,
            first_usable: "198.51.100.2".parse()?,
            last_usable: "198.51.100.6".parse()?,
        },
    )?;
    let external_realm_id = uuid::Uuid::now_v7();
    let state = o3k_api::AppState::new()
        .with_identity(identity)
        .with_network(network)
        .with_public_allocator(allocator)
        .with_network_external_realm(external_realm_id);
    let auth = serde_json::json!({"auth":{"identity":{"methods":["password"],"password":{"user":{"name":"admin","password":"password"}}},"scope":{"project":{"name":"admin"}}}});
    let token_response = o3k_api::router_with_state(state.clone())
        .oneshot(
            Request::builder()
                .method(Method::POST)
                .uri("/v3/auth/tokens")
                .header(header::CONTENT_TYPE, "application/json")
                .body(Body::from(auth.to_string()))?,
        )
        .await?;
    let token = token_response
        .headers()
        .get("x-subject-token")
        .ok_or("token missing")?
        .to_str()?
        .to_owned();
    let wrong_network = serde_json::json!({
        "floatingip": {
            "floating_network_id": network_record.id,
            "port_id": port.id
        }
    });
    let rejected = o3k_api::router_with_state(state.clone())
        .oneshot(
            Request::builder()
                .method(Method::POST)
                .uri("/v2.0/floatingips")
                .header("x-auth-token", &token)
                .header(header::CONTENT_TYPE, "application/json")
                .header("x-openstack-request-id", "floating-wrong-network")
                .body(Body::from(wrong_network.to_string()))?,
        )
        .await?;
    assert_eq!(rejected.status(), StatusCode::BAD_REQUEST);
    let missing_endpoint = serde_json::json!({
        "floatingip": {
            "floating_network_id": external_realm_id,
            "port_id": uuid::Uuid::now_v7()
        }
    });
    let missing_endpoint_response = o3k_api::router_with_state(state.clone())
        .oneshot(
            Request::builder()
                .method(Method::POST)
                .uri("/v2.0/floatingips")
                .header("x-auth-token", &token)
                .header(header::CONTENT_TYPE, "application/json")
                .header("x-openstack-request-id", "floating-missing-endpoint")
                .body(Body::from(missing_endpoint.to_string()))?,
        )
        .await?;
    assert_eq!(missing_endpoint_response.status(), StatusCode::BAD_REQUEST);
    let empty = o3k_api::router_with_state(state.clone())
        .oneshot(
            Request::builder()
                .uri("/v2.0/floatingips")
                .header("x-auth-token", &token)
                .body(Body::empty())?,
        )
        .await?;
    let empty: Value =
        serde_json::from_slice(&axum::body::to_bytes(empty.into_body(), 4096).await?)?;
    assert_eq!(empty["floatingips"].as_array().map(Vec::len), Some(0));
    let request_body = serde_json::json!({
        "floatingip": {
            "floating_network_id": external_realm_id,
            "port_id": port.id
        }
    });
    let response = o3k_api::router_with_state(state.clone())
        .oneshot(
            Request::builder()
                .method(Method::POST)
                .uri("/v2.0/floatingips")
                .header("x-auth-token", &token)
                .header(header::CONTENT_TYPE, "application/json")
                .header("x-openstack-request-id", "floating-create-1")
                .body(Body::from(request_body.to_string()))?,
        )
        .await?;
    assert_eq!(response.status(), StatusCode::CREATED);
    let created: Value =
        serde_json::from_slice(&axum::body::to_bytes(response.into_body(), 4096).await?)?;
    let id = created["floatingip"]["id"].as_str().ok_or("id missing")?;
    assert_eq!(created["floatingip"]["port_id"], port.id.to_string());

    let replay = o3k_api::router_with_state(state.clone())
        .oneshot(
            Request::builder()
                .method(Method::POST)
                .uri("/v2.0/floatingips")
                .header("x-auth-token", &token)
                .header(header::CONTENT_TYPE, "application/json")
                .header("x-openstack-request-id", "floating-create-1")
                .body(Body::from(request_body.to_string()))?,
        )
        .await?;
    assert_eq!(replay.status(), StatusCode::CREATED);
    let replayed: Value =
        serde_json::from_slice(&axum::body::to_bytes(replay.into_body(), 4096).await?)?;
    assert_eq!(replayed["floatingip"]["id"], id);

    let listed = o3k_api::router_with_state(state.clone())
        .oneshot(
            Request::builder()
                .uri("/v2.0/floatingips")
                .header("x-auth-token", &token)
                .body(Body::empty())?,
        )
        .await?;
    assert_eq!(listed.status(), StatusCode::OK);
    let listed: Value =
        serde_json::from_slice(&axum::body::to_bytes(listed.into_body(), 4096).await?)?;
    assert_eq!(listed["floatingips"].as_array().map(Vec::len), Some(1));

    // Deleting an associated floating IP must remove its realization and
    // canonical association as part of the same compatibility operation.
    let deleted = o3k_api::router_with_state(state)
        .oneshot(
            Request::builder()
                .method(Method::DELETE)
                .uri(format!("/v2.0/floatingips/{id}"))
                .header("x-auth-token", &token)
                .body(Body::empty())?,
        )
        .await?;
    assert_eq!(deleted.status(), StatusCode::NO_CONTENT);
    Ok(())
}

#[tokio::test]
async fn floating_ip_api_dispatches_a_public_binding_plan_to_the_selected_agent()
-> Result<(), Box<dyn std::error::Error>> {
    let root = std::path::PathBuf::from(format!(
        "/tmp/o3k-api-floating-dispatch-{}",
        uuid::Uuid::now_v7()
    ));
    let _ = std::fs::remove_dir_all(&root);
    let identity = test_service("http://127.0.0.1:8080").await?;
    let project_id = "eba29e2d-53de-461d-ae91-ede7402713cb";
    let store = std::sync::Arc::new(o3k_store::testkit::open_memory().await?);
    let network = NetworkService::open_for_test(root.join("network"), store).await?;
    let network_record = network
        .create_network_for_project(project_id, "private".to_owned())
        .await?;
    network
        .create_subnet_for_project(
            project_id,
            network_record.id,
            "private-subnet".to_owned(),
            "10.0.0.0/29".to_owned(),
            None,
            None,
            None,
        )
        .await?;
    let port = network
        .create_port_for_project(project_id, network_record.id, "vm".to_owned())
        .await?;
    network
        .record_binding_intent(project_id, port.id, "agent-network")
        .await?;

    let dispatcher = RecordingNetworkDispatcher::default();
    let commands = dispatcher.commands.clone();
    let external_realm_id = network_record.id;
    let public_root = root.join("public");
    let allocator = PublicAddressAllocator::open(
        &public_root,
        PublicAddressPool {
            prefix: Ipv4Prefix::new("198.51.100.0".parse()?, 29).ok_or("invalid pool")?,
            first_usable: "198.51.100.2".parse()?,
            last_usable: "198.51.100.6".parse()?,
        },
    )?;
    let state = o3k_api::AppState::new()
        .with_identity(identity)
        .with_network(network)
        .with_public_allocator(allocator)
        .with_network_external_realm(external_realm_id)
        .with_network_dispatcher(
            Arc::new(dispatcher),
            o3k_network::NetworkControllerLease {
                controller_id: "controller-test".to_owned(),
                controller_epoch: "epoch-1".to_owned(),
                fencing_token: 1,
            },
        )
        .with_network_agent_identity(o3k_network::NetworkAgentIdentity {
            agent_id: "agent-network".to_owned(),
            agent_epoch: "epoch-1".to_owned(),
        });
    let auth = serde_json::json!({"auth":{"identity":{"methods":["password"],"password":{"user":{"name":"admin","password":"password"}}},"scope":{"project":{"name":"admin"}}}});
    let token_response = o3k_api::router_with_state(state.clone())
        .oneshot(
            Request::builder()
                .method(Method::POST)
                .uri("/v3/auth/tokens")
                .header(header::CONTENT_TYPE, "application/json")
                .body(Body::from(auth.to_string()))?,
        )
        .await?;
    let token = token_response
        .headers()
        .get("x-subject-token")
        .ok_or("token missing")?
        .to_str()?
        .to_owned();
    let request_body = serde_json::json!({
        "floatingip": {
            "floating_network_id": external_realm_id,
            "port_id": port.id
        }
    });
    let response = o3k_api::router_with_state(state.clone())
        .oneshot(
            Request::builder()
                .method(Method::POST)
                .uri("/v2.0/floatingips")
                .header("x-auth-token", &token)
                .header(header::CONTENT_TYPE, "application/json")
                .header("x-openstack-request-id", "floating-dispatch-1")
                .body(Body::from(request_body.to_string()))?,
        )
        .await?;
    assert_eq!(response.status(), StatusCode::CREATED);
    drop(response);

    {
        let recorded = commands
            .lock()
            .map_err(|_| std::io::Error::other("recording dispatcher lock poisoned"))?;
        assert_eq!(recorded.len(), 1);
        let command = &recorded[0];
        assert_eq!(command.action, NetworkPlanAction::Apply);
        assert_eq!(command.target.agent_id, "agent-network");
        assert_eq!(command.target.agent_epoch, "epoch-1");
        assert!(command.plan.intents.iter().any(|intent| {
            matches!(
                intent,
                o3k_domain::NetworkPlanIntent::PublicAddressBinding(binding)
                    if binding.endpoint_id == port.id
            )
        }));
    }

    // Endpoint deletion must clean the public realization before removing the
    // endpoint snapshot, covering IaC destroy order where the port precedes
    // the Floating IP.
    let deleted_port = o3k_api::router_with_state(state.clone())
        .oneshot(
            Request::builder()
                .method(Method::DELETE)
                .uri(format!("/v2.0/ports/{}", port.id))
                .header("x-auth-token", &token)
                .body(Body::empty())?,
        )
        .await?;
    assert_eq!(deleted_port.status(), StatusCode::NO_CONTENT);
    let allocator = PublicAddressAllocator::open(
        &public_root,
        PublicAddressPool {
            prefix: Ipv4Prefix::new("198.51.100.0".parse()?, 29).ok_or("invalid pool")?,
            first_usable: "198.51.100.2".parse()?,
            last_usable: "198.51.100.6".parse()?,
        },
    )?;
    assert!(
        allocator
            .list(project_id)?
            .into_iter()
            .all(|binding| binding.endpoint_id != Some(port.id))
    );
    assert!(
        commands
            .lock()
            .map_err(|_| std::io::Error::other("recording dispatcher lock poisoned"))?
            .iter()
            .any(|command| {
                command.action == NetworkPlanAction::Remove
                    && command.plan.intents.iter().any(|intent| {
                        matches!(
                            intent,
                            o3k_domain::NetworkPlanIntent::PublicAddressBinding(binding)
                                if binding.endpoint_id == port.id
                        )
                    })
            })
    );
    Ok(())
}

#[tokio::test]
async fn registered_agent_console_reads_fall_back_to_durable_cache()
-> Result<(), Box<dyn std::error::Error>> {
    let identity = test_service("http://127.0.0.1:8080").await?;
    let store_path = std::path::PathBuf::from(format!(
        "/tmp/o3k-api-agent-console-{}.sqlite",
        uuid::Uuid::now_v7()
    ));
    let store = std::sync::Arc::new(o3k_store::testkit::open_file(&store_path).await?);
    let provider = std::sync::Arc::new(FakeComputeProvider::new());
    let registry = o3k_compute_agent::NodeRegistry::default();
    registry
        .register(&o3k_provider_contract::compute_proto::RegisterRequest {
            agent_id: "agent-1".to_owned(),
            agent_epoch: "epoch-1".to_owned(),
            software_version: "test".to_owned(),
            host_label: "host".to_owned(),
            supported_versions: vec![o3k_compute_agent::PROTOCOL_VERSION],
            capabilities: Some(o3k_provider_contract::compute_proto::Capabilities {
                architecture: "x86_64".to_owned(),
                agent_provider_name: "test".to_owned(),
                agent_provider_version: "1".to_owned(),
                ..Default::default()
            }),
        })
        .await?;
    let placement_root = format!("/tmp/o3k-api-agent-placement-{}", uuid::Uuid::now_v7());
    let placement_repository: std::sync::Arc<dyn o3k_store::PlacementRepository> = store.clone();
    let placement =
        o3k_placement::PlacementLedger::open(&placement_root, placement_repository).await?;
    placement
        .register_provider(
            "agent-1",
            std::collections::BTreeMap::from([
                (
                    o3k_placement::VCPU.to_owned(),
                    o3k_placement::Inventory {
                        total: 8,
                        reserved: 0,
                        allocation_ratio: 1.0,
                        used: 0,
                    },
                ),
                (
                    o3k_placement::MEMORY_MB.to_owned(),
                    o3k_placement::Inventory {
                        total: 8192,
                        reserved: 0,
                        allocation_ratio: 1.0,
                        used: 0,
                    },
                ),
                (
                    o3k_placement::DISK_GB.to_owned(),
                    o3k_placement::Inventory {
                        total: 100,
                        reserved: 0,
                        allocation_ratio: 1.0,
                        used: 0,
                    },
                ),
            ]),
        )
        .await?;
    let compute = ComputeService::new_for_test(store, provider)
        .with_scheduler(o3k_scheduler::Scheduler::new(placement))
        .with_agent_registry(std::sync::Arc::new(registry.clone()));
    let console = o3k_console::ConsoleService::open(format!(
        "/tmp/o3k-api-agent-console-cache-{}",
        uuid::Uuid::now_v7()
    ))?;
    let state = o3k_api::AppState::new()
        .with_identity(identity)
        .with_compute(compute)
        .with_console(console.clone())
        .with_agent_registry(registry);
    let auth = serde_json::json!({"auth":{"identity":{"methods":["password"],"password":{"user":{"name":"admin","password":"password"}}},"scope":{"project":{"name":"admin"}}}});
    let auth_response = o3k_api::router_with_state(state.clone())
        .oneshot(
            Request::builder()
                .method(Method::POST)
                .uri("/v3/auth/tokens")
                .header(header::CONTENT_TYPE, "application/json")
                .body(Body::from(auth.to_string()))?,
        )
        .await?;
    let token = auth_response
        .headers()
        .get("x-subject-token")
        .ok_or_else(|| std::io::Error::other("token missing"))?
        .to_str()?
        .to_owned();
    let create = o3k_api::router_with_state(state.clone())
        .oneshot(
            Request::builder()
                .method(Method::POST)
                .uri("/v2.1/eba29e2d-53de-461d-ae91-ede7402713cb/servers")
                .header("x-auth-token", &token)
                .header(header::CONTENT_TYPE, "application/json")
                .body(Body::from(
                    r#"{"server":{"name":"agent-console","image":{"id":"image-1"},"flavor":{"id":"00000000-0000-0000-0000-000000000001"},"networks":[{"uuid":"network-1"}]}}"#,
                ))?,
        )
        .await?;
    assert_eq!(create.status(), StatusCode::ACCEPTED);
    let server: Value =
        serde_json::from_slice(&axum::body::to_bytes(create.into_body(), 8192).await?)?;
    let server_id = server["server"]["id"]
        .as_str()
        .ok_or_else(|| std::io::Error::other("server missing"))?;
    let server_uuid = server_id.parse::<uuid::Uuid>()?;
    console.write(server_uuid, b"0123456789abcdef")?;

    let response = o3k_api::router_with_state(state)
        .oneshot(
            Request::builder()
                .method(Method::POST)
                .uri(format!(
                    "/v2.1/eba29e2d-53de-461d-ae91-ede7402713cb/servers/{server_id}/action"
                ))
                .header("x-auth-token", &token)
                .header(header::CONTENT_TYPE, "application/json")
                .body(Body::from(
                    r#"{"os-getConsoleOutput":{"offset":4,"length":6}}"#,
                ))?,
        )
        .await?;
    assert_eq!(response.status(), StatusCode::OK);
    let body: Value =
        serde_json::from_slice(&axum::body::to_bytes(response.into_body(), 4096).await?)?;
    assert_eq!(body["output"], "456789");
    Ok(())
}

#[tokio::test]
async fn readiness_reports_startup_failure() -> Result<(), Box<dyn std::error::Error>> {
    let state = o3k_api::AppState::new();
    let request = Request::builder().uri("/readyz").body(Body::empty())?;
    let response = o3k_api::router_with_state(state).oneshot(request).await?;

    assert_eq!(response.status(), StatusCode::SERVICE_UNAVAILABLE);
    let bytes = axum::body::to_bytes(response.into_body(), 1024).await?;
    let body: Value = serde_json::from_slice(&bytes)?;
    assert_eq!(body, serde_json::json!({"status": "not_ready"}));
    Ok(())
}

#[tokio::test]
async fn keystone_password_scope_returns_signed_subject_token()
-> Result<(), Box<dyn std::error::Error>> {
    let service = test_service("http://127.0.0.1:8080").await?;
    let body = serde_json::json!({
        "auth": {
            "identity": {
                "methods": ["password"],
                "password": {"user": {"name": "admin", "password": "password"}}
            },
            "scope": {"project": {"name": "admin"}}
        }
    });
    let request = Request::builder()
        .method(Method::POST)
        .uri("/v3/auth/tokens")
        .header(header::CONTENT_TYPE, "application/json")
        .body(Body::from(body.to_string()))?;
    let response = o3k_api::router_with_state(o3k_api::AppState::new().with_identity(service))
        .oneshot(request)
        .await?;
    assert_eq!(response.status(), StatusCode::CREATED);
    let subject_token = response
        .headers()
        .get("x-subject-token")
        .ok_or_else(|| std::io::Error::other("missing subject token"))?
        .to_str()?;
    assert_eq!(subject_token.split('.').count(), 3);
    let bytes = axum::body::to_bytes(response.into_body(), 16 * 1024).await?;
    let body: Value = serde_json::from_slice(&bytes)?;
    assert_eq!(
        body["token"]["project"]["id"],
        "eba29e2d-53de-461d-ae91-ede7402713cb"
    );
    assert!(
        body["token"]["catalog"]
            .as_array()
            .is_some_and(|items| items.len() == 6)
    );
    Ok(())
}

#[tokio::test]
async fn keystone_token_reauthentication_exchanges_a_valid_token()
-> Result<(), Box<dyn std::error::Error>> {
    let service = test_service("http://127.0.0.1:8080").await?;
    let router = o3k_api::router_with_state(o3k_api::AppState::new().with_identity(service));
    let password_body = serde_json::json!({
        "auth": {
            "identity": {
                "methods": ["password"],
                "password": {"user": {"name": "admin", "password": "password"}}
            },
            "scope": {"project": {"name": "admin"}}
        }
    });
    let response = router
        .clone()
        .oneshot(
            Request::builder()
                .method(Method::POST)
                .uri("/v3/auth/tokens")
                .header(header::CONTENT_TYPE, "application/json")
                .body(Body::from(password_body.to_string()))?,
        )
        .await?;
    assert_eq!(response.status(), StatusCode::CREATED);
    let presented = response
        .headers()
        .get("x-subject-token")
        .ok_or_else(|| std::io::Error::other("missing subject token"))?
        .to_str()?
        .to_owned();

    // Cinder's Nova client re-authenticates with methods: ["token"].
    let token_body = serde_json::json!({
        "auth": {
            "identity": {
                "methods": ["token"],
                "token": {"id": presented}
            },
            "scope": {"project": {"name": "admin"}}
        }
    });
    let reissued = router
        .clone()
        .oneshot(
            Request::builder()
                .method(Method::POST)
                .uri("/v3/auth/tokens")
                .header(header::CONTENT_TYPE, "application/json")
                .body(Body::from(token_body.to_string()))?,
        )
        .await?;
    assert_eq!(reissued.status(), StatusCode::CREATED);
    let reissued_token = reissued
        .headers()
        .get("x-subject-token")
        .ok_or_else(|| std::io::Error::other("missing reissued token"))?
        .to_str()?;
    assert_ne!(reissued_token, presented);
    let bytes = axum::body::to_bytes(reissued.into_body(), 16 * 1024).await?;
    let body: Value = serde_json::from_slice(&bytes)?;
    assert_eq!(body["token"]["user"]["id"], "bootstrap-user");

    // An invalid presented token is rejected as unauthorized.
    let invalid_body = serde_json::json!({
        "auth": {
            "identity": {
                "methods": ["token"],
                "token": {"id": "bogus-token"}
            },
            "scope": {"project": {"name": "admin"}}
        }
    });
    let invalid = router
        .clone()
        .oneshot(
            Request::builder()
                .method(Method::POST)
                .uri("/v3/auth/tokens")
                .header(header::CONTENT_TYPE, "application/json")
                .body(Body::from(invalid_body.to_string()))?,
        )
        .await?;
    assert_eq!(invalid.status(), StatusCode::UNAUTHORIZED);
    Ok(())
}

#[tokio::test]
async fn keystone_discovery_exposes_v3_without_fallback_warning()
-> Result<(), Box<dyn std::error::Error>> {
    for uri in ["/", "/v3"] {
        let response = o3k_api::router()
            .oneshot(
                Request::builder()
                    .method(Method::GET)
                    .uri(uri)
                    .body(Body::empty())?,
            )
            .await?;
        assert_eq!(
            response.status(),
            if uri == "/" {
                StatusCode::MULTIPLE_CHOICES
            } else {
                StatusCode::OK
            },
            "{uri}"
        );
        let body: Value =
            serde_json::from_slice(&axum::body::to_bytes(response.into_body(), 8192).await?)?;
        if uri == "/" {
            assert!(
                body["versions"]["values"]
                    .as_array()
                    .is_some_and(|values| !values.is_empty())
            );
        } else {
            assert_eq!(body["version"]["id"], "v3");
            assert_eq!(body["version"]["status"], "stable");
            assert_eq!(body["version"]["links"][0]["rel"], "self");
            assert_eq!(
                body["version"]["links"][0]["href"],
                "http://127.0.0.1:8080/v3"
            );
        }
    }
    Ok(())
}

#[tokio::test]
async fn keystone_catalog_contains_all_testlab_services_and_consistent_urls()
-> Result<(), Box<dyn std::error::Error>> {
    let identity = test_service("http://testlab.example.invalid/").await?;
    let body = serde_json::json!({"auth":{"identity":{"methods":["password"],"password":{"user":{"name":"admin","password":"password"}}},"scope":{"project":{"name":"admin"}}}});
    let response = o3k_api::router_with_state(o3k_api::AppState::new().with_identity(identity))
        .oneshot(
            Request::builder()
                .method(Method::POST)
                .uri("/v3/auth/tokens")
                .header(header::CONTENT_TYPE, "application/json")
                .body(Body::from(body.to_string()))?,
        )
        .await?;
    assert_eq!(response.status(), StatusCode::CREATED);
    let body: Value =
        serde_json::from_slice(&axum::body::to_bytes(response.into_body(), 16384).await?)?;
    let catalog = body["token"]["catalog"]
        .as_array()
        .ok_or("catalog missing")?;
    let services: std::collections::BTreeMap<_, _> = catalog
        .iter()
        .filter_map(|service| {
            Some((
                service["type"].as_str()?,
                service["endpoints"][0]["url"].as_str()?,
            ))
        })
        .collect();
    assert_eq!(services.len(), 6);
    assert_eq!(services["identity"], "http://testlab.example.invalid/v3");
    assert_eq!(services["image"], "http://testlab.example.invalid/");
    assert_eq!(services["network"], "http://testlab.example.invalid/");
    assert_eq!(
        services["compute"],
        "http://testlab.example.invalid/v2.1/eba29e2d-53de-461d-ae91-ede7402713cb"
    );
    assert_eq!(
        services["placement"],
        "http://testlab.example.invalid/placement"
    );
    assert_eq!(
        services["volumev3"],
        "http://127.0.0.1:8776/v3/eba29e2d-53de-461d-ae91-ede7402713cb"
    );
    Ok(())
}

#[tokio::test]
async fn keystone_invalid_password_is_generic_unauthorized()
-> Result<(), Box<dyn std::error::Error>> {
    let service = test_service("http://127.0.0.1:8080").await?;
    let request = Request::builder()
        .method(Method::POST)
        .uri("/v3/auth/tokens")
        .header(header::CONTENT_TYPE, "application/json")
        .body(Body::from(r#"{"auth":{"identity":{"methods":["password"],"password":{"user":{"name":"admin","password":"wrong"}}},"scope":{"project":{"name":"admin"}}}}"#))?;
    let response = o3k_api::router_with_state(o3k_api::AppState::new().with_identity(service))
        .oneshot(request)
        .await?;
    assert_eq!(response.status(), StatusCode::UNAUTHORIZED);
    let body = axum::body::to_bytes(response.into_body(), 4096).await?;
    assert!(!String::from_utf8(body.to_vec())?.contains("wrong"));
    Ok(())
}

#[tokio::test]
async fn keystone_unscoped_password_auth_without_scope_issues_token()
-> Result<(), Box<dyn std::error::Error>> {
    let service = test_service("http://127.0.0.1:8080").await?;
    let router = o3k_api::router_with_state(o3k_api::AppState::new().with_identity(service));
    let response = post_auth(&router, unscoped_password_body()).await?;
    assert_eq!(response.status(), StatusCode::CREATED);
    let token = response
        .headers()
        .get("x-subject-token")
        .ok_or("missing x-subject-token header")?
        .to_str()?
        .to_owned();
    assert_eq!(token.split('.').count(), 3);
    let body: Value =
        serde_json::from_slice(&axum::body::to_bytes(response.into_body(), 16 * 1024).await?)?;
    assert_unscoped_token_body(&body);
    Ok(())
}

#[tokio::test]
async fn keystone_unscoped_scope_keyword_issues_token() -> Result<(), Box<dyn std::error::Error>> {
    let service = test_service("http://127.0.0.1:8080").await?;
    let router = o3k_api::router_with_state(o3k_api::AppState::new().with_identity(service));
    let mut request = unscoped_password_body();
    request["auth"]["scope"] = Value::from("unscoped");
    let response = post_auth(&router, request).await?;
    assert_eq!(response.status(), StatusCode::CREATED);
    assert!(response.headers().get("x-subject-token").is_some());
    let body: Value =
        serde_json::from_slice(&axum::body::to_bytes(response.into_body(), 16 * 1024).await?)?;
    assert_unscoped_token_body(&body);
    Ok(())
}

#[tokio::test]
async fn keystone_unscoped_token_validation_returns_unscoped_shape()
-> Result<(), Box<dyn std::error::Error>> {
    let service = test_service("http://127.0.0.1:8080").await?;
    let router = o3k_api::router_with_state(o3k_api::AppState::new().with_identity(service));
    let (token, _) = issue_keystone_token(&router, unscoped_password_body()).await?;
    let response = router
        .clone()
        .oneshot(
            Request::builder()
                .uri("/v3/auth/tokens")
                .header("x-subject-token", &token)
                .body(Body::empty())?,
        )
        .await?;
    assert_eq!(response.status(), StatusCode::OK);
    let body: Value =
        serde_json::from_slice(&axum::body::to_bytes(response.into_body(), 16 * 1024).await?)?;
    assert_unscoped_token_body(&body);
    Ok(())
}

#[tokio::test]
async fn keystone_unscoped_invalid_password_is_generic_unauthorized()
-> Result<(), Box<dyn std::error::Error>> {
    let service = test_service("http://127.0.0.1:8080").await?;
    let router = o3k_api::router_with_state(o3k_api::AppState::new().with_identity(service));
    let body = serde_json::json!({
        "auth": {
            "identity": {
                "methods": ["password"],
                "password": {"user": {"name": "admin", "password": "wrong"}}
            }
        }
    });
    let response = post_auth(&router, body).await?;
    assert_eq!(response.status(), StatusCode::UNAUTHORIZED);
    let text = String::from_utf8(
        axum::body::to_bytes(response.into_body(), 4096)
            .await?
            .to_vec(),
    )?;
    assert!(!text.contains("wrong"));
    Ok(())
}

#[tokio::test]
async fn keystone_unsupported_scope_keyword_is_bounded_rejection()
-> Result<(), Box<dyn std::error::Error>> {
    let service = test_service("http://127.0.0.1:8080").await?;
    let router = o3k_api::router_with_state(o3k_api::AppState::new().with_identity(service));
    for keyword in ["domain", "garbage"] {
        let mut body = unscoped_password_body();
        body["auth"]["scope"] = Value::from(keyword);
        let response = post_auth(&router, body).await?;
        assert_eq!(
            response.status(),
            StatusCode::BAD_REQUEST,
            "scope keyword {keyword} must be rejected, not treated as unscoped"
        );
    }
    Ok(())
}

#[tokio::test]
async fn keystone_unsupported_identity_method_is_bounded_rejection()
-> Result<(), Box<dyn std::error::Error>> {
    let service = test_service("http://127.0.0.1:8080").await?;
    let router = o3k_api::router_with_state(o3k_api::AppState::new().with_identity(service));
    for methods in [
        serde_json::json!(["totp"]),
        serde_json::json!(["password", "token"]),
    ] {
        let mut body = unscoped_password_body();
        body["auth"]["identity"]["methods"] = methods.clone();
        let response = post_auth(&router, body).await?;
        assert_eq!(
            response.status(),
            StatusCode::BAD_REQUEST,
            "unsupported method set {methods} must be rejected"
        );
    }
    Ok(())
}

#[tokio::test]
async fn keystone_wrong_project_and_malformed_scope_fail_closed_without_leaking_credentials()
-> Result<(), Box<dyn std::error::Error>> {
    // The absence of a scope is now a supported unscoped request; a *wrong*
    // project and a malformed scope must still fail closed.
    let service = test_service("http://127.0.0.1:8080").await?;
    let router = o3k_api::router_with_state(o3k_api::AppState::new().with_identity(service));
    for (body, expected) in [
        (
            serde_json::json!({"auth":{"identity":{"methods":["password"],"password":{"user":{"name":"admin","password":"password"}}},"scope":{"project":{"name":"other-project"}}}}),
            StatusCode::UNAUTHORIZED,
        ),
        (
            serde_json::json!({"auth":{"identity":{"methods":["password"],"password":{"user":{"name":"admin","password":"password"}}},"scope":{"project":"not-a-project-object"}}}),
            StatusCode::BAD_REQUEST,
        ),
        (
            serde_json::json!({"auth":{"identity":{"methods":["password"],"password":{"user":{"name":"admin","password":"password"}}},"scope":7}}),
            StatusCode::BAD_REQUEST,
        ),
    ] {
        let description = body.to_string();
        let response = post_auth(&router, body).await?;
        assert_eq!(response.status(), expected, "{description}");
        let text = String::from_utf8(
            axum::body::to_bytes(response.into_body(), 4096)
                .await?
                .to_vec(),
        )?;
        assert!(!text.contains("password"));
        assert!(!text.contains("other-project"));
    }
    Ok(())
}

#[tokio::test]
async fn keystone_auth_projects_lists_authorized_projects_for_unscoped_token()
-> Result<(), Box<dyn std::error::Error>> {
    let service = test_service("http://127.0.0.1:8080").await?;
    let router = o3k_api::router_with_state(o3k_api::AppState::new().with_identity(service));
    let (token, _) = issue_keystone_token(&router, unscoped_password_body()).await?;
    let response = router
        .clone()
        .oneshot(
            Request::builder()
                .uri("/v3/auth/projects")
                .header("x-auth-token", &token)
                .body(Body::empty())?,
        )
        .await?;
    assert_eq!(response.status(), StatusCode::OK);
    let body: Value =
        serde_json::from_slice(&axum::body::to_bytes(response.into_body(), 16 * 1024).await?)?;
    let projects = body["projects"].as_array().ok_or("projects missing")?;
    assert_eq!(projects.len(), 1, "{body}");
    assert_eq!(projects[0]["id"], ADMIN_PROJECT_ID);
    assert_eq!(projects[0]["name"], "admin");
    assert_eq!(projects[0]["domain_id"], "default");
    assert_eq!(projects[0]["enabled"], true);
    Ok(())
}

#[tokio::test]
async fn keystone_auth_projects_accepts_project_scoped_token()
-> Result<(), Box<dyn std::error::Error>> {
    let service = test_service("http://127.0.0.1:8080").await?;
    let router = o3k_api::router_with_state(o3k_api::AppState::new().with_identity(service));
    let (token, _) = issue_keystone_token(&router, project_scoped_password_body()).await?;
    let response = router
        .clone()
        .oneshot(
            Request::builder()
                .uri("/v3/auth/projects")
                .header("x-auth-token", &token)
                .body(Body::empty())?,
        )
        .await?;
    assert_eq!(response.status(), StatusCode::OK);
    let body: Value =
        serde_json::from_slice(&axum::body::to_bytes(response.into_body(), 16 * 1024).await?)?;
    assert_eq!(body["projects"][0]["id"], ADMIN_PROJECT_ID);
    Ok(())
}

#[tokio::test]
async fn keystone_auth_projects_rejects_invalid_and_missing_tokens()
-> Result<(), Box<dyn std::error::Error>> {
    let service = test_service("http://127.0.0.1:8080").await?;
    let router = o3k_api::router_with_state(o3k_api::AppState::new().with_identity(service));
    for header_value in [Some("not-a-token"), None] {
        let mut request = Request::builder().uri("/v3/auth/projects");
        if let Some(value) = header_value {
            request = request.header("x-auth-token", value);
        }
        let response = router.clone().oneshot(request.body(Body::empty())?).await?;
        assert_eq!(
            response.status(),
            StatusCode::UNAUTHORIZED,
            "header {header_value:?}"
        );
        let text = String::from_utf8(
            axum::body::to_bytes(response.into_body(), 4096)
                .await?
                .to_vec(),
        )?;
        assert!(!text.contains("not-a-token"));
    }
    Ok(())
}

#[tokio::test]
async fn keystone_auth_projects_rejects_expired_token() -> Result<(), Box<dyn std::error::Error>> {
    // The API layer has no injectable clock, so the expiry is constructed the
    // same way the identity expiry test does: issue against a `now` in the
    // past so the token's lifetime has already elapsed.
    let service = test_service("http://127.0.0.1:8080").await?;
    let request: o3k_identity::TokenRequest = serde_json::from_value(unscoped_password_body())?;
    let (expired, _) = service.issue(&request, SystemTime::now() - Duration::from_secs(7_200))?;
    let router = o3k_api::router_with_state(o3k_api::AppState::new().with_identity(service));
    let response = router
        .clone()
        .oneshot(
            Request::builder()
                .uri("/v3/auth/projects")
                .header("x-auth-token", &expired)
                .body(Body::empty())?,
        )
        .await?;
    assert_eq!(response.status(), StatusCode::UNAUTHORIZED);
    Ok(())
}

#[tokio::test]
async fn keystone_auth_projects_never_returns_unrelated_projects()
-> Result<(), Box<dyn std::error::Error>> {
    let tenant_b = "8d1f3c4a-5b6e-4f2a-9c3d-1e2f3a4b5c6d";
    let service = test_service_with_projects(
        "http://127.0.0.1:8080",
        vec![ExtraProjectSeed {
            project_id: tenant_b.to_owned(),
            project_name: "tenant-b".to_owned(),
            user_id: "a7c2e9d1-4f3b-4c8e-9d2a-3b4c5d6e7f8a".to_owned(),
            user_name: "tenant-b-user".to_owned(),
            password: Secret::new("tenant-b-password".to_owned()),
        }],
    )
    .await?;
    let router = o3k_api::router_with_state(o3k_api::AppState::new().with_identity(service));

    let (admin_token, _) = issue_keystone_token(&router, unscoped_password_body()).await?;
    let response = router
        .clone()
        .oneshot(
            Request::builder()
                .uri("/v3/auth/projects")
                .header("x-auth-token", &admin_token)
                .body(Body::empty())?,
        )
        .await?;
    let body: Value =
        serde_json::from_slice(&axum::body::to_bytes(response.into_body(), 16 * 1024).await?)?;
    let ids: Vec<&str> = body["projects"]
        .as_array()
        .ok_or("projects missing")?
        .iter()
        .filter_map(|project| project["id"].as_str())
        .collect();
    assert_eq!(ids, [ADMIN_PROJECT_ID], "{body}");
    assert!(!ids.contains(&tenant_b));
    assert!(!ids.contains(&"service-project"));

    // The isolated tenant sees exactly its own project, never the bootstrap one.
    let (tenant_token, _) = issue_keystone_token(
        &router,
        unscoped_password_body_for("tenant-b-user", "tenant-b-password"),
    )
    .await?;
    let response = router
        .clone()
        .oneshot(
            Request::builder()
                .uri("/v3/auth/projects")
                .header("x-auth-token", &tenant_token)
                .body(Body::empty())?,
        )
        .await?;
    let body: Value =
        serde_json::from_slice(&axum::body::to_bytes(response.into_body(), 16 * 1024).await?)?;
    assert_eq!(
        body["projects"]
            .as_array()
            .ok_or("projects missing")?
            .iter()
            .filter_map(|project| project["id"].as_str())
            .collect::<Vec<_>>(),
        [tenant_b]
    );
    Ok(())
}

async fn get_with_token(
    router: &axum::Router,
    uri: &str,
    token: Option<(&str, &str)>,
) -> Result<axum::response::Response, Box<dyn std::error::Error>> {
    let mut request = Request::builder().uri(uri);
    if let Some((header_name, value)) = token {
        request = request.header(header_name, value);
    }
    Ok(router.clone().oneshot(request.body(Body::empty())?).await?)
}

#[tokio::test]
async fn keystone_user_projects_lists_own_authorized_projects()
-> Result<(), Box<dyn std::error::Error>> {
    let service = test_service("http://127.0.0.1:8080").await?;
    let router = o3k_api::router_with_state(o3k_api::AppState::new().with_identity(service));
    let (token, _) = issue_keystone_token(&router, unscoped_password_body()).await?;
    let response = get_with_token(
        &router,
        "/v3/users/bootstrap-user/projects",
        Some(("x-auth-token", &token)),
    )
    .await?;
    assert_eq!(response.status(), StatusCode::OK);
    let body: Value =
        serde_json::from_slice(&axum::body::to_bytes(response.into_body(), 16 * 1024).await?)?;
    let projects = body["projects"].as_array().ok_or("projects missing")?;
    assert_eq!(projects.len(), 1, "{body}");
    assert_eq!(projects[0]["id"], ADMIN_PROJECT_ID);
    assert_eq!(projects[0]["name"], "admin");
    assert_eq!(projects[0]["domain_id"], "default");
    assert_eq!(projects[0]["enabled"], true);
    Ok(())
}

#[tokio::test]
async fn keystone_user_projects_accepts_project_scoped_token()
-> Result<(), Box<dyn std::error::Error>> {
    let service = test_service("http://127.0.0.1:8080").await?;
    let router = o3k_api::router_with_state(o3k_api::AppState::new().with_identity(service));
    let (token, _) = issue_keystone_token(&router, project_scoped_password_body()).await?;

    let response = get_with_token(
        &router,
        "/v3/users/bootstrap-user/projects",
        Some(("x-auth-token", &token)),
    )
    .await?;
    assert_eq!(response.status(), StatusCode::OK);
    let body: Value =
        serde_json::from_slice(&axum::body::to_bytes(response.into_body(), 16 * 1024).await?)?;
    assert_eq!(body["projects"][0]["id"], ADMIN_PROJECT_ID);

    // The sibling `/v3/auth/projects` route and the per-user route project the
    // same capability, so both must return the identical body.
    let sibling = get_with_token(
        &router,
        "/v3/auth/projects",
        Some(("x-subject-token", &token)),
    )
    .await?;
    assert_eq!(sibling.status(), StatusCode::OK);
    let sibling_body: Value =
        serde_json::from_slice(&axum::body::to_bytes(sibling.into_body(), 16 * 1024).await?)?;
    assert_eq!(body, sibling_body);
    Ok(())
}

/// The bounded `GET /v3/projects` listing the unmodified Horizon 2026.1
/// Instances panel needs to resolve a server's project name. It is authorized
/// as a project-visibility read, never as Keystone project administration.
#[tokio::test]
async fn keystone_projects_lists_only_projects_authorized_for_the_caller()
-> Result<(), Box<dyn std::error::Error>> {
    let service = test_service("http://127.0.0.1:8080").await?;
    let router = o3k_api::router_with_state(o3k_api::AppState::new().with_identity(service));
    let (token, _) = issue_keystone_token(&router, project_scoped_password_body()).await?;
    let response = get_with_token(&router, "/v3/projects", Some(("x-auth-token", &token))).await?;
    assert_eq!(response.status(), StatusCode::OK);
    let body: Value =
        serde_json::from_slice(&axum::body::to_bytes(response.into_body(), 16 * 1024).await?)?;
    let projects = body["projects"].as_array().ok_or("projects missing")?;
    assert_eq!(projects.len(), 1, "{body}");
    assert_eq!(projects[0]["id"], ADMIN_PROJECT_ID);
    assert_eq!(projects[0]["name"], "admin");
    assert_eq!(projects[0]["domain_id"], "default");
    assert_eq!(projects[0]["enabled"], true);
    // The listing is the same authorization question as scope discovery, so a
    // caller must not be able to observe a project through one route that it
    // cannot observe through the other.
    let discovery =
        get_with_token(&router, "/v3/auth/projects", Some(("x-auth-token", &token))).await?;
    let discovery_body: Value =
        serde_json::from_slice(&axum::body::to_bytes(discovery.into_body(), 16 * 1024).await?)?;
    assert_eq!(body, discovery_body);
    Ok(())
}

#[tokio::test]
async fn keystone_projects_accepts_unscoped_token_with_the_bounded_contract()
-> Result<(), Box<dyn std::error::Error>> {
    // Bounded deviation, deliberately defined: an identity-only token is
    // sufficient to ask which projects its identity can reach, but the answer
    // is still filtered to that identity's durable assignments.
    let service = test_service("http://127.0.0.1:8080").await?;
    let router = o3k_api::router_with_state(o3k_api::AppState::new().with_identity(service));
    let (token, _) = issue_keystone_token(&router, unscoped_password_body()).await?;
    let response = get_with_token(&router, "/v3/projects", Some(("x-auth-token", &token))).await?;
    assert_eq!(response.status(), StatusCode::OK);
    let body: Value =
        serde_json::from_slice(&axum::body::to_bytes(response.into_body(), 16 * 1024).await?)?;
    let ids: Vec<&str> = body["projects"]
        .as_array()
        .ok_or("projects missing")?
        .iter()
        .filter_map(|project| project["id"].as_str())
        .collect();
    assert_eq!(ids, [ADMIN_PROJECT_ID], "{body}");
    Ok(())
}

#[tokio::test]
async fn keystone_projects_rejects_invalid_missing_and_expired_tokens()
-> Result<(), Box<dyn std::error::Error>> {
    let service = test_service("http://127.0.0.1:8080").await?;
    let request: o3k_identity::TokenRequest = serde_json::from_value(unscoped_password_body())?;
    let (expired, _) = service.issue(&request, SystemTime::now() - Duration::from_secs(7_200))?;
    let router = o3k_api::router_with_state(o3k_api::AppState::new().with_identity(service));
    for header_value in [Some("not-a-token"), Some("a.b.c"), None, Some(&expired)] {
        let response = get_with_token(
            &router,
            "/v3/projects",
            header_value.map(|value| ("x-auth-token", value)),
        )
        .await?;
        assert_eq!(
            response.status(),
            StatusCode::UNAUTHORIZED,
            "header {header_value:?}"
        );
        let text = String::from_utf8(
            axum::body::to_bytes(response.into_body(), 4096)
                .await?
                .to_vec(),
        )?;
        if let Some(value) = header_value {
            assert!(!text.contains(value), "{text}");
        }
    }
    Ok(())
}

#[tokio::test]
async fn keystone_projects_never_returns_unrelated_projects()
-> Result<(), Box<dyn std::error::Error>> {
    let tenant_b = "8d1f3c4a-5b6e-4f2a-9c3d-1e2f3a4b5c6d";
    let service = test_service_with_projects(
        "http://127.0.0.1:8080",
        vec![ExtraProjectSeed {
            project_id: tenant_b.to_owned(),
            project_name: "tenant-b".to_owned(),
            user_id: "a7c2e9d1-4f3b-4c8e-9d2a-3b4c5d6e7f8a".to_owned(),
            user_name: "tenant-b-user".to_owned(),
            password: Secret::new("tenant-b-password".to_owned()),
        }],
    )
    .await?;
    let router = o3k_api::router_with_state(o3k_api::AppState::new().with_identity(service));
    for (body, expected, foreign) in [
        (unscoped_password_body(), ADMIN_PROJECT_ID, tenant_b),
        (
            unscoped_password_body_for("tenant-b-user", "tenant-b-password"),
            tenant_b,
            ADMIN_PROJECT_ID,
        ),
    ] {
        let (token, _) = issue_keystone_token(&router, body).await?;
        let response =
            get_with_token(&router, "/v3/projects", Some(("x-auth-token", &token))).await?;
        assert_eq!(response.status(), StatusCode::OK);
        let listed: Value =
            serde_json::from_slice(&axum::body::to_bytes(response.into_body(), 16 * 1024).await?)?;
        let ids: Vec<&str> = listed["projects"]
            .as_array()
            .ok_or("projects missing")?
            .iter()
            .filter_map(|project| project["id"].as_str())
            .collect();
        assert_eq!(ids, [expected], "{listed}");
        assert!(!ids.contains(&foreign), "{listed}");
        // `service-project` is a stored project the caller holds no role on.
        assert!(!ids.contains(&"service-project"), "{listed}");
    }
    Ok(())
}

#[tokio::test]
async fn keystone_projects_returns_empty_list_for_identity_without_assignment()
-> Result<(), Box<dyn std::error::Error>> {
    let service = o3k_identity::testkit::test_service_with_unassigned_user(
        "http://127.0.0.1:8080",
        "unassigned-user",
        "unassigned",
        "unassigned-password",
    )
    .await?;
    let router = o3k_api::router_with_state(o3k_api::AppState::new().with_identity(service));
    // An identity-only token is issued without any role assignment; the listing
    // must answer with an empty set rather than with the stored projects.
    let (token, _) = issue_keystone_token(
        &router,
        unscoped_password_body_for("unassigned", "unassigned-password"),
    )
    .await?;
    let response = get_with_token(&router, "/v3/projects", Some(("x-auth-token", &token))).await?;
    assert_eq!(response.status(), StatusCode::OK);
    let body: Value =
        serde_json::from_slice(&axum::body::to_bytes(response.into_body(), 16 * 1024).await?)?;
    assert_eq!(body["projects"].as_array().map(Vec::len), Some(0), "{body}");
    let text = body.to_string();
    assert!(!text.contains(ADMIN_PROJECT_ID), "{text}");
    assert!(!text.contains("service-project"), "{text}");
    Ok(())
}

#[tokio::test]
async fn keystone_user_projects_rejects_invalid_and_missing_tokens()
-> Result<(), Box<dyn std::error::Error>> {
    let service = test_service("http://127.0.0.1:8080").await?;
    let router = o3k_api::router_with_state(o3k_api::AppState::new().with_identity(service));
    for header_value in [Some("not-a-token"), Some("a.b.c"), None] {
        let response = get_with_token(
            &router,
            "/v3/users/bootstrap-user/projects",
            header_value.map(|value| ("x-auth-token", value)),
        )
        .await?;
        assert_eq!(
            response.status(),
            StatusCode::UNAUTHORIZED,
            "header {header_value:?}"
        );
        let text = String::from_utf8(
            axum::body::to_bytes(response.into_body(), 4096)
                .await?
                .to_vec(),
        )?;
        if let Some(value) = header_value {
            assert!(!text.contains(value));
        }
    }
    Ok(())
}

#[tokio::test]
async fn keystone_user_projects_never_leaks_another_subject()
-> Result<(), Box<dyn std::error::Error>> {
    let service = test_service("http://127.0.0.1:8080").await?;
    let router = o3k_api::router_with_state(o3k_api::AppState::new().with_identity(service));
    let (admin_token, _) = issue_keystone_token(&router, unscoped_password_body()).await?;

    let mut bodies = Vec::new();
    // `cinder` is a real durable user in the bootstrap universe; the second id
    // does not exist. Both must be indistinguishable.
    for foreign in ["cinder", "00000000-0000-0000-0000-000000000000"] {
        let response = get_with_token(
            &router,
            &format!("/v3/users/{foreign}/projects"),
            Some(("x-auth-token", &admin_token)),
        )
        .await?;
        assert_eq!(response.status(), StatusCode::FORBIDDEN, "{foreign}");
        let text = String::from_utf8(
            axum::body::to_bytes(response.into_body(), 4096)
                .await?
                .to_vec(),
        )?;
        assert!(!text.contains(ADMIN_PROJECT_ID), "{foreign}: {text}");
        assert!(!text.contains("\"admin\""), "{foreign}: {text}");
        assert!(!text.contains("service-project"), "{foreign}: {text}");
        bodies.push(text);
    }
    assert_eq!(
        bodies[0], bodies[1],
        "an unknown user and a foreign existing user must be indistinguishable"
    );

    // The caller's own list is still reachable, so the 403 is about the id.
    let own = get_with_token(
        &router,
        "/v3/users/bootstrap-user/projects",
        Some(("x-auth-token", &admin_token)),
    )
    .await?;
    assert_eq!(own.status(), StatusCode::OK);
    Ok(())
}

#[tokio::test]
async fn keystone_user_projects_returns_empty_without_assignments()
-> Result<(), Box<dyn std::error::Error>> {
    let service = test_service("http://127.0.0.1:8080").await?;
    let mut snapshot = service.snapshot().clone();
    snapshot.users.push(o3k_identity::SnapshotUser {
        id: "roleless-user".to_owned(),
        domain_id: "default".to_owned(),
        name: "roleless".to_owned(),
        password_hash: o3k_identity::PasswordHash::derive_with_iterations_for_testing(
            "password", 1_000,
        )?,
        enabled: true,
    });
    let service = o3k_identity::TokenService::from_snapshot(
        snapshot,
        Secret::new("a-secure-signing-key-with-at-least-32-bytes".to_owned()),
        Duration::from_secs(3600),
    )?;
    let router = o3k_api::router_with_state(o3k_api::AppState::new().with_identity(service));
    let (token, _) =
        issue_keystone_token(&router, unscoped_password_body_for("roleless", "password")).await?;
    let response = get_with_token(
        &router,
        "/v3/users/roleless-user/projects",
        Some(("x-auth-token", &token)),
    )
    .await?;
    assert_eq!(response.status(), StatusCode::OK);
    let body: Value =
        serde_json::from_slice(&axum::body::to_bytes(response.into_body(), 16 * 1024).await?)?;
    assert_eq!(body, serde_json::json!({"projects": []}));
    Ok(())
}

#[tokio::test]
async fn keystone_user_projects_rejects_expired_token() -> Result<(), Box<dyn std::error::Error>> {
    let service = test_service("http://127.0.0.1:8080").await?;
    let request: o3k_identity::TokenRequest = serde_json::from_value(unscoped_password_body())?;
    let (expired, _) = service.issue(&request, SystemTime::now() - Duration::from_secs(7_200))?;
    let router = o3k_api::router_with_state(o3k_api::AppState::new().with_identity(service));
    let response = get_with_token(
        &router,
        "/v3/users/bootstrap-user/projects",
        Some(("x-auth-token", &expired)),
    )
    .await?;
    assert_eq!(response.status(), StatusCode::UNAUTHORIZED);
    Ok(())
}

#[tokio::test]
async fn keystone_unscoped_token_cannot_authorize_compatibility_or_native_routes()
-> Result<(), Box<dyn std::error::Error>> {
    let root = std::path::PathBuf::from(format!(
        "/tmp/o3k-api-unscoped-gate-{}",
        uuid::Uuid::now_v7()
    ));
    let _ = std::fs::remove_dir_all(&root);
    let identity = test_service("http://127.0.0.1:8080").await?;
    let store = Arc::new(o3k_store::testkit::open_memory().await?);
    let image = ImageService::open_for_test(&root, DEFAULT_MAX_UPLOAD_BYTES, store).await?;
    let native = o3k_native_api::NativeApiState::new(
        None,
        o3k_native_api::pagination::CursorConfig::default(),
        Some(Arc::new(IdentityBackedIssuer(Arc::new(identity.clone())))),
        None,
        None,
        None,
    )?;
    let state = o3k_api::AppState::new()
        .with_identity(identity)
        .with_image(image)
        .with_native_api(native);
    let router = o3k_api::router_with_state(state);

    let (unscoped, _) = issue_keystone_token(&router, unscoped_password_body()).await?;
    let (scoped, _) = issue_keystone_token(&router, project_scoped_password_body()).await?;

    // Glance compatibility route: the project-scoped token is accepted, the
    // unscoped token is rejected with 401.
    let scoped_images = router
        .clone()
        .oneshot(
            Request::builder()
                .uri("/v2/images")
                .header("x-auth-token", &scoped)
                .body(Body::empty())?,
        )
        .await?;
    assert_eq!(scoped_images.status(), StatusCode::OK);
    let unscoped_images = router
        .clone()
        .oneshot(
            Request::builder()
                .uri("/v2/images")
                .header("x-auth-token", &unscoped)
                .body(Body::empty())?,
        )
        .await?;
    assert_eq!(unscoped_images.status(), StatusCode::UNAUTHORIZED);

    // Native /o3k/v1 route: the same authorization boundary applies.
    let scoped_native = router
        .clone()
        .oneshot(
            Request::builder()
                .uri("/o3k/v1/identity/me")
                .header("authorization", format!("Bearer {scoped}"))
                .body(Body::empty())?,
        )
        .await?;
    assert_eq!(scoped_native.status(), StatusCode::OK);
    let unscoped_native = router
        .clone()
        .oneshot(
            Request::builder()
                .uri("/o3k/v1/identity/me")
                .header("authorization", format!("Bearer {unscoped}"))
                .body(Body::empty())?,
        )
        .await?;
    assert_eq!(unscoped_native.status(), StatusCode::UNAUTHORIZED);
    Ok(())
}

#[tokio::test]
async fn keystone_project_scoped_password_auth_still_returns_project_roles_and_catalog()
-> Result<(), Box<dyn std::error::Error>> {
    let service = test_service("http://127.0.0.1:8080").await?;
    let router = o3k_api::router_with_state(o3k_api::AppState::new().with_identity(service));
    let (_, body) = issue_keystone_token(&router, project_scoped_password_body()).await?;
    assert_eq!(body["token"]["project"]["id"], ADMIN_PROJECT_ID);
    assert_eq!(body["token"]["project"]["name"], "admin");
    let roles = body["token"]["roles"].as_array().ok_or("roles missing")?;
    assert!(roles.iter().any(|role| role["name"] == "admin"));
    assert!(roles.iter().any(|role| role["name"] == "member"));
    let catalog = body["token"]["catalog"]
        .as_array()
        .ok_or("catalog missing")?;
    assert!(!catalog.is_empty());
    assert!(catalog.iter().any(|service| service["type"] == "identity"));
    Ok(())
}

/// The canonical OpenStack/Horizon unscoped password body: the user is
/// identified by name inside its domain. The pinned client sends this exact
/// shape, so the bounded profile must accept it with the user domain present
/// rather than treating domain-less identification as the only supported form.
fn horizon_unscoped_password_body() -> Value {
    serde_json::json!({
        "auth": {
            "identity": {
                "methods": ["password"],
                "password": {
                    "user": {
                        "name": "admin",
                        "domain": {"name": "Default"},
                        "password": "password"
                    }
                }
            }
        }
    })
}

#[tokio::test]
async fn keystone_unscoped_auth_accepts_the_canonical_horizon_user_domain_form()
-> Result<(), Box<dyn std::error::Error>> {
    let service = test_service("http://127.0.0.1:8080").await?;
    let router = o3k_api::router_with_state(o3k_api::AppState::new().with_identity(service));
    let mut explicit_unscoped = horizon_unscoped_password_body();
    explicit_unscoped["auth"]["scope"] = serde_json::json!("unscoped");
    for body in [horizon_unscoped_password_body(), explicit_unscoped] {
        let (_, token_body) = issue_keystone_token(&router, body.clone()).await?;
        assert_unscoped_token_body(&token_body);
    }
    Ok(())
}

/// The bounded login sequence the pinned, unmodified Horizon 2026.1 client
/// performs, end to end against real identity routes: unscoped password
/// authentication, available-scope discovery under the route `keystoneclient`
/// actually issues, project-scoped authentication with the discovered project,
/// the Instances-panel project listing, and finally a compatibility request
/// authorized by the resulting scoped session. Nothing about the identity
/// boundary is mocked.
#[tokio::test]
async fn keystone_horizon_login_sequence_establishes_a_usable_scoped_session()
-> Result<(), Box<dyn std::error::Error>> {
    let root = std::path::PathBuf::from(format!(
        "/tmp/o3k-api-horizon-login-{}",
        uuid::Uuid::now_v7()
    ));
    let _ = std::fs::remove_dir_all(&root);
    let identity = test_service("http://127.0.0.1:8080").await?;
    let store = Arc::new(o3k_store::testkit::open_memory().await?);
    let image = ImageService::open_for_test(&root, DEFAULT_MAX_UPLOAD_BYTES, store).await?;
    let router = o3k_api::router_with_state(
        o3k_api::AppState::new()
            .with_identity(identity)
            .with_image(image),
    );

    // Step 1: unscoped password authentication.
    let (unscoped, unscoped_body) =
        issue_keystone_token(&router, horizon_unscoped_password_body()).await?;
    assert_unscoped_token_body(&unscoped_body);

    // Step 2: available-scope discovery.
    let discovered = get_with_token(
        &router,
        "/v3/users/bootstrap-user/projects",
        Some(("x-auth-token", &unscoped)),
    )
    .await?;
    assert_eq!(discovered.status(), StatusCode::OK);
    let discovered_body: Value =
        serde_json::from_slice(&axum::body::to_bytes(discovered.into_body(), 16 * 1024).await?)?;
    let project_id = discovered_body["projects"][0]["id"]
        .as_str()
        .ok_or("discovered project id missing")?
        .to_owned();

    // Step 3: project-scoped authentication for the discovered project.
    let (scoped, scoped_body) =
        issue_keystone_token(&router, project_scoped_password_body()).await?;
    assert_eq!(scoped_body["token"]["project"]["id"], project_id);

    // Step 4: the project listing the Instances panel resolves names through.
    let projects = get_with_token(&router, "/v3/projects", Some(("x-auth-token", &scoped))).await?;
    assert_eq!(projects.status(), StatusCode::OK);
    let projects_body: Value =
        serde_json::from_slice(&axum::body::to_bytes(projects.into_body(), 16 * 1024).await?)?;
    assert!(
        projects_body["projects"]
            .as_array()
            .ok_or("projects missing")?
            .iter()
            .any(|project| project["id"] == project_id),
        "{projects_body}"
    );

    // Step 5: the scoped session authorizes a compatibility request while the
    // identity-only token still cannot.
    let scoped_images =
        get_with_token(&router, "/v2/images", Some(("x-auth-token", &scoped))).await?;
    assert_eq!(scoped_images.status(), StatusCode::OK);
    let unscoped_images =
        get_with_token(&router, "/v2/images", Some(("x-auth-token", &unscoped))).await?;
    assert_eq!(unscoped_images.status(), StatusCode::UNAUTHORIZED);
    Ok(())
}

#[tokio::test]
async fn glance_image_lifecycle_is_project_scoped_and_immutable_after_upload()
-> Result<(), Box<dyn std::error::Error>> {
    let root = std::path::PathBuf::from(format!("/tmp/o3k-api-images-{}", std::process::id()));
    let identity = test_service("http://127.0.0.1:8080").await?;
    let store = std::sync::Arc::new(o3k_store::testkit::open_memory().await?);
    let image = ImageService::open_for_test(&root, DEFAULT_MAX_UPLOAD_BYTES, store).await?;
    let state = o3k_api::AppState::new()
        .with_identity(identity)
        .with_image(image);
    let auth_body = serde_json::json!({"auth":{"identity":{"methods":["password"],"password":{"user":{"name":"admin","password":"password"}}},"scope":{"project":{"name":"admin"}}}});
    let auth_response = o3k_api::router_with_state(state.clone())
        .oneshot(
            Request::builder()
                .method(Method::POST)
                .uri("/v3/auth/tokens")
                .header(header::CONTENT_TYPE, "application/json")
                .body(Body::from(auth_body.to_string()))?,
        )
        .await?;
    let token = auth_response
        .headers()
        .get("x-subject-token")
        .ok_or_else(|| std::io::Error::other("token missing"))?
        .to_str()?
        .to_owned();
    let create_body = serde_json::json!({"name":"test-image","visibility":"private","container_format":"bare","disk_format":"raw"});
    let create_response = o3k_api::router_with_state(state.clone())
        .oneshot(
            Request::builder()
                .method(Method::POST)
                .uri("/v2/images")
                .header("x-auth-token", &token)
                .header(header::CONTENT_TYPE, "application/json")
                .body(Body::from(create_body.to_string()))?,
        )
        .await?;
    assert_eq!(create_response.status(), StatusCode::CREATED);
    let create_json: Value =
        serde_json::from_slice(&axum::body::to_bytes(create_response.into_body(), 4096).await?)?;
    let id = create_json["id"]
        .as_str()
        .ok_or_else(|| std::io::Error::other("image id missing"))?
        .to_owned();
    let checksum_mismatch = o3k_api::router_with_state(state.clone())
        .oneshot(
            Request::builder()
                .method(Method::PUT)
                .uri(format!("/v2/images/{id}/file"))
                .header("x-auth-token", &token)
                .header(header::CONTENT_TYPE, "application/octet-stream")
                .header("x-openstack-image-sha256", "00")
                .body(Body::from("image-content"))?,
        )
        .await?;
    assert_eq!(checksum_mismatch.status(), StatusCode::BAD_REQUEST);
    let upload_response = o3k_api::router_with_state(state.clone())
        .oneshot(
            Request::builder()
                .method(Method::PUT)
                .uri(format!("/v2/images/{id}/file"))
                .header("x-auth-token", &token)
                .header(header::CONTENT_TYPE, "application/octet-stream")
                .body(Body::from("image-content"))?,
        )
        .await?;
    assert_eq!(upload_response.status(), StatusCode::NO_CONTENT);
    let second_upload = o3k_api::router_with_state(state.clone())
        .oneshot(
            Request::builder()
                .method(Method::PUT)
                .uri(format!("/v2/images/{id}/file"))
                .header("x-auth-token", &token)
                .header(header::CONTENT_TYPE, "application/octet-stream")
                .body(Body::from("changed"))?,
        )
        .await?;
    assert_eq!(second_upload.status(), StatusCode::CONFLICT);
    let show_response = o3k_api::router_with_state(state.clone())
        .oneshot(
            Request::builder()
                .uri(format!("/v2/images/{id}"))
                .header("x-auth-token", &token)
                .body(Body::empty())?,
        )
        .await?;
    let show_json: Value =
        serde_json::from_slice(&axum::body::to_bytes(show_response.into_body(), 4096).await?)?;
    assert_eq!(show_json["status"], "active");
    assert_eq!(show_json["size"], 13);
    let download_response = o3k_api::router_with_state(state.clone())
        .oneshot(
            Request::builder()
                .method(Method::GET)
                .uri(format!("/v2/images/{id}/file"))
                .header("x-auth-token", &token)
                .body(Body::empty())?,
        )
        .await?;
    assert_eq!(download_response.status(), StatusCode::OK);
    assert_eq!(
        download_response.headers()[header::CONTENT_TYPE],
        "application/octet-stream"
    );
    assert_eq!(download_response.headers()[header::CONTENT_LENGTH], "13");
    assert_eq!(
        axum::body::to_bytes(download_response.into_body(), 4096).await?,
        "image-content"
    );
    let invalid_format = o3k_api::router_with_state(state.clone())
        .oneshot(
            Request::builder()
                .method(Method::POST)
                .uri("/v2/images")
                .header("x-auth-token", &token)
                .header(header::CONTENT_TYPE, "application/json")
                .body(Body::from(
                    r#"{"name":"invalid","visibility":"private","container_format":"bare","disk_format":"vmdk"}"#,
                ))?,
        )
        .await?;
    assert_eq!(invalid_format.status(), StatusCode::BAD_REQUEST);
    let delete_response = o3k_api::router_with_state(state.clone())
        .oneshot(
            Request::builder()
                .method(Method::DELETE)
                .uri(format!("/v2/images/{id}"))
                .header("x-auth-token", &token)
                .body(Body::empty())?,
        )
        .await?;
    assert_eq!(delete_response.status(), StatusCode::NO_CONTENT);
    std::fs::remove_dir_all(root)?;
    Ok(())
}

#[tokio::test]
async fn glance_upload_rejects_corrupt_qcow2_with_terminal_bad_request()
-> Result<(), Box<dyn std::error::Error>> {
    let root = std::path::PathBuf::from(format!("/tmp/o3k-api-truncated-{}", std::process::id()));
    let _ = std::fs::remove_dir_all(&root);
    let identity = test_service("http://127.0.0.1:8080").await?;
    let store = std::sync::Arc::new(o3k_store::testkit::open_memory().await?);
    let image = ImageService::open_for_test(&root, DEFAULT_MAX_UPLOAD_BYTES, store).await?;
    let state = o3k_api::AppState::new()
        .with_identity(identity)
        .with_image(image);
    let auth_body = serde_json::json!({"auth":{"identity":{"methods":["password"],"password":{"user":{"name":"admin","password":"password"}}},"scope":{"project":{"name":"admin"}}}});
    let auth_response = o3k_api::router_with_state(state.clone())
        .oneshot(
            Request::builder()
                .method(Method::POST)
                .uri("/v3/auth/tokens")
                .header(header::CONTENT_TYPE, "application/json")
                .body(Body::from(auth_body.to_string()))?,
        )
        .await?;
    let token = auth_response
        .headers()
        .get("x-subject-token")
        .ok_or_else(|| std::io::Error::other("token missing"))?
        .to_str()?
        .to_owned();
    let create_response = o3k_api::router_with_state(state.clone())
        .oneshot(
            Request::builder()
                .method(Method::POST)
                .uri("/v2/images")
                .header("x-auth-token", &token)
                .header(header::CONTENT_TYPE, "application/json")
                .body(Body::from(
                    r#"{"name":"truncated","visibility":"private","container_format":"bare","disk_format":"qcow2"}"#,
                ))?,
        )
        .await?;
    assert_eq!(create_response.status(), StatusCode::CREATED);
    let create_json: Value =
        serde_json::from_slice(&axum::body::to_bytes(create_response.into_body(), 4096).await?)?;
    let id = create_json["id"]
        .as_str()
        .ok_or_else(|| std::io::Error::other("image id missing"))?
        .to_owned();
    // A qcow2-looking prefix whose structures point beyond the payload is a
    // truncated image; the upload must fail terminally with 400 before the
    // record can become active.
    let mut truncated = vec![0_u8; 4096];
    truncated[0..4].copy_from_slice(b"QFI\xfb");
    truncated[4..8].copy_from_slice(&3_u32.to_be_bytes());
    let upload_response = o3k_api::router_with_state(state.clone())
        .oneshot(
            Request::builder()
                .method(Method::PUT)
                .uri(format!("/v2/images/{id}/file"))
                .header("x-auth-token", &token)
                .header(header::CONTENT_TYPE, "application/octet-stream")
                .body(Body::from(truncated))?,
        )
        .await?;
    assert_eq!(upload_response.status(), StatusCode::BAD_REQUEST);
    let show_response = o3k_api::router_with_state(state.clone())
        .oneshot(
            Request::builder()
                .uri(format!("/v2/images/{id}"))
                .header("x-auth-token", &token)
                .body(Body::empty())?,
        )
        .await?;
    let show_json: Value =
        serde_json::from_slice(&axum::body::to_bytes(show_response.into_body(), 4096).await?)?;
    assert_eq!(show_json["status"], "queued");
    assert_eq!(show_json["size"], Value::Null);
    std::fs::remove_dir_all(root)?;
    Ok(())
}

#[tokio::test]
async fn neutron_network_subnet_port_lifecycle_is_deterministic()
-> Result<(), Box<dyn std::error::Error>> {
    let root = std::path::PathBuf::from(format!("/tmp/o3k-api-network-{}", std::process::id()));
    let _ = std::fs::remove_dir_all(&root);
    let identity = test_service("http://127.0.0.1:8080").await?;
    let state = o3k_api::AppState::new()
        .with_identity(identity)
        .with_network(
            NetworkService::open_for_test(
                &root,
                std::sync::Arc::new(o3k_store::testkit::open_memory().await?),
            )
            .await?,
        );
    let auth = serde_json::json!({"auth":{"identity":{"methods":["password"],"password":{"user":{"name":"admin","password":"password"}}},"scope":{"project":{"name":"admin"}}}});
    let response = o3k_api::router_with_state(state.clone())
        .oneshot(
            Request::builder()
                .method(Method::POST)
                .uri("/v3/auth/tokens")
                .header(header::CONTENT_TYPE, "application/json")
                .body(Body::from(auth.to_string()))?,
        )
        .await?;
    let token = response
        .headers()
        .get("x-subject-token")
        .ok_or_else(|| std::io::Error::other("token missing"))?
        .to_str()?
        .to_owned();
    let extensions = o3k_api::router_with_state(state.clone())
        .oneshot(
            Request::builder()
                .uri("/v2.0/extensions")
                .header("x-auth-token", &token)
                .body(Body::empty())?,
        )
        .await?;
    assert_eq!(extensions.status(), StatusCode::OK);
    assert_eq!(
        serde_json::from_slice::<Value>(
            &axum::body::to_bytes(extensions.into_body(), 4096).await?
        )?,
        serde_json::json!({"extensions": []})
    );
    let body = serde_json::json!({"network":{"name":"flat"}});
    let response = o3k_api::router_with_state(state.clone())
        .oneshot(
            Request::builder()
                .method(Method::POST)
                .uri("/v2.0/networks")
                .header("x-auth-token", &token)
                .header(header::CONTENT_TYPE, "application/json")
                .body(Body::from(body.to_string()))?,
        )
        .await?;
    assert_eq!(response.status(), StatusCode::CREATED);
    let network: Value =
        serde_json::from_slice(&axum::body::to_bytes(response.into_body(), 4096).await?)?;
    let network_id = network["network"]["id"]
        .as_str()
        .ok_or_else(|| std::io::Error::other("network id missing"))?
        .to_owned();
    let renamed = o3k_api::router_with_state(state.clone())
        .oneshot(
            Request::builder()
                .method(Method::PUT)
                .uri(format!("/v2.0/networks/{network_id}"))
                .header("x-auth-token", &token)
                .header(header::CONTENT_TYPE, "application/json")
                .body(Body::from(
                    r#"{"network":{"name":"flat-renamed","admin_state_up":true}}"#,
                ))?,
        )
        .await?;
    assert_eq!(renamed.status(), StatusCode::OK);
    let renamed_json: Value =
        serde_json::from_slice(&axum::body::to_bytes(renamed.into_body(), 4096).await?)?;
    assert_eq!(renamed_json["network"]["id"], network_id);
    assert_eq!(renamed_json["network"]["name"], "flat-renamed");
    assert_eq!(renamed_json["network"]["admin_state_up"], true);
    let admin_only = o3k_api::router_with_state(state.clone())
        .oneshot(
            Request::builder()
                .method(Method::PUT)
                .uri(format!("/v2.0/networks/{network_id}"))
                .header("x-auth-token", &token)
                .header(header::CONTENT_TYPE, "application/json")
                .body(Body::from(r#"{"network":{"admin_state_up":false}}"#))?,
        )
        .await?;
    assert_eq!(admin_only.status(), StatusCode::OK);
    let admin_only_json: Value =
        serde_json::from_slice(&axum::body::to_bytes(admin_only.into_body(), 4096).await?)?;
    assert_eq!(admin_only_json["network"]["name"], "flat-renamed");
    assert_eq!(admin_only_json["network"]["admin_state_up"], false);
    let both = o3k_api::router_with_state(state.clone())
        .oneshot(
            Request::builder()
                .method(Method::PUT)
                .uri(format!("/v2.0/networks/{network_id}"))
                .header("x-auth-token", &token)
                .header(header::CONTENT_TYPE, "application/json")
                .body(Body::from(
                    r#"{"network":{"name":"flat-final","admin_state_up":true}}"#,
                ))?,
        )
        .await?;
    assert_eq!(both.status(), StatusCode::OK);
    let both_json: Value =
        serde_json::from_slice(&axum::body::to_bytes(both.into_body(), 4096).await?)?;
    assert_eq!(both_json["network"]["name"], "flat-final");
    assert_eq!(both_json["network"]["admin_state_up"], true);
    let invalid_name = o3k_api::router_with_state(state.clone())
        .oneshot(
            Request::builder()
                .method(Method::PUT)
                .uri(format!("/v2.0/networks/{network_id}"))
                .header("x-auth-token", &token)
                .header(header::CONTENT_TYPE, "application/json")
                .body(Body::from(r#"{"network":{"name":""}}"#))?,
        )
        .await?;
    assert_eq!(invalid_name.status(), StatusCode::BAD_REQUEST);
    let body = serde_json::json!({"subnet":{"network_id":network_id,"cidr":"192.0.2.0/29","ip_version":4,"enable_dhcp":false}});
    let response = o3k_api::router_with_state(state.clone())
        .oneshot(
            Request::builder()
                .method(Method::POST)
                .uri("/v2.0/subnets")
                .header("x-auth-token", &token)
                .header(header::CONTENT_TYPE, "application/json")
                .body(Body::from(body.to_string()))?,
        )
        .await?;
    assert_eq!(response.status(), StatusCode::CREATED);
    let subnet: Value =
        serde_json::from_slice(&axum::body::to_bytes(response.into_body(), 4096).await?)?;
    assert_eq!(subnet["subnet"]["gateway_ip"], "192.0.2.1");
    assert_eq!(subnet["subnet"]["name"], "");
    assert_eq!(subnet["subnet"]["enable_dhcp"], false);
    let network_after_subnet = o3k_api::router_with_state(state.clone())
        .oneshot(
            Request::builder()
                .uri(format!("/v2.0/networks/{network_id}"))
                .header("x-auth-token", &token)
                .body(Body::empty())?,
        )
        .await?;
    let network_after_subnet_json: Value = serde_json::from_slice(
        &axum::body::to_bytes(network_after_subnet.into_body(), 4096).await?,
    )?;
    assert_eq!(
        network_after_subnet_json["network"]["subnets"],
        serde_json::json!([subnet["subnet"]["id"]])
    );
    let second = o3k_api::router_with_state(state.clone())
        .oneshot(
            Request::builder()
                .method(Method::POST)
                .uri("/v2.0/subnets")
                .header("x-auth-token", &token)
                .header(header::CONTENT_TYPE, "application/json")
                .body(Body::from(format!(
                    r#"{{"subnet":{{"network_id":"{network_id}","cidr":"198.51.100.0/29","ip_version":4}}}}"#
                )))?,
        )
        .await?;
    assert_eq!(second.status(), StatusCode::CONFLICT);
    let subnet_update = o3k_api::router_with_state(state.clone())
        .oneshot(
            Request::builder()
                .method(Method::PUT)
                .uri(format!(
                    "/v2.0/subnets/{}",
                    subnet["subnet"]["id"].as_str().unwrap_or_default()
                ))
                .header("x-auth-token", &token)
                .header(header::CONTENT_TYPE, "application/json")
                .body(Body::from(r#"{"subnet":{"name":"renamed"}}"#))?,
        )
        .await?;
    assert_eq!(subnet_update.status(), StatusCode::OK);
    let subnet_update_json: Value =
        serde_json::from_slice(&axum::body::to_bytes(subnet_update.into_body(), 4096).await?)?;
    assert_eq!(subnet_update_json["subnet"]["name"], "renamed");
    let unsupported_pools = o3k_api::router_with_state(state.clone())
        .oneshot(
            Request::builder()
                .method(Method::POST)
                .uri("/v2.0/subnets")
                .header("x-auth-token", &token)
                .header(header::CONTENT_TYPE, "application/json")
                .body(Body::from(format!(
                    r#"{{"subnet":{{"name":"many-pools","network_id":"{network_id}","cidr":"198.51.100.0/29","allocation_pools":[{{"start":"198.51.100.2","end":"198.51.100.3"}},{{"start":"198.51.100.5","end":"198.51.100.6"}}]}}}}"#
                )))?,
        )
        .await?;
    assert_eq!(unsupported_pools.status(), StatusCode::BAD_REQUEST);
    let body = serde_json::json!({"port":{"name":"port-1","network_id":network_id}});
    let response = o3k_api::router_with_state(state.clone())
        .oneshot(
            Request::builder()
                .method(Method::POST)
                .uri("/v2.0/ports")
                .header("x-auth-token", &token)
                .header(header::CONTENT_TYPE, "application/json")
                .body(Body::from(body.to_string()))?,
        )
        .await?;
    assert_eq!(response.status(), StatusCode::CREATED);
    let port: Value =
        serde_json::from_slice(&axum::body::to_bytes(response.into_body(), 4096).await?)?;
    assert!(port["port"]["mac_address"].as_str().is_some());
    assert_eq!(port["port"]["fixed_ips"][0]["ip_address"], "192.0.2.2");
    let conflict = o3k_api::router_with_state(state.clone())
        .oneshot(
            Request::builder()
                .method(Method::DELETE)
                .uri(format!("/v2.0/networks/{network_id}"))
                .header("x-auth-token", &token)
                .body(Body::empty())?,
        )
        .await?;
    assert_eq!(conflict.status(), StatusCode::CONFLICT);
    let delete_port = o3k_api::router_with_state(state.clone())
        .oneshot(
            Request::builder()
                .method(Method::DELETE)
                .uri(format!(
                    "/v2.0/ports/{}",
                    port["port"]["id"].as_str().unwrap_or_default()
                ))
                .header("x-auth-token", &token)
                .body(Body::empty())?,
        )
        .await?;
    assert_eq!(delete_port.status(), StatusCode::NO_CONTENT);
    let delete_subnet = o3k_api::router_with_state(state.clone())
        .oneshot(
            Request::builder()
                .method(Method::DELETE)
                .uri(format!(
                    "/v2.0/subnets/{}",
                    subnet["subnet"]["id"].as_str().unwrap_or_default()
                ))
                .header("x-auth-token", &token)
                .body(Body::empty())?,
        )
        .await?;
    assert_eq!(delete_subnet.status(), StatusCode::NO_CONTENT);
    let delete_network = o3k_api::router_with_state(state)
        .oneshot(
            Request::builder()
                .method(Method::DELETE)
                .uri(format!("/v2.0/networks/{network_id}"))
                .header("x-auth-token", &token)
                .body(Body::empty())?,
        )
        .await?;
    assert_eq!(delete_network.status(), StatusCode::NO_CONTENT);
    std::fs::remove_dir_all(root)?;
    Ok(())
}

#[tokio::test]
async fn neutron_network_projection_reports_zero_and_multiple_realms()
-> Result<(), Box<dyn std::error::Error>> {
    let root = std::path::PathBuf::from(format!(
        "/tmp/o3k-api-network-projection-{}",
        uuid::Uuid::now_v7()
    ));
    let _ = std::fs::remove_dir_all(&root);
    let identity = test_service("http://127.0.0.1:8080").await?;
    let store = std::sync::Arc::new(o3k_store::testkit::open_memory().await?);
    let network = NetworkService::open_for_test(&root, store).await?;
    let project_id = "eba29e2d-53de-461d-ae91-ede7402713cb";
    let network_record = network
        .create_canonical_network_for_project(project_id, "projection".to_owned())
        .await?;
    let realm_a = network
        .create_canonical_realm_for_project(
            project_id,
            network_record.id,
            "10.40.0.0/24".to_owned(),
            false,
        )
        .await?;
    let realm_b = network
        .create_canonical_realm_for_project(
            project_id,
            network_record.id,
            "10.41.0.0/24".to_owned(),
            false,
        )
        .await?;
    let state = o3k_api::AppState::new()
        .with_identity(identity)
        .with_network(network.clone());
    let auth_body = serde_json::json!({"auth":{"identity":{"methods":["password"],"password":{"user":{"name":"admin","password":"password"}}},"scope":{"project":{"name":"admin"}}}});
    let token_response = o3k_api::router_with_state(state.clone())
        .oneshot(
            Request::builder()
                .method(Method::POST)
                .uri("/v3/auth/tokens")
                .header(header::CONTENT_TYPE, "application/json")
                .body(Body::from(auth_body.to_string()))?,
        )
        .await?;
    let token = token_response
        .headers()
        .get("x-subject-token")
        .ok_or("token missing")?
        .to_str()?
        .to_owned();

    let zero_network = network
        .create_canonical_network_for_project(project_id, "zero".to_owned())
        .await?;
    let zero_response = o3k_api::router_with_state(state.clone())
        .oneshot(
            Request::builder()
                .uri(format!("/v2.0/networks/{}", zero_network.id))
                .header("x-auth-token", &token)
                .body(Body::empty())?,
        )
        .await?;
    let zero_json: Value =
        serde_json::from_slice(&axum::body::to_bytes(zero_response.into_body(), 4096).await?)?;
    assert_eq!(zero_json["network"]["subnets"], serde_json::json!([]));

    let response = o3k_api::router_with_state(state)
        .oneshot(
            Request::builder()
                .uri(format!("/v2.0/networks/{}", network_record.id))
                .header("x-auth-token", &token)
                .body(Body::empty())?,
        )
        .await?;
    assert_eq!(response.status(), StatusCode::OK);
    let json: Value =
        serde_json::from_slice(&axum::body::to_bytes(response.into_body(), 4096).await?)?;
    assert_eq!(
        json["network"]["subnets"],
        serde_json::json!([realm_a.id.to_string(), realm_b.id.to_string()])
    );
    assert!(json["network"]["subnets"].as_array().is_some_and(|ids| {
        ids.windows(2)
            .all(|pair| pair[0].as_str().unwrap_or_default() < pair[1].as_str().unwrap_or_default())
    }));
    std::fs::remove_dir_all(root)?;
    Ok(())
}

#[tokio::test]
async fn nova_server_lifecycle_uses_project_scoped_envelopes()
-> Result<(), Box<dyn std::error::Error>> {
    let path = std::path::PathBuf::from(format!(
        "/tmp/o3k-api-compute-{}.sqlite",
        std::process::id()
    ));
    let _ = std::fs::remove_file(&path);
    let identity = test_service("http://127.0.0.1:8080").await?;
    let store = std::sync::Arc::new(o3k_store::testkit::open_file(&path).await?);
    let provider = std::sync::Arc::new(FakeComputeProvider::new());
    let compute = ComputeService::new_for_test(store, provider.clone());
    let network_root = std::path::PathBuf::from(format!(
        "/tmp/o3k-api-compute-network-{}",
        uuid::Uuid::now_v7()
    ));
    let network_service = NetworkService::open_for_test(
        &network_root,
        std::sync::Arc::new(o3k_store::testkit::open_memory().await?),
    )
    .await?;
    let network = network_service
        .create_network_for_project("eba29e2d-53de-461d-ae91-ede7402713cb", "flat".to_owned())
        .await?;
    let _subnet = network_service
        .create_subnet_for_project(
            "eba29e2d-53de-461d-ae91-ede7402713cb",
            network.id,
            "subnet".to_owned(),
            "192.0.2.0/29".to_owned(),
            None,
            None,
            None,
        )
        .await?;
    let port = network_service
        .create_port_for_project(
            "eba29e2d-53de-461d-ae91-ede7402713cb",
            network.id,
            "server-port".to_owned(),
        )
        .await?;
    let port_id = port.id.to_string();
    let expected_fixed_ip = port.fixed_ip.to_string();
    let console = o3k_console::ConsoleService::open(format!(
        "/tmp/o3k-api-console-{}",
        uuid::Uuid::now_v7()
    ))?;
    let state = o3k_api::AppState::new()
        .with_identity(identity)
        .with_compute(compute)
        .with_network(network_service)
        .with_console(console.clone());
    let auth = serde_json::json!({"auth":{"identity":{"methods":["password"],"password":{"user":{"name":"admin","password":"password"}}},"scope":{"project":{"name":"admin"}}}});
    let response = o3k_api::router_with_state(state.clone())
        .oneshot(
            Request::builder()
                .method(Method::POST)
                .uri("/v3/auth/tokens")
                .header(header::CONTENT_TYPE, "application/json")
                .body(Body::from(auth.to_string()))?,
        )
        .await?;
    let token = response
        .headers()
        .get("x-subject-token")
        .ok_or_else(|| std::io::Error::other("token missing"))?
        .to_str()?
        .to_owned();
    let flavors = o3k_api::router_with_state(state.clone())
        .oneshot(
            Request::builder()
                .uri("/v2.1/eba29e2d-53de-461d-ae91-ede7402713cb/flavors")
                .header("x-auth-token", &token)
                .body(Body::empty())?,
        )
        .await?;
    assert_eq!(flavors.status(), StatusCode::OK);
    let flavor_json: Value =
        serde_json::from_slice(&axum::body::to_bytes(flavors.into_body(), 4096).await?)?;
    let default_flavor_id = flavor_json["flavors"][0]["id"]
        .as_str()
        .ok_or_else(|| std::io::Error::other("default flavor missing"))?
        .to_owned();
    let extra_specs = o3k_api::router_with_state(state.clone())
        .oneshot(
            Request::builder()
                .uri(format!(
                    "/v2.1/eba29e2d-53de-461d-ae91-ede7402713cb/flavors/{default_flavor_id}/os-extra_specs"
                ))
                .header("x-auth-token", &token)
                .body(Body::empty())?,
        )
        .await?;
    assert_eq!(extra_specs.status(), StatusCode::OK);
    let extra_specs_json: Value =
        serde_json::from_slice(&axum::body::to_bytes(extra_specs.into_body(), 4096).await?)?;
    assert_eq!(extra_specs_json, serde_json::json!({"extra_specs": {}}));
    let missing_extra_specs = o3k_api::router_with_state(state.clone())
        .oneshot(
            Request::builder()
                .uri("/v2.1/eba29e2d-53de-461d-ae91-ede7402713cb/flavors/00000000-0000-0000-0000-000000000099/os-extra_specs")
                .header("x-auth-token", &token)
                .body(Body::empty())?,
        )
        .await?;
    assert_eq!(missing_extra_specs.status(), StatusCode::NOT_FOUND);
    let foreign_extra_specs = o3k_api::router_with_state(state.clone())
        .oneshot(
            Request::builder()
                .uri("/v2.1/foreign-project/flavors/00000000-0000-0000-0000-000000000001/os-extra_specs")
                .header("x-auth-token", &token)
                .body(Body::empty())?,
        )
        .await?;
    assert_eq!(foreign_extra_specs.status(), StatusCode::NOT_FOUND);
    let custom_flavor = o3k_api::router_with_state(state.clone())
        .oneshot(
            Request::builder()
                .method(Method::POST)
                .uri("/v2.1/eba29e2d-53de-461d-ae91-ede7402713cb/flavors")
                .header("x-auth-token", &token)
                .header(header::CONTENT_TYPE, "application/json")
                .body(Body::from(
                    r#"{"flavor":{"name":"api.custom","vcpus":1,"ram":768,"disk":4}}"#,
                ))?,
        )
        .await?;
    assert_eq!(custom_flavor.status(), StatusCode::CREATED);
    let custom_flavor_json: Value =
        serde_json::from_slice(&axum::body::to_bytes(custom_flavor.into_body(), 4096).await?)?;
    let custom_flavor_id = custom_flavor_json["flavor"]["id"]
        .as_str()
        .ok_or_else(|| std::io::Error::other("custom flavor missing"))?
        .to_owned();
    let custom_show = o3k_api::router_with_state(state.clone())
        .oneshot(
            Request::builder()
                .uri(format!(
                    "/v2.1/eba29e2d-53de-461d-ae91-ede7402713cb/flavors/{custom_flavor_id}"
                ))
                .header("x-auth-token", &token)
                .body(Body::empty())?,
        )
        .await?;
    assert_eq!(custom_show.status(), StatusCode::OK);
    let detailed_flavors = o3k_api::router_with_state(state.clone())
        .oneshot(
            Request::builder()
                .uri("/v2.1/eba29e2d-53de-461d-ae91-ede7402713cb/flavors/detail")
                .header("x-auth-token", &token)
                .body(Body::empty())?,
        )
        .await?;
    assert_eq!(detailed_flavors.status(), StatusCode::OK);
    let flavor_id = default_flavor_id.as_str();
    let detailed_servers = o3k_api::router_with_state(state.clone())
        .oneshot(
            Request::builder()
                .uri("/v2.1/eba29e2d-53de-461d-ae91-ede7402713cb/servers/detail")
                .header("x-auth-token", &token)
                .body(Body::empty())?,
        )
        .await?;
    assert_eq!(detailed_servers.status(), StatusCode::OK);
    let keypair_create = o3k_api::router_with_state(state.clone())
        .oneshot(
            Request::builder()
                .method(Method::POST)
                .uri("/v2.1/eba29e2d-53de-461d-ae91-ede7402713cb/os-keypairs")
                .header("x-auth-token", &token)
                .header(header::CONTENT_TYPE, "application/json")
                .body(Body::from(serde_json::json!({"keypair":{"name":"nova-test-key","public_key":"ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIBJuQvak7YBzsbN71EyvJnDK8pODWM1Ox/3wO3tT8Adj o3k-test"}}).to_string()))?,
        )
        .await?;
    assert_eq!(keypair_create.status(), StatusCode::OK);
    let keypair_json: Value =
        serde_json::from_slice(&axum::body::to_bytes(keypair_create.into_body(), 8192).await?)?;
    assert_eq!(keypair_json["keypair"]["name"], "nova-test-key");
    assert_eq!(keypair_json["keypair"]["type"], "ssh");
    assert_eq!(
        keypair_json["keypair"]["fingerprint"]
            .as_str()
            .map(str::len),
        Some(47)
    );
    let keypair_list = o3k_api::router_with_state(state.clone())
        .oneshot(
            Request::builder()
                .uri("/v2.1/eba29e2d-53de-461d-ae91-ede7402713cb/os-keypairs")
                .header("x-auth-token", &token)
                .body(Body::empty())?,
        )
        .await?;
    assert_eq!(keypair_list.status(), StatusCode::OK);
    assert_eq!(
        serde_json::from_slice::<Value>(
            &axum::body::to_bytes(keypair_list.into_body(), 8192).await?
        )?["keypairs"]
            .as_array()
            .map(Vec::len),
        Some(1)
    );
    let request_body = serde_json::json!({"server":{"name":"nova-test","image":{"id":"image-1"},"flavor":{"id":flavor_id},"networks":[{"port":port_id.clone()}],"key_name":"nova-test-key"}});
    let created = o3k_api::router_with_state(state.clone())
        .oneshot(
            Request::builder()
                .method(Method::POST)
                .uri("/v2.1/eba29e2d-53de-461d-ae91-ede7402713cb/servers")
                .header("x-auth-token", &token)
                .header(header::CONTENT_TYPE, "application/json")
                .header("x-openstack-request-id", "nova-test-request")
                .body(Body::from(request_body.to_string()))?,
        )
        .await?;
    assert_eq!(created.status(), StatusCode::ACCEPTED);
    let server_json: Value =
        serde_json::from_slice(&axum::body::to_bytes(created.into_body(), 8192).await?)?;
    assert_eq!(server_json["server"]["status"], "ACTIVE");
    // Public clients (openstackclient 6.6 `_prep_server_detail`) pop the
    // server metadata object unconditionally; Nova always carries one.
    assert_eq!(server_json["server"]["metadata"], serde_json::json!({}));
    assert_eq!(
        server_json["server"]["addresses"][network.name][0]["addr"],
        expected_fixed_ip
    );
    let server_id = server_json["server"]["id"]
        .as_str()
        .ok_or_else(|| std::io::Error::other("server missing"))?;
    let server_uuid = server_id.parse::<uuid::Uuid>()?;
    console.write(server_uuid, b"0123456789abcdef")?;
    let console_response = o3k_api::router_with_state(state.clone())
        .oneshot(
            Request::builder()
                .method(Method::POST)
                .uri(format!(
                    "/v2.1/eba29e2d-53de-461d-ae91-ede7402713cb/servers/{server_id}/action"
                ))
                .header("x-auth-token", &token)
                .header(header::CONTENT_TYPE, "application/json")
                .body(Body::from(
                    r#"{"os-getConsoleOutput":{"offset":4,"length":6}}"#,
                ))?,
        )
        .await?;
    assert_eq!(console_response.status(), StatusCode::OK);
    let console_json: Value =
        serde_json::from_slice(&axum::body::to_bytes(console_response.into_body(), 4096).await?)?;
    assert_eq!(console_json["output"], "456789");
    let stopped = o3k_api::router_with_state(state.clone())
        .oneshot(
            Request::builder()
                .method(Method::POST)
                .uri(format!(
                    "/v2.1/eba29e2d-53de-461d-ae91-ede7402713cb/servers/{server_id}/action"
                ))
                .header("x-auth-token", &token)
                .header(header::CONTENT_TYPE, "application/json")
                .body(Body::from(r#"{"os-stop":null}"#))?,
        )
        .await?;
    assert_eq!(stopped.status(), StatusCode::ACCEPTED);
    let deleted = o3k_api::router_with_state(state.clone())
        .oneshot(
            Request::builder()
                .method(Method::DELETE)
                .uri(format!(
                    "/v2.1/eba29e2d-53de-461d-ae91-ede7402713cb/servers/{server_id}"
                ))
                .header("x-auth-token", &token)
                .body(Body::empty())?,
        )
        .await?;
    assert_eq!(deleted.status(), StatusCode::NO_CONTENT);
    assert!(matches!(
        console.read(server_uuid),
        Err(o3k_console::ConsoleError::NotFound)
    ));
    let custom_deleted = o3k_api::router_with_state(state.clone())
        .oneshot(
            Request::builder()
                .method(Method::DELETE)
                .uri(format!(
                    "/v2.1/eba29e2d-53de-461d-ae91-ede7402713cb/flavors/{custom_flavor_id}"
                ))
                .header("x-auth-token", &token)
                .body(Body::empty())?,
        )
        .await?;
    assert_eq!(custom_deleted.status(), StatusCode::NO_CONTENT);
    let keypair_deleted = o3k_api::router_with_state(state.clone())
        .oneshot(
            Request::builder()
                .method(Method::DELETE)
                .uri("/v2.1/eba29e2d-53de-461d-ae91-ede7402713cb/os-keypairs/nova-test-key")
                .header("x-auth-token", &token)
                .body(Body::empty())?,
        )
        .await?;
    assert_eq!(keypair_deleted.status(), StatusCode::NO_CONTENT);
    assert!(keypair_deleted.into_body().is_end_stream());

    let second_body = serde_json::json!({"server":{"name":"nova-failed-delete","image":{"id":"image-1"},"flavor":{"id":default_flavor_id},"networks":[{"uuid":port_id}]}});
    let second_created = o3k_api::router_with_state(state.clone())
        .oneshot(
            Request::builder()
                .method(Method::POST)
                .uri("/v2.1/eba29e2d-53de-461d-ae91-ede7402713cb/servers")
                .header("x-auth-token", &token)
                .header(header::CONTENT_TYPE, "application/json")
                .header("x-openstack-request-id", "nova-failed-delete-request")
                .body(Body::from(second_body.to_string()))?,
        )
        .await?;
    assert_eq!(second_created.status(), StatusCode::ACCEPTED);
    let second_json: Value =
        serde_json::from_slice(&axum::body::to_bytes(second_created.into_body(), 8192).await?)?;
    let second_id = second_json["server"]["id"]
        .as_str()
        .ok_or_else(|| std::io::Error::other("second server missing"))?;
    let second_uuid = second_id.parse::<uuid::Uuid>()?;
    console.write(second_uuid, b"failed-delete-console")?;
    provider.set_failure(FailureInjection::Transient)?;
    let failed_delete = o3k_api::router_with_state(state.clone())
        .oneshot(
            Request::builder()
                .method(Method::DELETE)
                .uri(format!(
                    "/v2.1/eba29e2d-53de-461d-ae91-ede7402713cb/servers/{second_id}"
                ))
                .header("x-auth-token", &token)
                .body(Body::empty())?,
        )
        .await?;
    assert_eq!(failed_delete.status(), StatusCode::CONFLICT);
    assert_eq!(console.read(second_uuid)?, b"failed-delete-console");

    let repeated_delete = o3k_api::router_with_state(state)
        .oneshot(
            Request::builder()
                .method(Method::DELETE)
                .uri(format!(
                    "/v2.1/eba29e2d-53de-461d-ae91-ede7402713cb/servers/{server_id}"
                ))
                .header("x-auth-token", &token)
                .body(Body::empty())?,
        )
        .await?;
    assert_eq!(repeated_delete.status(), StatusCode::NO_CONTENT);
    assert!(matches!(
        console.read(server_uuid),
        Err(o3k_console::ConsoleError::NotFound)
    ));
    std::fs::remove_file(path)?;
    std::fs::remove_dir_all(network_root)?;
    Ok(())
}

#[tokio::test]
async fn microversion_nova_discovery_and_negotiation() -> Result<(), Box<dyn std::error::Error>> {
    let req = Request::builder().uri("/v2.1").body(Body::empty())?;
    let resp = o3k_api::router().oneshot(req).await?;
    assert_eq!(resp.status(), StatusCode::OK);
    let json: Value = serde_json::from_slice(&axum::body::to_bytes(resp.into_body(), 2048).await?)?;
    assert_eq!(json["version"]["id"], "v2.1");
    assert_eq!(json["version"]["version"], "2.1");
    assert_eq!(json["version"]["min_version"], "2.1");

    let req = Request::builder().uri("/v2.1/").body(Body::empty())?;
    let resp = o3k_api::router().oneshot(req).await?;
    assert_eq!(resp.status(), StatusCode::OK);

    let req = Request::builder()
        .uri("/v2.1/eba29e2d-53de-461d-ae91-ede7402713cb/flavors")
        .body(Body::empty())?;
    let resp = o3k_api::router().oneshot(req).await?;
    assert_eq!(
        resp.headers().get("OpenStack-API-Version"),
        Some(&HeaderValue::from_static("compute 2.1"))
    );
    assert_eq!(
        resp.headers().get("X-OpenStack-Nova-API-Version"),
        Some(&HeaderValue::from_static("2.1"))
    );
    assert_eq!(
        resp.headers().get("Vary"),
        Some(&HeaderValue::from_static(
            "OpenStack-API-Version, X-OpenStack-Nova-API-Version"
        ))
    );

    let req = Request::builder()
        .uri("/v2.1/eba29e2d-53de-461d-ae91-ede7402713cb/flavors")
        .header("OpenStack-API-Version", "compute 2.1")
        .body(Body::empty())?;
    let resp = o3k_api::router().oneshot(req).await?;
    assert_eq!(
        resp.headers().get("OpenStack-API-Version"),
        Some(&HeaderValue::from_static("compute 2.1"))
    );

    let req = Request::builder()
        .uri("/v2.1/eba29e2d-53de-461d-ae91-ede7402713cb/flavors")
        .header("X-OpenStack-Nova-API-Version", "2.1")
        .body(Body::empty())?;
    let resp = o3k_api::router().oneshot(req).await?;
    assert_eq!(
        resp.headers().get("OpenStack-API-Version"),
        Some(&HeaderValue::from_static("compute 2.1"))
    );

    let req = Request::builder()
        .uri("/v2.1/eba29e2d-53de-461d-ae91-ede7402713cb/flavors")
        .header("OpenStack-API-Version", "compute 2.95")
        .body(Body::empty())?;
    let resp = o3k_api::router().oneshot(req).await?;
    assert_eq!(resp.status(), StatusCode::NOT_ACCEPTABLE);
    let json: Value = serde_json::from_slice(&axum::body::to_bytes(resp.into_body(), 2048).await?)?;
    assert_eq!(json["computeFault"]["code"], 406);

    let req = Request::builder()
        .uri("/v2.1/eba29e2d-53de-461d-ae91-ede7402713cb/flavors")
        .header("OpenStack-API-Version", "compute invalid_ver extra_token")
        .body(Body::empty())?;
    let resp = o3k_api::router().oneshot(req).await?;
    assert_eq!(resp.status(), StatusCode::BAD_REQUEST);

    let req = Request::builder()
        .uri("/v2.1/eba29e2d-53de-461d-ae91-ede7402713cb/flavors")
        .header("OpenStack-API-Version", "placement 1.28")
        .body(Body::empty())?;
    let resp = o3k_api::router().oneshot(req).await?;
    assert_eq!(
        resp.headers().get("OpenStack-API-Version"),
        Some(&HeaderValue::from_static("compute 2.1"))
    );

    Ok(())
}

#[tokio::test]
async fn microversion_placement_discovery_and_negotiation() -> Result<(), Box<dyn std::error::Error>>
{
    let req = Request::builder().uri("/placement").body(Body::empty())?;
    let resp = o3k_api::router().oneshot(req).await?;
    assert_eq!(resp.status(), StatusCode::OK);
    let json: Value = serde_json::from_slice(&axum::body::to_bytes(resp.into_body(), 2048).await?)?;
    assert_eq!(json["versions"][0]["id"], "v1.0");
    assert_eq!(json["versions"][0]["min_version"], "1.0");
    assert_eq!(json["versions"][0]["max_version"], "1.28");

    let req = Request::builder()
        .uri("/placement/resource_providers")
        .header("OpenStack-API-Version", "placement 1.28")
        .body(Body::empty())?;
    let resp = o3k_api::router().oneshot(req).await?;
    assert_eq!(
        resp.headers().get("OpenStack-API-Version"),
        Some(&HeaderValue::from_static("placement 1.28"))
    );

    let req = Request::builder()
        .uri("/placement/resource_providers")
        .header("OpenStack-API-Version", "placement latest")
        .body(Body::empty())?;
    let resp = o3k_api::router().oneshot(req).await?;
    assert_eq!(
        resp.headers().get("OpenStack-API-Version"),
        Some(&HeaderValue::from_static("placement 1.28"))
    );

    let req = Request::builder()
        .uri("/placement/resource_providers")
        .header("OpenStack-API-Version", "placement 1.39")
        .body(Body::empty())?;
    let resp = o3k_api::router().oneshot(req).await?;
    assert_eq!(resp.status(), StatusCode::NOT_ACCEPTABLE);

    Ok(())
}

#[tokio::test]
async fn identity_image_network_services_have_no_microversion_headers()
-> Result<(), Box<dyn std::error::Error>> {
    let req = Request::builder().uri("/v3").body(Body::empty())?;
    let resp = o3k_api::router().oneshot(req).await?;
    assert!(resp.headers().get("OpenStack-API-Version").is_none());

    let req = Request::builder().uri("/v2/images").body(Body::empty())?;
    let resp = o3k_api::router().oneshot(req).await?;
    assert!(resp.headers().get("OpenStack-API-Version").is_none());

    let req = Request::builder()
        .uri("/v2.0/networks")
        .body(Body::empty())?;
    let resp = o3k_api::router().oneshot(req).await?;
    assert!(resp.headers().get("OpenStack-API-Version").is_none());

    Ok(())
}

#[tokio::test]
async fn keystone_get_and_head_token_validation_and_cinder_catalog()
-> Result<(), Box<dyn std::error::Error>> {
    use tower::ServiceExt;

    let identity = test_service("http://127.0.0.1:18080").await?;

    let state = o3k_api::AppState::new().with_identity(identity);
    state.set_ready(true);
    let app = o3k_api::router_with_state(state);

    let auth_body = serde_json::json!({
        "auth": {
            "identity": {
                "methods": ["password"],
                "password": {
                    "user": {
                        "name": "admin",
                        "password": "password"
                    }
                }
            },
            "scope": {
                "project": {
                    "name": "admin"
                }
            }
        }
    });

    let req = Request::builder()
        .method(Method::POST)
        .uri("/v3/auth/tokens")
        .header(header::CONTENT_TYPE, "application/json")
        .body(Body::from(auth_body.to_string()))?;
    let resp = app.clone().oneshot(req).await?;
    assert_eq!(resp.status(), StatusCode::CREATED);
    let token = resp
        .headers()
        .get("x-subject-token")
        .ok_or("missing x-subject-token header")?
        .to_str()?
        .to_owned();

    // Verify GET /v3/auth/tokens validates token
    let req = Request::builder()
        .method(Method::GET)
        .uri("/v3/auth/tokens")
        .header("x-subject-token", &token)
        .body(Body::empty())?;
    let resp = app.clone().oneshot(req).await?;
    assert_eq!(resp.status(), StatusCode::OK);
    assert_eq!(
        resp.headers()
            .get("x-subject-token")
            .ok_or("missing x-subject-token header")?
            .to_str()?,
        token
    );

    let body_bytes = axum::body::to_bytes(resp.into_body(), usize::MAX).await?;
    let json: Value = serde_json::from_slice(&body_bytes)?;
    let catalog = json["token"]["catalog"]
        .as_array()
        .ok_or("missing catalog")?;
    let cinder_entry = catalog
        .iter()
        .find(|item| item["type"] == "volumev3")
        .ok_or("missing volumev3 service entry")?;
    assert_eq!(
        cinder_entry["endpoints"][0]["url"],
        "http://127.0.0.1:8776/v3/eba29e2d-53de-461d-ae91-ede7402713cb"
    );

    // Verify HEAD /v3/auth/tokens validates token without body
    let req = Request::builder()
        .method(Method::HEAD)
        .uri("/v3/auth/tokens")
        .header("x-subject-token", &token)
        .body(Body::empty())?;
    let resp = app.clone().oneshot(req).await?;
    assert_eq!(resp.status(), StatusCode::OK);
    assert_eq!(
        resp.headers()
            .get("x-subject-token")
            .ok_or("missing x-subject-token header")?
            .to_str()?,
        token
    );

    // Invalid token on GET returns 404
    let req = Request::builder()
        .method(Method::GET)
        .uri("/v3/auth/tokens")
        .header("x-subject-token", "invalid.token.str")
        .body(Body::empty())?;
    let resp = app.clone().oneshot(req).await?;
    assert_eq!(resp.status(), StatusCode::NOT_FOUND);

    Ok(())
}

#[tokio::test]
async fn nova_volume_attachment_lifecycle_list_create_show_delete()
-> Result<(), Box<dyn std::error::Error>> {
    use std::sync::Arc;
    use tower::ServiceExt;

    let store = Arc::new(o3k_store::testkit::open_memory().await?);
    let provider = Arc::new(FakeComputeProvider::new());
    let compute = ComputeService::new_for_test(store, provider);

    let state = o3k_api::AppState::new().with_compute(compute);
    state.set_ready(true);
    let app = o3k_api::router_with_state(state);

    let server_id = uuid::Uuid::now_v7();
    let volume_id = uuid::Uuid::now_v7();

    // 1. Attaching volume to non-existent server returns 404
    let attach_body = serde_json::json!({
        "volumeAttachment": {
            "volumeId": volume_id.to_string(),
            "device": "/dev/vdb"
        }
    });
    let req = Request::builder()
        .method(Method::POST)
        .uri(format!(
            "/v2.1/project-1/servers/{server_id}/os-volume_attachments"
        ))
        .header(header::CONTENT_TYPE, "application/json")
        .body(Body::from(attach_body.to_string()))?;
    let resp = app.clone().oneshot(req).await?;
    assert_eq!(resp.status(), StatusCode::NOT_FOUND);

    // 2. Listing attachments for non-existent server returns 404
    let req = Request::builder()
        .method(Method::GET)
        .uri(format!(
            "/v2.1/project-1/servers/{server_id}/os-volume_attachments"
        ))
        .body(Body::empty())?;
    let resp = app.clone().oneshot(req).await?;
    assert_eq!(resp.status(), StatusCode::NOT_FOUND);

    Ok(())
}

#[tokio::test]
async fn router_detach_dispatches_only_the_requested_gateway_and_finalizes_after_dispatch()
-> Result<(), Box<dyn std::error::Error>> {
    let root = std::path::PathBuf::from(format!(
        "/tmp/o3k-api-router-lifecycle-{}",
        uuid::Uuid::now_v7()
    ));
    let _ = std::fs::remove_dir_all(&root);
    let identity = test_service("http://127.0.0.1:8080").await?;
    let project_id = "eba29e2d-53de-461d-ae91-ede7402713cb";
    let store = Arc::new(o3k_store::testkit::open_memory().await?);
    let network = NetworkService::open_for_test(root.join("network"), store).await?;
    let network_record = network
        .create_network_for_project(project_id, "router-network".to_owned())
        .await?;
    network
        .create_subnet_for_project(
            project_id,
            network_record.id,
            "router-subnet".to_owned(),
            "10.42.0.0/24".to_owned(),
            None,
            None,
            None,
        )
        .await?;
    let port = network
        .create_port_for_project(project_id, network_record.id, "router-port".to_owned())
        .await?;
    network
        .record_binding_intent(project_id, port.id, "network-agent")
        .await?;
    let realm = network
        .list_canonical_realms_for_project(project_id, network_record.id)
        .await?
        .into_iter()
        .next()
        .ok_or("router realm missing")?;
    let gateway_a = network
        .create_l3_gateway_for_project(project_id, "gateway-a".to_owned(), None, true)
        .await?;
    let gateway_b = network
        .create_l3_gateway_for_project(project_id, "gateway-b".to_owned(), None, true)
        .await?;
    let gateway_c = network
        .create_l3_gateway_for_project(project_id, "gateway-c".to_owned(), None, true)
        .await?;
    let gateway_d = network
        .create_l3_gateway_for_project(project_id, "gateway-d".to_owned(), None, true)
        .await?;
    network
        .attach_l3_gateway_realm(project_id, &gateway_a.id, &realm.id)
        .await?;
    network
        .attach_l3_gateway_realm(project_id, &gateway_b.id, &realm.id)
        .await?;

    let dispatcher = RecordingNetworkDispatcher::default();
    let commands = dispatcher.commands.clone();
    let state = o3k_api::AppState::new()
        .with_identity(identity)
        .with_network(network.clone())
        .with_network_dispatcher(
            Arc::new(dispatcher),
            o3k_network::NetworkControllerLease {
                controller_id: "controller-test".to_owned(),
                controller_epoch: "epoch-1".to_owned(),
                fencing_token: 1,
            },
        )
        .with_network_agent_identity(o3k_network::NetworkAgentIdentity {
            agent_id: "network-agent".to_owned(),
            agent_epoch: "network-epoch-1".to_owned(),
        });
    let auth = serde_json::json!({"auth":{"identity":{"methods":["password"],"password":{"user":{"name":"admin","password":"password"}}},"scope":{"project":{"name":"admin"}}}});
    let token_response = o3k_api::router_with_state(state.clone())
        .oneshot(
            Request::builder()
                .method(Method::POST)
                .uri("/v3/auth/tokens")
                .header(header::CONTENT_TYPE, "application/json")
                .body(Body::from(auth.to_string()))?,
        )
        .await?;
    let token = token_response
        .headers()
        .get("x-subject-token")
        .ok_or("token missing")?
        .to_str()?
        .to_owned();

    let response = o3k_api::router_with_state(state.clone())
        .oneshot(
            Request::builder()
                .method(Method::DELETE)
                .uri(format!("/v2.0/routers/{}", gateway_c.id))
                .header("x-auth-token", &token)
                .body(Body::empty())?,
        )
        .await?;
    assert_eq!(response.status(), StatusCode::ACCEPTED);
    {
        let commands = commands
            .lock()
            .map_err(|_| std::io::Error::other("recording dispatcher lock poisoned"))?;
        assert_eq!(commands.len(), 1);
        assert_eq!(commands[0].action, NetworkPlanAction::Remove);
        assert_eq!(
            commands[0]
                .plan
                .gateway
                .as_ref()
                .ok_or("gateway removal snapshot missing")?
                .gateway_id,
            gateway_c.id
        );
    }
    assert!(
        network
            .list_l3_gateways_for_project(project_id)
            .await?
            .into_iter()
            .all(|gateway| gateway.id != gateway_c.id)
    );

    // A successful interface DELETE may leave a durable deletion reservation
    // until the next request observes the disabled realization boundary. A
    // following router DELETE must finish that reservation rather than
    // exposing a transient "router in use" conflict to the IaC provider.
    let attachment_d = network
        .attach_l3_gateway_realm(project_id, &gateway_d.id, &realm.id)
        .await?;
    let deleting_attachment = network
        .detach_l3_gateway_realm(project_id, &attachment_d.id, attachment_d.generation)
        .await?;
    assert_eq!(deleting_attachment.state, "deleting");
    let disabled_state = state.clone().with_network_gateway_realization(false);
    let response = o3k_api::router_with_state(disabled_state)
        .oneshot(
            Request::builder()
                .method(Method::DELETE)
                .uri(format!("/v2.0/routers/{}", gateway_d.id))
                .header("x-auth-token", &token)
                .body(Body::empty())?,
        )
        .await?;
    assert_eq!(response.status(), StatusCode::ACCEPTED);
    assert!(
        network
            .list_l3_gateways_for_project(project_id)
            .await?
            .into_iter()
            .all(|gateway| gateway.id != gateway_d.id)
    );

    let response = o3k_api::router_with_state(state)
        .oneshot(
            Request::builder()
                .method(Method::PUT)
                .uri(format!(
                    "/v2.0/routers/{}/remove_router_interface",
                    gateway_a.id
                ))
                .header("x-auth-token", token)
                .header(header::CONTENT_TYPE, "application/json")
                .body(Body::from(
                    serde_json::json!({
                        "router_interface": {"subnet_id": realm.id}
                    })
                    .to_string(),
                ))?,
        )
        .await?;
    assert_eq!(response.status(), StatusCode::OK);
    let removal: Value =
        serde_json::from_slice(&axum::body::to_bytes(response.into_body(), 1024).await?)?;
    assert_eq!(removal["id"], removal["port_id"]);
    assert_eq!(removal["subnet_id"], realm.id.to_string());
    assert_eq!(removal["tenant_id"], project_id);

    {
        let commands = commands
            .lock()
            .map_err(|_| std::io::Error::other("recording dispatcher lock poisoned"))?;
        assert_eq!(commands.len(), 2);
        assert_eq!(commands[1].action, NetworkPlanAction::Apply);
        assert_eq!(
            commands[1]
                .plan
                .gateway
                .as_ref()
                .ok_or("gateway snapshot missing")?
                .gateway_id,
            gateway_a.id
        );
    }
    let detached = network
        .list_l3_gateway_attachments(project_id, &gateway_a.id)
        .await?;
    assert!(detached.is_empty());
    assert_eq!(
        network
            .list_l3_gateway_attachments(project_id, &gateway_b.id)
            .await?
            .first()
            .ok_or("unrelated gateway attachment missing")?
            .state,
        "active"
    );
    Ok(())
}
