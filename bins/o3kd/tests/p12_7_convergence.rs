//! P12.7 black-box evidence that the native and OpenStack adapters share the
//! same canonical application/store authority.
#![allow(clippy::expect_used, clippy::panic)]

use axum::body::Body;
use axum::http::{Method, Request, StatusCode, header};
use o3k_compute::ComputeService;
use o3k_kernel::{
    ControllerSession, ManifestRegistry, PrincipalId, ProtocolVersion, ServicePrincipal,
};
use o3k_native_api::auth::TokenIssuer;
use o3k_network::NetworkService;
use o3k_provider::FakeComputeProvider;
use o3k_store::DurableStore;
use o3k_store::IdentityRepository;
use serde_json::Value;
use std::{sync::Arc, time::Duration};
use tower::ServiceExt;

fn session(service: &str, namespace: &str, generation: u64) -> ControllerSession {
    ControllerSession {
        service_id: service.to_owned(),
        namespace: namespace.to_owned(),
        service_principal: ServicePrincipal::new(
            PrincipalId::new_unchecked(format!("{service}-controller")),
            format!("{service}-controller"),
            namespace,
        ),
        session_id: uuid::Uuid::new_v4(),
        session_generation: generation,
        protocol_version: ProtocolVersion::new(1, 0),
        manifest_digest: format!("p12-7-{service}"),
        manifest_generation: generation,
        started_at: "2026-08-23T00:00:00Z".to_owned(),
    }
}

async fn response_json(response: axum::response::Response) -> Value {
    let bytes = axum::body::to_bytes(response.into_body(), 64 * 1024)
        .await
        .expect("response body");
    serde_json::from_slice(&bytes).unwrap_or_else(|_| {
        panic!(
            "non-JSON response body: {:?}",
            String::from_utf8_lossy(&bytes)
        )
    })
}

async fn issue_token_for(
    app: &axum::Router,
    user: &str,
    password: &str,
    project: &str,
) -> Result<String, Box<dyn std::error::Error>> {
    let body = serde_json::json!({
        "auth": {
            "identity": {
                "methods": ["password"],
                "password": {"user": {"name": user, "password": password}}
            },
            "scope": {"project": {"name": project}}
        }
    });
    let response = app
        .clone()
        .oneshot(
            Request::builder()
                .method(Method::POST)
                .uri("/v3/auth/tokens")
                .header(header::CONTENT_TYPE, "application/json")
                .body(Body::from(serde_json::to_vec(&body)?))?,
        )
        .await?;
    assert_eq!(response.status(), StatusCode::CREATED);
    Ok(response
        .headers()
        .get("x-subject-token")
        .ok_or("missing Keystone token")?
        .to_str()?
        .to_owned())
}

async fn issue_token(app: &axum::Router) -> Result<String, Box<dyn std::error::Error>> {
    issue_token_for(app, "admin", "password", "admin").await
}

async fn get_json(
    app: &axum::Router,
    uri: &str,
    token: &str,
) -> Result<Value, Box<dyn std::error::Error>> {
    let response = app
        .clone()
        .oneshot(
            Request::builder()
                .uri(uri)
                .header("x-auth-token", token)
                .header("authorization", format!("Bearer {token}"))
                .body(Body::empty())?,
        )
        .await?;
    let status = response.status();
    let body = response_json(response).await;
    assert_eq!(status, StatusCode::OK, "GET {uri}: {body:?}");
    Ok(body)
}

async fn status_for(app: &axum::Router, method: Method, uri: &str, token: &str) -> StatusCode {
    let response = app
        .clone()
        .oneshot(
            Request::builder()
                .method(method.clone())
                .uri(uri)
                .header("x-auth-token", token)
                .header("authorization", format!("Bearer {token}"))
                .body(Body::empty())
                .expect("request"),
        )
        .await
        .expect("response");
    let status = response.status();
    if status.is_server_error() {
        let body = axum::body::to_bytes(response.into_body(), 64 * 1024)
            .await
            .expect("error body");
        eprintln!(
            "{method} {uri} -> {status}: {:?}",
            String::from_utf8_lossy(&body)
        );
    }
    status
}

async fn build_http_runtime(
    store: Arc<o3k_store::unified::O3kStore>,
) -> Result<(axum::Router, Arc<FakeComputeProvider>), Box<dyn std::error::Error>> {
    let identity = o3k_identity::testkit::test_service_with_projects(
        "http://127.0.0.1:8080",
        vec![
            o3k_identity::ExtraProjectSeed {
                project_id: "project-a".to_owned(),
                project_name: "project-a".to_owned(),
                user_id: "user-a".to_owned(),
                user_name: "user-a".to_owned(),
                password: o3k_identity::Secret::new("password-a".to_owned()),
            },
            o3k_identity::ExtraProjectSeed {
                project_id: "project-b".to_owned(),
                project_name: "project-b".to_owned(),
                user_id: "user-b".to_owned(),
                user_name: "user-b".to_owned(),
                password: o3k_identity::Secret::new("password-b".to_owned()),
            },
        ],
    )
    .await?;
    build_http_runtime_with_identity(store, identity, None).await
}

async fn build_http_runtime_with_identity(
    store: Arc<o3k_store::unified::O3kStore>,
    identity: o3k_identity::TokenService,
    oidc_validator: Option<Arc<o3k_identity::oidc::OidcValidator>>,
) -> Result<(axum::Router, Arc<FakeComputeProvider>), Box<dyn std::error::Error>> {
    let provider = Arc::new(FakeComputeProvider::new());
    let compute_service = ComputeService::new_for_test(store.clone(), provider.clone());
    let compute = Arc::new(compute_service.clone());
    let network = Arc::new(
        NetworkService::open_for_test(
            std::env::temp_dir().join(format!(
                "o3k-p12-7-restart-network-{}",
                uuid::Uuid::new_v4()
            )),
            store.clone(),
        )
        .await?,
    );
    let mut manifests = ManifestRegistry::new();
    manifests.seed_core()?;
    for (service, namespace) in [
        ("compute", "compute"),
        ("network", "network"),
        ("volume", "volume"),
    ] {
        manifests.register_controller(service, session(service, namespace, 1))?;
        manifests.activate_controller(service)?;
    }
    let server_reader: Arc<dyn o3k_native_api::compute::ServerReader> =
        Arc::new(o3kd::native_adapters::ServerReaderAdapter {
            service: compute.clone(),
        });
    let network_reader: Arc<dyn o3k_native_api::network::NetworkReader> =
        Arc::new(o3kd::native_adapters::NetworkReaderAdapter {
            store: store.clone(),
            authorizer: Arc::new(o3k_kernel::StaticAuthorizer::standard()),
        });
    let application: Arc<dyn o3k_native_api::resource::ResourceApplication> =
        Arc::new(o3kd::native_adapters::GenericResourceApplication {
            compute: compute.clone(),
            image: None,
            public_address_workflow: None,
            network_service: network.clone(),
            store: store.clone(),
            storage_provider: Some(Arc::new(
                o3k_storage::testkit::InMemoryStorageProvider::default(),
            )),
            server: server_reader.clone(),
            network: network_reader.clone(),
            external_controllers: Arc::new(Default::default()),
            public_allocator: None,
            network_external_realm_id: None,
            attachment_workflow: None,
            metering: None,
        });
    let token_issuer: Arc<dyn TokenIssuer> = Arc::new(o3kd::native_adapters::TokenIssuerAdapter {
        service: Arc::new(identity.clone()),
        oidc_validator,
    });
    let native = o3k_native_api::NativeApiState::new(
        Some(manifests),
        o3k_native_api::pagination::CursorConfig::new(
            b"test-only-native-cursor-key-at-least-32-bytes".to_vec(),
        )
        .expect("test cursor key"),
        Some(token_issuer),
        Some(server_reader),
        None,
        Some(network_reader),
    )?
    .with_resource_application(application)
    .with_quota_reader(Arc::new(o3kd::native_adapters::QuotaReaderAdapter::new(
        store.clone(),
    )))
    .with_authorizer(Arc::new(o3k_kernel::StaticAuthorizer::standard()));
    Ok((
        o3k_api::router_with_state(
            o3k_api::AppState::new()
                .with_identity(identity)
                .with_compute(compute_service)
                .with_network((*network).clone())
                .with_native_api(native),
        ),
        provider,
    ))
}

enum HttpRestartBackend {
    Sqlite(std::path::PathBuf),
    Postgres(String),
}

async fn open_http_restart_store(
    backend: &HttpRestartBackend,
) -> Result<o3k_store::unified::O3kStore, Box<dyn std::error::Error>> {
    Ok(match backend {
        HttpRestartBackend::Sqlite(path) => {
            o3k_store::unified::O3kStore::connect_sqlite_file(path).await?
        }
        HttpRestartBackend::Postgres(url) => {
            o3k_store::unified::O3kStore::connect_postgres(url).await?
        }
    })
}

async fn run_native_openstack_http_conformance(
    store: Arc<o3k_store::unified::O3kStore>,
) -> Result<(), Box<dyn std::error::Error>> {
    let run_tag = uuid::Uuid::new_v4().simple().to_string();
    let identity = o3k_identity::testkit::test_service_with_projects(
        "http://127.0.0.1:8080",
        vec![
            o3k_identity::ExtraProjectSeed {
                project_id: "project-a".to_owned(),
                project_name: "project-a".to_owned(),
                user_id: "user-a".to_owned(),
                user_name: "user-a".to_owned(),
                password: o3k_identity::Secret::new("password-a".to_owned()),
            },
            o3k_identity::ExtraProjectSeed {
                project_id: "project-b".to_owned(),
                project_name: "project-b".to_owned(),
                user_id: "user-b".to_owned(),
                user_name: "user-b".to_owned(),
                password: o3k_identity::Secret::new("password-b".to_owned()),
            },
        ],
    )
    .await?;
    let provider = Arc::new(FakeComputeProvider::new());
    let compute_service = ComputeService::new_for_test(store.clone(), provider.clone());
    let compute = Arc::new(compute_service.clone());
    let network = Arc::new(
        NetworkService::open_for_test(
            std::env::temp_dir().join(format!("o3k-p12-7-network-{}", uuid::Uuid::new_v4())),
            store.clone(),
        )
        .await?,
    );

    let mut manifests = ManifestRegistry::new();
    manifests.seed_core()?;
    for (service, namespace) in [
        ("compute", "compute"),
        ("network", "network"),
        ("volume", "volume"),
    ] {
        manifests.register_controller(service, session(service, namespace, 1))?;
        manifests.activate_controller(service)?;
    }

    let server_reader: Arc<dyn o3k_native_api::compute::ServerReader> =
        Arc::new(o3kd::native_adapters::ServerReaderAdapter {
            service: compute.clone(),
        });
    let network_reader: Arc<dyn o3k_native_api::network::NetworkReader> =
        Arc::new(o3kd::native_adapters::NetworkReaderAdapter {
            store: store.clone(),
            authorizer: Arc::new(o3k_kernel::StaticAuthorizer::standard()),
        });
    let application: Arc<dyn o3k_native_api::resource::ResourceApplication> =
        Arc::new(o3kd::native_adapters::GenericResourceApplication {
            compute: compute.clone(),
            image: None,
            public_address_workflow: None,
            network_service: network.clone(),
            store: store.clone(),
            storage_provider: Some(Arc::new(
                o3k_storage::testkit::InMemoryStorageProvider::default(),
            )),
            server: server_reader.clone(),
            network: network_reader.clone(),
            external_controllers: Arc::new(Default::default()),
            public_allocator: None,
            network_external_realm_id: None,
            attachment_workflow: None,
            metering: None,
        });
    let token_issuer: Arc<dyn TokenIssuer> = Arc::new(o3kd::native_adapters::TokenIssuerAdapter {
        service: Arc::new(identity.clone()),
        oidc_validator: None,
    });
    let native = o3k_native_api::NativeApiState::new(
        Some(manifests),
        o3k_native_api::pagination::CursorConfig::new(
            b"test-only-native-cursor-key-at-least-32-bytes".to_vec(),
        )
        .expect("test cursor key"),
        Some(token_issuer),
        Some(server_reader),
        None,
        Some(network_reader),
    )?
    .with_resource_application(application)
    .with_authorizer(Arc::new(o3k_kernel::StaticAuthorizer::standard()));
    let app = o3k_api::router_with_state(
        o3k_api::AppState::new()
            .with_identity(identity.clone())
            .with_compute(compute_service.clone())
            .with_network((*network).clone())
            .with_native_api(native.clone()),
    );
    let token = issue_token(&app).await?;

    // Direction A: OpenStack create -> native read.  The ID and owner are
    // asserted from both protocol representations, not inferred by name.
    let network_body = serde_json::json!({"network": {"name": format!("p12-7-network-{run_tag}")}});
    let openstack_network = app
        .clone()
        .oneshot(
            Request::builder()
                .method(Method::POST)
                .uri("/v2.0/networks")
                .header("x-auth-token", &token)
                .header(header::CONTENT_TYPE, "application/json")
                .body(Body::from(serde_json::to_vec(&network_body)?))?,
        )
        .await?;
    assert_eq!(openstack_network.status(), StatusCode::CREATED);
    let openstack_network_json = response_json(openstack_network).await;
    let network_id = openstack_network_json["network"]["id"]
        .as_str()
        .ok_or("OpenStack network ID")?;
    let project_id = openstack_network_json["network"]["project_id"]
        .as_str()
        .ok_or("OpenStack network project ID")?;
    let openstack_subnet = app
        .clone()
        .oneshot(
            Request::builder()
                .method(Method::POST)
                .uri("/v2.0/subnets")
                .header("x-auth-token", &token)
                .header(header::CONTENT_TYPE, "application/json")
                .body(Body::from(serde_json::to_vec(&serde_json::json!({
                    "subnet": {
                        "network_id": network_id,
                        "name": format!("p12-7-subnet-{run_tag}"),
                        "cidr": "192.0.2.0/24",
                        "gateway_ip": "192.0.2.1"
                    }
                }))?))?,
        )
        .await?;
    assert_eq!(openstack_subnet.status(), StatusCode::CREATED);
    let openstack_subnet_json = response_json(openstack_subnet).await;
    let subnet_id = openstack_subnet_json["subnet"]["id"]
        .as_str()
        .ok_or("OpenStack subnet ID")?;
    let openstack_port = app
        .clone()
        .oneshot(
            Request::builder()
                .method(Method::POST)
                .uri("/v2.0/ports")
                .header("x-auth-token", &token)
                .header(header::CONTENT_TYPE, "application/json")
                .body(Body::from(serde_json::to_vec(&serde_json::json!({
                    "port": {"network_id": network_id, "name": format!("p12-7-port-{run_tag}")}
                }))?))?,
        )
        .await?;
    let openstack_port_status = openstack_port.status();
    if openstack_port_status != StatusCode::CREATED {
        let body = axum::body::to_bytes(openstack_port.into_body(), 64 * 1024).await?;
        panic!(
            "OpenStack port create failed: {openstack_port_status} {}",
            String::from_utf8_lossy(&body)
        );
    }
    let openstack_port_json = response_json(openstack_port).await;
    let port_id = openstack_port_json["port"]["id"]
        .as_str()
        .ok_or("OpenStack port ID")?;
    let token_a = issue_token_for(&app, "user-a", "password-a", "project-a").await?;
    let token_b = issue_token_for(&app, "user-b", "password-b", "project-b").await?;
    let foreign_network = app
        .clone()
        .oneshot(
            Request::builder()
                .method(Method::POST)
                .uri("/v2.0/networks")
                .header("x-auth-token", &token_b)
                .header(header::CONTENT_TYPE, "application/json")
                .body(Body::from(serde_json::to_vec(&serde_json::json!({
                    "network": {"name": format!("foreign-network-{run_tag}")}
                }))?))?,
        )
        .await?;
    assert_eq!(foreign_network.status(), StatusCode::CREATED);
    let foreign_network_id = response_json(foreign_network).await["network"]["id"]
        .as_str()
        .ok_or("foreign network ID")?
        .to_owned();
    let foreign_subnet = app
        .clone()
        .oneshot(
            Request::builder()
                .method(Method::POST)
                .uri("/v2.0/subnets")
                .header("x-auth-token", &token_b)
                .header(header::CONTENT_TYPE, "application/json")
                .body(Body::from(serde_json::to_vec(&serde_json::json!({
                    "subnet": {
                        "network_id": foreign_network_id,
                        "name": format!("foreign-subnet-{run_tag}"),
                        "cidr": "198.51.100.0/24",
                        "gateway_ip": "198.51.100.1"
                    }
                }))?))?,
        )
        .await?;
    assert_eq!(foreign_subnet.status(), StatusCode::CREATED);
    let foreign_port = app
        .clone()
        .oneshot(
            Request::builder()
                .method(Method::POST)
                .uri("/v2.0/ports")
                .header("x-auth-token", &token_b)
                .header(header::CONTENT_TYPE, "application/json")
                .body(Body::from(serde_json::to_vec(&serde_json::json!({
                    "port": {"network_id": foreign_network_id, "name": format!("foreign-port-{run_tag}")}
                }))?))?,
        )
        .await?;
    assert_eq!(foreign_port.status(), StatusCode::CREATED);
    let foreign_port_id = response_json(foreign_port).await["port"]["id"]
        .as_str()
        .ok_or("foreign port ID")?
        .to_owned();
    let flavor_id = "00000000-0000-0000-0000-000000000001";
    let before_foreign_attempt = provider.instance_count();
    let foreign_attempt = app
        .clone()
        .oneshot(
            Request::builder()
                .method(Method::POST)
                .uri("/v2.1/project-a/servers")
                .header("x-auth-token", &token_a)
                .header(header::CONTENT_TYPE, "application/json")
                .header("x-openstack-request-id", "foreign-network-attempt")
                .body(Body::from(serde_json::to_vec(&serde_json::json!({
                    "server": {
                        "name": "must-not-exist",
                        "image": {"id": "image-a"},
                        "flavor": {"id": flavor_id},
                        "networks": [{"port": foreign_port_id}]
                    }
                }))?))?,
        )
        .await?;
    assert_eq!(foreign_attempt.status(), StatusCode::NOT_FOUND);
    assert_eq!(provider.instance_count(), before_foreign_attempt);
    let native_network = get_json(
        &app,
        &format!("/o3k/v1/network/networks/{network_id}"),
        &token,
    )
    .await?;
    assert_eq!(native_network["metadata"]["id"], network_id);
    assert_eq!(native_network["metadata"]["owner_scope"], project_id);

    // Direction B: native create -> OpenStack read.  Both paths use the same
    // NetworkService and therefore expose the identical durable UUID.
    let native_network_create = app
        .clone()
        .oneshot(
            Request::builder()
                .method(Method::POST)
                .uri("/o3k/v1/network/networks")
                .header("authorization", format!("Bearer {token}"))
                .header(header::CONTENT_TYPE, "application/json")
                .body(Body::from(serde_json::to_vec(&serde_json::json!({
                    "kind": "network:network",
                    "spec": {"name": format!("p12-7-native-network-{run_tag}")}
                }))?))?,
        )
        .await?;
    let native_network_create_status = native_network_create.status();
    let native_network_create_json = response_json(native_network_create).await;
    assert_eq!(
        native_network_create_status,
        StatusCode::CREATED,
        "{native_network_create_json}"
    );
    let native_network_id = native_network_create_json["resource_id"]
        .as_str()
        .ok_or("native network ID")?;
    let openstack_network_read =
        get_json(&app, &format!("/v2.0/networks/{native_network_id}"), &token).await?;
    assert_eq!(openstack_network_read["network"]["id"], native_network_id);

    // Compute uses the same shared authority.  The fake provider is only an
    // execution dependency; neither adapter owns a second public record.
    let openstack_server_body = serde_json::json!({
        "server": {
            "name": format!("p12-7-openstack-server-{run_tag}"),
            "image": {"id": "image-a"},
            "flavor": {"id": flavor_id},
            "networks": [{"port": port_id}]
        }
    });
    let openstack_server = app
        .clone()
        .oneshot(
            Request::builder()
                .method(Method::POST)
                .uri(format!("/v2.1/{project_id}/servers"))
                .header("x-auth-token", &token)
                .header(header::CONTENT_TYPE, "application/json")
                .header(
                    "x-openstack-request-id",
                    format!("p12-7-openstack-create-{run_tag}"),
                )
                .body(Body::from(serde_json::to_vec(&openstack_server_body)?))?,
        )
        .await?;
    let openstack_server_status = openstack_server.status();
    if openstack_server_status != StatusCode::ACCEPTED {
        let body = axum::body::to_bytes(openstack_server.into_body(), 64 * 1024).await?;
        panic!(
            "OpenStack Compute create failed: {openstack_server_status} {}",
            String::from_utf8_lossy(&body)
        );
    }
    let openstack_server_json = response_json(openstack_server).await;
    let openstack_server_id = openstack_server_json["server"]["id"]
        .as_str()
        .ok_or("OpenStack server ID")?;
    let native_server = get_json(
        &app,
        &format!("/o3k/v1/compute/servers/{openstack_server_id}"),
        &token,
    )
    .await?;
    assert_eq!(native_server["metadata"]["id"], openstack_server_id);
    assert_eq!(native_server["metadata"]["owner_scope"], project_id);

    let native_server_create = app
        .clone()
        .oneshot(
            Request::builder()
                .method(Method::POST)
                .uri("/o3k/v1/compute/servers")
                .header("authorization", format!("Bearer {token}"))
                .header(header::CONTENT_TYPE, "application/json")
                .header("idempotency-key", format!("p12-7-native-create-{run_tag}"))
                .body(Body::from(serde_json::to_vec(&serde_json::json!({
                    "kind": "compute:server",
                    "spec": {
                        "name": format!("p12-7-native-server-{run_tag}"),
                        "image_id": "image-b",
                        "flavor_id": flavor_id,
                        "network_ids": [port_id]
                    }
                }))?))?,
        )
        .await?;
    assert_eq!(native_server_create.status(), StatusCode::CREATED);
    let native_server_json = response_json(native_server_create).await;
    let native_server_id = native_server_json["resource_id"]
        .as_str()
        .ok_or("native server ID")?;
    let current_generation = native_server_json["resource"]["metadata"]["generation"]
        .as_i64()
        .ok_or("native server generation")?;
    assert!(current_generation > 0);

    // SPEC-0030 v1 generation preconditions are exercised at the native HTTP
    // boundary.  The resource starts at generation 1; a stale request is
    // rejected before the compute provider is touched, while the matching
    // request is accepted and advances durable generation through deletion.
    let before_stale_generation = provider.instance_count();
    let stale_delete = app
        .clone()
        .oneshot(
            Request::builder()
                .method(Method::DELETE)
                .uri(format!("/o3k/v1/compute/servers/{native_server_id}"))
                .header("authorization", format!("Bearer {token}"))
                .header("if-match", format!("generation-{}", current_generation - 1))
                .body(Body::empty())?,
        )
        .await?;
    assert_eq!(stale_delete.status(), StatusCode::CONFLICT);
    assert_eq!(provider.instance_count(), before_stale_generation);
    let tenant_b_generation_attempt = app
        .clone()
        .oneshot(
            Request::builder()
                .method(Method::DELETE)
                .uri(format!("/o3k/v1/compute/servers/{native_server_id}"))
                .header("authorization", format!("Bearer {token_b}"))
                .header("if-match", format!("generation-{current_generation}"))
                .body(Body::empty())?,
        )
        .await?;
    assert_eq!(tenant_b_generation_attempt.status(), StatusCode::NOT_FOUND);
    assert_eq!(provider.instance_count(), before_stale_generation);

    // Native collection pagination is exercised through HTTP, including its
    // opaque authenticated cursor rather than the cursor codec directly.
    let first_page = get_json(&app, "/o3k/v1/compute/servers?limit=1", &token).await?;
    assert_eq!(first_page["items"].as_array().map(Vec::len), Some(1));
    let next_cursor = first_page["next_cursor"]
        .as_str()
        .ok_or("native next cursor")?;
    let second_page = get_json(
        &app,
        &format!("/o3k/v1/compute/servers?limit=1&cursor={next_cursor}"),
        &token,
    )
    .await?;
    assert_eq!(second_page["items"].as_array().map(Vec::len), Some(1));
    let tampered_cursor = format!("{next_cursor}x");
    assert_eq!(
        status_for(
            &app,
            Method::GET,
            &format!("/o3k/v1/compute/servers?limit=1&cursor={tampered_cursor}"),
            &token,
        )
        .await,
        StatusCode::BAD_REQUEST
    );
    let openstack_server_read = get_json(
        &app,
        &format!("/v2.1/{project_id}/servers/{native_server_id}"),
        &token,
    )
    .await?;
    assert_eq!(openstack_server_read["server"]["id"], native_server_id);

    let matching_delete = app
        .clone()
        .oneshot(
            Request::builder()
                .method(Method::DELETE)
                .uri(format!("/o3k/v1/compute/servers/{native_server_id}"))
                .header("authorization", format!("Bearer {token}"))
                .header("if-match", format!("generation-{current_generation}"))
                .body(Body::empty())?,
        )
        .await?;
    assert_eq!(matching_delete.status(), StatusCode::NO_CONTENT);
    let deleted = store
        .get_resource(uuid::Uuid::parse_str(native_server_id)?)
        .await?;
    assert_eq!(deleted.generation, current_generation + 1);
    assert_eq!(deleted.observed_state, "DELETED");
    assert_eq!(
        status_for(
            &app,
            Method::GET,
            &format!("/v2.1/{project_id}/servers/{native_server_id}"),
            &token,
        )
        .await,
        StatusCode::NOT_FOUND
    );
    assert_eq!(
        status_for(
            &app,
            Method::DELETE,
            &format!("/v2.1/{project_id}/servers/{openstack_server_id}"),
            &token,
        )
        .await,
        StatusCode::NO_CONTENT
    );
    assert_eq!(
        status_for(
            &app,
            Method::GET,
            &format!("/o3k/v1/compute/servers/{openstack_server_id}"),
            &token,
        )
        .await,
        StatusCode::NOT_FOUND
    );

    assert_eq!(
        status_for(
            &app,
            Method::DELETE,
            &format!("/v2.0/ports/{port_id}"),
            &token,
        )
        .await,
        StatusCode::NO_CONTENT
    );
    assert_eq!(
        status_for(
            &app,
            Method::DELETE,
            &format!("/v2.0/subnets/{subnet_id}"),
            &token,
        )
        .await,
        StatusCode::NO_CONTENT
    );
    assert_eq!(
        status_for(
            &app,
            Method::DELETE,
            &format!("/v2.0/networks/{network_id}"),
            &token,
        )
        .await,
        StatusCode::NO_CONTENT
    );
    assert_eq!(
        status_for(
            &app,
            Method::GET,
            &format!("/o3k/v1/network/networks/{network_id}"),
            &token,
        )
        .await,
        StatusCode::NOT_FOUND
    );

    // The durable store is the canonical authority; the provider is only an
    // execution dependency and owns no public resource identity.
    assert_eq!(
        store
            .get_resource(uuid::Uuid::parse_str(native_server_id)?)
            .await?
            .project_id,
        project_id
    );
    Ok(())
}

#[tokio::test]
async fn native_and_openstack_http_surfaces_reconstruct_over_durable_sqlite()
-> Result<(), Box<dyn std::error::Error>> {
    let path = std::env::temp_dir().join(format!(
        "o3k-p12-7-http-restart-{}.sqlite",
        uuid::Uuid::new_v4()
    ));
    run_http_restart_conformance(HttpRestartBackend::Sqlite(path.clone())).await?;
    let _ = std::fs::remove_file(path);
    Ok(())
}

async fn run_http_restart_conformance(
    backend: HttpRestartBackend,
) -> Result<(), Box<dyn std::error::Error>> {
    let run_tag = uuid::Uuid::new_v4().simple().to_string();
    let (app_a, provider_a) =
        build_http_runtime(Arc::new(open_http_restart_store(&backend).await?)).await?;
    let token_a = issue_token_for(&app_a, "user-a", "password-a", "project-a").await?;

    let quota = get_json(&app_a, "/o3k/v1/quota", &token_a).await?;
    assert_eq!(quota["version"], "v1");
    assert_eq!(quota["scope"]["id"], "project-a");
    assert!(quota["items"].as_array().is_some());
    let quota_dimension = get_json(&app_a, "/o3k/v1/quota/compute/servers", &token_a).await?;
    assert_eq!(quota_dimension["namespace"], "compute");
    assert_eq!(quota_dimension["key"], "servers");
    // The tenant token cannot select a foreign project through the operator
    // surface, and the native read has no caller-controlled scope parameter.
    assert_eq!(
        status_for(
            &app_a,
            Method::GET,
            "/o3k/v1/operator/quotas/project-b",
            &token_a
        )
        .await,
        StatusCode::FORBIDDEN
    );

    let network = app_a
        .clone()
        .oneshot(
            Request::builder()
                .method(Method::POST)
                .uri("/v2.0/networks")
                .header("x-auth-token", &token_a)
                .header(header::CONTENT_TYPE, "application/json")
                .body(Body::from(
                    serde_json::json!({"network":{"name":format!("restart-os-network-{run_tag}")}})
                        .to_string(),
                ))?,
        )
        .await?;
    assert_eq!(network.status(), StatusCode::CREATED);
    let network_id = response_json(network).await["network"]["id"]
        .as_str()
        .ok_or("network id")?
        .to_owned();
    let native_network = app_a
        .clone()
        .oneshot(
            Request::builder()
                .method(Method::POST)
                .uri("/o3k/v1/network/networks")
                .header("authorization", format!("Bearer {token_a}"))
                .header(header::CONTENT_TYPE, "application/json")
                .body(Body::from(
                    serde_json::json!({"kind":"network:network","spec":{"name":format!("restart-native-network-{run_tag}")}}).to_string(),
                ))?,
        )
        .await?;
    assert_eq!(native_network.status(), StatusCode::CREATED);
    let native_network_id = response_json(native_network).await["resource_id"]
        .as_str()
        .ok_or("native network id")?
        .to_owned();
    let subnet = app_a.clone().oneshot(Request::builder().method(Method::POST).uri("/v2.0/subnets")
        .header("x-auth-token", &token_a).header(header::CONTENT_TYPE, "application/json")
        .body(Body::from(serde_json::json!({"subnet":{"network_id":network_id,"name":format!("restart-subnet-{run_tag}"),"cidr":"192.0.2.0/24","gateway_ip":"192.0.2.1"}}).to_string()))?).await?;
    assert_eq!(subnet.status(), StatusCode::CREATED);
    let port = app_a
        .clone()
        .oneshot(
            Request::builder()
                .method(Method::POST)
                .uri("/v2.0/ports")
                .header("x-auth-token", &token_a)
                .header(header::CONTENT_TYPE, "application/json")
                .body(Body::from(
                    serde_json::json!({"port":{"network_id":network_id,"name":format!("restart-port-{run_tag}")}})
                        .to_string(),
                ))?,
        )
        .await?;
    assert_eq!(port.status(), StatusCode::CREATED);
    let port_id = response_json(port).await["port"]["id"]
        .as_str()
        .ok_or("port id")?
        .to_owned();
    let server_body = serde_json::json!({"server":{"name":format!("restart-server-{run_tag}"),"image":{"id":"image-a"},"flavor":{"id":"00000000-0000-0000-0000-000000000001"},"networks":[{"port":port_id}]}});
    let os_server = app_a
        .clone()
        .oneshot(
            Request::builder()
                .method(Method::POST)
                .uri("/v2.1/project-a/servers")
                .header("x-auth-token", &token_a)
                .header(header::CONTENT_TYPE, "application/json")
                .body(Body::from(serde_json::to_vec(&server_body)?))?,
        )
        .await?;
    assert_eq!(os_server.status(), StatusCode::ACCEPTED);
    let os_server_id = response_json(os_server).await["server"]["id"]
        .as_str()
        .ok_or("os server id")?
        .to_owned();
    let native_server = app_a.clone().oneshot(Request::builder().method(Method::POST).uri("/o3k/v1/compute/servers")
        .header("authorization", format!("Bearer {token_a}")).header(header::CONTENT_TYPE, "application/json")
        .header("idempotency-key", format!("restart-native-server-{run_tag}"))
        .body(Body::from(serde_json::json!({"kind":"compute:server","spec":{"name":format!("restart-native-server-{run_tag}"),"image_id":"image-b","flavor_id":"00000000-0000-0000-0000-000000000001","network_ids":[port_id]}}).to_string()))?).await?;
    assert_eq!(native_server.status(), StatusCode::CREATED);
    let native_server_id = response_json(native_server).await["resource_id"]
        .as_str()
        .ok_or("native server id")?
        .to_owned();
    assert!(provider_a.instance_count() >= 2);
    let quota_after_create = get_json(&app_a, "/o3k/v1/quota/compute/servers", &token_a).await?;
    assert!(quota_after_create["usage"].as_u64().unwrap_or_default() >= 2);
    drop(app_a);
    drop(provider_a);

    let (app_b, _provider_b) =
        build_http_runtime(Arc::new(open_http_restart_store(&backend).await?)).await?;
    let token_b = issue_token_for(&app_b, "user-a", "password-a", "project-a").await?;
    for (native_path, os_path, id) in [
        (
            format!("/o3k/v1/network/networks/{network_id}"),
            format!("/v2.0/networks/{network_id}"),
            network_id.clone(),
        ),
        (
            format!("/o3k/v1/network/networks/{native_network_id}"),
            format!("/v2.0/networks/{native_network_id}"),
            native_network_id.clone(),
        ),
        (
            format!("/o3k/v1/compute/servers/{os_server_id}"),
            format!("/v2.1/project-a/servers/{os_server_id}"),
            os_server_id.clone(),
        ),
        (
            format!("/o3k/v1/compute/servers/{native_server_id}"),
            format!("/v2.1/project-a/servers/{native_server_id}"),
            native_server_id.clone(),
        ),
    ] {
        let native_read = get_json(&app_b, &native_path, &token_b).await?;
        let os_read = get_json(&app_b, &os_path, &token_b).await?;
        assert_eq!(
            native_read["metadata"]["id"]
                .as_str()
                .or_else(|| native_read["network"]["id"].as_str()),
            Some(id.as_str())
        );
        assert_eq!(
            os_read["network"]["id"]
                .as_str()
                .or_else(|| os_read["server"]["id"].as_str()),
            Some(id.as_str())
        );
    }
    assert_eq!(
        status_for(
            &app_b,
            Method::DELETE,
            &format!("/o3k/v1/compute/servers/{native_server_id}"),
            &token_b
        )
        .await,
        StatusCode::NO_CONTENT
    );
    assert_eq!(
        status_for(
            &app_b,
            Method::GET,
            &format!("/v2.1/project-a/servers/{native_server_id}"),
            &token_b
        )
        .await,
        StatusCode::NOT_FOUND
    );
    let quota_after_release = get_json(&app_b, "/o3k/v1/quota/compute/servers", &token_b).await?;
    assert!(quota_after_release["usage"].as_u64().unwrap_or_default() < 2);
    Ok(())
}

#[tokio::test]
#[ignore = "requires O3K_DATABASE_URL pointing at a real PostgreSQL conformance database"]
async fn native_and_openstack_http_surfaces_reconstruct_over_durable_postgres()
-> Result<(), Box<dyn std::error::Error>> {
    let url = std::env::var("O3K_DATABASE_URL")?;
    run_http_restart_conformance(HttpRestartBackend::Postgres(url)).await
}

#[tokio::test]
async fn native_http_scope_like_request_fields_cannot_select_foreign_owner()
-> Result<(), Box<dyn std::error::Error>> {
    let (app, provider) = build_http_runtime(Arc::new(
        o3k_store::unified::O3kStore::connect_sqlite_memory().await?,
    ))
    .await?;
    let token = issue_token_for(&app, "user-a", "password-a", "project-a").await?;
    let response = app
        .clone()
        .oneshot(
            Request::builder()
                .method(Method::POST)
                .uri("/o3k/v1/compute/servers")
                .header("authorization", format!("Bearer {token}"))
                .header(header::CONTENT_TYPE, "application/json")
                .header("idempotency-key", "scope-injection")
                .body(Body::from(
                    serde_json::json!({
                        "owner_scope": "project-b",
                        "project_id": "project-b",
                        "metadata": {"owner_scope": "project-b", "project_id": "project-b"},
                        "kind": "compute:server",
                        "spec": {
                            "name": "scope-injection",
                            "image_id": "image-a",
                            "flavor_id": "00000000-0000-0000-0000-000000000001",
                            "network_ids": ["opaque-network-reference"]
                        }
                    })
                    .to_string(),
                ))?,
        )
        .await?;
    assert!(response.status().is_client_error());
    assert_eq!(provider.instance_count(), 0);
    let response = app
        .clone()
        .oneshot(
            Request::builder()
                .method(Method::POST)
                .uri("/o3k/v1/compute/servers")
                .header("authorization", format!("Bearer {token}"))
                .header(header::CONTENT_TYPE, "application/json")
                .header("idempotency-key", "scope-injection-valid")
                .body(Body::from(
                    serde_json::json!({
                        "kind": "compute:server",
                        "spec": {
                            "name": "scope-injection-valid",
                            "image_id": "image-a",
                            "flavor_id": "00000000-0000-0000-0000-000000000001",
                            "network_ids": ["opaque-network-reference"]
                        }
                    })
                    .to_string(),
                ))?,
        )
        .await?;
    assert_eq!(response.status(), StatusCode::CREATED);
    let created = response_json(response).await;
    let id = created["resource_id"].as_str().ok_or("resource id")?;
    let shown = get_json(&app, &format!("/o3k/v1/compute/servers/{id}"), &token).await?;
    assert_eq!(shown["metadata"]["owner_scope"], "project-a");
    assert_eq!(provider.instance_count(), 1);

    // Scope-like fields inside the typed desired-state object are rejected by
    // schema validation rather than becoming an owner-selection mechanism.
    let rejected = app
        .clone()
        .oneshot(
            Request::builder()
                .method(Method::POST)
                .uri("/o3k/v1/compute/servers")
                .header("authorization", format!("Bearer {token}"))
                .header(header::CONTENT_TYPE, "application/json")
                .header("idempotency-key", "scope-injection-spec")
                .body(Body::from(
                    serde_json::json!({
                        "kind": "compute:server",
                        "spec": {
                            "name": "scope-injection-rejected",
                            "owner_scope": "project-b",
                            "image_id": "image-a",
                            "flavor_id": "00000000-0000-0000-0000-000000000001",
                            "network_ids": ["opaque-network-reference"]
                        }
                    })
                    .to_string(),
                ))?,
        )
        .await?;
    assert!(rejected.status().is_client_error());
    assert_eq!(provider.instance_count(), 1);
    Ok(())
}

#[tokio::test]
#[ignore = "requires the real OIDC testbed started by tests/p12-iam-7-real-idp.sh"]
async fn native_quota_operator_http_uses_real_iam_and_durable_cas()
-> Result<(), Box<dyn std::error::Error>> {
    fn required(name: &str) -> String {
        std::env::var(name).unwrap_or_else(|_| panic!("missing {name}"))
    }
    let issuer = required("O3K_P12_7_ISSUER");
    let discovery = url::Url::parse(&required("O3K_P12_7_DISCOVERY_URL"))?;
    let issuer_url = url::Url::parse(&issuer)?;
    let validator = Arc::new(o3k_identity::oidc::OidcValidator::new(
        o3k_identity::oidc::TrustedIssuer::test_local(
            "p12-7-keycloak",
            issuer_url,
            "o3k",
            discovery,
        ),
    )?);
    let store = Arc::new(if let Ok(url) = std::env::var("O3K_DATABASE_URL") {
        o3k_store::unified::O3kStore::connect_postgres(&url).await?
    } else {
        o3k_store::unified::O3kStore::connect_sqlite_file(std::path::Path::new(&required(
            "O3K_P12_7_SQLITE_PATH",
        )))
        .await?
    });
    o3k_identity::seed_identity_defaults(
        store.as_ref(),
        &o3k_identity::BootstrapConfig {
            catalog_endpoint: "http://127.0.0.1:8080".to_owned(),
            bootstrap_password: o3k_identity::Secret::new(required("O3K_P12_7_BOOTSTRAP_SECRET")),
            cinder_password: None,
            cinder_endpoint: None,
            pbkdf2_iterations: 1_000,
            extra_projects: vec![
                o3k_identity::ExtraProjectSeed {
                    project_id: "project-a".to_owned(),
                    project_name: "project-a".to_owned(),
                    user_id: "user-a".to_owned(),
                    user_name: "alice".to_owned(),
                    password: o3k_identity::Secret::new(required("O3K_P12_7_BOOTSTRAP_SECRET")),
                },
                o3k_identity::ExtraProjectSeed {
                    project_id: "project-b".to_owned(),
                    project_name: "project-b".to_owned(),
                    user_id: "user-b".to_owned(),
                    user_name: "bob".to_owned(),
                    password: o3k_identity::Secret::new(required("O3K_P12_7_BOOTSTRAP_SECRET")),
                },
            ],
        },
    )
    .await?;
    let now = "2026-09-10T00:00:00Z".to_owned();
    if store
        .find_federated_binding("p12-7-keycloak", &required("O3K_P12_7_OPERATOR_SUBJECT"))
        .await?
        .is_none()
    {
        store
            .insert_federated_binding(&o3k_store::FederatedBindingRecord {
                id: "p12-7-quota-operator".to_owned(),
                trusted_issuer_id: "p12-7-keycloak".to_owned(),
                issuer: issuer.clone(),
                subject: required("O3K_P12_7_OPERATOR_SUBJECT"),
                principal_id: "bootstrap-user".to_owned(),
                principal_type: "user".to_owned(),
                enabled: true,
                created_at: now.clone(),
                updated_at: now.clone(),
            })
            .await?;
    }
    if store.list_operator_assignments().await?.is_empty() {
        store
            .insert_operator_assignment(&o3k_store::OperatorAssignmentRecord {
                id: "p12-7-quota-operator-assignment".to_owned(),
                user_id: "bootstrap-user".to_owned(),
                profile: "operator-console".to_owned(),
                enabled: true,
                created_at: now.clone(),
                updated_at: now,
            })
            .await?;
    }
    let identity = o3k_identity::TokenService::load(
        store.clone(),
        o3k_identity::Secret::new("p12-7-real-evidence-signing-key-at-least-32-bytes".to_owned()),
        Duration::from_secs(900),
    )
    .await?;
    let (app, provider) =
        build_http_runtime_with_identity(store.clone(), identity, Some(validator)).await?;
    let body = serde_json::json!({"auth":{"method":"federated","federated":{"access_token":required("O3K_P12_7_OPERATOR_TOKEN"),"scope":{"kind":"system"}}}});
    let response = app
        .clone()
        .oneshot(
            Request::builder()
                .method(Method::POST)
                .uri("/o3k/v1/identity/tokens")
                .header(header::CONTENT_TYPE, "application/json")
                .body(Body::from(serde_json::to_vec(&body)?))?,
        )
        .await?;
    assert_eq!(response.status(), StatusCode::CREATED);
    let native_token = response_json(response).await["token"]["id"]
        .as_str()
        .ok_or("native token")?
        .to_owned();
    let before = get_json(&app, "/o3k/v1/operator/quotas/project-a", &native_token).await?;
    let generation = before["items"]
        .as_array()
        .and_then(|items| {
            items
                .iter()
                .find(|i| i["namespace"] == "compute" && i["key"] == "servers")
        })
        .and_then(|i| i["generation"].as_u64())
        .ok_or("generation")?;
    let update = serde_json::json!({"limit": {"kind": "maximum", "value": 1}, "expected_generation": generation});
    let response = app
        .clone()
        .oneshot(
            Request::builder()
                .method(Method::PUT)
                .uri("/o3k/v1/operator/quotas/project-a/compute/servers")
                .header("authorization", format!("Bearer {native_token}"))
                .header(header::CONTENT_TYPE, "application/json")
                .body(Body::from(serde_json::to_vec(&update)?))?,
        )
        .await?;
    assert_eq!(response.status(), StatusCode::OK);
    let changed = response_json(response).await;
    assert_eq!(changed["generation"], generation + 1);
    assert_eq!(changed["limit"]["kind"], "maximum");
    assert_eq!(changed["limit"]["value"], 1);
    let stale =
        serde_json::json!({"limit": {"kind": "unlimited"}, "expected_generation": generation});
    let response = app
        .clone()
        .oneshot(
            Request::builder()
                .method(Method::PUT)
                .uri("/o3k/v1/operator/quotas/project-a/compute/servers")
                .header("authorization", format!("Bearer {native_token}"))
                .header(header::CONTENT_TYPE, "application/json")
                .body(Body::from(serde_json::to_vec(&stale)?))?,
        )
        .await?;
    assert_eq!(response.status(), StatusCode::CONFLICT);

    // The same real HTTP composition now proves the configured limit is
    // enforced before the execution provider is touched.
    let tenant_body = serde_json::json!({"auth":{"method":"federated","project_id":"project-a","federated":{"access_token":required("O3K_P12_7_ALICE_TOKEN")}}});
    let response = app
        .clone()
        .oneshot(
            Request::builder()
                .method(Method::POST)
                .uri("/o3k/v1/identity/tokens")
                .header(header::CONTENT_TYPE, "application/json")
                .body(Body::from(serde_json::to_vec(&tenant_body)?))?,
        )
        .await?;
    if response.status() != StatusCode::CREATED {
        let status = response.status();
        let body = axum::body::to_bytes(response.into_body(), 64 * 1024).await?;
        panic!(
            "tenant token failed: {status} {}",
            String::from_utf8_lossy(&body)
        );
    }
    let tenant_token = response_json(response).await["token"]["id"]
        .as_str()
        .ok_or("tenant token")?
        .to_owned();
    let network_response = app
        .clone()
        .oneshot(
            Request::builder()
                .method(Method::POST)
                .uri("/o3k/v1/network/networks")
                .header("authorization", format!("Bearer {tenant_token}"))
                .header(header::CONTENT_TYPE, "application/json")
                .body(Body::from(
                    serde_json::json!({"kind":"network:network","spec":{"name":"quota-http-network"}}).to_string(),
                ))?,
        )
        .await?;
    assert_eq!(network_response.status(), StatusCode::CREATED);
    let network_id = response_json(network_response).await["resource_id"]
        .as_str()
        .ok_or("quota network id")?
        .to_owned();
    // A canonical network is not attachable until it has a bounded-flat
    // subnet/realm.  Native compute resolves network UUIDs through the
    // canonical Network authority and creates its endpoint there; keep this
    // real-IAM quota test on the same supported network contract instead of
    // relying on an opaque compatibility reference or a provider shortcut.
    let subnet_response = app
        .clone()
        .oneshot(
            Request::builder()
                .method(Method::POST)
                .uri("/v2.0/subnets")
                .header("x-auth-token", &tenant_token)
                .header(header::CONTENT_TYPE, "application/json")
                .body(Body::from(
                    serde_json::json!({
                        "subnet": {
                            "network_id": network_id,
                            "name": "quota-http-subnet",
                            "cidr": "192.0.2.0/24",
                            "gateway_ip": "192.0.2.1"
                        }
                    })
                    .to_string(),
                ))?,
        )
        .await?;
    if subnet_response.status() != StatusCode::CREATED {
        let status = subnet_response.status();
        let body = axum::body::to_bytes(subnet_response.into_body(), 64 * 1024).await?;
        panic!(
            "quota subnet create failed: {status} {}",
            String::from_utf8_lossy(&body)
        );
    }
    let create_body = serde_json::json!({"kind":"compute:server","spec":{"name":"quota-http-server","image_id":"image-a","flavor_id":"00000000-0000-0000-0000-000000000001","network_ids":[network_id]}});
    let response = app
        .clone()
        .oneshot(
            Request::builder()
                .method(Method::POST)
                .uri("/o3k/v1/compute/servers")
                .header("authorization", format!("Bearer {tenant_token}"))
                .header(header::CONTENT_TYPE, "application/json")
                .header("idempotency-key", "quota-http-server-1")
                .body(Body::from(serde_json::to_vec(&create_body)?))?,
        )
        .await?;
    if response.status() != StatusCode::CREATED {
        let status = response.status();
        let body = axum::body::to_bytes(response.into_body(), 64 * 1024).await?;
        panic!(
            "quota create failed: {status} {}",
            String::from_utf8_lossy(&body)
        );
    }
    let before_provider = provider.instance_count();
    let response = app
        .clone()
        .oneshot(
            Request::builder()
                .method(Method::POST)
                .uri("/o3k/v1/compute/servers")
                .header("authorization", format!("Bearer {tenant_token}"))
                .header(header::CONTENT_TYPE, "application/json")
                .header("idempotency-key", "quota-http-server-2")
                .body(Body::from(serde_json::to_vec(&create_body)?))?,
        )
        .await?;
    assert!(
        response.status().is_client_error(),
        "quota rejection: {}",
        response.status()
    );
    assert_eq!(provider.instance_count(), before_provider);
    Ok(())
}

#[tokio::test]
async fn native_and_openstack_http_surfaces_share_compute_and_network_authority()
-> Result<(), Box<dyn std::error::Error>> {
    run_native_openstack_http_conformance(Arc::new(
        o3k_store::unified::O3kStore::connect_sqlite_memory().await?,
    ))
    .await
}

#[tokio::test]
#[ignore = "requires O3K_DATABASE_URL pointing at a real PostgreSQL conformance database"]
async fn native_and_openstack_http_surfaces_share_compute_and_network_authority_postgres()
-> Result<(), Box<dyn std::error::Error>> {
    let url = std::env::var("O3K_DATABASE_URL")?;
    run_native_openstack_http_conformance(Arc::new(
        o3k_store::unified::O3kStore::connect_postgres(&url).await?,
    ))
    .await
}
