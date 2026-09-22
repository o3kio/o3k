//! PP.4 Core #1034 — server-owned network endpoint lifecycle across both
//! interfaces.
//!
//! The rc.23 public campaign proved the invariant was missing: deleting a
//! compatibility-created server through the *native* interface marked the
//! server `DELETED` while its auto-created port stayed `ACTIVE`, so the shipped
//! TestLab teardown could no longer delete the subnet. The mirror path
//! (native-created server deleted through the compatibility interface) released
//! its port, so the two interfaces kept different durable state for the same
//! logical operation.
//!
//! These tests are the interface-symmetry matrix for that invariant, plus the
//! safety cases that must survive the fix: a caller-supplied endpoint is never
//! removed, a foreign endpoint is never touched, a delete replay converges
//! again, and a create whose outcome is unknown keeps its endpoint so a real
//! guest is never stripped of its network dependency.
//!
//! Everything runs through the real registrations: the OpenStack `/v2.1` and
//! `/v2.0` routers, the native `/o3k/v1` router, the real `NetworkService`, and
//! the production `NetworkBindingProjector` the composition root wires. Only
//! the compute execution provider is a fake.
#![allow(clippy::expect_used, clippy::panic)]

use super::NetworkBindingProjector;
use axum::body::Body;
use axum::http::{Method, Request, StatusCode, header};
use o3k_compute::ComputeService;
use o3k_kernel::{
    ControllerSession, ManifestRegistry, PrincipalId, ProtocolVersion, ServicePrincipal,
};
use o3k_native_api::auth::TokenIssuer;
use o3k_network::NetworkService;
use o3k_provider::{FailureInjection, FakeComputeProvider};
use o3k_store::DurableStore;
use o3k_store::unified::O3kStore;
use serde_json::{Value, json};
use std::sync::Arc;
use tower::ServiceExt;
use uuid::Uuid;

const PROJECT_A: &str = "project-a";
const PROJECT_B: &str = "project-b";
const FLAVOR_ID: &str = "00000000-0000-0000-0000-000000000001";

fn session(service: &str, namespace: &str) -> ControllerSession {
    ControllerSession {
        service_id: service.to_owned(),
        namespace: namespace.to_owned(),
        service_principal: ServicePrincipal::new(
            PrincipalId::new_unchecked(format!("{service}-controller")),
            format!("{service}-controller"),
            namespace,
        ),
        session_id: Uuid::new_v4(),
        session_generation: 1,
        protocol_version: ProtocolVersion::new(1, 0),
        manifest_digest: format!("pp4-endpoint-{service}"),
        manifest_generation: 1,
        started_at: "2026-09-01T00:00:00Z".to_owned(),
    }
}

struct Harness {
    app: axum::Router,
    store: Arc<O3kStore>,
    network: Arc<NetworkService>,
    provider: Arc<FakeComputeProvider>,
    token_a: String,
    token_b: String,
    network_id: Uuid,
    subnet_id: Uuid,
    foreign_network_id: Uuid,
    root: std::path::PathBuf,
}

impl Harness {
    async fn build() -> Result<Self, Box<dyn std::error::Error + Send + Sync>> {
        let root = std::env::temp_dir().join(format!("o3k-pp4-endpoint-{}", Uuid::now_v7()));
        std::fs::create_dir_all(&root)?;
        let sqlite_path = root.join("cloud.sqlite");
        let store = Arc::new(O3kStore::connect_sqlite_file(&sqlite_path).await?);
        let identity = o3k_identity::testkit::test_service_with_projects(
            "http://127.0.0.1:8080",
            vec![
                o3k_identity::ExtraProjectSeed {
                    project_id: PROJECT_A.to_owned(),
                    project_name: PROJECT_A.to_owned(),
                    user_id: "user-a".to_owned(),
                    user_name: "user-a".to_owned(),
                    password: o3k_identity::Secret::new("password-a".to_owned()),
                },
                o3k_identity::ExtraProjectSeed {
                    project_id: PROJECT_B.to_owned(),
                    project_name: PROJECT_B.to_owned(),
                    user_id: "user-b".to_owned(),
                    user_name: "user-b".to_owned(),
                    password: o3k_identity::Secret::new("password-b".to_owned()),
                },
            ],
        )
        .await?;
        let provider = Arc::new(FakeComputeProvider::new());
        let network =
            Arc::new(NetworkService::open_for_test(root.join("network"), store.clone()).await?);
        // The production binding projector: the composition root wires exactly
        // this type, so the endpoint release path exercised here is the shipped
        // one rather than a test double.
        let projector = Arc::new(NetworkBindingProjector {
            network: (*network).clone(),
            registry: Arc::new(o3k_compute_agent::NodeRegistry::default()),
            network_dispatcher: None,
            network_controller: o3k_network::NetworkControllerLease {
                controller_id: "pp4-endpoint-controller".to_owned(),
                controller_epoch: "pp4-endpoint-epoch".to_owned(),
                fencing_token: 1,
            },
            network_external_realm_id: None,
            network_agent: None,
            public_allocator: None,
            unbind_lock: Arc::new(tokio::sync::Mutex::new(())),
        });
        let compute_service = ComputeService::new_for_test(store.clone(), provider.clone())
            .with_binding_projector(projector);
        let compute = Arc::new(compute_service.clone());
        let mut manifests = ManifestRegistry::new();
        manifests.seed_core()?;
        for (service, namespace) in [("compute", "compute"), ("network", "network")] {
            manifests.register_controller(service, session(service, namespace))?;
            manifests.activate_controller(service)?;
        }
        let server_reader: Arc<dyn o3k_native_api::compute::ServerReader> =
            Arc::new(crate::native_adapters::ServerReaderAdapter {
                service: compute.clone(),
            });
        let network_reader: Arc<dyn o3k_native_api::network::NetworkReader> =
            Arc::new(crate::native_adapters::NetworkReaderAdapter {
                store: store.clone(),
                authorizer: Arc::new(o3k_kernel::StaticAuthorizer::standard()),
            });
        let application: Arc<dyn o3k_native_api::resource::ResourceApplication> =
            Arc::new(crate::native_adapters::GenericResourceApplication {
                compute: compute.clone(),
                image: None,
                network_service: network.clone(),
                store: store.clone(),
                storage_provider: Some(Arc::new(
                    o3k_storage::testkit::InMemoryStorageProvider::default(),
                )),
                server: server_reader.clone(),
                network: network_reader.clone(),
                external_controllers: Arc::new(Default::default()),
                public_allocator: None,
                public_address_workflow: None,
                network_external_realm_id: None,
                attachment_workflow: None,
                metering: None,
            });
        let token_issuer: Arc<dyn TokenIssuer> =
            Arc::new(crate::native_adapters::TokenIssuerAdapter {
                service: Arc::new(identity.clone()),
                oidc_validator: None,
            });
        let native = o3k_native_api::NativeApiState::new(
            Some(manifests),
            o3k_native_api::pagination::CursorConfig::new(
                b"pp4-endpoint-native-cursor-key-32b".to_vec(),
            )?,
            Some(token_issuer),
            Some(server_reader),
            None,
            Some(network_reader),
        )?
        .with_resource_application(application)
        .with_quota_reader(Arc::new(crate::native_adapters::QuotaReaderAdapter::new(
            store.clone(),
        )))
        .with_authorizer(Arc::new(o3k_kernel::StaticAuthorizer::standard()));
        let app = o3k_api::router_with_state(
            o3k_api::AppState::new()
                .with_identity(identity)
                .with_compute(compute_service)
                .with_network((*network).clone())
                .with_native_api(native),
        );
        let token_a = issue_token(&app, "user-a", "password-a", PROJECT_A).await?;
        let token_b = issue_token(&app, "user-b", "password-b", PROJECT_B).await?;
        let network_row = network
            .create_network_for_project(PROJECT_A, "pp4-endpoint-network".to_owned())
            .await?;
        let subnet = network
            .create_subnet_for_project(
                PROJECT_A,
                network_row.id,
                "pp4-endpoint-subnet".to_owned(),
                "192.0.2.0/24".to_owned(),
                None,
                None,
                None,
            )
            .await?;
        let foreign = network
            .create_network_for_project(PROJECT_B, "pp4-endpoint-foreign".to_owned())
            .await?;
        network
            .create_subnet_for_project(
                PROJECT_B,
                foreign.id,
                "pp4-endpoint-foreign-subnet".to_owned(),
                "198.51.100.0/24".to_owned(),
                None,
                None,
                None,
            )
            .await?;
        Ok(Self {
            app,
            store,
            network,
            provider,
            token_a,
            token_b,
            network_id: network_row.id,
            subnet_id: subnet.id,
            foreign_network_id: foreign.id,
            root,
        })
    }

    async fn send(&self, request: Request<Body>) -> (StatusCode, Value) {
        let response = self.app.clone().oneshot(request).await.expect("response");
        let status = response.status();
        let bytes = axum::body::to_bytes(response.into_body(), 256 * 1024)
            .await
            .expect("body");
        let body = serde_json::from_slice(&bytes).unwrap_or(Value::Null);
        (status, body)
    }

    /// OpenStack `/v2.1` create. `networks` is passed through verbatim so a
    /// test can supply either a network UUID (O3K creates the endpoint) or an
    /// existing port UUID (the caller owns the endpoint).
    async fn compat_create(
        &self,
        name: &str,
        networks: Value,
    ) -> Result<(StatusCode, Value), Box<dyn std::error::Error + Send + Sync>> {
        let request = Request::builder()
            .method(Method::POST)
            .uri(format!("/v2.1/{PROJECT_A}/servers"))
            .header("x-auth-token", &self.token_a)
            .header(header::CONTENT_TYPE, "application/json")
            .header("x-openstack-request-id", name)
            .body(Body::from(serde_json::to_vec(&json!({
                "server": {
                    "name": name,
                    "image": {"id": "pp4-image"},
                    "flavor": {"id": FLAVOR_ID},
                    "networks": networks,
                }
            }))?))?;
        Ok(self.send(request).await)
    }

    async fn native_create(
        &self,
        name: &str,
        network_ids: Value,
    ) -> Result<(StatusCode, Value), Box<dyn std::error::Error + Send + Sync>> {
        let request = Request::builder()
            .method(Method::POST)
            .uri("/o3k/v1/compute/servers")
            .header("authorization", format!("Bearer {}", self.token_a))
            .header(header::CONTENT_TYPE, "application/json")
            .header("idempotency-key", name)
            .body(Body::from(serde_json::to_vec(&json!({
                "kind": "compute:server",
                "spec": {
                    "name": name,
                    "image_id": "pp4-image",
                    "flavor_id": FLAVOR_ID,
                    "network_ids": network_ids,
                }
            }))?))?;
        Ok(self.send(request).await)
    }

    async fn compat_delete(&self, id: &str) -> StatusCode {
        let request = Request::builder()
            .method(Method::DELETE)
            .uri(format!("/v2.1/{PROJECT_A}/servers/{id}"))
            .header("x-auth-token", &self.token_a)
            .body(Body::empty())
            .expect("request");
        self.send(request).await.0
    }

    async fn native_delete(&self, id: &str) -> (StatusCode, Value) {
        let request = Request::builder()
            .method(Method::DELETE)
            .uri(format!("/o3k/v1/compute/servers/{id}"))
            .header("authorization", format!("Bearer {}", self.token_a))
            .header("idempotency-key", format!("pp4-endpoint-delete-{id}"))
            .body(Body::empty())
            .expect("request");
        self.send(request).await
    }

    /// The ports the server's durable create intent names.
    async fn intent_ports(
        &self,
        id: &str,
    ) -> Result<Vec<Uuid>, Box<dyn std::error::Error + Send + Sync>> {
        let resource = self.store.get_resource(Uuid::parse_str(id)?).await?;
        let intent: Value = serde_json::from_str(&resource.desired_state)?;
        Ok(intent["network_ids"]
            .as_array()
            .map(|ids| {
                ids.iter()
                    .filter_map(|id| id.as_str())
                    .filter_map(|id| Uuid::parse_str(id).ok())
                    .collect()
            })
            .unwrap_or_default())
    }

    /// The project's durable endpoints, as the tenant-facing list sees them.
    async fn project_ports(&self) -> Result<Vec<Uuid>, Box<dyn std::error::Error + Send + Sync>> {
        let request = Request::builder()
            .uri(format!("/v2.0/ports?project_id={PROJECT_A}"))
            .header("x-auth-token", &self.token_a)
            .body(Body::empty())?;
        let (status, body) = self.send(request).await;
        assert_eq!(status, StatusCode::OK, "{body}");
        Ok(body["ports"]
            .as_array()
            .map(|ports| {
                ports
                    .iter()
                    .filter_map(|port| port["id"].as_str())
                    .filter_map(|id| Uuid::parse_str(id).ok())
                    .collect()
            })
            .unwrap_or_default())
    }

    async fn port_present(&self, port: Uuid) -> bool {
        self.network
            .get_port_for_project(PROJECT_A, port)
            .await
            .is_ok()
    }

    fn cleanup(&self) {
        let _ = std::fs::remove_dir_all(&self.root);
    }
}

async fn issue_token(
    app: &axum::Router,
    user: &str,
    password: &str,
    project: &str,
) -> Result<String, Box<dyn std::error::Error + Send + Sync>> {
    let body = json!({
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

/// The four interface combinations must converge on identical durable state,
/// and a caller-supplied endpoint must survive every one of them.
///
/// This is the invariant rc.23 proved was missing. The table is exactly the one
/// #1034 requires:
///
/// | create    | delete     | auto-created endpoint |
/// | --------- | ---------- | --------------------- |
/// | native    | native     | absent                |
/// | native    | OpenStack  | absent                |
/// | OpenStack | native     | absent                |
/// | OpenStack | OpenStack  | absent                |
#[tokio::test]
async fn server_owned_endpoints_converge_for_every_interface_pair()
-> Result<(), Box<dyn std::error::Error + Send + Sync>> {
    let harness = Harness::build().await?;
    let network_id = harness.network_id;

    for (create_native, delete_native) in
        [(true, true), (true, false), (false, true), (false, false)]
    {
        let name = format!(
            "pp4-{}-{}-{}",
            if create_native { "native" } else { "openstack" },
            if delete_native { "native" } else { "openstack" },
            Uuid::new_v4().simple()
        );
        let (status, body) = if create_native {
            harness
                .native_create(&name, json!([network_id.to_string()]))
                .await?
        } else {
            harness
                .compat_create(&name, json!([{"uuid": network_id.to_string()}]))
                .await?
        };
        assert!(
            status == StatusCode::CREATED || status == StatusCode::ACCEPTED,
            "create {name}: {status} {body}"
        );
        let id = body["resource_id"]
            .as_str()
            .or_else(|| body["server"]["id"].as_str())
            .expect("server id")
            .to_owned();
        let ports = harness.intent_ports(&id).await?;
        assert_eq!(ports.len(), 1, "auto-created endpoint for {name}");
        assert!(harness.port_present(ports[0]).await);

        if delete_native {
            let (status, body) = harness.native_delete(&id).await;
            assert!(status.is_success(), "native delete {name}: {status} {body}");
        } else {
            assert!(harness.compat_delete(&id).await.is_success());
        }
        assert!(
            !harness.port_present(ports[0]).await,
            "{name}: the delete left its server-owned endpoint behind"
        );
    }

    harness.cleanup();
    Ok(())
}

/// A server attaching an endpoint the caller created is not the same as the
/// server owning it: both interfaces must delete the server and preserve the
/// port (and its address) for its owner.
#[tokio::test]
async fn caller_supplied_endpoints_are_preserved_on_delete()
-> Result<(), Box<dyn std::error::Error + Send + Sync>> {
    let harness = Harness::build().await?;
    let network_id = harness.network_id;

    for delete_native in [true, false] {
        let name = format!("pp4-supplied-{}", Uuid::new_v4().simple());
        let supplied = harness
            .network
            .create_port_for_project(PROJECT_A, network_id, "tenant-port".to_owned())
            .await?;
        let (status, body) = harness
            .compat_create(&name, json!([{"port": supplied.id.to_string()}]))
            .await?;
        assert!(
            status == StatusCode::CREATED || status == StatusCode::ACCEPTED,
            "create {name}: {status} {body}"
        );
        let id = body["server"]["id"].as_str().expect("server id").to_owned();
        let ports = harness.intent_ports(&id).await?;
        assert_eq!(ports, vec![supplied.id]);

        if delete_native {
            let (status, body) = harness.native_delete(&id).await;
            assert!(status.is_success(), "native delete {name}: {status} {body}");
        } else {
            assert!(harness.compat_delete(&id).await.is_success());
        }
        assert!(
            harness.port_present(supplied.id).await,
            "{name}: the server delete removed a caller-supplied endpoint"
        );
    }

    harness.cleanup();
    Ok(())
}

/// Replaying the same delete must converge again and must not fail just because
/// the endpoint is already gone.
#[tokio::test]
async fn delete_replay_keeps_the_endpoint_absent()
-> Result<(), Box<dyn std::error::Error + Send + Sync>> {
    let harness = Harness::build().await?;
    let network_id = harness.network_id;
    let (status, body) = harness
        .compat_create("pp4-replay", json!([{"uuid": network_id.to_string()}]))
        .await?;
    assert_eq!(status, StatusCode::ACCEPTED, "{body}");
    let id = body["server"]["id"].as_str().expect("server id").to_owned();
    let ports = harness.intent_ports(&id).await?;

    let (first, body) = harness.native_delete(&id).await;
    assert!(first.is_success(), "{first} {body}");
    assert!(!harness.port_present(ports[0]).await);

    // The replay resolves the same canonical delete and converges again: the
    // endpoint is already gone, which must be idempotent success, not a failed
    // cleanup.
    let (replay, body) = harness.native_delete(&id).await;
    assert_eq!(replay, StatusCode::NO_CONTENT, "replay {replay} {body}");
    assert!(!harness.port_present(ports[0]).await);

    harness.cleanup();
    Ok(())
}

/// After every server the campaign created has been deleted, the subnet must be
/// deletable. This is the rc.23 phase-10 blocker expressed as a test: an ACTIVE
/// server-owned endpoint that nobody released kept the subnet in use.
#[tokio::test]
async fn subnet_becomes_deletable_once_server_endpoints_are_released()
-> Result<(), Box<dyn std::error::Error + Send + Sync>> {
    let harness = Harness::build().await?;
    let network_id = harness.network_id;

    let (create_status, body) = harness
        .compat_create("pp4-teardown", json!([{"uuid": network_id.to_string()}]))
        .await?;
    assert_eq!(create_status, StatusCode::ACCEPTED, "{body}");
    let compat_id = body["server"]["id"].as_str().expect("server id").to_owned();
    let (create_status, body) = harness
        .native_create("pp4-teardown-native", json!([network_id.to_string()]))
        .await?;
    assert_eq!(create_status, StatusCode::CREATED, "{body}");
    let native_id = body["resource_id"].as_str().expect("server id").to_owned();

    assert!(harness.native_delete(&compat_id).await.0.is_success());
    assert!(harness.compat_delete(&native_id).await.is_success());

    let request = Request::builder()
        .method(Method::DELETE)
        .uri(format!("/v2.0/subnets/{}", harness.subnet_id))
        .header("x-auth-token", &harness.token_a)
        .body(Body::empty())?;
    let (status, body) = harness.send(request).await;
    assert_eq!(status, StatusCode::NO_CONTENT, "subnet delete: {body}");
    assert!(
        harness.project_ports().await?.is_empty(),
        "the subnet delete succeeded with server endpoints still present"
    );

    harness.cleanup();
    Ok(())
}

/// A create that terminates in a failed operation must release the endpoint it
/// allocated, while keeping the `ERROR` resource and the failed operation as
/// terminal evidence.
#[tokio::test]
async fn terminal_create_failure_releases_the_endpoint_and_keeps_the_evidence()
-> Result<(), Box<dyn std::error::Error + Send + Sync>> {
    let harness = Harness::build().await?;
    let network_id = harness.network_id;
    harness.provider.set_failure(FailureInjection::Terminal)?;
    let (status, body) = harness
        .compat_create(
            "pp4-failed-create",
            json!([{"uuid": network_id.to_string()}]),
        )
        .await?;
    assert!(
        !status.is_success(),
        "a terminal provider failure must not report success: {status} {body}"
    );
    harness.provider.set_failure(FailureInjection::None)?;

    // The failed create left no endpoint behind.
    let ports = harness.project_ports().await?;
    assert!(
        ports.is_empty(),
        "a terminally failed create left endpoints: {ports:?}"
    );
    // The address is reusable: a later create on the same subnet allocates.
    let (status, body) = harness
        .compat_create(
            "pp4-after-failure",
            json!([{"uuid": network_id.to_string()}]),
        )
        .await?;
    assert_eq!(status, StatusCode::ACCEPTED, "{body}");
    let recovered = body["server"]["id"].as_str().expect("server id").to_owned();
    let recovered_ports = harness.intent_ports(&recovered).await?;
    assert_eq!(recovered_ports.len(), 1);
    assert!(harness.port_present(recovered_ports[0]).await);

    // The failed attempt is retained as durable terminal evidence.
    let failed = harness
        .store
        .get_resource(uuid::Uuid::new_v5(
            &uuid::Uuid::NAMESPACE_URL,
            format!("o3k:server:{PROJECT_A}:pp4-failed-create").as_bytes(),
        ))
        .await;
    // The compat adapter keys the create by the OpenStack request id, which is
    // the server name here.
    if let Ok(record) = failed {
        assert_eq!(record.observed_state, "ERROR");
        let intent: Value = serde_json::from_str(&record.desired_state)?;
        let operation_id = Uuid::parse_str(intent["operation_id"].as_str().expect("operation id"))?;
        let operation = harness.store.get_operation(operation_id).await?;
        assert_eq!(operation.state, o3k_store::OperationState::Failed);
    } else {
        panic!("terminal create failure left no durable resource to inspect");
    }

    harness.cleanup();
    Ok(())
}

/// The over-compensation guard: while a create is still converging, its
/// endpoint must be preserved, because a real guest may already exist and
/// deleting its endpoint would strip a live workload of its network
/// dependency. Only a durable *terminal failed* create may compensate.
#[tokio::test]
async fn in_flight_create_outcome_preserves_the_endpoint()
-> Result<(), Box<dyn std::error::Error + Send + Sync>> {
    let harness = Harness::build().await?;
    let network_id = harness.network_id;
    harness
        .provider
        .set_failure(FailureInjection::PartialCompletion)?;
    let (create_status, body) = harness
        .compat_create("pp4-in-flight", json!([{"uuid": network_id.to_string()}]))
        .await?;
    let id = body["server"]["id"]
        .as_str()
        .unwrap_or_else(|| panic!("create: {create_status} {body}"))
        .to_owned();
    harness.provider.set_failure(FailureInjection::None)?;

    let ports = harness.intent_ports(&id).await?;
    assert_eq!(ports.len(), 1);
    // The durable canonical operation proves the create has not terminated, so
    // the surviving endpoint is the intended behaviour rather than a side
    // effect of the request never having allocated one.
    let resource = harness.store.get_resource(Uuid::parse_str(&id)?).await?;
    let intent: Value = serde_json::from_str(&resource.desired_state)?;
    let operation = harness
        .store
        .get_operation(Uuid::parse_str(
            intent["operation_id"].as_str().expect("operation id"),
        )?)
        .await?;
    assert!(
        !matches!(
            operation.state,
            o3k_store::OperationState::Succeeded | o3k_store::OperationState::Failed
        ),
        "the create must still be converging for this guard to mean anything: {:?}",
        operation.state
    );
    assert!(
        harness.port_present(ports[0]).await,
        "an in-flight create outcome must preserve its endpoint for reconciliation"
    );

    // Re-driving the same create is rejected as a conflict — an *error
    // response* on the create path — and that rejection must not compensate the
    // in-flight server's endpoint. This is the shape the rc.23 rehearsal
    // produced (`compute operation conflicts with current state`): it must not
    // be allowed to delete a live server's network dependency.
    let (retry_status, retry_body) = harness
        .compat_create("pp4-in-flight", json!([{"uuid": network_id.to_string()}]))
        .await?;
    assert_eq!(retry_status, StatusCode::CONFLICT, "{retry_body}");
    assert!(
        harness.port_present(ports[0]).await,
        "a rejected in-flight create replay compensated a live server's endpoint"
    );

    harness.cleanup();
    Ok(())
}

/// A create whose provider accepted the instance must keep its endpoint even
/// when the provider could not report the outcome: the durable server is live,
/// so its network dependency is not a leftover.
#[tokio::test]
async fn live_create_outcome_preserves_the_endpoint()
-> Result<(), Box<dyn std::error::Error + Send + Sync>> {
    let harness = Harness::build().await?;
    let network_id = harness.network_id;
    harness.provider.set_failure(FailureInjection::Timeout)?;
    let (create_status, body) = harness
        .compat_create(
            "pp4-live-outcome",
            json!([{"uuid": network_id.to_string()}]),
        )
        .await?;
    harness.provider.set_failure(FailureInjection::None)?;
    let id = body["server"]["id"]
        .as_str()
        .unwrap_or_else(|| panic!("create: {create_status} {body}"))
        .to_owned();
    let ports = harness.intent_ports(&id).await?;
    assert_eq!(ports.len(), 1);

    assert!(
        harness.port_present(ports[0]).await,
        "a live server lost the endpoint its network attachment needs"
    );
    let (status, body) = harness.native_delete(&id).await;
    assert!(status.is_success(), "delete: {status} {body}");
    assert!(
        !harness.port_present(ports[0]).await,
        "the delete of the live server did not release its endpoint"
    );

    harness.cleanup();
    Ok(())
}

/// A project can never attach, and therefore can never release, another
/// project's endpoint: the compatibility create rejects the foreign reference
/// before any compute or network side effect, and the foreign endpoint
/// survives.
#[tokio::test]
async fn foreign_endpoint_can_neither_be_attached_nor_released()
-> Result<(), Box<dyn std::error::Error + Send + Sync>> {
    let harness = Harness::build().await?;
    let foreign = harness
        .network
        .create_port_for_project(PROJECT_B, harness.foreign_network_id, "foreign".to_owned())
        .await?;

    let (status, body) = harness
        .compat_create(
            "pp4-foreign-attachment",
            json!([{"port": foreign.id.to_string()}]),
        )
        .await?;
    assert_eq!(
        status,
        StatusCode::NOT_FOUND,
        "a foreign endpoint reference must stay concealed: {body}"
    );
    assert!(
        harness
            .network
            .get_port_for_project(PROJECT_B, foreign.id)
            .await
            .is_ok(),
        "a foreign project's endpoint was released by another project's request"
    );
    let foreign_ports_request = Request::builder()
        .uri("/v2.0/ports")
        .header("x-auth-token", &harness.token_b)
        .body(Body::empty())?;
    let (status, body) = harness.send(foreign_ports_request).await;
    assert_eq!(status, StatusCode::OK, "{body}");
    assert!(
        body["ports"].as_array().is_some_and(|ports| ports
            .iter()
            .any(|port| port["id"] == foreign.id.to_string())),
        "the foreign project must still own its endpoint: {body}"
    );

    harness.cleanup();
    Ok(())
}

/// Two independent equivalent deletes of the same server must converge on one
/// deletion: no internal error, no double release, and the endpoint gone.
#[tokio::test]
async fn concurrent_equivalent_deletes_converge_once()
-> Result<(), Box<dyn std::error::Error + Send + Sync>> {
    let harness = Harness::build().await?;
    let network_id = harness.network_id;
    let (status, body) = harness
        .compat_create(
            "pp4-concurrent-delete",
            json!([{"uuid": network_id.to_string()}]),
        )
        .await?;
    assert_eq!(status, StatusCode::ACCEPTED, "{body}");
    let id = body["server"]["id"].as_str().expect("server id").to_owned();
    let ports = harness.intent_ports(&id).await?;

    let (first, second) = tokio::join!(harness.native_delete(&id), harness.native_delete(&id));
    for (status, body) in [first, second] {
        assert!(
            status.is_success() && !status.is_server_error(),
            "concurrent equivalent delete: {status} {body}"
        );
    }
    for port in ports {
        assert!(
            !harness.port_present(port).await,
            "server-owned endpoint {port} survived the delete"
        );
    }
    // The address is reusable afterwards.
    let (status, body) = harness
        .compat_create(
            "pp4-after-concurrent",
            json!([{"uuid": network_id.to_string()}]),
        )
        .await?;
    assert_eq!(status, StatusCode::ACCEPTED, "{body}");

    harness.cleanup();
    Ok(())
}
