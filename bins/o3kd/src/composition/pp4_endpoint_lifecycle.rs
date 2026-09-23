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
//! PP.5 #1035 adds the *repair* seat for the same invariant: the window where
//! the canonical delete is already durably terminal but the process died
//! before the request-path release. The sweep cases live here too, because
//! they reuse this harness and must not be provable without the real
//! `NetworkService` ownership rule behind the projector.
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
use o3k_store::ComputeRepository;
use o3k_store::DurableStore;
use o3k_store::unified::O3kStore;
use serde_json::{Value, json};
use sqlx::{Connection, postgres::PgConnection};
use std::sync::Arc;
use std::time::Duration;
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

/// Wraps the production binding projector; tests use it to fault-inject the
/// collaborator boundary without replacing the authority behind it.
type ProjectorWrapper = Arc<
    dyn Fn(
            &NetworkService,
            Arc<dyn o3k_compute::PortBindingProjector>,
        ) -> Arc<dyn o3k_compute::PortBindingProjector>
        + Send
        + Sync,
>;

/// Which durable store the harness runtime is built over. The #1035 orphan
/// window is a property of the *durable* canonical state, so the same harness
/// must be able to run it against both SQLite (the portable default) and real
/// PostgreSQL (the production-conformance register).
#[derive(Clone)]
enum HarnessBackend {
    Sqlite,
    Postgres { url: String },
}

struct Harness {
    app: axum::Router,
    store: Arc<O3kStore>,
    network: Arc<NetworkService>,
    provider: Arc<FakeComputeProvider>,
    /// The same service instance the router drives. The PP.5 orphan-repair
    /// tests spawn the shipped periodic reconciler from it rather than calling
    /// a test-only convergence pass.
    compute: Arc<ComputeService>,
    token_a: String,
    token_b: String,
    network_id: Uuid,
    subnet_id: Uuid,
    foreign_network_id: Uuid,
    root: std::path::PathBuf,
}

impl Harness {
    async fn build() -> Result<Self, Box<dyn std::error::Error + Send + Sync>> {
        Self::build_with(None).await
    }

    /// Builds the runtime with the production binding projector, optionally
    /// wrapped in a fault injector so the transient-failure retry contract can
    /// be exercised against the real projector behind it.
    async fn build_with(
        projector_wrapper: Option<ProjectorWrapper>,
    ) -> Result<Self, Box<dyn std::error::Error + Send + Sync>> {
        let root = std::env::temp_dir().join(format!("o3k-pp4-endpoint-{}", Uuid::now_v7()));
        Self::build_at(root, projector_wrapper).await
    }

    /// Rebuilds the runtime over an existing durable root, the way a restarted
    /// control plane would. SQLite: the SQLite file and the network state root
    /// are the only inputs. PostgreSQL: a *new connection to the same database*
    /// without cleaning it, mirroring the SQLite case re-opening the same file.
    /// Everything this runtime then observes is durable state written by the
    /// previous one. Used by the #1035 crash/restart regression.
    async fn build_at(
        root: std::path::PathBuf,
        projector_wrapper: Option<ProjectorWrapper>,
    ) -> Result<Self, Box<dyn std::error::Error + Send + Sync>> {
        Self::build_at_backend(root, HarnessBackend::Sqlite, projector_wrapper).await
    }

    /// Backend-parameterized build used by the PostgreSQL #1035 regressions and
    /// delegated to by [`Self::build_at`], which means SQLite.
    async fn build_at_backend(
        root: std::path::PathBuf,
        backend: HarnessBackend,
        projector_wrapper: Option<ProjectorWrapper>,
    ) -> Result<Self, Box<dyn std::error::Error + Send + Sync>> {
        std::fs::create_dir_all(&root)?;
        let store: Arc<O3kStore> = match backend {
            HarnessBackend::Sqlite => {
                let sqlite_path = root.join("cloud.sqlite");
                Arc::new(O3kStore::connect_sqlite_file(&sqlite_path).await?)
            }
            HarnessBackend::Postgres { url } => Arc::new(O3kStore::connect_postgres(&url).await?),
        };
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
        let projector: Arc<dyn o3k_compute::PortBindingProjector> = match projector_wrapper.as_ref()
        {
            Some(wrapper) => wrapper(&network, projector),
            None => projector,
        };
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
        // Fixture names are unique per build so a runtime can be rebuilt over
        // an existing durable root (the #1035 restart regression) without the
        // canonical network service rejecting a duplicate name.
        let fixture = Uuid::new_v4().simple().to_string();
        let network_row = network
            .create_network_for_project(PROJECT_A, format!("pp4-endpoint-network-{fixture}"))
            .await?;
        let subnet = network
            .create_subnet_for_project(
                PROJECT_A,
                network_row.id,
                format!("pp4-endpoint-subnet-{fixture}"),
                "192.0.2.0/24".to_owned(),
                None,
                None,
                None,
            )
            .await?;
        let foreign = network
            .create_network_for_project(PROJECT_B, format!("pp4-endpoint-foreign-{fixture}"))
            .await?;
        network
            .create_subnet_for_project(
                PROJECT_B,
                foreign.id,
                format!("pp4-endpoint-foreign-subnet-{fixture}"),
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
            compute,
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

    /// The canonical lifetime compute its delete-operation id from the
    /// idempotency key, so a genuinely different key yields a brand-new delete
    /// operation even for a server that is already durably `DELETED` — which is
    /// what routes the replayed delete through the `observed == Deleted` retry
    /// seat (a same-key replay would just return the stored, already-terminale
    /// operation without re-running).
    async fn native_delete_with_key(&self, id: &str, idempotency_key: &str) -> (StatusCode, Value) {
        let request = Request::builder()
            .method(Method::DELETE)
            .uri(format!("/o3k/v1/compute/servers/{id}"))
            .header("authorization", format!("Bearer {}", self.token_a))
            .header("idempotency-key", idempotency_key)
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

/// Fails the next endpoint release for one chosen endpoint, and delegates
/// everything else to the production projector underneath.
///
/// Only the collaborator boundary is doubled: the ownership decision and the
/// deletion itself still run against the real `NetworkService`, so the test
/// proves the retry contract rather than a scripted expectation.
#[derive(Clone)]
struct FaultInjectingProjector {
    inner: Arc<dyn o3k_compute::PortBindingProjector>,
    fail_next: Arc<std::sync::Mutex<Option<Uuid>>>,
}

impl FaultInjectingProjector {
    fn wrap(
        inner: Arc<dyn o3k_compute::PortBindingProjector>,
        fail_next: Arc<std::sync::Mutex<Option<Uuid>>>,
    ) -> Self {
        Self { inner, fail_next }
    }
}

#[async_trait::async_trait]
impl o3k_compute::PortBindingProjector for FaultInjectingProjector {
    async fn project_create_outcome(
        &self,
        project_id: &str,
        port_id: &str,
        succeeded: bool,
    ) -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
        self.inner
            .project_create_outcome(project_id, port_id, succeeded)
            .await
    }

    async fn unbind_port(
        &self,
        project_id: &str,
        port_id: &str,
        operation_id: Uuid,
    ) -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
        self.inner
            .unbind_port(project_id, port_id, operation_id)
            .await
    }

    async fn release_server_owned_endpoint(
        &self,
        project_id: &str,
        port_id: &str,
    ) -> Result<o3k_compute::ServerEndpointRelease, Box<dyn std::error::Error + Send + Sync>> {
        let armed = self
            .fail_next
            .lock()
            .map_err(|_| "fault slot poisoned".to_owned())?
            .take();
        if armed.is_some_and(|endpoint| endpoint.to_string() == port_id) {
            return Err("injected transient endpoint release failure".into());
        }
        self.inner
            .release_server_owned_endpoint(project_id, port_id)
            .await
    }

    async fn port_binding(
        &self,
        project_id: &str,
        port_id: &str,
    ) -> Result<Option<o3k_compute::PortBindingInfo>, Box<dyn std::error::Error + Send + Sync>>
    {
        self.inner.port_binding(project_id, port_id).await
    }
}

/// A transient endpoint-release failure must fail the delete mutation and be
/// recoverable by replaying the same delete — never leave the endpoint behind
/// silently.
#[tokio::test]
async fn transient_release_failure_is_reported_and_repaired_by_replay()
-> Result<(), Box<dyn std::error::Error + Send + Sync>> {
    let fail_next: Arc<std::sync::Mutex<Option<Uuid>>> = Arc::new(std::sync::Mutex::new(None));
    let wrapper: ProjectorWrapper = {
        let fail_next = fail_next.clone();
        Arc::new(move |_network, inner| {
            Arc::new(FaultInjectingProjector::wrap(inner, fail_next.clone()))
        })
    };
    let harness = Harness::build_with(Some(wrapper)).await?;
    let network_id = harness.network_id;
    let (status, body) = harness
        .compat_create("pp4-transient", json!([{"uuid": network_id.to_string()}]))
        .await?;
    assert_eq!(status, StatusCode::ACCEPTED, "{body}");
    let id = body["server"]["id"].as_str().expect("server id").to_owned();
    let ports = harness.intent_ports(&id).await?;
    assert_eq!(ports.len(), 1);

    *fail_next.lock().expect("fault slot") = Some(ports[0]);
    let (status, body) = harness.native_delete(&id).await;
    assert!(
        status.is_server_error(),
        "a failed endpoint release must fail the delete mutation: {status} {body}"
    );
    assert!(
        harness.port_present(ports[0]).await,
        "the injected failure must actually have blocked the release"
    );

    // The replay resolves the same canonical delete and retries the release.
    let (status, body) = harness.native_delete(&id).await;
    assert!(status.is_success(), "replay: {status} {body}");
    assert!(
        !harness.port_present(ports[0]).await,
        "the replay did not finish the release a transient failure left behind"
    );

    harness.cleanup();
    Ok(())
}

// ─── PP.5 #1035 — orphaned server-owned endpoint repair ───────────────────

/// Simulates a control plane that died between the durable terminal delete and
/// the request-path endpoint release.
///
/// While armed, the release never succeeds. Because the delete operation is
/// already durably terminal when the release runs, the durable state this
/// leaves behind is exactly the #1035 interruption window: the server is
/// `DELETED`, the delete is terminal, and the `o3k-server:` endpoint is still
/// present. Everything else is delegated to the production projector, so the
/// ownership rule under test is never doubled.
#[derive(Clone)]
struct CrashBeforeReleaseProjector {
    inner: Arc<dyn o3k_compute::PortBindingProjector>,
    armed: Arc<std::sync::atomic::AtomicBool>,
}

#[async_trait::async_trait]
impl o3k_compute::PortBindingProjector for CrashBeforeReleaseProjector {
    async fn project_create_outcome(
        &self,
        project_id: &str,
        port_id: &str,
        succeeded: bool,
    ) -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
        self.inner
            .project_create_outcome(project_id, port_id, succeeded)
            .await
    }

    async fn unbind_port(
        &self,
        project_id: &str,
        port_id: &str,
        operation_id: Uuid,
    ) -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
        self.inner
            .unbind_port(project_id, port_id, operation_id)
            .await
    }

    async fn release_server_owned_endpoint(
        &self,
        project_id: &str,
        port_id: &str,
    ) -> Result<o3k_compute::ServerEndpointRelease, Box<dyn std::error::Error + Send + Sync>> {
        if self.armed.load(std::sync::atomic::Ordering::SeqCst) {
            return Err("simulated crash before the request-path endpoint release".into());
        }
        self.inner
            .release_server_owned_endpoint(project_id, port_id)
            .await
    }

    async fn port_binding(
        &self,
        project_id: &str,
        port_id: &str,
    ) -> Result<Option<o3k_compute::PortBindingInfo>, Box<dyn std::error::Error + Send + Sync>>
    {
        self.inner.port_binding(project_id, port_id).await
    }
}

/// Models the PRE-UNBIND #1035 crash window: the process dies after the delete
/// terminalized but before either the fabric unbind OR the endpoint release,
/// leaving the orphan port still durably `bound`.
///
/// While an armed flag is set, `unbind_port` and `release_server_owned_endpoint`
/// both fail; everything else delegates to the production projector. Fail the
/// unbind (not the release) is what keeps the port `bound`, which is the window
/// the shipped sweep must repair by unbinding first and only then releasing.
#[derive(Clone)]
struct CrashBeforeUnbindProjector {
    inner: Arc<dyn o3k_compute::PortBindingProjector>,
    fail_unbind: Arc<std::sync::atomic::AtomicBool>,
    fail_release: Arc<std::sync::atomic::AtomicBool>,
}

#[async_trait::async_trait]
impl o3k_compute::PortBindingProjector for CrashBeforeUnbindProjector {
    async fn project_create_outcome(
        &self,
        project_id: &str,
        port_id: &str,
        succeeded: bool,
    ) -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
        self.inner
            .project_create_outcome(project_id, port_id, succeeded)
            .await
    }

    async fn unbind_port(
        &self,
        project_id: &str,
        port_id: &str,
        operation_id: Uuid,
    ) -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
        if self.fail_unbind.load(std::sync::atomic::Ordering::SeqCst) {
            return Err("simulated crash before the fabric unbind".into());
        }
        self.inner
            .unbind_port(project_id, port_id, operation_id)
            .await
    }

    async fn release_server_owned_endpoint(
        &self,
        project_id: &str,
        port_id: &str,
    ) -> Result<o3k_compute::ServerEndpointRelease, Box<dyn std::error::Error + Send + Sync>> {
        if self.fail_release.load(std::sync::atomic::Ordering::SeqCst) {
            return Err("simulated crash before the request-path endpoint release".into());
        }
        self.inner
            .release_server_owned_endpoint(project_id, port_id)
            .await
    }

    async fn port_binding(
        &self,
        project_id: &str,
        port_id: &str,
    ) -> Result<Option<o3k_compute::PortBindingInfo>, Box<dyn std::error::Error + Send + Sync>>
    {
        self.inner.port_binding(project_id, port_id).await
    }
}

/// Spawns the shipped periodic lifecycle convergence reconciler.
///
/// The PP.5 tests deliberately use the production driver
/// (`spawn_lifecycle_convergence_reconciler`) rather than a test-only
/// convergence call, so what repairs an orphan here is the sweep that ships.
fn spawn_shipped_sweeps(compute: &ComputeService) -> tokio::task::JoinHandle<()> {
    compute.spawn_lifecycle_convergence_reconciler(1)
}

/// Waits for `settled`, then aborts `reconciler` and asserts it did not panic.
async fn wait_for_settled<F, Fut>(reconciler: tokio::task::JoinHandle<()>, settled: F)
where
    F: Fn() -> Fut,
    Fut: std::future::Future<Output = bool>,
{
    let outcome = tokio::time::timeout(Duration::from_secs(60), async {
        loop {
            if settled().await {
                break;
            }
            tokio::time::sleep(Duration::from_millis(100)).await;
        }
    })
    .await;
    reconciler.abort();
    let stopped = reconciler.await;
    assert!(
        stopped.is_err_and(|error| error.is_cancelled()),
        "the shipped convergence sweep ended abnormally"
    );
    assert!(
        outcome.is_ok(),
        "the shipped convergence sweep did not settle in time"
    );
}

/// Runs the shipped reconciler long enough to complete at least two full
/// passes, then stops it. Used by the no-op cases, which have nothing to wait
/// for: the assertion is that a settled system is left alone.
async fn run_shipped_sweeps_for(compute: &ComputeService, duration: Duration) {
    let reconciler = spawn_shipped_sweeps(compute);
    tokio::time::sleep(duration).await;
    reconciler.abort();
    let stopped = reconciler.await;
    assert!(
        stopped.is_err_and(|error| error.is_cancelled()),
        "the shipped convergence sweep ended abnormally"
    );
}

/// Creates a server and deletes it while the release is armed to fail, leaving
/// exactly the #1035 interruption window behind. Returns the server id and the
/// orphaned endpoint id.
async fn create_orphaned_endpoint(
    harness: &Harness,
    name: &str,
) -> Result<(String, Uuid), Box<dyn std::error::Error + Send + Sync>> {
    let (status, body) = harness
        .compat_create(name, json!([{"uuid": harness.network_id.to_string()}]))
        .await?;
    assert_eq!(status, StatusCode::ACCEPTED, "{body}");
    let id = body["server"]["id"].as_str().expect("server id").to_owned();
    let ports = harness.intent_ports(&id).await?;
    assert_eq!(ports.len(), 1, "auto-created endpoint for {name}");
    assert!(harness.port_present(ports[0]).await);

    // The delete terminalizes the canonical operation durably, then fails the
    // mutation when the release cannot run. That is the crash window: durable
    // terminal success, endpoint still present.
    let (status, body) = harness.native_delete(&id).await;
    assert!(
        status.is_server_error(),
        "an unreleasable endpoint must fail the delete mutation: {status} {body}"
    );
    assert!(
        harness.port_present(ports[0]).await,
        "the injected interruption must actually have left the endpoint behind"
    );
    Ok((id, ports[0]))
}

/// Creates a server and deletes it while BOTH the fabric unbind and the release
/// are armed to fail, leaving the PRE-UNBIND #1035 window behind: the delete is
/// durably terminal but the `o3k-server:` endpoint is still `bound` (the request
/// path could neither unbind nor release it). Returns the server id and the
/// still-present, still-bound endpoint id.
///
/// Fail the unbind is what keeps the port `bound`; because the unbind failed,
/// the release is never attempted, so the delete mutation itself converges
/// terminal (the failed unbind is a best-effort projection, not a mutation
/// failure).
async fn create_bound_orphan(
    harness: &Harness,
    name: &str,
) -> Result<(String, Uuid), Box<dyn std::error::Error + Send + Sync>> {
    let (status, body) = harness
        .compat_create(name, json!([{"uuid": harness.network_id.to_string()}]))
        .await?;
    assert_eq!(status, StatusCode::ACCEPTED, "{body}");
    let id = body["server"]["id"].as_str().expect("server id").to_owned();
    let ports = harness.intent_ports(&id).await?;
    assert_eq!(ports.len(), 1, "auto-created endpoint for {name}");
    assert!(harness.port_present(ports[0]).await);

    // The production create's binding is written when an agent observes the
    // realization; this TestLab harness has no agent dispatcher, so the bind is
    // recorded explicitly through the same network service calls the agent's
    // observation would project: intent (host selected + `binding`) then the
    // `bound` observation. That is the durable bound state a pre-unbind crash
    // leaves behind.
    harness
        .network
        .record_binding_intent(PROJECT_A, ports[0], "compute-1")
        .await?;
    harness
        .network
        .project_binding_observation(PROJECT_A, ports[0], "compute-1", "bound")
        .await?;

    let (status, body) = harness.native_delete(&id).await;
    assert!(
        status.is_success(),
        "a failed unbind must not fail the delete mutation: {status} {body}"
    );
    let bound = harness
        .network
        .get_port_for_project(PROJECT_A, ports[0])
        .await?;
    assert_eq!(
        bound.binding_state.as_deref(),
        Some("bound"),
        "the pre-unbind window must leave the orphaned endpoint durably bound"
    );
    Ok((id, ports[0]))
}

/// repairs, and would make the orphan invisible to the repair below.
async fn assert_durable_terminal_delete_with_orphan(
    harness: &Harness,
    id: &str,
    port: Uuid,
) -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
    let resource = harness.store.get_resource(Uuid::parse_str(id)?).await?;
    assert_eq!(
        resource.observed_state, "DELETED",
        "the canonical delete must be durably terminal for this to be the #1035 window"
    );
    let non_terminal = harness
        .store
        .list_non_terminal_lifecycle_operations()
        .await?
        .into_iter()
        .filter(|operation| operation.resource_id == resource.id)
        .collect::<Vec<_>>();
    assert!(
        non_terminal.is_empty(),
        "issue #1041: a terminalized delete must leave no non-terminal lifecycle \
         operation behind (half-committed split): {non_terminal:?}"
    );
    assert!(
        harness.port_present(port).await,
        "the orphaned endpoint must still be present"
    );
    Ok(())
}

/// The orphan left by an interrupted terminal delete is repaired by the shipped
/// periodic sweep, and the sweep is idempotent afterwards.
#[tokio::test]
async fn interrupted_terminal_delete_orphan_is_repaired_by_the_shipped_sweep()
-> Result<(), Box<dyn std::error::Error + Send + Sync>> {
    let armed = Arc::new(std::sync::atomic::AtomicBool::new(true));
    let wrapper: ProjectorWrapper = {
        let armed = armed.clone();
        Arc::new(move |_network, inner| {
            Arc::new(CrashBeforeReleaseProjector {
                inner,
                armed: armed.clone(),
            })
        })
    };
    let harness = Harness::build_with(Some(wrapper)).await?;
    let (id, port) = create_orphaned_endpoint(&harness, "pp5-orphan").await?;
    assert_durable_terminal_delete_with_orphan(&harness, &id, port).await?;

    // The control plane comes back with a working release path.
    armed.store(false, std::sync::atomic::Ordering::SeqCst);
    // Serialize all sweep emissions process-wide: the report buffer is global,
    // so a concurrent sweep from another harness would interleave its reports
    // into this test's capture window (see REPORT_CAPTURE_LOCK).
    let _report_guard = REPORT_CAPTURE_LOCK.lock().await;
    let reconciler = spawn_shipped_sweeps(&harness.compute);
    let network = harness.network.clone();
    wait_for_settled(reconciler, || {
        let network = network.clone();
        async move { network.get_port_for_project(PROJECT_A, port).await.is_err() }
    })
    .await;
    assert!(
        !harness.port_present(port).await,
        "the shipped sweep did not repair the orphaned server-owned endpoint"
    );

    // Idempotent: a further pass over the repaired state changes nothing and
    // does not fail.
    run_shipped_sweeps_for(&harness.compute, Duration::from_millis(2500)).await;
    assert!(!harness.port_present(port).await);

    // The address and the network-port quota are reusable afterwards.
    let (status, body) = harness
        .compat_create(
            "pp5-orphan-after",
            json!([{"uuid": harness.network_id.to_string()}]),
        )
        .await?;
    assert_eq!(status, StatusCode::ACCEPTED, "{body}");

    harness.cleanup();
    Ok(())
}

/// The #1035 PRE-UNBIND crash window: the delete terminalized but the process
/// died before the fabric unbind, so the orphaned server-owned endpoint is
/// still durably `bound`. The shipped sweep must restore the request-path
/// invariant — unbind first (dispatch the agent-side Remove / record the `down`
/// tombstone), then release. Fail-before/fix-after centerpiece for the BLOCKER:
/// before this fix the network binding fence preserved a `bound` orphan forever.
#[tokio::test]
async fn orphaned_bound_endpoint_is_unbound_then_released_by_the_shipped_sweep()
-> Result<(), Box<dyn std::error::Error + Send + Sync>> {
    let fail_unbind = Arc::new(std::sync::atomic::AtomicBool::new(true));
    let fail_release = Arc::new(std::sync::atomic::AtomicBool::new(true));
    let wrapper: ProjectorWrapper = {
        let fail_unbind = fail_unbind.clone();
        let fail_release = fail_release.clone();
        Arc::new(move |_network, inner| {
            Arc::new(CrashBeforeUnbindProjector {
                inner,
                fail_unbind: fail_unbind.clone(),
                fail_release: fail_release.clone(),
            })
        })
    };
    let harness = Harness::build_with(Some(wrapper)).await?;
    let (a_id, port) = create_bound_orphan(&harness, "pp5-bound-orphan").await?;
    assert_durable_terminal_delete_with_orphan(&harness, &a_id, port).await?;
    // Prove the bound state explicitly: this is the fail-before proof — a sweep
    // that cannot unbind a `bound` orphan cannot repair it.
    assert_eq!(
        harness
            .network
            .get_port_for_project(PROJECT_A, port)
            .await?
            .binding_state
            .as_deref(),
        Some("bound"),
        "the orphan must still be durably bound before the sweep"
    );

    // The control plane comes back. First unbind only: the sweep's first pass
    // must dispatch the unbind (binding converges `down`) even though the
    // release is still failing.
    fail_unbind.store(false, std::sync::atomic::Ordering::SeqCst);
    let _report_guard = REPORT_CAPTURE_LOCK.lock().await;
    install_global_report_collector();
    reset_report_collector();
    run_shipped_sweeps_for(&harness.compute, Duration::from_millis(2500)).await;
    assert!(
        harness.port_present(port).await,
        "a still-failing release must keep the endpoint present after the unbind"
    );
    assert_eq!(
        harness
            .network
            .get_port_for_project(PROJECT_A, port)
            .await?
            .binding_state
            .as_deref(),
        Some("down"),
        "the sweep must have dispatched the unbind even though the release failed"
    );

    // Now the release can run: the next sweep pass releases and deletes the
    // (now unbound) endpoint, frees its address, and leaves no quota residue.
    fail_release.store(false, std::sync::atomic::Ordering::SeqCst);
    reset_report_collector();
    let reconciler = spawn_shipped_sweeps(&harness.compute);
    let network = harness.network.clone();
    wait_for_settled(reconciler, || {
        let network = network.clone();
        async move { network.get_port_for_project(PROJECT_A, port).await.is_err() }
    })
    .await;
    assert!(
        !harness.port_present(port).await,
        "the shipped sweep did not delete the unbound orphan"
    );
    let report = sweep_reports().last().cloned().unwrap_or_default();
    assert!(
        report_field(&report, "released") >= 1,
        "the sweep must have released the bound orphan: {report}"
    );

    // Idempotent: a further pass over the repaired state changes nothing.
    run_shipped_sweeps_for(&harness.compute, Duration::from_millis(2500)).await;
    assert!(!harness.port_present(port).await);

    // The released address allocation is reusable and the project's endpoint
    // count is exactly expected (the orphan left no leaked allocation).
    let (status, body) = harness
        .compat_create(
            "pp5-bound-orphan-after",
            json!([{"uuid": harness.network_id.to_string()}]),
        )
        .await?;
    assert_eq!(status, StatusCode::ACCEPTED, "{body}");
    let project_ports = harness.project_ports().await?;
    assert_eq!(
        project_ports.len(),
        1,
        "no leaked allocation after repairing a bound orphan: {project_ports:?}"
    );

    harness.cleanup();
    Ok(())
}

/// The repair must be derivable from durable state alone: a control plane that
/// restarts over the orphaned database repairs it with no request and no
/// in-memory residue from the process that died.
#[tokio::test]
async fn orphan_repair_survives_a_control_plane_restart()
-> Result<(), Box<dyn std::error::Error + Send + Sync>> {
    let armed = Arc::new(std::sync::atomic::AtomicBool::new(true));
    let wrapper: ProjectorWrapper = {
        let armed = armed.clone();
        Arc::new(move |_network, inner| {
            Arc::new(CrashBeforeReleaseProjector {
                inner,
                armed: armed.clone(),
            })
        })
    };
    let harness = Harness::build_with(Some(wrapper)).await?;
    let root = harness.root.clone();
    let (id, port) = create_orphaned_endpoint(&harness, "pp5-orphan-restart").await?;
    assert_durable_terminal_delete_with_orphan(&harness, &id, port).await?;

    // The process dies. Nothing in memory survives; only the SQLite file and
    // the network state root do.
    drop(harness);
    let restarted = Harness::build_at(root, None).await?;
    assert!(
        restarted.port_present(port).await,
        "the orphan must still be present before the restarted sweep runs"
    );

    {
        // Serialize all sweep emissions process-wide (see REPORT_CAPTURE_LOCK).
        let _report_guard = REPORT_CAPTURE_LOCK.lock().await;
        let reconciler = spawn_shipped_sweeps(&restarted.compute);
        let network = restarted.network.clone();
        wait_for_settled(reconciler, || {
            let network = network.clone();
            async move { network.get_port_for_project(PROJECT_A, port).await.is_err() }
        })
        .await;
    }
    assert!(
        !restarted.port_present(port).await,
        "a restarted control plane did not repair the durable orphan"
    );

    restarted.cleanup();
    Ok(())
}

/// The sweep is a no-op for every state that must never be repaired: a live
/// server, a create still in flight, an endpoint the caller supplied itself,
/// and a foreign project's server-owned endpoint.
#[tokio::test]
async fn orphan_repair_is_a_no_op_for_live_in_flight_caller_supplied_and_foreign_state()
-> Result<(), Box<dyn std::error::Error + Send + Sync>> {
    let harness = Harness::build().await?;
    let network_id = harness.network_id;

    // A live server keeps the endpoint its network attachment needs.
    let (status, body) = harness
        .compat_create("pp5-live", json!([{"uuid": network_id.to_string()}]))
        .await?;
    assert_eq!(status, StatusCode::ACCEPTED, "{body}");
    let live_id = body["server"]["id"].as_str().expect("server id").to_owned();
    let live_ports = harness.intent_ports(&live_id).await?;
    assert_eq!(live_ports.len(), 1);

    // A create whose outcome is still in flight must keep its endpoint too.
    harness
        .provider
        .set_failure(FailureInjection::PartialCompletion)?;
    let (in_flight_status, body) = harness
        .compat_create("pp5-in-flight", json!([{"uuid": network_id.to_string()}]))
        .await?;
    let in_flight_id = body["server"]["id"]
        .as_str()
        .unwrap_or_else(|| panic!("create: {in_flight_status} {body}"))
        .to_owned();
    harness.provider.set_failure(FailureInjection::None)?;
    let in_flight_ports = harness.intent_ports(&in_flight_id).await?;
    assert_eq!(in_flight_ports.len(), 1);

    // A caller-supplied endpoint is attached, not owned: the delete preserves
    // it, and so must the sweep.
    let supplied = harness
        .network
        .create_port_for_project(PROJECT_A, network_id, "tenant-port".to_owned())
        .await?;
    let (status, body) = harness
        .compat_create("pp5-supplied", json!([{"port": supplied.id.to_string()}]))
        .await?;
    assert_eq!(status, StatusCode::ACCEPTED, "{body}");
    let supplied_server = body["server"]["id"].as_str().expect("server id").to_owned();
    let (status, body) = harness.native_delete(&supplied_server).await;
    assert!(status.is_success(), "delete: {status} {body}");
    assert!(harness.port_present(supplied.id).await);

    // A foreign project's server-owned endpoint. It carries the reserved name
    // shape for its own project, so it is a valid server-owned identity — just
    // not this project's, and never this sweep's business.
    let foreign_owned = harness
        .network
        .create_port_for_project(
            PROJECT_B,
            harness.foreign_network_id,
            "o3k-server:project-b:elsewhere".to_owned(),
        )
        .await?;

    // Serialize all sweep emissions process-wide (see REPORT_CAPTURE_LOCK).
    let _report_guard = REPORT_CAPTURE_LOCK.lock().await;
    run_shipped_sweeps_for(&harness.compute, Duration::from_millis(2500)).await;

    assert!(
        harness.port_present(live_ports[0]).await,
        "the sweep stripped a live server's network dependency"
    );
    assert!(
        harness.port_present(in_flight_ports[0]).await,
        "the sweep stripped an in-flight create's network dependency"
    );
    assert!(
        harness.port_present(supplied.id).await,
        "the sweep removed a caller-supplied endpoint"
    );
    assert!(
        harness
            .network
            .get_port_for_project(PROJECT_B, foreign_owned.id)
            .await
            .is_ok(),
        "the sweep touched another project's endpoint"
    );

    // The ownership boundary itself, asserted at the exact call the sweep
    // makes: a foreign identifier addressed from the wrong project is never
    // released, and is reported as nothing to repair.
    let report = harness
        .network
        .cleanup_server_owned_ports_for_project(PROJECT_A, &[foreign_owned.id])
        .await?;
    assert_eq!(
        report,
        o3k_network::ServerOwnedEndpointRelease {
            discovered: 0,
            released: 0,
            preserved: 0,
            absent: 1,
        },
        "a foreign endpoint must not be discoverable, let alone releasable"
    );
    assert!(
        harness
            .network
            .get_port_for_project(PROJECT_B, foreign_owned.id)
            .await
            .is_ok()
    );

    harness.cleanup();
    Ok(())
}

/// Concurrent reconcilers must converge on one repair: no error, no double
/// release, and the address reusable afterwards.
#[tokio::test]
async fn concurrent_orphan_repairs_converge_once()
-> Result<(), Box<dyn std::error::Error + Send + Sync>> {
    let armed = Arc::new(std::sync::atomic::AtomicBool::new(true));
    let wrapper: ProjectorWrapper = {
        let armed = armed.clone();
        Arc::new(move |_network, inner| {
            Arc::new(CrashBeforeReleaseProjector {
                inner,
                armed: armed.clone(),
            })
        })
    };
    let harness = Harness::build_with(Some(wrapper)).await?;
    let (id, port) = create_orphaned_endpoint(&harness, "pp5-concurrent-orphan").await?;
    assert_durable_terminal_delete_with_orphan(&harness, &id, port).await?;
    armed.store(false, std::sync::atomic::Ordering::SeqCst);

    // Serialize all sweep emissions process-wide (see REPORT_CAPTURE_LOCK).
    let _report_guard = REPORT_CAPTURE_LOCK.lock().await;
    let first = spawn_shipped_sweeps(&harness.compute);
    let second = spawn_shipped_sweeps(&harness.compute);
    let network = harness.network.clone();
    let gone = tokio::time::timeout(Duration::from_secs(60), async {
        loop {
            if network.get_port_for_project(PROJECT_A, port).await.is_err() {
                break;
            }
            tokio::time::sleep(Duration::from_millis(100)).await;
        }
    })
    .await;
    for reconciler in [first, second] {
        reconciler.abort();
        let stopped = reconciler.await;
        assert!(
            stopped.is_err_and(|error| error.is_cancelled()),
            "a concurrent convergence sweep ended abnormally"
        );
    }
    assert!(
        gone.is_ok(),
        "concurrent sweeps did not converge on the repair"
    );
    assert!(!harness.port_present(port).await);

    // The address is reusable: the repair released the reservation rather than
    // leaking it.
    let (status, body) = harness
        .compat_create(
            "pp5-concurrent-after",
            json!([{"uuid": harness.network_id.to_string()}]),
        )
        .await?;
    assert_eq!(status, StatusCode::ACCEPTED, "{body}");

    harness.cleanup();
    Ok(())
}

/// The #1035 safety-gap scenario: after server A's delete is durably terminal
/// but its endpoint release was interrupted (P orphaned), a NEW live server B
/// explicitly attaches P. The shipped sweep must skip P (counted
/// `skipped_attached`) rather than strip live B's NIC, and deleting B must then
/// release P normally. Returns `(b_id, port)` so the caller can finish the
/// release step.
async fn assert_attached_orphan_skipped_by_sweep_then_released_on_delete(
    harness: &Harness,
    disarm: &std::sync::atomic::AtomicBool,
) -> Result<(String, Uuid), Box<dyn std::error::Error + Send + Sync>> {
    // Serialized with every other sweep-emitting test (REPORT_CAPTURE_LOCK):
    // the report buffer is process-global, so a concurrent sweep from any
    // other harness would corrupt the assertions below.
    let _report_guard = REPORT_CAPTURE_LOCK.lock().await;
    let (a_id, port) = create_orphaned_endpoint(harness, "pp5-attached-orphan-a").await?;
    assert_durable_terminal_delete_with_orphan(harness, &a_id, port).await?;

    // Disarm so a genuine release is possible once B is gone; the crash window
    // is already durably recorded.
    disarm.store(false, std::sync::atomic::Ordering::SeqCst);

    // A new live server B explicitly attaches the orphaned, still-present P.
    let (status, body) = harness
        .compat_create("pp5-attached-orphan-b", json!([{"port": port.to_string()}]))
        .await?;
    assert!(
        status == StatusCode::ACCEPTED || status == StatusCode::CREATED,
        "live server attaching the orphan: {status} {body}"
    );
    let b_id = body["server"]["id"]
        .as_str()
        .expect("server b id")
        .to_owned();
    assert!(
        harness.port_present(port).await,
        "live server B must have the orphaned endpoint as its NIC"
    );

    // Run the shipped sweep long enough for at least one pass, capturing its
    // report so the assertion is on what the sweep actually did.
    install_global_report_collector();
    reset_report_collector();
    run_shipped_sweeps_for(&harness.compute, Duration::from_millis(2500)).await;

    let reports = sweep_reports();
    let report = reports.first().ok_or_else(|| {
        std::io::Error::other("the sweep must report during the attached-orphan run")
    })?;
    assert_eq!(
        report_field(report, "released"),
        0,
        "the sweep must not release an endpoint a live server still depends on: {report}"
    );
    assert!(
        report_field(report, "skipped_attached") >= 1,
        "the sweep must have skipped the still-attached orphaned endpoint: {report}"
    );
    assert!(
        harness.port_present(port).await,
        "the sweep stripped live server B's NIC"
    );

    // Deleting B releases P: B explicitly attached it, but P is server-owned by
    // name in this project, so the request-path release resolves it.
    let (status, body) = harness.native_delete(&b_id).await;
    assert!(status.is_success(), "delete live server B: {status} {body}");
    assert!(
        !harness.port_present(port).await,
        "deleting live server B must release the server-owned endpoint P it attached"
    );
    Ok((b_id, port))
}

/// The sweep must never strip an endpoint a live server depends on, even when a
/// deleted server's stale create intent names it and the reserved identity makes
/// it releasable. Regression for the adjudicated #1035 safety gap (SQLite).
#[tokio::test]
async fn orphan_endpoint_re_attached_by_live_server_is_skipped_and_released_on_delete()
-> Result<(), Box<dyn std::error::Error + Send + Sync>> {
    let armed = Arc::new(std::sync::atomic::AtomicBool::new(true));
    let wrapper: ProjectorWrapper = {
        let armed = armed.clone();
        Arc::new(move |_network, inner| {
            Arc::new(CrashBeforeReleaseProjector {
                inner,
                armed: armed.clone(),
            })
        })
    };
    let harness = Harness::build_with(Some(wrapper)).await?;
    assert_attached_orphan_skipped_by_sweep_then_released_on_delete(&harness, &armed).await?;
    harness.cleanup();
    Ok(())
}

/// #1035 F2: the delete-replay seat (`observed == Deleted` +
/// `release_server_endpoints_from_intent`) release every port a terminally
/// deleted server's intent names with no still-attached/binding check. A
/// replayed delete — reached with a genuinely new idempotency key, so a fresh
/// delete operation is created for the already-`DELETED` owner — must preserve
/// the endpoint a NEW live server has explicitly attached. The durable-binding
/// fence at the port-deletion layer is the backstop here, because this seat
/// releases directly and never consults a still-attached scan (SQLite).
#[tokio::test]
async fn replayed_delete_of_terminally_deleted_owner_preserves_live_servers_attached_endpoint()
-> Result<(), Box<dyn std::error::Error + Send + Sync>> {
    let armed = Arc::new(std::sync::atomic::AtomicBool::new(true));
    let wrapper: ProjectorWrapper = {
        let armed = armed.clone();
        Arc::new(move |_network, inner| {
            Arc::new(CrashBeforeReleaseProjector {
                inner,
                armed: armed.clone(),
            })
        })
    };
    let harness = Harness::build_with(Some(wrapper)).await?;
    let (a_id, port) = create_orphaned_endpoint(&harness, "pp5-replay-orphan-a").await?;
    assert_durable_terminal_delete_with_orphan(&harness, &a_id, port).await?;

    // Disarm so a later release genuinely succeeds; the crash window is already
    // durably recorded.
    armed.store(false, std::sync::atomic::Ordering::SeqCst);

    // A new live server B explicitly attaches the orphaned, still-present P.
    let (status, body) = harness
        .compat_create("pp5-replay-orphan-b", json!([{"port": port.to_string()}]))
        .await?;
    assert!(
        status == StatusCode::ACCEPTED || status == StatusCode::CREATED,
        "live server attaching the orphan: {status} {body}"
    );
    let b_id = body["server"]["id"]
        .as_str()
        .expect("server b id")
        .to_owned();
    assert!(
        harness.port_present(port).await,
        "live server B must have the orphaned endpoint as its NIC"
    );

    // A replayed delete of A with a brand-new idempotency key reaches the
    // observed == Deleted retry seat, which releases A's intent ports with no
    // still-attached scan. The binding fence must preserve live B's endpoint.
    let (status, body) = harness
        .native_delete_with_key(&a_id, "pp5-replay-orphan-a-delete-2")
        .await;
    assert!(status.is_success(), "replayed delete of A: {status} {body}");
    assert!(
        harness.port_present(port).await,
        "replaying A's delete stripped live server B's NIC (F2)"
    );

    // Deleting B still releases P through the normal request path.
    let (status, body) = harness.native_delete(&b_id).await;
    assert!(status.is_success(), "delete live server B: {status} {body}");
    assert!(
        !harness.port_present(port).await,
        "deleting live server B must release the server-owned endpoint P it attached"
    );

    harness.cleanup();
    Ok(())
}

// ─── PP.5 #1035 — PostgreSQL regressions ──────────────────────────────────
//
// The SQLite regressions prove the repair semantics; those semantics must also
// hold against real PostgreSQL, because the durable canonical delete, the
// idempotent replay/rollback and the address/quota accounting are all *store*
// decisions. These tests rebuild the same production runtime (the real
// `NetworkService`, the production `NetworkBindingProjector`, the shipped
// reconciler) over `O3K_DATABASE_URL`. They are `#[ignore]`d by default and
// *fail closed*: when requested via `--ignored` with the variable unset or the
// host unreachable they panic rather than silently skip.

static PG_TEST_DATABASE_LOCK: tokio::sync::Mutex<()> = tokio::sync::Mutex::const_new(());

/// Fails closed: a requested PostgreSQL regression with `O3K_DATABASE_URL`
/// unset panics rather than silently skipping.
fn postgres_test_url() -> String {
    std::env::var("O3K_DATABASE_URL").unwrap_or_else(|_| {
        panic!("O3K_DATABASE_URL must be set to run the PostgreSQL endpoint-lifecycle regression")
    })
}

/// Cleans the conformance database at test start. Fails closed (panics) if the
/// configured PostgreSQL host is unreachable.
async fn clean_postgres(url: &str) {
    let store = o3k_store::PostgresStore::connect(url)
        .await
        .expect("connect to the configured PostgreSQL conformance database");
    store
        .clean_tables_for_testing()
        .await
        .expect("clean the PostgreSQL conformance tables at test start");
}

/// Acquires a session-level advisory lock on the shared PostgreSQL test
/// database, held by a dedicated connection for the caller's entire test. The
/// shared `o3k-shared-test-database` key serializes every test group that
/// destructively resets the database — the `postgres_p13_f1` suite and group
/// C's `conformance`/`postgres_ops` helpers in o3k-store — against each other,
/// even across separate `cargo test` processes. Matches
/// `o3k_store::conformance::prepare_shared_postgres_test_database`.
async fn acquire_postgres_database_guard(url: &str) -> PgConnection {
    let mut connection = PgConnection::connect(url)
        .await
        .expect("connect to the configured PostgreSQL conformance database");
    sqlx::query("SELECT pg_advisory_lock(hashtextextended('o3k-shared-test-database', 0))")
        .execute(&mut connection)
        .await
        .expect("acquire the shared PostgreSQL test-database advisory lock");
    connection
}

/// Builds the production harness over PostgreSQL on a fresh temp root.
async fn build_postgres(
    url: String,
    projector_wrapper: Option<ProjectorWrapper>,
) -> Result<Harness, Box<dyn std::error::Error + Send + Sync>> {
    let root = std::env::temp_dir().join(format!("o3k-pp5-pg-{}", Uuid::now_v7()));
    Harness::build_at_backend(root, HarnessBackend::Postgres { url }, projector_wrapper).await
}

// ─── capturing the shipped sweep's own report ─────────────────────────────
//
// The repair pass reports what it did through `tracing::info!` with structured
// fields (`discovered`/`released`/`preserved`/`absent`/`skipped_attached`).
// These helpers collect that output so a regression can assert the sweep ran
// and did real work — rather than passing vacuously because the sweep silently
// did nothing.

/// A `MakeWriter` that appends raw formatted lines into a shared buffer.
#[derive(Clone)]
struct CollectWriter {
    buf: Arc<std::sync::Mutex<Vec<u8>>>,
}

impl std::io::Write for CollectWriter {
    fn write(&mut self, data: &[u8]) -> std::io::Result<usize> {
        self.buf
            .lock()
            .map_err(|_| std::io::Error::other("collect buffer poisoned"))?
            .extend_from_slice(data);
        Ok(data.len())
    }
    fn flush(&mut self) -> std::io::Result<()> {
        Ok(())
    }
}

static GLOBAL_REPORT_BUF: std::sync::OnceLock<Arc<std::sync::Mutex<Vec<u8>>>> =
    std::sync::OnceLock::new();

/// Serializes EVERY test that spawns the shipped sweep, whether or not it
/// asserts on the reports. The report buffer backs a process-global tracing
/// subscriber (the shipped reconciler runs on arbitrary worker threads), so a
/// sweep emitted by any concurrently running test — the SQLite lanes and the
/// PostgreSQL lanes share the process when both run — lands in the same
/// buffer. A capturing test that only locked out other *capturing* tests
/// still saw unrelated emissions between its reset and its read (observed as
/// `released: 1` from another harness's legitimate repair). Contract: hold
/// this lock for the entire window in which this test spawns sweeps, from
/// before the first spawn (or buffer reset) until the last sweep task is
/// aborted.
static REPORT_CAPTURE_LOCK: tokio::sync::Mutex<()> = tokio::sync::Mutex::const_new(());

fn global_report_buf() -> Arc<std::sync::Mutex<Vec<u8>>> {
    GLOBAL_REPORT_BUF
        .get_or_init(|| Arc::new(std::sync::Mutex::new(Vec::new())))
        .clone()
}

/// Installs a process-wide JSON collector. The shipped reconciler is spawned
/// with `tokio::spawn` and may run on any tokio worker thread, so a thread-local
/// default is insufficient: the global default routes every thread's events to
/// the shared buffer. Idempotent; no other o3kd lib test installs a global
/// subscriber.
fn install_global_report_collector() {
    static ONCE: std::sync::Once = std::sync::Once::new();
    ONCE.call_once(|| {
        let writer = CollectWriter {
            buf: global_report_buf(),
        };
        let subscriber = tracing_subscriber::fmt()
            .with_max_level(tracing::Level::INFO)
            .json()
            .with_writer(move || writer.clone())
            .finish();
        tracing::subscriber::set_global_default(subscriber)
            .expect("no other global tracing subscriber may be set for o3kd lib tests");
    });
}

/// Clears the process-wide report buffer at the start of a capturing test.
fn reset_report_collector() {
    global_report_buf()
        .lock()
        .expect("report buffer poisoned")
        .clear();
}

/// Every `server-owned endpoint orphan repair sweep` report captured (parsed
/// from structured JSON, so the counts are exact), newest first.
fn sweep_reports() -> Vec<serde_json::Value> {
    let buf = global_report_buf();
    let bytes = buf.lock().expect("report buffer poisoned");
    String::from_utf8_lossy(&bytes)
        .lines()
        .rev()
        .filter_map(|line| {
            let value: serde_json::Value = serde_json::from_str(line).ok()?;
            (value
                .get("fields")
                .and_then(|fields| fields.get("message"))
                .and_then(serde_json::Value::as_str)
                == Some("server-owned endpoint orphan repair sweep"))
            .then_some(value)
        })
        .collect()
}

fn report_field(report: &serde_json::Value, name: &str) -> u64 {
    report
        .get("fields")
        .and_then(|fields| fields.get(name))
        .and_then(serde_json::Value::as_u64)
        .unwrap_or_else(|| panic!("missing sweep report field {name:?}: {report}"))
}

/// The full #1035 window against real PostgreSQL: an interrupted terminal
/// delete leaves an O3K-owned endpoint orphaned in durable state, a restarted
/// control plane (a *new connection to the same database*, not cleaned)
/// repairs it with the shipped sweep, and every side invariant — idempotent
/// replay, released-address reuse, quota accounting, and caller-supplied and
/// foreign preservation — holds.
#[tokio::test]
#[ignore = "requires O3K_DATABASE_URL (PostgreSQL)"]
async fn postgres_interrupted_delete_orphan_is_repaired_and_reuse_is_restored()
-> Result<(), Box<dyn std::error::Error + Send + Sync>> {
    let _pg_test_lock_guard = PG_TEST_DATABASE_LOCK.lock().await;
    let url = postgres_test_url();
    let _database_guard = acquire_postgres_database_guard(&url).await;
    // Clean once at test start only; never between the crash and the repair.
    clean_postgres(&url).await;

    let armed = Arc::new(std::sync::atomic::AtomicBool::new(true));
    let wrapper: ProjectorWrapper = {
        let armed = armed.clone();
        Arc::new(move |_network, inner| {
            Arc::new(CrashBeforeReleaseProjector {
                inner,
                armed: armed.clone(),
            })
        })
    };
    let harness = build_postgres(url.clone(), Some(wrapper)).await?;
    let network_id = harness.network_id;

    // __11. Caller-supplied endpoint: attached, not owned -> the sweep must
    // preserve it.__
    let supplied = harness
        .network
        .create_port_for_project(PROJECT_A, network_id, "tenant-port".to_owned())
        .await?;
    // __12. Foreign server-owned endpoint: another project's identity -> never
    // this sweep's business.__
    let foreign_owned = harness
        .network
        .create_port_for_project(
            PROJECT_B,
            harness.foreign_network_id,
            "o3k-server:project-b:elsewhere".to_owned(),
        )
        .await?;

    // __1. Create a server with an O3K-owned endpoint.__
    let (id, port) = create_orphaned_endpoint(&harness, "pp5-pg-orphan").await?;
    let orphan_fixed_ip = harness
        .network
        .get_port_for_project(PROJECT_A, port)
        .await?
        .fixed_ip;

    // __2/3. Durable terminal-successful delete, interrupted before the
    // request-path endpoint release.__ __4. Still orphaned pre-reconciliation.__
    assert_durable_terminal_delete_with_orphan(&harness, &id, port).await?;
    assert!(
        harness.port_present(port).await,
        "the orphan must be present before reconciliation"
    );

    // __5. Restart/reconstruct the runtime from durable PostgreSQL state: a new
    // connection to the same database, not cleaned.__
    armed.store(false, std::sync::atomic::Ordering::SeqCst);
    drop(harness);
    let restarted = build_postgres(url.clone(), None).await?;
    assert!(
        restarted.port_present(port).await,
        "the orphan must survive a PostgreSQL control-plane restart"
    );

    // __6. Run the shipped lifecycle reconciler.__ __7. Endpoint removed.__ Collect
    // the sweep's own report so point 11/12 cannot pass because the sweep did
    // nothing. Serialized with the other sweep-report captures: the report
    // buffer is process-global (see REPORT_CAPTURE_LOCK).
    let _report_guard = REPORT_CAPTURE_LOCK.lock().await;
    install_global_report_collector();
    reset_report_collector();
    let reconciler = spawn_shipped_sweeps(&restarted.compute);
    let network = restarted.network.clone();
    wait_for_settled(reconciler, || {
        let network = network.clone();
        async move { network.get_port_for_project(PROJECT_A, port).await.is_err() }
    })
    .await;
    assert!(
        !restarted.port_present(port).await,
        "the shipped sweep did not repair the PostgreSQL orphan"
    );
    // The sweep ran and did real work on the deleted server's orphan: it must
    // have discovered and released the endpoint, and must NOT have skipped it
    // (no live server attached it here) nor preserved anything incorrectly.
    let reports = sweep_reports();
    let orphan_report = reports.first().ok_or_else(|| {
        std::io::Error::other("the shipped sweep never produced an orphan-repair report")
    })?;
    assert!(
        report_field(orphan_report, "discovered") >= 1
            && report_field(orphan_report, "released") >= 1,
        "the sweep must have discovered and released the orphaned endpoint: {orphan_report}"
    );
    assert_eq!(
        report_field(orphan_report, "skipped_attached"),
        0,
        "no live server attached the orphan, so the sweep must not have skipped it"
    );
    assert_eq!(
        report_field(orphan_report, "preserved"),
        0,
        "a server-owned project endpoint must never be counted as preserved by repair"
    );

    // __11/12. Caller-supplied and foreign endpoints survive the sweep, non-
    // vacuously: the sweep above demonstrably repaired the orphan, so seeing
    // these still present is preservation by the running sweep, not a no-op.
    assert!(
        restarted.port_present(supplied.id).await,
        "the sweep removed a caller-supplied endpoint"
    );
    assert!(
        restarted
            .network
            .get_port_for_project(PROJECT_B, foreign_owned.id)
            .await
            .is_ok(),
        "the sweep touched another project's endpoint"
    );

    // __8. Idempotent: replay converges; released/discovered go to zero; nothing
    // double-deleted.__
    run_shipped_sweeps_for(&restarted.compute, Duration::from_millis(2500)).await;
    assert!(!restarted.port_present(port).await);
    let report = restarted
        .network
        .cleanup_server_owned_ports_for_project(PROJECT_A, &[port])
        .await?;
    assert_eq!(
        report,
        o3k_network::ServerOwnedEndpointRelease {
            discovered: 0,
            released: 0,
            preserved: 0,
            absent: 1,
        },
        "the repaired endpoint must be idempotently absent, not double-released"
    );
    assert!(
        restarted.port_present(supplied.id).await,
        "the idempotent pass must not have removed the caller-supplied endpoint"
    );

    // __9/10. The released address allocation is reusable and quota does not
    // leak: a server on the SAME subnet re-allocates the exact freed low address
    // and the project's endpoint count is exactly expected (no residue).__
    let (status, body) = restarted
        .compat_create("pp5-pg-after", json!([{"uuid": network_id.to_string()}]))
        .await?;
    assert_eq!(status, StatusCode::ACCEPTED, "{body}");
    let recreated = body["server"]["id"].as_str().expect("server id").to_owned();
    let recreated_ports = restarted.intent_ports(&recreated).await?;
    assert_eq!(recreated_ports.len(), 1);
    let recreated_fixed_ip = restarted
        .network
        .get_port_for_project(PROJECT_A, recreated_ports[0])
        .await?
        .fixed_ip;
    assert_eq!(
        recreated_fixed_ip, orphan_fixed_ip,
        "the released address must be reusable and re-allocated"
    );
    // Accounting after repair: the caller-supplied endpoint plus the recreated
    // server endpoint is all that remains — the orphan left no leaked allocation.
    let project_ports = restarted.project_ports().await?;
    assert_eq!(
        project_ports.len(),
        2,
        "no leaked allocation after repair: {project_ports:?}"
    );
    assert!(project_ports.contains(&supplied.id));

    restarted.cleanup();
    Ok(())
}

/// PostgreSQL variant of the pre-unbind BLOCKER regression: a delete that
/// terminalized before the fabric unbind leaves the orphan `bound`, and the
/// shipped sweep must unbind it first (binding converges `down`) and then
/// release/delete it, freeing the address with no quota residue. Fails closed
/// when `O3K_DATABASE_URL` is unset or the host is unreachable.
#[tokio::test]
#[ignore = "requires O3K_DATABASE_URL (PostgreSQL)"]
async fn postgres_bound_orphan_is_unbound_and_released_by_the_shipped_sweep()
-> Result<(), Box<dyn std::error::Error + Send + Sync>> {
    let _pg_test_lock_guard = PG_TEST_DATABASE_LOCK.lock().await;
    let url = postgres_test_url();
    let _database_guard = acquire_postgres_database_guard(&url).await;
    clean_postgres(&url).await;

    let fail_unbind = Arc::new(std::sync::atomic::AtomicBool::new(true));
    let fail_release = Arc::new(std::sync::atomic::AtomicBool::new(true));
    let wrapper: ProjectorWrapper = {
        let fail_unbind = fail_unbind.clone();
        let fail_release = fail_release.clone();
        Arc::new(move |_network, inner| {
            Arc::new(CrashBeforeUnbindProjector {
                inner,
                fail_unbind: fail_unbind.clone(),
                fail_release: fail_release.clone(),
            })
        })
    };
    let harness = build_postgres(url.clone(), Some(wrapper.clone())).await?;
    let network_id = harness.network_id;
    let (id, port) = create_bound_orphan(&harness, "pp5-pg-bound-orphan").await?;
    let orphan_fixed_ip = harness
        .network
        .get_port_for_project(PROJECT_A, port)
        .await?
        .fixed_ip;
    assert_durable_terminal_delete_with_orphan(&harness, &id, port).await?;
    assert_eq!(
        harness
            .network
            .get_port_for_project(PROJECT_A, port)
            .await?
            .binding_state
            .as_deref(),
        Some("bound"),
        "the PostgreSQL orphan must be durably bound before the sweep"
    );

    // Restart over the same durable database; the control plane "comes back"
    // with the unbind working but the release still failing (the restart
    // rebuilds the runtime over the PostgreSQL state, while the injector keeps
    // the release failing so the unbind phase is observable).
    fail_unbind.store(false, std::sync::atomic::Ordering::SeqCst);
    drop(harness);
    let restarted = build_postgres(url.clone(), Some(wrapper)).await?;
    assert!(restarted.port_present(port).await);

    let _report_guard = REPORT_CAPTURE_LOCK.lock().await;
    install_global_report_collector();
    reset_report_collector();
    run_shipped_sweeps_for(&restarted.compute, Duration::from_millis(2500)).await;
    assert_eq!(
        restarted
            .network
            .get_port_for_project(PROJECT_A, port)
            .await?
            .binding_state
            .as_deref(),
        Some("down"),
        "the sweep must have dispatched the unbind even while the release failed"
    );

    // Release enabled: the sweep deletes the now-unbound endpoint, frees the
    // address, and leaves no quota residue.
    fail_release.store(false, std::sync::atomic::Ordering::SeqCst);
    reset_report_collector();
    let reconciler = spawn_shipped_sweeps(&restarted.compute);
    let network = restarted.network.clone();
    wait_for_settled(reconciler, || {
        let network = network.clone();
        async move { network.get_port_for_project(PROJECT_A, port).await.is_err() }
    })
    .await;
    assert!(
        !restarted.port_present(port).await,
        "the shipped sweep did not delete the PostgreSQL bound orphan"
    );
    let report = sweep_reports().last().cloned().unwrap_or_default();
    assert!(
        report_field(&report, "released") >= 1,
        "the sweep must have released the bound orphan: {report}"
    );

    // The released address is reusable; the recreated endpoint re-allocates it.
    let (status, body) = restarted
        .compat_create(
            "pp5-pg-bound-orphan-after",
            json!([{"uuid": network_id.to_string()}]),
        )
        .await?;
    assert_eq!(status, StatusCode::ACCEPTED, "{body}");
    let recreated = body["server"]["id"].as_str().expect("server id").to_owned();
    let recreated_ports = restarted.intent_ports(&recreated).await?;
    assert_eq!(recreated_ports.len(), 1);
    let recreated_fixed_ip = restarted
        .network
        .get_port_for_project(PROJECT_A, recreated_ports[0])
        .await?
        .fixed_ip;
    assert_eq!(
        recreated_fixed_ip, orphan_fixed_ip,
        "the released address must be reusable and re-allocated"
    );
    let project_ports = restarted.project_ports().await?;
    assert_eq!(
        project_ports.len(),
        1,
        "no leaked allocation after repairing a bound orphan: {project_ports:?}"
    );

    restarted.cleanup();
    Ok(())
}

/// Concurrent shipped sweep attempts and a concurrent delete replay must
/// converge on exactly one repair against real PostgreSQL: no error, no double
/// release, and the released address reusable afterwards.
#[tokio::test]
#[ignore = "requires O3K_DATABASE_URL (PostgreSQL)"]
async fn postgres_concurrent_sweeps_and_delete_replay_converge_once()
-> Result<(), Box<dyn std::error::Error + Send + Sync>> {
    let _pg_test_lock_guard = PG_TEST_DATABASE_LOCK.lock().await;
    let url = postgres_test_url();
    let _database_guard = acquire_postgres_database_guard(&url).await;
    clean_postgres(&url).await;

    let armed = Arc::new(std::sync::atomic::AtomicBool::new(true));
    let wrapper: ProjectorWrapper = {
        let armed = armed.clone();
        Arc::new(move |_network, inner| {
            Arc::new(CrashBeforeReleaseProjector {
                inner,
                armed: armed.clone(),
            })
        })
    };
    let harness = build_postgres(url.clone(), Some(wrapper)).await?;
    let network_id = harness.network_id;
    let (id, port) = create_orphaned_endpoint(&harness, "pp5-pg-concurrent").await?;
    assert_durable_terminal_delete_with_orphan(&harness, &id, port).await?;
    armed.store(false, std::sync::atomic::Ordering::SeqCst);

    // __13. Two concurrent shipped sweeps race.__
    // Serialize all sweep emissions process-wide (see REPORT_CAPTURE_LOCK).
    let _report_guard = REPORT_CAPTURE_LOCK.lock().await;
    let first = spawn_shipped_sweeps(&harness.compute);
    let second = spawn_shipped_sweeps(&harness.compute);
    // __14. A delete replay races the sweeps: it must converge, not conflict.__
    let (replay_status, replay_body) = harness.native_delete(&id).await;
    assert!(
        replay_status.is_success() && !replay_status.is_server_error(),
        "a delete replay racing the sweep must converge: {replay_status} {replay_body}"
    );

    let network = harness.network.clone();
    let gone = tokio::time::timeout(Duration::from_secs(60), async {
        loop {
            if network.get_port_for_project(PROJECT_A, port).await.is_err() {
                break;
            }
            tokio::time::sleep(Duration::from_millis(100)).await;
        }
    })
    .await;
    for reconciler in [first, second] {
        reconciler.abort();
        let stopped = reconciler.await;
        assert!(
            stopped.is_err_and(|error| error.is_cancelled()),
            "a concurrent PostgreSQL convergence sweep ended abnormally"
        );
    }
    assert!(
        gone.is_ok(),
        "concurrent sweeps and a delete replay did not converge on the repair"
    );
    assert!(!harness.port_present(port).await);

    // Nothing double-deleted: the endpoint is idempotently absent.
    let report = harness
        .network
        .cleanup_server_owned_ports_for_project(PROJECT_A, &[port])
        .await?;
    assert_eq!(
        report,
        o3k_network::ServerOwnedEndpointRelease {
            discovered: 0,
            released: 0,
            preserved: 0,
            absent: 1,
        },
        "concurrent sweeps/replay double-released the endpoint"
    );

    // The released address is reusable afterwards.
    let (status, body) = harness
        .compat_create(
            "pp5-pg-concurrent-after",
            json!([{"uuid": network_id.to_string()}]),
        )
        .await?;
    assert_eq!(status, StatusCode::ACCEPTED, "{body}");

    harness.cleanup();
    Ok(())
}

/// The safety-gap regression against real PostgreSQL: the shipped sweep skips an
/// orphaned endpoint re-attached by a live server (reporting `skipped_attached`)
/// rather than stripping the live guest's NIC, and the live server's delete then
/// releases it.
#[tokio::test]
#[ignore = "requires O3K_DATABASE_URL (PostgreSQL)"]
async fn postgres_orphan_endpoint_re_attached_by_live_server_is_skipped_and_released_on_delete()
-> Result<(), Box<dyn std::error::Error + Send + Sync>> {
    let _pg_test_lock_guard = PG_TEST_DATABASE_LOCK.lock().await;
    let url = postgres_test_url();
    let _database_guard = acquire_postgres_database_guard(&url).await;
    clean_postgres(&url).await;

    let armed = Arc::new(std::sync::atomic::AtomicBool::new(true));
    let wrapper: ProjectorWrapper = {
        let armed = armed.clone();
        Arc::new(move |_network, inner| {
            Arc::new(CrashBeforeReleaseProjector {
                inner,
                armed: armed.clone(),
            })
        })
    };
    let harness = build_postgres(url.clone(), Some(wrapper)).await?;
    assert_attached_orphan_skipped_by_sweep_then_released_on_delete(&harness, &armed).await?;
    harness.cleanup();
    Ok(())
}

/// Issue #1035 regression: the orphan repair sweep is serialized (via
/// `ComputeService::orphan_repair_lock`, held by the adapter create paths
/// across [existing-port validation -> durable intent persist] and by the
/// sweep for its whole pass) so a create racing the sweep resolves to exactly
/// one durable outcome: either the create wins (a non-terminal server durably
/// references the port, and the port survives the sweep) or the sweep wins
/// (the port is released and the create is rejected — never leaving a durable
/// reference to a deleted port). Proven on both the SQLite and PostgreSQL
/// lanes.
async fn run_orphan_serialization_race(
    harness: &Harness,
    armed: &Arc<std::sync::atomic::AtomicBool>,
    label: &str,
) -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
    let _report_guard = REPORT_CAPTURE_LOCK.lock().await;

    // A fresh orphan per iteration so each race is independent: a server-owned
    // endpoint is 1:1 with a server, so reusing one port across iterations
    // would couple the races.
    for iteration in 0..4i32 {
        // Re-arm the crash projector so this iteration's delete leaves a fresh
        // orphan; then disarm so the race's release path works again.
        armed.store(true, std::sync::atomic::Ordering::SeqCst);
        let (deleted_id, port) =
            create_orphaned_endpoint(harness, &format!("{label}-orphan-{iteration}")).await?;
        assert_durable_terminal_delete_with_orphan(harness, &deleted_id, port).await?;
        // The control plane "comes back": the release path works again.
        armed.store(false, std::sync::atomic::Ordering::SeqCst);

        // Race one sweep pass against a create that reuses the orphan's port.
        let reconciler = spawn_shipped_sweeps(&harness.compute);
        let (status, body) = harness
            .native_create(
                &format!("{label}-create-{iteration}"),
                json!([port.to_string()]),
            )
            .await?;
        // Let the in-flight sweep pass settle, then stop the reconciler.
        tokio::time::sleep(Duration::from_millis(1200)).await;
        reconciler.abort();
        let stopped = reconciler.await;
        assert!(
            stopped.is_err_and(|error| error.is_cancelled()),
            "the shipped convergence sweep ended abnormally"
        );

        if status.is_success() {
            // The create won the race: a live, non-terminal server durably
            // references the port, and the port must still be present (the
            // sweep must have preserved a still-referenced endpoint).
            let id = body["resource_id"]
                .as_str()
                .or_else(|| body["server"]["id"].as_str())
                .expect("created server id")
                .to_owned();
            let resource = harness
                .store
                .get_resource(Uuid::parse_str(&id)?)
                .await
                .expect("created server resource");
            assert_ne!(
                resource.observed_state, "DELETED",
                "a create that won the race must leave a non-terminal server"
            );
            assert!(
                harness.port_present(port).await,
                "a referenced server-owned endpoint must survive the orphan sweep"
            );
        } else {
            // The sweep won the race: the create was rejected and the port must
            // have been released — a durable reference to a deleted port is the
            // exact invariant this serialization exists to rule out.
            assert!(
                !harness.port_present(port).await,
                "if the orphan sweep won, the endpoint must be released: {status} {body}"
            );
        }
    }

    // Realm-wide invariant: no non-terminal server's durable intent references
    // a port that no longer exists.
    let resources = harness
        .store
        .list_resources_by_kind("compute_instance")
        .await
        .expect("list compute resources");
    for resource in &resources {
        if resource.observed_state == "DELETED" {
            continue;
        }
        let intent: Value = serde_json::from_str(&resource.desired_state)?;
        let Some(ids) = intent["network_ids"].as_array() else {
            continue;
        };
        for network_id in ids {
            let Some(network_id) = network_id.as_str() else {
                continue;
            };
            let Ok(port_id) = Uuid::parse_str(network_id) else {
                continue;
            };
            assert!(
                harness.port_present(port_id).await,
                "non-terminal server {} references a deleted port {port_id}",
                resource.id
            );
        }
    }
    Ok(())
}

#[tokio::test]
async fn orphan_repair_is_serialized_with_a_port_attaching_create()
-> Result<(), Box<dyn std::error::Error + Send + Sync>> {
    let armed = Arc::new(std::sync::atomic::AtomicBool::new(true));
    let wrapper: ProjectorWrapper = {
        let armed = armed.clone();
        Arc::new(move |_network, inner| {
            Arc::new(CrashBeforeReleaseProjector {
                inner,
                armed: armed.clone(),
            })
        })
    };
    let harness = Harness::build_with(Some(wrapper)).await?;
    run_orphan_serialization_race(&harness, &armed, "pp5-race").await?;
    harness.cleanup();
    Ok(())
}

#[tokio::test]
#[ignore = "requires O3K_DATABASE_URL (PostgreSQL)"]
async fn postgres_orphan_repair_is_serialized_with_a_port_attaching_create()
-> Result<(), Box<dyn std::error::Error + Send + Sync>> {
    let _pg_test_lock_guard = PG_TEST_DATABASE_LOCK.lock().await;
    let url = postgres_test_url();
    clean_postgres(&url).await;
    let armed = Arc::new(std::sync::atomic::AtomicBool::new(true));
    let wrapper: ProjectorWrapper = {
        let armed = armed.clone();
        Arc::new(move |_network, inner| {
            Arc::new(CrashBeforeReleaseProjector {
                inner,
                armed: armed.clone(),
            })
        })
    };
    let harness = build_postgres(url.clone(), Some(wrapper)).await?;
    run_orphan_serialization_race(&harness, &armed, "pp5-pg-race").await?;
    harness.cleanup();
    Ok(())
}
