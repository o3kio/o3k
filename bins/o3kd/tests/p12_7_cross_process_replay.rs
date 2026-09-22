//! P12.7 independent-runtime evidence for the canonical native compute-create
//! replay contract.
//!
//! rc.18 failed because an *equivalent* same-key create re-entered Placement
//! before canonical acceptance, consumed the deterministic allocation, and
//! surfaced `NoValidHost` as an HTTP 500. The correction resolves the canonical
//! idempotency reservation before scheduling/reserving any new authority. The
//! in-process regressions in `p12_7_convergence.rs` prove the ordering; this
//! file proves that the replay authority is *durable rather than process-local*
//! by exercising genuinely independent runtimes.
//!
//! Runtime independence is literal: each `runtime A`/`runtime B` is a separate
//! operating-system process (a re-exec of this test binary, selected by the
//! `p12_7_cross_process_runtime_child` entrypoint) with its own PostgreSQL
//! connection pool, its own in-memory provider, and its own Placement ledger
//! handle. The only thing the runtimes share is the durable store, which is the
//! production authority boundary. No process-local mutex, channel, or shared
//! `Arc` participates in convergence.
#![cfg(unix)]
#![allow(clippy::expect_used, clippy::panic)]

use axum::http::StatusCode;
use o3k_compute::ComputeService;
use o3k_kernel::{
    ControllerSession, LimitKey, ManifestRegistry, OwnershipScope, PrincipalId, ProtocolVersion,
    ScopeId, ServicePrincipal,
};
use o3k_native_api::auth::TokenIssuer;
use o3k_network::NetworkService;
use o3k_provider::{FailureInjection, FakeComputeProvider};
use o3k_store::{DurableStore, KeypairRepository, NetworkRepository, O3kStore, QuotaRepository};
use serde_json::{Value, json};
use sqlx::postgres::PgPoolOptions;
use std::{
    collections::{BTreeMap, BTreeSet},
    path::{Path, PathBuf},
    process::{Child, Command, Stdio},
    sync::Arc,
    time::{Duration, Instant},
};

/// Shared, deterministic signing key so a token minted by one runtime is
/// accepted by the other (both load the same durable identity snapshot).
const SIGNING_KEY: &str = "a-secure-signing-key-with-at-least-32-bytes";
const CATALOG_ENDPOINT: &str = "http://127.0.0.1:8080";
const PROJECT_ID: &str = "11111111-1111-1111-1111-111111111111";
const PROJECT_NAME: &str = "project-a";
const USER_ID: &str = "22222222-2222-2222-2222-222222222222";
const USER_NAME: &str = "user-a";
const USER_PASSWORD: &str = "password-a";
const KEYPAIR_NAME: &str = "native-key";
const NETWORK_NAME: &str = "xproc-network";
const SUBNET_NAME: &str = "xproc-subnet";

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
        manifest_digest: format!("p12-7-xproc-{service}"),
        manifest_generation: generation,
        started_at: "2026-09-21T00:00:00Z".to_owned(),
    }
}

/// The runtime objects shared by the in-process P12.7 evidence and this
/// cross-process gate. Each call constructs an application root over exactly
/// one store connection, so calling it inside a child process yields an
/// independent runtime rather than a view onto another runtime's memory.
async fn build_runtime(
    store: Arc<O3kStore>,
    identity: o3k_identity::TokenService,
    scheduler: o3k_scheduler::Scheduler,
) -> Result<(axum::Router, Arc<FakeComputeProvider>), Box<dyn std::error::Error>> {
    let provider = Arc::new(FakeComputeProvider::new());
    let compute_service =
        ComputeService::new_for_test(store.clone(), provider.clone()).with_scheduler(scheduler);
    let compute = Arc::new(compute_service.clone());
    let network = Arc::new(
        NetworkService::open_for_test(
            std::env::temp_dir().join(format!("o3k-p12-7-xproc-network-{}", uuid::Uuid::new_v4())),
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

// ---------------------------------------------------------------------------
// Child runtime entrypoint: a literal independent OS process.
// ---------------------------------------------------------------------------

/// Runs only when spawned by the parent tests below. As an ordinary test it is
/// a no-op, so it never disturbs the normal harness.
#[test]
fn p12_7_cross_process_runtime_child() {
    let Ok(store_spec) = std::env::var("O3K_P12_7_CHILD_STORE") else {
        return;
    };
    let address = std::env::var("O3K_P12_7_CHILD_ADDR").expect("child address");
    let ready = std::env::var("O3K_P12_7_CHILD_READY").expect("child ready path");
    let role = std::env::var("O3K_P12_7_CHILD_ROLE").unwrap_or_else(|_| "child".to_owned());
    let hold = std::env::var("O3K_P12_7_CHILD_HOLD").ok();
    let runtime = tokio::runtime::Runtime::new().expect("child tokio runtime");
    runtime.block_on(async move {
        run_child(&store_spec, &address, &ready, &role, hold.as_deref())
            .await
            .expect("child runtime failed");
    });
}

async fn run_child(
    store_spec: &str,
    address: &str,
    ready: &str,
    role: &str,
    hold: Option<&str>,
) -> Result<(), Box<dyn std::error::Error>> {
    init_child_logging();
    // The parent has already migrated and seeded the shared durable store; this
    // child only reads it, so no two runtimes race on schema/seed bootstrap.
    let store = match store_spec.strip_prefix("sqlite:") {
        Some(path) => Arc::new(O3kStore::connect_sqlite_file(Path::new(path)).await?),
        None => Arc::new(O3kStore::connect_postgres(store_spec).await?),
    };
    let identity = o3k_identity::TokenService::load(
        store.clone(),
        o3k_identity::Secret::new(SIGNING_KEY.to_owned()),
        Duration::from_secs(3600),
    )
    .await?;
    let placement_root = std::env::temp_dir().join(format!(
        "o3k-p12-7-xproc-placement-{role}-{}",
        uuid::Uuid::new_v4()
    ));
    let ledger = o3k_placement::PlacementLedger::open(&placement_root, store.clone()).await?;
    let scheduler = o3k_scheduler::Scheduler::new(ledger);
    let (app, provider) = build_runtime(store.clone(), identity, scheduler).await?;
    if let Some(hold) = hold {
        let injection = match hold {
            "running" => FailureInjection::PartialCompletion,
            "failed" => FailureInjection::Terminal,
            other => return Err(format!("unknown hold injection: {other}").into()),
        };
        provider.set_failure(injection)?;
    }
    // A test-only observation of this runtime's provider side effects: the
    // identities it materialized. Independent runtimes resolve the same
    // deterministic provider identity, so the parent proves domain-identity
    // uniqueness across a genuine process boundary.
    let role = role.to_owned();
    let count_provider = provider.clone();
    let app = app.route(
        "/__p12_7_provider_count",
        axum::routing::get(move || {
            let provider = count_provider.clone();
            let role = role.clone();
            async move {
                axum::Json(json!({
                    "provider_instances": provider.instance_count(),
                    "provider_instance_ids": provider.instance_ids(),
                    "role": role,
                }))
            }
        }),
    );
    let listener = tokio::net::TcpListener::bind(address).await?;
    let bound = listener.local_addr()?;
    std::fs::write(ready, format!("{bound}"))?;
    axum::serve(listener, app).await?;
    Ok(())
}

fn init_child_logging() {
    if let Ok(filter) = std::env::var("O3K_P12_7_CHILD_LOG") {
        let _ = tracing_subscriber::fmt()
            .with_env_filter(tracing_subscriber::EnvFilter::new(filter))
            .with_writer(std::io::stderr)
            .try_init();
    }
}

// ---------------------------------------------------------------------------
// Parent harness
// ---------------------------------------------------------------------------

/// A disposable PostgreSQL database created inside the CI `O3K_DATABASE_URL`
/// server, mirroring the established `o3kd` process-test fixture.
struct PgFixture {
    admin_url: String,
    database: String,
    url: String,
}

impl PgFixture {
    async fn new() -> Result<Self, Box<dyn std::error::Error>> {
        let url = std::env::var("O3K_DATABASE_URL")?;
        let parsed = url::Url::parse(&url)?;
        let database = format!("o3k_p12_7_xproc_{}", uuid::Uuid::now_v7().simple());
        let mut base = parsed.clone();
        base.set_path("/postgres");
        let admin_url = base.to_string();
        let admin = PgPoolOptions::new()
            .max_connections(1)
            .connect(&admin_url)
            .await?;
        sqlx::query(&format!("CREATE DATABASE {database}"))
            .execute(&admin)
            .await?;
        admin.close().await;
        let mut isolated = parsed;
        isolated.set_path(&format!("/{database}"));
        Ok(Self {
            admin_url,
            database,
            url: isolated.to_string(),
        })
    }

    async fn dispose(self) {
        let Ok(admin) = PgPoolOptions::new()
            .max_connections(1)
            .connect(&self.admin_url)
            .await
        else {
            return;
        };
        let _ = sqlx::query(
            "SELECT pg_terminate_backend(pid) FROM pg_stat_activity \
             WHERE datname = $1 AND pid <> pg_backend_pid()",
        )
        .bind(&self.database)
        .execute(&admin)
        .await;
        for _ in 0..5u64 {
            if sqlx::query(&format!("DROP DATABASE {} WITH (FORCE)", self.database))
                .execute(&admin)
                .await
                .is_ok()
            {
                break;
            }
            tokio::time::sleep(Duration::from_millis(200)).await;
        }
    }
}

/// One independent OS process hosting a runtime over the shared durable store.
struct RuntimeProcess {
    child: Child,
    base: String,
    ready: PathBuf,
}

fn free_address() -> std::net::SocketAddr {
    let listener = std::net::TcpListener::bind("127.0.0.1:0").expect("bind ephemeral port");
    listener.local_addr().expect("ephemeral addr")
}

fn store_spec_for_sqlite(path: &Path) -> String {
    format!("sqlite:{}", path.display())
}

impl RuntimeProcess {
    async fn spawn(
        store_spec: &str,
        role: &str,
        hold: Option<&str>,
    ) -> Result<Self, Box<dyn std::error::Error>> {
        let address = free_address();
        let ready = std::env::temp_dir().join(format!(
            "o3k-p12-7-xproc-ready-{role}-{}",
            uuid::Uuid::now_v7().simple()
        ));
        let mut command = Command::new(std::env::current_exe()?);
        command
            .args([
                "--exact",
                "p12_7_cross_process_runtime_child",
                "--test-threads=1",
            ])
            .env("O3K_P12_7_CHILD_STORE", store_spec)
            .env("O3K_P12_7_CHILD_ADDR", address.to_string())
            .env("O3K_P12_7_CHILD_READY", ready.to_string_lossy().to_string())
            .env("O3K_P12_7_CHILD_ROLE", role)
            .stdout(Stdio::null())
            .stderr(if std::env::var("O3K_P12_7_CHILD_LOG").is_ok() {
                Stdio::inherit()
            } else {
                Stdio::null()
            });
        if let Some(hold) = hold {
            command.env("O3K_P12_7_CHILD_HOLD", hold);
        }
        let child = command.spawn()?;
        let process = Self {
            child,
            base: format!("http://{address}"),
            ready,
        };
        process.wait_ready(Duration::from_secs(120)).await?;
        Ok(process)
    }

    async fn wait_ready(&self, timeout: Duration) -> Result<(), Box<dyn std::error::Error>> {
        let deadline = Instant::now() + timeout;
        while Instant::now() < deadline {
            if self.ready.exists() {
                return Ok(());
            }
            tokio::time::sleep(Duration::from_millis(50)).await;
        }
        Err(format!("runtime {} did not become ready", self.base).into())
    }

    async fn provider_instances(&self, client: &reqwest::Client) -> usize {
        let value = self.provider_observation(client).await;
        value["provider_instances"]
            .as_u64()
            .expect("provider instance count") as usize
    }

    async fn provider_instance_ids(&self, client: &reqwest::Client) -> Vec<String> {
        self.provider_observation(client).await["provider_instance_ids"]
            .as_array()
            .expect("provider instance ids")
            .iter()
            .map(|value| value.as_str().expect("instance id").to_owned())
            .collect()
    }

    async fn provider_observation(&self, client: &reqwest::Client) -> Value {
        client
            .get(format!("{}/__p12_7_provider_count", self.base))
            .send()
            .await
            .expect("provider count response")
            .json()
            .await
            .expect("provider count json")
    }

    async fn issue_token(
        &self,
        client: &reqwest::Client,
    ) -> Result<String, Box<dyn std::error::Error>> {
        let body = json!({
            "auth": {
                "identity": {
                    "methods": ["password"],
                    "password": {"user": {"name": USER_NAME, "password": USER_PASSWORD}}
                },
                "scope": {"project": {"name": PROJECT_NAME}}
            }
        });
        let response = client
            .post(format!("{}/v3/auth/tokens", self.base))
            .json(&body)
            .send()
            .await?;
        assert_eq!(response.status(), StatusCode::CREATED, "token issue");
        Ok(response
            .headers()
            .get("x-subject-token")
            .expect("subject token header")
            .to_str()?
            .to_owned())
    }

    async fn create_network(
        &self,
        client: &reqwest::Client,
        token: &str,
    ) -> Result<String, Box<dyn std::error::Error>> {
        let response = client
            .post(format!("{}/v2.0/networks", self.base))
            .bearer_auth(token)
            .header("x-auth-token", token)
            .json(&json!({"network": {"name": NETWORK_NAME}}))
            .send()
            .await?;
        assert_eq!(response.status(), StatusCode::CREATED, "network create");
        let body: Value = response.json().await?;
        let network_id = body["network"]["id"]
            .as_str()
            .expect("network id")
            .to_owned();
        let subnet = client
            .post(format!("{}/v2.0/subnets", self.base))
            .bearer_auth(token)
            .header("x-auth-token", token)
            .json(&json!({"subnet": {
                "network_id": network_id,
                "name": SUBNET_NAME,
                "cidr": "192.0.2.0/24",
                "gateway_ip": "192.0.2.1"
            }}))
            .send()
            .await?;
        assert_eq!(subnet.status(), StatusCode::CREATED, "subnet create");
        Ok(network_id)
    }

    async fn create_server(
        &self,
        client: &reqwest::Client,
        token: &str,
        key: &str,
        body: &Value,
    ) -> (StatusCode, Value) {
        let response = client
            .post(format!("{}/o3k/v1/compute/servers", self.base))
            .bearer_auth(token)
            .header("x-auth-token", token)
            .header("idempotency-key", key)
            .json(body)
            .send()
            .await
            .expect("native create response");
        let status = response.status();
        let value: Value = response.json().await.unwrap_or(Value::Null);
        (status, value)
    }

    fn terminate(&mut self) {
        let _ = self.child.kill();
        let _ = self.child.wait();
    }
}

impl Drop for RuntimeProcess {
    fn drop(&mut self) {
        let _ = self.child.kill();
        let _ = self.child.wait();
        let _ = std::fs::remove_file(&self.ready);
    }
}

async fn open_store(spec: &str) -> Result<Arc<O3kStore>, Box<dyn std::error::Error>> {
    Ok(match spec.strip_prefix("sqlite:") {
        Some(path) => Arc::new(O3kStore::connect_sqlite_file(Path::new(path)).await?),
        None => Arc::new(O3kStore::connect_postgres(spec).await?),
    })
}

/// Seeds the durable baseline the runtimes converge through: identity, one
/// placement provider, and the keypair the create intent references.
async fn prepare_durable_state(store: &Arc<O3kStore>) -> Result<(), Box<dyn std::error::Error>> {
    o3k_identity::seed_identity_defaults(
        store.as_ref(),
        &o3k_identity::BootstrapConfig {
            catalog_endpoint: CATALOG_ENDPOINT.to_owned(),
            bootstrap_password: o3k_identity::Secret::new("bootstrap-password".to_owned()),
            cinder_password: None,
            cinder_endpoint: None,
            pbkdf2_iterations: 1_000,
            extra_projects: vec![o3k_identity::ExtraProjectSeed {
                project_id: PROJECT_ID.to_owned(),
                project_name: PROJECT_NAME.to_owned(),
                user_id: USER_ID.to_owned(),
                user_name: USER_NAME.to_owned(),
                password: o3k_identity::Secret::new(USER_PASSWORD.to_owned()),
            }],
        },
    )
    .await?;

    let placement_root = std::env::temp_dir().join(format!(
        "o3k-p12-7-xproc-parent-placement-{}",
        uuid::Uuid::now_v7().simple()
    ));
    let ledger = o3k_placement::PlacementLedger::open(&placement_root, store.clone()).await?;
    ledger
        .register_provider(
            "node-a",
            BTreeMap::from([
                (
                    o3k_placement::VCPU.to_owned(),
                    o3k_placement::Inventory {
                        total: 4,
                        reserved: 0,
                        allocation_ratio: 1.0,
                        used: 0,
                    },
                ),
                (
                    o3k_placement::MEMORY_MB.to_owned(),
                    o3k_placement::Inventory {
                        total: 4096,
                        reserved: 0,
                        allocation_ratio: 1.0,
                        used: 0,
                    },
                ),
                (
                    o3k_placement::DISK_GB.to_owned(),
                    o3k_placement::Inventory {
                        total: 40,
                        reserved: 0,
                        allocation_ratio: 1.0,
                        used: 0,
                    },
                ),
            ]),
        )
        .await?;

    let public_key =
        "ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIBJuQvak7YBzsbN71EyvJnDK8pODWM1Ox/3wO3tT8Adj o3k-test";
    let (key_type, fingerprint, public_key) = o3k_store::validate_public_key(public_key)?;
    store
        .insert_keypair(&o3k_store::KeypairRecord {
            id: uuid::Uuid::new_v5(&uuid::Uuid::NAMESPACE_URL, b"o3k:xproc-keypair"),
            user_id: USER_ID.to_owned(),
            project_id: PROJECT_ID.to_owned(),
            name: KEYPAIR_NAME.to_owned(),
            key_type,
            public_key,
            fingerprint,
            created_at: "2026-09-21T00:00:00Z".to_owned(),
        })
        .await?;
    Ok(())
}

fn project_scope() -> OwnershipScope {
    OwnershipScope::project(ScopeId::new_unchecked(PROJECT_ID), None, None)
}

fn create_body(name: &str, network_id: &str, image: &str) -> Value {
    json!({
        "kind": "compute:server",
        "spec": {
            "name": name,
            "image_id": image,
            "flavor_id": "00000000-0000-0000-0000-000000000001",
            "network_ids": [network_id],
            "key_name": KEYPAIR_NAME
        }
    })
}

struct DurableCounts {
    operation_state: o3k_store::OperationState,
    ports: usize,
    allocations: usize,
    quota_servers: u64,
}

/// Inspects durable state directly through repository APIs rather than trusting
/// any HTTP body.
async fn inspect(
    store: &Arc<O3kStore>,
    resource_id: uuid::Uuid,
    operation_id: uuid::Uuid,
) -> Result<DurableCounts, Box<dyn std::error::Error>> {
    let ports = store.list_ports(PROJECT_ID).await?;
    let ledger = o3k_placement::PlacementLedger::open(
        std::env::temp_dir().join(format!("o3k-p12-7-xproc-inspect-{}", uuid::Uuid::now_v7())),
        store.clone(),
    )
    .await?;
    let allocation_id = format!("allocation-{resource_id}");
    let allocations = ledger
        .providers()
        .await?
        .iter()
        .filter(|provider| provider.allocations.contains_key(&allocation_id))
        .count();
    let operation = store.get_operation(operation_id).await?;
    let usage = store
        .get_usage(&project_scope(), &LimitKey::compute_servers())
        .await?;
    let _ = store.get_resource(resource_id).await?;
    Ok(DurableCounts {
        operation_state: operation.state,
        ports: ports.len(),
        allocations,
        quota_servers: usage.in_use,
    })
}

/// Bounded SQL confirmation that the durable reservation/operation/resource
/// rows exist exactly once for the canonical identity.
async fn assert_single_durable_rows(
    admin_url: &str,
    database: &str,
    resource_id: uuid::Uuid,
    operation_id: uuid::Uuid,
    idempotency_key: &str,
) -> Result<(), Box<dyn std::error::Error>> {
    let parsed = url::Url::parse(admin_url)?;
    let mut base = parsed.clone();
    base.set_path(&format!("/{database}"));
    let pool = PgPoolOptions::new()
        .max_connections(1)
        .connect(base.as_str())
        .await?;
    let (reservations, action): (i64, String) = {
        let row = sqlx::query(
            "SELECT count(*) AS n, coalesce(max(action), '') AS action \
             FROM idempotency_reservations WHERE owner_scope = $1 AND idempotency_key = $2",
        )
        .bind(PROJECT_ID)
        .bind(idempotency_key)
        .fetch_one(&pool)
        .await?;
        use sqlx::Row;
        (row.try_get("n")?, row.try_get("action")?)
    };
    let operations: i64 = sqlx::query_scalar("SELECT count(*) FROM operations WHERE id = $1")
        .bind(operation_id.to_string())
        .fetch_one(&pool)
        .await?;
    let resources: i64 = sqlx::query_scalar("SELECT count(*) FROM resources WHERE id = $1")
        .bind(resource_id.to_string())
        .fetch_one(&pool)
        .await?;
    let ports: i64 = sqlx::query_scalar("SELECT count(*) FROM network_ports WHERE project_id = $1")
        .bind(PROJECT_ID)
        .fetch_one(&pool)
        .await?;
    pool.close().await;
    assert_eq!(reservations, 1, "canonical idempotency reservation count");
    assert!(!action.is_empty(), "reservation action recorded");
    assert_eq!(operations, 1, "canonical operation count");
    assert_eq!(resources, 1, "canonical resource count");
    assert_eq!(ports, 1, "deterministic native port count");
    Ok(())
}

fn resource_id_of(value: &Value) -> uuid::Uuid {
    value["resource_id"]
        .as_str()
        .expect("resource_id in response")
        .parse()
        .expect("resource uuid")
}

fn operation_id_of(value: &Value) -> uuid::Uuid {
    value["operation_id"]
        .as_str()
        .expect("operation_id in response")
        .parse()
        .expect("operation uuid")
}

// ---------------------------------------------------------------------------
// PostgreSQL: mandatory independent-runtime gate
// ---------------------------------------------------------------------------

#[tokio::test]
#[ignore = "requires O3K_DATABASE_URL pointing at a real PostgreSQL conformance database"]
async fn cross_process_sequential_replay_postgres() -> Result<(), Box<dyn std::error::Error>> {
    let fixture = PgFixture::new().await?;
    let store = open_store(&fixture.url).await?;
    prepare_durable_state(&store).await?;
    let client = reqwest::Client::new();

    let mut runtime_a = RuntimeProcess::spawn(&fixture.url, "a", None).await?;
    let mut runtime_b = RuntimeProcess::spawn(&fixture.url, "b", None).await?;

    let token = runtime_a.issue_token(&client).await?;
    let network_id = runtime_a.create_network(&client, &token).await?;
    let body = create_body("xproc-sequential", &network_id, "image-a");

    let (status_a, value_a) = runtime_a
        .create_server(&client, &token, "xproc-seq", &body)
        .await;
    assert_eq!(status_a, StatusCode::CREATED, "runtime A create: {value_a}");
    let resource_id = resource_id_of(&value_a);
    let operation_id = operation_id_of(&value_a);
    assert_eq!(
        runtime_a.provider_instances(&client).await,
        1,
        "A provider create"
    );
    assert_eq!(
        runtime_b.provider_instances(&client).await,
        0,
        "B provider create"
    );

    let ports_after_a = store.list_ports(PROJECT_ID).await?;
    let usage_after_a = store
        .get_usage(&project_scope(), &LimitKey::compute_servers())
        .await?;

    // Runtime B resolves the replay from durable authority alone.
    let (status_b, value_b) = runtime_b
        .create_server(&client, &token, "xproc-seq", &body)
        .await;
    assert_eq!(
        status_b,
        StatusCode::CREATED,
        "equivalent cross-process replay must not be an internal error: {value_b}"
    );
    assert_eq!(resource_id_of(&value_b), resource_id, "same resource");
    assert_eq!(operation_id_of(&value_b), operation_id, "same operation");
    assert_eq!(
        runtime_b.provider_instances(&client).await,
        0,
        "B provider duplicate"
    );
    assert_eq!(
        store.list_ports(PROJECT_ID).await?,
        ports_after_a,
        "B must not create another port"
    );
    assert_eq!(
        store
            .get_usage(&project_scope(), &LimitKey::compute_servers())
            .await?,
        usage_after_a,
        "B must not consume additional quota"
    );

    let counts = inspect(&store, resource_id, operation_id).await?;
    assert_eq!(counts.operation_state, o3k_store::OperationState::Succeeded);
    assert_eq!(counts.ports, 1);
    assert_eq!(counts.allocations, 1);
    assert_eq!(counts.quota_servers, 1);
    assert_single_durable_rows(
        &fixture.admin_url,
        &fixture.database,
        resource_id,
        operation_id,
        "xproc-seq",
    )
    .await?;

    runtime_a.terminate();
    runtime_b.terminate();
    fixture.dispose().await;
    Ok(())
}

#[tokio::test]
#[ignore = "requires O3K_DATABASE_URL pointing at a real PostgreSQL conformance database"]
async fn cross_process_concurrent_replay_postgres() -> Result<(), Box<dyn std::error::Error>> {
    let fixture = PgFixture::new().await?;
    let store = open_store(&fixture.url).await?;
    prepare_durable_state(&store).await?;
    let client = reqwest::Client::new();

    let mut runtime_a = RuntimeProcess::spawn(&fixture.url, "a", None).await?;
    let mut runtime_b = RuntimeProcess::spawn(&fixture.url, "b", None).await?;

    let token = runtime_a.issue_token(&client).await?;
    let network_id = runtime_a.create_network(&client, &token).await?;
    let body = create_body("xproc-concurrent", &network_id, "image-a");

    // Fire both independent runtimes at the same scope/key/request as
    // simultaneously as practical. No shared process-local gate orders them.
    let (result_a, result_b) = tokio::join!(
        runtime_a.create_server(&client, &token, "xproc-race", &body),
        runtime_b.create_server(&client, &token, "xproc-race", &body),
    );
    for (label, result) in [("A", &result_a), ("B", &result_b)] {
        assert!(
            result.0 == StatusCode::CREATED || result.0 == StatusCode::ACCEPTED,
            "runtime {label} must converge on the canonical result, never fail because it \
             lost the create race: {} {}",
            result.0,
            result.1
        );
    }
    let resource_id = resource_id_of(&result_a.1);
    assert_eq!(
        resource_id,
        resource_id_of(&result_b.1),
        "converged resource"
    );
    let operation_id = operation_id_of(&result_a.1);
    assert_eq!(
        operation_id,
        operation_id_of(&result_b.1),
        "converged operation"
    );

    // Control-plane convergence is durable: both runtimes converge on one
    // canonical identity and one deterministic provider identity. The
    // in-memory `FakeComputeProvider` keeps its idempotency ledger per process,
    // so two independent runtimes can each *attempt* the deterministic provider
    // create; the product dedups provider commands at the shared execution
    // boundary (the compute-agent command journal, single-owner dispatch —
    // covered by crates/o3k-compute/tests/multi_controller_acceptance.rs),
    // which an in-process fake cannot represent. What must hold across a real
    // process boundary is that both runtimes resolve the SAME deterministic
    // provider identity: never two domain identities for one canonical server.
    let expected_provider_id = format!("fake-{resource_id}");
    let mut provider_ids: BTreeSet<String> = BTreeSet::new();
    for runtime in [&runtime_a, &runtime_b] {
        let ids = runtime.provider_instance_ids(&client).await;
        assert!(
            ids.len() <= 1,
            "a runtime must not materialize more than one domain for one create: {ids:?}"
        );
        provider_ids.extend(ids);
    }
    assert_eq!(
        provider_ids,
        BTreeSet::from([expected_provider_id]),
        "independent runtimes must converge on exactly one deterministic provider identity"
    );
    let total_provider =
        runtime_a.provider_instances(&client).await + runtime_b.provider_instances(&client).await;
    assert_eq!(
        total_provider, 1,
        "exactly one provider create across independent runtimes"
    );

    let counts = inspect(&store, resource_id, operation_id).await?;
    assert_eq!(counts.operation_state, o3k_store::OperationState::Succeeded);
    assert_eq!(counts.ports, 1);
    assert_eq!(counts.allocations, 1);
    assert_eq!(counts.quota_servers, 1);
    assert_single_durable_rows(
        &fixture.admin_url,
        &fixture.database,
        resource_id,
        operation_id,
        "xproc-race",
    )
    .await?;

    runtime_a.terminate();
    runtime_b.terminate();
    fixture.dispose().await;
    Ok(())
}

#[tokio::test]
#[ignore = "requires O3K_DATABASE_URL pointing at a real PostgreSQL conformance database"]
async fn cross_process_in_flight_replay_postgres() -> Result<(), Box<dyn std::error::Error>> {
    let fixture = PgFixture::new().await?;
    let store = open_store(&fixture.url).await?;
    prepare_durable_state(&store).await?;
    let client = reqwest::Client::new();

    let mut runtime_a = RuntimeProcess::spawn(&fixture.url, "a", Some("running")).await?;
    let mut runtime_b = RuntimeProcess::spawn(&fixture.url, "b", None).await?;

    let token = runtime_a.issue_token(&client).await?;
    let network_id = runtime_a.create_network(&client, &token).await?;
    let body = create_body("xproc-in-flight", &network_id, "image-a");

    let (status_a, value_a) = runtime_a
        .create_server(&client, &token, "xproc-inflight", &body)
        .await;
    assert_eq!(
        status_a,
        StatusCode::ACCEPTED,
        "runtime A create is in flight: {value_a}"
    );
    let resource_id = resource_id_of(&value_a);
    let operation_id = operation_id_of(&value_a);
    let ports_after_a = store.list_ports(PROJECT_ID).await?;

    let (status_b, value_b) = runtime_b
        .create_server(&client, &token, "xproc-inflight", &body)
        .await;
    assert_eq!(
        status_b,
        StatusCode::ACCEPTED,
        "in-flight replay must return the live operation, not a new lifecycle: {value_b}"
    );
    assert_eq!(resource_id_of(&value_b), resource_id, "same resource");
    assert_eq!(operation_id_of(&value_b), operation_id, "same operation");
    assert_eq!(
        runtime_b.provider_instances(&client).await,
        0,
        "B must not dispatch a duplicate provider command"
    );
    assert_eq!(
        store.list_ports(PROJECT_ID).await?,
        ports_after_a,
        "B must not allocate another port"
    );
    let operation = store.get_operation(operation_id).await?;
    assert_eq!(
        operation.state,
        o3k_store::OperationState::Running,
        "replay must report the truthful current operation state without waiting"
    );

    runtime_a.terminate();
    runtime_b.terminate();
    fixture.dispose().await;
    Ok(())
}

#[tokio::test]
#[ignore = "requires O3K_DATABASE_URL pointing at a real PostgreSQL conformance database"]
async fn cross_process_terminal_replay_and_conflict_postgres()
-> Result<(), Box<dyn std::error::Error>> {
    let fixture = PgFixture::new().await?;
    let store = open_store(&fixture.url).await?;
    prepare_durable_state(&store).await?;
    let client = reqwest::Client::new();

    let mut runtime_a = RuntimeProcess::spawn(&fixture.url, "a", None).await?;
    let mut runtime_b = RuntimeProcess::spawn(&fixture.url, "b", None).await?;

    let token = runtime_a.issue_token(&client).await?;
    let network_id = runtime_a.create_network(&client, &token).await?;
    let body = create_body("xproc-terminal", &network_id, "image-a");

    let (status_a, value_a) = runtime_a
        .create_server(&client, &token, "xproc-terminal", &body)
        .await;
    assert_eq!(status_a, StatusCode::CREATED, "runtime A create: {value_a}");
    let resource_id = resource_id_of(&value_a);
    let operation_id = operation_id_of(&value_a);
    assert_eq!(runtime_a.provider_instances(&client).await, 1);

    let ports_after_first = store.list_ports(PROJECT_ID).await?;
    let usage_after_first = store
        .get_usage(&project_scope(), &LimitKey::compute_servers())
        .await?;

    // The public rc.18 failure shape: equivalent replay after terminal success.
    let (status_b, value_b) = runtime_b
        .create_server(&client, &token, "xproc-terminal", &body)
        .await;
    assert_eq!(status_b, StatusCode::CREATED, "terminal replay: {value_b}");
    assert_eq!(resource_id_of(&value_b), resource_id);
    assert_eq!(operation_id_of(&value_b), operation_id);
    assert_eq!(
        store.get_operation(operation_id).await?.state,
        o3k_store::OperationState::Succeeded
    );

    // Same key, materially different body -> conflict with no new side effects.
    let changed = create_body("xproc-terminal", &network_id, "image-b");
    let (status_conflict, _) = runtime_b
        .create_server(&client, &token, "xproc-terminal", &changed)
        .await;
    assert_eq!(
        status_conflict,
        StatusCode::CONFLICT,
        "different-body same-key request must conflict"
    );
    assert_eq!(runtime_a.provider_instances(&client).await, 1);
    assert_eq!(
        runtime_b.provider_instances(&client).await,
        0,
        "conflict must not dispatch a provider command"
    );
    assert_eq!(store.get_resource(resource_id).await?.id, resource_id);
    assert_eq!(
        store.get_operation(operation_id).await?.state,
        o3k_store::OperationState::Succeeded
    );
    assert_eq!(
        store.list_ports(PROJECT_ID).await?,
        ports_after_first,
        "conflict must not allocate another port"
    );
    assert_eq!(
        store
            .get_usage(&project_scope(), &LimitKey::compute_servers())
            .await?,
        usage_after_first,
        "conflict must not consume additional quota"
    );

    runtime_a.terminate();
    runtime_b.terminate();
    fixture.dispose().await;
    Ok(())
}

#[tokio::test]
#[ignore = "requires O3K_DATABASE_URL pointing at a real PostgreSQL conformance database"]
async fn cross_process_restart_replay_postgres() -> Result<(), Box<dyn std::error::Error>> {
    let fixture = PgFixture::new().await?;
    let store = open_store(&fixture.url).await?;
    prepare_durable_state(&store).await?;
    let client = reqwest::Client::new();

    let mut runtime_a = RuntimeProcess::spawn(&fixture.url, "a", None).await?;
    let token = runtime_a.issue_token(&client).await?;
    let network_id = runtime_a.create_network(&client, &token).await?;
    let body = create_body("xproc-restart", &network_id, "image-a");

    let (status_a, value_a) = runtime_a
        .create_server(&client, &token, "xproc-restart", &body)
        .await;
    assert_eq!(status_a, StatusCode::CREATED, "runtime A create: {value_a}");
    let resource_id = resource_id_of(&value_a);
    let operation_id = operation_id_of(&value_a);
    assert_eq!(runtime_a.provider_instances(&client).await, 1);
    let ports_after_a = store.list_ports(PROJECT_ID).await?;

    // Complete process loss: the create runtime no longer exists.
    runtime_a.terminate();

    let mut runtime_b = RuntimeProcess::spawn(&fixture.url, "b", None).await?;
    let (status_b, value_b) = runtime_b
        .create_server(&client, &token, "xproc-restart", &body)
        .await;
    assert_eq!(
        status_b,
        StatusCode::CREATED,
        "restart replay must resolve from durable authority: {value_b}"
    );
    assert_eq!(
        resource_id_of(&value_b),
        resource_id,
        "same resource after restart"
    );
    assert_eq!(
        operation_id_of(&value_b),
        operation_id,
        "same operation after restart"
    );
    assert_eq!(runtime_b.provider_instances(&client).await, 0);
    assert_eq!(store.list_ports(PROJECT_ID).await?, ports_after_a);
    assert_eq!(
        store.get_operation(operation_id).await?.state,
        o3k_store::OperationState::Succeeded
    );

    runtime_b.terminate();
    fixture.dispose().await;
    Ok(())
}

// ---------------------------------------------------------------------------
// SQLite: additional portable independent-runtime evidence
// ---------------------------------------------------------------------------

fn sqlite_path(tag: &str) -> PathBuf {
    std::env::temp_dir().join(format!(
        "o3k-p12-7-xproc-{tag}-{}.sqlite",
        uuid::Uuid::now_v7().simple()
    ))
}

#[tokio::test]
async fn cross_process_sequential_replay_sqlite() -> Result<(), Box<dyn std::error::Error>> {
    let path = sqlite_path("sequential");
    let spec = store_spec_for_sqlite(&path);
    let store = open_store(&spec).await?;
    prepare_durable_state(&store).await?;
    let client = reqwest::Client::new();

    let mut runtime_a = RuntimeProcess::spawn(&spec, "a", None).await?;
    let mut runtime_b = RuntimeProcess::spawn(&spec, "b", None).await?;

    let token = runtime_a.issue_token(&client).await?;
    let network_id = runtime_a.create_network(&client, &token).await?;
    let body = create_body("xproc-sqlite", &network_id, "image-a");

    let (status_a, value_a) = runtime_a
        .create_server(&client, &token, "xproc-sqlite", &body)
        .await;
    assert_eq!(status_a, StatusCode::CREATED, "runtime A create: {value_a}");
    let resource_id = resource_id_of(&value_a);
    let operation_id = operation_id_of(&value_a);

    let (status_b, value_b) = runtime_b
        .create_server(&client, &token, "xproc-sqlite", &body)
        .await;
    assert_eq!(
        status_b,
        StatusCode::CREATED,
        "equivalent replay: {value_b}"
    );
    assert_eq!(resource_id_of(&value_b), resource_id);
    assert_eq!(operation_id_of(&value_b), operation_id);
    assert_eq!(runtime_b.provider_instances(&client).await, 0);

    runtime_a.terminate();
    runtime_b.terminate();
    let _ = std::fs::remove_file(&path);
    Ok(())
}

#[tokio::test]
async fn cross_process_restart_replay_sqlite() -> Result<(), Box<dyn std::error::Error>> {
    let path = sqlite_path("restart");
    let spec = store_spec_for_sqlite(&path);
    let store = open_store(&spec).await?;
    prepare_durable_state(&store).await?;
    let client = reqwest::Client::new();

    let mut runtime_a = RuntimeProcess::spawn(&spec, "a", None).await?;
    let token = runtime_a.issue_token(&client).await?;
    let network_id = runtime_a.create_network(&client, &token).await?;
    let body = create_body("xproc-sqlite-restart", &network_id, "image-a");

    let (status_a, value_a) = runtime_a
        .create_server(&client, &token, "xproc-sqlite-restart", &body)
        .await;
    assert_eq!(status_a, StatusCode::CREATED, "runtime A create: {value_a}");
    let resource_id = resource_id_of(&value_a);
    let operation_id = operation_id_of(&value_a);
    runtime_a.terminate();

    let mut runtime_b = RuntimeProcess::spawn(&spec, "b", None).await?;
    let (status_b, value_b) = runtime_b
        .create_server(&client, &token, "xproc-sqlite-restart", &body)
        .await;
    assert_eq!(status_b, StatusCode::CREATED, "restart replay: {value_b}");
    assert_eq!(resource_id_of(&value_b), resource_id);
    assert_eq!(operation_id_of(&value_b), operation_id);
    assert_eq!(runtime_b.provider_instances(&client).await, 0);

    runtime_b.terminate();
    let _ = std::fs::remove_file(&path);
    Ok(())
}
