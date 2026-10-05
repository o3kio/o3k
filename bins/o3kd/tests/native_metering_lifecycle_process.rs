//! Real lifecycle-driven metering evidence (#904).
//!
//! Unlike `native_metering_process.rs`, which drives the observer directly,
//! this suite drives the *production* lifecycle paths:
//!
//! - a compute server is created, stopped, started and deleted through the
//!   real native resource API, with convergence going through
//!   `o3k_reconciler`/`o3k_compute` so every observed state projects the
//!   `compute:instance_seconds` meter;
//! - a volume is created and deleted through `GenericResourceApplication` so
//!   the `volume:allocated_byte_seconds` allocation meter opens and closes;
//! - `o3k_api::recover_native_volumes` closes an allocation interval left open
//!   by an interrupted delete.
//!
//! A single controllable fake clock is installed in the adapter that is both
//! the native API reader and the lifecycle observer, so observation instants
//! and query evaluation share one deterministic time source. No wall-clock
//! sleeping is used to advance usage.
//!
//! ## Completeness vs. the evaluation instant
//!
//! `o3k-store` marks a usage window whose `end` is later than
//! `evaluated_at_ms` as `partial`, and accrues an open interval only up to
//! `min(end, evaluated_at_ms)`. Exactly one of those two facts can hold for a
//! query taken while an interval is still open inside the requested window: a
//! query evaluated at the live instant reports the exact live quantity but is
//! `partial` (the window extends past the instant), while a query evaluated at
//! the window end is `complete` but would accrue an open interval for the
//! whole window. The tests below therefore assert the exact quantity at the
//! live instant and assert `complete` once the interval is closed and the
//! window is fully evaluated.
#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]

use axum::body::Body;
use axum::http::{Method, Request, StatusCode, header};
use o3k_compute::ComputeService;
use o3k_kernel::{
    AuthContext, Clock, ManifestRegistry, MeterUsageReport, OwnershipScope, Principal, PrincipalId,
    ResourceType, ScopeId, ScopeKind, UsageGranularity, UsageQuery, UserPrincipal,
};
use o3k_native_api::auth::TokenIssuer;
use o3k_native_api::metering::MeteringReader;
use o3k_native_api::pagination::CursorConfig;
use o3k_native_api::resource::{ResourceApplication, ValidatedCreateRequest};
use o3k_native_api::resource_contract::ValidatedSpec;
use o3k_network::NetworkService;
use o3k_provider::FakeComputeProvider;
use o3k_storage::StorageProvider;
use o3k_storage::testkit::InMemoryStorageProvider;
use o3k_store::unified::O3kStore;
use o3k_store::{DurableStore, StorageRepository};
use serde_json::{Value, json};
use std::sync::Arc;
use std::sync::atomic::{AtomicI64, Ordering};
use std::time::Duration;
use tower::ServiceExt;
use uuid::Uuid;

type TestResult = Result<(), Box<dyn std::error::Error>>;

const HOUR_MS: i64 = 3_600_000;
/// A UTC hour boundary: 2023-11-14T22:00:00Z.
const BASE_MS: i64 = 1_699_999_200_000;
/// Known volume capacity used by the allocation-meter assertions.
const VOLUME_SIZE_BYTES: u64 = 1_000_000;

/// Never present in any public metering DTO.
const SECRET_MARKERS: [&str; 6] = [
    "password",
    "private_key",
    "postgres://",
    "Bearer ",
    "node-42",
    "agent-epoch-9",
];

/// Fake clock the test drives directly. The adapter reads it for every
/// observation and for usage evaluation.
#[derive(Clone)]
struct TestClock(Arc<AtomicI64>);

impl TestClock {
    fn new(now_ms: i64) -> Self {
        Self(Arc::new(AtomicI64::new(now_ms)))
    }

    fn set(&self, now_ms: i64) {
        self.0.store(now_ms, Ordering::SeqCst);
    }
}

impl Clock for TestClock {
    fn now_unix_ms(&self) -> i64 {
        self.0.load(Ordering::SeqCst)
    }
}

/// Mock `TokenIssuer` keyed by token string: a durable system operator and a
/// plain project tenant.
#[derive(Clone)]
struct TestIssuer {
    operator: AuthContext,
    tenant: AuthContext,
}

#[async_trait::async_trait]
impl TokenIssuer for TestIssuer {
    async fn issue_native(
        &self,
        _request: &o3k_native_api::auth::NativeTokenRequestV1,
    ) -> Result<(String, Value), o3k_native_api::error::ProblemDetails> {
        Err(o3k_native_api::error::ProblemDetails::unauthorized())
    }

    async fn auth_context(
        &self,
        token: &str,
    ) -> Result<AuthContext, o3k_native_api::error::ProblemDetails> {
        match token {
            "operator-token" => Ok(self.operator.clone()),
            "tenant-token" => Ok(self.tenant.clone()),
            _ => Err(o3k_native_api::error::ProblemDetails::unauthorized()),
        }
    }
}

fn auth_context(scope_id: &str, scope_kind: ScopeKind, roles: &[&str]) -> AuthContext {
    AuthContext::new(
        Principal::User(UserPrincipal::new(
            PrincipalId::new_unchecked("user-1"),
            "user-1",
            None,
        )),
        OwnershipScope::new(ScopeId::new_unchecked(scope_id), scope_kind, None, None),
        roles.iter().map(|role| (*role).to_owned()).collect(),
        1,
        2,
        "audit-test",
        "request-test",
        None,
    )
}

fn tenant_auth() -> AuthContext {
    auth_context("project-a", ScopeKind::Project, &["member"])
}

fn instant(unix_ms: i64) -> String {
    chrono::DateTime::from_timestamp_millis(unix_ms)
        .expect("representable instant")
        .to_rfc3339_opts(chrono::SecondsFormat::Millis, true)
}

async fn request(
    app: &axum::Router,
    method: Method,
    uri: &str,
    token: &str,
    body: Option<Value>,
    idempotency_key: Option<&str>,
    content_type: bool,
) -> Result<(StatusCode, String), Box<dyn std::error::Error>> {
    let mut builder = Request::builder()
        .method(method)
        .uri(uri)
        .header(header::AUTHORIZATION, format!("Bearer {token}"));
    if content_type {
        builder = builder.header(header::CONTENT_TYPE, "application/json");
    }
    if let Some(key) = idempotency_key {
        builder = builder.header("idempotency-key", key);
    }
    let body = match body {
        Some(value) => Body::from(serde_json::to_vec(&value)?),
        None => Body::empty(),
    };
    let response = app.clone().oneshot(builder.body(body)?).await?;
    let status = response.status();
    let bytes = axum::body::to_bytes(response.into_body(), 64 * 1024).await?;
    Ok((status, String::from_utf8_lossy(&bytes).into_owned()))
}

async fn get_json(
    app: &axum::Router,
    uri: &str,
    token: &str,
) -> Result<Value, Box<dyn std::error::Error>> {
    let (status, body) = request(app, Method::GET, uri, token, None, None, false).await?;
    assert_eq!(status, StatusCode::OK, "GET {uri}: {body}");
    Ok(serde_json::from_str(&body)?)
}

/// Builds a native-API runtime whose compute service and reader share one
/// metering adapter, with the compute/network/volume controllers ready.
async fn build_runtime(
    store: Arc<O3kStore>,
    adapter: Arc<o3kd::native_adapters::MeteringAdapter>,
) -> Result<axum::Router, Box<dyn std::error::Error>> {
    let provider = Arc::new(FakeComputeProvider::new());
    let compute_service = ComputeService::new_for_test(store.clone(), provider)
        .with_metering_observer(adapter.clone());
    let compute = Arc::new(compute_service);
    let network = Arc::new(
        NetworkService::open_for_test(
            std::env::temp_dir().join(format!("o3k-metering-lifecycle-net-{}", Uuid::new_v4())),
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
        manifests.register_controller(service, controller_session(service, namespace))?;
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
    let application: Arc<dyn ResourceApplication> =
        Arc::new(o3kd::native_adapters::GenericResourceApplication {
            compute: compute.clone(),
            image: None,
            public_address_workflow: None,
            network_service: network,
            realm_deletion: None,
            store: store.clone(),
            storage_provider: Some(Arc::new(InMemoryStorageProvider::default())),
            server: server_reader.clone(),
            network: network_reader.clone(),
            external_controllers: Arc::new(Default::default()),
            public_allocator: None,
            network_external_realm_id: None,
            attachment_workflow: None,
            metering: Some(adapter.clone()),
        });
    let token_issuer: Arc<dyn TokenIssuer> = Arc::new(TestIssuer {
        operator: auth_context("system", ScopeKind::System, &["operator"]),
        tenant: tenant_auth(),
    });
    let native = o3k_native_api::NativeApiState::new(
        Some(manifests),
        CursorConfig::new(b"test-only-native-cursor-key-at-least-32-bytes".to_vec())?,
        Some(token_issuer),
        Some(server_reader),
        None,
        Some(network_reader),
    )?
    .with_resource_application(application)
    .with_metering_reader(adapter)
    .with_authorizer(Arc::new(o3k_kernel::StaticAuthorizer::standard()));
    Ok(o3k_api::router_with_state(
        o3k_api::AppState::new().with_native_api(native),
    ))
}

fn controller_session(service: &str, namespace: &str) -> o3k_kernel::ControllerSession {
    o3k_kernel::ControllerSession {
        service_id: service.to_owned(),
        namespace: namespace.to_owned(),
        service_principal: o3k_kernel::ServicePrincipal::new(
            PrincipalId::new_unchecked(format!("{service}-controller")),
            format!("{service}-controller"),
            namespace,
        ),
        session_id: Uuid::new_v4(),
        session_generation: 1,
        protocol_version: o3k_kernel::ProtocolVersion::new(1, 0),
        manifest_digest: format!("metering-lifecycle-{service}"),
        manifest_generation: 1,
        started_at: "2026-09-11T00:00:00Z".to_owned(),
    }
}

/// Drives create convergence through the real native show path and waits until
/// the durable resource ledger reports the wanted storage state.
async fn converge(
    app: &axum::Router,
    store: &Arc<O3kStore>,
    server_id: &str,
    wanted: &str,
) -> Result<(), Box<dyn std::error::Error>> {
    let id = Uuid::parse_str(server_id)?;
    for _ in 0..400 {
        match store.get_resource(id).await {
            Ok(resource) if resource.observed_state == wanted => return Ok(()),
            Ok(_) => {}
            Err(error) => {
                return Err(format!("resource {server_id} not readable: {error:?}").into());
            }
        }
        // The native read path drives create convergence lazily; ignoring a
        // 404 here is fine because the delete path is synchronous.
        let _ = request(
            app,
            Method::GET,
            &format!("/o3k/v1/compute/servers/{server_id}"),
            "tenant-token",
            None,
            None,
            false,
        )
        .await?;
        tokio::time::sleep(Duration::from_millis(5)).await;
    }
    Err(format!("server {server_id} did not converge to {wanted}").into())
}

fn usage_uri(meter: &str, start_ms: i64, end_ms: i64, scope: Option<&str>) -> String {
    let mut uri = format!(
        "/o3k/v1/metering/usage?meter={meter}&start={}&end={}",
        instant(start_ms),
        instant(end_ms),
    );
    if let Some(scope) = scope {
        uri.push_str("&scope=");
        uri.push_str(scope);
    }
    uri
}

async fn usage_body(
    app: &axum::Router,
    meter: &str,
    token: &str,
    start_ms: i64,
    end_ms: i64,
) -> Result<Value, Box<dyn std::error::Error>> {
    get_json(app, &usage_uri(meter, start_ms, end_ms, None), token).await
}

fn meter_field<'a>(value: &'a Value, field: &str) -> &'a str {
    value[0][field].as_str().unwrap_or_default()
}

/// Creates, stops, starts and deletes a server through the real native API and
/// proves the durable compute meter records exactly the running time, survives
/// a durable-store restart, and stays scope-isolated.
#[tokio::test]
async fn lifecycle_driven_compute_metering_is_exact_and_restart_stable() -> TestResult {
    let path =
        std::env::temp_dir().join(format!("o3k-metering-lifecycle-{}.sqlite", Uuid::new_v4()));
    let meter = "compute:instance_seconds";

    {
        let store = Arc::new(O3kStore::connect_sqlite_file(&path).await?);
        let clock = Arc::new(TestClock::new(BASE_MS));
        let adapter = Arc::new(o3kd::native_adapters::MeteringAdapter::new(
            store.clone(),
            clock.clone(),
        ));
        o3k_kernel::MeteringRepository::ensure_authority(&*store, BASE_MS).await?;
        let app = build_runtime(store.clone(), adapter).await?;

        // 1. create while the fake clock is anchored at the hour boundary.
        clock.set(BASE_MS);
        let (status, body) = request(
            &app,
            Method::POST,
            "/o3k/v1/compute/servers",
            "tenant-token",
            Some(json!({
                "kind": "compute:server",
                "spec": {
                    "name": "meter-srv",
                    "image_id": "image-a",
                    "flavor_id": "00000000-0000-0000-0000-000000000001",
                    "network_ids": ["opaque-network-reference"],
                }
            })),
            Some("meter-srv-create"),
            true,
        )
        .await?;
        assert_eq!(status, StatusCode::CREATED, "{body}");
        let created: Value = serde_json::from_str(&body)?;
        let server_id = created["resource_id"]
            .as_str()
            .ok_or("server resource id")?
            .to_owned();

        // 2. converge to ACTIVE (opens the interval at BASE_MS).
        converge(&app, &store, &server_id, "ACTIVE").await?;

        // 3. 60 s of running time, evaluated at the live instant.
        clock.set(BASE_MS + 60_000);
        let value = usage_body(&app, meter, "tenant-token", BASE_MS, BASE_MS + HOUR_MS).await?;
        assert_eq!(meter_field(&value, "total"), "60.000", "{value}");
        assert_eq!(meter_field(&value, "status"), "partial", "{value}");
        assert_eq!(meter_field(&value, "unit"), "instance_second");
        assert_eq!(value[0]["buckets"][0]["quantity"], "60.000");

        // 4. stop; the interval closes at the stop instant. Evaluated later,
        // the closed total is unchanged, and at the fully evaluated window end
        // the response is complete.
        let (status, body) = request(
            &app,
            Method::POST,
            &format!("/o3k/v1/compute/servers/{server_id}/actions/stop"),
            "tenant-token",
            Some(json!({})),
            Some("meter-srv-stop"),
            true,
        )
        .await?;
        assert!(status.is_success(), "stop: {status} {body}");
        converge(&app, &store, &server_id, "SHUTOFF").await?;
        clock.set(BASE_MS + 90_000);
        let value = usage_body(&app, meter, "tenant-token", BASE_MS, BASE_MS + HOUR_MS).await?;
        assert_eq!(
            meter_field(&value, "total"),
            "60.000",
            "stopped time must not count: {value}"
        );
        clock.set(BASE_MS + HOUR_MS);
        let value = usage_body(&app, meter, "tenant-token", BASE_MS, BASE_MS + HOUR_MS).await?;
        assert_eq!(meter_field(&value, "total"), "60.000", "{value}");
        assert_eq!(meter_field(&value, "status"), "complete", "{value}");

        // 5. start again; only the second running segment accrues. Evaluated at
        // the live instant the second segment is exactly 40 s.
        clock.set(BASE_MS + 90_000);
        let (status, body) = request(
            &app,
            Method::POST,
            &format!("/o3k/v1/compute/servers/{server_id}/actions/start"),
            "tenant-token",
            Some(json!({})),
            Some("meter-srv-start"),
            true,
        )
        .await?;
        assert!(status.is_success(), "start: {status} {body}");
        converge(&app, &store, &server_id, "ACTIVE").await?;
        clock.set(BASE_MS + 130_000);
        let value = usage_body(&app, meter, "tenant-token", BASE_MS, BASE_MS + HOUR_MS).await?;
        assert_eq!(meter_field(&value, "total"), "100.000", "{value}");
        assert_eq!(meter_field(&value, "status"), "partial", "{value}");

        // 6. delete; the second segment closes and later time accrues nothing.
        let (status, body) = request(
            &app,
            Method::DELETE,
            &format!("/o3k/v1/compute/servers/{server_id}"),
            "tenant-token",
            None,
            Some("meter-srv-delete"),
            false,
        )
        .await?;
        assert_eq!(status, StatusCode::NO_CONTENT, "delete: {body}");
        converge(&app, &store, &server_id, "DELETED").await?;
        clock.set(BASE_MS + 190_000);
        let value = usage_body(&app, meter, "tenant-token", BASE_MS, BASE_MS + HOUR_MS).await?;
        assert_eq!(meter_field(&value, "total"), "100.000", "{value}");
        clock.set(BASE_MS + HOUR_MS);
        let value = usage_body(&app, meter, "tenant-token", BASE_MS, BASE_MS + HOUR_MS).await?;
        assert_eq!(meter_field(&value, "total"), "100.000", "{value}");
        assert_eq!(meter_field(&value, "status"), "complete", "{value}");

        // The tenant cannot select another project's scope.
        let (status, _) = request(
            &app,
            Method::GET,
            &usage_uri(meter, BASE_MS, BASE_MS + HOUR_MS, Some("project-b")),
            "tenant-token",
            None,
            None,
            false,
        )
        .await?;
        assert_eq!(status, StatusCode::FORBIDDEN);
    }

    // 7. A fresh process over the same durable store reports the same total:
    // no duplicate interval is opened across the restart.
    {
        let store = Arc::new(O3kStore::connect_sqlite_file(&path).await?);
        let clock = Arc::new(TestClock::new(BASE_MS + HOUR_MS));
        let adapter = Arc::new(o3kd::native_adapters::MeteringAdapter::new(
            store.clone(),
            clock.clone(),
        ));
        let app = build_runtime(store, adapter).await?;
        let (status, body) = request(
            &app,
            Method::GET,
            &usage_uri(meter, BASE_MS, BASE_MS + HOUR_MS, None),
            "tenant-token",
            None,
            None,
            false,
        )
        .await?;
        assert_eq!(status, StatusCode::OK, "{body}");
        for secret in SECRET_MARKERS {
            assert!(
                !body.contains(secret),
                "{secret:?} leaked into a usage body"
            );
        }
        let value: Value = serde_json::from_str(&body)?;
        assert_eq!(value[0]["total"], "100.000");
        assert_eq!(value[0]["status"], "complete");
        assert_eq!(value[0]["unit"], "instance_second");
        assert_eq!(value[0]["aggregation"], "integral");
        for field in ["start", "end", "observed_through"] {
            let text = value[0][field].as_str().ok_or("instant")?;
            assert!(text.ends_with('Z'), "{field} is not UTC: {text}");
            assert!(
                chrono::DateTime::parse_from_rfc3339(text).is_ok(),
                "{field} is not RFC3339: {text}"
            );
        }
    }

    let _ = std::fs::remove_file(&path);
    Ok(())
}

/// Builds a `GenericResourceApplication` over the caller's store with the
/// metering adapter attached, and resolves the canonical volume descriptor.
async fn volume_application(
    store: Arc<O3kStore>,
    adapter: Arc<o3kd::native_adapters::MeteringAdapter>,
    provider: Arc<dyn StorageProvider>,
) -> Result<
    (
        o3k_native_api::resource::ResourceDescriptor,
        Arc<o3kd::native_adapters::GenericResourceApplication>,
    ),
    Box<dyn std::error::Error>,
> {
    let compute = Arc::new(ComputeService::new_for_test(
        store.clone(),
        Arc::new(FakeComputeProvider::new()),
    ));
    let network = Arc::new(
        NetworkService::open_for_test(
            std::env::temp_dir().join(format!("o3k-metering-volume-net-{}", Uuid::new_v4())),
            store.clone(),
        )
        .await?,
    );
    let mut manifests = ManifestRegistry::new();
    manifests.seed_core()?;
    let dispatcher =
        o3k_native_api::resource::ResourceDispatcher::from_manifest_registry(&manifests)
            .map_err(|error| format!("dispatcher: {error:?}"))?;
    let descriptor = dispatcher
        .resolve_resource_type(&ResourceType::new("volume", "volume")?)
        .ok_or("volume:volume descriptor missing")?
        .clone();
    let server_reader: Arc<dyn o3k_native_api::compute::ServerReader> =
        Arc::new(o3kd::native_adapters::ServerReaderAdapter {
            service: compute.clone(),
        });
    let application = Arc::new(o3kd::native_adapters::GenericResourceApplication {
        compute,
        image: None,
        public_address_workflow: None,
        network_service: network,
        realm_deletion: None,
        store: store.clone(),
        storage_provider: Some(provider),
        server: server_reader,
        network: Arc::new(o3kd::native_adapters::NetworkReaderAdapter {
            store: store.clone(),
            authorizer: Arc::new(o3k_kernel::StaticAuthorizer::standard()),
        }),
        external_controllers: Arc::new(Default::default()),
        public_allocator: None,
        network_external_realm_id: None,
        attachment_workflow: None,
        metering: Some(adapter),
    });
    Ok((descriptor, application))
}

fn volume_query(scope: &str, start_ms: i64, end_ms: i64) -> UsageQuery {
    UsageQuery {
        scope: scope.to_owned(),
        meter_keys: vec![o3k_api::VOLUME_ALLOCATION_METER.to_owned()],
        start_ms,
        end_ms,
        granularity: UsageGranularity::Hour,
        resource_id: None,
        // The adapter re-stamps this from its injectable clock.
        evaluated_at_ms: end_ms,
    }
}

async fn volume_report(
    adapter: &Arc<o3kd::native_adapters::MeteringAdapter>,
) -> Result<MeterUsageReport, Box<dyn std::error::Error>> {
    adapter
        .usage(&volume_query("project-a", BASE_MS, BASE_MS + HOUR_MS))
        .await
        .map_err(|error| format!("metering usage: {error:?}").into())
}

fn assert_volume_total(report: &MeterUsageReport, total: &str, status: &str) {
    assert_eq!(report.scope, "project-a");
    assert_eq!(report.meters.len(), 1);
    assert_eq!(report.meters[0].unit.as_str(), "byte_second");
    assert_eq!(report.meters[0].total, total, "{report:?}");
    assert_eq!(report.meters[0].status.as_str(), status, "{report:?}");
}

/// Creates a `volume:volume` through `GenericResourceApplication`.
async fn create_volume(
    application: &Arc<o3kd::native_adapters::GenericResourceApplication>,
    descriptor: &o3k_native_api::resource::ResourceDescriptor,
    key: &str,
) -> Result<String, Box<dyn std::error::Error>> {
    let created = application
        .create(
            descriptor,
            &tenant_auth(),
            ValidatedCreateRequest {
                api_version: Some("o3k.io/v1".into()),
                kind: Some("volume:volume".into()),
                spec: ValidatedSpec::from_external_contract(json!({
                    "size_bytes": VOLUME_SIZE_BYTES,
                    "volume_type": "standard",
                })),
            },
            Some(key),
        )
        .await
        .map_err(|error| format!("volume create: {error:?}"))?;
    assert!(
        created.complete,
        "volume create must be durable: {created:?}"
    );
    created
        .resource_id
        .ok_or_else(|| "volume resource id".into())
}

/// Proves `GenericResourceApplication` opens the volume allocation meter on a
/// durable create, closes it on delete, and a replayed delete does not double
/// count.
#[tokio::test]
async fn volume_allocation_meter_is_exact_and_replay_safe() -> TestResult {
    let store = Arc::new(O3kStore::connect_sqlite_memory().await?);
    o3k_kernel::MeteringRepository::ensure_authority(&*store, BASE_MS).await?;
    let clock = Arc::new(TestClock::new(BASE_MS));
    let adapter = Arc::new(o3kd::native_adapters::MeteringAdapter::new(
        store.clone(),
        clock.clone(),
    ));
    let provider: Arc<dyn StorageProvider> = Arc::new(InMemoryStorageProvider::default());
    let (descriptor, application) = volume_application(store, adapter.clone(), provider).await?;

    clock.set(BASE_MS);
    let volume_id = create_volume(&application, &descriptor, "meter-volume-create").await?;

    // 60 s of allocated capacity, evaluated at the live instant:
    // size_bytes x 60 byte-seconds.
    clock.set(BASE_MS + 60_000);
    let report = volume_report(&adapter).await?;
    assert_volume_total(&report, "60000000.000", "partial");

    // Delete closes the interval at the delete instant.
    clock.set(BASE_MS + 60_000);
    let deleted = application
        .delete(
            &descriptor,
            &tenant_auth(),
            &volume_id,
            Some("meter-volume-delete"),
            None,
        )
        .await
        .map_err(|error| format!("volume delete: {error:?}"))?;
    assert!(
        deleted.complete,
        "volume delete must be durable: {deleted:?}"
    );
    clock.set(BASE_MS + HOUR_MS);
    let report = volume_report(&adapter).await?;
    assert_volume_total(&report, "60000000.000", "complete");

    // A replayed delete is an idempotent close: no double count, no corruption.
    let replay = application
        .delete(
            &descriptor,
            &tenant_auth(),
            &volume_id,
            Some("meter-volume-delete"),
            None,
        )
        .await
        .map_err(|error| format!("volume delete replay: {error:?}"))?;
    assert!(
        replay.complete,
        "replayed delete must stay complete: {replay:?}"
    );
    assert_eq!(
        replay.resource_id.as_deref(),
        Some(volume_id.as_str()),
        "replayed delete must address the same volume"
    );
    clock.set(BASE_MS + 2 * HOUR_MS);
    let report = volume_report(&adapter).await?;
    assert_volume_total(&report, "60000000.000", "complete");
    Ok(())
}

/// Proves `o3k_api::recover_native_volumes` closes the allocation interval left
/// open by an interrupted delete: usage up to the close instant is preserved
/// and later time accrues nothing.
#[tokio::test]
async fn recovery_closes_interrupted_volume_delete() -> TestResult {
    let store = Arc::new(O3kStore::connect_sqlite_memory().await?);
    o3k_kernel::MeteringRepository::ensure_authority(&*store, BASE_MS).await?;
    let clock = Arc::new(TestClock::new(BASE_MS));
    let adapter = Arc::new(o3kd::native_adapters::MeteringAdapter::new(
        store.clone(),
        clock.clone(),
    ));
    let provider: Arc<dyn StorageProvider> = Arc::new(InMemoryStorageProvider::default());
    let (descriptor, application) =
        volume_application(store.clone(), adapter.clone(), provider.clone()).await?;

    // Create the volume (opens the allocation interval at BASE_MS).
    clock.set(BASE_MS);
    let volume_id = Uuid::parse_str(
        &create_volume(&application, &descriptor, "recovery-volume-create").await?,
    )?;

    // Model the delete path up to the point it crashed: the provider volume is
    // gone and the canonical row is durably `Deleting`, but the close
    // observation never happened.
    clock.set(BASE_MS + 90_000);
    o3k_api::remove_native_volume(
        store.clone(),
        provider.clone(),
        "project-a",
        volume_id,
        None,
        // Model the crash window: the provider deletion happened but the close
        // observation did not, so recovery must close the interval.
        None,
    )
    .await
    .map_err(|error| format!("remove_native_volume: {error}"))?;
    let deleting = store
        .get_volume(volume_id)
        .await?
        .ok_or("volume row missing after removal step")?;
    assert_eq!(deleting.volume.state, o3k_domain::VolumeState::Deleting);
    assert!(
        provider
            .inspect_volume(&o3k_storage::StorageVolumeRequest {
                volume_id: deleting.volume.id,
                project_id: deleting.volume.project_id.clone(),
                size_bytes: deleting.volume.size_bytes,
                generation: deleting.volume.generation,
            })
            .await
            .is_err(),
        "the provider volume must be absent so recovery observes NotFound"
    );

    // Recovery observes provider absence and closes the interval.
    let state = o3k_api::AppState::new()
        .with_storage_store(store.clone())
        .with_storage_provider(provider.clone())
        .with_metering_observer(adapter.clone());
    o3k_api::recover_native_volumes(&state).await;
    assert!(
        store.get_volume(volume_id).await?.is_none(),
        "recovery must finalize the durable delete"
    );

    // Usage up to the close instant (90 s) is preserved; later time accrues
    // nothing.
    clock.set(BASE_MS + HOUR_MS);
    let report = volume_report(&adapter).await?;
    assert_volume_total(&report, "90000000.000", "complete");
    Ok(())
}

// ── F1: the Cinder-compatible volume surface observes the allocation meter ──

/// Project id used by the Cinder-compatible `/v3/{project_id}/volumes` routes.
const CINDER_PROJECT: &str = "metering-cinder-project";

/// Builds the Cinder-compatible runtime: real router, real in-memory store,
/// real provider, and the real metering adapter installed as the recovery /
/// volume observer.
async fn cinder_runtime(
    store: Arc<O3kStore>,
    adapter: Arc<o3kd::native_adapters::MeteringAdapter>,
) -> Result<axum::Router, Box<dyn std::error::Error>> {
    let identity = o3k_identity::testkit::test_service_with_projects(
        "http://127.0.0.1:8080",
        vec![o3k_identity::ExtraProjectSeed {
            project_id: CINDER_PROJECT.to_owned(),
            project_name: CINDER_PROJECT.to_owned(),
            user_id: "cinder-user".to_owned(),
            user_name: "cinder-user".to_owned(),
            password: o3k_identity::Secret::new("cinder-password".to_owned()),
        }],
    )
    .await?;
    let provider: Arc<dyn StorageProvider> = Arc::new(InMemoryStorageProvider::default());
    let state = o3k_api::AppState::new()
        .with_identity(identity)
        .with_storage_store(store)
        .with_storage_provider(provider)
        .with_metering_observer(adapter);
    state.set_ready(true);
    Ok(o3k_api::router_with_state(state))
}

async fn keystone_token(
    app: &axum::Router,
    user: &str,
    password: &str,
    project: &str,
) -> Result<String, Box<dyn std::error::Error>> {
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

/// A request against the Keystone-compatible surface, which authenticates with
/// `x-auth-token` rather than the native bearer header.
async fn cinder_request(
    app: &axum::Router,
    method: Method,
    uri: &str,
    token: &str,
    body: Option<Value>,
) -> Result<(StatusCode, String), Box<dyn std::error::Error>> {
    let mut builder = Request::builder()
        .method(method)
        .uri(uri)
        .header("x-auth-token", token);
    let body = match body {
        Some(value) => {
            builder = builder.header(header::CONTENT_TYPE, "application/json");
            Body::from(serde_json::to_vec(&value)?)
        }
        None => Body::empty(),
    };
    let response = app.clone().oneshot(builder.body(body)?).await?;
    let status = response.status();
    let bytes = axum::body::to_bytes(response.into_body(), 64 * 1024).await?;
    Ok((status, String::from_utf8_lossy(&bytes).into_owned()))
}

/// F1 regression: a volume durably created by the Cinder-compatible
/// `/v3/{project_id}/volumes` handler opens the allocation meter, and one
/// removed by `/v3/{project_id}/volumes/{id}` closes it. The observation now
/// lives in the canonical `realize_native_volume_create` /
/// `remove_native_volume` functions, so this surface is covered even though it
/// never touches the native adapter.
#[tokio::test]
async fn cinder_volume_lifecycle_opens_and_closes_the_allocation_meter() -> TestResult {
    let store = Arc::new(O3kStore::connect_sqlite_memory().await?);
    o3k_kernel::MeteringRepository::ensure_authority(&*store, BASE_MS).await?;
    let clock = Arc::new(TestClock::new(BASE_MS));
    let adapter = Arc::new(o3kd::native_adapters::MeteringAdapter::new(
        store.clone(),
        clock.clone(),
    ));
    let app = cinder_runtime(store.clone(), adapter.clone()).await?;
    let token = keystone_token(&app, "cinder-user", "cinder-password", CINDER_PROJECT).await?;

    // Cinder `size` is GiB; 1 GiB of allocated capacity.
    const CINDER_SIZE_BYTES: u64 = 1024 * 1024 * 1024;
    let expected_total = format!("{}.000", CINDER_SIZE_BYTES * 60);
    clock.set(BASE_MS);
    let (status, body) = cinder_request(
        &app,
        Method::POST,
        &format!("/v3/{CINDER_PROJECT}/volumes"),
        &token,
        Some(json!({"volume": {"size": 1, "name": "metered-cinder"}})),
    )
    .await?;
    assert_eq!(status, StatusCode::ACCEPTED, "{body}");
    let created: Value = serde_json::from_str(&body)?;
    let volume_id = created["volume"]["id"]
        .as_str()
        .ok_or("cinder volume id")?
        .to_owned();

    // The Cinder create opened the meter at BASE_MS.
    clock.set(BASE_MS + 60_000);
    let report = adapter
        .usage(&volume_query(CINDER_PROJECT, BASE_MS, BASE_MS + HOUR_MS))
        .await
        .map_err(|error| format!("metering usage: {error:?}"))?;
    assert_eq!(report.meters.len(), 1);
    assert_eq!(report.meters[0].unit.as_str(), "byte_second");
    assert_eq!(report.meters[0].total, expected_total, "{report:?}");

    // The Cinder delete closes it at the delete instant.
    clock.set(BASE_MS + 60_000);
    let (status, body) = cinder_request(
        &app,
        Method::DELETE,
        &format!("/v3/{CINDER_PROJECT}/volumes/{volume_id}"),
        &token,
        None,
    )
    .await?;
    assert_eq!(status, StatusCode::NO_CONTENT, "{body}");
    assert!(
        store
            .get_volume(Uuid::parse_str(&volume_id)?)
            .await?
            .is_none(),
        "the Cinder delete must remove the canonical row"
    );
    clock.set(BASE_MS + HOUR_MS);
    let report = adapter
        .usage(&volume_query(CINDER_PROJECT, BASE_MS, BASE_MS + HOUR_MS))
        .await
        .map_err(|error| format!("metering usage: {error:?}"))?;
    assert_eq!(report.meters[0].total, expected_total, "{report:?}");
    assert_eq!(report.meters[0].status.as_str(), "complete");
    Ok(())
}

// ── F2: recovery defers its mutation when the projection fails ─────────────

/// Observer that always fails, standing in for an unavailable metering
/// authority during recovery. It counts attempts so the test can prove the
/// projection was attempted (and rejected) rather than bypassed.
#[derive(Default)]
struct FailingMeteringObserver {
    attempts: std::sync::atomic::AtomicUsize,
}

impl FailingMeteringObserver {
    fn attempts(&self) -> usize {
        self.attempts.load(Ordering::SeqCst)
    }
}

#[async_trait::async_trait]
impl o3k_kernel::LifecycleMeteringObserver for FailingMeteringObserver {
    async fn observe_resource_state(
        &self,
        _kind: &str,
        _project_id: &str,
        _resource_id: &str,
        _observed_state: &str,
    ) -> Result<(), o3k_kernel::KernelError> {
        self.attempts.fetch_add(1, Ordering::SeqCst);
        Err(o3k_kernel::KernelError::MeteringUnavailable(
            "injected failure".to_owned(),
        ))
    }

    async fn observe_allocation(
        &self,
        _meter_key: &str,
        _project_id: &str,
        _resource_id: &str,
        _quantity: u64,
        _consuming: bool,
    ) -> Result<(), o3k_kernel::KernelError> {
        self.attempts.fetch_add(1, Ordering::SeqCst);
        Err(o3k_kernel::KernelError::MeteringUnavailable(
            "injected failure".to_owned(),
        ))
    }
}

async fn insert_volume_row(
    store: &Arc<O3kStore>,
    id: Uuid,
    project: &str,
    size_bytes: u64,
    state: o3k_domain::VolumeState,
    generation: u64,
) -> Result<(), Box<dyn std::error::Error>> {
    store
        .insert_volume(&o3k_store::VolumeRecord {
            volume: o3k_domain::Volume {
                id: o3k_domain::VolumeId::from_uuid(id),
                project_id: project.to_owned(),
                name: "recovery-test".to_owned(),
                description: String::new(),
                metadata: Default::default(),
                availability_zone: None,
                size_bytes,
                volume_type: "standard".to_owned(),
                backend_id: "local".to_owned(),
                execution_scope: o3k_domain::StorageExecutionScope::Host("local".to_owned()),
                state,
                generation,
                operation_id: None,
                provider_reference: None,
            },
            created_at: "2026-09-11T00:00:00.000".to_owned(),
        })
        .await?;
    Ok(())
}

/// F2 regression: when the metering projection fails, recovery must not mutate
/// the row. The row stays in its pre-recovery state so the next startup
/// re-observes the same idempotent transition instead of losing it forever.
#[tokio::test]
async fn recovery_defers_mutation_when_metering_projection_fails() -> TestResult {
    let store = Arc::new(O3kStore::connect_sqlite_memory().await?);
    let provider: Arc<dyn StorageProvider> = Arc::new(InMemoryStorageProvider::default());

    // A volume the provider already owns: recovery would move it to Available.
    let creating_id = Uuid::new_v4();
    provider
        .create_volume(&o3k_storage::StorageVolumeRequest {
            volume_id: o3k_domain::VolumeId::from_uuid(creating_id),
            project_id: "project-a".to_owned(),
            size_bytes: VOLUME_SIZE_BYTES,
            generation: 2,
        })
        .await?;
    insert_volume_row(
        &store,
        creating_id,
        "project-a",
        VOLUME_SIZE_BYTES,
        o3k_domain::VolumeState::Creating,
        2,
    )
    .await?;

    // A volume the provider no longer owns: recovery would finalize its delete.
    let deleting_id = Uuid::new_v4();
    insert_volume_row(
        &store,
        deleting_id,
        "project-a",
        VOLUME_SIZE_BYTES,
        o3k_domain::VolumeState::Deleting,
        2,
    )
    .await?;

    let observer = Arc::new(FailingMeteringObserver::default());
    let state = o3k_api::AppState::new()
        .with_storage_store(store.clone())
        .with_storage_provider(provider.clone())
        .with_metering_observer(observer.clone());
    o3k_api::recover_native_volumes(&state).await;

    assert!(
        observer.attempts() >= 2,
        "recovery must attempt each projection before deciding to mutate"
    );
    assert_eq!(
        store
            .get_volume(creating_id)
            .await?
            .ok_or("creating row missing")?
            .volume
            .state,
        o3k_domain::VolumeState::Creating,
        "a failed open projection must not recover the row to Available"
    );
    assert_eq!(
        store
            .get_volume(deleting_id)
            .await?
            .ok_or("deleting row missing")?
            .volume
            .state,
        o3k_domain::VolumeState::Deleting,
        "a failed close projection must not finalize the delete"
    );
    Ok(())
}

// ── F7: capability-hiding of non-producible meters ─────────────────────────

fn definition_keys(value: &Value) -> Vec<String> {
    value["definitions"]
        .as_array()
        .map(|definitions| {
            definitions
                .iter()
                .filter_map(|definition| definition["key"].as_str().map(str::to_owned))
                .collect()
        })
        .unwrap_or_default()
}

/// F7 regression: the catalog is filtered to the meters this composition can
/// actually produce, and a request for a non-producible meter is an unknown
/// meter (400), never a zero reading.
#[tokio::test]
async fn meter_capability_hiding_filters_definitions_and_rejects_usage() -> TestResult {
    let store = Arc::new(O3kStore::connect_sqlite_memory().await?);
    o3k_kernel::MeteringRepository::ensure_authority(&*store, BASE_MS).await?;
    let clock = Arc::new(TestClock::new(BASE_MS));
    let compute_meter = o3kd::native_adapters::metering::COMPUTE_INSTANCE_METER;

    // Current composition (native storage provider configured): both meters.
    let both = Arc::new(
        o3kd::native_adapters::MeteringAdapter::new(store.clone(), clock.clone())
            .with_producible_meters(o3kd::native_adapters::metering::producible_meters(
                true, true,
            )),
    );
    let app = build_runtime(store.clone(), both).await?;
    let value = get_json(&app, "/o3k/v1/metering/definitions", "tenant-token").await?;
    let keys = definition_keys(&value);
    assert!(keys.iter().any(|key| key == compute_meter), "{value}");
    assert!(
        keys.iter()
            .any(|key| key == o3k_api::VOLUME_ALLOCATION_METER),
        "{value}"
    );

    // No native storage provider: the volume meter is hidden.
    let compute_only = Arc::new(
        o3kd::native_adapters::MeteringAdapter::new(store.clone(), clock.clone())
            .with_producible_meters(o3kd::native_adapters::metering::producible_meters(
                true, false,
            )),
    );
    let app = build_runtime(store.clone(), compute_only).await?;
    let value = get_json(&app, "/o3k/v1/metering/definitions", "tenant-token").await?;
    let keys = definition_keys(&value);
    assert!(keys.iter().any(|key| key == compute_meter), "{value}");
    assert!(
        !keys
            .iter()
            .any(|key| key == o3k_api::VOLUME_ALLOCATION_METER),
        "a non-producible meter must not be advertised: {value}"
    );

    let (status, body) = request(
        &app,
        Method::GET,
        &usage_uri(
            o3k_api::VOLUME_ALLOCATION_METER,
            BASE_MS,
            BASE_MS + HOUR_MS,
            None,
        ),
        "tenant-token",
        None,
        None,
        false,
    )
    .await?;
    assert_eq!(
        status,
        StatusCode::BAD_REQUEST,
        "a non-producible meter is unknown, never zero usage: {body}"
    );
    Ok(())
}
