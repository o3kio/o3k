//! Read-path repair of the canonical native volume allocation meter (HQ2).
//!
//! A native volume create commits the durable `Available` row before it
//! projects the open observation. If that projection fails the create response
//! degrades while the row already exists, and because the Cinder create path
//! mints a fresh UUID per attempt a client retry never replays it. This test
//! proves the read path repairs the lost open from durable truth and that
//! later elapsed time then accrues.

use async_trait::async_trait;
use axum::{
    body::Body,
    http::{Method, Request, StatusCode},
};
use o3k_api::AppState;
use o3k_compute::ComputeService;
use o3k_domain::{
    StorageCapabilities, StorageExecutionScope, StorageProviderReference, Volume, VolumeId,
    VolumeState,
};
use o3k_identity::{BootstrapConfig, Secret, TokenService};
use o3k_kernel::{
    KernelError, LifecycleMeteringObserver, MeterObservation, MeterUsageReport, MeteringRepository,
    UsageGranularity, UsageQuery,
};
use o3k_provider::FakeComputeProvider;
use o3k_storage::{
    PreparedAttachment, StorageAttachmentObservation, StorageAttachmentRequest, StorageProvider,
    StorageProviderError, StorageSnapshotObservation, StorageSnapshotRequest,
    StorageVolumeObservation, StorageVolumeRequest,
};
use o3k_store::{StorageRepository, VolumeRecord, testkit::TestStore};
use std::{
    collections::BTreeMap,
    sync::{
        Arc, Mutex,
        atomic::{AtomicBool, AtomicI64, Ordering},
    },
    time::Duration,
};
use tower::ServiceExt;
use uuid::Uuid;

const PROJECT: &str = "eba29e2d-53de-461d-ae91-ede7402713cb";
const BASE_MS: i64 = 1_699_999_200_000; // 2023-11-14T22:00:00Z, an hour boundary.
const HOUR_MS: i64 = 3_600_000;

#[derive(Default)]
struct RepairProvider {
    volumes: Mutex<BTreeMap<Uuid, StorageVolumeObservation>>,
}

struct TestNativeWorkflow {
    store: Arc<TestStore>,
    provider: Arc<RepairProvider>,
    meter: Arc<dyn LifecycleMeteringObserver>,
}

#[async_trait]
impl o3k_api::NativeVolumeWorkflow for TestNativeWorkflow {
    async fn create(&self, volume_id: Uuid) -> Result<(), String> {
        let record = self
            .store
            .get_volume(volume_id)
            .await
            .map_err(|e| e.to_string())?
            .ok_or("missing volume")?;
        let record = o3k_api::realize_native_volume_create(
            self.store.clone(),
            self.provider.clone(),
            record,
            Some(&self.meter),
        )
        .await?;
        let _ = record;
        Ok(())
    }
    async fn delete(&self, project_id: &str, volume_id: Uuid) -> Result<(), String> {
        o3k_api::remove_native_volume(
            self.store.clone(),
            self.provider.clone(),
            project_id,
            volume_id,
            None,
            Some(&self.meter),
        )
        .await
    }
    async fn recover(&self) -> Result<(), String> {
        Ok(())
    }
}

#[async_trait]
impl StorageProvider for RepairProvider {
    async fn capabilities(&self) -> Result<StorageCapabilities, StorageProviderError> {
        Err(StorageProviderError::InvalidRequest)
    }

    async fn create_volume(
        &self,
        request: &StorageVolumeRequest,
    ) -> Result<StorageVolumeObservation, StorageProviderError> {
        let observation = StorageVolumeObservation {
            provider_reference: StorageProviderReference {
                provider: "test".into(),
                resource_id: format!("volume-{}", request.volume_id),
            },
            size_bytes: request.size_bytes,
            owned: true,
            available: true,
        };
        self.volumes
            .lock()
            .map_err(|_| StorageProviderError::CommandFailed)?
            .insert(request.volume_id.as_uuid(), observation.clone());
        Ok(observation)
    }

    async fn inspect_volume(
        &self,
        request: &StorageVolumeRequest,
    ) -> Result<StorageVolumeObservation, StorageProviderError> {
        self.volumes
            .lock()
            .map_err(|_| StorageProviderError::CommandFailed)?
            .get(&request.volume_id.as_uuid())
            .cloned()
            .ok_or(StorageProviderError::NotFound)
    }

    async fn delete_volume(
        &self,
        request: &StorageVolumeRequest,
    ) -> Result<(), StorageProviderError> {
        self.volumes
            .lock()
            .map_err(|_| StorageProviderError::CommandFailed)?
            .remove(&request.volume_id.as_uuid())
            .map(|_| ())
            .ok_or(StorageProviderError::NotFound)
    }

    async fn prepare_attachment(
        &self,
        request: &StorageAttachmentRequest,
    ) -> Result<PreparedAttachment, StorageProviderError> {
        PreparedAttachment::from_provider(
            StorageProviderReference {
                provider: "test".into(),
                resource_id: format!("volume-{}", request.volume_id),
            },
            "/dev/test".into(),
            request.attachment_id,
            request.volume_id,
        )
    }

    async fn inspect_attachment(
        &self,
        request: &StorageAttachmentRequest,
    ) -> Result<StorageAttachmentObservation, StorageProviderError> {
        Ok(StorageAttachmentObservation {
            attachment_id: request.attachment_id,
            volume_id: request.volume_id,
            host_id: "test".into(),
            attached: false,
            provider_reference: StorageProviderReference {
                provider: "test".into(),
                resource_id: format!("volume-{}", request.volume_id),
            },
        })
    }

    async fn terminate_attachment(
        &self,
        request: &StorageAttachmentRequest,
    ) -> Result<StorageAttachmentObservation, StorageProviderError> {
        self.inspect_attachment(request).await
    }

    async fn create_snapshot(
        &self,
        _request: &StorageSnapshotRequest,
    ) -> Result<StorageSnapshotObservation, StorageProviderError> {
        Err(StorageProviderError::InvalidRequest)
    }

    async fn delete_snapshot(
        &self,
        _request: &StorageSnapshotRequest,
    ) -> Result<(), StorageProviderError> {
        Err(StorageProviderError::InvalidRequest)
    }
}

/// Lifecycle observer that forwards volume allocations to the real metering
/// authority and can be toggled to fail, so a test can prove the read path
/// repairs a lost projection. `observe_resource_state` is unused by volumes.
struct ToggleVolumeMeter {
    store: Arc<TestStore>,
    now_ms: Arc<AtomicI64>,
    failing: Arc<AtomicBool>,
}

impl ToggleVolumeMeter {
    fn new(store: Arc<TestStore>, now_ms: i64) -> Self {
        Self {
            store,
            now_ms: Arc::new(AtomicI64::new(now_ms)),
            failing: Arc::new(AtomicBool::new(false)),
        }
    }

    fn set_failing(&self, failing: bool) {
        self.failing.store(failing, Ordering::SeqCst);
    }

    fn set_now(&self, now_ms: i64) {
        self.now_ms.store(now_ms, Ordering::SeqCst);
    }
}

#[async_trait]
impl LifecycleMeteringObserver for ToggleVolumeMeter {
    async fn observe_resource_state(
        &self,
        _kind: &str,
        _project_id: &str,
        _resource_id: &str,
        _observed_state: &str,
    ) -> Result<(), KernelError> {
        Ok(())
    }

    async fn observe_allocation(
        &self,
        meter_key: &str,
        project_id: &str,
        resource_id: &str,
        quantity: u64,
        consuming: bool,
    ) -> Result<(), KernelError> {
        if self.failing.load(Ordering::SeqCst) {
            return Err(KernelError::MeteringUnavailable("observer failing".into()));
        }
        self.store
            .record_observation(&MeterObservation {
                meter_key: meter_key.to_owned(),
                scope: project_id.to_owned(),
                resource_id: resource_id.to_owned(),
                quantity: if consuming { quantity } else { 0 },
                consuming,
                observed_at_ms: self.now_ms.load(Ordering::SeqCst),
                authority: "test-lifecycle".to_owned(),
            })
            .await
    }
}

async fn store() -> Result<Arc<TestStore>, Box<dyn std::error::Error>> {
    let store = Arc::new(o3k_store::testkit::open_memory().await?);
    o3k_identity::seed_identity_defaults(
        store.as_ref(),
        &BootstrapConfig {
            catalog_endpoint: "http://127.0.0.1:18090".into(),
            bootstrap_password: Secret::new("password".into()),
            cinder_password: None,
            cinder_endpoint: None,
            pbkdf2_iterations: 1_000,
            extra_projects: vec![],
        },
    )
    .await?;
    Ok(store)
}

async fn token(app: &axum::Router) -> Result<String, Box<dyn std::error::Error>> {
    let body = serde_json::json!({"auth":{"identity":{"methods":["password"],"password":{"user":{"name":"admin","password":"password"}}},"scope":{"project":{"name":"admin"}}}});
    let response = app
        .clone()
        .oneshot(
            Request::builder()
                .method(Method::POST)
                .uri("/v3/auth/tokens")
                .header("content-type", "application/json")
                .body(Body::from(body.to_string()))?,
        )
        .await?;
    Ok(response
        .headers()
        .get("x-subject-token")
        .ok_or("missing token")?
        .to_str()?
        .to_owned())
}

#[tokio::test]
async fn lost_open_observation_is_repaired_by_the_next_volume_read()
-> Result<(), Box<dyn std::error::Error>> {
    let store = store().await?;
    store.ensure_authority(BASE_MS).await?;
    let identity = TokenService::load(
        store.clone(),
        Secret::new("a-secure-signing-key-with-at-least-32-bytes".into()),
        Duration::from_secs(3600),
    )
    .await?;
    let compute = ComputeService::new_for_test(store.clone(), Arc::new(FakeComputeProvider::new()));
    let meter = Arc::new(ToggleVolumeMeter::new(store.clone(), BASE_MS));
    let workflow = Arc::new(TestNativeWorkflow {
        store: store.clone(),
        provider: Arc::new(RepairProvider::default()),
        meter: meter.clone(),
    });
    let state = AppState::new()
        .with_identity(identity)
        .with_compute(compute)
        .with_storage_store(store.clone())
        .with_storage_provider(Arc::new(RepairProvider::default()))
        .with_metering_observer(meter.clone())
        .with_native_volume_workflow(workflow);
    state.set_ready(true);
    let app = o3k_api::router_with_state(state);
    let auth = token(&app).await?;

    // Metering is unhappy: the durable `Available` transition still commits but
    // the create response degrades.
    meter.set_failing(true);
    let create = app
        .clone()
        .oneshot(
            Request::builder()
                .method(Method::POST)
                .uri(format!("/v3/{PROJECT}/volumes"))
                .header("x-auth-token", &auth)
                .header("content-type", "application/json")
                .body(Body::from(
                    serde_json::json!({"volume":{"size":1,"name":"repair"}}).to_string(),
                ))?,
        )
        .await?;
    assert_eq!(create.status(), StatusCode::SERVICE_UNAVAILABLE);

    // The canonical row exists and is `Available`: the open was lost.
    let records = store.list_volumes(PROJECT).await?;
    assert_eq!(records.len(), 1);
    assert_eq!(records[0].volume.state, VolumeState::Available);
    let volume_id = records[0].volume.id.to_string();
    let size_bytes = records[0].volume.size_bytes;
    assert!(size_bytes > 0);

    // Recover metering and read the volume: the read path repairs the open from
    // durable truth.
    meter.set_failing(false);
    let show = app
        .clone()
        .oneshot(
            Request::builder()
                .method(Method::GET)
                .uri(format!("/v3/{PROJECT}/volumes/{volume_id}"))
                .header("x-auth-token", &auth)
                .body(Body::empty())?,
        )
        .await?;
    assert_eq!(show.status(), StatusCode::OK);

    // The interval is open at BASE_MS; later elapsed time accrues.
    meter.set_now(BASE_MS + HOUR_MS / 2);
    let report = store
        .usage(&UsageQuery {
            scope: PROJECT.to_owned(),
            meter_keys: vec![o3k_api::VOLUME_ALLOCATION_METER.to_owned()],
            start_ms: BASE_MS,
            end_ms: BASE_MS + HOUR_MS,
            granularity: UsageGranularity::Hour,
            resource_id: None,
            evaluated_at_ms: BASE_MS + HOUR_MS / 2,
        })
        .await?;
    assert_eq!(report.meters.len(), 1);
    assert_ne!(
        report.meters[0].total, "0.000",
        "the repaired open interval must accrue elapsed time"
    );
    Ok(())
}

#[tokio::test]
async fn volume_state_consumes_matches_the_canonical_mapping() {
    for state in [
        VolumeState::Creating,
        VolumeState::Available,
        VolumeState::Attaching,
        VolumeState::InUse,
        VolumeState::Detaching,
        VolumeState::Unknown,
    ] {
        assert!(o3k_api::volume_state_consumes(state), "{state:?}");
    }
    for state in [
        VolumeState::Requested,
        VolumeState::Deleting,
        VolumeState::Deleted,
        VolumeState::Error,
    ] {
        assert!(!o3k_api::volume_state_consumes(state), "{state:?}");
    }
}

async fn volume_usage(
    store: &TestStore,
    evaluated_at_ms: i64,
) -> Result<MeterUsageReport, Box<dyn std::error::Error>> {
    Ok(store
        .usage(&UsageQuery {
            scope: PROJECT.to_owned(),
            meter_keys: vec![o3k_api::VOLUME_ALLOCATION_METER.to_owned()],
            start_ms: BASE_MS,
            end_ms: BASE_MS + HOUR_MS,
            granularity: UsageGranularity::Hour,
            resource_id: None,
            evaluated_at_ms,
        })
        .await?)
}

/// R1: a read of a durably `Deleting` volume must not close its open interval.
/// The repair only opens/refreshes consuming states, so the read leaves the
/// interval accruing and only the authoritative provider-absence close ends it.
#[tokio::test]
async fn deleting_volume_read_does_not_close_the_open_interval()
-> Result<(), Box<dyn std::error::Error>> {
    let store = store().await?;
    store.ensure_authority(BASE_MS).await?;
    let identity = TokenService::load(
        store.clone(),
        Secret::new("a-secure-signing-key-with-at-least-32-bytes".into()),
        Duration::from_secs(3600),
    )
    .await?;
    let compute = ComputeService::new_for_test(store.clone(), Arc::new(FakeComputeProvider::new()));
    let provider = Arc::new(RepairProvider::default());
    let meter = Arc::new(ToggleVolumeMeter::new(store.clone(), BASE_MS));
    let workflow = Arc::new(TestNativeWorkflow {
        store: store.clone(),
        provider: provider.clone(),
        meter: meter.clone(),
    });
    let state = AppState::new()
        .with_identity(identity)
        .with_compute(compute)
        .with_storage_store(store.clone())
        .with_storage_provider(provider.clone())
        .with_metering_observer(meter.clone())
        .with_native_volume_workflow(workflow);
    state.set_ready(true);
    let app = o3k_api::router_with_state(state);
    let auth = token(&app).await?;

    // A successful create opens the interval at BASE_MS.
    let create = app
        .clone()
        .oneshot(
            Request::builder()
                .method(Method::POST)
                .uri(format!("/v3/{PROJECT}/volumes"))
                .header("x-auth-token", &auth)
                .header("content-type", "application/json")
                .body(Body::from(
                    serde_json::json!({"volume":{"size":1,"name":"deleting"}}).to_string(),
                ))?,
        )
        .await?;
    assert_eq!(create.status(), StatusCode::ACCEPTED);
    let records = store.list_volumes(PROJECT).await?;
    assert_eq!(records.len(), 1);
    let record = records[0].clone();
    let volume_id = record.volume.id.to_string();

    // Make the row durably `Deleting` while the provider still holds the volume,
    // so the interval is open and no authoritative close has happened.
    let mut deleting = record.clone();
    deleting.volume.state = VolumeState::Deleting;
    deleting.volume.generation = record
        .volume
        .generation
        .checked_add(1)
        .ok_or("volume generation overflow")?;
    store
        .update_volume(record.volume.generation, &deleting)
        .await?;

    let before = volume_usage(&store, BASE_MS + 600_000).await?.meters[0]
        .total
        .clone();
    assert_ne!(before, "0.000");

    // Reading the Deleting volume must not close the interval.
    let show = app
        .clone()
        .oneshot(
            Request::builder()
                .method(Method::GET)
                .uri(format!("/v3/{PROJECT}/volumes/{volume_id}"))
                .header("x-auth-token", &auth)
                .body(Body::empty())?,
        )
        .await?;
    assert_eq!(show.status(), StatusCode::OK);
    let after_read = volume_usage(&store, BASE_MS + 600_000).await?.meters[0]
        .total
        .clone();
    assert_eq!(
        before, after_read,
        "a read must not close (or alter) a Deleting volume's open interval"
    );

    // The interval is still open and keeps accruing.
    let later = volume_usage(&store, BASE_MS + 1_800_000).await?.meters[0]
        .total
        .clone();
    assert_ne!(
        later, after_read,
        "the interval must keep accruing after the read"
    );

    // The authoritative provider-absence close ends it at BASE_MS + 30min.
    meter.set_now(BASE_MS + 1_800_000);
    let repo: Arc<dyn StorageRepository> = store.clone();
    let provider_dyn: Arc<dyn StorageProvider> = provider.clone();
    let observer: Arc<dyn LifecycleMeteringObserver> = meter.clone();
    o3k_api::remove_native_volume(
        repo,
        provider_dyn,
        PROJECT,
        record.volume.id.as_uuid(),
        None,
        Some(&observer),
    )
    .await
    .map_err(|error| -> Box<dyn std::error::Error> { error.into() })?;

    // A closed interval no longer accrues: the total at the close instant and
    // the total evaluated later are identical.
    let closed_at = volume_usage(&store, BASE_MS + 1_800_000).await?.meters[0]
        .total
        .clone();
    let much_later = volume_usage(&store, BASE_MS + HOUR_MS).await?.meters[0]
        .total
        .clone();
    assert_eq!(
        closed_at, much_later,
        "the authoritative close must stop further accrual"
    );
    Ok(())
}

fn volume_record(state: VolumeState, id: Uuid) -> VolumeRecord {
    VolumeRecord {
        volume: Volume {
            id: VolumeId::from_uuid(id),
            project_id: PROJECT.to_owned(),
            name: "metered".to_owned(),
            description: String::new(),
            metadata: Default::default(),
            availability_zone: None,
            size_bytes: 1024 * 1024 * 1024,
            volume_type: "lvm".to_owned(),
            backend_id: "local".to_owned(),
            execution_scope: StorageExecutionScope::Host("local".to_owned()),
            state,
            generation: 1,
            operation_id: None,
            provider_reference: None,
        },
        created_at: "2026-08-28T00:00:00.000".to_owned(),
    }
}

async fn resource_usage(
    store: &TestStore,
    resource_id: &str,
    evaluated_at_ms: i64,
) -> Result<MeterUsageReport, Box<dyn std::error::Error>> {
    Ok(store
        .usage(&UsageQuery {
            scope: PROJECT.to_owned(),
            meter_keys: vec![o3k_api::VOLUME_ALLOCATION_METER.to_owned()],
            start_ms: BASE_MS,
            end_ms: BASE_MS + HOUR_MS,
            granularity: UsageGranularity::Hour,
            resource_id: Some(resource_id.to_owned()),
            evaluated_at_ms,
        })
        .await?)
}

/// R3: a caller-side create replay derives `consuming` from the durable row.
/// A `Deleting` row must not be reopened; a consuming row opens.
#[tokio::test]
async fn caller_side_replay_only_opens_consuming_rows() -> Result<(), Box<dyn std::error::Error>> {
    let store = store().await?;
    store.ensure_authority(BASE_MS).await?;
    let meter = Arc::new(ToggleVolumeMeter::new(store.clone(), BASE_MS));
    let observer: Arc<dyn LifecycleMeteringObserver> = meter.clone();

    let consuming_id = Uuid::new_v4();
    let idle_id = Uuid::new_v4();
    let consuming = volume_record(VolumeState::Available, consuming_id);
    let idle = volume_record(VolumeState::Deleting, idle_id);

    o3k_api::observe_volume_open_if_consuming(Some(&observer), &consuming)
        .await
        .map_err(|error| -> Box<dyn std::error::Error> { error.into() })?;
    o3k_api::observe_volume_open_if_consuming(Some(&observer), &idle)
        .await
        .map_err(|error| -> Box<dyn std::error::Error> { error.into() })?;

    let consuming_usage =
        resource_usage(&store, &consuming_id.to_string(), BASE_MS + 600_000).await?;
    assert_ne!(
        consuming_usage.meters[0].total, "0.000",
        "a consuming row must be reopened by a caller-side replay"
    );
    let idle_usage = resource_usage(&store, &idle_id.to_string(), BASE_MS + 600_000).await?;
    assert_eq!(
        idle_usage.meters[0].total, "0.000",
        "a Deleting row must never be reopened by a caller-side replay"
    );
    Ok(())
}
