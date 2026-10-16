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
use o3k_kernel::{KernelError, LifecycleMeteringObserver};
use o3k_provider::FakeComputeProvider;
use o3k_storage::{
    PreparedAttachment, StorageAttachmentObservation, StorageAttachmentRequest, StorageProvider,
    StorageProviderError, StorageSnapshotObservation, StorageSnapshotRequest,
    StorageVolumeObservation, StorageVolumeRequest,
};
use o3k_store::{DurableStore, StorageRepository, VolumeRecord, testkit::TestStore};
use std::{
    collections::BTreeMap,
    sync::{
        Arc, Mutex,
        atomic::{AtomicUsize, Ordering},
    },
    time::Duration,
};
use tower::ServiceExt;
use uuid::Uuid;

const PROJECT: &str = "eba29e2d-53de-461d-ae91-ede7402713cb";

struct RecoveryProvider {
    volumes: Mutex<BTreeMap<Uuid, StorageVolumeObservation>>,
    observations_owned: Mutex<bool>,
    create_error: Option<StorageProviderError>,
    inspect_calls: AtomicUsize,
}

impl Default for RecoveryProvider {
    fn default() -> Self {
        Self {
            volumes: Mutex::default(),
            observations_owned: Mutex::new(true),
            create_error: None,
            inspect_calls: AtomicUsize::default(),
        }
    }
}

#[async_trait]
impl StorageProvider for RecoveryProvider {
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
        if let Some(error) = &self.create_error {
            return Err(error.clone());
        }
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
        self.inspect_calls.fetch_add(1, Ordering::SeqCst);
        let mut observation = self
            .volumes
            .lock()
            .map_err(|_| StorageProviderError::CommandFailed)?
            .get(&request.volume_id.as_uuid())
            .cloned()
            .ok_or(StorageProviderError::NotFound)?;
        observation.owned = *self
            .observations_owned
            .lock()
            .map_err(|_| StorageProviderError::CommandFailed)?;
        Ok(observation)
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

#[derive(Default)]
struct CountingMeter(AtomicUsize);

#[async_trait]
impl LifecycleMeteringObserver for CountingMeter {
    async fn observe_resource_state(
        &self,
        _kind: &str,
        _project_id: &str,
        _resource_id: &str,
        _observed_state: &str,
    ) -> Result<(), KernelError> {
        self.0.fetch_add(1, Ordering::SeqCst);
        Ok(())
    }

    async fn observe_allocation(
        &self,
        _meter_key: &str,
        _project_id: &str,
        _resource_id: &str,
        _quantity: u64,
        _consuming: bool,
    ) -> Result<(), KernelError> {
        self.0.fetch_add(1, Ordering::SeqCst);
        Ok(())
    }
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

#[tokio::test]
async fn native_volume_capacity_failure_is_durable_and_skips_follow_up_work()
-> Result<(), Box<dyn std::error::Error>> {
    let store = store().await?;
    let volume_id = VolumeId::new();
    let requested = VolumeRecord {
        volume: Volume {
            id: volume_id,
            project_id: PROJECT.into(),
            name: "capacity-limited".into(),
            description: String::new(),
            metadata: Default::default(),
            availability_zone: None,
            size_bytes: 1024 * 1024 * 1024,
            volume_type: "lvm".into(),
            backend_id: "local".into(),
            execution_scope: StorageExecutionScope::Host("local".into()),
            state: VolumeState::Requested,
            generation: 1,
            operation_id: None,
            provider_reference: None,
        },
        created_at: "2026-08-28T00:00:00.000".into(),
    };
    store.insert_volume(&requested).await?;

    let provider = Arc::new(RecoveryProvider {
        create_error: Some(StorageProviderError::Capacity),
        ..RecoveryProvider::default()
    });
    let meter = Arc::new(CountingMeter::default());
    let observer: Arc<dyn LifecycleMeteringObserver> = meter.clone();
    let result = o3k_api::realize_native_volume_create(
        store.clone(),
        provider.clone(),
        requested.clone(),
        Some(&observer),
    )
    .await;

    let error = match result {
        Ok(_) => return Err("capacity failure must be surfaced".into()),
        Err(error) => error,
    };
    assert_eq!(error, "storage capacity is unavailable");
    let failed = store
        .get_volume(volume_id.as_uuid())
        .await?
        .ok_or("failed volume row must remain durable")?;
    assert_eq!(failed.volume.state, VolumeState::Error);
    assert_eq!(failed.volume.generation, requested.volume.generation + 2);
    assert_eq!(failed.volume.provider_reference, None);
    assert_eq!(provider.inspect_calls.load(Ordering::SeqCst), 0);
    assert_eq!(meter.0.load(Ordering::SeqCst), 0);
    Ok(())
}

#[tokio::test]
async fn native_volume_projection_requires_durable_attachment_workflow()
-> Result<(), Box<dyn std::error::Error>> {
    let store = store().await?;
    let server_id = Uuid::now_v7();
    store
        .insert_resource(&o3k_store::ResourceRecord {
            id: server_id,
            kind: "compute_instance".into(),
            project_id: PROJECT.into(),
            generation: 1,
            observed_generation: 1,
            desired_state: serde_json::to_string(&o3k_provider::CreateInstanceRequest {
                operation_id: Uuid::now_v7(),
                o3k_server_id: server_id,
                project_id: PROJECT.into(),
                name: "native-server".into(),
                vcpus: 1,
                memory_mib: 512,
                flavor_id: Uuid::from_u128(1).to_string(),
                disk_gib: 10,
                image_id: Some(Uuid::now_v7().to_string()),
                key_name: None,
                keypair_id: None,
                network_ids: Vec::new(),
                placement_provider_id: Some("compute-1".into()),
                placement_allocation_id: Some(Uuid::now_v7().to_string()),
                config_drive: None,
                idempotency_key: format!("create:{server_id}"),
            })?,
            observed_state: "ACTIVE".into(),
            provider_id: None,
        })
        .await?;
    let volume_id = VolumeId::new();
    store
        .insert_volume(&VolumeRecord {
            volume: Volume {
                id: volume_id,
                project_id: PROJECT.into(),
                name: "native".into(),
                description: String::new(),
                metadata: Default::default(),
                availability_zone: None,
                size_bytes: 1024 * 1024 * 1024,
                volume_type: "lvm".into(),
                backend_id: "local".into(),
                execution_scope: StorageExecutionScope::Host("local".into()),
                state: VolumeState::Available,
                generation: 1,
                operation_id: None,
                provider_reference: None,
            },
            created_at: "2026-08-28T00:00:00.000".into(),
        })
        .await?;
    let identity = TokenService::load(
        store.clone(),
        Secret::new("a-secure-signing-key-with-at-least-32-bytes".into()),
        Duration::from_secs(3600),
    )
    .await?;
    let compute = ComputeService::new_for_test(store.clone(), Arc::new(FakeComputeProvider::new()));
    let storage_provider = Arc::new(RecoveryProvider::default());
    let state = AppState::new()
        .with_identity(identity)
        .with_compute(compute)
        .with_storage_store(store.clone())
        .with_storage_provider(storage_provider)
        .with_volume_attachments_enabled(true);
    state.set_ready(true);
    let app = o3k_api::router_with_state(state);
    let auth = token(&app).await?;
    let request = serde_json::json!({"volume_attachment":{"volume_id": volume_id.to_string(), "delete_on_termination": false}});
    let response = app
        .clone()
        .oneshot(
            Request::builder()
                .method(Method::POST)
                .uri(format!(
                    "/v2.1/{PROJECT}/servers/{server_id}/os-volume_attachments"
                ))
                .header("x-auth-token", &auth)
                .header("content-type", "application/json")
                .body(Body::from(request.to_string()))?,
        )
        .await?;
    // Native attachment mutations require the durable workflow supplied by
    // the composition root; the API must fail closed rather than bypass it.
    assert_eq!(response.status(), StatusCode::SERVICE_UNAVAILABLE);
    Ok(())
}

#[tokio::test]
async fn native_volume_transitional_states_recover_from_provider_observation()
-> Result<(), Box<dyn std::error::Error>> {
    let store = store().await?;
    let volume_id = VolumeId::new();
    store
        .insert_volume(&VolumeRecord {
            volume: Volume {
                id: volume_id,
                project_id: PROJECT.into(),
                name: "recovering".into(),
                description: String::new(),
                metadata: Default::default(),
                availability_zone: None,
                size_bytes: 1024 * 1024 * 1024,
                volume_type: "lvm".into(),
                backend_id: "local".into(),
                execution_scope: StorageExecutionScope::Host("local".into()),
                state: VolumeState::Creating,
                generation: 2,
                operation_id: None,
                provider_reference: None,
            },
            created_at: "2026-08-28T00:00:00.000".into(),
        })
        .await?;
    let provider = Arc::new(RecoveryProvider::default());
    provider
        .create_volume(&StorageVolumeRequest {
            volume_id,
            project_id: PROJECT.into(),
            size_bytes: 1024 * 1024 * 1024,
            generation: 2,
        })
        .await?;
    let state = AppState::new()
        .with_storage_store(store.clone())
        .with_storage_provider(provider.clone());
    o3k_api::recover_native_volumes(&state).await;
    assert_eq!(
        store
            .get_volume(volume_id.as_uuid())
            .await?
            .ok_or("missing recovered volume")?
            .volume
            .state,
        VolumeState::Available
    );

    let deleting_id = VolumeId::new();
    let mut deleting = store
        .get_volume(volume_id.as_uuid())
        .await?
        .ok_or("missing recovered volume")?;
    deleting.volume.id = deleting_id;
    deleting.volume.state = VolumeState::Deleting;
    deleting.volume.generation += 1;
    store.insert_volume(&deleting).await?;
    o3k_api::recover_native_volumes(&state).await;
    assert!(store.get_volume(deleting_id.as_uuid()).await?.is_none());
    Ok(())
}

#[tokio::test]
async fn native_volume_recovery_rejects_foreign_provider_observation()
-> Result<(), Box<dyn std::error::Error>> {
    let store = store().await?;
    let volume_id = VolumeId::new();
    store
        .insert_volume(&VolumeRecord {
            volume: Volume {
                id: volume_id,
                project_id: PROJECT.into(),
                name: "foreign-observation".into(),
                description: String::new(),
                metadata: Default::default(),
                availability_zone: None,
                size_bytes: 1024 * 1024 * 1024,
                volume_type: "lvm".into(),
                backend_id: "local".into(),
                execution_scope: StorageExecutionScope::Host("local".into()),
                state: VolumeState::Creating,
                generation: 2,
                operation_id: None,
                provider_reference: None,
            },
            created_at: "2026-08-28T00:00:00.000".into(),
        })
        .await?;
    let provider = Arc::new(RecoveryProvider::default());
    provider
        .create_volume(&StorageVolumeRequest {
            volume_id,
            project_id: PROJECT.into(),
            size_bytes: 1024 * 1024 * 1024,
            generation: 2,
        })
        .await?;
    if let Ok(mut owned) = provider.observations_owned.lock() {
        *owned = false;
    } else {
        return Err("poisoned test mutex".into());
    }
    let state = AppState::new()
        .with_storage_store(store.clone())
        .with_storage_provider(provider);
    o3k_api::recover_native_volumes(&state).await;
    assert_eq!(
        store
            .get_volume(volume_id.as_uuid())
            .await?
            .ok_or("missing volume")?
            .volume
            .state,
        VolumeState::Creating
    );
    Ok(())
}

#[tokio::test]
async fn delete_missing_volume_is_404_not_an_existence_oracle()
-> Result<(), Box<dyn std::error::Error>> {
    // P13.6 non-disclosure regression: deleting a volume that does not exist
    // must return 404 (matching a foreign volume delete and upstream Cinder)
    // rather than an idempotent 204, otherwise an attacker can distinguish "no
    // such volume" from "a volume that exists in another project" and turn the
    // delete endpoint into an existence oracle.
    let store = store().await?;
    let identity = TokenService::load(
        store.clone(),
        Secret::new("a-secure-signing-key-with-at-least-32-bytes".into()),
        Duration::from_secs(3600),
    )
    .await?;
    let compute = ComputeService::new_for_test(store.clone(), Arc::new(FakeComputeProvider::new()));
    let storage_provider = Arc::new(RecoveryProvider::default());
    let state = AppState::new()
        .with_identity(identity)
        .with_compute(compute)
        .with_storage_store(store.clone())
        .with_storage_provider(storage_provider);
    state.set_ready(true);
    let app = o3k_api::router_with_state(state);
    let auth = token(&app).await?;
    let missing = VolumeId::new();
    let response = app
        .clone()
        .oneshot(
            Request::builder()
                .method(Method::DELETE)
                .uri(format!("/v3/{PROJECT}/volumes/{missing}"))
                .header("x-auth-token", &auth)
                .body(Body::empty())?,
        )
        .await?;
    assert_eq!(response.status(), StatusCode::NOT_FOUND);
    Ok(())
}
