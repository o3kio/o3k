pub mod compute;
pub mod external_controllers;
pub mod network;
pub mod runtime;
pub mod storage;

use o3k_kernel::{Clock, Controller};
use o3k_provider::ComputeProvider;
use o3k_storage::StorageProvider;
use o3k_store::ComputeRepository;
use std::{sync::Arc, time::Duration};
use tracing::info;
use uuid::Uuid;

struct NativeAttachmentWorkflowAdapter(Arc<dyn o3k_api::NativeAttachmentWorkflow>);

#[async_trait::async_trait]
impl o3k_native_api::resource::VolumeAttachmentWorkflow for NativeAttachmentWorkflowAdapter {
    async fn attach(&self, attachment_id: Uuid) -> Result<(), String> {
        self.0.attach(attachment_id).await
    }

    async fn detach(&self, attachment_id: Uuid) -> Result<(), String> {
        self.0.detach(attachment_id).await
    }
}

fn federated_oidc_validator_from_env()
-> Result<Option<Arc<o3k_identity::oidc::OidcValidator>>, Box<dyn std::error::Error>> {
    let values = [
        std::env::var("O3K_OIDC_TRUST_ID").ok(),
        std::env::var("O3K_OIDC_ISSUER").ok(),
        std::env::var("O3K_OIDC_AUDIENCE").ok(),
        std::env::var("O3K_OIDC_DISCOVERY_URL").ok(),
    ]
    .map(|value| value.filter(|value| !value.is_empty()));
    match values {
        [None, None, None, None] => Ok(None),
        [Some(id), Some(issuer), Some(audience), Some(discovery_url)] => {
            let allow_insecure_local = std::env::var("O3K_OIDC_ALLOW_INSECURE_LOCAL")
                .map(|value| matches!(value.as_str(), "1" | "true" | "TRUE"))
                .unwrap_or(false);
            let trusted = o3k_identity::oidc::TrustedIssuer {
                id,
                issuer: url::Url::parse(&issuer)?,
                audience,
                algorithms: vec![jsonwebtoken::Algorithm::RS256],
                discovery_url: url::Url::parse(&discovery_url)?,
                allow_insecure_local,
                timeout: Duration::from_secs(5),
                cache_ttl: Duration::from_secs(300),
                max_token_bytes: 16 * 1024,
                max_document_bytes: 512 * 1024,
                clock_skew: Duration::from_secs(30),
            };
            Ok(Some(Arc::new(o3k_identity::oidc::OidcValidator::new(
                trusted,
            )?)))
        }
        _ => Err("partial O3K_OIDC_* configuration: set trust ID, issuer, audience, and discovery URL, or none".into()),
    }
}

/// Reads the canonical O3K location topology from deployment configuration.
///
/// Regions and availability domains are provided via the `O3K_LOCATIONS`
/// environment variable as a JSON array of `RegionDeclaration`:
///
/// ```json
/// [{"id":"region-a","availability_domains":[{"id":"az-1"},{"id":"az-2"}]}]
/// ```
///
/// When unset or empty, an empty registry is returned (no regions configured —
/// the endpoint reports no location truth rather than fabricating any). The
/// registry is validated deterministically and is the single authority for
/// region/AZ identity; it is never derived from providers/hosts/backends.
fn locations_from_env() -> Result<o3k_kernel::LocationRegistry, Box<dyn std::error::Error>> {
    let raw = std::env::var("O3K_LOCATIONS").ok();
    let Some(raw) = raw.filter(|value| !value.trim().is_empty()) else {
        return Ok(o3k_kernel::LocationRegistry::default());
    };
    locations_from_declarations(&raw)
}

/// Parses and validates canonical location declarations from configuration.
///
/// `raw` is a JSON array of `RegionDeclaration`. Deterministic validation is
/// applied by [`o3k_kernel::LocationRegistry::from_declarations`]; any
/// malformed or invalid topology fails closed.
fn locations_from_declarations(
    raw: &str,
) -> Result<o3k_kernel::LocationRegistry, Box<dyn std::error::Error>> {
    let declarations: Vec<o3k_kernel::RegionDeclaration> = serde_json::from_str(raw)?;
    Ok(o3k_kernel::LocationRegistry::from_declarations(
        declarations,
    )?)
}

use self::compute::{
    DaemonCreateResolver, agent_inspect_probe_from_env, parse_extra_project_seeds,
};
use self::external_controllers::external_controllers_from_config;
use self::network::{
    NetworkBindingProjector, network_dispatcher_from_env, public_allocator_from_env,
};
use self::runtime::{control_shutdown_signal, spawn_console_event_consumer};
use self::storage::{
    LocalComputeAttachmentExecutor, LocalStorageFence, NativeStorageAttachmentWorkflow,
    storage_intent_epoch,
};

fn placement_consumer_ids(resources: &[o3k_store::ResourceRecord]) -> Vec<String> {
    let mut ids = resources
        .iter()
        .filter(|resource| resource.observed_state != "DELETED")
        .map(|resource| resource.id.to_string())
        .collect::<Vec<_>>();
    ids.sort();
    ids.dedup();
    ids
}

fn unix_time_millis() -> u64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map_or(0, |duration| duration.as_millis() as u64)
}

/// Resolve the native LVM provider configuration from the three `O3K_LVM_*`
/// environment values. Unset and set-but-empty values both mean "provider not
/// configured"; a partial configuration (some values set, others unset or
/// empty) is rejected so a misconfigured host fails closed instead of
/// silently running without storage. Values that are set but invalid are
/// rejected by `LvmConfig::validate`.
fn resolve_native_lvm_config(
    volume_group: Option<String>,
    thin_pool: Option<String>,
    provider_namespace: Option<String>,
) -> Result<Option<o3k_storage::LvmConfig>, Box<dyn std::error::Error>> {
    let volume_group = volume_group.filter(|value| !value.is_empty());
    let thin_pool = thin_pool.filter(|value| !value.is_empty());
    let provider_namespace = provider_namespace.filter(|value| !value.is_empty());
    match (volume_group, thin_pool, provider_namespace) {
        (None, None, None) => Ok(None),
        (Some(volume_group), Some(thin_pool), Some(provider_namespace)) => {
            let config = o3k_storage::LvmConfig {
                volume_group,
                thin_pool,
                provider_namespace,
            };
            config.validate()?;
            Ok(Some(config))
        }
        _ => Err(Box::new(std::io::Error::new(
            std::io::ErrorKind::InvalidInput,
            "partial O3K_LVM_* configuration: set all of O3K_LVM_VOLUME_GROUP, \
             O3K_LVM_THIN_POOL and O3K_LVM_PROVIDER_NAMESPACE, or none",
        ))),
    }
}

pub struct Composition {
    pub state: o3k_api::AppState,
    controller_id: o3k_store::ControllerId,
    controller_epoch: o3k_store::ControllerEpoch,
    coordination_store: Arc<dyn o3k_store::CoordinationRepository>,
    session_heartbeat_task: tokio::task::JoinHandle<()>,
    event_task: tokio::task::JoinHandle<()>,
    console_event_task: tokio::task::JoinHandle<()>,
    attachment_reconciler: tokio::task::JoinHandle<()>,
    create_convergence_reconciler: tokio::task::JoinHandle<()>,
    lifecycle_convergence_reconciler: tokio::task::JoinHandle<()>,
    inventory_task: Option<tokio::task::JoinHandle<()>>,
    composition_task: Option<tokio::task::JoinHandle<()>>,
    native_storage_recovery_task: Option<tokio::task::JoinHandle<()>>,
    control_task: Option<tokio::task::JoinHandle<()>>,
    inspect_probe_task: Option<tokio::task::JoinHandle<()>>,
    diagnostics_probe_task: tokio::task::JoinHandle<()>,
    external_cinder_probe_task: Option<tokio::task::JoinHandle<()>>,
}

impl Composition {
    pub async fn shutdown(self) {
        if let Some(task) = self.composition_task {
            task.abort();
            let _ = task.await;
        }
        if let Some(mut task) = self.control_task
            && tokio::time::timeout(std::time::Duration::from_secs(5), &mut task)
                .await
                .is_err()
        {
            task.abort();
            let _ = task.await;
        }
        if let Some(mut task) = self.inspect_probe_task
            && tokio::time::timeout(std::time::Duration::from_secs(5), &mut task)
                .await
                .is_err()
        {
            task.abort();
            let _ = task.await;
        }
        if let Some(task) = self.external_cinder_probe_task {
            task.abort();
            let _ = task.await;
        }
        self.event_task.abort();
        let _ = self.event_task.await;
        self.console_event_task.abort();
        let _ = self.console_event_task.await;
        self.attachment_reconciler.abort();
        let _ = self.attachment_reconciler.await;
        self.create_convergence_reconciler.abort();
        let _ = self.create_convergence_reconciler.await;
        self.lifecycle_convergence_reconciler.abort();
        if let Some(task) = self.native_storage_recovery_task {
            task.abort();
            let _ = task.await;
        }
        let _ = self.lifecycle_convergence_reconciler.await;
        if let Some(task) = self.inventory_task {
            task.abort();
            let _ = task.await;
        }
        self.session_heartbeat_task.abort();
        let _ = self.session_heartbeat_task.await;
        self.diagnostics_probe_task.abort();
        let _ = self.diagnostics_probe_task.await;
        let _ = self
            .coordination_store
            .drain_controller_session(&self.controller_id, &self.controller_epoch)
            .await;
        info!(
            controller_id = %self.controller_id,
            controller_epoch = %self.controller_epoch,
            "controller session drained"
        );
    }
}

pub async fn build_composition(
    config: o3k_config::Config,
) -> Result<Composition, Box<dyn std::error::Error>> {
    let store = match config.database_backend {
        o3k_config::DatabaseBackend::Sqlite => {
            let database_path = config.data_dir.join("o3k.sqlite");
            Arc::new(o3k_store::O3kStore::connect_sqlite_file(&database_path).await?)
        }
        o3k_config::DatabaseBackend::Postgres => {
            let url = config
                .database_url()
                .map(|s| s.expose())
                .ok_or("missing O3K_DATABASE_URL for PostgreSQL backend")?;
            Arc::new(o3k_store::O3kStore::connect_postgres(url).await?)
        }
    };
    let native_api_store = store.clone();

    // Canonical O3K topology is durable. The store is the authority; deployment
    // configuration declarations (O3K_LOCATIONS) are converged into it
    // idempotently at startup. A restart therefore reconstructs regions,
    // availability domains, failure domains and bindings from durable state
    // (ADR-0181/SPEC-0038; ADR-0184/SPEC-0047).
    let topology_store: Arc<dyn o3k_kernel::TopologyStore> = store.clone();
    let mut native_locations = o3k_kernel::LocationRegistry::from_snapshot(
        topology_store
            .load_snapshot()
            .await
            .map_err(|error| format!("canonical topology load failed: {error}"))?,
    )
    .map_err(|error| format!("stored canonical topology is invalid: {error}"))?;
    let declared_locations = locations_from_env()
        .map_err(|error| format!("native location configuration failed: {error}"))?;
    for region in declared_locations.regions() {
        // Startup convergence is not an HTTP mutation request, so no audit
        // event (it is a restart-safe idempotent seed).
        native_locations
            .declare_region(&*topology_store, &region.id, None)
            .await
            .map_err(|error| format!("canonical region convergence failed: {error}"))?;
        for az in &region.availability_domains {
            native_locations
                .declare_availability_domain(&*topology_store, &region.id, &az.id, None)
                .await
                .map_err(|error| {
                    format!("canonical availability-domain convergence failed: {error}")
                })?;
        }
    }
    // OpenStack region projection: the canonical region when exactly one is
    // configured, otherwise the historical RegionOne default. Multi-region
    // catalog projection is deferred (see SPEC-0047 traceability).
    let catalog_region = match native_locations.regions() {
        [only] => only.id.clone(),
        _ => "RegionOne".to_owned(),
    };

    let controller_id = o3k_store::ControllerId::new(
        std::env::var("O3K_CONTROLLER_ID").unwrap_or_else(|_| uuid::Uuid::new_v4().to_string()),
    );
    let controller_epoch = std::env::var("O3K_CONTROLLER_EPOCH")
        .map(o3k_store::ControllerEpoch::new)
        .unwrap_or_else(|_| o3k_store::ControllerEpoch::random());
    let session = o3k_store::ControllerSession {
        controller_id: controller_id.clone(),
        controller_epoch: controller_epoch.clone(),
        started_at: String::new(),
        heartbeat_at: String::new(),
        lease_until: String::new(),
        software_version: env!("CARGO_PKG_VERSION").to_owned(),
        source_commit: std::env::var("O3K_SOURCE_COMMIT").unwrap_or_else(|_| "HEAD".to_owned()),
        state: o3k_store::ControllerState::Active,
    };

    let coordination_store: Arc<dyn o3k_store::CoordinationRepository> = store.clone();
    coordination_store
        .register_controller_session(&session, Duration::from_secs(15))
        .await?;

    info!(
        controller_id = %controller_id,
        controller_epoch = %controller_epoch,
        "controller session registered"
    );

    let heartbeat_store = coordination_store.clone();
    let heartbeat_ctrl_id = controller_id.clone();
    let heartbeat_ctrl_epoch = controller_epoch.clone();
    let session_heartbeat_task = tokio::spawn(async move {
        let mut interval = tokio::time::interval(Duration::from_secs(5));
        interval.tick().await;
        loop {
            interval.tick().await;
            if let Err(error) = heartbeat_store
                .heartbeat_controller_session(
                    &heartbeat_ctrl_id,
                    &heartbeat_ctrl_epoch,
                    Duration::from_secs(15),
                )
                .await
            {
                tracing::warn!(%error, "controller session heartbeat failed");
            }
        }
    });

    let identity_store = store.clone();
    // Production composition uses the durable repository as the sole
    // authoritative Audit sink. Test-only constructors may still inject
    // Memory/Noop sinks explicitly, but no production service is allowed to
    // silently fall back to either implementation.
    let audit_sink: Arc<dyn o3k_kernel::RequiredAuditPublisher> =
        Arc::new(o3k_kernel::DurableAuditSink::new(store.clone()));
    let image_repository: Arc<dyn o3k_store::ImageRepository> = store.clone();
    let image_service = o3k_image::ImageService::open(
        config.data_dir.join("images"),
        o3k_image::DEFAULT_MAX_UPLOAD_BYTES,
        image_repository,
        audit_sink.clone(),
    )
    .await?
    .with_required_audit_publisher(audit_sink.clone());
    let network_repository: Arc<dyn o3k_store::NetworkRepository> = store.clone();
    let network_service = o3k_network::NetworkService::open(
        config.data_dir.join("network"),
        network_repository,
        audit_sink.clone(),
    )
    .await?
    .with_required_audit_publisher(audit_sink.clone());
    let config_drive_root = config.data_dir.join("config-drive");
    let config_drive_store = o3k_config_drive::ConfigDriveStore::open(&config_drive_root)?;
    let console_service = o3k_console::ConsoleService::open(config.data_dir.join("console"))?;
    // The registry's durable store is load-bearing for the console-log path:
    // o3k-api persists dispatched console commands through
    // `registry.persist_pending_command`, which requires this store to be
    // wired before the registry is shared.
    let registry = o3k_compute_agent::NodeRegistry::default()
        .with_store(store.clone())
        .with_coordination(
            coordination_store.clone(),
            controller_id.clone(),
            controller_epoch.clone(),
        );
    // The console-log consumer keeps its own durable liveness handle: the
    // `store` arc itself is moved into the compute service below.
    let console_store: Arc<dyn o3k_store::DurableStore> = store.clone();
    let placement_repository: Arc<dyn o3k_store::PlacementRepository> = store.clone();
    let placement = o3k_placement::PlacementLedger::open(
        config.data_dir.join("placement"),
        placement_repository,
    )
    .await
    .map_err(|error| format!("open Placement ledger: {error}"))?;
    let durable_compute_resources = store.list_resources_by_kind("compute_instance").await?;
    let consumer_ids = placement_consumer_ids(&durable_compute_resources);
    let reconciliation = placement
        .reconcile_consumers(&consumer_ids)
        .await
        .map_err(|error| format!("reconcile Placement consumers: {error}"))?;
    if !reconciliation.orphaned_allocations.is_empty()
        || !reconciliation.abandoned_intents.is_empty()
    {
        info!(
            orphaned_allocations = reconciliation.orphaned_allocations.len(),
            abandoned_intents = reconciliation.abandoned_intents.len(),
            "reconciled Placement state against durable compute resources"
        );
    }
    let scheduler = o3k_scheduler::Scheduler::new(placement.clone());
    let network_dispatcher = network_dispatcher_from_env()?;
    let public_allocator = public_allocator_from_env(&config.data_dir)?;
    let public_allocator_for_binding = public_allocator_from_env(&config.data_dir)?.map(Arc::new);
    let network_controller = o3k_network::NetworkControllerLease {
        controller_id: controller_id.to_string(),
        controller_epoch: controller_epoch.to_string(),
        fencing_token: std::env::var("O3K_NETWORK_FENCING_TOKEN")
            .ok()
            .and_then(|value| value.parse().ok())
            .unwrap_or(1),
    };
    let network_external_realm_id = std::env::var("O3K_NETWORK_EXTERNAL_REALM_ID")
        .ok()
        .map(|value| Uuid::parse_str(&value))
        .transpose()?;
    let network_agent_identity = match (
        std::env::var("O3K_NETWORK_AGENT_ID").ok(),
        std::env::var("O3K_NETWORK_AGENT_EPOCH").ok(),
    ) {
        (Some(agent_id), Some(agent_epoch)) => Some(o3k_network::NetworkAgentIdentity {
            agent_id,
            agent_epoch,
        }),
        (None, None) => None,
        _ => {
            return Err(
                "O3K_NETWORK_AGENT_ID and O3K_NETWORK_AGENT_EPOCH must be set together".into(),
            );
        }
    };
    let agent_control_enabled = config.compute_server_certificate.is_some()
        && config.compute_server_private_key.is_some()
        && config.compute_client_ca.is_some();
    let binding_projector = Arc::new(NetworkBindingProjector {
        network: network_service.clone(),
        registry: Arc::new(registry.clone()),
        network_dispatcher: network_dispatcher.clone(),
        network_controller: network_controller.clone(),
        network_external_realm_id,
        network_agent: network_agent_identity.clone(),
        public_allocator: public_allocator_for_binding.clone(),
        unbind_lock: Arc::new(tokio::sync::Mutex::new(())),
    });

    // Build compute service based on configured provider.
    let mut compute_service = if config.provider == o3k_config::Provider::Agent {
        let resolver = Arc::new(DaemonCreateResolver {
            store: store.clone(),
            image: image_service.clone(),
            network: network_service.clone(),
            config_drive: config_drive_store.clone(),
            network_dispatcher: network_dispatcher.clone(),
            network_controller: network_controller.clone(),
            network_external_realm_id,
            network_agent: network_agent_identity.clone(),
            public_allocator: public_allocator_for_binding.clone(),
        });
        o3k_compute::ComputeService::new(
            store.clone(),
            Arc::new(
                o3k_compute_agent::AgentComputeProvider::new_with_store(
                    registry.clone(),
                    resolver.clone(),
                    Some(store.clone()),
                )
                .with_artifact_resolver(resolver),
            ),
            audit_sink.clone(),
        )
        .with_binding_projector(binding_projector.clone())
        .with_config_drive_cleaner(config_drive_store.clone())
    } else {
        match config.provider {
            o3k_config::Provider::Libvirt => {
                return Err(o3k_config::ConfigError::DirectLibvirtProviderUnavailable.into());
            }
            o3k_config::Provider::Fake => o3k_compute::ComputeService::new(
                store.clone(),
                Arc::new(o3k_provider::FakeComputeProvider::new()),
                audit_sink.clone(),
            )
            .with_binding_projector(binding_projector.clone()),
            o3k_config::Provider::CellHv => {
                let provider = o3k_cellhv::CellHvProvider::connect(&o3k_cellhv::CellHvConfig {
                    endpoint: config
                        .cellhv_endpoint
                        .clone()
                        .ok_or("missing CellHV endpoint")?,
                    expected_version: config
                        .cellhv_expected_version
                        .clone()
                        .ok_or("missing CellHV expected version")?,
                    ca_certificate: config.cellhv_ca_certificate.clone(),
                    client_certificate: config.cellhv_client_certificate.clone(),
                    client_key: config.cellhv_client_key.clone(),
                })
                .await?;
                o3k_compute::ComputeService::new(
                    store.clone(),
                    Arc::new(provider),
                    audit_sink.clone(),
                )
                .with_binding_projector(binding_projector.clone())
            }
            o3k_config::Provider::Agent => unreachable!("agent provider handled above"),
        }
    };
    compute_service = compute_service.with_coordination(
        coordination_store.clone(),
        controller_id.clone(),
        controller_epoch.clone(),
    );
    compute_service = compute_service.with_required_audit_publisher(audit_sink.clone());
    if agent_control_enabled {
        compute_service = compute_service
            .with_scheduler(scheduler)
            .with_agent_registry(Arc::new(registry.clone()));
    }
    let mut external_cinder_client: Option<Arc<o3k_cinder::CinderClient>> = None;
    if let (Some(cinder_password), Ok(cinder_endpoint)) = (
        config.cinder_password(),
        std::env::var("O3K_CINDER_ENDPOINT"),
    ) {
        let catalog_endpoint = format!("http://{}", config.listen_addr);
        let cinder_client = Arc::new(o3k_cinder::CinderClient::new(
            o3k_cinder::CinderClientConfig {
                keystone_endpoint: catalog_endpoint,
                cinder_endpoint,
                username: "cinder".to_owned(),
                password: o3k_identity::Secret::new(cinder_password.expose().to_owned()),
                domain_name: "Default".to_owned(),
            },
        ));
        compute_service = compute_service.with_attachment_provider(cinder_client.clone());
        external_cinder_client = Some(cinder_client);
        info!("external Cinder attachment client enabled");
    }
    let inventory_task = agent_control_enabled.then(|| {
        o3k_compute::spawn_agent_inventory_publisher(
            Arc::new(registry.clone()),
            placement.clone(),
            registry.registration_notify(),
        )
    });
    let compute_ready = if config.provider == o3k_config::Provider::Agent && agent_control_enabled {
        // The authenticated agent is deliberately started after o3kd's health
        // endpoint.  A capability probe before registration would permanently
        // publish `not_ready`, deadlocking the agent bootstrap.  The compute
        // process owns the agent-registration/libvirt readiness gate; o3kd's
        // readyz here means that its authenticated control endpoint can accept
        // that registration.  If the control task later stops, the task below
        // clears readiness again.
        info!("agent control plane is ready for authenticated registration");
        true
    } else {
        match tokio::time::timeout(
            Duration::from_secs(5),
            compute_service.provider().capabilities(),
        )
        .await
        {
            Ok(Ok(capabilities)) => {
                info!(provider = %capabilities.provider_name, "compute provider is ready");
                true
            }
            Ok(Err(error)) => {
                tracing::warn!(%error, "compute provider is not ready");
                false
            }
            Err(_) => {
                tracing::warn!("compute provider readiness probe timed out");
                false
            }
        }
    };
    let event_task = compute_service.spawn_agent_event_consumer(Arc::new(registry.clone()));
    let console_event_task = spawn_console_event_consumer(
        registry.subscribe_events(),
        console_service.clone(),
        console_store.clone(),
    );
    let attachment_reconciler = compute_service.spawn_attachment_reconciler(5);
    let create_convergence_reconciler = compute_service.spawn_create_convergence_reconciler(5);
    let lifecycle_convergence_reconciler =
        compute_service.spawn_lifecycle_convergence_reconciler(5);
    let extra_projects = parse_extra_project_seeds()?;
    let mut identity = match (config.bootstrap_password(), config.token_signing_key()) {
        (Some(password), Some(signing_key)) => {
            let catalog_endpoint = format!("http://{}", config.listen_addr);
            o3k_identity::seed_identity_defaults_in_region(
                identity_store.as_ref(),
                &o3k_identity::BootstrapConfig {
                    catalog_endpoint: catalog_endpoint.clone(),
                    bootstrap_password: o3k_identity::Secret::new(password.expose().to_owned()),
                    cinder_password: config
                        .cinder_password()
                        .map(|secret| o3k_identity::Secret::new(secret.expose().to_owned())),
                    cinder_endpoint: std::env::var("O3K_CINDER_ENDPOINT").ok(),
                    pbkdf2_iterations: 0,
                    extra_projects,
                },
                &catalog_region,
            )
            .await?;
            Some(
                o3k_identity::TokenService::load(
                    identity_store.clone(),
                    o3k_identity::Secret::new(signing_key.expose().to_owned()),
                    Duration::from_secs(3600),
                )
                .await?
                .with_catalog_endpoint(catalog_endpoint.clone())
                // Keystone catalog/project projection of canonical O3K topology.
                .with_registry(o3k_kernel::KernelRegistry::standard_in_region(
                    &catalog_endpoint,
                    std::env::var("O3K_CINDER_ENDPOINT").ok().as_deref(),
                    &catalog_region,
                )),
            )
        }
        _ => {
            tracing::warn!(
                "identity is not configured: token authentication is disabled until O3K_BOOTSTRAP_PASSWORD and O3K_TOKEN_SIGNING_KEY are set (see scripts/generate-passwords.sh)"
            );
            None
        }
    };
    let oidc_validator = federated_oidc_validator_from_env()?;

    let authorized_agents = config
        .compute_authorized_agents
        .as_deref()
        .map(o3k_compute_agent::parse_authorized_agents)
        .transpose()?
        .unwrap_or_default();

    let mut native_manifest_registry = o3k_kernel::ManifestRegistry::new();
    // Core manifests publish cloud-wide availability over the canonical
    // topology reconstructed above (regions/AZs are references, never
    // invented here).
    native_manifest_registry
        .seed_core_with_locations(&native_locations)
        .map_err(|e| format!("native manifest seed_core failed: {e}"))?;
    if let Ok(manifest_directory) = std::env::var("O3K_MANIFEST_DIR") {
        let path = std::path::Path::new(&manifest_directory);
        native_manifest_registry
            .register_json_directory(path)
            .map_err(|e| format!("external manifest directory failed: {e}"))?;
        info!(directory = %path.display(), "external service manifests loaded");
    }

    // Canonical O3K location topology is the single source of region and
    // availability-domain truth (ADR-0181/SPEC-0038): durable store plus
    // converged deployment declarations, never derived from hosts, providers,
    // or backends (see the topology bootstrap above).
    native_locations
        .validate_manifest_registry(&native_manifest_registry)
        .map_err(|e| format!("service manifest references unknown location: {e}"))?;
    if !native_locations.is_empty() {
        info!(
            regions = native_locations.len(),
            "canonical native location topology configured"
        );
    }

    // Compatibility metadata is subordinate to the canonical manifests.  It
    // is registered only after identity validation, so an orphan projection
    // can never become a catalog service.
    // External Cinder is not an O3K native manifest (its API and lifecycle are
    // owned by the external deployment), but its canonical compatibility
    // identity still lives in the same authority. This lets the projection
    // remain lifecycle-gated without making native discovery claim Cinder.
    if external_cinder_client.is_some() {
        native_manifest_registry
            .register_external_service(
                "cinder",
                "cinder",
                o3k_kernel::ServiceLifecycleState::NotReady,
            )
            .map_err(|e| format!("external Cinder identity registration failed: {e}"))?;
    }
    let compatibility_template = o3k_kernel::KernelRegistry::standard_in_region(
        &format!("http://{}", config.listen_addr),
        std::env::var("O3K_CINDER_ENDPOINT").ok().as_deref(),
        &catalog_region,
    );
    compatibility_template
        .register_projections_into(&mut native_manifest_registry)
        .map_err(|e| format!("compatibility projection registration failed: {e}"))?;

    // Wire native API service adapters.
    let server_reader: Option<std::sync::Arc<dyn o3k_native_api::compute::ServerReader>> = Some(
        std::sync::Arc::new(crate::native_adapters::ServerReaderAdapter {
            service: std::sync::Arc::new(compute_service.clone()),
        }) as std::sync::Arc<dyn o3k_native_api::compute::ServerReader>,
    );
    let volume_reader: Option<std::sync::Arc<dyn o3k_native_api::volume::VolumeReader>> = Some(
        std::sync::Arc::new(crate::native_adapters::VolumeReaderAdapter {
            store: native_api_store.clone(),
            authorizer: std::sync::Arc::new(o3k_kernel::StaticAuthorizer::standard()),
        }) as std::sync::Arc<dyn o3k_native_api::volume::VolumeReader>,
    );
    let network_reader: Option<std::sync::Arc<dyn o3k_native_api::network::NetworkReader>> = Some(
        std::sync::Arc::new(crate::native_adapters::NetworkReaderAdapter {
            store: native_api_store.clone(),
            authorizer: std::sync::Arc::new(o3k_kernel::StaticAuthorizer::standard()),
        }) as std::sync::Arc<dyn o3k_native_api::network::NetworkReader>,
    );
    let operation_reader: std::sync::Arc<dyn o3k_native_api::operation::OperationReader> =
        std::sync::Arc::new(crate::native_adapters::OperationReaderAdapter {
            store: native_api_store.clone(),
        });
    let mut token_issuer: Option<std::sync::Arc<dyn o3k_native_api::auth::TokenIssuer>> =
        identity.as_ref().map(|id_service| {
            std::sync::Arc::new(crate::native_adapters::TokenIssuerAdapter {
                service: std::sync::Arc::new(id_service.clone()),
                oidc_validator: oidc_validator.clone(),
            }) as std::sync::Arc<dyn o3k_native_api::auth::TokenIssuer>
        });
    // The governance adapter shares the same identity snapshot as the token
    // issuer, so role/operator grant and revoke converge into subsequent token
    // issuance and scope discovery without a process restart.
    let external_controllers = external_controllers_from_config().await?;
    // The diagnostics controller probe needs the same external-controller set
    // that is later moved into the generic resource application, so keep a
    // private clone for it.
    let probe_external_controllers = external_controllers.clone();
    for (service_id, controller) in &external_controllers {
        let manifest = native_manifest_registry
            .get(service_id)
            .ok_or_else(|| format!("external controller has no manifest: {service_id}"))?;
        let capabilities = controller.capabilities().await;
        let declared_types = manifest
            .resource_types
            .iter()
            .map(|resource| resource.resource_type.to_string())
            .collect::<std::collections::BTreeSet<_>>();
        let required_actions = manifest
            .resource_types
            .iter()
            .flat_map(|resource| resource.operations.values().map(ToString::to_string))
            .collect::<std::collections::BTreeSet<_>>();
        if !capabilities
            .resource_types
            .iter()
            .all(|resource| declared_types.contains(resource))
            || !capabilities
                .actions
                .iter()
                .all(|action| manifest.actions.iter().any(|declared| declared == action))
            || !required_actions.iter().all(|action| {
                capabilities
                    .actions
                    .iter()
                    .any(|advertised| advertised == action)
            })
        {
            return Err(
                format!("external controller capabilities exceed manifest: {service_id}").into(),
            );
        }
        native_manifest_registry.register_controller(service_id, controller.session().clone())?;
        let health = controller.health().await;
        native_manifest_registry.update_controller_health(service_id, health)?;
    }

    let native_lvm_config = resolve_native_lvm_config(
        std::env::var("O3K_LVM_VOLUME_GROUP").ok(),
        std::env::var("O3K_LVM_THIN_POOL").ok(),
        std::env::var("O3K_LVM_PROVIDER_NAMESPACE").ok(),
    )?;
    let native_lvm_provider = native_lvm_config
        .map(|config| o3k_storage::LvmStorageProvider::new(config).map(Arc::new))
        .transpose()?;
    let native_storage_provider: Option<Arc<dyn o3k_storage::StorageProvider>> =
        match native_lvm_provider.clone() {
            Some(provider) => match provider.capabilities().await {
                Ok(capabilities) if capabilities.create_volume => Some(provider as _),
                Ok(_) => {
                    tracing::warn!("native storage provider lacks volume-create capability");
                    None
                }
                Err(error) => {
                    tracing::warn!(%error, "native storage provider readiness probe failed");
                    None
                }
            },
            None => None,
        };

    // Metering authority: the durable authority window is anchored once at
    // daemon start so consumption before this instant is never invented. The
    // same adapter is both the bounded read projection and the lifecycle write
    // projection, so reads and observations share one authority.
    let metering_clock: Arc<dyn Clock> = Arc::new(o3k_kernel::SystemClock);
    // A meter is advertised only when this composition can actually produce it:
    // the compute-instance meter requires the compute authority (always
    // configured by this composition root) and the volume allocation meter
    // requires a native storage provider.
    let metering_adapter = Arc::new(
        crate::native_adapters::MeteringAdapter::new(store.clone(), metering_clock.clone())
            .with_producible_meters(crate::native_adapters::metering::producible_meters(
                true,
                native_storage_provider.is_some(),
            )),
    );
    o3k_kernel::MeteringRepository::ensure_authority(&*store, metering_clock.now_unix_ms()).await?;
    let metering_observer: Arc<dyn o3k_kernel::LifecycleMeteringObserver> =
        metering_adapter.clone();
    // The compute service forwards the observer to its reconciliation journal
    // as well, so both the direct and the reconciled lifecycle paths project
    // the same compute-instance meter.
    compute_service = compute_service.with_metering_observer(metering_observer.clone());

    // First-party services remain in-process in the modular o3kd composition,
    // but they still publish the shared controller lifecycle state used by
    // native discovery and mutation dispatch.  Each readiness value is tied
    // to the dependency that the service actually needs; no manifest is
    // promoted to Ready merely because it was seeded.
    for (service_id, ready, detail) in [
        (
            "identity",
            token_issuer.is_some(),
            if token_issuer.is_some() {
                Some("identity service is configured".to_owned())
            } else {
                Some("identity service is not configured".to_owned())
            },
        ),
        (
            "image",
            true,
            Some("image service and repository are available".to_owned()),
        ),
        (
            "compute",
            compute_ready,
            Some(
                if compute_ready {
                    "compute provider is available"
                } else {
                    "compute provider is unavailable"
                }
                .to_owned(),
            ),
        ),
        (
            "network",
            true,
            Some("network service and repository are available".to_owned()),
        ),
        (
            "volume",
            native_storage_provider.is_some(),
            Some(
                if native_storage_provider.is_some() {
                    "native storage provider is available"
                } else {
                    "native storage provider is not configured"
                }
                .to_owned(),
            ),
        ),
    ] {
        if external_controllers.contains_key(service_id) {
            // An explicitly configured external controller owns its own
            // session/readiness and must not be replaced by in-process state.
            continue;
        }
        native_manifest_registry.register_in_process_controller(service_id, ready, detail)?;
    }

    // From this point onward every runtime consumer shares one canonical
    // service authority.  The Keystone adapter receives a derived facade
    // bound to this handle; it cannot maintain an independent inventory.
    let canonical_manifest_registry =
        std::sync::Arc::new(std::sync::RwLock::new(native_manifest_registry));
    // External Cinder is advertised only after the real attachment client can
    // authenticate and execute a read against the configured service.  An
    // endpoint environment variable alone is never sufficient for Ready.
    let external_cinder_probe_task = external_cinder_client.map(|client| {
        let lifecycle_registry = canonical_manifest_registry.clone();
        tokio::spawn(async move {
            let mut interval = tokio::time::interval(Duration::from_secs(1));
            loop {
                interval.tick().await;
                let ready = tokio::time::timeout(
                    Duration::from_secs(5),
                    client.list_volumes("eba29e2d-53de-461d-ae91-ede7402713cb"),
                )
                .await
                .is_ok_and(|result| result.is_ok());
                if let Ok(mut registry) = lifecycle_registry.write() {
                    let _ = registry.update_external_service_lifecycle(
                        "cinder",
                        if ready {
                            o3k_kernel::ServiceLifecycleState::Ready
                        } else {
                            o3k_kernel::ServiceLifecycleState::NotReady
                        },
                    );
                }
            }
        })
    });
    if let Some(identity_service) = identity.as_mut() {
        *identity_service = identity_service
            .clone()
            .with_manifest_registry(canonical_manifest_registry.clone());
    }
    token_issuer = identity.as_ref().map(|id_service| {
        std::sync::Arc::new(crate::native_adapters::TokenIssuerAdapter {
            service: std::sync::Arc::new(id_service.clone()),
            oidc_validator: oidc_validator.clone(),
        }) as std::sync::Arc<dyn o3k_native_api::auth::TokenIssuer>
    });
    let governance_identity = identity
        .as_ref()
        .map(|id_service| std::sync::Arc::new(id_service.clone()));
    let storage_intent_epoch = storage_intent_epoch(&controller_epoch);
    let native_attachment_workflow: Option<Arc<dyn o3k_api::NativeAttachmentWorkflow>> =
        native_lvm_provider.as_ref().map(|provider| {
            let workflow = o3k_reconciler::storage_workflow::StorageAttachmentWorkflow::new(
                store.clone(),
                provider.clone(),
                Arc::new(LocalComputeAttachmentExecutor {
                    compute: Arc::new(compute_service.clone()),
                }),
                Arc::new(LocalStorageFence {
                    coordination: coordination_store.clone(),
                    controller_id: controller_id.clone(),
                    controller_epoch: controller_epoch.clone(),
                    intent_epoch: storage_intent_epoch,
                    execution_lock_path: config.data_dir.join("storage.execution.lock"),
                    attempt: Arc::new(tokio::sync::Mutex::new(None)),
                }),
            );
            Arc::new(NativeStorageAttachmentWorkflow {
                store: store.clone(),
                controller_epoch: storage_intent_epoch,
                workflow,
            }) as Arc<dyn o3k_api::NativeAttachmentWorkflow>
        });
    let generic_application: std::sync::Arc<dyn o3k_native_api::resource::ResourceApplication> =
        std::sync::Arc::new(crate::native_adapters::GenericResourceApplication {
            compute: std::sync::Arc::new(compute_service.clone()),
            image: Some(std::sync::Arc::new(image_service.clone())),
            network_service: std::sync::Arc::new(network_service.clone()),
            store: native_api_store.clone(),
            storage_provider: native_storage_provider.clone(),
            server: server_reader
                .clone()
                .ok_or("generic native application requires compute reader")?,
            network: network_reader
                .clone()
                .ok_or("generic native application requires network reader")?,
            external_controllers: std::sync::Arc::new(external_controllers),
            public_allocator: public_allocator_for_binding.clone(),
            public_address_workflow: Some(binding_projector.clone()),
            network_external_realm_id,
            attachment_workflow: native_attachment_workflow.as_ref().map(|workflow| {
                Arc::new(NativeAttachmentWorkflowAdapter(workflow.clone()))
                    as Arc<dyn o3k_native_api::resource::VolumeAttachmentWorkflow>
            }),
            metering: Some(metering_observer.clone()),
        });

    let composition_task = if let Ok(listen_addr) = std::env::var("O3K_COMPOSITION_LISTEN_ADDR") {
        let address: std::net::SocketAddr = listen_addr
            .parse()
            .map_err(|_| "invalid O3K_COMPOSITION_LISTEN_ADDR")?;
        let ca = std::env::var("O3K_COMPOSITION_CLIENT_CA")
            .map_err(|_| "O3K_COMPOSITION_CLIENT_CA is required")?;
        let certificate = std::env::var("O3K_COMPOSITION_SERVER_CERT")
            .map_err(|_| "O3K_COMPOSITION_SERVER_CERT is required")?;
        let key = std::env::var("O3K_COMPOSITION_SERVER_KEY")
            .map_err(|_| "O3K_COMPOSITION_SERVER_KEY is required")?;
        let service_id = std::env::var("O3K_COMPOSITION_SERVICE_ID")
            .map_err(|_| "O3K_COMPOSITION_SERVICE_ID is required")?;
        let service_principal = std::env::var("O3K_COMPOSITION_SERVICE_PRINCIPAL")
            .map_err(|_| "O3K_COMPOSITION_SERVICE_PRINCIPAL is required")?;
        let key_id = std::env::var("O3K_COMPOSITION_DELEGATION_KEY_ID")
            .map_err(|_| "O3K_COMPOSITION_DELEGATION_KEY_ID is required")?;
        let key_path = std::env::var("O3K_COMPOSITION_DELEGATION_KEY")
            .map_err(|_| "O3K_COMPOSITION_DELEGATION_KEY is required")?;
        let key_bytes = std::fs::read(key_path)?;
        let key_bytes: [u8; 32] = key_bytes
            .try_into()
            .map_err(|_| "delegation verification key must be 32 bytes")?;
        let verification_key = ed25519_dalek::VerifyingKey::from_bytes(&key_bytes)
            .map_err(|_| "invalid delegation verification key")?;
        let tls = o3k_service_sdk::tls::server(&ca, &certificate, &key)
            .map_err(|error| format!("composition TLS configuration failed: {error}"))?;
        let handler = std::sync::Arc::new(crate::native_adapters::CompositionResourceHandler {
            application: generic_application.clone(),
            store: native_api_store.clone(),
            manifests: std::sync::Arc::new(
                canonical_manifest_registry
                    .read()
                    .map_err(|_| "canonical manifest registry poisoned")?
                    .clone(),
            ),
            delegation_keys: std::collections::HashMap::from([(key_id.clone(), verification_key)]),
            dispatcher:
                o3k_native_api::resource::ResourceDispatcher::from_shared_manifest_registry(
                    canonical_manifest_registry.clone(),
                )
                .map_err(|_| "failed to build composition resource descriptors")?,
        });
        let service = o3k_service_sdk::composition::CompositionServiceAdapter::new(
            handler,
            service_id,
            service_principal,
        )
        .with_delegation_keys(
            "o3k-composition",
            std::collections::HashMap::from([(key_id, verification_key)]),
        );
        info!(address = %address, "generic composition service enabled");
        Some(tokio::spawn(async move {
            let mut builder = match tonic::transport::Server::builder().tls_config(tls) {
                Ok(builder) => builder,
                Err(error) => {
                    tracing::error!(%error, "composition server configuration failed");
                    return;
                }
            };
            if let Err(error) = builder
                .add_service(service.into_server())
                .serve(address)
                .await
            {
                tracing::error!(%error, "composition service stopped");
            }
        }))
    } else {
        None
    };

    let inspect_compute_service = compute_service.clone();
    // Native storage is always wired in this composition root; the adapter
    // selects the canonical native path when external Cinder is absent.
    let volume_attachments_enabled = true;
    let mut state = if let Some(identity) = identity {
        o3k_api::AppState::new()
            .with_identity(identity)
            .with_image(image_service)
            .with_network(network_service)
            .with_console(console_service.clone())
            .with_agent_registry(registry.clone())
            .with_volume_attachments_enabled(volume_attachments_enabled)
            .with_compute(compute_service)
    } else {
        o3k_api::AppState::new()
            .with_image(image_service)
            .with_network(network_service)
            .with_console(console_service)
            .with_agent_registry(registry.clone())
            .with_volume_attachments_enabled(volume_attachments_enabled)
            .with_compute(compute_service)
    };
    // Native pagination is reachable only when IAM is configured.  In the
    // IAM-disabled health/operational profile, keep the API unavailable and
    // avoid requiring production secrets solely to start healthz.
    let cursor_config = if token_issuer.is_some() {
        o3k_native_api::pagination::CursorConfig::from_env()
            .map_err(|error| format!("native cursor configuration failed: {error}"))?
    } else {
        o3k_native_api::pagination::CursorConfig::default()
    };
    let native_state = o3k_native_api::NativeApiState::new_shared(
        canonical_manifest_registry.clone(),
        cursor_config,
        token_issuer,
        server_reader,
        volume_reader,
        network_reader,
    )?
    .with_composition_reader(std::sync::Arc::new(
        crate::native_adapters::CloudProfileAdapter {
            store: store.clone(),
            registry: canonical_manifest_registry.clone(),
        },
    ))
    .with_locations(std::sync::Arc::new(
        o3k_native_api::topology::TopologyGuard::new(native_locations.clone()),
    ))
    .with_topology_store(store.clone())
    .with_operation_reader(operation_reader)
    .with_quota_reader(std::sync::Arc::new(
        crate::native_adapters::QuotaReaderAdapter::new(store.clone()),
    ))
    .with_audit_reader(std::sync::Arc::new(
        crate::native_adapters::AuditReaderAdapter {
            store: store.clone(),
        },
    ))
    .with_governance_reader(std::sync::Arc::new(
        crate::native_adapters::GovernanceReaderAdapter {
            store: native_api_store.clone(),
            identity: governance_identity,
        },
    ))
    .with_resource_application(generic_application)
    .with_authorizer(std::sync::Arc::new(o3k_kernel::StaticAuthorizer::standard()));
    let native_lifecycle_registry = native_state
        .lifecycle_registry()
        .ok_or_else(|| "lifecycle registry not configured".to_owned())?;
    // Diagnostics reader adapter: projects canonical authority (lifecycle
    // registry, agent registry, placement store, location registry) into the
    // operator diagnostics contract. The same lifecycle registry is shared so
    // the projection always reflects the canonical controller state.
    let diagnostics_agents: std::sync::Arc<dyn o3k_provider::AgentNodeRegistry> =
        Arc::new(registry.clone());
    let diagnostics_adapter =
        std::sync::Arc::new(crate::native_adapters::DiagnosticsReaderAdapter::new(
            native_lifecycle_registry.clone(),
            diagnostics_agents,
            store.clone(),
            native_locations.clone(),
        ));
    let diagnostics_probe_task = spawn_diagnostics_controller_probe(
        native_lifecycle_registry.clone(),
        probe_external_controllers,
        diagnostics_adapter.observations(),
    );
    let native_state = native_state.with_diagnostics_reader(diagnostics_adapter);
    // Bounded read projection of the same canonical metering authority the
    // lifecycle observer writes to.
    let native_state = native_state.with_metering_reader(metering_adapter.clone());
    state = state.with_native_api(native_state);
    state = state.with_metering_observer(metering_observer.clone());
    state = state.with_storage_store(store.clone());
    if let Some(provider) = native_storage_provider {
        state = state.with_storage_provider(provider);
    }
    o3k_api::recover_native_volumes(&state).await;
    let native_storage_recovery_task = if let Some(workflow) = native_attachment_workflow.clone() {
        state = state.with_native_attachment_workflow(workflow.clone());
        if let Err(error) = workflow.recover().await {
            tracing::warn!(%error, "native storage attachment recovery is incomplete");
        }
        // Startup can race the previous controller's lease expiry.  Keep the
        // existing recovery boundary live so a Busy takeover is retried
        // automatically without requiring the original client request.
        Some(tokio::spawn(async move {
            let mut interval = tokio::time::interval(Duration::from_secs(5));
            interval.tick().await;
            loop {
                interval.tick().await;
                if let Err(error) = workflow.recover().await {
                    tracing::debug!(%error, "native storage recovery pass deferred");
                }
            }
        }))
    } else {
        None
    };
    if let Some(allocator) = public_allocator {
        state = state.with_public_allocator(allocator);
    }
    if let Some(realm_id) = network_external_realm_id {
        state = state.with_network_external_realm(realm_id);
    }
    if let Some(dispatcher) = network_dispatcher {
        state = state.with_network_dispatcher(dispatcher, network_controller);
    }
    if let Some(agent) = network_agent_identity {
        state = state.with_network_agent_identity(agent);
    }
    if !config.network_gateway_realization {
        info!(
            "host-side L3 gateway realization disabled (O3K_NETWORK_GATEWAY_REALIZATION=disabled)"
        );
    }
    state = state.with_network_gateway_realization(config.network_gateway_realization);
    // Recover canonical gateway and gateway-attachment deletion reservations
    // after the execution boundary is available.  This is intentionally
    // startup work, not a replay of an HTTP request.
    o3k_api::recover_l3_gateway_operations(&state).await;
    state.set_ready(compute_ready);
    let control_task = match (
        config.compute_server_certificate.clone(),
        config.compute_server_private_key.clone(),
        config.compute_client_ca.clone(),
    ) {
        (Some(server_certificate), Some(server_private_key), Some(client_ca_certificate)) => {
            let server = o3k_compute_agent::ControlPlaneServer {
                registry: registry.clone(),
                address: config.compute_control_addr,
                tls: o3k_compute_agent::ControlPlaneTls {
                    server_certificate,
                    server_private_key,
                    client_ca_certificate,
                },
                authorized_agents,
            };
            let readiness = state.clone();
            let lifecycle_readiness = native_lifecycle_registry.clone();
            info!(address = %config.compute_control_addr, "compute-agent control plane enabled");
            Some(tokio::spawn(async move {
                let result = server.serve(control_shutdown_signal()).await;
                if let Err(error) = &result {
                    readiness.set_ready(false);
                    if let Ok(mut registry) = lifecycle_readiness.write() {
                        let _ = registry.update_controller_health(
                            "compute",
                            o3k_kernel::controller::ControllerHealth {
                                healthy: false,
                                detail: Some("compute-agent control plane stopped".to_owned()),
                                protocol_version: o3k_kernel::controller::ProtocolVersion::V1,
                            },
                        );
                    }
                    tracing::error!(%error, "compute-agent control plane stopped before shutdown");
                }
                let _ = result;
            }))
        }
        _ => {
            info!(
                "compute-agent control plane disabled; configure all compute TLS paths to enable it"
            );
            None
        }
    };
    let inspect_probe_task = agent_inspect_probe_from_env(inspect_compute_service);

    Ok(Composition {
        state,
        controller_id,
        controller_epoch,
        coordination_store,
        session_heartbeat_task,
        event_task,
        console_event_task,
        attachment_reconciler,
        create_convergence_reconciler,
        lifecycle_convergence_reconciler,
        inventory_task,
        composition_task,
        native_storage_recovery_task,
        control_task,
        inspect_probe_task,
        diagnostics_probe_task,
        external_cinder_probe_task,
    })
}

/// Spawns the periodic external-controller re-probe task for operator
/// diagnostics.
///
/// Every 15 seconds it walks the controllers present in the shared lifecycle
/// registry. For each service backed by an external controller it issues a
/// bounded health probe (5s timeout): on success it records the reported
/// health and on timeout it synthesizes an unhealthy health so a dead external
/// controller can never stay `healthy` forever. In-process services have no
/// transport I/O; they are simply re-observed. Every probe records a fresh
/// observation timestamp so the projection can distinguish "observed" from
/// "stale" services.
fn spawn_diagnostics_controller_probe(
    registry: std::sync::Arc<std::sync::RwLock<o3k_kernel::ManifestRegistry>>,
    external_controllers: std::collections::BTreeMap<
        String,
        std::sync::Arc<o3k_service_sdk::GrpcControllerAdapter>,
    >,
    observations: std::sync::Arc<std::sync::RwLock<std::collections::HashMap<String, i64>>>,
) -> tokio::task::JoinHandle<()> {
    tokio::spawn(async move {
        let mut interval = tokio::time::interval(Duration::from_secs(15));
        interval.tick().await;
        loop {
            interval.tick().await;
            let controller_ids: Vec<String> = match registry.read() {
                Ok(reg) => reg
                    .all_controllers()
                    .into_iter()
                    .map(|registration| registration.service_id.clone())
                    .collect(),
                Err(_) => continue,
            };
            for service_id in controller_ids {
                if let Some(controller) = external_controllers.get(&service_id) {
                    let health = tokio::time::timeout(Duration::from_secs(5), controller.health())
                        .await
                        .unwrap_or(o3k_kernel::controller::ControllerHealth {
                            healthy: false,
                            detail: None,
                            protocol_version: o3k_kernel::controller::ProtocolVersion::V1,
                        });
                    if let Ok(mut reg) = registry.write() {
                        let _ = reg.update_controller_health(&service_id, health);
                    }
                }
                // In-process services re-observe configuration without I/O;
                // external controllers record an observation after their probe.
                // The timestamp is taken at the moment of observation, not at
                // the loop start: a serial probe pass over a large fleet can
                // otherwise record an observation far older than the
                // 75 s freshness threshold for controllers that were just
                // confirmed healthy.
                if let Ok(mut observations) = observations.write() {
                    let observed_at = crate::native_adapters::diagnostics::now_unix_ms();
                    observations.insert(service_id, observed_at);
                }
            }
        }
    })
}

/// Runs an opt-in, read-only process-boundary probe for protected validation.
/// It is deliberately absent unless its output and either a fixed resource ID
/// or a lifecycle-produced resource-ID file are configured. It records only
pub async fn shutdown_signal(state: o3k_api::AppState) {
    let ctrl_c = async { tokio::signal::ctrl_c().await };

    #[cfg(unix)]
    let terminate = async {
        match tokio::signal::unix::signal(tokio::signal::unix::SignalKind::terminate()) {
            Ok(mut signal) => {
                signal.recv().await;
                Ok(())
            }
            Err(error) => Err(error),
        }
    };

    #[cfg(not(unix))]
    let terminate = std::future::pending::<Option<()>>();

    tokio::select! {
        result = ctrl_c => match result {
            Ok(()) => info!("received Ctrl+C, shutting down"),
            Err(error) => tracing::error!(%error, "Ctrl+C handler failed; shutting down"),
        },
        result = terminate => match result {
            Ok(()) => info!("received SIGTERM, shutting down"),
            Err(error) => tracing::error!(%error, "SIGTERM handler failed; shutting down"),
        },
    }
    state.set_ready(false);
}

#[cfg(test)]
mod tests {
    use super::{
        DaemonCreateResolver, NetworkBindingProjector, locations_from_declarations,
        placement_consumer_ids, resolve_native_lvm_config,
    };
    use crate::composition::compute::validate_inspect_probe_paths;
    use o3k_compute::PortBindingProjector;
    use std::net::Ipv4Addr;
    use std::path::Path;
    use std::sync::Arc;
    use uuid::Uuid;

    #[derive(Clone, Default)]
    struct RecordingNetworkDispatcher {
        commands: Arc<std::sync::Mutex<Vec<o3k_network::NetworkPlanCommand>>>,
    }

    #[async_trait::async_trait]
    impl o3k_network::NetworkPlanDispatcher for RecordingNetworkDispatcher {
        async fn dispatch(
            &self,
            command: o3k_network::NetworkPlanCommand,
        ) -> Result<o3k_network::NetworkPlanStatus, o3k_network::NetworkDispatchError> {
            self.commands
                .lock()
                .map_err(|_| o3k_network::NetworkDispatchError::Unavailable)?
                .push(command);
            Ok(o3k_network::NetworkPlanStatus::Succeeded)
        }
    }

    #[test]
    fn lvm_config_unset_and_empty_env_means_provider_not_configured() -> Result<(), String> {
        assert!(
            resolve_native_lvm_config(None, None, None)
                .map_err(|error| error.to_string())?
                .is_none()
        );
        assert!(
            resolve_native_lvm_config(
                Some(String::new()),
                Some(String::new()),
                Some(String::new())
            )
            .map_err(|error| error.to_string())?
            .is_none()
        );
        Ok(())
    }

    #[test]
    fn lvm_config_all_values_set_resolves_to_config() -> Result<(), String> {
        let config = resolve_native_lvm_config(
            Some("vg-o3k".to_owned()),
            Some("pool-o3k".to_owned()),
            Some("o3k".to_owned()),
        )
        .map_err(|error| error.to_string())?
        .ok_or_else(|| "complete values should produce a config".to_owned())?;
        assert_eq!(config.volume_group, "vg-o3k");
        assert_eq!(config.thin_pool, "pool-o3k");
        assert_eq!(config.provider_namespace, "o3k");
        Ok(())
    }

    #[test]
    fn location_config_parses_region_topology_deterministically() -> Result<(), String> {
        let raw = r#"[{"id":"region-b","availability_domains":[{"id":"az-2"},{"id":"az-1"}]},
                          {"id":"region-a","availability_domains":[{"id":"az-3"}]}]"#
            .to_owned();
        let locations = locations_from_declarations(&raw).map_err(|e| e.to_string())?;
        let ids: Vec<&str> = locations
            .regions()
            .iter()
            .map(|region| region.id.as_str())
            .collect();
        assert_eq!(ids, vec!["region-a", "region-b"]);
        let azs: Vec<&str> = locations
            .availability_domains_of("region-b")
            .iter()
            .map(|az| az.id.as_str())
            .collect();
        assert_eq!(azs, vec!["az-1", "az-2"]);
        Ok(())
    }

    #[test]
    fn location_config_rejects_duplicate_region() {
        let raw = r#"[{"id":"region-a"},{"id":"region-a"}]"#.to_owned();
        let text = locations_from_declarations(&raw)
            .map(|_| "ok".to_owned())
            .unwrap_or_else(|error| error.to_string());
        assert!(text.contains("duplicate region"), "unexpected: {text}");
    }

    #[test]
    fn location_config_rejects_ambiguous_availability_domain() {
        let raw = r#"[{"id":"region-a","availability_domains":[{"id":"az-1"}]},
                       {"id":"region-b","availability_domains":[{"id":"az-1"}]}]"#
            .to_owned();
        let text = locations_from_declarations(&raw)
            .map(|_| "ok".to_owned())
            .unwrap_or_else(|error| error.to_string());
        assert!(text.contains("ambiguous"), "unexpected: {text}");
    }

    #[test]
    fn lvm_config_partial_env_fails_closed() {
        for values in [
            (Some("vg-o3k".to_owned()), None, None),
            (Some("vg-o3k".to_owned()), Some(String::new()), None),
            (
                Some("vg-o3k".to_owned()),
                Some("pool-o3k".to_owned()),
                Some(String::new()),
            ),
        ] {
            assert!(
                resolve_native_lvm_config(values.0, values.1, values.2).is_err(),
                "partial LVM configuration must fail closed"
            );
        }
    }

    #[test]
    fn lvm_config_complete_but_invalid_values_are_rejected() {
        assert!(
            resolve_native_lvm_config(
                Some("vg-o3k".to_owned()),
                Some("vg-o3k".to_owned()),
                Some("o3k".to_owned()),
            )
            .is_err()
        );
        assert!(
            resolve_native_lvm_config(
                Some("vg o3k".to_owned()),
                Some("pool-o3k".to_owned()),
                Some("o3k".to_owned()),
            )
            .is_err()
        );
    }

    #[test]
    fn config_drive_iso_is_published_beside_owned_instance_directory() -> Result<(), String> {
        let server_id = Uuid::now_v7();
        let directory = Path::new("/var/lib/o3k-testlab/config-drive").join(server_id.to_string());
        let output = DaemonCreateResolver::config_drive_iso_path(&directory, server_id)
            .map_err(|error| error.to_string())?;
        let parent = directory
            .parent()
            .ok_or_else(|| "instance directory should have a parent".to_owned())?;
        assert_eq!(output, parent.join(format!("{server_id}.iso")));
        Ok(())
    }

    #[test]
    fn placement_startup_consumer_set_is_live_sorted_and_deduplicated() {
        let live = Uuid::now_v7();
        let deleted = Uuid::now_v7();
        let resources = vec![
            o3k_store::ResourceRecord {
                id: deleted,
                kind: "compute_instance".to_owned(),
                project_id: "p".to_owned(),
                generation: 1,
                observed_generation: 1,
                desired_state: String::new(),
                observed_state: "DELETED".to_owned(),
                provider_id: None,
            },
            o3k_store::ResourceRecord {
                id: live,
                kind: "compute_instance".to_owned(),
                project_id: "p".to_owned(),
                generation: 1,
                observed_generation: 1,
                desired_state: String::new(),
                observed_state: "ACTIVE".to_owned(),
                provider_id: None,
            },
        ];
        assert_eq!(placement_consumer_ids(&resources), vec![live.to_string()]);
    }

    #[test]
    fn agent_inspect_probe_rejects_invalid_relative_traversal_or_symlinked_paths() {
        assert!(!validate_inspect_probe_paths(
            Some("relative/path.json"),
            None
        ));
        assert!(!validate_inspect_probe_paths(
            Some("/tmp/valid-output.json"),
            Some("/tmp/../etc/passwd")
        ));
        assert!(validate_inspect_probe_paths(
            Some("/tmp/valid-output.json"),
            Some("/tmp/valid-resource-file")
        ));
    }

    #[tokio::test]
    async fn console_observation_rejects_stale_replay_for_deleted_or_absent_resource()
    -> Result<(), Box<dyn std::error::Error>> {
        let root = std::env::temp_dir().join(format!("o3kd-console-guard-{}", Uuid::now_v7()));
        let sqlite_path = root.with_extension("sqlite");
        std::fs::create_dir_all(&root)?;
        let store = Arc::new(o3k_store::testkit::open_file(&sqlite_path).await?);
        let store_handle: Arc<dyn o3k_store::DurableStore> = store.clone();
        let console = o3k_console::ConsoleService::open(root.join("console"))?;

        let live_id = Uuid::now_v7();
        let deleted_id = Uuid::now_v7();
        let absent_id = Uuid::now_v7();
        let record = |id: Uuid, observed_state: &str| o3k_store::ResourceRecord {
            id,
            kind: "compute_instance".to_owned(),
            project_id: "project-a".to_owned(),
            generation: 1,
            observed_generation: 1,
            desired_state: "{}".to_owned(),
            observed_state: observed_state.to_owned(),
            provider_id: None,
        };
        store_handle
            .insert_resource(&record(live_id, "ACTIVE"))
            .await?;
        // The delete projection keeps a DELETED tombstone (issue #89, defect
        // 4: a crash + journal replay must not resurrect the console log).
        store_handle
            .insert_resource(&record(deleted_id, "DELETED"))
            .await?;

        let (sender, receiver) = tokio::sync::broadcast::channel(16);
        let task = super::spawn_console_event_consumer(receiver, console.clone(), store_handle);
        let observation = |resource_id: Uuid, bytes: &[u8]| {
            o3k_provider::AgentEvent::Observation(Box::new(o3k_provider::AgentObservation {
                agent_id: "agent-1".to_owned(),
                agent_epoch: "epoch-1".to_owned(),
                resource_id,
                provider_resource_id: None,
                state: o3k_provider::InstanceState::Running,
                operation_id: Uuid::now_v7(),
                operation_state: o3k_provider::AgentOperationState::Succeeded,
                observation_sequence: 1,
                observed_at_unix_ms: 0,
                redacted_message: None,
                console_log_bytes: bytes.to_vec(),
                console_log_offset: 0,
                console_log_complete: true,
                console_log_truncated: false,
                block_device: None,
            }))
        };
        sender.send(observation(deleted_id, b"stale delete replay"))?;
        sender.send(observation(absent_id, b"stale absent replay"))?;
        sender.send(observation(live_id, b"live boot"))?;
        drop(sender);
        task.await?;

        assert!(
            matches!(
                console.read(deleted_id),
                Err(o3k_console::ConsoleError::NotFound)
            ),
            "deleted resource console replay must not write the console log"
        );
        assert!(
            matches!(
                console.read(absent_id),
                Err(o3k_console::ConsoleError::NotFound)
            ),
            "absent resource console replay must not write the console log"
        );
        assert_eq!(
            console.read(live_id)?,
            b"live boot",
            "live resource console observation must still be written"
        );

        drop(console);
        std::fs::remove_dir_all(&root)?;
        let _ = std::fs::remove_file(&sqlite_path);
        let _ = std::fs::remove_file(format!("{}-wal", sqlite_path.display()));
        let _ = std::fs::remove_file(format!("{}-shm", sqlite_path.display()));
        Ok(())
    }

    #[tokio::test]
    async fn binding_intent_is_recorded_only_after_attachment_resolution_succeeds()
    -> Result<(), Box<dyn std::error::Error>> {
        let root = std::env::temp_dir().join(format!("o3kd-resolver-{}", Uuid::now_v7()));
        let sqlite_path = root.with_extension("sqlite");
        std::fs::create_dir_all(&root)?;
        let store = Arc::new(o3k_store::testkit::open_file(&sqlite_path).await?);
        let image = o3k_image::ImageService::open_for_test(
            root.join("images"),
            o3k_image::DEFAULT_MAX_UPLOAD_BYTES,
            store.clone(),
        )
        .await?;
        let config_drive = o3k_config_drive::ConfigDriveStore::open(root.join("config-drive"))?;
        let network_repository: Arc<dyn o3k_store::NetworkRepository> = store.clone();
        let network =
            o3k_network::NetworkService::open_for_test(root.join("network"), network_repository)
                .await?;
        let public_address: std::net::Ipv4Addr = "198.51.100.10".parse()?;
        let public_allocator = o3k_network::PublicAddressAllocator::open(
            root.join("public-addresses"),
            o3k_network::PublicAddressPool {
                prefix: o3k_domain::Ipv4Prefix::new("198.51.100.0".parse()?, 24)
                    .ok_or("invalid test prefix")?,
                first_usable: public_address,
                last_usable: public_address,
            },
        )?;
        let dispatcher = RecordingNetworkDispatcher::default();
        let commands = dispatcher.commands.clone();
        let resolver = DaemonCreateResolver {
            store: store.clone(),
            image,
            network: network.clone(),
            config_drive,
            network_dispatcher: Some(Arc::new(dispatcher)),
            network_controller: o3k_network::NetworkControllerLease {
                controller_id: "test-controller".to_owned(),
                controller_epoch: "test-epoch".to_owned(),
                fencing_token: 1,
            },
            network_agent: None,
            network_external_realm_id: None,
            public_allocator: Some(Arc::new(public_allocator)),
        };
        let net = network
            .create_network_for_project("project-a", "flat".to_owned())
            .await?;
        let _subnet = network
            .create_subnet_for_project(
                "project-a",
                net.id,
                "lab".to_owned(),
                "192.0.2.0/29".to_owned(),
                None,
                None,
                None,
            )
            .await?;
        let port = network
            .create_port_for_project("project-a", net.id, "one".to_owned())
            .await?;
        let security_group = network
            .create_security_group_for_project(
                "project-a",
                "default-deny".to_owned(),
                String::new(),
            )
            .await?;
        network
            .replace_security_group_bindings_for_project(
                "project-a",
                port.id,
                vec![security_group.id],
            )
            .await?;
        let allocation = resolver
            .public_allocator
            .as_ref()
            .ok_or("missing public allocator")?
            .allocate("project-a", "test-public-operation")?;
        resolver
            .public_allocator
            .as_ref()
            .ok_or("missing public allocator")?
            .associate("project-a", allocation.allocation_id, port.id)?;
        let request = o3k_provider::CreateInstanceRequest {
            operation_id: Uuid::now_v7(),
            o3k_server_id: Uuid::now_v7(),
            project_id: "project-a".to_owned(),
            name: "server".to_owned(),
            vcpus: 1,
            memory_mib: 512,
            flavor_id: String::new(),
            disk_gib: 1,
            image_id: None,
            key_name: None,
            keypair_id: None,
            network_ids: vec![port.id.to_string()],
            placement_provider_id: None,
            placement_allocation_id: None,
            config_drive: None,
            idempotency_key: "test".to_owned(),
        };
        let (attachments, _) = resolver
            .resolve_network(&request, "compute-1", "epoch-1")
            .await?;
        assert_eq!(attachments.len(), 1);
        assert_eq!(attachments[0].port_id, port.id.to_string());
        let bound = network.get_port_for_project("project-a", port.id).await?;
        assert_eq!(bound.binding_host.as_deref(), Some("compute-1"));
        assert_eq!(bound.binding_state.as_deref(), Some("binding"));
        {
            let commands = commands.lock().map_err(|_| "commands poisoned")?;
            assert_eq!(commands.len(), 1);
            assert!(commands[0].plan.intents.iter().any(|intent| matches!(
                intent,
                o3k_domain::NetworkPlanIntent::PublicAddressBinding(binding)
                    if binding.public_address == public_address
            )));
            assert!(commands[0].plan.intents.iter().any(|intent| matches!(
                intent,
                o3k_domain::NetworkPlanIntent::PolicyDefault(default)
                    if default.endpoint_id == port.id
                        && default.policy_id == security_group.id
                        && default.unmatched_action == o3k_domain::PolicyAction::Deny
            )));
        }

        let unresolved_port = o3k_store::PortRecord {
            id: Uuid::now_v7(),
            network_id: net.id,
            subnet_id: None,
            project_id: "project-a".to_owned(),
            name: "legacy-unresolvable".to_owned(),
            mac_address: "02:00:00:00:00:77".to_owned(),
            fixed_ip: Ipv4Addr::new(192, 0, 2, 7),
            status: "ACTIVE".to_owned(),
            binding_host: None,
            binding_state: None,
        };
        store.insert_port(&unresolved_port).await?;
        let unresolved = o3k_provider::CreateInstanceRequest {
            operation_id: Uuid::now_v7(),
            o3k_server_id: Uuid::now_v7(),
            project_id: "project-a".to_owned(),
            name: "server".to_owned(),
            vcpus: 1,
            memory_mib: 512,
            flavor_id: String::new(),
            disk_gib: 1,
            image_id: None,
            key_name: None,
            keypair_id: None,
            network_ids: vec![unresolved_port.id.to_string()],
            placement_provider_id: None,
            placement_allocation_id: None,
            config_drive: None,
            idempotency_key: "test".to_owned(),
        };
        let failed = resolver
            .resolve_network(&unresolved, "compute-1", "epoch-1")
            .await;
        assert!(failed.is_err());
        let after = store
            .get_port("project-a", &unresolved_port.id)
            .await?
            .ok_or("legacy projection disappeared")?;
        assert_eq!(after.binding_host, None);
        assert_eq!(after.binding_state, None);
        drop(resolver);
        drop(network);
        std::fs::remove_dir_all(&root)?;
        let _ = std::fs::remove_file(&sqlite_path);
        let _ = std::fs::remove_file(format!("{}-wal", sqlite_path.display()));
        let _ = std::fs::remove_file(format!("{}-shm", sqlite_path.display()));
        Ok(())
    }

    #[tokio::test]
    async fn configured_network_agent_owns_binding_target_separately_from_compute_host()
    -> Result<(), Box<dyn std::error::Error>> {
        let root = std::env::temp_dir().join(format!("o3kd-network-target-{}", Uuid::now_v7()));
        let sqlite_path = root.with_extension("sqlite");
        std::fs::create_dir_all(&root)?;
        let store = Arc::new(o3k_store::testkit::open_file(&sqlite_path).await?);
        let image = o3k_image::ImageService::open_for_test(
            root.join("images"),
            o3k_image::DEFAULT_MAX_UPLOAD_BYTES,
            store.clone(),
        )
        .await?;
        let config_drive = o3k_config_drive::ConfigDriveStore::open(root.join("config-drive"))?;
        let network_repository: Arc<dyn o3k_store::NetworkRepository> = store.clone();
        let network =
            o3k_network::NetworkService::open_for_test(root.join("network"), network_repository)
                .await?;
        let resolver = DaemonCreateResolver {
            store: store.clone(),
            image,
            network: network.clone(),
            config_drive,
            network_dispatcher: None,
            network_controller: o3k_network::NetworkControllerLease {
                controller_id: "test-controller".to_owned(),
                controller_epoch: "test-epoch".to_owned(),
                fencing_token: 1,
            },
            network_agent: Some(o3k_network::NetworkAgentIdentity {
                agent_id: "network-agent-1".to_owned(),
                agent_epoch: "network-epoch-1".to_owned(),
            }),
            network_external_realm_id: None,
            public_allocator: None,
        };
        let net = network
            .create_network_for_project("project-a", "flat".to_owned())
            .await?;
        network
            .create_subnet_for_project(
                "project-a",
                net.id,
                "lab".to_owned(),
                "192.0.2.0/29".to_owned(),
                None,
                None,
                None,
            )
            .await?;
        let port = network
            .create_port_for_project("project-a", net.id, "one".to_owned())
            .await?;
        let request = o3k_provider::CreateInstanceRequest {
            operation_id: Uuid::now_v7(),
            o3k_server_id: Uuid::now_v7(),
            project_id: "project-a".to_owned(),
            name: "server".to_owned(),
            vcpus: 1,
            memory_mib: 512,
            flavor_id: String::new(),
            disk_gib: 1,
            image_id: None,
            key_name: None,
            keypair_id: None,
            network_ids: vec![port.id.to_string()],
            placement_provider_id: None,
            placement_allocation_id: None,
            config_drive: None,
            idempotency_key: "test-network-agent-target".to_owned(),
        };
        let (attachments, _) = resolver
            .resolve_network(&request, "compute-agent-1", "compute-epoch-1")
            .await?;
        assert_eq!(attachments[0].port_id, port.id.to_string());
        let bound = network.get_port_for_project("project-a", port.id).await?;
        assert_eq!(bound.binding_host.as_deref(), Some("network-agent-1"));
        assert_eq!(bound.binding_state.as_deref(), Some("binding"));
        drop(resolver);
        drop(network);
        std::fs::remove_dir_all(&root)?;
        let _ = std::fs::remove_file(&sqlite_path);
        let _ = std::fs::remove_file(format!("{}-wal", sqlite_path.display()));
        let _ = std::fs::remove_file(format!("{}-shm", sqlite_path.display()));
        Ok(())
    }

    #[tokio::test]
    async fn terminal_fake_provider_outcome_dispatches_unbound_network_once()
    -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
        let root = std::env::temp_dir().join(format!("o3kd-terminal-binding-{}", Uuid::now_v7()));
        let sqlite_path = root.with_extension("sqlite");
        std::fs::create_dir_all(&root)?;
        let store = Arc::new(o3k_store::testkit::open_file(&sqlite_path).await?);
        let network_repository: Arc<dyn o3k_store::NetworkRepository> = store.clone();
        let network =
            o3k_network::NetworkService::open_for_test(root.join("network"), network_repository)
                .await?;
        let net = network
            .create_network_for_project("project-a", "terminal".to_owned())
            .await?;
        network
            .create_subnet_for_project(
                "project-a",
                net.id,
                "subnet".to_owned(),
                "192.0.2.0/29".to_owned(),
                None,
                None,
                None,
            )
            .await?;
        let port = network
            .create_port_for_project("project-a", net.id, "endpoint".to_owned())
            .await?;
        let public_root = root.join("public-addresses");
        let public_address: std::net::Ipv4Addr = "198.51.100.10".parse()?;
        let public_allocator = o3k_network::PublicAddressAllocator::open(
            &public_root,
            o3k_network::PublicAddressPool {
                prefix: o3k_domain::Ipv4Prefix::new("198.51.100.0".parse()?, 24)
                    .ok_or("invalid test prefix")?,
                first_usable: public_address,
                last_usable: public_address,
            },
        )?;
        let allocation = public_allocator.allocate("project-a", "test-operation")?;
        public_allocator.associate("project-a", allocation.allocation_id, port.id)?;
        let dispatcher = RecordingNetworkDispatcher::default();
        let commands = dispatcher.commands.clone();
        let projector = NetworkBindingProjector {
            network: network.clone(),
            registry: Arc::new(o3k_compute_agent::NodeRegistry::default()),
            network_dispatcher: Some(Arc::new(dispatcher)),
            network_controller: o3k_network::NetworkControllerLease {
                controller_id: "controller".to_owned(),
                controller_epoch: "epoch".to_owned(),
                fencing_token: 1,
            },
            network_external_realm_id: None,
            network_agent: Some(o3k_network::NetworkAgentIdentity {
                agent_id: "network-agent".to_owned(),
                agent_epoch: "agent-epoch".to_owned(),
            }),
            public_allocator: Some(Arc::new(public_allocator)),
            unbind_lock: Arc::new(tokio::sync::Mutex::new(())),
        };
        projector
            .project_create_outcome("project-a", &port.id.to_string(), true)
            .await?;
        projector
            .project_create_outcome("project-a", &port.id.to_string(), true)
            .await?;
        let bound = network.get_port_for_project("project-a", port.id).await?;
        assert_eq!(bound.binding_host.as_deref(), Some("network-agent"));
        assert_eq!(bound.binding_state.as_deref(), Some("bound"));
        let first = projector.clone();
        let second = projector.clone();
        let first_port_id = port.id.to_string();
        let second_port_id = first_port_id.clone();
        let first_unbind = tokio::spawn(async move {
            first
                .unbind_port("project-a", &first_port_id, uuid::Uuid::now_v7())
                .await
        });
        let second_unbind = tokio::spawn(async move {
            second
                .unbind_port("project-a", &second_port_id, uuid::Uuid::now_v7())
                .await
        });
        first_unbind.await??;
        second_unbind.await??;
        // A late successful create outcome must not recreate a binding after
        // terminal unbind has persisted the `down` tombstone.
        assert!(
            projector
                .project_create_outcome("project-a", &port.id.to_string(), true)
                .await
                .is_err()
        );
        let commands = commands.lock().map_err(|_| "commands poisoned")?;
        assert_eq!(commands.len(), 2);
        assert_eq!(
            commands
                .iter()
                .filter(|command| command.action == o3k_network::NetworkPlanAction::Remove)
                .count(),
            1
        );
        assert!(commands[0].plan.intents.iter().any(|intent| matches!(
            intent,
            o3k_domain::NetworkPlanIntent::PublicAddressBinding(binding)
                if binding.public_address == public_address
        )));
        std::fs::remove_dir_all(&root)?;
        let _ = std::fs::remove_file(&sqlite_path);
        let _ = std::fs::remove_file(format!("{}-wal", sqlite_path.display()));
        let _ = std::fs::remove_file(format!("{}-shm", sqlite_path.display()));
        Ok(())
    }

    #[tokio::test]
    async fn network_binding_projector_reflects_outcomes_on_recorded_intent()
    -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
        let root = std::env::temp_dir().join(format!("o3kd-projector-{}", Uuid::now_v7()));
        let sqlite_path = root.with_extension("sqlite");
        std::fs::create_dir_all(&root)?;
        let store = Arc::new(o3k_store::testkit::open_file(&sqlite_path).await?);
        let network_repository: Arc<dyn o3k_store::NetworkRepository> = store.clone();
        let network =
            o3k_network::NetworkService::open_for_test(root.join("network"), network_repository)
                .await?;
        let projector = NetworkBindingProjector {
            network: network.clone(),
            registry: Arc::new(o3k_compute_agent::NodeRegistry::default()),
            network_dispatcher: None,
            network_controller: o3k_network::NetworkControllerLease {
                controller_id: "test-controller".to_owned(),
                controller_epoch: "test-epoch".to_owned(),
                fencing_token: 1,
            },
            network_agent: None,
            network_external_realm_id: None,
            public_allocator: None,
            unbind_lock: Arc::new(tokio::sync::Mutex::new(())),
        };
        let net = network
            .create_network_for_project("project-a", "flat".to_owned())
            .await?;
        network
            .create_subnet_for_project(
                "project-a",
                net.id,
                "lab".to_owned(),
                "192.0.2.0/29".to_owned(),
                None,
                None,
                None,
            )
            .await?;
        let port = network
            .create_port_for_project("project-a", net.id, "one".to_owned())
            .await?;
        // Projection without a recorded intent is rejected (logged upstream).
        assert!(
            projector
                .project_create_outcome("project-a", &port.id.to_string(), true)
                .await
                .is_err()
        );
        network
            .record_binding_intent("project-a", port.id, "compute-1")
            .await?;
        projector
            .project_create_outcome("project-a", &port.id.to_string(), true)
            .await?;
        let bound = network.get_port_for_project("project-a", port.id).await?;
        assert_eq!(bound.binding_host.as_deref(), Some("compute-1"));
        assert_eq!(bound.binding_state.as_deref(), Some("bound"));
        projector
            .unbind_port("project-a", &port.id.to_string(), uuid::Uuid::now_v7())
            .await?;
        let unbound = network.get_port_for_project("project-a", port.id).await?;
        assert_eq!(unbound.binding_host, None);
        assert_eq!(unbound.binding_state.as_deref(), Some("down"));
        drop(projector);
        drop(network);
        std::fs::remove_dir_all(&root)?;
        let _ = std::fs::remove_file(&sqlite_path);
        let _ = std::fs::remove_file(format!("{}-wal", sqlite_path.display()));
        let _ = std::fs::remove_file(format!("{}-shm", sqlite_path.display()));
        Ok(())
    }
}
