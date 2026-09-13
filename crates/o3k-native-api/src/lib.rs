//! O3K Native Resource API — service-namespaced REST surface over Cloud Kernel
//! resources.
//!
//! Sibling to `o3k-api` (OpenStack compatibility adapter). Both consume the
//! same canonical application/domain services. See ADR-0173, ADR-0174, SPEC-0030.

use axum::{
    Json, Router,
    extract::{DefaultBodyLimit, State},
    http::StatusCode,
    response::IntoResponse,
    routing::{get, post},
};
use o3k_kernel::{ManifestRegistry, ServiceManifest};
use serde::Serialize;
use std::sync::{Arc, RwLock};

pub mod audit;
pub mod auth;
pub mod building_block;
pub mod composition;
pub mod compute;
pub mod diagnostics;
pub mod error;
pub mod governance;
pub mod identity;
pub mod metering;
pub mod network;
pub mod operation;
pub mod pagination;
pub mod quota;
pub mod resource;
pub mod resource_contract;
pub mod topology;
pub mod volume;

use resource::{LifecycleOperation, ResourceDescriptor};

/// Shared application state for the native API router.
#[derive(Clone, Default)]
pub struct NativeApiState {
    pub registry: Option<ManifestRegistry>,
    lifecycle_registry: Option<Arc<RwLock<ManifestRegistry>>>,
    pub cursor_config: pagination::CursorConfig,
    pub token_issuer: Option<std::sync::Arc<dyn auth::TokenIssuer>>,
    pub server_reader: Option<std::sync::Arc<dyn compute::ServerReader>>,
    pub volume_reader: Option<std::sync::Arc<dyn volume::VolumeReader>>,
    pub network_reader: Option<std::sync::Arc<dyn network::NetworkReader>>,
    pub operation_reader: Option<std::sync::Arc<dyn operation::OperationReader>>,
    pub audit_reader: Option<std::sync::Arc<dyn audit::AuditReader>>,
    pub quota_reader: Option<std::sync::Arc<dyn quota::QuotaReader>>,
    pub governance_reader: Option<std::sync::Arc<dyn governance::GovernanceReader>>,
    pub diagnostics_reader: Option<std::sync::Arc<dyn diagnostics::DiagnosticsReader>>,
    pub metering_reader: Option<std::sync::Arc<dyn metering::MeteringReader>>,
    /// Validated generic resource descriptors.  This is the northbound
    /// registry; applications below it are intentionally controller-agnostic.
    resource_index: resource::ResourceDispatcher,
    pub resource_application: Option<resource::SharedResourceApplication>,
    pub authorizer: Option<std::sync::Arc<dyn o3k_kernel::Authorizer>>,
    /// Canonical O3K location topology (regions, availability domains,
    /// failure domains, and bindings) behind the shared mutation guard.
    /// This is the single authoritative location source; service manifests
    /// reference canonical IDs only. See ADR-0181 / SPEC-0038 and P15.1
    /// (ADR-0184 / SPEC-0047).
    pub locations: Option<Arc<topology::TopologyGuard>>,
    /// Durable topology store every mutation persists through before it
    /// applies to memory. Reads of topology collections are bounded keyset
    /// pages over this port.
    ///
    /// Topology mutation audit is unconditional and structural: every successful
    /// mutation request is folded into the SAME store transaction as the
    /// mutation (P15.1 issue #931 MEDIUM-1), so there is no audit sink field —
    /// a missing sink is no longer possible.
    pub topology_store: Option<Arc<dyn o3k_kernel::TopologyStore>>,
    pub composition_reader: Option<Arc<dyn composition::CompositionReader>>,
    pub building_block_reader: Option<Arc<dyn building_block::BuildingBlockReader>>,
}

impl NativeApiState {
    #[allow(clippy::too_many_arguments)]
    pub fn new(
        registry: Option<ManifestRegistry>,
        cursor_config: pagination::CursorConfig,
        token_issuer: Option<std::sync::Arc<dyn auth::TokenIssuer>>,
        server_reader: Option<std::sync::Arc<dyn compute::ServerReader>>,
        volume_reader: Option<std::sync::Arc<dyn volume::VolumeReader>>,
        network_reader: Option<std::sync::Arc<dyn network::NetworkReader>>,
    ) -> Result<Self, String> {
        let lifecycle_registry = registry.map(|registry| Arc::new(RwLock::new(registry)));
        Self::new_with_lifecycle_registry(
            lifecycle_registry,
            cursor_config,
            token_issuer,
            server_reader,
            volume_reader,
            network_reader,
        )
    }

    /// Builds state over an already shared canonical service authority.
    /// Native discovery, resource discovery and diagnostics can therefore not
    /// drift from compatibility consumers that hold the same handle.
    #[allow(clippy::too_many_arguments)]
    pub fn new_shared(
        lifecycle_registry: Arc<RwLock<ManifestRegistry>>,
        cursor_config: pagination::CursorConfig,
        token_issuer: Option<std::sync::Arc<dyn auth::TokenIssuer>>,
        server_reader: Option<std::sync::Arc<dyn compute::ServerReader>>,
        volume_reader: Option<std::sync::Arc<dyn volume::VolumeReader>>,
        network_reader: Option<std::sync::Arc<dyn network::NetworkReader>>,
    ) -> Result<Self, String> {
        Self::new_with_lifecycle_registry(
            Some(lifecycle_registry),
            cursor_config,
            token_issuer,
            server_reader,
            volume_reader,
            network_reader,
        )
    }

    fn new_with_lifecycle_registry(
        lifecycle_registry: Option<Arc<RwLock<ManifestRegistry>>>,
        cursor_config: pagination::CursorConfig,
        token_issuer: Option<std::sync::Arc<dyn auth::TokenIssuer>>,
        server_reader: Option<std::sync::Arc<dyn compute::ServerReader>>,
        volume_reader: Option<std::sync::Arc<dyn volume::VolumeReader>>,
        network_reader: Option<std::sync::Arc<dyn network::NetworkReader>>,
    ) -> Result<Self, String> {
        let resource_index = lifecycle_registry
            .as_ref()
            .map(|registry| {
                resource::ResourceDispatcher::from_shared_manifest_registry(registry.clone())
            })
            .transpose()
            .map_err(|error| format!("native resource dispatcher construction failed: {error:?}"))?
            .unwrap_or_default();
        let registry = lifecycle_registry
            .as_ref()
            .and_then(|registry| registry.read().ok().map(|registry| registry.clone()));
        Ok(Self {
            registry,
            lifecycle_registry,
            cursor_config,
            token_issuer,
            server_reader,
            volume_reader,
            network_reader,
            operation_reader: None,
            audit_reader: None,
            quota_reader: None,
            governance_reader: None,
            diagnostics_reader: None,
            metering_reader: None,
            resource_index,
            resource_application: None,
            authorizer: None,
            locations: None,
            topology_store: None,
            composition_reader: None,
            building_block_reader: None,
        })
    }

    #[must_use]
    pub fn with_composition_reader(
        mut self,
        reader: Arc<dyn composition::CompositionReader>,
    ) -> Self {
        self.composition_reader = Some(reader);
        self
    }

    #[must_use]
    pub fn with_building_block_reader(
        mut self,
        reader: Arc<dyn building_block::BuildingBlockReader>,
    ) -> Self {
        self.building_block_reader = Some(reader);
        self
    }

    /// Sets the canonical location topology served and mutated by the native
    /// API. The guard serializes every durable topology mutation.
    #[must_use]
    pub fn with_locations(mut self, locations: Arc<topology::TopologyGuard>) -> Self {
        self.locations = Some(locations);
        self
    }

    /// Sets the durable topology store mutations persist through.
    #[must_use]
    pub fn with_topology_store(mut self, store: Arc<dyn o3k_kernel::TopologyStore>) -> Self {
        self.topology_store = Some(store);
        self
    }

    #[must_use]
    pub fn with_operation_reader(
        mut self,
        reader: std::sync::Arc<dyn operation::OperationReader>,
    ) -> Self {
        self.operation_reader = Some(reader);
        self
    }

    #[must_use]
    pub fn with_audit_reader(mut self, reader: std::sync::Arc<dyn audit::AuditReader>) -> Self {
        self.audit_reader = Some(reader);
        self
    }

    #[must_use]
    pub fn with_quota_reader(mut self, reader: std::sync::Arc<dyn quota::QuotaReader>) -> Self {
        self.quota_reader = Some(reader);
        self
    }

    #[must_use]
    pub fn with_governance_reader(
        mut self,
        reader: std::sync::Arc<dyn governance::GovernanceReader>,
    ) -> Self {
        self.governance_reader = Some(reader);
        self
    }

    #[must_use]
    pub fn with_diagnostics_reader(
        mut self,
        reader: std::sync::Arc<dyn diagnostics::DiagnosticsReader>,
    ) -> Self {
        self.diagnostics_reader = Some(reader);
        self
    }

    #[must_use]
    pub fn with_metering_reader(
        mut self,
        reader: std::sync::Arc<dyn metering::MeteringReader>,
    ) -> Self {
        self.metering_reader = Some(reader);
        self
    }

    #[must_use]
    pub fn with_resource_application(
        mut self,
        application: resource::SharedResourceApplication,
    ) -> Self {
        self.resource_application = Some(application);
        self
    }

    #[must_use]
    pub fn with_authorizer(
        mut self,
        authorizer: std::sync::Arc<dyn o3k_kernel::Authorizer>,
    ) -> Self {
        self.authorizer = Some(authorizer);
        self
    }

    /// Returns the shared lifecycle registry used by native discovery and
    /// mutation gating. Runtime health transitions must update this registry
    /// so every cloned request state observes the same readiness.
    #[must_use]
    pub fn lifecycle_registry(&self) -> Option<Arc<RwLock<ManifestRegistry>>> {
        self.lifecycle_registry.clone()
    }
}

/// Builds the native API router with the given state.
pub fn router(state: NativeApiState) -> Router {
    Router::new()
        .route("/", get(api_root))
        .route("/services", get(discover_services))
        .route("/resource-types", get(discover_resource_types))
        .route(
            "/resource-schemas/{namespace}/{collection}/{version}",
            get(discover_resource_schema),
        )
        .route("/regions", get(discover_regions))
        .route(
            "/regions/{region}",
            axum::routing::put(topology::declare_region).delete(topology::remove_region),
        )
        .route(
            "/regions/{region}/availability-domains/{az}",
            axum::routing::put(topology::declare_availability_domain)
                .delete(topology::remove_availability_domain),
        )
        .route(
            "/topology/failure-domains",
            get(topology::list_failure_domains).post(topology::create_failure_domain),
        )
        .route(
            "/topology/failure-domains/{id}",
            get(topology::show_failure_domain)
                .put(topology::update_failure_domain)
                .delete(topology::delete_failure_domain),
        )
        .route(
            "/topology/failure-domains/{id}/bindings",
            get(topology::list_bindings),
        )
        .route(
            "/topology/failure-domains/{id}/bindings/{kind}/{target}",
            axum::routing::put(topology::bind).delete(topology::unbind),
        )
        .route("/identity/tokens", post(identity::issue_token))
        .route(
            "/identity/scopes",
            post(identity::discover_federated_scopes),
        )
        .route("/identity/me", get(identity::current_context))
        .route("/operator/profile", get(identity::operator_profile))
        .route(
            "/operator/cloud-profiles/{id}",
            get(composition::show).put(composition::put),
        )
        .route(
            "/operator/cloud-profiles/{id}/actions/reconcile",
            post(composition::reconcile),
        )
        .route(
            "/operator/building-blocks",
            get(building_block::list).post(building_block::enroll),
        )
        .route("/operator/building-blocks/{id}", get(building_block::show))
        .route(
            "/operator/building-blocks/{id}/actions/{action_name}",
            post(building_block::action),
        )
        .route("/compute/servers/{id}", get(compute::show_server))
        .route("/volume/volumes/{id}", get(volume::show_volume))
        .route(
            "/network/address-realms/{id}",
            get(network::show_address_realm),
        )
        .route(
            "/{namespace}/{collection}",
            get(resource::list).post(resource::create),
        )
        .route(
            "/{namespace}/{collection}/{id}",
            get(resource::show)
                .put(resource::update)
                .delete(resource::delete),
        )
        .route(
            "/{namespace}/{collection}/{id}/actions/{action_name}",
            post(resource::action),
        )
        .route("/operations", get(operation::list_operations))
        .route("/audit", get(audit::list_audit))
        .route("/audit/{id}", get(audit::show_audit))
        .route("/quota", get(quota::list))
        .route("/quota/{namespace}/{dimension}", get(quota::show))
        .route("/operator/quotas/{project}", get(quota::operator_list))
        .route(
            "/operator/quotas/{project}/{namespace}/{dimension}",
            axum::routing::put(quota::set).delete(quota::clear),
        )
        .route("/operations/{id}", get(operation::show_operation))
        .route(
            "/operator/governance/projects",
            get(governance::list_projects),
        )
        .route(
            "/operator/governance/projects/{id}",
            get(governance::show_project),
        )
        .route(
            "/operator/governance/principals",
            get(governance::list_principals),
        )
        .route(
            "/operator/governance/principals/{id}",
            get(governance::show_principal),
        )
        .route("/operator/governance/roles", get(governance::list_roles))
        .route(
            "/operator/governance/capabilities",
            get(governance::list_capabilities),
        )
        .route(
            "/operator/governance/assignments",
            get(governance::list_assignments).post(governance::create_assignment),
        )
        .route(
            "/operator/governance/assignments/{id}",
            axum::routing::delete(governance::delete_assignment),
        )
        .route(
            "/operator/governance/operator-assignments",
            get(governance::list_operator_assignments).post(governance::create_operator_assignment),
        )
        .route(
            "/operator/governance/operator-assignments/{id}",
            axum::routing::delete(governance::delete_operator_assignment),
        )
        .route("/operator/diagnostics", get(diagnostics::summary))
        .route("/operator/diagnostics/services", get(diagnostics::services))
        .route(
            "/operator/diagnostics/providers",
            get(diagnostics::providers),
        )
        .route("/operator/diagnostics/capacity", get(diagnostics::capacity))
        .route("/metering/definitions", get(metering::definitions))
        .route("/metering/usage", get(metering::usage))
        .layer(DefaultBodyLimit::max(1_048_576))
        .with_state(state)
}

#[cfg(test)]
#[allow(clippy::expect_used, clippy::panic)]
pub(crate) fn assert_resource_envelope_schema(value: &serde_json::Value) {
    let schema: serde_json::Value = serde_json::from_str(include_str!(concat!(
        env!("CARGO_MANIFEST_DIR"),
        "/../../contracts/native-resource-envelope-v1.schema.json"
    )))
    .expect("valid native envelope schema");
    let validator = jsonschema::validator_for(&schema).expect("compiled native envelope schema");
    if let Err(errors) = validator.validate(value) {
        panic!("native envelope schema violation: {errors}");
    }
}

#[cfg(test)]
#[allow(clippy::expect_used, clippy::panic)]
pub(crate) fn assert_location_discovery_schema(value: &serde_json::Value) {
    let schema: serde_json::Value = serde_json::from_str(include_str!(concat!(
        env!("CARGO_MANIFEST_DIR"),
        "/../../contracts/native-location-discovery-v1.schema.json"
    )))
    .expect("valid native location discovery schema");
    let validator = jsonschema::validator_for(&schema).expect("compiled native location schema");
    if let Err(errors) = validator.validate(value) {
        panic!("native location discovery schema violation: {errors}");
    }
}

#[cfg(test)]
#[allow(clippy::expect_used, clippy::panic)]
pub(crate) fn assert_topology_failure_domain_schema(value: &serde_json::Value) {
    let schema: serde_json::Value = serde_json::from_str(include_str!(concat!(
        env!("CARGO_MANIFEST_DIR"),
        "/../../contracts/native-topology-failure-domain-v1.schema.json"
    )))
    .expect("valid native topology failure domain schema");
    let validator =
        jsonschema::validator_for(&schema).expect("compiled native topology failure domain schema");
    if let Err(errors) = validator.validate(value) {
        panic!("native topology failure domain schema violation: {errors}");
    }
}

#[cfg(test)]
#[allow(clippy::expect_used, clippy::panic)]
pub(crate) fn assert_topology_binding_schema(value: &serde_json::Value) {
    let schema: serde_json::Value = serde_json::from_str(include_str!(concat!(
        env!("CARGO_MANIFEST_DIR"),
        "/../../contracts/native-topology-binding-v1.schema.json"
    )))
    .expect("valid native topology binding schema");
    let validator =
        jsonschema::validator_for(&schema).expect("compiled native topology binding schema");
    if let Err(errors) = validator.validate(value) {
        panic!("native topology binding schema violation: {errors}");
    }
}

#[cfg(test)]
#[allow(clippy::expect_used, clippy::panic)]
pub(crate) fn assert_governance_schema(value: &serde_json::Value) {
    let schema: serde_json::Value = serde_json::from_str(include_str!(concat!(
        env!("CARGO_MANIFEST_DIR"),
        "/../../contracts/native-governance-v1.schema.json"
    )))
    .expect("valid native governance schema");
    let validator = jsonschema::validator_for(&schema).expect("compiled native governance schema");
    if let Err(errors) = validator.validate(value) {
        panic!("native governance schema violation: {errors}");
    }
}

// ── API root ──────────────────────────────────────────────────────────────

#[derive(Serialize)]
pub struct ApiRootResponse {
    api_version: &'static str,
    endpoints: Vec<&'static str>,
}

pub async fn api_root() -> Json<ApiRootResponse> {
    Json(ApiRootResponse {
        api_version: "o3k.io/v1",
        endpoints: vec![
            "/o3k/v1/services",
            "/o3k/v1/resource-types",
            "/o3k/v1/resource-schemas/{namespace}/{collection}/{version}",
            "/o3k/v1/regions",
            "/o3k/v1/regions/{region}",
            "/o3k/v1/regions/{region}/availability-domains/{az}",
            "/o3k/v1/topology/failure-domains",
            "/o3k/v1/topology/failure-domains/{id}",
            "/o3k/v1/topology/failure-domains/{id}/bindings",
            "/o3k/v1/topology/failure-domains/{id}/bindings/{kind}/{target}",
            "/o3k/v1/identity/tokens",
            "/o3k/v1/identity/scopes",
            "/o3k/v1/identity/me",
            "/o3k/v1/operator/profile",
            "/o3k/v1/operator/building-blocks",
            "/o3k/v1/operator/building-blocks/{id}",
            "/o3k/v1/operator/building-blocks/{id}/actions/{action_name}",
            "/o3k/v1/compute/servers",
            "/o3k/v1/volume/volumes",
            "/o3k/v1/network/address-realms",
            "/o3k/v1/operations",
            "/o3k/v1/operations/{id}",
            "/o3k/v1/audit",
            "/o3k/v1/audit/{id}",
            "/o3k/v1/quota",
            "/o3k/v1/quota/{namespace}/{dimension}",
            "/o3k/v1/operator/quotas/{project}",
            "/o3k/v1/operator/quotas/{project}/{namespace}/{dimension}",
            "/o3k/v1/operator/diagnostics",
            "/o3k/v1/operator/diagnostics/services",
            "/o3k/v1/operator/diagnostics/providers",
            "/o3k/v1/operator/diagnostics/capacity",
            "/o3k/v1/metering/definitions",
            "/o3k/v1/metering/usage",
            "/o3k/v1/operator/governance/projects",
            "/o3k/v1/operator/governance/projects/{id}",
            "/o3k/v1/operator/governance/principals",
            "/o3k/v1/operator/governance/principals/{id}",
            "/o3k/v1/operator/governance/roles",
            "/o3k/v1/operator/governance/capabilities",
            "/o3k/v1/operator/governance/assignments",
            "/o3k/v1/operator/governance/assignments/{id}",
            "/o3k/v1/operator/governance/operator-assignments",
            "/o3k/v1/operator/governance/operator-assignments/{id}",
        ],
    })
}

// ── Service discovery ──────────────────────────────────────────────────────

#[derive(Serialize)]
pub struct DiscoveredService {
    id: String,
    namespace: String,
    service_version: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    ownership: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    lifecycle_state: Option<String>,
}

#[derive(Serialize)]
pub struct ServicesResponse {
    services: Vec<DiscoveredService>,
    count: usize,
}

pub async fn discover_services(State(state): State<NativeApiState>) -> impl IntoResponse {
    let Some(registry) = state.lifecycle_registry.as_ref() else {
        return (
            StatusCode::OK,
            Json(serde_json::json!({"services": [], "count": 0})),
        )
            .into_response();
    };

    let Ok(registry) = registry.read() else {
        return (
            StatusCode::SERVICE_UNAVAILABLE,
            Json(serde_json::json!({"services": [], "count": 0})),
        )
            .into_response();
    };

    let services: Vec<DiscoveredService> = registry
        .all()
        .iter()
        .map(|m| {
            let lc = registry
                .lifecycle_state(&m.service_id)
                .map_or_else(|| "declared".to_owned(), |state| state.to_string());
            DiscoveredService {
                id: m.service_id.clone(),
                namespace: m.namespace.clone(),
                service_version: m.service_version.clone(),
                ownership: Some(m.ownership.to_string()),
                lifecycle_state: Some(lc),
            }
        })
        .collect();

    let count = services.len();
    (
        StatusCode::OK,
        Json(serde_json::to_value(ServicesResponse { services, count }).unwrap_or_default()),
    )
        .into_response()
}

// ── Resource-type discovery ────────────────────────────────────────────────

#[derive(Serialize)]
pub struct DiscoveredResourceType {
    namespace: String,
    name: String,
    service: String,
    schema_version: String,
    collection: String,
    scope: String,
    ready: bool,
    lifecycle_actions: std::collections::HashMap<String, String>,
    /// Placement scope derived from the owning service's canonical region
    /// declaration: `"global"` (no regional restriction) or `"regional"`.
    placement: String,
    /// Canonical region IDs the resource is available in (`regional` only).
    /// Empty for global resources so global placement is never falsely
    /// advertised as regional.
    #[serde(skip_serializing_if = "Vec::is_empty")]
    regions: Vec<String>,
    /// Availability-domain selection capability: `"unsupported"`, `"optional"`
    /// or `"required"`, derived from the owning service's canonical presence of
    /// a region/AZ declaration. Provider/host/backend identity is never
    /// exposed here.
    availability_domain_selection: String,
    schema: SchemaReference,
    actions: Vec<ActionSchemaMetadata>,
}

#[derive(Serialize, Clone)]
struct SchemaReference {
    id: String,
    version: String,
    representation: String,
}

#[derive(Serialize, Clone)]
struct ActionSchemaMetadata {
    name: String,
    action_id: String,
    target: String,
    input: Option<String>,
    output: Option<String>,
    asynchronous: bool,
}

fn schema_id(namespace: &str, collection: &str, version: &str) -> String {
    format!("https://o3k.io/schemas/{namespace}/{collection}/{version}/resource")
}

fn create_input_schema_id(namespace: &str, collection: &str, version: &str) -> String {
    format!(
        "{}#/allOf/1/properties/spec",
        schema_id(namespace, collection, version)
    )
}

fn action_metadata(
    descriptor: &ResourceDescriptor,
    collection_supported: bool,
) -> Vec<ActionSchemaMetadata> {
    // The same reachability rules as the lifecycle_actions projection: an
    // operation the runtime would reject must not appear in either field of
    // the discovery response.
    let create_reachable = create_reachable(descriptor);
    let mut actions: Vec<_> =
        descriptor
            .lifecycle_actions
            .iter()
            .filter(|(operation, _)| {
                (*operation != &LifecycleOperation::List || collection_supported)
                    && (*operation != &LifecycleOperation::Create || create_reachable)
            })
            .map(|(operation, action)| {
                let name = format!("{operation:?}").to_lowercase();
                let target = match operation {
                    LifecycleOperation::List | LifecycleOperation::Create => "collection",
                    LifecycleOperation::Show
                    | LifecycleOperation::Update
                    | LifecycleOperation::Delete => "instance",
                };
                ActionSchemaMetadata {
                name,
                action_id: action.to_string(),
                target: target.to_owned(),
                    input: match operation {
                    LifecycleOperation::Create => resource_contract::ContractKind::for_resource(
                        &descriptor.resource_type.to_string(),
                        &descriptor.schema_version,
                    ).map(|_| create_input_schema_id(
                        descriptor.resource_type.namespace(),
                        &descriptor.collection,
                        &descriptor.schema_version,
                    )),
                    _ => None,
                },
                output: Some(match operation {
                    LifecycleOperation::List =>
                        "https://o3k.io/contracts/native-resource-list-response-v1.schema.json",
                    LifecycleOperation::Show =>
                        "https://o3k.io/contracts/native-resource-envelope-v1.schema.json",
                    LifecycleOperation::Create
                    | LifecycleOperation::Update
                    | LifecycleOperation::Delete =>
                        "https://o3k.io/contracts/native-mutation-result-v1.schema.json",
                }.to_owned()),
                // Lifecycle mutations return a canonical operation_id. Reads
                // do not create operations, but are still represented here.
                asynchronous: matches!(
                    operation,
                    LifecycleOperation::Create
                        | LifecycleOperation::Update
                        | LifecycleOperation::Delete
                ),
            }
            })
            .collect();
    for (operation, action) in &descriptor.lifecycle_actions {
        if *operation == LifecycleOperation::Create && !create_reachable {
            continue;
        }
        if *operation == LifecycleOperation::List && !collection_supported {
            continue;
        }
        // The canonical action-name entry must agree with the operation-name
        // entry (and with contracts/cloud-kernel-actions.yaml): reads are
        // synchronous and carry read schemas; only mutations are
        // asynchronous with the mutation-result schema.
        let (target, asynchronous) = match operation {
            LifecycleOperation::List | LifecycleOperation::Create => ("collection", false),
            LifecycleOperation::Show | LifecycleOperation::Update | LifecycleOperation::Delete => {
                ("instance", false)
            }
        };
        let asynchronous = asynchronous
            || matches!(
                operation,
                LifecycleOperation::Create
                    | LifecycleOperation::Update
                    | LifecycleOperation::Delete
            );
        let input = match operation {
            LifecycleOperation::Create => resource_contract::ContractKind::for_resource(
                &descriptor.resource_type.to_string(),
                &descriptor.schema_version,
            )
            .map(|_| {
                create_input_schema_id(
                    descriptor.resource_type.namespace(),
                    &descriptor.collection,
                    &descriptor.schema_version,
                )
            }),
            _ => None,
        };
        let output = match operation {
            LifecycleOperation::List => {
                "https://o3k.io/contracts/native-resource-list-response-v1.schema.json"
            }
            LifecycleOperation::Show => {
                "https://o3k.io/contracts/native-resource-envelope-v1.schema.json"
            }
            LifecycleOperation::Create
            | LifecycleOperation::Update
            | LifecycleOperation::Delete => {
                "https://o3k.io/contracts/native-mutation-result-v1.schema.json"
            }
        };
        actions.push(ActionSchemaMetadata {
            name: action.action().to_owned(),
            action_id: action.to_string(),
            target: target.to_owned(),
            input,
            output: Some(output.to_owned()),
            asynchronous,
        });
    }
    actions.sort_by(|a, b| a.name.cmp(&b.name));
    actions
}

#[derive(Serialize)]
pub struct ResourceTypesResponse {
    resource_types: Vec<DiscoveredResourceType>,
    count: usize,
}

/// Derives the generic placement semantics for an owning service manifest.
///
/// Placement is *derived* from the single canonical manifest region/AZ
/// declaration — there is no separate placement authority that could drift.
/// Global/regional scope is mutually exclusive by construction (both are
/// functions of the same `regions` field); availability-domain selection is
/// orthogonal placement metadata (see ADR-0181/SPEC-0038).
///
/// Returns `(scope, canonical_regions, availability_domain_selection)`.
async fn placement_for_service(
    manifest: &ServiceManifest,
    locations: Option<&topology::TopologyGuard>,
) -> (String, Vec<String>, String) {
    let location_ids = match locations {
        Some(guard) => guard
            .read_regions()
            .await
            .iter()
            .map(|region| region.id.clone())
            .collect::<std::collections::BTreeSet<_>>(),
        None => std::collections::BTreeSet::new(),
    };

    // Only disclose region IDs that are canonical O3K location identity.
    // Declared-but-unknown regions are filtered out (fail closed).
    let mut regions: Vec<String> = manifest
        .regions
        .iter()
        .filter(|region| location_ids.contains(region.as_str()))
        .cloned()
        .collect();
    regions.sort();
    regions.dedup();

    let scope = if manifest.regions.is_empty() {
        "global".to_owned()
    } else {
        "regional".to_owned()
    };

    let availability_domain_selection = if manifest.availability_domains.is_empty() {
        "unsupported".to_owned()
    } else if manifest.regions.is_empty() {
        "required".to_owned()
    } else {
        "optional".to_owned()
    };

    (scope, regions, availability_domain_selection)
}

/// Mirrors the generic create handler's reachability rule (`resource::create`):
/// a create is executable only when a public create contract exists for the
/// descriptor, or the resource is owned by an external controller that
/// validates its own contract at its boundary. A manifest declaration alone
/// must not advertise a create that the runtime fails closed with 503.
fn create_reachable(descriptor: &ResourceDescriptor) -> bool {
    crate::resource_contract::ContractKind::for_resource(
        &descriptor.resource_type.to_string(),
        &descriptor.schema_version,
    )
    .is_some()
        || descriptor.ownership == o3k_kernel::ServiceOwnership::ExternalController
}

pub async fn discover_resource_types(State(state): State<NativeApiState>) -> impl IntoResponse {
    if state.lifecycle_registry.is_none() {
        return (
            StatusCode::OK,
            Json(serde_json::json!({"resource_types": [], "count": 0})),
        )
            .into_response();
    };

    let mut resource_types: Vec<DiscoveredResourceType> = Vec::new();
    for descriptor in state.resource_index.all() {
        let live_ready = state.resource_index.is_ready(descriptor);
        let application_present = state.resource_application.is_some();
        let collection_supported = application_present
            && state.cursor_config.is_available()
            && state
                .resource_application
                .as_ref()
                .is_some_and(|application| application.supports_collection(descriptor));
        let mut actions = std::collections::HashMap::new();
        for (op, action) in &descriptor.lifecycle_actions {
            // Every advertised operation must be executable in the live
            // composition: readiness and a configured resource application
            // gate all operations (a not-ready resource, or a discovery
            // surface without an application, must not advertise
            // show/create/delete either), list additionally requires bounded
            // collection support, and create additionally requires a
            // reachable create contract. Advertising an operation the
            // runtime would reject violates the advertised-implies-executable
            // discovery contract (#907).
            if !live_ready || !application_present {
                continue;
            }
            if *op == LifecycleOperation::List && !collection_supported {
                continue;
            }
            if *op == LifecycleOperation::Create && !create_reachable(descriptor) {
                continue;
            }
            actions.insert(format!("{op:?}").to_lowercase(), action.to_string());
        }
        let owning_service = state
            .lifecycle_registry
            .as_ref()
            .and_then(|registry| registry.read().ok())
            .and_then(|registry| registry.get(&descriptor.owning_service).cloned())
            .unwrap_or_else(|| ServiceManifest {
                manifest_version: 1,
                service_id: descriptor.owning_service.clone(),
                namespace: descriptor.resource_type.namespace().to_owned(),
                service_version: String::new(),
                ownership: o3k_kernel::ServiceOwnership::O3kImplemented,
                resource_types: vec![],
                actions: vec![],
                capabilities: vec![],
                dependencies: vec![],
                quota_dimensions: vec![],
                regions: vec![],
                availability_domains: vec![],
                controller: None,
                health: None,
            });
        let (placement, regions, availability_domain_selection) =
            placement_for_service(&owning_service, state.locations.as_deref()).await;
        resource_types.push(DiscoveredResourceType {
            namespace: descriptor.resource_type.namespace().to_owned(),
            name: descriptor.resource_type.name().to_owned(),
            service: descriptor.owning_service.clone(),
            schema_version: descriptor.schema_version.clone(),
            collection: descriptor.collection.clone(),
            scope: descriptor.scope.to_string(),
            ready: live_ready,
            lifecycle_actions: actions,
            placement,
            regions,
            availability_domain_selection,
            schema: SchemaReference {
                id: schema_id(
                    descriptor.resource_type.namespace(),
                    &descriptor.collection,
                    &descriptor.schema_version,
                ),
                version: descriptor.schema_version.clone(),
                representation: "native-resource-envelope".to_owned(),
            },
            actions: if live_ready && application_present {
                action_metadata(descriptor, collection_supported)
            } else {
                Vec::new()
            },
        });
    }
    resource_types.sort_by(|a, b| (&a.namespace, &a.name).cmp(&(&b.namespace, &b.name)));

    let count = resource_types.len();
    (
        StatusCode::OK,
        Json(
            serde_json::to_value(ResourceTypesResponse {
                resource_types,
                count,
            })
            .unwrap_or_default(),
        ),
    )
        .into_response()
}

#[derive(serde::Deserialize)]
pub struct ResourceSchemaPath {
    namespace: String,
    collection: String,
    version: String,
}

/// Returns the common envelope schema reference for a manifest-derived
/// resource descriptor. The version is resolved against the descriptor, so a
/// schema cannot be requested for an undeclared resource/version pair.
pub async fn discover_resource_schema(
    State(state): State<NativeApiState>,
    axum::extract::Path(path): axum::extract::Path<ResourceSchemaPath>,
) -> impl IntoResponse {
    let Some(descriptor) = state
        .resource_index
        .resolve(&path.namespace, &path.collection)
    else {
        return (
            StatusCode::NOT_FOUND,
            Json(serde_json::json!({"error": "resource schema not found"})),
        )
            .into_response();
    };
    if descriptor.schema_version != path.version {
        return (
            StatusCode::NOT_FOUND,
            Json(serde_json::json!({"error": "resource schema not found"})),
        )
            .into_response();
    }
    let resource_type = descriptor.resource_type.to_string();
    let Some(contract) =
        resource_contract::ContractKind::for_resource(&resource_type, &path.version)
    else {
        // A declared resource without a registered public contract must not
        // be advertised as the misleading `spec: object` contract.
        return (
            StatusCode::NOT_FOUND,
            Json(serde_json::json!({"error": "resource schema not available"})),
        )
            .into_response();
    };
    let spec_schema = contract.schema();
    (
        StatusCode::OK,
        Json(serde_json::json!({
            "$schema": "https://json-schema.org/draft/2020-12/schema",
            "$id": schema_id(&path.namespace, &path.collection, &path.version),
            "title": format!("O3K {}:{} resource {}", path.namespace, path.collection, path.version),
            "description": "Canonical native resource representation: the common envelope with a resource-specific, typed spec. Status remains represented only when returned by the owning service.",
            "allOf": [
                {"$ref": "https://o3k.io/contracts/native-resource-envelope-v1.schema.json"},
                {"type": "object", "properties": {"spec": spec_schema}, "required": ["spec"]}
            ],
            "x-o3k-resource-type": resource_type,
            "x-o3k-schema-version": descriptor.schema_version,
        })),
    ).into_response()
}

// ── Region location discovery ──────────────────────────────────────────────
//
// Exposes the canonical O3K location topology. O3K is the single authority for
// region and availability-domain identity; this endpoint never derives or
// invents locations from hosts, providers, or backends. See ADR-0181/SPEC-0038.

#[derive(Serialize)]
pub struct DiscoveredAvailabilityDomain {
    id: String,
}

#[derive(Serialize)]
pub struct DiscoveredRegion {
    id: String,
    #[serde(skip_serializing_if = "Vec::is_empty")]
    availability_domains: Vec<DiscoveredAvailabilityDomain>,
}

#[derive(Serialize)]
pub struct RegionsResponse {
    regions: Vec<DiscoveredRegion>,
    count: usize,
}

pub async fn discover_regions(State(state): State<NativeApiState>) -> impl IntoResponse {
    let Some(ref locations) = state.locations else {
        return (
            StatusCode::OK,
            Json(serde_json::json!({"regions": [], "count": 0})),
        )
            .into_response();
    };

    // Source regions from the shared topology guard; the wire shape is
    // byte-identical to the previous registry-direct projection.
    let regions: Vec<DiscoveredRegion> = locations
        .read_regions()
        .await
        .iter()
        .map(|region| DiscoveredRegion {
            id: region.id.clone(),
            availability_domains: region
                .availability_domains
                .iter()
                .map(|az| DiscoveredAvailabilityDomain { id: az.id.clone() })
                .collect(),
        })
        .collect();

    let count = regions.len();
    (
        StatusCode::OK,
        Json(serde_json::to_value(RegionsResponse { regions, count }).unwrap_or_default()),
    )
        .into_response()
}

// ── Tests ─────────────────────────────────────────────────────────────────

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::panic)]
mod tests {
    use super::*;
    use o3k_kernel::manifest::{ManifestController, RegisteredResourceType, ResourceScope};
    use o3k_kernel::resource::ResourceType;
    use o3k_kernel::{
        AuthContext, OwnershipScope, Principal, PrincipalId, ScopeId, ScopeKind, ServiceManifest,
        UserPrincipal,
    };

    #[derive(Clone)]
    struct TestIssuer(AuthContext);

    #[async_trait::async_trait]
    impl auth::TokenIssuer for TestIssuer {
        async fn issue_native(
            &self,
            _request: &auth::NativeTokenRequestV1,
        ) -> Result<(String, serde_json::Value), error::ProblemDetails> {
            Err(error::ProblemDetails::unauthorized())
        }

        async fn auth_context(&self, _token: &str) -> Result<AuthContext, error::ProblemDetails> {
            Ok(self.0.clone())
        }
    }

    /// Discovery-only application stub: proves bounded collection support
    /// for every resource type without exercising any mutation.
    struct DiscoveryStubApplication;

    #[async_trait::async_trait]
    impl resource::ResourceApplication for DiscoveryStubApplication {
        fn supports_collection(&self, _descriptor: &resource::ResourceDescriptor) -> bool {
            true
        }

        async fn create(
            &self,
            _descriptor: &resource::ResourceDescriptor,
            _auth: &AuthContext,
            _request: resource::ValidatedCreateRequest,
            _idempotency_key: Option<&str>,
        ) -> Result<resource::MutationResult, resource::ResourceApplicationError> {
            Err(resource::ResourceApplicationError::UnsupportedOperation)
        }

        async fn delete(
            &self,
            _descriptor: &resource::ResourceDescriptor,
            _auth: &AuthContext,
            _id: &str,
            _idempotency_key: Option<&str>,
            _expected_generation: Option<i64>,
        ) -> Result<resource::MutationResult, resource::ResourceApplicationError> {
            Err(resource::ResourceApplicationError::UnsupportedOperation)
        }

        async fn update(
            &self,
            _descriptor: &resource::ResourceDescriptor,
            _auth: &AuthContext,
            _id: &str,
            _request: resource::ValidatedUpdateRequest,
            _idempotency_key: Option<&str>,
            _expected_generation: i64,
        ) -> Result<resource::MutationResult, resource::ResourceApplicationError> {
            Err(resource::ResourceApplicationError::UnsupportedOperation)
        }

        async fn action(
            &self,
            _descriptor: &resource::ResourceDescriptor,
            _auth: &AuthContext,
            _id: &str,
            _action: o3k_kernel::ActionId,
            _request: resource::ActionRequest,
            _idempotency_key: &str,
        ) -> Result<resource::MutationResult, resource::ResourceApplicationError> {
            Err(resource::ResourceApplicationError::UnsupportedOperation)
        }

        async fn list_page(
            &self,
            _descriptor: &resource::ResourceDescriptor,
            _auth: &AuthContext,
            _query: &pagination::ResourceQuery,
            _cursors: &pagination::CursorConfig,
        ) -> Result<pagination::ResourcePage<serde_json::Value>, resource::ResourceApplicationError>
        {
            Err(resource::ResourceApplicationError::UnsupportedOperation)
        }

        async fn show(
            &self,
            _descriptor: &resource::ResourceDescriptor,
            _auth: &AuthContext,
            _id: &str,
        ) -> Result<serde_json::Value, resource::ResourceApplicationError> {
            Err(resource::ResourceApplicationError::UnsupportedOperation)
        }

        async fn relationships(
            &self,
            _descriptor: &resource::ResourceDescriptor,
            _auth: &AuthContext,
            _id: &str,
            _query: &pagination::ResourceQuery,
            _cursors: &pagination::CursorConfig,
        ) -> Result<
            pagination::ResourcePage<resource::RelationshipView>,
            resource::ResourceApplicationError,
        > {
            Err(resource::ResourceApplicationError::UnsupportedOperation)
        }
    }

    fn test_operator_context(system: bool) -> AuthContext {
        AuthContext::new(
            Principal::User(UserPrincipal::new(
                PrincipalId::new_unchecked("operator-1"),
                "operator",
                None,
            )),
            OwnershipScope::new(
                ScopeId::new_unchecked(if system { "system" } else { "project-a" }),
                if system {
                    ScopeKind::System
                } else {
                    ScopeKind::Project
                },
                None,
                None,
            ),
            vec!["operator".to_owned()],
            1,
            2,
            "audit-test",
            "request-test",
            None,
        )
    }

    fn test_manifest_registry() -> ManifestRegistry {
        let mut reg = ManifestRegistry::new();
        let m = ServiceManifest {
            manifest_version: 1,
            service_id: "compute".to_owned(),
            namespace: "compute".to_owned(),
            service_version: "0.4.0".to_owned(),
            ownership: o3k_kernel::ServiceOwnership::O3kImplemented,
            resource_types: vec![
                RegisteredResourceType {
                    resource_type: ResourceType::new_unchecked("compute", "server"),
                    schema_version: "v1".to_owned(),
                    collection: None,
                    scope: ResourceScope::Tenant,
                    operations: std::collections::HashMap::new(),
                },
                RegisteredResourceType {
                    resource_type: ResourceType::new_unchecked("compute", "flavor"),
                    schema_version: "v1".to_owned(),
                    collection: None,
                    scope: ResourceScope::Tenant,
                    operations: std::collections::HashMap::new(),
                },
            ],
            actions: vec![
                "compute:ListServers".to_owned(),
                "compute:CreateServer".to_owned(),
                "compute:UpdateServer".to_owned(),
            ],
            capabilities: vec![],
            dependencies: vec![],
            quota_dimensions: vec![],
            regions: vec![],
            availability_domains: vec![],
            controller: Some(ManifestController {
                mode: "in-process".to_owned(),
                protocol: "in-process".to_owned(),
                protocol_version: "1.0".to_owned(),
                service_principal: None,
            }),
            health: None,
        };
        let _ = reg.register(m);
        reg
    }

    #[test]
    fn create_action_input_reference_targets_the_typed_spec_fragment() {
        assert_eq!(
            create_input_schema_id("compute", "servers", "v1"),
            "https://o3k.io/schemas/compute/servers/v1/resource#/allOf/1/properties/spec"
        );
    }

    #[tokio::test]
    async fn api_root_returns_version() {
        let state = NativeApiState::new(
            Some(test_manifest_registry()),
            pagination::CursorConfig::default(),
            None,
            None,
            None,
            None,
        )
        .unwrap();
        let app = router(state);
        let response = axum::http::Request::builder()
            .uri("/")
            .body(axum::body::Body::empty())
            .unwrap();
        let resp = axum::response::Response::from(
            tower::ServiceExt::oneshot(app, response).await.unwrap(),
        );
        assert_eq!(resp.status(), StatusCode::OK);
        let body: serde_json::Value = serde_json::from_slice(
            &axum::body::to_bytes(resp.into_body(), usize::MAX)
                .await
                .unwrap(),
        )
        .unwrap();
        assert_eq!(body["api_version"], "o3k.io/v1");
        assert!(
            body["endpoints"]
                .as_array()
                .unwrap()
                .iter()
                .any(|endpoint| endpoint == "/o3k/v1/identity/scopes")
        );
    }

    #[tokio::test]
    async fn operator_profile_route_is_server_authorized_and_system_scoped() {
        let state = NativeApiState::new(
            Some(test_manifest_registry()),
            pagination::CursorConfig::default(),
            Some(Arc::new(TestIssuer(test_operator_context(true)))),
            None,
            None,
            None,
        )
        .unwrap()
        .with_authorizer(Arc::new(o3k_kernel::StaticAuthorizer::standard()));
        let response = tower::ServiceExt::oneshot(
            router(state),
            axum::http::Request::builder()
                .uri("/operator/profile")
                .header("authorization", "Bearer test-token")
                .body(axum::body::Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();
        assert_eq!(response.status(), StatusCode::OK);

        let state = NativeApiState::new(
            Some(test_manifest_registry()),
            pagination::CursorConfig::default(),
            Some(Arc::new(TestIssuer(test_operator_context(false)))),
            None,
            None,
            None,
        )
        .unwrap()
        .with_authorizer(Arc::new(o3k_kernel::StaticAuthorizer::standard()));
        let response = tower::ServiceExt::oneshot(
            router(state),
            axum::http::Request::builder()
                .uri("/operator/profile")
                .header("authorization", "Bearer test-token")
                .body(axum::body::Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();
        assert_eq!(response.status(), StatusCode::FORBIDDEN);
    }

    #[tokio::test]
    async fn federated_scope_discovery_rejects_empty_external_credentials() {
        let state = NativeApiState::new(
            Some(test_manifest_registry()),
            pagination::CursorConfig::default(),
            Some(Arc::new(TestIssuer(test_operator_context(false)))),
            None,
            None,
            None,
        )
        .unwrap();
        let response = tower::ServiceExt::oneshot(
            router(state),
            axum::http::Request::builder()
                .method("POST")
                .uri("/identity/scopes")
                .header("content-type", "application/json")
                .body(axum::body::Body::from(
                    r#"{"federated":{"access_token":""}}"#,
                ))
                .unwrap(),
        )
        .await
        .unwrap();
        assert_eq!(response.status(), StatusCode::BAD_REQUEST);
    }

    #[tokio::test]
    async fn discover_services_uses_manifest_registry() {
        let state = NativeApiState::new(
            Some(test_manifest_registry()),
            pagination::CursorConfig::default(),
            None,
            None,
            None,
            None,
        )
        .unwrap();
        let app = router(state);
        let response = axum::http::Request::builder()
            .uri("/services")
            .body(axum::body::Body::empty())
            .unwrap();
        let resp = axum::response::Response::from(
            tower::ServiceExt::oneshot(app, response).await.unwrap(),
        );
        assert_eq!(resp.status(), StatusCode::OK);
        let body: serde_json::Value = serde_json::from_slice(
            &axum::body::to_bytes(resp.into_body(), usize::MAX)
                .await
                .unwrap(),
        )
        .unwrap();
        assert_eq!(body["count"].as_u64().unwrap_or(0), 1);
        assert_eq!(body["services"][0]["namespace"], "compute");
        assert_eq!(body["services"][0]["lifecycle_state"], "declared");
        assert_eq!(body["services"][0]["ownership"], "o3k-implemented");
    }

    #[tokio::test]
    async fn discover_services_stable_wire_values() {
        let mut reg = ManifestRegistry::new();
        reg.seed_core().unwrap();
        let state = NativeApiState::new(
            Some(reg),
            pagination::CursorConfig::default(),
            None,
            None,
            None,
            None,
        )
        .unwrap();
        let app = router(state);
        let response = axum::http::Request::builder()
            .uri("/services")
            .body(axum::body::Body::empty())
            .unwrap();
        let resp = axum::response::Response::from(
            tower::ServiceExt::oneshot(app, response).await.unwrap(),
        );
        assert_eq!(resp.status(), StatusCode::OK);
        let body: serde_json::Value = serde_json::from_slice(
            &axum::body::to_bytes(resp.into_body(), usize::MAX)
                .await
                .unwrap(),
        )
        .unwrap();
        let services = body["services"].as_array().unwrap();
        assert!(services.len() >= 3, "expected at least 3 seeded services");
        for svc in services {
            let lc = svc["lifecycle_state"].as_str().unwrap_or("");
            assert!(
                ["declared", "ready", "not_ready", "disabled", "incompatible"].contains(&lc),
                "unexpected lifecycle_state: {lc}"
            );
            let ownership = svc["ownership"].as_str().unwrap_or("");
            assert!(
                ["o3k-implemented", "external-hosted"].contains(&ownership),
                "unexpected ownership: {ownership}"
            );
        }
    }

    #[tokio::test]
    async fn discover_resource_types_from_manifest_registry() {
        let mut registry = ManifestRegistry::new();
        registry.seed_core().unwrap();
        let state = NativeApiState::new(
            Some(registry),
            pagination::CursorConfig::default(),
            None,
            None,
            None,
            None,
        )
        .unwrap();
        let app = router(state);
        let response = axum::http::Request::builder()
            .uri("/resource-types")
            .body(axum::body::Body::empty())
            .unwrap();
        let resp = axum::response::Response::from(
            tower::ServiceExt::oneshot(app, response).await.unwrap(),
        );
        assert_eq!(resp.status(), StatusCode::OK);
        let body: serde_json::Value = serde_json::from_slice(
            &axum::body::to_bytes(resp.into_body(), usize::MAX)
                .await
                .unwrap(),
        )
        .unwrap();
        assert!(body["count"].as_u64().unwrap_or(0) >= 2);
        let kinds: Vec<String> = body["resource_types"]
            .as_array()
            .into_iter()
            .flatten()
            .filter_map(|item| {
                Some(format!(
                    "{}:{}",
                    item["namespace"].as_str()?,
                    item["name"].as_str()?
                ))
            })
            .collect();
        assert!(kinds.iter().any(|kind| kind == "compute:server"));
        assert!(kinds.iter().any(|kind| kind == "network:address_realm"));
        assert!(kinds.iter().any(|kind| kind == "volume:volume"));
    }

    #[tokio::test]
    async fn discovery_advertises_only_reachable_lifecycle_operations() {
        let mut registry = ManifestRegistry::new();
        registry.seed_core().unwrap();
        // Compute and network have ready controllers in this composition;
        // volume deliberately has none (mirrors a profile without a native
        // storage provider).
        registry
            .register_in_process_controller("compute", true, None)
            .unwrap();
        registry
            .register_in_process_controller("network", true, None)
            .unwrap();
        let state = NativeApiState::new(
            Some(registry),
            pagination::CursorConfig::new(b"discovery-test-cursor-key-0123456789".to_vec())
                .unwrap(),
            None,
            None,
            None,
            None,
        )
        .unwrap()
        .with_resource_application(std::sync::Arc::new(DiscoveryStubApplication));
        let app = router(state);
        let response = axum::http::Request::builder()
            .uri("/resource-types")
            .body(axum::body::Body::empty())
            .unwrap();
        let resp = axum::response::Response::from(
            tower::ServiceExt::oneshot(app, response).await.unwrap(),
        );
        assert_eq!(resp.status(), StatusCode::OK);
        let body: serde_json::Value = serde_json::from_slice(
            &axum::body::to_bytes(resp.into_body(), usize::MAX)
                .await
                .unwrap(),
        )
        .unwrap();
        let find = |namespace: &str, name: &str| {
            body["resource_types"]
                .as_array()
                .into_iter()
                .flatten()
                .find(|item| item["namespace"] == namespace && item["name"] == name)
                .cloned()
                .unwrap_or_else(|| panic!("missing {namespace}:{name}"))
        };
        let lifecycle_of = |item: &serde_json::Value| -> Vec<String> {
            item["lifecycle_actions"]
                .as_object()
                .into_iter()
                .flatten()
                .map(|(key, _)| key.clone())
                .collect()
        };
        // Contract-backed native creates stay advertised; the stub proves
        // collection support, so list appears too.
        let compute = find("compute", "server");
        let compute_ops = lifecycle_of(&compute);
        for op in ["create", "show", "update", "delete"] {
            assert!(
                compute_ops.iter().any(|key| key == op),
                "compute:server must advertise {op}: {compute}"
            );
        }
        assert!(
            compute_ops.iter().any(|key| key == "list"),
            "list must be advertised with collection support: {compute}"
        );
        // network:network has a create contract; network:subnet does not and
        // is o3k-implemented, so advertising its create would promise a route
        // that fails closed with 503 at runtime.
        let network = find("network", "network");
        assert!(
            lifecycle_of(&network).iter().any(|key| key == "create"),
            "network:network has a public create contract: {network}"
        );
        let subnet = find("network", "subnet");
        assert!(
            !lifecycle_of(&subnet).iter().any(|key| key == "create"),
            "network:subnet create is not reachable; it must not be advertised: {subnet}"
        );
        for op in ["show", "delete"] {
            assert!(
                lifecycle_of(&subnet).iter().any(|key| key == op),
                "network:subnet must still advertise reachable {op}: {subnet}"
            );
        }
        // The `actions` array must apply the same reachability rule: no
        // create entry for a resource whose create fails closed at runtime.
        let subnet_actions: Vec<&str> = subnet["actions"]
            .as_array()
            .into_iter()
            .flatten()
            .filter_map(|action| action["name"].as_str())
            .collect();
        assert!(
            !subnet_actions.contains(&"create"),
            "network:subnet actions must not advertise create: {subnet}"
        );
        assert!(
            !subnet_actions.contains(&"CreateSubnet"),
            "network:subnet actions must not advertise the canonical create action either: {subnet}"
        );
        // Canonical action-name entries must agree with the operation-name
        // entries (and contracts/cloud-kernel-actions.yaml): reads are
        // synchronous with read schemas; create targets the collection with
        // the create-schema input.
        let compute_action = |name: &str| {
            compute["actions"]
                .as_array()
                .into_iter()
                .flatten()
                .find(|action| action["name"] == name)
                .cloned()
                .unwrap_or_else(|| panic!("missing actions entry {name}: {compute}"))
        };
        let create_meta = compute_action("CreateServer");
        assert_eq!(create_meta["target"], "collection", "{create_meta}");
        assert_eq!(create_meta["asynchronous"], true, "{create_meta}");
        assert!(
            create_meta["input"]
                .as_str()
                .is_some_and(|input| input.contains("/resource")),
            "create input must reference the create schema: {create_meta}"
        );
        let read_meta = compute_action("ReadServer");
        assert_eq!(read_meta["target"], "instance", "{read_meta}");
        assert_eq!(read_meta["asynchronous"], false, "{read_meta}");
        assert!(
            read_meta["output"]
                .as_str()
                .is_some_and(|output| output.contains("native-resource-envelope")),
            "read output must be the envelope schema: {read_meta}"
        );
        // A service without a ready controller advertises no lifecycle
        // operations at all (previously only list was readiness-gated).
        let volume = find("volume", "volume");
        assert_eq!(volume["ready"], false, "{volume}");
        assert!(
            lifecycle_of(&volume).is_empty(),
            "a not-ready resource must advertise no lifecycle operations: {volume}"
        );
    }

    #[tokio::test]
    async fn resource_discovery_tracks_shared_readiness_transition() {
        let mut registry = ManifestRegistry::new();
        registry.seed_core().unwrap();
        registry
            .register_in_process_controller("compute", true, None)
            .unwrap();
        let state = NativeApiState::new(
            Some(registry),
            pagination::CursorConfig::default(),
            None,
            None,
            None,
            None,
        )
        .unwrap();
        let lifecycle = state.lifecycle_registry().unwrap();
        let app = router(state);

        let request = || {
            axum::http::Request::builder()
                .uri("/resource-types")
                .body(axum::body::Body::empty())
                .unwrap()
        };
        let response = tower::ServiceExt::oneshot(app.clone(), request())
            .await
            .unwrap();
        let body: serde_json::Value = serde_json::from_slice(
            &axum::body::to_bytes(response.into_body(), usize::MAX)
                .await
                .unwrap(),
        )
        .unwrap();
        let compute = body["resource_types"]
            .as_array()
            .unwrap()
            .iter()
            .find(|resource| resource["service"] == "compute")
            .unwrap();
        assert!(compute["ready"].as_bool().unwrap());

        lifecycle
            .write()
            .unwrap()
            .update_controller_health(
                "compute",
                o3k_kernel::controller::ControllerHealth {
                    healthy: false,
                    detail: Some("provider unavailable".to_owned()),
                    protocol_version: o3k_kernel::controller::ProtocolVersion::V1,
                },
            )
            .unwrap();

        let response = tower::ServiceExt::oneshot(app, request()).await.unwrap();
        let body: serde_json::Value = serde_json::from_slice(
            &axum::body::to_bytes(response.into_body(), usize::MAX)
                .await
                .unwrap(),
        )
        .unwrap();
        let compute = body["resource_types"]
            .as_array()
            .unwrap()
            .iter()
            .find(|resource| resource["service"] == "compute")
            .unwrap();
        assert!(!compute["ready"].as_bool().unwrap());
    }

    #[tokio::test]
    async fn endpoint_without_bearer_returns_401() {
        let state = NativeApiState::default();
        let app = router(state);
        // Identity/me requires auth
        let response = axum::http::Request::builder()
            .uri("/identity/me")
            .body(axum::body::Body::empty())
            .unwrap();
        let resp = axum::response::Response::from(
            tower::ServiceExt::oneshot(app, response).await.unwrap(),
        );
        assert_eq!(resp.status(), StatusCode::UNAUTHORIZED);
        assert_eq!(
            resp.headers()
                .get("Content-Type")
                .unwrap()
                .to_str()
                .unwrap(),
            "application/problem+json"
        );
    }

    #[derive(Clone)]
    struct TestAuditReader {
        events: Arc<Vec<o3k_kernel::AuditEvent>>,
        unavailable: bool,
    }

    #[async_trait::async_trait]
    impl audit::AuditReader for TestAuditReader {
        async fn list_page(
            &self,
            auth: &AuthContext,
            query: o3k_kernel::AuditQuery,
        ) -> Result<pagination::RepositoryPage<o3k_kernel::AuditEvent>, audit::AuditReadError>
        {
            if self.unavailable {
                return Err(audit::AuditReadError::Unavailable);
            }
            query
                .validate()
                .map_err(|_| audit::AuditReadError::InvalidPage)?;
            let mut events: Vec<_> = self
                .events
                .iter()
                .filter(|event| event.effective_scope == *auth.effective_scope())
                .filter(|event| {
                    query
                        .service
                        .as_deref()
                        .is_none_or(|v| event.service_namespace.as_str() == v)
                })
                .filter(|event| {
                    query
                        .action
                        .as_deref()
                        .is_none_or(|v| event.action.as_str() == v)
                })
                .filter(|event| {
                    query
                        .outcome
                        .as_deref()
                        .is_none_or(|v| event.outcome.to_string() == v)
                })
                .filter(|event| {
                    query
                        .after_event_id
                        .as_deref()
                        .is_none_or(|v| event.event_id.as_str() > v)
                })
                .cloned()
                .collect();
            events.sort_by(|a, b| a.event_id.cmp(&b.event_id));
            let start = query.limit.min(events.len());
            let has_more = events.len() > start;
            let continuation = has_more.then(|| events[start - 1].event_id.as_str().to_owned());
            events.truncate(start);
            pagination::RepositoryPage::new(events, has_more, continuation, query.limit)
                .map_err(|_| audit::AuditReadError::InvalidPage)
        }

        async fn show(
            &self,
            auth: &AuthContext,
            id: &str,
        ) -> Result<o3k_kernel::AuditEvent, audit::AuditReadError> {
            if self.unavailable {
                return Err(audit::AuditReadError::Unavailable);
            }
            self.events
                .iter()
                .find(|event| {
                    event.event_id.as_str() == id
                        && event.effective_scope == *auth.effective_scope()
                })
                .cloned()
                .ok_or(audit::AuditReadError::NotFound)
        }
    }

    fn audit_test_events() -> Arc<Vec<o3k_kernel::AuditEvent>> {
        use o3k_kernel::{ActionId, AuditEvent, AuditOutcome, EventId, ServiceNamespace};
        let auth = test_operator_context(false);
        let scope = auth.effective_scope().clone();
        let mut first = AuditEvent::from_auth(
            &auth,
            ServiceNamespace::new_unchecked("compute".to_owned()),
            ActionId::new_unchecked("compute", "CreateServer"),
            AuditOutcome::Succeeded,
        )
        .with_resource(
            o3k_kernel::ResourceType::new_unchecked("compute", "server"),
            Some(o3k_kernel::ResourceId::new_unchecked("server-1")),
            Some(scope.clone()),
        );
        first.event_id = EventId::from_string("0001".to_owned());
        let mut second = AuditEvent::from_auth(
            &auth,
            ServiceNamespace::new_unchecked("compute".to_owned()),
            ActionId::new_unchecked("compute", "DeleteServer"),
            AuditOutcome::Failed,
        );
        second.event_id = EventId::from_string("0002".to_owned());
        let mut foreign = AuditEvent::from_auth(
            &AuthContext::new(
                auth.principal().clone(),
                o3k_kernel::OwnershipScope::project(
                    o3k_kernel::ScopeId::new_unchecked("project-b"),
                    None,
                    None,
                ),
                vec!["member".to_owned()],
                1,
                2,
                "audit-b",
                "request-b",
                None,
            ),
            ServiceNamespace::new_unchecked("image".to_owned()),
            ActionId::new_unchecked("image", "CreateImage"),
            AuditOutcome::Denied,
        );
        foreign.event_id = EventId::from_string("0003".to_owned());
        Arc::new(vec![first, second, foreign])
    }

    #[tokio::test]
    async fn audit_api_b0_contract_matrix() {
        let events = audit_test_events();
        let issuer = Arc::new(TestIssuer(test_operator_context(false)));
        let reader = Arc::new(TestAuditReader {
            events,
            unavailable: false,
        });
        let cursor = pagination::CursorConfig::new(vec![7; 32]).unwrap();
        let state = NativeApiState::new(
            Some(test_manifest_registry()),
            cursor,
            Some(issuer),
            None,
            None,
            None,
        )
        .unwrap()
        .with_audit_reader(reader);
        let app = router(state);
        let request = |uri: &str| {
            axum::http::Request::builder()
                .uri(uri)
                .header("authorization", "Bearer test-token")
                .header("x-request-id", "b0-request")
                .body(axum::body::Body::empty())
                .unwrap()
        };

        let response =
            tower::ServiceExt::oneshot(app.clone(), request("/audit?limit=1&service=compute"))
                .await
                .unwrap();
        assert_eq!(response.status(), StatusCode::OK); // A03/A05/A09/A11
        let body: serde_json::Value = serde_json::from_slice(
            &axum::body::to_bytes(response.into_body(), usize::MAX)
                .await
                .unwrap(),
        )
        .unwrap();
        assert_eq!(body["items"].as_array().unwrap().len(), 1);
        assert!(body["has_more"].as_bool().unwrap());
        let cursor = body["next_cursor"].as_str().unwrap().to_owned();

        let response = tower::ServiceExt::oneshot(
            app.clone(),
            request(&format!("/audit?limit=1&service=compute&cursor={cursor}")),
        )
        .await
        .unwrap();
        assert_eq!(response.status(), StatusCode::OK); // A04/A10/A12

        let response = tower::ServiceExt::oneshot(
            app.clone(),
            request(&format!("/audit?limit=1&service=image&cursor={cursor}")),
        )
        .await
        .unwrap();
        assert_eq!(response.status(), StatusCode::BAD_REQUEST); // A16 filter binding

        for uri in [
            "/audit?limit=0",
            "/audit?limit=201",
            "/audit?unknown=value",
            "/audit?cursor=not-a-cursor",
        ] {
            let response = tower::ServiceExt::oneshot(app.clone(), request(uri))
                .await
                .unwrap();
            assert_eq!(response.status(), StatusCode::BAD_REQUEST); // A15/A17/A18
        }

        let response = tower::ServiceExt::oneshot(app.clone(), request("/audit/0001"))
            .await
            .unwrap();
        assert_eq!(response.status(), StatusCode::OK); // A06/A07/A13/A14
        let response = tower::ServiceExt::oneshot(app.clone(), request("/audit/0003"))
            .await
            .unwrap();
        assert_eq!(response.status(), StatusCode::NOT_FOUND); // A04 isolation

        let response = tower::ServiceExt::oneshot(
            router(NativeApiState::default()),
            axum::http::Request::builder()
                .uri("/audit")
                .body(axum::body::Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();
        assert_eq!(response.status(), StatusCode::UNAUTHORIZED); // A03 auth

        let unavailable_state = NativeApiState::new(
            Some(test_manifest_registry()),
            pagination::CursorConfig::new(vec![7; 32]).unwrap(),
            Some(Arc::new(TestIssuer(test_operator_context(false)))),
            None,
            None,
            None,
        )
        .unwrap()
        .with_audit_reader(Arc::new(TestAuditReader {
            events: Arc::new(Vec::new()),
            unavailable: true,
        }));
        let response = tower::ServiceExt::oneshot(router(unavailable_state), request("/audit"))
            .await
            .unwrap();
        assert_eq!(response.status(), StatusCode::SERVICE_UNAVAILABLE);
    }

    // ── Location & placement discovery (issue #887) ────────────────────

    fn test_locations() -> o3k_kernel::LocationRegistry {
        use o3k_kernel::{AvailabilityDomain, RegionDeclaration};
        o3k_kernel::LocationRegistry::from_declarations(vec![
            RegionDeclaration {
                id: "region-a".to_owned(),
                availability_domains: vec![
                    AvailabilityDomain {
                        id: "az-1".to_owned(),
                    },
                    AvailabilityDomain {
                        id: "az-2".to_owned(),
                    },
                ],
            },
            RegionDeclaration {
                id: "region-b".to_owned(),
                availability_domains: vec![AvailabilityDomain {
                    id: "az-3".to_owned(),
                }],
            },
        ])
        .unwrap()
    }

    /// Builds a manifest declaring the given canonical region/AZ scope.
    ///
    /// Uses real O3K resource types (`image:image`, `network:address_realm`,
    /// `volume:volume`) rather than fictional test concepts.
    fn scoped_manifest(
        service_id: &str,
        namespace: &str,
        resource_type_name: &str,
        regions: Vec<&str>,
        availability_domains: Vec<&str>,
    ) -> ServiceManifest {
        ServiceManifest {
            manifest_version: 1,
            service_id: service_id.to_owned(),
            namespace: namespace.to_owned(),
            service_version: "0.4.0".to_owned(),
            ownership: o3k_kernel::ServiceOwnership::O3kImplemented,
            resource_types: vec![RegisteredResourceType {
                resource_type: ResourceType::new_unchecked(namespace, resource_type_name),
                schema_version: "v1".to_owned(),
                collection: None,
                scope: ResourceScope::Tenant,
                operations: std::collections::HashMap::new(),
            }],
            actions: vec![format!("{namespace}:ListPrimary")],
            capabilities: vec![],
            dependencies: vec![],
            quota_dimensions: vec![],
            regions: regions.into_iter().map(ToOwned::to_owned).collect(),
            availability_domains: availability_domains
                .into_iter()
                .map(ToOwned::to_owned)
                .collect(),
            controller: Some(ManifestController {
                mode: "in-process".to_owned(),
                protocol: "in-process".to_owned(),
                protocol_version: "1.0".to_owned(),
                service_principal: None,
            }),
            health: None,
        }
    }

    fn state_with_locations(
        registry: Option<ManifestRegistry>,
        locations: Option<o3k_kernel::LocationRegistry>,
    ) -> NativeApiState {
        NativeApiState::new(
            registry,
            pagination::CursorConfig::default(),
            None,
            None,
            None,
            None,
        )
        .unwrap()
        .with_locations(Arc::new(crate::topology::TopologyGuard::new(
            locations.unwrap_or_default(),
        )))
    }

    async fn get_json(state: NativeApiState, uri: &str) -> (StatusCode, serde_json::Value) {
        let resp = axum::response::Response::from(
            tower::ServiceExt::oneshot(
                router(state),
                axum::http::Request::builder()
                    .uri(uri)
                    .body(axum::body::Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap(),
        );
        let status = resp.status();
        let body: serde_json::Value = serde_json::from_slice(
            &axum::body::to_bytes(resp.into_body(), usize::MAX)
                .await
                .unwrap(),
        )
        .unwrap();
        (status, body)
    }

    #[tokio::test]
    async fn discover_regions_exposes_multiple_configured_regions() {
        let (status, body) = get_json(
            state_with_locations(None, Some(test_locations())),
            "/regions",
        )
        .await;
        assert_eq!(status, StatusCode::OK);
        assert_eq!(body["count"].as_u64().unwrap_or(0), 2);
        let ids: Vec<&str> = body["regions"]
            .as_array()
            .unwrap()
            .iter()
            .filter_map(|region| region["id"].as_str())
            .collect();
        assert!(ids.contains(&"region-a"));
        assert!(ids.contains(&"region-b"));
        assert_location_discovery_schema(&body);
    }

    #[tokio::test]
    async fn discover_regions_region_has_multiple_availability_domains() {
        let (_, body) = get_json(
            state_with_locations(None, Some(test_locations())),
            "/regions",
        )
        .await;
        let region_a = body["regions"]
            .as_array()
            .unwrap()
            .iter()
            .find(|region| region["id"] == "region-a")
            .unwrap();
        let azs: Vec<&str> = region_a["availability_domains"]
            .as_array()
            .unwrap()
            .iter()
            .filter_map(|az| az["id"].as_str())
            .collect();
        assert!(azs.contains(&"az-1"));
        assert!(azs.contains(&"az-2"));
    }

    #[tokio::test]
    async fn discover_regions_order_is_deterministic() {
        // Declare regions in non-sorted order so the test genuinely exercises
        // the endpoint's deterministic ordering (would fail if sorting dropped).
        use o3k_kernel::{AvailabilityDomain, RegionDeclaration};
        let unsorted_input = o3k_kernel::LocationRegistry::from_declarations(vec![
            RegionDeclaration {
                id: "region-b".to_owned(),
                availability_domains: Vec::new(),
            },
            RegionDeclaration {
                id: "region-a".to_owned(),
                availability_domains: vec![AvailabilityDomain {
                    id: "az-1".to_owned(),
                }],
            },
        ])
        .unwrap();
        let (_, body) =
            get_json(state_with_locations(None, Some(unsorted_input)), "/regions").await;
        let ids: Vec<String> = body["regions"]
            .as_array()
            .unwrap()
            .iter()
            .filter_map(|region| region["id"].as_str().map(ToOwned::to_owned))
            .collect();
        assert_eq!(ids, vec!["region-a".to_owned(), "region-b".to_owned()]);
    }

    #[tokio::test]
    async fn discover_regions_empty_when_none_configured() {
        let (status, body) = get_json(state_with_locations(None, None), "/regions").await;
        assert_eq!(status, StatusCode::OK);
        assert_eq!(body["count"].as_u64().unwrap_or(1), 0);
        assert_eq!(body["regions"].as_array().unwrap().len(), 0);
    }

    #[tokio::test]
    async fn resource_type_global_does_not_advertise_regional_placement() {
        let mut registry = ManifestRegistry::new();
        registry
            .register(scoped_manifest("image", "image", "image", vec![], vec![]))
            .unwrap();
        let (_, body) = get_json(
            state_with_locations(Some(registry), Some(test_locations())),
            "/resource-types",
        )
        .await;
        let resource = &body["resource_types"][0];
        assert_eq!(resource["placement"], "global");
        // `regions` must be entirely absent for a global resource (never an
        // empty or populated regional advertisement).
        assert!(
            resource.get("regions").is_none(),
            "global resource must not advertise regional placement"
        );
        assert_eq!(resource["availability_domain_selection"], "unsupported");
    }

    #[tokio::test]
    async fn resource_type_regional_exposes_only_authoritative_regions() {
        let mut registry = ManifestRegistry::new();
        // Declares one canonical region and one unknown region; only the
        // canonical region may be disclosed (fail closed on unknown).
        registry
            .register(scoped_manifest(
                "network",
                "network",
                "address_realm",
                vec!["region-a", "region-b", "ghost-region"],
                vec![],
            ))
            .unwrap();
        let (_, body) = get_json(
            state_with_locations(Some(registry), Some(test_locations())),
            "/resource-types",
        )
        .await;
        let resource = &body["resource_types"][0];
        assert_eq!(resource["placement"], "regional");
        let regions: Vec<String> = resource["regions"]
            .as_array()
            .unwrap()
            .iter()
            .filter_map(|region| region.as_str().map(ToOwned::to_owned))
            .collect();
        assert_eq!(regions, vec!["region-a".to_owned(), "region-b".to_owned()]);
        assert!(!regions.contains(&"ghost-region".to_owned()));
    }

    #[tokio::test]
    async fn resource_type_regional_exposes_only_declared_canonical_subset() {
        let mut registry = ManifestRegistry::new();
        // region-b is canonical but the service only declares region-a: the
        // disclosed regions must be exactly the declared subset, never all
        // canonical regions.
        registry
            .register(scoped_manifest(
                "network",
                "network",
                "address_realm",
                vec!["region-a"],
                vec![],
            ))
            .unwrap();
        let (_, body) = get_json(
            state_with_locations(Some(registry), Some(test_locations())),
            "/resource-types",
        )
        .await;
        let resource = &body["resource_types"][0];
        assert_eq!(resource["placement"], "regional");
        let regions: Vec<String> = resource["regions"]
            .as_array()
            .unwrap()
            .iter()
            .filter_map(|region| region.as_str().map(ToOwned::to_owned))
            .collect();
        assert_eq!(regions, vec!["region-a".to_owned()]);
    }

    #[tokio::test]
    async fn resource_type_az_aware_exposes_capability_without_provider_leakage() {
        let mut registry = ManifestRegistry::new();
        registry
            .register(scoped_manifest(
                "volume",
                "volume",
                "volume",
                vec!["region-a"],
                vec!["az-1"],
            ))
            .unwrap();
        let (_, body) = get_json(
            state_with_locations(Some(registry), Some(test_locations())),
            "/resource-types",
        )
        .await;
        let resource = &body["resource_types"][0];
        assert_eq!(resource["placement"], "regional");
        assert_eq!(resource["availability_domain_selection"], "optional");
        // No provider/host/backend identity is ever disclosed: the placement
        // payload contains only canonical region/AZ IDs and capability verbs.
        let serialized = serde_json::to_string(resource).unwrap();
        for leaked in [
            "provider",
            "hypervisor",
            "ceph",
            "node-id",
            "pool-name",
            "backend",
        ] {
            assert!(
                !serialized.contains(leaked),
                "provider/host/backend token {leaked} leaked into placement"
            );
        }
    }

    #[tokio::test]
    async fn resource_type_az_required_when_only_az_declared() {
        let mut registry = ManifestRegistry::new();
        registry
            .register(scoped_manifest(
                "volume",
                "volume",
                "volume",
                vec![],
                vec!["az-1", "az-2"],
            ))
            .unwrap();
        let (_, body) = get_json(
            state_with_locations(Some(registry), Some(test_locations())),
            "/resource-types",
        )
        .await;
        assert_eq!(
            body["resource_types"][0]["availability_domain_selection"],
            "required"
        );
    }

    #[tokio::test]
    async fn resource_types_order_is_deterministic() {
        let mut registry = ManifestRegistry::new();
        registry.seed_core().unwrap();
        let state = state_with_locations(Some(registry), Some(test_locations()));
        for _ in 0..3 {
            let (_, body) = get_json(state.clone(), "/resource-types").await;
            let keys: Vec<String> = body["resource_types"]
                .as_array()
                .unwrap()
                .iter()
                .map(|r| format!("{}:{}", r["namespace"], r["name"]))
                .collect();
            assert_eq!(keys, {
                let mut sorted = keys.clone();
                sorted.sort();
                sorted
            });
        }
    }
}
