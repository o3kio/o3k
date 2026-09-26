use std::{collections::BTreeMap, sync::Arc};

use o3k_domain::{
    AttachmentAccessMode, StorageExecutionScope, Volume, VolumeAttachment, VolumeAttachmentId,
    VolumeAttachmentState, VolumeId, VolumeState,
};
use o3k_kernel::{Controller, LifecycleMeteringObserver};
use o3k_native_api::{
    compute::ServerItem,
    network::AddressRealmItem,
    resource::{
        ActionRequest, MutationResult, ResourceApplication, ResourceApplicationError,
        ResourceDescriptor, ValidatedCreateRequest, VolumeAttachmentWorkflow,
    },
};
use o3k_store::{DurableStore, storage::StorageRepository};
use uuid::Uuid;

#[async_trait::async_trait]
pub trait PublicAddressWorkflow: Send + Sync {
    async fn remove(&self, project_id: &str, allocation_id: Uuid) -> Result<(), String>;
}

/// Application adapter for generic native resource reads and mutations.
pub struct GenericResourceApplication {
    pub compute: Arc<o3k_compute::ComputeService>,
    pub image: Option<Arc<o3k_image::ImageService>>,
    pub network_service: Arc<o3k_network::NetworkService>,
    pub store: Arc<o3k_store::unified::O3kStore>,
    pub storage_provider: Option<Arc<dyn o3k_storage::StorageProvider>>,
    pub server: Arc<dyn o3k_native_api::compute::ServerReader>,
    pub network: Arc<dyn o3k_native_api::network::NetworkReader>,
    pub external_controllers: Arc<BTreeMap<String, Arc<o3k_service_sdk::GrpcControllerAdapter>>>,
    pub public_allocator: Option<Arc<o3k_network::PublicAddressAllocator>>,
    pub public_address_workflow: Option<Arc<dyn PublicAddressWorkflow>>,
    pub network_external_realm_id: Option<Uuid>,
    pub attachment_workflow: Option<Arc<dyn VolumeAttachmentWorkflow>>,
    /// Optional projection of canonical volume allocation into metering
    /// authority. `None` disables metering (tests and profiles without a
    /// metering authority); the composition root attaches the production
    /// adapter so a durably created or deleted volume opens/closes its meter.
    pub metering: Option<Arc<dyn LifecycleMeteringObserver>>,
}

impl GenericResourceApplication {
    /// Releases endpoints this request created for a server that was never
    /// accepted, or whose canonical create outcome requires compensation.
    ///
    /// The shared O3K ownership rule decides which of `ports` may be released,
    /// so an endpoint the caller supplied itself survives even when the server
    /// intent names it, and an endpoint of another project is never touched.
    /// An already-absent endpoint is idempotent success.
    async fn compensate_native_network_ports(&self, project_id: &str, ports: &[Uuid]) {
        if ports.is_empty() {
            return;
        }
        if let Err(error) = self
            .network_service
            .cleanup_server_owned_ports_for_project(project_id, ports)
            .await
        {
            tracing::warn!(error = %error, "native create port compensation failed");
        }
    }

    /// Compensates the endpoints of a native server create whose canonical
    /// outcome this caller cannot classify from the error alone.
    ///
    /// The decision is derived from durable canonical state, never from the
    /// error being reported: a create that is live, still converging, or
    /// inconclusive preserves its endpoints so a real guest never loses its
    /// network dependency, while a terminally failed create releases the
    /// endpoints its intent still names — including endpoints an earlier
    /// attempt allocated for the same create key.
    async fn compensate_native_network_ports_after_create_failure(
        &self,
        auth: &o3k_kernel::AuthContext,
        project_id: &str,
        provider_idempotency_key: &str,
        owned_network_ids: &[Uuid],
    ) {
        let server_id =
            o3k_compute::ComputeService::server_id_for_create(project_id, provider_idempotency_key);
        let dependency = match self
            .compute
            .create_dependency_state_for_auth(auth, o3k_domain::ServerId::from_uuid(server_id))
            .await
        {
            Ok(dependency) => dependency,
            Err(error) => {
                tracing::warn!(
                    error = ?error,
                    %server_id,
                    "native create outcome could not be classified; retaining endpoints"
                );
                return;
            }
        };
        if dependency.disposition == o3k_compute::CreateDependencyDisposition::Preserve {
            tracing::warn!(
                %server_id,
                "retaining native server endpoints for the durable create outcome"
            );
            return;
        }
        let mut candidates = owned_network_ids.to_vec();
        for port_id in &dependency.network_ids {
            if let Ok(port_id) = port_id.parse::<Uuid>()
                && !candidates.contains(&port_id)
            {
                candidates.push(port_id);
            }
        }
        self.compensate_native_network_ports(project_id, &candidates)
            .await;
    }

    /// Attaches the lifecycle metering observer used to open and close the
    /// volume allocation meter from canonical volume authority.
    #[must_use]
    pub fn with_metering_observer(mut self, observer: Arc<dyn LifecycleMeteringObserver>) -> Self {
        self.metering = Some(observer);
        self
    }

    /// Projects one volume allocation transition through the optional metering
    /// authority.
    ///
    /// A failure is surfaced as [`ResourceApplicationError::Retryable`]: the
    /// observation is idempotent, so a replay re-observes the same transition
    /// instead of double counting, and silently dropping it would under-report
    /// durable usage.
    ///
    /// The canonical open/close projection lives in
    /// [`o3k_api::realize_native_volume_create`]/[`o3k_api::remove_native_volume`];
    /// this helper covers only the two replay paths that do not call them (an
    /// existing row on create, and an already-removed row on delete).
    async fn observe_volume_allocation(
        &self,
        scope_id: &str,
        resource_id: Uuid,
        size_bytes: u64,
        consuming: bool,
    ) -> Result<(), ResourceApplicationError> {
        o3k_api::observe_volume_allocation(
            self.metering.as_ref(),
            scope_id,
            &resource_id.to_string(),
            size_bytes,
            consuming,
        )
        .await
        .map_err(|_| ResourceApplicationError::Retryable)
    }

    /// Replays the volume open only while the durable row is consuming, so a
    /// caller-side idempotent create cannot reopen a `Deleting`/`Deleted`/
    /// `Error` row (closing belongs to the authoritative delete path).
    async fn open_volume_metering_if_consuming(
        &self,
        record: &o3k_store::VolumeRecord,
    ) -> Result<(), ResourceApplicationError> {
        o3k_api::observe_volume_open_if_consuming(self.metering.as_ref(), record)
            .await
            .map_err(|_| ResourceApplicationError::Retryable)
    }

    /// The process configuration historically names the external network
    /// selector `...REALM_ID`, while compute/network composition consumes it
    /// as a canonical external-network ID. Resolve the active realm at the
    /// authority boundary before gateway/address operations use it.
    async fn external_realm_id(&self, project_id: &str) -> Result<Uuid, ResourceApplicationError> {
        let network_id = self
            .network_external_realm_id
            .ok_or(ResourceApplicationError::NotReady)?;
        self.network_service
            .list_canonical_realms_for_project(project_id, network_id)
            .await
            .map_err(|_| ResourceApplicationError::Conflict)?
            .into_iter()
            .find(|realm| realm.state == "active")
            .map(|realm| realm.id)
            .ok_or(ResourceApplicationError::Conflict)
    }

    async fn annotate_server_migration_metadata(
        &self,
        resource_id: Uuid,
        migration_id: &Uuid,
        source_key: &str,
    ) -> Result<o3k_store::ResourceRecord, ResourceApplicationError> {
        for _ in 0..4 {
            let resource = self
                .store
                .get_resource(resource_id)
                .await
                .map_err(|_| ResourceApplicationError::Internal)?;
            let mut desired = serde_json::from_str::<serde_json::Value>(&resource.desired_state)
                .map_err(|_| ResourceApplicationError::Internal)?;
            let object = desired
                .as_object_mut()
                .ok_or(ResourceApplicationError::Internal)?;
            object.insert(
                "migration_id".to_owned(),
                serde_json::Value::String(migration_id.to_string()),
            );
            object.insert(
                "source_key".to_owned(),
                serde_json::Value::String(source_key.to_owned()),
            );
            let desired_state =
                serde_json::to_string(&desired).map_err(|_| ResourceApplicationError::Internal)?;
            if desired_state == resource.desired_state {
                return Ok(resource);
            }
            match self
                .store
                .update_resource(
                    resource.id,
                    resource.generation,
                    &desired_state,
                    &resource.observed_state,
                    resource.observed_generation,
                    resource.provider_id.as_deref(),
                )
                .await
            {
                Ok(updated) => return Ok(updated),
                Err(o3k_store::StoreError::StaleGeneration) => continue,
                Err(_) => return Err(ResourceApplicationError::Internal),
            }
        }
        Err(ResourceApplicationError::Conflict)
    }
}

fn compute_error(error: o3k_compute::ComputeError) -> ResourceApplicationError {
    match error {
        o3k_compute::ComputeError::Unauthorized => ResourceApplicationError::Forbidden,
        o3k_compute::ComputeError::NotFound => ResourceApplicationError::NotFound,
        o3k_compute::ComputeError::InvalidRequest => ResourceApplicationError::Validation,
        o3k_compute::ComputeError::Conflict => ResourceApplicationError::Conflict,
        // A quota rejection is a caller-visible allocation denial, not an
        // internal failure: the OpenStack-compatible surface maps the same
        // ComputeError to 403, and a 500 here would hide the limit from the
        // tenant and mislead operators.
        o3k_compute::ComputeError::QuotaExceeded { .. } => ResourceApplicationError::Forbidden,
        _ => ResourceApplicationError::Internal,
    }
}

fn image_error(error: o3k_image::ImageError) -> ResourceApplicationError {
    match error {
        o3k_image::ImageError::Unauthorized => ResourceApplicationError::Forbidden,
        o3k_image::ImageError::NotFound => ResourceApplicationError::NotFound,
        o3k_image::ImageError::Conflict => ResourceApplicationError::Conflict,
        o3k_image::ImageError::InvalidMetadata
        | o3k_image::ImageError::UnsupportedFormat
        | o3k_image::ImageError::ChecksumMismatch => ResourceApplicationError::Validation,
        _ => ResourceApplicationError::Internal,
    }
}

fn generic_read_error(error: o3k_native_api::error::NativeReadError) -> ResourceApplicationError {
    match error {
        o3k_native_api::error::NativeReadError::NotFound => ResourceApplicationError::NotFound,
        o3k_native_api::error::NativeReadError::Forbidden => ResourceApplicationError::Forbidden,
        o3k_native_api::error::NativeReadError::Internal => ResourceApplicationError::Internal,
    }
}

fn server_json(item: ServerItem) -> serde_json::Value {
    serde_json::json!({"api_version":"o3k.io/v1","kind":"compute:server","metadata":{"id":item.id,"owner_scope":item.project_id,"generation":item.generation,"created_at":item.created_at},"spec":{"name":item.name,"flavor_id":item.flavor_id,"image_id":item.image_id},"status":{"state":item.state}})
}

fn server_json_with_resource(
    item: ServerItem,
    resource: Option<&o3k_store::ResourceRecord>,
) -> serde_json::Value {
    let mut value = server_json(item);
    if let Some(resource) = resource
        && let Ok(spec) = serde_json::from_str::<serde_json::Value>(&resource.desired_state)
    {
        for key in ["migration_id", "source_key"] {
            if let Some(text) = spec.get(key).and_then(serde_json::Value::as_str) {
                value["metadata"][key] = serde_json::Value::String(text.to_owned());
            }
        }
    }
    value
}

fn realm_json(item: AddressRealmItem) -> serde_json::Value {
    serde_json::json!({"api_version":"o3k.io/v1","kind":"network:address_realm","metadata":{"id":item.id,"owner_scope":item.project_id,"generation":item.generation,"created_at":item.created_at},"spec":{"prefix":item.prefix,"overlapping_prefixes":item.overlapping_prefixes},"status":{"state":item.state}})
}

fn network_json(item: &o3k_store::CanonicalNetworkRecord) -> serde_json::Value {
    serde_json::json!({
        "api_version":"o3k.io/v1",
        "kind":"network:network",
        "metadata":{"id":item.id,"owner_scope":item.project_id,"generation":item.generation},
        "spec":{"name":item.name},
        "status":{"state":item.state}
    })
}

fn flavor_json(item: &o3k_compute::Flavor, owner_scope: &str) -> serde_json::Value {
    serde_json::json!({
        "api_version": "o3k.io/v1",
        "kind": "compute:flavor",
        "metadata": {"id": item.id, "owner_scope": owner_scope},
        "spec": {
            "name": item.name,
            "vcpus": item.vcpus,
            "ram_mib": item.ram_mib,
            "disk_gib": item.disk_gib
        },
        "status": {"state": "ACTIVE"}
    })
}

fn image_json(item: &o3k_image::ImageRecord) -> serde_json::Value {
    serde_json::json!({
        "api_version": "o3k.io/v1",
        "kind": "image:image",
        "metadata": {"id": item.id, "owner_scope": item.project_id},
        "spec": {
            "name": item.name,
            "visibility": item.visibility,
            "container_format": item.container_format,
            "disk_format": item.disk_format
        },
        "status": {"state": item.status}
    })
}

fn image_json_with_resource(
    item: &o3k_image::ImageRecord,
    resource: Option<&o3k_store::ResourceRecord>,
) -> serde_json::Value {
    let mut value = image_json(item);
    if let Some(resource) = resource {
        value["metadata"]["owner_scope"] = serde_json::Value::String(resource.project_id.clone());
        if let Ok(spec) = serde_json::from_str::<serde_json::Value>(&resource.desired_state) {
            if let Some(migration_id) = spec.get("migration_id").and_then(serde_json::Value::as_str)
            {
                value["metadata"]["migration_id"] =
                    serde_json::Value::String(migration_id.to_owned());
            }
            if let Some(source_key) = spec.get("source_key").and_then(serde_json::Value::as_str) {
                value["metadata"]["source_key"] = serde_json::Value::String(source_key.to_owned());
            }
        }
    }
    value
}

fn native_volume_json(record: &o3k_store::VolumeRecord) -> serde_json::Value {
    let mut metadata = serde_json::json!({
        "id": record.volume.id.to_string(),
        "owner_scope": record.volume.project_id,
        "generation": record.volume.generation,
        "created_at": record.created_at,
    });
    for key in ["migration_id", "source_key"] {
        if let Some(value) = record.volume.metadata.get(key) {
            metadata[key] = serde_json::Value::String(value.clone());
        }
    }
    serde_json::json!({
        "api_version":"o3k.io/v1",
        "kind":"volume:volume",
        "metadata":metadata,
        "spec":{"size_bytes":record.volume.size_bytes,"volume_type":record.volume.volume_type,"name":record.volume.name,"description":record.volume.description,"metadata":record.volume.metadata,"availability_zone":record.volume.availability_zone},
        "status":{"state":record.volume.state}
    })
}

fn native_attachment_json(
    record: &o3k_store::storage::VolumeAttachmentRecordV1,
    resource: Option<&o3k_store::ResourceRecord>,
) -> serde_json::Value {
    let mut metadata = serde_json::json!({
        "id": record.attachment.id.to_string(),
        "owner_scope": record.attachment.project_id,
        "generation": record.attachment.generation,
    });
    if let Some(resource) = resource
        && let Ok(spec) = serde_json::from_str::<serde_json::Value>(&resource.desired_state)
    {
        for key in ["migration_id", "source_key"] {
            if let Some(value) = spec.get(key) {
                metadata[key] = value.clone();
            }
        }
    }
    serde_json::json!({
        "api_version": "o3k.io/v1",
        "kind": "volume:volume_attachment",
        "metadata": metadata,
        "spec": {
            "server_id": record.attachment.server_id,
            "volume_id": record.attachment.volume_id,
            "delete_on_termination": record.attachment.delete_on_termination,
        },
        "status": {"state": record.attachment.state},
    })
}

fn floating_ip_json(
    binding: &o3k_network::PublicAddressBinding,
    realm_id: Option<Uuid>,
    owner: &str,
    migration_id: Option<&str>,
    source_key: Option<&str>,
) -> serde_json::Value {
    let mut metadata = serde_json::json!({
        "id": binding.allocation_id,
        "owner_scope": owner,
        "generation": binding.generation,
    });
    if let Some(value) = migration_id {
        metadata["migration_id"] = value.into();
    }
    if let Some(value) = source_key {
        metadata["source_key"] = value.into();
    }
    serde_json::json!({
        "api_version":"o3k.io/v1", "kind":"network:floating_ip", "metadata":metadata,
        "spec":{"floating_network_id":realm_id,"floating_ip_address":binding.public_address,"port_id":binding.endpoint_id},
        "status":{"state":"ACTIVE"}
    })
}

fn generic_external_json(resource: &o3k_store::ResourceRecord) -> serde_json::Value {
    // Durable desired state is not a public DTO: it may contain user-data,
    // provider references, or credentials from older/imported records.  Only
    // stable identity and lifecycle state cross the native boundary here.
    let metadata = serde_json::json!({
        "id": resource.id,
        "owner_scope": resource.project_id,
        "generation": resource.generation
    });
    // Storage kinds are deliberately decoupled from the versioned native
    // resource type (for example compute_instance is persisted for the
    // compute:server resource).  Never leak the storage discriminator across
    // the native contract boundary.
    let public_kind = match resource.kind.as_str() {
        "compute_instance" => "compute:server",
        "volume" => "volume:volume",
        other => other,
    };
    serde_json::json!({
        "api_version": "o3k.io/v1",
        "kind": public_kind,
        "metadata": metadata,
        "spec": {},
        "status": {"state": resource.observed_state}
    })
}

fn network_external_json(resource: &o3k_store::ResourceRecord) -> serde_json::Value {
    let mut value = generic_external_json(resource);
    // A network spec is a name-only public contract (validated by
    // NetworkCreateSpec), so the display name may cross the boundary. Raw
    // desired_state still must not: imported/migration rows can carry
    // provider references and migration metadata.
    if let Ok(spec) = serde_json::from_str::<serde_json::Value>(&resource.desired_state)
        && let Some(name) = spec.get("name").cloned()
        && name.is_string()
    {
        value["spec"]["name"] = name;
    }
    value
}

fn bounded_store_kind(resource_type: &str) -> Option<&str> {
    match resource_type {
        "image:image"
        | "network:network"
        | "network:subnet"
        | "network:port"
        | "network:security_group"
        | "network:security_group_rule"
        | "network:router"
        | "network:router_interface" => Some(resource_type),
        // Volumes predate the generic resource envelope and use this
        // canonical durable kind.
        "compute:server" => Some("compute_instance"),
        "volume:volume" => Some("volume"),
        _ => None,
    }
}

#[async_trait::async_trait]
impl ResourceApplication for GenericResourceApplication {
    fn supports_collection(&self, descriptor: &ResourceDescriptor) -> bool {
        bounded_store_kind(&descriptor.resource_type.to_string()).is_some()
    }

    async fn list_page(
        &self,
        descriptor: &ResourceDescriptor,
        auth: &o3k_kernel::AuthContext,
        query: &o3k_native_api::pagination::ResourceQuery,
        cursors: &o3k_native_api::pagination::CursorConfig,
    ) -> Result<o3k_native_api::pagination::ResourcePage<serde_json::Value>, ResourceApplicationError>
    {
        if query.scope_id() != auth.effective_scope().id().as_str()
            || query.resource_type() != descriptor.resource_type.to_string()
        {
            return Err(ResourceApplicationError::Forbidden);
        }
        let Some(store_kind) = bounded_store_kind(query.resource_type()) else {
            return Err(ResourceApplicationError::UnsupportedOperation);
        };
        let page = self
            .store
            .list_resources_page(
                query.scope_id(),
                store_kind,
                query.continuation_key(),
                query.limit(),
            )
            .await
            .map_err(|_| ResourceApplicationError::Internal)?;
        let items = page
            .items
            .iter()
            .map(|record| {
                if record.kind == "network:network" {
                    network_external_json(record)
                } else {
                    generic_external_json(record)
                }
            })
            .collect();
        let repository = o3k_native_api::pagination::RepositoryPage::new(
            items,
            page.has_more,
            page.continuation_key,
            query.limit(),
        )
        .map_err(|_| ResourceApplicationError::Internal)?;
        cursors
            .complete_page(query, repository)
            .map_err(|_| ResourceApplicationError::Internal)
    }

    async fn action(
        &self,
        descriptor: &ResourceDescriptor,
        auth: &o3k_kernel::AuthContext,
        id: &str,
        action: o3k_kernel::ActionId,
        request: ActionRequest,
        idempotency_key: &str,
    ) -> Result<MutationResult, ResourceApplicationError> {
        if descriptor.resource_type.to_string() != "compute:server" {
            return Err(ResourceApplicationError::UnsupportedOperation);
        }
        if !request.input.is_object() {
            return Err(ResourceApplicationError::Validation);
        }
        let action_kind = match action.action() {
            "StartServer" => o3k_provider::InstanceAction::Start,
            "StopServer" => o3k_provider::InstanceAction::Stop,
            "RebootServer" => o3k_provider::InstanceAction::Reboot,
            _ => return Err(ResourceApplicationError::UnsupportedOperation),
        };
        let server_id = id
            .parse::<Uuid>()
            .map(o3k_compute::ServerId::from_uuid)
            .map_err(|_| ResourceApplicationError::NotFound)?;
        let context = o3k_reconciler::CanonicalMutationContext::new(
            action,
            auth.principal().id().to_string(),
            auth.effective_scope().clone(),
            Some(auth.request_id().to_owned()),
            idempotency_key.to_owned(),
            request.input,
        )
        .map_err(|_| ResourceApplicationError::Validation)?;
        let receipt = self
            .compute
            .action_for_auth_canonical(auth, server_id, action_kind, context)
            .await
            .map_err(compute_error)?;
        Ok(MutationResult {
            operation_id: receipt.operation_id.to_string(),
            resource_id: Some(receipt.resource.to_string()),
            complete: matches!(
                receipt.operation_state,
                o3k_store::OperationState::Succeeded | o3k_store::OperationState::Failed
            ),
            resource: None,
        })
    }

    async fn update(
        &self,
        descriptor: &ResourceDescriptor,
        auth: &o3k_kernel::AuthContext,
        id: &str,
        request: o3k_native_api::resource::ValidatedUpdateRequest,
        idempotency_key: Option<&str>,
        expected_generation: i64,
    ) -> Result<MutationResult, ResourceApplicationError> {
        if descriptor.resource_type.to_string() != "compute:server" {
            return Err(ResourceApplicationError::UnsupportedOperation);
        }
        let resource_id = Uuid::parse_str(id).map_err(|_| ResourceApplicationError::NotFound)?;
        let existing = self
            .store
            .get_resource(resource_id)
            .await
            .map_err(|error| match error {
                o3k_store::StoreError::ResourceNotFound => ResourceApplicationError::NotFound,
                _ => ResourceApplicationError::Internal,
            })?;
        if existing.kind != "compute_instance"
            || existing.project_id != auth.effective_scope().id().as_str()
        {
            return Err(ResourceApplicationError::NotFound);
        }
        let name = request
            .spec
            .get("name")
            .and_then(serde_json::Value::as_str)
            .ok_or(ResourceApplicationError::Validation)?;
        let mut desired: serde_json::Value = serde_json::from_str(&existing.desired_state)
            .map_err(|_| ResourceApplicationError::Conflict)?;
        let desired_object = desired
            .as_object_mut()
            .ok_or(ResourceApplicationError::Conflict)?;
        desired_object.insert(
            "name".to_owned(),
            serde_json::Value::String(name.to_owned()),
        );
        let action = descriptor
            .lifecycle_actions
            .get(&o3k_native_api::resource::LifecycleOperation::Update)
            .cloned()
            .ok_or(ResourceApplicationError::UnsupportedOperation)?;
        let key = idempotency_key.ok_or(ResourceApplicationError::Validation)?;
        let operation_id = Uuid::new_v5(
            &Uuid::NAMESPACE_URL,
            format!("{}:{}:{}:{}", descriptor.resource_type, id, action, key).as_bytes(),
        );
        // Idempotent replay detection precedes the mutable generation
        // precondition. The reservation fingerprint pins the original request
        // semantics: a true replay returns the durable result regardless of
        // the CURRENT generation (the original request was validated when
        // accepted, and the resource may legitimately have moved on since,
        // typically because of the original call itself), while reusing a
        // key with different semantics is a conflict, exactly as the create
        // path treats it.
        let identity = o3k_store::IdempotencyReservationRequest::from_semantics(
            auth.effective_scope().id().as_str(),
            action.to_string(),
            key.to_owned(),
            &descriptor.resource_type.to_string(),
            Some(id),
            &serde_json::json!({"spec": request.spec.clone(), "generation": expected_generation}),
            operation_id,
        )
        .map_err(|_| ResourceApplicationError::Validation)?;
        match self
            .store
            .get_idempotency_reservation(
                auth.effective_scope().id().as_str(),
                &action.to_string(),
                key,
            )
            .await
        {
            Ok(Some(stored)) => {
                if stored.fingerprint != identity.fingerprint {
                    return Err(ResourceApplicationError::IdempotencyConflict);
                }
                let stored_operation = self
                    .store
                    .get_canonical_operation(stored.operation_id)
                    .await
                    .map_err(|_| ResourceApplicationError::Internal)?;
                if matches!(
                    stored_operation.state,
                    o3k_store::OperationState::Failed | o3k_store::OperationState::UnknownOutcome
                ) {
                    // Terminal-but-unknown or failed: the caller must retry
                    // with a fresh key instead of replaying an indeterminate
                    // result forever.
                    return Err(ResourceApplicationError::Conflict);
                }
                return Ok(MutationResult {
                    operation_id: stored.operation_id.to_string(),
                    resource_id: Some(id.to_owned()),
                    complete: stored_operation.state == o3k_store::OperationState::Succeeded,
                    resource: None,
                });
            }
            Ok(None) => {}
            Err(_) => return Err(ResourceApplicationError::Internal),
        }
        // The resource precondition is validated BEFORE any durable operation
        // or idempotency reservation is written: a stale If-Match on a
        // never-accepted request must leave no phantom Pending operation
        // behind — `lifecycle:update` has no reconciler handler, so a Pending
        // operation would make same-key retries replay 202 forever with no
        // recovery path — and must not consume the idempotency key.
        if existing.generation != expected_generation {
            return Err(ResourceApplicationError::PreconditionConflict);
        }
        let operation = o3k_store::OperationRecord {
            id: operation_id,
            resource_id,
            kind: "lifecycle:update".into(),
            state: o3k_store::OperationState::Pending,
            provider_operation_id: None,
            error_category: None,
            error_message: None,
        };
        let canonical = o3k_store::CanonicalOperationRecord::from_kernel_operation(
            &o3k_kernel::Operation::new(
                operation_id,
                descriptor.owning_service.clone(),
                action.clone(),
                auth.principal().id().to_string(),
                auth.effective_scope().clone(),
                descriptor.resource_type.clone(),
                Some(o3k_kernel::ResourceId::new_unchecked(id)),
                Some(auth.request_id().to_owned()),
            ),
        )
        .map_err(|_| ResourceApplicationError::Internal)?;
        match self
            .store
            .create_or_replay_canonical_lifecycle_operation(&operation, &canonical, &identity)
            .await
            .map_err(|_| ResourceApplicationError::Internal)?
        {
            o3k_store::CanonicalAcceptanceOutcome::Conflict => {
                return Err(ResourceApplicationError::IdempotencyConflict);
            }
            o3k_store::CanonicalAcceptanceOutcome::ExistingEquivalent { operation_id, .. } => {
                // An idempotent replay must reflect the durable operation state.
                // In particular, a request which was accepted but whose resource
                // write failed (or could not be recorded truthfully) must not be
                // reported as a successful replay.
                let existing_operation = self
                    .store
                    .get_canonical_operation(operation_id)
                    .await
                    .map_err(|_| ResourceApplicationError::Internal)?;
                if matches!(
                    existing_operation.state,
                    o3k_store::OperationState::Failed | o3k_store::OperationState::UnknownOutcome
                ) {
                    return Err(ResourceApplicationError::Conflict);
                }
                return Ok(MutationResult {
                    operation_id: operation_id.to_string(),
                    resource_id: Some(id.to_owned()),
                    complete: existing_operation.state == o3k_store::OperationState::Succeeded,
                    resource: None,
                });
            }
            o3k_store::CanonicalAcceptanceOutcome::Created { .. } => {}
        }
        let desired =
            serde_json::to_string(&desired).map_err(|_| ResourceApplicationError::Internal)?;
        let now = chrono::Utc::now().to_rfc3339();
        if let Err(error) = self
            .store
            .update_resource(
                resource_id,
                expected_generation,
                &desired,
                &existing.observed_state,
                existing.observed_generation,
                existing.provider_id.as_deref(),
            )
            .await
        {
            // The operation was already accepted durably; a post-acceptance
            // write failure must terminalize it — `lifecycle:update` has no
            // reconciler handler, so a lingering Pending operation would
            // make same-key replays return 202 forever. A CAS rejection
            // proves the update did not apply (Failed); any other store
            // error leaves the outcome genuinely unknown.
            let terminal_state = if matches!(error, o3k_store::StoreError::StaleGeneration) {
                o3k_kernel::OperationState::Failed
            } else {
                o3k_kernel::OperationState::UnknownOutcome
            };
            let terminal = o3k_store::CanonicalOperationLifecycleUpdate::new(
                terminal_state,
                1,
                None,
                if terminal_state == o3k_kernel::OperationState::Failed {
                    Some(now.clone())
                } else {
                    None
                },
                Some("resource_write_failed".to_owned()),
            )
            .map_err(|_| ResourceApplicationError::Internal)?;
            // Best effort: if the terminalization write itself fails, the
            // operation may stay Pending; nothing more can be done inline.
            let _ = self
                .store
                .update_canonical_operation_lifecycle(operation_id, &terminal)
                .await;
            return Err(match error {
                o3k_store::StoreError::StaleGeneration => {
                    ResourceApplicationError::PreconditionConflict
                }
                _ => ResourceApplicationError::Internal,
            });
        }
        let lifecycle = o3k_store::CanonicalOperationLifecycleUpdate::new(
            o3k_kernel::OperationState::Succeeded,
            1,
            Some(now.clone()),
            Some(now.clone()),
            None,
        )
        .map_err(|_| ResourceApplicationError::Internal)?;
        if let Err(error) = self
            .store
            .update_canonical_operation_lifecycle(operation_id, &lifecycle)
            .await
        {
            // The resource mutation applied but the operation record could
            // not be marked Succeeded: the truthful state is UnknownOutcome
            // (terminal without finished_at), so same-key replays terminate
            // deterministically instead of replaying an incomplete result.
            tracing::error!(%error, %operation_id, "update operation terminalization failed");
            let unknown = o3k_store::CanonicalOperationLifecycleUpdate::new(
                o3k_kernel::OperationState::UnknownOutcome,
                1,
                None,
                None,
                Some("operation_state_write_failed".to_owned()),
            )
            .map_err(|_| ResourceApplicationError::Internal)?;
            let _ = self
                .store
                .update_canonical_operation_lifecycle(operation_id, &unknown)
                .await;
            // The response reports the resource truth (the mutation applied);
            // the operation record is degraded (unknown_outcome) and same-key
            // replays terminate as conflicts. This response/record divergence
            // is deliberate: a completed mutation must not be reported as
            // incomplete.
        }
        Ok(MutationResult {
            operation_id: operation_id.to_string(),
            resource_id: Some(id.to_owned()),
            complete: true,
            resource: None,
        })
    }

    async fn show(
        &self,
        descriptor: &ResourceDescriptor,
        auth: &o3k_kernel::AuthContext,
        id: &str,
    ) -> Result<serde_json::Value, ResourceApplicationError> {
        if descriptor.resource_type.to_string() == "image:image" {
            let service = self
                .image
                .as_ref()
                .ok_or(ResourceApplicationError::NotReady)?;
            let id = id
                .parse::<Uuid>()
                .map_err(|_| ResourceApplicationError::NotFound)?;
            let item = service.get(auth, id).await.map_err(image_error)?;
            let resource = self.store.get_resource(id).await.ok();
            return Ok(image_json_with_resource(&item, resource.as_ref()));
        }
        if self
            .external_controllers
            .contains_key(&descriptor.owning_service)
        {
            let resource_id = id
                .parse::<Uuid>()
                .map_err(|_| ResourceApplicationError::NotFound)?;
            let resource = self
                .store
                .get_resource(resource_id)
                .await
                .map_err(|_| ResourceApplicationError::NotFound)?;
            if resource.kind != descriptor.resource_type.to_string()
                || resource.project_id != auth.effective_scope().id().as_str()
            {
                return Err(ResourceApplicationError::NotFound);
            }
            return Ok(generic_external_json(&resource));
        }
        let id = id
            .parse::<Uuid>()
            .map_err(|_| ResourceApplicationError::NotFound)?;
        // Flavor resources created through the generic canonical path carry
        // migration ownership in their durable record.  Preserve that
        // metadata on read so the migration runner can fence and verify the
        // exact resource it created; seeded compatibility flavors continue
        // through the concrete compute read below.
        if descriptor.resource_type.to_string() == "compute:flavor"
            && let Ok(resource) = self.store.get_resource(id).await
            && resource.kind == "compute_flavor"
            && resource.project_id == auth.effective_scope().id().as_str()
        {
            return Ok(generic_external_json(&resource));
        }
        if descriptor.resource_type.to_string() == "network:network"
            && let Ok(resource) = self.store.get_resource(id).await
            && resource.kind == "network:network"
            && resource.project_id == auth.effective_scope().id().as_str()
            // Finalized resources are concealed like every other domain: the
            // ledger keeps the tombstone for projection/audit purposes, but
            // show is the live-resource view (compute:server behaves the
            // same). The collection still surfaces tombstones with an
            // explicit DELETED status state.
            && resource.observed_state != "DELETED"
        {
            return Ok(network_external_json(&resource));
        }
        if matches!(
            descriptor.resource_type.to_string().as_str(),
            "network:subnet"
                | "network:port"
                | "network:security_group"
                | "network:security_group_rule"
                | "network:router"
                | "network:router_interface"
                | "network:floating_ip"
        ) && let Ok(resource) = self.store.get_resource(id).await
            && resource.kind == descriptor.resource_type.to_string()
            && resource.project_id == auth.effective_scope().id().as_str()
        {
            return Ok(generic_external_json(&resource));
        }
        match descriptor.resource_type.to_string().as_str() {
            "compute:flavor" => self
                .compute
                .flavor_for_auth(auth, id)
                .await
                .map(|item| flavor_json(&item, auth.effective_scope().id().as_str()))
                .map_err(compute_error),
            "compute:server" => {
                let item = self
                    .server
                    .show_server(auth, id)
                    .await
                    .map_err(generic_read_error)?;
                let resource = self
                    .store
                    .get_resource(
                        item.id
                            .parse::<Uuid>()
                            .map_err(|_| ResourceApplicationError::Internal)?,
                    )
                    .await
                    .map_err(|_| ResourceApplicationError::Internal)?;
                Ok(server_json_with_resource(item, Some(&resource)))
            }
            "network:address_realm" => self
                .network
                .show_address_realm(auth, id)
                .await
                .map(realm_json)
                .map_err(generic_read_error),
            "network:network" => self
                .network_service
                .get_canonical_network(auth, id)
                .await
                .map(|item| {
                    // Native migration records are an ownership/evidence
                    // projection over the canonical network authority.
                    network_json(&item)
                })
                .map_err(|_| ResourceApplicationError::NotFound),
            "network:floating_ip" => {
                let allocator = self
                    .public_allocator
                    .as_ref()
                    .ok_or(ResourceApplicationError::NotReady)?;
                let item = allocator
                    .get(auth.effective_scope().id().as_str(), id)
                    .map_err(|_| ResourceApplicationError::NotFound)?;
                let record = self.store.get_resource(id).await.ok();
                let spec = record
                    .as_ref()
                    .and_then(|r| serde_json::from_str::<serde_json::Value>(&r.desired_state).ok());
                Ok(floating_ip_json(
                    &item,
                    Some(
                        self.external_realm_id(auth.effective_scope().id().as_str())
                            .await?,
                    ),
                    auth.effective_scope().id().as_str(),
                    spec.as_ref()
                        .and_then(|v| v.get("migration_id"))
                        .and_then(serde_json::Value::as_str),
                    spec.as_ref()
                        .and_then(|v| v.get("source_key"))
                        .and_then(serde_json::Value::as_str),
                ))
            }
            "volume:volume" => {
                let record = self
                    .store
                    .get_volume(id)
                    .await
                    .map_err(|_| ResourceApplicationError::NotFound)?;
                match record {
                    Some(record)
                        if record.volume.project_id == auth.effective_scope().id().as_str() =>
                    {
                        // Repair a projection lost after this volume's durable
                        // transition; idempotent and best-effort so a metering
                        // hiccup never fails the read.
                        o3k_api::repair_volume_metering(self.metering.as_ref(), &record).await;
                        Ok(native_volume_json(&record))
                    }
                    _ => Err(ResourceApplicationError::NotFound),
                }
            }
            "volume:volume_attachment" => {
                let record = self
                    .store
                    .get_volume_attachment_v1(id)
                    .await
                    .map_err(|_| ResourceApplicationError::Internal)?
                    .filter(|item| {
                        item.attachment.project_id == auth.effective_scope().id().as_str()
                            && item.attachment.state == VolumeAttachmentState::Attached
                    })
                    .ok_or(ResourceApplicationError::NotFound)?;
                let resource = self.store.get_resource(id).await.ok();
                Ok(native_attachment_json(&record, resource.as_ref()))
            }
            _ => Err(ResourceApplicationError::NotFound),
        }
    }

    async fn create(
        &self,
        descriptor: &ResourceDescriptor,
        auth: &o3k_kernel::AuthContext,
        request: ValidatedCreateRequest,
        idempotency_key: Option<&str>,
    ) -> Result<MutationResult, ResourceApplicationError> {
        if descriptor.resource_type.to_string() == "image:image" {
            let service = self
                .image
                .as_ref()
                .ok_or(ResourceApplicationError::NotReady)?;
            let source = request
                .spec
                .get("source")
                .filter(|value| value.is_object())
                .unwrap_or(&request.spec);
            let source = source
                .get("image")
                .filter(|value| value.is_object())
                .unwrap_or(source);
            let name = source
                .get("name")
                .and_then(serde_json::Value::as_str)
                .ok_or(ResourceApplicationError::Validation)?
                .to_owned();
            let visibility = source
                .get("visibility")
                .and_then(serde_json::Value::as_str)
                .unwrap_or("private")
                .to_owned();
            let container_format = source
                .get("container_format")
                .and_then(serde_json::Value::as_str)
                .unwrap_or("bare")
                .to_owned();
            let disk_format = source
                .get("disk_format")
                .and_then(serde_json::Value::as_str)
                .unwrap_or("qcow2")
                .to_owned();
            let canonical_id = request
                .spec
                .get("canonical_id")
                .and_then(serde_json::Value::as_str)
                .map(str::parse::<Uuid>)
                .transpose()
                .map_err(|_| ResourceApplicationError::Validation)?;
            let image = match canonical_id {
                Some(id) => {
                    service
                        .create_with_id(auth, id, name, visibility, container_format, disk_format)
                        .await
                }
                None => {
                    service
                        .create(auth, name, visibility, container_format, disk_format)
                        .await
                }
            }
            .map_err(image_error)?;
            self.store
                .insert_resource(&o3k_store::ResourceRecord {
                    id: image.id,
                    kind: "image:image".to_owned(),
                    project_id: auth.effective_scope().id().as_str().to_owned(),
                    generation: 1,
                    observed_generation: 1,
                    desired_state: serde_json::to_string(&request.spec)
                        .map_err(|_| ResourceApplicationError::Validation)?,
                    observed_state: "active".to_owned(),
                    provider_id: None,
                })
                .await
                .map_err(|error| match error {
                    o3k_store::StoreError::ResourceAlreadyExists => {
                        ResourceApplicationError::Conflict
                    }
                    _ => ResourceApplicationError::Internal,
                })?;
            return Ok(MutationResult {
                operation_id: format!("native:image:create:{}", image.id),
                resource_id: Some(image.id.to_string()),
                complete: true,
                resource: Some(image_json(&image)),
            });
        }
        if descriptor.resource_type.to_string() == "compute:flavor" {
            let source = request
                .spec
                .get("source")
                .filter(|value| value.is_object())
                .unwrap_or(&request.spec);
            let source = source
                .get("flavor")
                .filter(|value| value.is_object())
                .unwrap_or(source);
            let name = source
                .get("name")
                .and_then(serde_json::Value::as_str)
                .ok_or(ResourceApplicationError::Validation)?
                .to_owned();
            let vcpus = source
                .get("vcpus")
                .and_then(serde_json::Value::as_u64)
                .ok_or(ResourceApplicationError::Validation)?;
            let ram_mib = source
                .get("ram_mib")
                .or_else(|| source.get("ram"))
                .or_else(|| source.get("memory_mib"))
                .and_then(serde_json::Value::as_u64)
                .ok_or(ResourceApplicationError::Validation)?;
            let disk_gib = source
                .get("disk_gib")
                .or_else(|| source.get("disk"))
                .and_then(serde_json::Value::as_u64)
                .unwrap_or_default();
            let flavor = self
                .compute
                .create_flavor_for_auth(
                    auth,
                    name,
                    u32::try_from(vcpus).map_err(|_| ResourceApplicationError::Validation)?,
                    ram_mib,
                    disk_gib,
                )
                .await
                .map_err(compute_error)?;
            // The concrete compute service owns the flavor fields, while the
            // generic migration envelope owns run correlation.  Retain the
            // latter in the durable desired state so later reads can prove
            // migration ownership without trusting an in-memory response.
            if request.spec.get("migration_id").is_some()
                || request.spec.get("source_key").is_some()
            {
                let mut desired = serde_json::to_value(&flavor)
                    .map_err(|_| ResourceApplicationError::Internal)?;
                if let Some(object) = desired.as_object_mut() {
                    for key in ["migration_id", "source_key"] {
                        if let Some(value) = request.spec.get(key) {
                            object.insert(key.to_owned(), value.clone());
                        }
                    }
                }
                let record = self
                    .store
                    .get_resource(flavor.id)
                    .await
                    .map_err(|_| ResourceApplicationError::Internal)?;
                let desired = serde_json::to_string(&desired)
                    .map_err(|_| ResourceApplicationError::Internal)?;
                self.store
                    .update_resource(
                        flavor.id,
                        record.generation,
                        &desired,
                        &record.observed_state,
                        record.observed_generation,
                        record.provider_id.as_deref(),
                    )
                    .await
                    .map_err(|_| ResourceApplicationError::Internal)?;
            }
            return Ok(MutationResult {
                operation_id: Uuid::new_v5(
                    &Uuid::NAMESPACE_URL,
                    format!(
                        "native:compute-flavor:{}:{}",
                        auth.effective_scope().id(),
                        flavor.id
                    )
                    .as_bytes(),
                )
                .to_string(),
                resource_id: Some(flavor.id.to_string()),
                complete: true,
                resource: Some(flavor_json(&flavor, auth.effective_scope().id().as_str())),
            });
        }
        if let Some(controller) = self.external_controllers.get(&descriptor.owning_service) {
            if !controller.health().await.healthy {
                return Err(ResourceApplicationError::NotReady);
            }
            // The descriptor is derived at startup and cannot reflect a later
            // controller outage.  Re-check readiness at the mutation boundary
            // so a Ready -> NotReady transition cannot accept new work.
            let action = descriptor
                .lifecycle_actions
                .get(&o3k_native_api::resource::LifecycleOperation::Create)
                .cloned()
                .ok_or(ResourceApplicationError::UnsupportedOperation)?;
            let key = idempotency_key
                .map(str::to_owned)
                .unwrap_or_else(|| format!("native:{}", Uuid::new_v4()));
            let resource_identity = format!(
                "{}:{}:{}:{}",
                auth.effective_scope().id(),
                descriptor.resource_type,
                action,
                key
            );
            let resource_id = Uuid::new_v5(&Uuid::NAMESPACE_OID, resource_identity.as_bytes());
            let operation_id = Uuid::new_v5(
                &Uuid::NAMESPACE_URL,
                format!("{}:create:{resource_id}", descriptor.resource_type).as_bytes(),
            );
            let desired_state = serde_json::to_string(&request.spec)
                .map_err(|_| ResourceApplicationError::Validation)?;
            let resource = o3k_store::ResourceRecord {
                id: resource_id,
                kind: descriptor.resource_type.to_string(),
                project_id: auth.effective_scope().id().as_str().to_owned(),
                generation: 1,
                observed_generation: 0,
                desired_state,
                observed_state: "PROVISIONING".to_owned(),
                provider_id: None,
            };
            let operation = o3k_store::OperationRecord {
                id: operation_id,
                resource_id,
                kind: "lifecycle:create".into(),
                state: o3k_store::OperationState::Pending,
                provider_operation_id: None,
                error_category: None,
                error_message: None,
            };
            let canonical = o3k_store::CanonicalOperationRecord::from_kernel_operation(
                &o3k_kernel::Operation::new(
                    operation_id,
                    descriptor.owning_service.clone(),
                    action.clone(),
                    auth.principal().id().to_string(),
                    auth.effective_scope().clone(),
                    descriptor.resource_type.clone(),
                    Some(o3k_kernel::ResourceId::new_unchecked(
                        resource_id.to_string(),
                    )),
                    Some(auth.request_id().to_owned()),
                ),
            )
            .map_err(|_| ResourceApplicationError::Internal)?;
            let identity = o3k_store::IdempotencyReservationRequest::from_semantics(
                auth.effective_scope().id().as_str(),
                action.to_string(),
                key,
                &descriptor.resource_type.to_string(),
                Some(&resource_id.to_string()),
                &request.spec,
                operation_id,
            )
            .map_err(|_| ResourceApplicationError::Validation)?;
            let acceptance = self
                .store
                .create_or_replay_canonical_resource_operation(
                    &resource, &operation, &canonical, &identity, None,
                )
                .await
                .map_err(|_| ResourceApplicationError::Internal)?;
            let (operation_id, resource_id, replayed) = match acceptance {
                o3k_store::CanonicalAcceptanceOutcome::Created {
                    operation_id,
                    resource_id,
                } => (operation_id, resource_id, false),
                o3k_store::CanonicalAcceptanceOutcome::ExistingEquivalent {
                    operation_id,
                    resource_id,
                } => (operation_id, resource_id, true),
                o3k_store::CanonicalAcceptanceOutcome::Conflict => {
                    return Err(ResourceApplicationError::IdempotencyConflict);
                }
            };
            if replayed {
                let existing = self
                    .store
                    .get_resource(resource_id)
                    .await
                    .map_err(|_| ResourceApplicationError::Internal)?;
                // An equivalent replay must not redrive an external mutation
                // while its canonical operation is still converging.  The
                // durable reconciler owns retry/recovery; this API call only
                // returns the existing canonical result.
                return Ok(MutationResult {
                    operation_id: operation_id.to_string(),
                    resource_id: Some(resource_id.to_string()),
                    complete: existing.observed_state == "READY",
                    resource: Some(generic_external_json(&existing)),
                });
            }
            let session = controller.session();
            let context = o3k_kernel::OperationContext {
                request_id: auth
                    .request_id()
                    .parse()
                    .map_err(|_| ResourceApplicationError::Internal)?,
                operation_id,
                action,
                service_id: descriptor.owning_service.clone(),
                owner_scope: auth.effective_scope().clone(),
                session_id: session.session_id,
                session_generation: session.session_generation,
                deadline_unix_ms: chrono::Utc::now().timestamp_millis() as u64 + 60_000,
                replay_identity: format!("parent:{operation_id}"),
                audit_correlation: format!("parent:{operation_id}"),
            };
            let parent_reference = o3k_kernel::ResourceReference {
                resource_type: descriptor.resource_type.clone(),
                resource_id: o3k_kernel::ResourceId::new_unchecked(resource_id.to_string()),
                generation: 1,
            };
            let delegation = controller
                .issue_parent_delegation(
                    &context,
                    auth.principal().id().to_string(),
                    &parent_reference,
                )
                .map_err(|_| ResourceApplicationError::Unauthorized)?;
            let outcome = controller
                .reconcile(o3k_kernel::ReconcileRequest {
                    context,
                    resource: o3k_kernel::ResourceSnapshot {
                        reference: parent_reference,
                        desired_spec: request.spec.into_value(),
                        known_status: None,
                        owner_scope: auth.effective_scope().clone(),
                    },
                    delegation: Some(delegation),
                })
                .await;
            let complete = matches!(outcome, o3k_kernel::ReconcileOutcome::Succeeded { .. });
            let observed_state = match &outcome {
                o3k_kernel::ReconcileOutcome::Succeeded { .. } => "READY",
                o3k_kernel::ReconcileOutcome::Unknown { .. } => "UNKNOWN",
                o3k_kernel::ReconcileOutcome::Failed { .. }
                | o3k_kernel::ReconcileOutcome::Retryable { .. } => "ERROR",
                o3k_kernel::ReconcileOutcome::Accepted { .. } => "PROVISIONING",
            };
            let lifecycle_state = match &outcome {
                o3k_kernel::ReconcileOutcome::Succeeded { .. } => {
                    o3k_kernel::OperationState::Succeeded
                }
                o3k_kernel::ReconcileOutcome::Unknown { .. } => {
                    o3k_kernel::OperationState::UnknownOutcome
                }
                o3k_kernel::ReconcileOutcome::Retryable { .. } => {
                    o3k_kernel::OperationState::Retryable
                }
                o3k_kernel::ReconcileOutcome::Failed { .. } => o3k_kernel::OperationState::Failed,
                o3k_kernel::ReconcileOutcome::Accepted { .. } => {
                    o3k_kernel::OperationState::Running
                }
            };
            let now = chrono::Utc::now().to_rfc3339();
            let lifecycle = o3k_store::CanonicalOperationLifecycleUpdate::new(
                lifecycle_state,
                1,
                Some(now.clone()),
                matches!(
                    lifecycle_state,
                    o3k_kernel::OperationState::Succeeded | o3k_kernel::OperationState::Failed
                )
                .then_some(now),
                None,
            )
            .map_err(|_| ResourceApplicationError::Internal)?;
            self.store
                .update_canonical_operation_lifecycle(operation_id, &lifecycle)
                .await
                .map_err(|_| ResourceApplicationError::Internal)?;
            self.store
                .update_resource(
                    resource_id,
                    1,
                    &resource.desired_state,
                    observed_state,
                    if complete { 1 } else { 0 },
                    None,
                )
                .await
                .map_err(|_| ResourceApplicationError::Internal)?;
            return Ok(MutationResult {
                operation_id: operation_id.to_string(),
                resource_id: Some(resource_id.to_string()),
                complete,
                resource: Some(serde_json::json!({
                    "api_version": "o3k.io/v1",
                    "kind": descriptor.resource_type.to_string(),
                    "metadata": {"id": resource_id, "generation": 1},
                    "spec": resource.desired_state,
                    "status": {"state": if complete {"READY"} else {"PROVISIONING"}}
                })),
            });
        }
        if descriptor.resource_type.to_string() == "volume:volume_attachment" {
            let workflow = self
                .attachment_workflow
                .as_ref()
                .ok_or(ResourceApplicationError::NotReady)?;
            let source = request.spec.get("source").unwrap_or(&request.spec);
            let server_id = source
                .get("server_id")
                .and_then(serde_json::Value::as_str)
                .and_then(|value| value.parse::<Uuid>().ok())
                .ok_or(ResourceApplicationError::Validation)?;
            let volume_id = source
                .get("volume_id")
                .or_else(|| source.get("id"))
                .and_then(serde_json::Value::as_str)
                .and_then(|value| value.parse::<Uuid>().ok())
                .ok_or(ResourceApplicationError::Validation)?;
            self.server
                .show_server(auth, server_id)
                .await
                .map_err(generic_read_error)?;
            let volume = self
                .store
                .get_volume(volume_id)
                .await
                .map_err(|_| ResourceApplicationError::Internal)?
                .filter(|record| {
                    record.volume.project_id == auth.effective_scope().id().as_str()
                        && record.volume.state == VolumeState::Available
                })
                .ok_or(ResourceApplicationError::Conflict)?;
            let key = idempotency_key
                .map(str::to_owned)
                .unwrap_or_else(|| format!("native:{}", Uuid::new_v4()));
            let attachment_id = request
                .spec
                .get("canonical_id")
                .and_then(serde_json::Value::as_str)
                .and_then(|value| value.parse::<Uuid>().ok())
                .unwrap_or_else(|| {
                    Uuid::new_v5(
                        &Uuid::NAMESPACE_OID,
                        format!(
                            "{}:volume:volume_attachment:{}",
                            auth.effective_scope().id(),
                            key
                        )
                        .as_bytes(),
                    )
                });
            let record = o3k_store::storage::VolumeAttachmentRecordV1 {
                attachment: VolumeAttachment {
                    id: VolumeAttachmentId::from_uuid(attachment_id),
                    project_id: auth.effective_scope().id().as_str().to_owned(),
                    volume_id: volume.volume.id,
                    server_id,
                    execution_scope: StorageExecutionScope::Host("local".to_owned()),
                    access_mode: AttachmentAccessMode::ReadWrite,
                    delete_on_termination: request
                        .spec
                        .get("delete_on_termination")
                        .and_then(serde_json::Value::as_bool)
                        .unwrap_or(false),
                    state: VolumeAttachmentState::Reserved,
                    generation: 1,
                    operation_id: None,
                },
                created_at: chrono::Utc::now().to_rfc3339(),
            };
            self.store
                .insert_volume_attachment_v1(&record)
                .await
                .map_err(|_| ResourceApplicationError::Conflict)?;
            let resource = o3k_store::ResourceRecord {
                id: attachment_id,
                kind: "native_volume_attachment".to_owned(),
                project_id: record.attachment.project_id.clone(),
                generation: 1,
                observed_generation: 1,
                desired_state: serde_json::to_string(&request.spec)
                    .map_err(|_| ResourceApplicationError::Validation)?,
                observed_state: "reserved".to_owned(),
                provider_id: None,
            };
            if self.store.insert_resource(&resource).await.is_err() {
                let _ = self
                    .store
                    .delete_volume_attachment_v1(&resource.project_id, attachment_id)
                    .await;
                return Err(ResourceApplicationError::Internal);
            }
            workflow
                .attach(attachment_id)
                .await
                .map_err(|_| ResourceApplicationError::NotReady)?;
            let attached = self
                .store
                .get_volume_attachment_v1(attachment_id)
                .await
                .map_err(|_| ResourceApplicationError::Internal)?
                .ok_or(ResourceApplicationError::Internal)?;
            return Ok(MutationResult {
                operation_id: format!("native:volume-attachment:create:{attachment_id}"),
                resource_id: Some(attachment_id.to_string()),
                complete: attached.attachment.state == VolumeAttachmentState::Attached,
                resource: Some(native_attachment_json(&attached, Some(&resource))),
            });
        }
        if descriptor.resource_type.to_string() == "volume:volume" {
            #[derive(serde::Deserialize)]
            #[serde(deny_unknown_fields)]
            struct VolumeSpec {
                size_bytes: u64,
                volume_type: String,
                #[serde(default)]
                name: Option<String>,
                #[serde(default)]
                description: Option<String>,
                #[serde(default)]
                metadata: Option<std::collections::BTreeMap<String, String>>,
                #[serde(default)]
                availability_zone: Option<String>,
                #[serde(default, rename = "canonical_id")]
                _canonical_id: Option<Uuid>,
                #[serde(default)]
                migration_id: Option<Uuid>,
                #[serde(default)]
                source_key: Option<String>,
            }
            let spec: VolumeSpec = serde_json::from_value(request.spec.clone().into_value())
                .map_err(|_| ResourceApplicationError::Validation)?;
            if spec.size_bytes == 0 || spec.volume_type.trim().is_empty() {
                return Err(ResourceApplicationError::Validation);
            }
            let key = idempotency_key
                .map(str::to_owned)
                .unwrap_or_else(|| format!("native:{}", Uuid::new_v4()));
            let resource_id = spec._canonical_id.unwrap_or_else(|| {
                Uuid::new_v5(
                    &Uuid::NAMESPACE_OID,
                    format!("{}:volume:volume:{}", auth.effective_scope().id(), key).as_bytes(),
                )
            });
            let operation_id = Uuid::new_v5(
                &Uuid::NAMESPACE_URL,
                format!("volume:create:{resource_id}").as_bytes(),
            );
            let mut metadata = spec.metadata.unwrap_or_default();
            if let Some(migration_id) = spec.migration_id {
                metadata.insert("migration_id".to_owned(), migration_id.to_string());
            }
            if let Some(source_key) = spec.source_key {
                metadata.insert("source_key".to_owned(), source_key);
            }
            let volume = Volume {
                id: VolumeId::from_uuid(resource_id),
                project_id: auth.effective_scope().id().as_str().to_owned(),
                name: spec.name.unwrap_or_else(|| resource_id.to_string()),
                description: spec.description.unwrap_or_default(),
                metadata,
                availability_zone: spec.availability_zone,
                size_bytes: spec.size_bytes,
                volume_type: spec.volume_type,
                backend_id: "local".to_owned(),
                execution_scope: StorageExecutionScope::Host("local".to_owned()),
                state: VolumeState::Requested,
                generation: 1,
                operation_id: Some(operation_id),
                provider_reference: None,
            };
            let record = o3k_store::VolumeRecord {
                volume,
                created_at: chrono::Utc::now().to_rfc3339(),
            };
            let compatibility_generation = record.volume.generation;
            let Some(provider) = self.storage_provider.clone() else {
                return Err(ResourceApplicationError::NotReady);
            };
            match self.store.insert_volume(&record).await {
                Ok(()) => {}
                Err(o3k_store::StoreError::ResourceAlreadyExists) => {
                    let existing = self
                        .store
                        .get_volume(resource_id)
                        .await
                        .map_err(|_| ResourceApplicationError::Internal)?
                        .ok_or(ResourceApplicationError::Internal)?;
                    // Same-key replay with changed semantics is key reuse,
                    // not a replay: this arm writes no idempotency
                    // reservation, so the deterministic id is the only
                    // replay identity and the durable result must be pinned
                    // to the request's declared semantics — exactly as the
                    // generic idempotency contract treats changed bodies.
                    if existing.volume.name != record.volume.name
                        || existing.volume.description != record.volume.description
                        || existing.volume.size_bytes != record.volume.size_bytes
                        || existing.volume.volume_type != record.volume.volume_type
                        || existing.volume.availability_zone != record.volume.availability_zone
                        || existing.volume.metadata != record.volume.metadata
                    {
                        return Err(ResourceApplicationError::IdempotencyConflict);
                    }
                    // The row already exists from a prior attempt (the create
                    // is idempotent by deterministic resource id), so the open
                    // observation is replayed here rather than only in the
                    // fresh-insert path. Without this, a retry after a failed
                    // first observation would silently drop the allocation.
                    // The replay only opens while the row is durably consuming.
                    self.open_volume_metering_if_consuming(&existing).await?;
                    return Ok(MutationResult {
                        operation_id: operation_id.to_string(),
                        resource_id: Some(resource_id.to_string()),
                        complete: existing.volume.state == VolumeState::Available,
                        resource: Some(native_volume_json(&existing)),
                    });
                }
                Err(_) => return Err(ResourceApplicationError::Internal),
            }
            o3k_api::realize_native_volume_create(
                self.store.clone(),
                provider,
                record,
                self.metering.as_ref(),
            )
            .await
            .map_err(|_| ResourceApplicationError::Retryable)?;
            // The legacy generic-resource index is a compatibility projection
            // used by relationship tests and older native callers.  The
            // canonical volume above remains the sole authority.
            match self
                .store
                .insert_resource(&o3k_store::ResourceRecord {
                    id: resource_id,
                    kind: "volume".to_owned(),
                    project_id: auth.effective_scope().id().as_str().to_owned(),
                    // The native volume row is authoritative and has already
                    // advanced through provider realization.  Keep the
                    // compatibility projection at the same generation so
                    // later lifecycle updates cannot be rejected as stale.
                    generation: compatibility_generation as i64,
                    observed_generation: compatibility_generation as i64,
                    desired_state: "available".to_owned(),
                    observed_state: "available".to_owned(),
                    provider_id: None,
                })
                .await
            {
                Ok(()) | Err(o3k_store::StoreError::ResourceAlreadyExists) => {}
                Err(_) => return Err(ResourceApplicationError::Internal),
            }
            match self
                .store
                .insert_operation(&o3k_store::OperationRecord {
                    id: operation_id,
                    resource_id,
                    kind: "lifecycle:create".to_owned(),
                    state: o3k_store::OperationState::Succeeded,
                    provider_operation_id: None,
                    error_category: None,
                    error_message: None,
                })
                .await
            {
                Ok(()) | Err(o3k_store::StoreError::ResourceAlreadyExists) => {}
                Err(_) => return Err(ResourceApplicationError::Internal),
            }
            let record = self
                .store
                .get_volume(resource_id)
                .await
                .map_err(|_| ResourceApplicationError::Internal)?
                .ok_or(ResourceApplicationError::Internal)?;
            return Ok(MutationResult {
                operation_id: operation_id.to_string(),
                resource_id: Some(resource_id.to_string()),
                complete: true,
                resource: Some(native_volume_json(&record)),
            });
        }
        if descriptor.resource_type.to_string() == "network:network" {
            // The public network create contract is name-only
            // (NetworkCreateSpec, deny_unknown_fields); the handler has
            // already validated the spec, so the envelope indirection and
            // canonical_id/migration fields that predate the contract are
            // gone from this path.
            let name = request
                .spec
                .get("name")
                .and_then(serde_json::Value::as_str)
                .ok_or(ResourceApplicationError::Validation)?
                .to_owned();
            // Idempotency: derive the canonical identity deterministically
            // from the caller's idempotency key (same pattern as the volume
            // arm), so a same-key retry converges on the same resource
            // instead of creating a duplicate or name-conflicting.
            let key = idempotency_key
                .map(str::to_owned)
                .unwrap_or_else(|| format!("native:network:{}", Uuid::new_v4()));
            let canonical_id = Uuid::new_v5(
                &Uuid::NAMESPACE_OID,
                format!("{}:network:network:{}", auth.effective_scope().id(), key).as_bytes(),
            );
            let project_id = auth.effective_scope().id().as_str().to_owned();
            let (network_id, created_here) = match self
                .network_service
                .create_network_for_project_with_id(&project_id, canonical_id, name.clone())
                .await
            {
                Ok(network) => (network.id, true),
                // A durable quota denial is a non-retryable limit, exactly as
                // on the compute surface — it is never a replay probe.
                Err(o3k_network::NetworkError::QuotaExceeded { .. }) => {
                    return Err(ResourceApplicationError::Forbidden);
                }
                // Replay: a same-key retry derives the same canonical id, so a
                // name conflict on that exact id is the durable result of the
                // original call — but only when the semantics match: reusing
                // the key with a different name is a conflict, exactly as the
                // generic idempotency contract treats changed bodies.
                Err(_) => {
                    let existing = self
                        .network_service
                        .list_canonical_networks_for_project(&project_id)
                        .await
                        .map_err(|_| ResourceApplicationError::Internal)?;
                    let candidate = existing
                        .into_iter()
                        .find(|candidate| candidate.id == canonical_id)
                        .ok_or(ResourceApplicationError::Conflict)?;
                    if candidate.name != name {
                        return Err(ResourceApplicationError::IdempotencyConflict);
                    }
                    // Pre-existing durable authority: a later ledger failure
                    // must never compensate (delete) a row this call did not
                    // create.
                    (candidate.id, false)
                }
            };
            // The generic native ledger must reflect every natively created
            // network, not only migration envelopes: the generic
            // list/show/delete routes read this row, so without it a network
            // created through the native route is invisible to the native
            // collection and cannot be deleted through it either. The row's
            // observed state deliberately uses the canonical network state
            // vocabulary ("active", matching the canonical record this row
            // shadows) rather than the migration-envelope "READY" convention:
            // composition consumers observe children through this projection,
            // and the canonical vocabulary is what they accept as ready.
            let record = o3k_store::ResourceRecord {
                id: network_id,
                kind: "network:network".to_owned(),
                project_id: project_id.clone(),
                generation: 1,
                observed_generation: 1,
                desired_state: serde_json::to_string(&request.spec)
                    .map_err(|_| ResourceApplicationError::Internal)?,
                observed_state: "active".to_owned(),
                provider_id: None,
            };
            match self.store.insert_resource(&record).await {
                Ok(()) => {}
                Err(o3k_store::StoreError::ResourceAlreadyExists) => {
                    // Same-key replay re-derives the same row. A finalized
                    // (DELETED) row is never a replay target: the canonical
                    // create above already succeeded with a fresh generation,
                    // so accepting would split canonical and ledger truth.
                    // A row whose stored name differs from the request is
                    // key reuse with changed semantics — a conflict, not a
                    // replay. Only an identical live row replays. Any other
                    // row at this id must not orphan the canonical network
                    // created above.
                    let existing = self
                        .store
                        .get_resource(network_id)
                        .await
                        .map_err(|_| ResourceApplicationError::Internal)?;
                    let stored_name =
                        serde_json::from_str::<serde_json::Value>(&existing.desired_state)
                            .ok()
                            .and_then(|spec| spec.get("name").cloned())
                            .and_then(|name| name.as_str().map(str::to_owned));
                    let replay = existing.kind == "network:network"
                        && existing.project_id == record.project_id
                        && existing.observed_state != "DELETED"
                        && stored_name.as_deref() == Some(name.as_str());
                    if !replay {
                        if created_here {
                            self.network_service
                                .delete_network_for_project(&project_id, network_id)
                                .await
                                .map_err(|_| ResourceApplicationError::Internal)?;
                        }
                        return Err(ResourceApplicationError::Conflict);
                    }
                }
                Err(_) => {
                    // The canonical network and its quota reservation are
                    // already committed; without the ledger row the resource
                    // would be visible to native show yet invisible to native
                    // list and undeletable through it. Compensate by removing
                    // the canonical network so the failed create leaves no
                    // orphan authority — but only when this call created it.
                    if created_here {
                        self.network_service
                            .delete_network_for_project(&project_id, network_id)
                            .await
                            .map_err(|_| ResourceApplicationError::Internal)?;
                    }
                    return Err(ResourceApplicationError::Internal);
                }
            }
            let record = self
                .store
                .get_resource(network_id)
                .await
                .map_err(|_| ResourceApplicationError::Internal)?;
            return Ok(MutationResult {
                operation_id: Uuid::new_v5(
                    &Uuid::NAMESPACE_URL,
                    format!("network:create:{network_id}").as_bytes(),
                )
                .to_string(),
                resource_id: Some(network_id.to_string()),
                complete: true,
                resource: Some(network_external_json(&record)),
            });
        }
        if descriptor.resource_type.to_string() == "network:subnet" {
            let source = request.spec.get("source").unwrap_or(&request.spec);
            let source = source.get("subnet").unwrap_or(source);
            let network_id = source
                .get("network_id")
                .and_then(serde_json::Value::as_str)
                .and_then(|v| v.parse::<Uuid>().ok())
                .ok_or(ResourceApplicationError::Validation)?;
            let cidr = source
                .get("cidr")
                .and_then(serde_json::Value::as_str)
                .ok_or(ResourceApplicationError::Validation)?
                .to_owned();
            let name = source
                .get("name")
                .and_then(serde_json::Value::as_str)
                .unwrap_or("migrated-subnet")
                .to_owned();
            let canonical_id = request
                .spec
                .get("canonical_id")
                .and_then(serde_json::Value::as_str)
                .map(str::parse::<Uuid>)
                .transpose()
                .map_err(|_| ResourceApplicationError::Validation)?
                .unwrap_or_else(Uuid::now_v7);
            let subnet = self
                .network_service
                .create_subnet_for_project_with_id(
                    auth.effective_scope().id().as_str(),
                    canonical_id,
                    network_id,
                    name,
                    cidr,
                    None,
                    None,
                    None,
                )
                .await
                .map_err(|_| ResourceApplicationError::Conflict)?;
            let id = subnet.id;
            let record = o3k_store::ResourceRecord {
                id,
                kind: "network:subnet".into(),
                project_id: auth.effective_scope().id().as_str().into(),
                generation: 1,
                observed_generation: 1,
                desired_state: serde_json::to_string(&request.spec)
                    .map_err(|_| ResourceApplicationError::Internal)?,
                observed_state: "READY".into(),
                provider_id: None,
            };
            self.store
                .insert_resource(&record)
                .await
                .map_err(|_| ResourceApplicationError::Internal)?;
            return Ok(MutationResult {
                operation_id: format!("native:subnet:create:{id}"),
                resource_id: Some(id.to_string()),
                complete: true,
                resource: Some(generic_external_json(&record)),
            });
        }
        if descriptor.resource_type.to_string() == "network:port" {
            let source = request.spec.get("source").unwrap_or(&request.spec);
            let source = source.get("port").unwrap_or(source);
            let network_id = source
                .get("network_id")
                .and_then(serde_json::Value::as_str)
                .and_then(|v| v.parse::<Uuid>().ok())
                .ok_or(ResourceApplicationError::Validation)?;
            let name = source
                .get("name")
                .and_then(serde_json::Value::as_str)
                .unwrap_or("migrated-port")
                .to_owned();
            let canonical_id = request
                .spec
                .get("canonical_id")
                .and_then(serde_json::Value::as_str)
                .map(str::parse::<Uuid>)
                .transpose()
                .map_err(|_| ResourceApplicationError::Validation)?
                .unwrap_or_else(Uuid::now_v7);
            let requested_fixed_ip = source
                .get("fixed_ips")
                .and_then(serde_json::Value::as_array)
                .and_then(|items| items.first())
                .and_then(|item| {
                    Some((
                        item.get("subnet_id")?.as_str()?.parse().ok()?,
                        item.get("ip_address")?.as_str()?.parse().ok(),
                    ))
                });
            let port = self
                .network_service
                .create_port_for_project_with_id_and_fixed_ip(
                    auth.effective_scope().id().as_str(),
                    canonical_id,
                    network_id,
                    name,
                    requested_fixed_ip,
                )
                .await
                .map_err(|_| ResourceApplicationError::Conflict)?;
            let id = port.id;
            let record = o3k_store::ResourceRecord {
                id,
                kind: "network:port".into(),
                project_id: auth.effective_scope().id().as_str().into(),
                generation: 1,
                observed_generation: 1,
                desired_state: serde_json::to_string(&request.spec)
                    .map_err(|_| ResourceApplicationError::Internal)?,
                observed_state: "READY".into(),
                provider_id: None,
            };
            self.store
                .insert_resource(&record)
                .await
                .map_err(|_| ResourceApplicationError::Internal)?;
            return Ok(MutationResult {
                operation_id: format!("native:port:create:{id}"),
                resource_id: Some(id.to_string()),
                complete: true,
                resource: Some(generic_external_json(&record)),
            });
        }
        if descriptor.resource_type.to_string() == "network:security_group" {
            let source = request.spec.get("source").unwrap_or(&request.spec);
            let source = source.get("security_group").unwrap_or(source);
            let group = self
                .network_service
                .create_security_group_for_project(
                    auth.effective_scope().id().as_str(),
                    source
                        .get("name")
                        .and_then(serde_json::Value::as_str)
                        .ok_or(ResourceApplicationError::Validation)?
                        .to_owned(),
                    source
                        .get("description")
                        .and_then(serde_json::Value::as_str)
                        .unwrap_or_default()
                        .to_owned(),
                )
                .await
                .map_err(|_| ResourceApplicationError::Conflict)?;
            let record = o3k_store::ResourceRecord {
                id: group.id,
                kind: "network:security_group".into(),
                project_id: auth.effective_scope().id().as_str().into(),
                generation: 1,
                observed_generation: 1,
                desired_state: serde_json::to_string(&request.spec)
                    .map_err(|_| ResourceApplicationError::Internal)?,
                observed_state: "READY".into(),
                provider_id: None,
            };
            self.store
                .insert_resource(&record)
                .await
                .map_err(|_| ResourceApplicationError::Internal)?;
            return Ok(MutationResult {
                operation_id: format!("native:security-group:create:{}", group.id),
                resource_id: Some(group.id.to_string()),
                complete: true,
                resource: Some(generic_external_json(&record)),
            });
        }
        if descriptor.resource_type.to_string() == "network:security_group_rule" {
            let source = request.spec.get("source").unwrap_or(&request.spec);
            let source = source.get("security_group_rule").unwrap_or(source);
            let group_id = source
                .get("security_group_id")
                .and_then(serde_json::Value::as_str)
                .and_then(|value| value.parse::<Uuid>().ok())
                .ok_or(ResourceApplicationError::Validation)?;
            let rule = self
                .network_service
                .create_security_group_rule_for_project(
                    auth.effective_scope().id().as_str(),
                    group_id,
                    source
                        .get("direction")
                        .and_then(serde_json::Value::as_str)
                        .unwrap_or("ingress")
                        .to_owned(),
                    source
                        .get("protocol")
                        .and_then(serde_json::Value::as_str)
                        .unwrap_or("tcp")
                        .to_owned(),
                    source
                        .get("port_range_min")
                        .and_then(serde_json::Value::as_u64)
                        .map(|value| {
                            u16::try_from(value).map_err(|_| ResourceApplicationError::Validation)
                        })
                        .transpose()?,
                    source
                        .get("port_range_max")
                        .and_then(serde_json::Value::as_u64)
                        .map(|value| {
                            u16::try_from(value).map_err(|_| ResourceApplicationError::Validation)
                        })
                        .transpose()?,
                    source
                        .get("remote_ip_prefix")
                        .and_then(serde_json::Value::as_str)
                        .map(str::to_owned),
                )
                .await
                .map_err(|_| ResourceApplicationError::Conflict)?;
            let record = o3k_store::ResourceRecord {
                id: rule.id,
                kind: "network:security_group_rule".into(),
                project_id: auth.effective_scope().id().as_str().into(),
                generation: 1,
                observed_generation: 1,
                desired_state: serde_json::to_string(&request.spec)
                    .map_err(|_| ResourceApplicationError::Internal)?,
                observed_state: "READY".into(),
                provider_id: None,
            };
            self.store
                .insert_resource(&record)
                .await
                .map_err(|_| ResourceApplicationError::Internal)?;
            return Ok(MutationResult {
                operation_id: format!("native:security-group-rule:create:{}", rule.id),
                resource_id: Some(rule.id.to_string()),
                complete: true,
                resource: Some(generic_external_json(&record)),
            });
        }
        if descriptor.resource_type.to_string() == "network:router" {
            let source = request.spec.get("source").unwrap_or(&request.spec);
            let source = source.get("router").unwrap_or(source);
            let canonical_id = request
                .spec
                .get("canonical_id")
                .and_then(serde_json::Value::as_str)
                .map(str::parse::<Uuid>)
                .transpose()
                .map_err(|_| ResourceApplicationError::Validation)?
                .unwrap_or_else(Uuid::now_v7);
            let gateway = self
                .network_service
                .create_l3_gateway_for_project_with_id(
                    canonical_id,
                    auth.effective_scope().id().as_str(),
                    source
                        .get("name")
                        .and_then(serde_json::Value::as_str)
                        .ok_or(ResourceApplicationError::Validation)?
                        .to_owned(),
                    Some(
                        self.external_realm_id(auth.effective_scope().id().as_str())
                            .await?,
                    ),
                    source
                        .get("enable_snat")
                        .and_then(serde_json::Value::as_bool)
                        .or_else(|| {
                            source
                                .get("external_gateway_info")
                                .and_then(|value| value.get("enable_snat"))
                                .and_then(serde_json::Value::as_bool)
                        })
                        .unwrap_or(true),
                )
                .await
                .map_err(|_| ResourceApplicationError::Conflict)?;
            let record = o3k_store::ResourceRecord {
                id: gateway.id,
                kind: "network:router".into(),
                project_id: auth.effective_scope().id().as_str().into(),
                generation: gateway.generation as i64,
                observed_generation: gateway.generation as i64,
                desired_state: serde_json::to_string(&request.spec)
                    .map_err(|_| ResourceApplicationError::Internal)?,
                observed_state: "READY".into(),
                provider_id: None,
            };
            self.store
                .insert_resource(&record)
                .await
                .map_err(|_| ResourceApplicationError::Internal)?;
            return Ok(MutationResult {
                operation_id: format!("native:router:create:{}", gateway.id),
                resource_id: Some(gateway.id.to_string()),
                complete: true,
                resource: Some(generic_external_json(&record)),
            });
        }
        if descriptor.resource_type.to_string() == "network:router_interface" {
            let source = request.spec.get("source").unwrap_or(&request.spec);
            let source = source.get("router_interface").unwrap_or(source);
            let router_id = source
                .get("router_id")
                .or_else(|| source.get("device_id"))
                .and_then(serde_json::Value::as_str)
                .and_then(|value| value.parse::<Uuid>().ok())
                .ok_or(ResourceApplicationError::Validation)?;
            let subnet_id = source
                .get("subnet_id")
                .or_else(|| {
                    source
                        .get("fixed_ips")
                        .and_then(serde_json::Value::as_array)
                        .and_then(|items| items.first())
                        .and_then(|item| item.get("subnet_id"))
                })
                .and_then(serde_json::Value::as_str)
                .and_then(|value| value.parse::<Uuid>().ok())
                .ok_or(ResourceApplicationError::Validation)?;
            let canonical_id = request
                .spec
                .get("canonical_id")
                .and_then(serde_json::Value::as_str)
                .map(str::parse::<Uuid>)
                .transpose()
                .map_err(|_| ResourceApplicationError::Validation)?
                .unwrap_or_else(Uuid::now_v7);
            let attachment = self
                .network_service
                .attach_l3_gateway_realm_with_id(
                    canonical_id,
                    auth.effective_scope().id().as_str(),
                    &router_id,
                    &subnet_id,
                )
                .await
                .map_err(|_| ResourceApplicationError::Conflict)?;
            let record = o3k_store::ResourceRecord {
                id: attachment.id,
                kind: "network:router_interface".into(),
                project_id: auth.effective_scope().id().as_str().into(),
                generation: attachment.generation as i64,
                observed_generation: attachment.generation as i64,
                desired_state: serde_json::to_string(&request.spec)
                    .map_err(|_| ResourceApplicationError::Internal)?,
                observed_state: "READY".into(),
                provider_id: None,
            };
            self.store
                .insert_resource(&record)
                .await
                .map_err(|_| ResourceApplicationError::Internal)?;
            return Ok(MutationResult {
                operation_id: format!("native:router-interface:create:{}", attachment.id),
                resource_id: Some(attachment.id.to_string()),
                complete: true,
                resource: Some(generic_external_json(&record)),
            });
        }
        if descriptor.resource_type.to_string() == "network:floating_ip" {
            let allocator = self
                .public_allocator
                .as_ref()
                .ok_or(ResourceApplicationError::NotReady)?;
            let realm_id = self
                .external_realm_id(auth.effective_scope().id().as_str())
                .await?;
            let source = request.spec.get("source").unwrap_or(&request.spec);
            let source = source.get("floatingip").unwrap_or(source);
            // The source cloud's external-network UUID is not a destination
            // identity and is therefore intentionally not rewritten when the
            // source project cannot read the shared public network.  The
            // destination's configured external realm is the authority for
            // this bounded public-address pool; require the source request to
            // carry an external-network reference, but never treat its UUID
            // as an O3K resource identity.
            if source
                .get("floating_network_id")
                .and_then(serde_json::Value::as_str)
                .is_none()
            {
                return Err(ResourceApplicationError::Validation);
            }
            let port_id = source
                .get("port_id")
                .and_then(serde_json::Value::as_str)
                .and_then(|value| value.parse::<Uuid>().ok());
            if let Some(port_id) = port_id {
                self.network_service
                    .get_port(auth, port_id)
                    .await
                    .map_err(|_| ResourceApplicationError::Validation)?;
            }
            let operation_id = format!(
                "native:{}:{}",
                request
                    .spec
                    .get("migration_id")
                    .and_then(serde_json::Value::as_str)
                    .unwrap_or("unknown"),
                request
                    .spec
                    .get("source_key")
                    .and_then(serde_json::Value::as_str)
                    .unwrap_or_else(|| idempotency_key.unwrap_or("floating-ip"))
            );
            let canonical_id = request
                .spec
                .get("canonical_id")
                .and_then(serde_json::Value::as_str)
                .map(str::parse::<Uuid>)
                .transpose()
                .map_err(|_| ResourceApplicationError::Validation)?;
            let mut binding = allocator
                .allocate_with_id(
                    auth.effective_scope().id().as_str(),
                    &operation_id,
                    canonical_id.unwrap_or_else(Uuid::now_v7),
                )
                .map_err(|error| {
                    tracing::warn!(
                        error = %error,
                        operation_id = %operation_id,
                        "floating address allocation rejected"
                    );
                    ResourceApplicationError::Conflict
                })?;
            if let Some(port_id) = port_id {
                binding = allocator
                    .associate(
                        auth.effective_scope().id().as_str(),
                        binding.allocation_id,
                        port_id,
                    )
                    .map_err(|error| {
                        tracing::warn!(
                            error = %error,
                            allocation_id = %binding.allocation_id,
                            port_id = %port_id,
                            "floating address association rejected"
                        );
                        ResourceApplicationError::Conflict
                    })?;
            }
            let id = binding.allocation_id;
            let record = o3k_store::ResourceRecord {
                id,
                kind: "network:floating_ip".to_owned(),
                project_id: auth.effective_scope().id().as_str().to_owned(),
                generation: binding.generation as i64,
                observed_generation: binding.generation as i64,
                desired_state: serde_json::to_string(&request.spec)
                    .map_err(|_| ResourceApplicationError::Validation)?,
                observed_state: "READY".to_owned(),
                provider_id: None,
            };
            self.store
                .insert_resource(&record)
                .await
                .map_err(|_| ResourceApplicationError::Internal)?;
            return Ok(MutationResult {
                operation_id,
                resource_id: Some(id.to_string()),
                complete: true,
                resource: Some(floating_ip_json(
                    &binding,
                    Some(realm_id),
                    auth.effective_scope().id().as_str(),
                    request
                        .spec
                        .get("migration_id")
                        .and_then(serde_json::Value::as_str),
                    request
                        .spec
                        .get("source_key")
                        .and_then(serde_json::Value::as_str),
                )),
            });
        }
        if descriptor.resource_type.to_string() != "compute:server" {
            return Err(ResourceApplicationError::UnsupportedOperation);
        }
        #[derive(serde::Deserialize)]
        #[serde(deny_unknown_fields)]
        #[allow(dead_code)]
        struct ComputeSpec {
            name: String,
            image_id: String,
            flavor_id: Uuid,
            network_ids: Vec<String>,
            #[serde(default)]
            key_name: Option<String>,
            #[serde(default)]
            ssh_public_key: Option<String>,
            // MigrationRunner carries source identity alongside the
            // destination compute intent. Keep the semantic payload strict
            // while accepting that bounded execution metadata at this
            // compatibility edge.
            #[serde(default, rename = "canonical_id")]
            _canonical_id: Option<Uuid>,
            #[serde(default)]
            migration_id: Option<Uuid>,
            #[serde(default)]
            source_key: Option<String>,
        }
        let semantic_request = serde_json::json!({"spec": request.spec});
        let spec: ComputeSpec = serde_json::from_value(semantic_request["spec"].clone())
            .map_err(|_| ResourceApplicationError::Validation)?;
        let key = idempotency_key
            .map(str::to_owned)
            .unwrap_or_else(|| format!("native:{}", Uuid::new_v4()))
            .replace('/', "_");
        let project_id = auth.effective_scope().id().as_str().to_owned();
        // Issue #1035: hold the orphan-repair serialization lock across
        // [existing-port validation/resolution -> durable intent persist] so a
        // concurrent orphan repair sweep can neither release a port mid-create
        // nor allow this create to durably reference a port the sweep just
        // released. The lock is taken before any network call, matching the
        // sweep's locking.
        let create_wait_marker =
            std::env::var_os("O3K_TEST_CREATE_LOCK_WAITER_MARKER").map(std::path::PathBuf::from);
        let _orphan_repair_guard = self
            .compute
            .orphan_repair_create_lock_guard(create_wait_marker.as_deref())
            .await;
        let mut network_ids = Vec::with_capacity(spec.network_ids.len());
        let mut owned_network_ids = Vec::new();
        // Validate all UUID references before creating any endpoint, so a
        // later invalid attachment cannot strand an earlier one.
        for network_id in &spec.network_ids {
            let Ok(id) = network_id.parse::<Uuid>() else {
                continue;
            };
            if self.network_service.get_port(auth, id).await.is_ok() {
                continue;
            }
            if self.network_service.get_network(auth, id).await.is_ok() {
                continue;
            }
            if self
                .network_service
                .find_port_by_id(id)
                .await
                .map_err(|_| ResourceApplicationError::Conflict)?
                .is_some()
            {
                return Err(ResourceApplicationError::Forbidden);
            }
            return Err(ResourceApplicationError::NotFound);
        }
        for network_id in &spec.network_ids {
            // Durable port references cross the Network authority boundary;
            // the provider's legacy opaque test references remain outside it.
            if let Ok(port_id) = network_id.parse::<Uuid>() {
                match self.network_service.get_port(auth, port_id).await {
                    Ok(_) => network_ids.push(port_id.to_string()),
                    Err(o3k_network::NetworkError::Unauthorized) => {
                        self.compensate_native_network_ports(&project_id, &owned_network_ids)
                            .await;
                        return Err(ResourceApplicationError::Forbidden);
                    }
                    // P12.6 generic composition also carries UUID child
                    // slots which are not NetworkService ports. Preserve
                    // that contract; resolvable ports remain owner-checked.
                    Err(o3k_network::NetworkError::NotFound) => {
                        let existing_port =
                            match self.network_service.find_port_by_id(port_id).await {
                                Ok(port) => port,
                                Err(_) => {
                                    self.compensate_native_network_ports(
                                        &project_id,
                                        &owned_network_ids,
                                    )
                                    .await;
                                    return Err(ResourceApplicationError::Conflict);
                                }
                            };
                        if let Some(port) = existing_port
                            && port.project_id != auth.effective_scope().id().as_str()
                        {
                            self.compensate_native_network_ports(&project_id, &owned_network_ids)
                                .await;
                            return Err(ResourceApplicationError::Forbidden);
                        }
                        // Native callers select canonical networks, while the
                        // compute provider consumes canonical ports. Resolve a
                        // network through the same Network authority used by
                        // the compatibility adapter and create one endpoint;
                        // never treat compatibility-side network rows as
                        // native authority.
                        if self
                            .network_service
                            .get_network(auth, port_id)
                            .await
                            .is_ok()
                        {
                            let deterministic_port_id = Uuid::new_v5(
                                &Uuid::NAMESPACE_OID,
                                format!("{project_id}:compute.server:{key}:{port_id}").as_bytes(),
                            );
                            let (port, created_here) = match self
                                .network_service
                                .create_port_for_project_with_stable_id(
                                    &project_id,
                                    deterministic_port_id,
                                    port_id,
                                    format!("o3k-server:{project_id}:{key}"),
                                )
                                .await
                            {
                                Ok(port) => (port, true),
                                Err(o3k_network::NetworkError::Conflict) => {
                                    let existing = match self
                                        .network_service
                                        .get_port_for_project(&project_id, deterministic_port_id)
                                        .await
                                    {
                                        Ok(existing) => existing,
                                        Err(_) => {
                                            self.compensate_native_network_ports(
                                                &project_id,
                                                &owned_network_ids,
                                            )
                                            .await;
                                            return Err(ResourceApplicationError::Conflict);
                                        }
                                    };
                                    if existing.network_id != port_id
                                        || existing.name != format!("o3k-server:{project_id}:{key}")
                                    {
                                        self.compensate_native_network_ports(
                                            &project_id,
                                            &owned_network_ids,
                                        )
                                        .await;
                                        return Err(ResourceApplicationError::Conflict);
                                    }
                                    (existing, false)
                                }
                                Err(_) => {
                                    self.compensate_native_network_ports(
                                        &project_id,
                                        &owned_network_ids,
                                    )
                                    .await;
                                    return Err(ResourceApplicationError::Conflict);
                                }
                            };
                            network_ids.push(port.id.to_string());
                            if created_here {
                                owned_network_ids.push(port.id);
                            }
                        } else {
                            self.compensate_native_network_ports(&project_id, &owned_network_ids)
                                .await;
                            return Err(ResourceApplicationError::NotFound);
                        }
                    }
                    Err(_) => {
                        self.compensate_native_network_ports(&project_id, &owned_network_ids)
                            .await;
                        return Err(ResourceApplicationError::Conflict);
                    }
                }
            } else {
                network_ids.push(network_id.clone());
            }
        }
        let canonical_id = spec._canonical_id;
        let compute_key = canonical_id.map_or_else(|| key.clone(), |id| format!("canonical:{id}"));
        // Native callers may identify a keypair by its non-secret name. Resolve
        // that reference at the Compute/IAM boundary so the provider receives
        // only the public key needed for config-drive generation. Never make a
        // client or compatibility adapter transport private key material.
        let key_name = spec.key_name.clone();
        let ssh_public_key = if let Some(public_key) = spec.ssh_public_key.clone() {
            Some(public_key)
        } else if let Some(key_name) = key_name.as_deref() {
            match self.compute.show_keypair_for_auth(auth, key_name).await {
                Ok(keypair) => Some(keypair.public_key),
                Err(error) => {
                    self.compensate_native_network_ports(&project_id, &owned_network_ids)
                        .await;
                    return Err(compute_error(error));
                }
            }
        } else {
            None
        };
        let action = descriptor
            .lifecycle_actions
            .get(&o3k_native_api::resource::LifecycleOperation::Create)
            .cloned()
            .ok_or(ResourceApplicationError::UnsupportedOperation)?;
        let context = o3k_reconciler::CanonicalMutationContext::new(
            action,
            auth.principal().id().to_string(),
            auth.effective_scope().clone(),
            None,
            compute_key.clone(),
            semantic_request,
        )
        .map_err(|error| {
            tracing::warn!(error = ?error, "canonical native server context rejected");
            ResourceApplicationError::Validation
        });
        let context = match context {
            Ok(context) => context,
            Err(error) => {
                self.compensate_native_network_ports(&project_id, &owned_network_ids)
                    .await;
                return Err(error);
            }
        };
        // Keep provider command identity scoped even when the client reuses
        // the same canonical key in another tenant. The same identity derives
        // the durable server id, which the failure path needs to classify the
        // create outcome.
        let provider_idempotency_key = format!("{}:{compute_key}", auth.effective_scope().id());
        let result = self
            .compute
            .create_server_for_auth_canonical(
                auth,
                o3k_compute::ServerCreateInput {
                    user_id: auth.principal().id().to_string(),
                    project_id: project_id.clone(),
                    name: spec.name,
                    image_id: spec.image_id,
                    flavor_id: spec.flavor_id,
                    network_ids,
                    key_name,
                    config_drive: ssh_public_key.map(|ssh_public_key| {
                        o3k_provider::ConfigDriveRequest {
                            user_data: Vec::new(),
                            vendor_data: None,
                            ssh_public_key,
                        }
                    }),
                    idempotency_key: provider_idempotency_key.clone(),
                },
                context,
            )
            .await;
        let receipt = match result {
            Ok(receipt) => receipt,
            Err(error) => {
                tracing::warn!(error = ?error, "canonical native server create failed");
                self.compensate_native_network_ports_after_create_failure(
                    auth,
                    &project_id,
                    &provider_idempotency_key,
                    &owned_network_ids,
                )
                .await;
                return Err(compute_error(error));
            }
        };
        let server = receipt.resource;
        let resource = if let (Some(migration_id), Some(source_key)) =
            (spec.migration_id.as_ref(), spec.source_key.as_deref())
        {
            self.annotate_server_migration_metadata(server.id.as_uuid(), migration_id, source_key)
                .await?
        } else {
            self.store
                .get_resource(server.id.as_uuid())
                .await
                .map_err(|_| ResourceApplicationError::Internal)?
        };
        Ok(MutationResult {
            operation_id: receipt.operation_id.to_string(),
            resource_id: Some(server.id.as_uuid().to_string()),
            complete: matches!(
                receipt.operation_state,
                o3k_store::OperationState::Succeeded
            ),
            resource: Some(server_json_with_resource(
                ServerItem {
                    id: server.id.as_uuid().to_string(),
                    project_id: server.project_id,
                    name: server.name,
                    flavor_id: server.flavor_id.to_string(),
                    image_id: server.image_id,
                    state: o3k_store::server_state_to_storage(server.state).to_owned(),
                    generation: resource.generation,
                    created_at: None,
                    migration_id: resource
                        .desired_state
                        .as_str()
                        .parse::<serde_json::Value>()
                        .ok()
                        .and_then(|value| {
                            value
                                .get("migration_id")
                                .and_then(serde_json::Value::as_str)
                                .map(ToOwned::to_owned)
                        }),
                    source_key: resource
                        .desired_state
                        .as_str()
                        .parse::<serde_json::Value>()
                        .ok()
                        .and_then(|value| {
                            value
                                .get("source_key")
                                .and_then(serde_json::Value::as_str)
                                .map(ToOwned::to_owned)
                        }),
                },
                Some(&resource),
            )),
        })
    }

    async fn relationships(
        &self,
        descriptor: &ResourceDescriptor,
        auth: &o3k_kernel::AuthContext,
        id: &str,
        query: &o3k_native_api::pagination::ResourceQuery,
        cursors: &o3k_native_api::pagination::CursorConfig,
    ) -> Result<
        o3k_native_api::pagination::ResourcePage<o3k_native_api::resource::RelationshipView>,
        ResourceApplicationError,
    > {
        let parent = Uuid::parse_str(id).map_err(|_| ResourceApplicationError::NotFound)?;
        let expected_query_resource = format!("relationship:{}:{}", descriptor.resource_type, id);
        if query.resource_type() != expected_query_resource
            || query.scope_id() != auth.effective_scope().id().as_str()
        {
            return Err(ResourceApplicationError::NotFound);
        }
        let record = self
            .store
            .get_resource(parent)
            .await
            .map_err(|error| match error {
                o3k_store::StoreError::ResourceNotFound => ResourceApplicationError::NotFound,
                _ => ResourceApplicationError::Internal,
            })?;
        let descriptor_type = descriptor.resource_type.to_string();
        let Some(expected_kind) = bounded_store_kind(&descriptor_type) else {
            return Err(ResourceApplicationError::NotFound);
        };
        if record.project_id != auth.effective_scope().id().as_str() || record.kind != expected_kind
        {
            return Err(ResourceApplicationError::NotFound);
        }
        let bounded = u32::try_from(query.limit().saturating_add(1))
            .map_err(|_| ResourceApplicationError::Internal)?;
        let records = self
            .store
            .list_relationships_page(parent, query.continuation_key(), bounded)
            .await
            .map_err(|_| ResourceApplicationError::Internal)?;
        let has_more = records.len() > query.limit();
        let mut records = records;
        if has_more {
            records.truncate(query.limit());
        }
        let continuation = has_more
            .then(|| records.last().map(|record| record.slot.clone()))
            .flatten();
        let items = records
            .into_iter()
            .map(|record| {
                Ok(o3k_native_api::resource::RelationshipView {
                    slot: record.slot,
                    resource_type: record.expected_child_resource_type,
                    resource_id: record.child_resource_id.map(|id| id.to_string()),
                    ownership: record.ownership,
                    state: record.state,
                    parent_operation_id: record.parent_operation_id.to_string(),
                    child_operation_id: record.child_operation_id.map(|id| id.to_string()),
                })
            })
            .collect::<Result<Vec<_>, _>>()?;
        let repository = o3k_native_api::pagination::RepositoryPage::new(
            items,
            has_more,
            continuation,
            query.limit(),
        )
        .map_err(|_| ResourceApplicationError::Internal)?;
        cursors
            .complete_page(query, repository)
            .map_err(|_| ResourceApplicationError::Internal)
    }

    async fn delete(
        &self,
        descriptor: &ResourceDescriptor,
        auth: &o3k_kernel::AuthContext,
        id: &str,
        idempotency_key: Option<&str>,
        expected_generation: Option<i64>,
    ) -> Result<MutationResult, ResourceApplicationError> {
        if descriptor.resource_type.to_string() == "volume:volume_attachment" {
            let workflow = self
                .attachment_workflow
                .as_ref()
                .ok_or(ResourceApplicationError::NotReady)?;
            let attachment_id = id
                .parse::<Uuid>()
                .map_err(|_| ResourceApplicationError::NotFound)?;
            let record = self
                .store
                .get_volume_attachment_v1(attachment_id)
                .await
                .map_err(|_| ResourceApplicationError::Internal)?
                .filter(|record| {
                    record.attachment.project_id == auth.effective_scope().id().as_str()
                })
                .ok_or(ResourceApplicationError::NotFound)?;
            workflow
                .detach(attachment_id)
                .await
                .map_err(|_| ResourceApplicationError::NotReady)?;
            self.store
                .delete_volume_attachment_v1(
                    auth.effective_scope().id().as_str(),
                    record.attachment.id.as_uuid(),
                )
                .await
                .map_err(|_| ResourceApplicationError::Internal)?;
            return Ok(MutationResult {
                operation_id: format!("native:volume-attachment:delete:{attachment_id}"),
                resource_id: Some(id.to_owned()),
                complete: true,
                resource: None,
            });
        }
        if descriptor.resource_type.to_string() == "compute:flavor" {
            let resource_id = id
                .parse::<Uuid>()
                .map_err(|_| ResourceApplicationError::NotFound)?;
            self.compute
                .delete_flavor_for_auth(auth, resource_id)
                .await
                .map_err(compute_error)?;
            return Ok(MutationResult {
                operation_id: Uuid::new_v5(
                    &Uuid::NAMESPACE_URL,
                    format!("native:compute-flavor-delete:{id}").as_bytes(),
                )
                .to_string(),
                resource_id: Some(id.to_owned()),
                complete: true,
                resource: None,
            });
        }
        if descriptor.resource_type.to_string() == "image:image" {
            let resource_id = id
                .parse::<Uuid>()
                .map_err(|_| ResourceApplicationError::NotFound)?;
            let resource = self
                .store
                .get_resource(resource_id)
                .await
                .map_err(|_| ResourceApplicationError::NotFound)?;
            if resource.kind != "image:image"
                || resource.project_id != auth.effective_scope().id().as_str()
            {
                return Err(ResourceApplicationError::NotFound);
            }
            if expected_generation.is_some_and(|expected| expected != resource.generation) {
                return Err(ResourceApplicationError::PreconditionConflict);
            }
            let service = self
                .image
                .as_ref()
                .ok_or(ResourceApplicationError::NotReady)?;
            service
                .delete(auth, resource_id)
                .await
                .map_err(image_error)?;
            self.store
                .update_resource(
                    resource_id,
                    resource.generation,
                    "DELETED",
                    "DELETED",
                    resource.generation.saturating_add(1),
                    None,
                )
                .await
                .map_err(|_| ResourceApplicationError::Internal)?;
            return Ok(MutationResult {
                operation_id: format!("native:image:delete:{id}"),
                resource_id: Some(id.to_owned()),
                complete: true,
                resource: None,
            });
        }
        // Migration-owned compatibility projections are backed by canonical
        // network operations.  Do not route their deletion through the
        // generic execution controller: these records have no provider
        // lifecycle session of their own, and that path correctly rejects a
        // missing provider operation with 501.  The canonical network service
        // is the authority and the sidecar is marked deleted only after the
        // operation succeeds.
        let network_kind = descriptor.resource_type.to_string();
        if matches!(
            network_kind.as_str(),
            "network:network"
                | "network:subnet"
                | "network:port"
                | "network:security_group"
                | "network:security_group_rule"
                | "network:router"
                | "network:router_interface"
        ) {
            let resource_id = id
                .parse::<Uuid>()
                .map_err(|_| ResourceApplicationError::NotFound)?;
            let resource = self
                .store
                .get_resource(resource_id)
                .await
                .map_err(|_| ResourceApplicationError::NotFound)?;
            if resource.kind != network_kind
                || resource.project_id != auth.effective_scope().id().as_str()
            {
                return Err(ResourceApplicationError::NotFound);
            }
            if expected_generation.is_some_and(|expected| expected != resource.generation) {
                return Err(ResourceApplicationError::PreconditionConflict);
            }
            let project_id = auth.effective_scope().id().as_str();
            match network_kind.as_str() {
                "network:network" => self
                    .network_service
                    .delete_network_for_project(project_id, resource_id)
                    .await
                    .map_err(|_| ResourceApplicationError::Conflict)?,
                "network:subnet" => self
                    .network_service
                    .delete_subnet_for_project(project_id, resource_id)
                    .await
                    .map_err(|_| ResourceApplicationError::Conflict)?,
                "network:port" => self
                    .network_service
                    .delete_port_for_project(project_id, resource_id)
                    .await
                    .map_err(|_| ResourceApplicationError::Conflict)?,
                "network:security_group" => self
                    .network_service
                    .delete_security_group_for_project(project_id, resource_id)
                    .await
                    .map_err(|_| ResourceApplicationError::Conflict)?,
                "network:security_group_rule" => self
                    .network_service
                    .delete_security_group_rule_for_project(project_id, resource_id)
                    .await
                    .map_err(|_| ResourceApplicationError::Conflict)?,
                "network:router" => {
                    let gateway = self
                        .network_service
                        .delete_l3_gateway_for_project(
                            project_id,
                            &resource_id,
                            resource.generation as u64,
                        )
                        .await
                        .map_err(|_| ResourceApplicationError::Conflict)?;
                    self.network_service
                        .finalize_l3_gateway_deletion_for_project(
                            project_id,
                            &resource_id,
                            gateway.generation,
                        )
                        .await
                        .map_err(|_| ResourceApplicationError::Conflict)?;
                }
                "network:router_interface" => {
                    let attachment = self
                        .network_service
                        .detach_l3_gateway_realm(
                            project_id,
                            &resource_id,
                            resource.generation as u64,
                        )
                        .await
                        .map_err(|_| ResourceApplicationError::Conflict)?;
                    self.network_service
                        .finalize_l3_gateway_realm_detachment_for_project(
                            project_id,
                            &resource_id,
                            attachment.generation,
                        )
                        .await
                        .map_err(|_| ResourceApplicationError::Conflict)?;
                }
                _ => unreachable!(),
            }
            self.store
                .update_resource(
                    resource_id,
                    resource.generation,
                    "DELETED",
                    "DELETED",
                    resource.generation.saturating_add(1),
                    None,
                )
                .await
                .map_err(|_| ResourceApplicationError::Internal)?;
            return Ok(MutationResult {
                operation_id: format!("native:{network_kind}:delete:{id}"),
                resource_id: Some(id.to_owned()),
                complete: true,
                resource: None,
            });
        }
        if network_kind == "network:floating_ip" {
            let resource_id = id
                .parse::<Uuid>()
                .map_err(|_| ResourceApplicationError::NotFound)?;
            let resource = self
                .store
                .get_resource(resource_id)
                .await
                .map_err(|_| ResourceApplicationError::NotFound)?;
            if resource.kind != network_kind
                || resource.project_id != auth.effective_scope().id().as_str()
            {
                return Err(ResourceApplicationError::NotFound);
            }
            if expected_generation.is_some_and(|expected| expected != resource.generation) {
                return Err(ResourceApplicationError::PreconditionConflict);
            }
            let allocator = self
                .public_allocator
                .as_ref()
                .ok_or(ResourceApplicationError::NotReady)?;
            let project_id = auth.effective_scope().id().as_str();
            let binding = allocator
                .get(project_id, resource_id)
                .map_err(|_| ResourceApplicationError::NotFound)?;
            if binding.endpoint_id.is_some() {
                if let Some(workflow) = self.public_address_workflow.as_ref() {
                    workflow
                        .remove(project_id, resource_id)
                        .await
                        .map_err(|_| ResourceApplicationError::Conflict)?;
                }
                allocator
                    .disassociate(project_id, resource_id)
                    .map_err(|_| ResourceApplicationError::Conflict)?;
            }
            allocator
                .release(project_id, resource_id)
                .map_err(|_| ResourceApplicationError::Conflict)?;
            self.store
                .update_resource(
                    resource_id,
                    resource.generation,
                    "DELETED",
                    "DELETED",
                    resource.generation.saturating_add(1),
                    None,
                )
                .await
                .map_err(|_| ResourceApplicationError::Internal)?;
            return Ok(MutationResult {
                operation_id: format!("native:network:floating_ip:delete:{id}"),
                resource_id: Some(id.to_owned()),
                complete: true,
                resource: None,
            });
        }
        // Native volumes are owned by the in-process storage boundary even
        // when a compatibility controller with the same service identity is
        // registered.  The provider-backed native lifecycle must run first;
        // the generic controller path can otherwise report success without
        // removing the LVM realization.
        if descriptor.resource_type.to_string() != "volume:volume"
            && let Some(controller) = self.external_controllers.get(&descriptor.owning_service)
        {
            if !controller.health().await.healthy {
                return Err(ResourceApplicationError::NotReady);
            }
            let resource_id = id
                .parse::<Uuid>()
                .map_err(|_| ResourceApplicationError::NotFound)?;
            let resource = self
                .store
                .get_resource(resource_id)
                .await
                .map_err(|_| ResourceApplicationError::NotFound)?;
            if resource.kind != descriptor.resource_type.to_string()
                || resource.project_id != auth.effective_scope().id().as_str()
            {
                return Err(ResourceApplicationError::NotFound);
            }
            if expected_generation.is_some_and(|expected| expected != resource.generation) {
                return Err(ResourceApplicationError::PreconditionConflict);
            }
            let action = descriptor
                .lifecycle_actions
                .get(&o3k_native_api::resource::LifecycleOperation::Delete)
                .cloned()
                .ok_or(ResourceApplicationError::UnsupportedOperation)?;
            let key = idempotency_key
                .map(str::to_owned)
                .unwrap_or_else(|| format!("native:delete:{id}"));
            let operation_id = Uuid::new_v5(
                &Uuid::NAMESPACE_URL,
                format!("{}:delete:{id}:{key}", descriptor.resource_type).as_bytes(),
            );
            let operation = o3k_store::OperationRecord {
                id: operation_id,
                resource_id,
                kind: "lifecycle:delete".into(),
                state: o3k_store::OperationState::Pending,
                provider_operation_id: None,
                error_category: None,
                error_message: None,
            };
            let canonical = o3k_store::CanonicalOperationRecord::from_kernel_operation(
                &o3k_kernel::Operation::new(
                    operation_id,
                    descriptor.owning_service.clone(),
                    action.clone(),
                    auth.principal().id().to_string(),
                    auth.effective_scope().clone(),
                    descriptor.resource_type.clone(),
                    Some(o3k_kernel::ResourceId::new_unchecked(id)),
                    Some(auth.request_id().to_owned()),
                ),
            )
            .map_err(|_| ResourceApplicationError::Internal)?;
            let identity = o3k_store::IdempotencyReservationRequest::from_semantics(
                auth.effective_scope().id().as_str(),
                action.to_string(),
                key,
                &descriptor.resource_type.to_string(),
                Some(id),
                &serde_json::json!({"resource_id": id}),
                operation_id,
            )
            .map_err(|_| ResourceApplicationError::Validation)?;
            if self
                .store
                .create_or_replay_canonical_lifecycle_operation(&operation, &canonical, &identity)
                .await
                .map_err(|_| ResourceApplicationError::Internal)?
                == o3k_store::CanonicalAcceptanceOutcome::Conflict
            {
                return Err(ResourceApplicationError::IdempotencyConflict);
            }
            let session = controller.session();
            let context = o3k_kernel::OperationContext {
                request_id: auth
                    .request_id()
                    .parse()
                    .map_err(|_| ResourceApplicationError::Internal)?,
                operation_id,
                action,
                service_id: descriptor.owning_service.clone(),
                owner_scope: auth.effective_scope().clone(),
                session_id: session.session_id,
                session_generation: session.session_generation,
                deadline_unix_ms: chrono::Utc::now().timestamp_millis() as u64 + 60_000,
                replay_identity: format!("delete:{operation_id}"),
                audit_correlation: format!("delete:{operation_id}"),
            };
            let parent_reference = o3k_kernel::ResourceReference {
                resource_type: descriptor.resource_type.clone(),
                resource_id: o3k_kernel::ResourceId::new_unchecked(id),
                generation: resource.generation,
            };
            let delegation = controller
                .issue_parent_delegation(
                    &context,
                    auth.principal().id().to_string(),
                    &parent_reference,
                )
                .map_err(|_| ResourceApplicationError::Unauthorized)?;
            let outcome = controller
                .delete(o3k_kernel::DeleteRequest {
                    context,
                    resource: parent_reference,
                    owner_scope: auth.effective_scope().clone(),
                    delegation: Some(delegation),
                })
                .await;
            let complete = matches!(outcome, o3k_kernel::ReconcileOutcome::Succeeded { .. });
            if complete {
                self.store
                    .update_resource(
                        resource_id,
                        resource.generation,
                        "DELETED",
                        "DELETED",
                        resource.generation.saturating_add(1),
                        None,
                    )
                    .await
                    .map_err(|_| ResourceApplicationError::Internal)?;
            }
            return Ok(MutationResult {
                operation_id: operation_id.to_string(),
                resource_id: Some(id.to_owned()),
                complete,
                resource: None,
            });
        }
        if descriptor.resource_type.to_string() == "volume:volume" {
            let resource_id = id
                .parse::<Uuid>()
                .map_err(|_| ResourceApplicationError::NotFound)?;
            let key = idempotency_key
                .map(str::to_owned)
                .unwrap_or_else(|| format!("native:volume-delete:{id}"));
            let operation_id = Uuid::new_v5(
                &Uuid::NAMESPACE_URL,
                format!(
                    "volume:delete:{}:{resource_id}:{key}:generation={}",
                    auth.effective_scope().id(),
                    expected_generation.map_or(-1, |generation| generation)
                )
                .as_bytes(),
            );
            // A successful delete removes the native volume row. Resolve a
            // deterministic replay before looking up that row so an
            // equivalent retry returns the original terminal operation.
            match self.store.get_canonical_operation(operation_id).await {
                Ok(existing) => {
                    if let Some(expected) = expected_generation {
                        let bookkeeping = self
                            .store
                            .get_resource(resource_id)
                            .await
                            .map_err(|_| ResourceApplicationError::NotFound)?;
                        if bookkeeping.project_id != auth.effective_scope().id().as_str()
                            || bookkeeping.kind != "volume"
                            || bookkeeping.generation != expected.saturating_add(1)
                        {
                            return Err(ResourceApplicationError::PreconditionConflict);
                        }
                    }
                    if existing.state != o3k_store::OperationState::Succeeded {
                        // A retry can arrive after provider deletion but before
                        // the first request persisted its terminal operation.
                        let Some(provider) = self.storage_provider.clone() else {
                            return Err(ResourceApplicationError::NotReady);
                        };
                        if let Some(record) = self
                            .store
                            .get_volume(resource_id)
                            .await
                            .map_err(|_| ResourceApplicationError::Internal)?
                        {
                            if record.volume.project_id != auth.effective_scope().id().as_str() {
                                return Err(ResourceApplicationError::NotFound);
                            }
                            o3k_api::remove_native_volume(
                    self.store.clone(),
                    provider,
                    auth.effective_scope().id().as_str(),
                    resource_id,
                    Some(operation_id),
                    self.metering.as_ref(),
                )
                .await
                .map_err(|error| {
                    tracing::error!(volume_id = %resource_id, %error, "native volume delete failed");
                    ResourceApplicationError::Retryable
                })?;
                            let bookkeeping = self
                                .store
                                .get_resource(resource_id)
                                .await
                                .map_err(|_| ResourceApplicationError::Internal)?;
                            if bookkeeping.project_id != auth.effective_scope().id().as_str()
                                || bookkeeping.kind != "volume"
                            {
                                return Err(ResourceApplicationError::NotFound);
                            }
                            if bookkeeping.observed_state != "DELETED"
                                || bookkeeping.desired_state != "DELETED"
                            {
                                self.store
                                    .update_resource(
                                        resource_id,
                                        bookkeeping.generation,
                                        "DELETED",
                                        "DELETED",
                                        bookkeeping.generation.saturating_add(1),
                                        None,
                                    )
                                    .await
                                    .map_err(|_| ResourceApplicationError::Internal)?;
                            }
                            let now = chrono::Utc::now().to_rfc3339();
                            let lifecycle = o3k_store::CanonicalOperationLifecycleUpdate::new(
                                o3k_kernel::OperationState::Succeeded,
                                existing.attempt.saturating_add(1),
                                Some(now.clone()),
                                Some(now),
                                None,
                            )
                            .map_err(|_| ResourceApplicationError::Internal)?;
                            self.store
                                .update_canonical_operation_lifecycle(operation_id, &lifecycle)
                                .await
                                .map_err(|_| ResourceApplicationError::Internal)?;
                            self.store
                                .delete_volume(auth.effective_scope().id().as_str(), resource_id)
                                .await
                                .map_err(|_| ResourceApplicationError::Internal)?;
                            return Ok(MutationResult {
                                operation_id: operation_id.to_string(),
                                resource_id: Some(id.to_owned()),
                                complete: true,
                                resource: None,
                            });
                        }
                    }
                    return Ok(MutationResult {
                        operation_id: operation_id.to_string(),
                        resource_id: Some(id.to_owned()),
                        complete: existing.state == o3k_store::OperationState::Succeeded,
                        resource: None,
                    });
                }
                Err(o3k_store::StoreError::OperationNotFound) => {}
                Err(_) => return Err(ResourceApplicationError::Internal),
            }
            if let Some(record) = self
                .store
                .get_volume(resource_id)
                .await
                .map_err(|_| ResourceApplicationError::Internal)?
            {
                if record.volume.project_id != auth.effective_scope().id().as_str() {
                    return Err(ResourceApplicationError::NotFound);
                }
                if expected_generation
                    .is_some_and(|expected| expected != record.volume.generation as i64)
                {
                    return Err(ResourceApplicationError::PreconditionConflict);
                }
                let action = descriptor
                    .lifecycle_actions
                    .get(&o3k_native_api::resource::LifecycleOperation::Delete)
                    .cloned()
                    .ok_or(ResourceApplicationError::UnsupportedOperation)?;
                let Some(provider) = self.storage_provider.clone() else {
                    return Err(ResourceApplicationError::NotReady);
                };
                // The native volume table is the lifecycle authority, while
                // the shared operation journal enforces its resource FK
                // through `resources`.  Compatibility-created volumes
                // predate that projection, so materialize the bookkeeping
                // row before reserving the native delete operation.
                if let Err(error) = self.store.get_resource(resource_id).await {
                    if !matches!(error, o3k_store::StoreError::ResourceNotFound) {
                        return Err(ResourceApplicationError::Internal);
                    }
                    self.store
                        .insert_resource(&o3k_store::ResourceRecord {
                            id: resource_id,
                            kind: "volume".to_owned(),
                            project_id: record.volume.project_id.clone(),
                            generation: record.volume.generation as i64,
                            observed_generation: record.volume.generation as i64,
                            desired_state: "AVAILABLE".to_owned(),
                            observed_state: "AVAILABLE".to_owned(),
                            provider_id: record
                                .volume
                                .provider_reference
                                .as_ref()
                                .map(|reference| reference.resource_id.clone()),
                        })
                        .await
                        .map_err(|_| ResourceApplicationError::Internal)?;
                }
                let operation = o3k_store::OperationRecord {
                    id: operation_id,
                    resource_id,
                    kind: "lifecycle:delete".into(),
                    state: o3k_store::OperationState::Pending,
                    provider_operation_id: None,
                    error_category: None,
                    error_message: None,
                };
                let canonical = o3k_store::CanonicalOperationRecord::from_kernel_operation(
                    &o3k_kernel::Operation::new(
                        operation_id,
                        "volume",
                        action.clone(),
                        auth.principal().id().to_string(),
                        auth.effective_scope().clone(),
                        o3k_kernel::ResourceType::new_unchecked("volume", "volume"),
                        Some(o3k_kernel::ResourceId::new_unchecked(id)),
                        Some(auth.request_id().to_owned()),
                    ),
                )
                .map_err(|_| ResourceApplicationError::Internal)?;
                let identity = o3k_store::IdempotencyReservationRequest::from_semantics(
                    auth.effective_scope().id().as_str(),
                    action.to_string(),
                    key,
                    "volume:volume",
                    Some(id),
                        &serde_json::json!({"resource_id": id, "expected_generation": expected_generation}),
                    operation_id,
                )
                .map_err(|_| ResourceApplicationError::Validation)?;
                let acceptance = self
                    .store
                    .create_or_replay_canonical_lifecycle_operation(
                        &operation, &canonical, &identity,
                    )
                    .await
                    .map_err(|_| ResourceApplicationError::Internal)?;
                if let o3k_store::CanonicalAcceptanceOutcome::ExistingEquivalent {
                    operation_id,
                    ..
                } = acceptance
                {
                    let existing = self
                        .store
                        .get_canonical_operation(operation_id)
                        .await
                        .map_err(|_| ResourceApplicationError::Internal)?;
                    return Ok(MutationResult {
                        operation_id: operation_id.to_string(),
                        resource_id: Some(id.to_owned()),
                        complete: existing.state == o3k_store::OperationState::Succeeded,
                        resource: None,
                    });
                }
                o3k_api::remove_native_volume(
                    self.store.clone(),
                    provider,
                    auth.effective_scope().id().as_str(),
                    resource_id,
                    Some(operation_id),
                    self.metering.as_ref(),
                )
                .await
                .map_err(|error| {
                    tracing::error!(volume_id = %resource_id, %error, "native volume delete failed");
                    ResourceApplicationError::Retryable
                })?;
                let bookkeeping = self
                    .store
                    .get_resource(resource_id)
                    .await
                    .map_err(|_| ResourceApplicationError::Internal)?;
                if bookkeeping.project_id != auth.effective_scope().id().as_str()
                    || bookkeeping.kind != "volume"
                {
                    return Err(ResourceApplicationError::NotFound);
                }
                self.store
                    .update_resource(
                        resource_id,
                        bookkeeping.generation,
                        "DELETED",
                        "DELETED",
                        bookkeeping.generation.saturating_add(1),
                        None,
                    )
                    .await
                    .map_err(|_| ResourceApplicationError::Internal)?;
                let now = chrono::Utc::now().to_rfc3339();
                let lifecycle = o3k_store::CanonicalOperationLifecycleUpdate::new(
                    o3k_kernel::OperationState::Succeeded,
                    1,
                    Some(now.clone()),
                    Some(now),
                    None,
                )
                .map_err(|_| ResourceApplicationError::Internal)?;
                self.store
                    .update_canonical_operation_lifecycle(operation_id, &lifecycle)
                    .await
                    .map_err(|_| ResourceApplicationError::Internal)?;
                // Keep the Deleting row until the canonical operation is
                // terminal. If cleanup fails, restart recovery still owns the
                // durable provider inventory and can finish the deletion.
                self.store
                    .delete_volume(auth.effective_scope().id().as_str(), resource_id)
                    .await
                    .map_err(|_| ResourceApplicationError::Internal)?;
                return Ok(MutationResult {
                    operation_id: operation_id.to_string(),
                    resource_id: Some(id.to_owned()),
                    complete: true,
                    resource: None,
                });
            }
            let resource = self
                .store
                .get_resource(resource_id)
                .await
                .map_err(|_| ResourceApplicationError::NotFound)?;
            if resource.kind != "volume"
                || resource.project_id != auth.effective_scope().id().as_str()
            {
                return Err(ResourceApplicationError::NotFound);
            }
            if expected_generation.is_some_and(|expected| expected != resource.generation) {
                return Err(ResourceApplicationError::PreconditionConflict);
            }
            let action = descriptor
                .lifecycle_actions
                .get(&o3k_native_api::resource::LifecycleOperation::Delete)
                .cloned()
                .ok_or(ResourceApplicationError::UnsupportedOperation)?;
            let key = idempotency_key
                .map(str::to_owned)
                .unwrap_or_else(|| format!("native:volume-delete:{id}"));
            let operation_id = Uuid::new_v5(
                &Uuid::NAMESPACE_URL,
                format!("volume:delete:{}:{id}:{key}", auth.effective_scope().id()).as_bytes(),
            );
            let operation = o3k_store::OperationRecord {
                id: operation_id,
                resource_id,
                kind: "lifecycle:delete".into(),
                state: o3k_store::OperationState::Pending,
                provider_operation_id: None,
                error_category: None,
                error_message: None,
            };
            let canonical = o3k_store::CanonicalOperationRecord::from_kernel_operation(
                &o3k_kernel::Operation::new(
                    operation_id,
                    "volume",
                    action.clone(),
                    auth.principal().id().to_string(),
                    auth.effective_scope().clone(),
                    o3k_kernel::ResourceType::new_unchecked("volume", "volume"),
                    Some(o3k_kernel::ResourceId::new_unchecked(id)),
                    Some(auth.request_id().to_owned()),
                ),
            )
            .map_err(|_| ResourceApplicationError::Internal)?;
            let request_identity = o3k_store::IdempotencyReservationRequest::from_semantics(
                auth.effective_scope().id().as_str(),
                action.to_string(),
                key,
                "volume:volume",
                Some(id),
                &serde_json::json!({"resource_id": id}),
                operation_id,
            )
            .map_err(|_| ResourceApplicationError::Validation)?;
            if self
                .store
                .create_or_replay_canonical_lifecycle_operation(
                    &operation,
                    &canonical,
                    &request_identity,
                )
                .await
                .map_err(|_| ResourceApplicationError::Internal)?
                == o3k_store::CanonicalAcceptanceOutcome::Conflict
            {
                return Err(ResourceApplicationError::IdempotencyConflict);
            }
            self.store
                .update_resource(
                    resource_id,
                    resource.generation,
                    "DELETED",
                    "DELETED",
                    resource.generation.saturating_add(1),
                    None,
                )
                .await
                .map_err(|_| ResourceApplicationError::Internal)?;
            // The native volume row is already gone (a prior attempt completed
            // the durable delete), so there is no size to close with. This is
            // an idempotent close with quantity zero: the store records nothing
            // when no interval is open, and it never fabricates a close for an
            // allocation that was never observed opening.
            self.observe_volume_allocation(
                auth.effective_scope().id().as_str(),
                resource_id,
                0,
                false,
            )
            .await?;
            return Ok(MutationResult {
                operation_id: operation_id.to_string(),
                resource_id: Some(id.to_owned()),
                complete: true,
                resource: None,
            });
        }
        if descriptor.resource_type.to_string() != "compute:server" {
            return Err(ResourceApplicationError::UnsupportedOperation);
        }
        let key = idempotency_key
            .map(str::to_owned)
            .unwrap_or_else(|| format!("native:{}", Uuid::new_v4()));
        let resource_id = id
            .parse::<Uuid>()
            .map_err(|_| ResourceApplicationError::NotFound)?;
        let existing = self
            .store
            .get_resource(resource_id)
            .await
            .map_err(|_| ResourceApplicationError::NotFound)?;
        if existing.project_id != auth.effective_scope().id().as_str() {
            return Err(ResourceApplicationError::NotFound);
        }
        if expected_generation.is_some_and(|expected| expected != existing.generation) {
            return Err(ResourceApplicationError::PreconditionConflict);
        }
        let action = descriptor
            .lifecycle_actions
            .get(&o3k_native_api::resource::LifecycleOperation::Delete)
            .cloned()
            .ok_or(ResourceApplicationError::UnsupportedOperation)?;
        let context = o3k_reconciler::CanonicalMutationContext::new(
            action,
            auth.principal().id().to_string(),
            auth.effective_scope().clone(),
            None,
            key,
            serde_json::json!({"resource_id": id}),
        )
        .map_err(|_| ResourceApplicationError::Validation)?;
        // The server's durable network attachments are read *before* the
        // canonical delete so the endpoints that the lifecycle owns can be
        // released once the delete is terminal. The read intentionally retains
        // attachment intent after deletion, which is what lets a replay of the
        // same delete retry endpoint cleanup after a transient failure.
        let project_id = auth.effective_scope().id().as_str().to_owned();
        let owned_ports = match self
            .compute
            .server_network_ids_for_auth(auth, o3k_domain::ServerId::from_uuid(resource_id))
            .await
        {
            Ok(network_ids) => network_ids
                .iter()
                .filter_map(|port_id| port_id.parse::<Uuid>().ok())
                .collect::<Vec<Uuid>>(),
            Err(o3k_compute::ComputeError::NotFound) => Vec::new(),
            Err(error) => {
                tracing::warn!(error = ?error, %id, "native server endpoint read failed");
                return Err(compute_error(error));
            }
        };
        let receipt = self
            .compute
            .delete_server_for_auth_canonical(
                auth,
                o3k_domain::ServerId::from_uuid(resource_id),
                context,
            )
            .await
            .map_err(compute_error)?;
        // Endpoints are released only after the canonical delete is terminal:
        // a converging delete still has a provider-side server that needs its
        // network dependency, and the retried delete releases them later.
        //
        // #1035 (replay release): the deleted owner's intent can name an
        // endpoint a NEW live server has explicitly re-attached. The network
        // layer cannot see that — the durable binding may already be cleared —
        // so this delete handler (which runs a direct, still-attached-blind
        // network release) consults the compute layer and refuses to hand such
        // a port back for deletion. The live server's own delete releases it.
        if matches!(
            receipt.operation_state,
            o3k_store::OperationState::Succeeded
        ) {
            // #1035 (replay release): this direct network release consults the
            // live-attached set and holds the orphan-repair lock across
            // [scan -> release] so it is serialized against port-attaching
            // creates and the orphan sweep; a port a live server now references
            // is never handed back for deletion.
            let _orphan_repair_guard = self.compute.orphan_repair_lock_guard().await;
            let attached = self
                .compute
                .live_attached_endpoint_ids()
                .await
                .map_err(compute_error)?;
            let releasable = owned_ports
                .iter()
                .copied()
                .filter(|port_id| !attached.contains(&port_id.to_string()))
                .collect::<Vec<_>>();
            if !releasable.is_empty()
                && let Err(error) = self
                    .network_service
                    .cleanup_server_owned_ports_for_project(&project_id, &releasable)
                    .await
            {
                tracing::error!(%error, %id, "native server endpoint cleanup failed");
                return Err(ResourceApplicationError::Internal);
            }
        }
        Ok(MutationResult {
            operation_id: receipt.operation_id.to_string(),
            resource_id: Some(id.to_owned()),
            complete: matches!(
                receipt.operation_state,
                o3k_store::OperationState::Succeeded
            ),
            resource: None,
        })
    }
}
