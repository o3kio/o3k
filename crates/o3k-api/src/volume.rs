//! Bounded Cinder v3 projection over the canonical native Volume store.
//!
//! This module intentionally contains only the provider-discovered CRUD
//! surface.  The Cinder representation is a projection; native storage rows
//! remain the authority.

use axum::{
    Json,
    extract::{Path, State},
    http::{HeaderMap, StatusCode},
    response::{IntoResponse, Response},
};
use o3k_domain::{StorageExecutionScope, Volume, VolumeId, VolumeState};
use o3k_storage::StorageVolumeRequest;
use o3k_store::VolumeRecord;
use serde::{Deserialize, Serialize};
use std::sync::Arc;
use uuid::Uuid;

use crate::{AppState, compute::project_auth_context, error::keystone_error};

/// Canonical key of the volume allocation meter. Defined once here because the
/// canonical volume authority owns the observation; the `o3kd` adapter
/// re-exports it rather than repeating the literal.
pub const VOLUME_ALLOCATION_METER: &str = "volume:allocated_byte_seconds";

/// Projects one volume allocation transition through the optional metering
/// authority.
///
/// This is the single observation path for native volumes. `size_bytes` is the
/// canonical allocation size for an open and is ignored by the adapter for a
/// close (which records quantity zero). A failure is returned so the caller can
/// defer its durable mutation; the observation itself is idempotent.
pub async fn observe_volume_allocation(
    metering: Option<&Arc<dyn o3k_kernel::LifecycleMeteringObserver>>,
    scope: &str,
    resource_id: &str,
    size_bytes: u64,
    consuming: bool,
) -> Result<(), String> {
    let Some(observer) = metering else {
        return Ok(());
    };
    observer
        .observe_allocation(
            VOLUME_ALLOCATION_METER,
            scope,
            resource_id,
            size_bytes,
            consuming,
        )
        .await
        .map_err(|error| error.to_string())
}

/// Whether a durable volume state means the volume is consuming allocated
/// byte-seconds.
///
/// This is the single canonical mapping. A volume consumes while its
/// allocation exists at the provider: `Creating`, `Available`, `Attaching`,
/// `InUse`, `Detaching` and `Unknown` all represent a durable allocation that
/// exists or is being reconciled. `Requested` has not been dispatched, `Error`
/// failed before an allocation was observed, and `Deleting`/`Deleted` are
/// terminal closes.
#[must_use]
pub fn volume_state_consumes(state: VolumeState) -> bool {
    matches!(
        state,
        VolumeState::Creating
            | VolumeState::Available
            | VolumeState::Attaching
            | VolumeState::InUse
            | VolumeState::Detaching
            | VolumeState::Unknown
    )
}

/// Best-effort repair of the canonical volume allocation observation from the
/// durable volume state.
///
/// Called from volume read paths so a projection lost after the durable
/// create/delete committed is repaired by the next read of that volume. The
/// observation is idempotent by state, so re-projecting durable truth is not a
/// fabrication; a failure is logged and never fails the read.
///
/// A repair only ever OPENS or REFRESHES a consuming interval. When the durable
/// state is not consuming it skips entirely and never emits a close: closing is
/// owned by the authoritative transition paths (`remove_native_volume`,
/// recovery on provider absence), and a read that closed at the read instant
/// would under-count a teardown tail and could permanently close an interval
/// for a volume later re-tried out of `Deleting`.
pub async fn repair_volume_metering(
    metering: Option<&Arc<dyn o3k_kernel::LifecycleMeteringObserver>>,
    record: &VolumeRecord,
) {
    if !volume_state_consumes(record.volume.state) {
        return;
    }
    if let Err(error) = observe_volume_allocation(
        metering,
        &record.volume.project_id,
        &record.volume.id.as_uuid().to_string(),
        record.volume.size_bytes,
        true,
    )
    .await
    {
        tracing::warn!(
            %error,
            volume_id = %record.volume.id,
            "native volume read-path metering repair failed; the next read repairs it"
        );
    }
}

/// Opens the volume allocation meter from a durable row, only while the row is
/// durably consuming.
///
/// Caller-side replays (an idempotent native create against an existing row)
/// must never reopen a non-consuming row: closing belongs to the authoritative
/// delete/provider-absence path. This keeps caller-side replay and the canonical
/// transition using the same [`volume_state_consumes`] mapping.
pub async fn observe_volume_open_if_consuming(
    metering: Option<&Arc<dyn o3k_kernel::LifecycleMeteringObserver>>,
    record: &VolumeRecord,
) -> Result<(), String> {
    if !volume_state_consumes(record.volume.state) {
        return Ok(());
    }
    observe_volume_allocation(
        metering,
        &record.volume.project_id,
        &record.volume.id.as_uuid().to_string(),
        record.volume.size_bytes,
        true,
    )
    .await
}

#[derive(Debug, Deserialize)]
pub(crate) struct VolumeRequest {
    volume: VolumeCreate,
}

#[derive(Debug, Deserialize)]
struct VolumeCreate {
    size: u64,
    #[serde(default)]
    name: Option<String>,
    #[serde(default)]
    description: Option<String>,
    #[serde(default)]
    volume_type: Option<String>,
    #[serde(default)]
    availability_zone: Option<String>,
    #[serde(default)]
    metadata: Option<serde_json::Value>,
}

#[derive(Debug, Deserialize)]
pub(crate) struct VolumeUpdateRequest {
    volume: VolumeUpdate,
}

#[derive(Debug, Deserialize)]
struct VolumeUpdate {
    #[serde(default)]
    name: Option<String>,
    #[serde(default)]
    description: Option<String>,
    #[serde(default)]
    metadata: Option<serde_json::Value>,
}

#[derive(Debug, Serialize)]
struct VolumeResponse {
    volume: VolumeView,
}

#[derive(Debug, Serialize)]
struct VolumeListResponse {
    volumes: Vec<VolumeView>,
}

#[derive(Debug, Serialize)]
struct VolumeView {
    id: String,
    status: String,
    size: u64,
    volume_type: String,
    name: String,
    description: String,
    availability_zone: Option<String>,
    metadata: serde_json::Value,
    attachments: Vec<serde_json::Value>,
    created_at: String,
    updated_at: String,
}

fn status(state: VolumeState) -> &'static str {
    match state {
        VolumeState::Requested | VolumeState::Creating => "creating",
        VolumeState::Available => "available",
        VolumeState::Attaching | VolumeState::InUse => "in-use",
        VolumeState::Detaching => "detaching",
        VolumeState::Deleting => "deleting",
        VolumeState::Deleted => "deleted",
        VolumeState::Unknown => "error",
        VolumeState::Error => "error",
    }
}

fn view(record: &VolumeRecord) -> VolumeView {
    let metadata = record
        .volume
        .metadata
        .iter()
        .map(|(key, value)| (key.clone(), serde_json::Value::String(value.clone())))
        .collect::<serde_json::Map<_, _>>();
    VolumeView {
        id: record.volume.id.to_string(),
        status: status(record.volume.state).to_owned(),
        size: record.volume.size_bytes / (1024 * 1024 * 1024),
        volume_type: record.volume.volume_type.clone(),
        name: if record.volume.name.is_empty() {
            record.volume.id.to_string()
        } else {
            record.volume.name.clone()
        },
        description: record.volume.description.clone(),
        availability_zone: record.volume.availability_zone.clone(),
        metadata: serde_json::Value::Object(metadata),
        attachments: Vec::new(),
        created_at: record.created_at.clone(),
        updated_at: record.created_at.clone(),
    }
}

fn unavailable() -> Response {
    keystone_error(
        StatusCode::SERVICE_UNAVAILABLE,
        "Service Unavailable",
        "native volume service unavailable",
    )
    .into_response()
}

fn now_rfc3339() -> String {
    chrono::Utc::now()
        .format("%Y-%m-%dT%H:%M:%S%.3f")
        .to_string()
}

fn volume_id(id: &str) -> Option<Uuid> {
    Uuid::parse_str(id).ok()
}

fn volume_not_found() -> Response {
    keystone_error(StatusCode::NOT_FOUND, "Not Found", "volume not found").into_response()
}

/// Shared provider-backed native Volume lifecycle used by both the Cinder
/// projection and the native `volume:volume` adapter.  Compatibility wire
/// formats remain outside this function; canonical persistence, provider
/// observation, and the metering projection are deliberately single-sourced
/// here so no caller can durably create a volume without opening its meter.
pub async fn realize_native_volume_create(
    store: Arc<dyn o3k_store::StorageRepository>,
    provider: Arc<dyn o3k_storage::StorageProvider>,
    record: VolumeRecord,
    metering: Option<&Arc<dyn o3k_kernel::LifecycleMeteringObserver>>,
) -> Result<VolumeRecord, String> {
    let mut creating = record.clone();
    creating.volume.state = VolumeState::Creating;
    creating.volume.generation = record
        .volume
        .generation
        .checked_add(1)
        .ok_or_else(|| "volume generation overflow".to_owned())?;
    let creating = store
        .update_volume(record.volume.generation, &creating)
        .await
        .map_err(|error| error.to_string())?;
    let request = StorageVolumeRequest {
        volume_id: creating.volume.id,
        project_id: creating.volume.project_id.clone(),
        size_bytes: creating.volume.size_bytes,
        generation: creating.volume.generation,
    };
    match provider.create_volume(&request).await {
        Ok(_) => {}
        Err(error) => {
            let mut failed = creating.clone();
            failed.volume.state = if error.is_unknown_outcome() {
                VolumeState::Unknown
            } else {
                VolumeState::Error
            };
            failed.volume.generation = failed.volume.generation.saturating_add(1);
            let _ = store
                .update_volume(creating.volume.generation, &failed)
                .await;
            return Err(error.to_string());
        }
    }
    let observed = provider
        .inspect_volume(&request)
        .await
        .map_err(|error| error.to_string())?;
    if !observed.owned || !observed.available || observed.size_bytes != creating.volume.size_bytes {
        return Err("provider volume observation did not match the requested volume".to_owned());
    }
    let mut realized = creating;
    realized.volume.state = VolumeState::Available;
    realized.volume.generation = realized
        .volume
        .generation
        .checked_add(1)
        .ok_or_else(|| "volume generation overflow".to_owned())?;
    realized.volume.provider_reference = Some(o3k_domain::StorageProviderReference {
        provider: observed.provider_reference.provider,
        resource_id: observed.provider_reference.resource_id,
    });
    let realized = store
        .update_volume(realized.volume.generation - 1, &realized)
        .await
        .map_err(|error| error.to_string())?;
    // The durable transition to `Available` is the point at which the volume
    // starts consuming allocated byte-seconds. A failed projection fails the
    // create so a caller with a deterministic resource id can replay it.
    observe_volume_allocation(
        metering,
        &realized.volume.project_id,
        &realized.volume.id.as_uuid().to_string(),
        realized.volume.size_bytes,
        true,
    )
    .await?;
    Ok(realized)
}

fn volume_observation_matches(
    record: &VolumeRecord,
    observation: &o3k_storage::StorageVolumeObservation,
) -> bool {
    observation.owned && observation.size_bytes == record.volume.size_bytes
}

fn available_volume_observation_matches(
    record: &VolumeRecord,
    observation: &o3k_storage::StorageVolumeObservation,
) -> bool {
    volume_observation_matches(record, observation) && observation.available
}

/// Shared provider-backed native Volume deletion.  Canonical state is kept in
/// `Deleting` until an explicit provider absence observation succeeds. The
/// allocation meter is closed at that same durable point so every caller
/// (Cinder projection and native adapter) closes exactly once.
pub async fn remove_native_volume(
    store: Arc<dyn o3k_store::StorageRepository>,
    provider: Arc<dyn o3k_storage::StorageProvider>,
    project_id: &str,
    id: Uuid,
    operation_id: Option<Uuid>,
    metering: Option<&Arc<dyn o3k_kernel::LifecycleMeteringObserver>>,
) -> Result<(), String> {
    let record = store
        .get_volume(id)
        .await
        .map_err(|error| error.to_string())?
        .ok_or_else(|| "volume not found".to_owned())?;
    if record.volume.project_id != project_id {
        return Err("volume not found".to_owned());
    }
    if store
        .list_volume_attachments_v1(project_id)
        .await
        .map_err(|error| error.to_string())?
        .into_iter()
        .any(|attachment| {
            attachment.attachment.volume_id.as_uuid() == id
                && !matches!(
                    attachment.attachment.state,
                    o3k_domain::VolumeAttachmentState::Deleted
                )
        })
    {
        return Err("volume has an active attachment".to_owned());
    }
    let mut deleting = record.clone();
    deleting.volume.state = VolumeState::Deleting;
    if operation_id.is_some() {
        deleting.volume.operation_id = operation_id;
    }
    deleting.volume.generation = record
        .volume
        .generation
        .checked_add(1)
        .ok_or_else(|| "volume generation overflow".to_owned())?;
    store
        .update_volume(record.volume.generation, &deleting)
        .await
        .map_err(|error| error.to_string())?;
    let request = StorageVolumeRequest {
        volume_id: id.into(),
        project_id: project_id.to_owned(),
        size_bytes: record.volume.size_bytes,
        generation: record.volume.generation,
    };
    match provider.delete_volume(&request).await {
        Ok(()) | Err(o3k_storage::StorageProviderError::NotFound) => {}
        Err(error) => return Err(error.to_string()),
    }
    match provider.inspect_volume(&request).await {
        // Keep the Deleting row as recovery inventory.  The caller removes
        // it only after all durable lifecycle projections have committed.
        Err(o3k_storage::StorageProviderError::NotFound) => {
            observe_volume_allocation(
                metering,
                &record.volume.project_id,
                &record.volume.id.as_uuid().to_string(),
                record.volume.size_bytes,
                false,
            )
            .await?;
            Ok(())
        }
        Ok(_) => Err("provider volume is still present".to_owned()),
        Err(error) => Err(error.to_string()),
    }
}

async fn scoped_store(
    state: &AppState,
    headers: &HeaderMap,
    project_id: &str,
) -> Result<
    (
        o3k_kernel::AuthContext,
        std::sync::Arc<dyn o3k_store::StorageRepository>,
    ),
    Response,
> {
    let auth = project_auth_context(state, headers, project_id)?;
    state
        .storage_store
        .clone()
        .map(|store| (auth, store))
        .ok_or_else(unavailable)
}

pub(crate) async fn list(
    State(state): State<AppState>,
    headers: HeaderMap,
    Path(project_id): Path<String>,
) -> Response {
    let Ok((_, store)) = scoped_store(&state, &headers, &project_id).await else {
        return unavailable();
    };
    match store.list_volumes(&project_id).await {
        Ok(records) => {
            // Repair any projection lost after a volume's durable transition;
            // idempotent and best-effort per record.
            for record in &records {
                repair_volume_metering(state.metering_observer.as_ref(), record).await;
            }
            Json(VolumeListResponse {
                volumes: records.iter().map(view).collect(),
            })
            .into_response()
        }
        Err(_) => unavailable(),
    }
}

pub(crate) async fn show(
    State(state): State<AppState>,
    headers: HeaderMap,
    Path((project_id, id)): Path<(String, String)>,
) -> Response {
    let Ok((_, store)) = scoped_store(&state, &headers, &project_id).await else {
        return unavailable();
    };
    let Some(id) = volume_id(&id) else {
        return volume_not_found();
    };
    match store.get_volume(id).await {
        Ok(Some(record)) if record.volume.project_id == project_id => {
            // Repair any projection lost after this volume's durable transition;
            // idempotent and best-effort so the read never fails on metering.
            repair_volume_metering(state.metering_observer.as_ref(), &record).await;
            (
                StatusCode::OK,
                Json(VolumeResponse {
                    volume: view(&record),
                }),
            )
                .into_response()
        }
        Ok(_) => {
            keystone_error(StatusCode::NOT_FOUND, "Not Found", "volume not found").into_response()
        }
        Err(_) => unavailable(),
    }
}

pub(crate) async fn create(
    State(state): State<AppState>,
    headers: HeaderMap,
    Path(project_id): Path<String>,
    Json(request): Json<VolumeRequest>,
) -> Response {
    let Ok((_, store)) = scoped_store(&state, &headers, &project_id).await else {
        return unavailable();
    };
    if request.volume.size == 0 {
        return keystone_error(
            StatusCode::BAD_REQUEST,
            "Bad Request",
            "size must be positive",
        )
        .into_response();
    }
    let size_bytes = match request.volume.size.checked_mul(1024 * 1024 * 1024) {
        Some(size_bytes) if size_bytes > 0 => size_bytes,
        _ => {
            return keystone_error(StatusCode::BAD_REQUEST, "Bad Request", "size is too large")
                .into_response();
        }
    };
    let id = VolumeId::from_uuid(Uuid::new_v4());
    let volume = Volume {
        id,
        project_id: project_id.clone(),
        name: request.volume.name.unwrap_or_else(|| id.to_string()),
        description: request.volume.description.unwrap_or_default(),
        metadata: match request.volume.metadata {
            Some(value) => match serde_json::from_value(value) {
                Ok(metadata) => metadata,
                Err(_) => {
                    return keystone_error(
                        StatusCode::BAD_REQUEST,
                        "Bad Request",
                        "metadata must be an object of strings",
                    )
                    .into_response();
                }
            },
            None => Default::default(),
        },
        availability_zone: request.volume.availability_zone,
        size_bytes,
        volume_type: request
            .volume
            .volume_type
            .unwrap_or_else(|| "lvmdriver-1".to_owned()),
        backend_id: "local".to_owned(),
        execution_scope: StorageExecutionScope::Host("local".to_owned()),
        state: VolumeState::Requested,
        generation: 1,
        operation_id: None,
        provider_reference: None,
    };
    let record = VolumeRecord {
        volume,
        created_at: now_rfc3339(),
    };
    if state.storage_provider.is_none() || state.native_volume_workflow.is_none() {
        return unavailable();
    }
    match store.insert_volume(&record).await {
        Ok(()) => {
            let workflow = state
                .native_volume_workflow
                .as_ref()
                .expect("checked above");
            if workflow.create(record.volume.id.as_uuid()).await.is_err() {
                return unavailable();
            }
            let record = match store.get_volume(record.volume.id.as_uuid()).await {
                Ok(Some(record)) => record,
                _ => return unavailable(),
            };
            (
                StatusCode::ACCEPTED,
                Json(VolumeResponse {
                    volume: view(&record),
                }),
            )
                .into_response()
        }
        Err(o3k_store::StoreError::ResourceAlreadyExists) => {
            keystone_error(StatusCode::CONFLICT, "Conflict", "volume already exists")
                .into_response()
        }
        Err(_) => unavailable(),
    }
}

pub(crate) async fn update(
    State(state): State<AppState>,
    headers: HeaderMap,
    Path((project_id, id)): Path<(String, String)>,
    Json(request): Json<VolumeUpdateRequest>,
) -> Response {
    let Ok((_, store)) = scoped_store(&state, &headers, &project_id).await else {
        return unavailable();
    };
    let Some(id) = volume_id(&id) else {
        return volume_not_found();
    };
    let Ok(Some(mut record)) = store.get_volume(id).await else {
        return keystone_error(StatusCode::NOT_FOUND, "Not Found", "volume not found")
            .into_response();
    };
    if record.volume.project_id != project_id {
        return keystone_error(StatusCode::NOT_FOUND, "Not Found", "volume not found")
            .into_response();
    }
    let VolumeUpdateRequest {
        volume:
            VolumeUpdate {
                name,
                description,
                metadata,
            },
    } = request;
    if let Some(name) = name {
        record.volume.name = name;
    }
    if let Some(description) = description {
        record.volume.description = description;
    }
    if let Some(metadata) = metadata {
        let Ok(metadata) = serde_json::from_value(metadata) else {
            return keystone_error(
                StatusCode::BAD_REQUEST,
                "Bad Request",
                "metadata must be an object",
            )
            .into_response();
        };
        record.volume.metadata = metadata;
    }
    record.volume.generation = record.volume.generation.saturating_add(1);
    match store
        .update_volume(record.volume.generation - 1, &record)
        .await
    {
        Ok(updated) => (
            StatusCode::OK,
            Json(VolumeResponse {
                volume: view(&updated),
            }),
        )
            .into_response(),
        Err(o3k_store::StoreError::StaleGeneration) => keystone_error(
            StatusCode::CONFLICT,
            "Conflict",
            "volume generation changed",
        )
        .into_response(),
        Err(_) => unavailable(),
    }
}

pub(crate) async fn delete(
    State(state): State<AppState>,
    headers: HeaderMap,
    Path((project_id, id)): Path<(String, String)>,
) -> Response {
    let Ok((_, store)) = scoped_store(&state, &headers, &project_id).await else {
        return unavailable();
    };
    let Some(id) = volume_id(&id) else {
        return volume_not_found();
    };
    let Ok(maybe_record) = store.get_volume(id).await else {
        return volume_not_found();
    };
    let Some(record) = maybe_record else {
        // A missing volume delete must be indistinguishable from a foreign
        // volume delete (both 404) so the endpoint does not act as an
        // existence oracle. Upstream Cinder also returns 404 when deleting a
        // volume that does not exist.
        return volume_not_found();
    };
    if record.volume.project_id != project_id {
        return keystone_error(StatusCode::NOT_FOUND, "Not Found", "volume not found")
            .into_response();
    }
    let attachments = match store.list_volume_attachments_v1(&project_id).await {
        Ok(attachments) => attachments,
        Err(_) => return unavailable(),
    };
    if attachments.into_iter().any(|a| {
        a.attachment.volume_id.as_uuid() == id
            && !matches!(
                a.attachment.state,
                o3k_domain::VolumeAttachmentState::Deleted
            )
    }) {
        return keystone_error(
            StatusCode::CONFLICT,
            "Conflict",
            "volume has an active attachment",
        )
        .into_response();
    }
    if state.storage_provider.is_none() || state.native_volume_workflow.is_none() {
        return unavailable();
    };
    let deletion = state
        .native_volume_workflow
        .as_ref()
        .expect("checked above")
        .delete(&project_id, id)
        .await;
    match deletion {
        Ok(()) => match store.delete_volume(&project_id, id).await {
            Ok(()) => StatusCode::NO_CONTENT.into_response(),
            Err(_) => unavailable(),
        },
        Err(_) => match store.get_volume(id).await {
            Ok(Some(deleting)) if deleting.volume.state == VolumeState::Deleting => (
                StatusCode::ACCEPTED,
                Json(VolumeResponse {
                    volume: view(&deleting),
                }),
            )
                .into_response(),
            _ => unavailable(),
        },
    }
}

/// Projects a recovered native volume transition into metering authority.
///
/// Returns `false` when a configured observer rejected the projection. The
/// caller must then skip the recovery mutation: the row stays in its
/// pre-recovery state and the next startup re-runs the same idempotent
/// transition. Without a configured observer recovery proceeds unchanged.
async fn observe_recovered_volume(
    state: &AppState,
    record: &VolumeRecord,
    consuming: bool,
) -> bool {
    match observe_volume_allocation(
        state.metering_observer.as_ref(),
        &record.volume.project_id,
        &record.volume.id.as_uuid().to_string(),
        record.volume.size_bytes,
        consuming,
    )
    .await
    {
        Ok(()) => true,
        Err(error) => {
            tracing::warn!(%error, volume_id = %record.volume.id, "native volume recovery metering projection failed; recovery deferred to the next startup");
            false
        }
    }
}

async fn finalize_recovered_native_delete(
    store: &Arc<dyn o3k_store::StorageRepository>,
    record: &VolumeRecord,
) -> bool {
    let Some(operation_id) = record.volume.operation_id else {
        return true;
    };
    let operation = match store.get_canonical_operation(operation_id).await {
        Ok(operation) => operation,
        Err(o3k_store::StoreError::OperationNotFound) => return true,
        Err(error) => {
            tracing::warn!(%error, volume_id = %record.volume.id, "native volume recovery could not read delete operation");
            return false;
        }
    };
    if operation.state == o3k_store::OperationState::Succeeded {
        return true;
    }
    let now = chrono::Utc::now().to_rfc3339();
    let update = match o3k_store::CanonicalOperationLifecycleUpdate::new(
        o3k_kernel::OperationState::Succeeded,
        operation.attempt.saturating_add(1),
        Some(now.clone()),
        Some(now),
        None,
    ) {
        Ok(update) => update,
        Err(error) => {
            tracing::warn!(%error, volume_id = %record.volume.id, "native volume recovery could not build delete completion");
            return false;
        }
    };
    match store
        .update_canonical_operation_lifecycle(operation_id, &update)
        .await
    {
        Ok(_) => true,
        Err(error) => {
            tracing::warn!(%error, volume_id = %record.volume.id, "native volume recovery could not persist delete completion");
            false
        }
    }
}

/// Reconciles native volumes left in a transitional state by a process
/// restart. Canonical volume rows are the recovery inventory; provider
/// inspection is performed before any repeat mutation and provider state is
/// never used to create a canonical volume.
pub async fn recover_native_volumes(state: &AppState) {
    let (Some(store), Some(provider)) = (
        state.storage_store.as_ref(),
        state.storage_provider.as_ref(),
    ) else {
        return;
    };
    let records = match store.list_all_volumes().await {
        Ok(records) => records,
        Err(error) => {
            tracing::error!(%error, "failed to enumerate native volumes during startup recovery");
            return;
        }
    };
    for record in records {
        let request = StorageVolumeRequest {
            volume_id: record.volume.id,
            project_id: record.volume.project_id.clone(),
            size_bytes: record.volume.size_bytes,
            generation: record.volume.generation,
        };
        match record.volume.state {
            VolumeState::Requested | VolumeState::Creating | VolumeState::Unknown => match provider
                .inspect_volume(&request)
                .await
            {
                Ok(observation) if available_volume_observation_matches(&record, &observation) => {
                    if !observe_recovered_volume(state, &record, true).await {
                        continue;
                    }
                    let mut available = record.clone();
                    available.volume.state = VolumeState::Available;
                    available.volume.generation = match record.volume.generation.checked_add(1) {
                        Some(generation) => generation,
                        None => {
                            tracing::error!(volume_id = %record.volume.id, "native volume generation overflow during recovery");
                            continue;
                        }
                    };
                    available.volume.provider_reference =
                        Some(o3k_domain::StorageProviderReference {
                            provider: observation.provider_reference.provider,
                            resource_id: observation.provider_reference.resource_id,
                        });
                    if let Err(error) = store
                        .update_volume(record.volume.generation, &available)
                        .await
                    {
                        tracing::warn!(%error, volume_id = %record.volume.id, "native volume recovery state update was fenced");
                    }
                }
                Ok(_) => {
                    tracing::warn!(volume_id = %record.volume.id, "native volume recovery rejected mismatched provider observation");
                }
                Err(o3k_storage::StorageProviderError::NotFound)
                    if matches!(
                        record.volume.state,
                        VolumeState::Requested | VolumeState::Creating | VolumeState::Unknown
                    ) =>
                {
                    // Recovery is observation-only. A missing provider object
                    // is not authorization to allocate a new object outside
                    // the durable operation workflow.
                    tracing::warn!(volume_id = %record.volume.id, "native volume recovery found no owned provider object; awaiting durable workflow replay");
                }
                Err(error) if error.is_unknown_outcome() => {
                    if record.volume.state != VolumeState::Requested {
                        let mut unknown = record.clone();
                        unknown.volume.state = VolumeState::Unknown;
                        unknown.volume.generation = unknown.volume.generation.saturating_add(1);
                        let _ = store
                            .update_volume(record.volume.generation, &unknown)
                            .await;
                    }
                }
                Err(_) => {}
            },
            VolumeState::Deleting => match provider.inspect_volume(&request).await {
                Err(o3k_storage::StorageProviderError::NotFound) => {
                    if !observe_recovered_volume(state, &record, false).await {
                        continue;
                    }
                    if finalize_recovered_native_delete(store, &record).await {
                        let _ = store
                            .delete_volume(&record.volume.project_id, record.volume.id.as_uuid())
                            .await;
                    }
                }
                Ok(observation) if volume_observation_matches(&record, &observation) => {
                    // Startup recovery is observation-only. The durable
                    // NativeVolumeWorkflow owns the subsequent delete and
                    // its observe-before-retry/fencing semantics.
                    tracing::info!(
                        volume_id = %record.volume.id,
                        provider_reference = %observation.provider_reference.resource_id,
                        "native volume deletion remains pending durable workflow replay"
                    );
                }
                Ok(_) => {
                    tracing::warn!(volume_id = %record.volume.id, "native volume deletion rejected mismatched provider observation");
                }
                Err(_) => {}
            },
            // An `Available` volume should be consuming. Re-observing its open
            // interval is idempotent and repairs a volume whose create
            // observation was interrupted before it was recorded. There is no
            // state mutation to gate, so a failed projection is simply retried
            // on the next startup.
            VolumeState::Available => {
                let _ = observe_recovered_volume(state, &record, true).await;
            }
            _ => {}
        }
    }
}
