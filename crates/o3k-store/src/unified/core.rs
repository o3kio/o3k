use async_trait::async_trait;
use uuid::Uuid;

use crate::{
    AgentCommandRecord, AgentCommandState, ArtifactTransferRecord, ArtifactTransferUpdate,
    CanonicalOperationLifecycleUpdate, CanonicalOperationRecord, DurableStore,
    IdempotencyReservation, IdempotencyReservationRequest, ImageOverlayIdentity,
    ImageOverlayOwnershipRecord, ImageOverlayUpdate, LifecycleTerminalization, ObservationUpdate,
    OperationRecord, OperationState, ProviderReference, RepositoryPage, ResourceRecord, StoreError,
    StoredIdempotencyReservation,
};

use super::O3kStore;
#[async_trait]
impl DurableStore for O3kStore {
    async fn insert_resource(&self, resource: &ResourceRecord) -> Result<(), StoreError> {
        match self {
            Self::Sqlite(s) => s.insert_resource(resource).await,
            Self::Postgres(s) => s.insert_resource(resource).await,
        }
    }

    async fn get_resource(&self, id: Uuid) -> Result<ResourceRecord, StoreError> {
        match self {
            Self::Sqlite(s) => s.get_resource(id).await,
            Self::Postgres(s) => s.get_resource(id).await,
        }
    }

    async fn list_resources(
        &self,
        project_id: &str,
        kind: &str,
    ) -> Result<Vec<ResourceRecord>, StoreError> {
        match self {
            Self::Sqlite(s) => s.list_resources(project_id, kind).await,
            Self::Postgres(s) => s.list_resources(project_id, kind).await,
        }
    }

    async fn list_resources_page(
        &self,
        project_id: &str,
        kind: &str,
        after_id: Option<&str>,
        limit: usize,
    ) -> Result<RepositoryPage<ResourceRecord>, StoreError> {
        match self {
            Self::Sqlite(s) => {
                s.list_resources_page(project_id, kind, after_id, limit)
                    .await
            }
            Self::Postgres(s) => {
                s.list_resources_page(project_id, kind, after_id, limit)
                    .await
            }
        }
    }

    async fn update_resource(
        &self,
        id: Uuid,
        expected_generation: i64,
        desired_state: &str,
        observed_state: &str,
        observed_generation: i64,
        provider_id: Option<&str>,
    ) -> Result<ResourceRecord, StoreError> {
        match self {
            Self::Sqlite(s) => {
                s.update_resource(
                    id,
                    expected_generation,
                    desired_state,
                    observed_state,
                    observed_generation,
                    provider_id,
                )
                .await
            }
            Self::Postgres(s) => {
                s.update_resource(
                    id,
                    expected_generation,
                    desired_state,
                    observed_state,
                    observed_generation,
                    provider_id,
                )
                .await
            }
        }
    }

    #[allow(clippy::too_many_arguments)]
    async fn update_resource_and_complete_operation(
        &self,
        resource_id: Uuid,
        expected_generation: i64,
        desired_state: &str,
        observed_state: &str,
        observed_generation: i64,
        provider_id: Option<&str>,
        operation_id: Uuid,
        lifecycle: &CanonicalOperationLifecycleUpdate,
    ) -> Result<ResourceRecord, StoreError> {
        match self {
            Self::Sqlite(s) => {
                s.update_resource_and_complete_operation(
                    resource_id,
                    expected_generation,
                    desired_state,
                    observed_state,
                    observed_generation,
                    provider_id,
                    operation_id,
                    lifecycle,
                )
                .await
            }
            Self::Postgres(s) => {
                s.update_resource_and_complete_operation(
                    resource_id,
                    expected_generation,
                    desired_state,
                    observed_state,
                    observed_generation,
                    provider_id,
                    operation_id,
                    lifecycle,
                )
                .await
            }
        }
    }

    async fn update_resource_from_observation(
        &self,
        id: Uuid,
        update: &ObservationUpdate<'_>,
    ) -> Result<ResourceRecord, StoreError> {
        match self {
            Self::Sqlite(s) => s.update_resource_from_observation(id, update).await,
            Self::Postgres(s) => s.update_resource_from_observation(id, update).await,
        }
    }

    async fn terminalize_lifecycle(
        &self,
        terminalization: &LifecycleTerminalization<'_>,
    ) -> Result<(OperationRecord, ResourceRecord), StoreError> {
        match self {
            Self::Sqlite(s) => s.terminalize_lifecycle(terminalization).await,
            Self::Postgres(s) => s.terminalize_lifecycle(terminalization).await,
        }
    }

    async fn insert_operation(&self, operation: &OperationRecord) -> Result<(), StoreError> {
        match self {
            Self::Sqlite(s) => s.insert_operation(operation).await,
            Self::Postgres(s) => s.insert_operation(operation).await,
        }
    }

    async fn get_idempotency_reservation(
        &self,
        owner_scope: &str,
        action: &str,
        key: &str,
    ) -> Result<Option<StoredIdempotencyReservation>, StoreError> {
        match self {
            Self::Sqlite(s) => {
                s.get_idempotency_reservation(owner_scope, action, key)
                    .await
            }
            Self::Postgres(s) => {
                s.get_idempotency_reservation(owner_scope, action, key)
                    .await
            }
        }
    }

    async fn reserve_idempotent_operation(
        &self,
        request: &IdempotencyReservationRequest,
    ) -> Result<IdempotencyReservation, StoreError> {
        match self {
            Self::Sqlite(s) => s.reserve_idempotent_operation(request).await,
            Self::Postgres(s) => s.reserve_idempotent_operation(request).await,
        }
    }

    async fn create_or_replay_idempotent_operation(
        &self,
        operation: &OperationRecord,
        request: &IdempotencyReservationRequest,
    ) -> Result<IdempotencyReservation, StoreError> {
        match self {
            Self::Sqlite(s) => {
                s.create_or_replay_idempotent_operation(operation, request)
                    .await
            }
            Self::Postgres(s) => {
                s.create_or_replay_idempotent_operation(operation, request)
                    .await
            }
        }
    }

    async fn create_or_replay_canonical_idempotent_operation(
        &self,
        operation: &OperationRecord,
        canonical: &CanonicalOperationRecord,
        request: &IdempotencyReservationRequest,
    ) -> Result<IdempotencyReservation, StoreError> {
        match self {
            Self::Sqlite(store) => {
                store
                    .create_or_replay_canonical_idempotent_operation(operation, canonical, request)
                    .await
            }
            Self::Postgres(store) => {
                store
                    .create_or_replay_canonical_idempotent_operation(operation, canonical, request)
                    .await
            }
        }
    }

    async fn create_or_replay_canonical_resource_operation(
        &self,
        resource: &crate::ResourceRecord,
        operation: &crate::OperationRecord,
        canonical: &crate::CanonicalOperationRecord,
        request: &crate::IdempotencyReservationRequest,
        expected_placement_allocation_id: Option<&str>,
    ) -> Result<crate::CanonicalAcceptanceOutcome, StoreError> {
        match self {
            Self::Sqlite(store) => {
                store
                    .create_or_replay_canonical_resource_operation(
                        resource,
                        operation,
                        canonical,
                        request,
                        expected_placement_allocation_id,
                    )
                    .await
            }
            Self::Postgres(store) => {
                store
                    .create_or_replay_canonical_resource_operation(
                        resource,
                        operation,
                        canonical,
                        request,
                        expected_placement_allocation_id,
                    )
                    .await
            }
        }
    }

    async fn create_or_replay_canonical_lifecycle_operation(
        &self,
        operation: &crate::OperationRecord,
        canonical: &crate::CanonicalOperationRecord,
        request: &crate::IdempotencyReservationRequest,
    ) -> Result<crate::CanonicalAcceptanceOutcome, StoreError> {
        match self {
            Self::Sqlite(store) => {
                store
                    .create_or_replay_canonical_lifecycle_operation(operation, canonical, request)
                    .await
            }
            Self::Postgres(store) => {
                store
                    .create_or_replay_canonical_lifecycle_operation(operation, canonical, request)
                    .await
            }
        }
    }

    async fn create_or_replay_canonical_scoped_operation(
        &self,
        operation: &OperationRecord,
        canonical: &CanonicalOperationRecord,
        request: &IdempotencyReservationRequest,
    ) -> Result<IdempotencyReservation, StoreError> {
        match self {
            Self::Sqlite(store) => {
                store
                    .create_or_replay_canonical_scoped_operation(operation, canonical, request)
                    .await
            }
            Self::Postgres(store) => {
                store
                    .create_or_replay_canonical_scoped_operation(operation, canonical, request)
                    .await
            }
        }
    }

    async fn get_operation(&self, id: Uuid) -> Result<OperationRecord, StoreError> {
        match self {
            Self::Sqlite(s) => s.get_operation(id).await,
            Self::Postgres(s) => s.get_operation(id).await,
        }
    }

    async fn get_canonical_operation(
        &self,
        id: Uuid,
    ) -> Result<CanonicalOperationRecord, StoreError> {
        match self {
            Self::Sqlite(s) => s.get_canonical_operation(id).await,
            Self::Postgres(s) => s.get_canonical_operation(id).await,
        }
    }

    async fn update_operation(
        &self,
        id: Uuid,
        state: OperationState,
        provider_operation_id: Option<&str>,
        error_category: Option<&str>,
        error_message: Option<&str>,
    ) -> Result<OperationRecord, StoreError> {
        match self {
            Self::Sqlite(s) => {
                s.update_operation(
                    id,
                    state,
                    provider_operation_id,
                    error_category,
                    error_message,
                )
                .await
            }
            Self::Postgres(s) => {
                s.update_operation(
                    id,
                    state,
                    provider_operation_id,
                    error_category,
                    error_message,
                )
                .await
            }
        }
    }

    async fn update_canonical_operation_lifecycle(
        &self,
        id: Uuid,
        update: &crate::CanonicalOperationLifecycleUpdate,
    ) -> Result<CanonicalOperationRecord, StoreError> {
        match self {
            Self::Sqlite(s) => s.update_canonical_operation_lifecycle(id, update).await,
            Self::Postgres(s) => s.update_canonical_operation_lifecycle(id, update).await,
        }
    }

    async fn list_non_terminal_lifecycle_operations(
        &self,
    ) -> Result<Vec<OperationRecord>, StoreError> {
        match self {
            Self::Sqlite(s) => s.list_non_terminal_lifecycle_operations().await,
            Self::Postgres(s) => s.list_non_terminal_lifecycle_operations().await,
        }
    }

    async fn list_canonical_operations_page(
        &self,
        owner_scope: &str,
        after_id: Option<Uuid>,
        limit: u32,
    ) -> Result<Vec<CanonicalOperationRecord>, StoreError> {
        match self {
            Self::Sqlite(s) => {
                s.list_canonical_operations_page(owner_scope, after_id, limit)
                    .await
            }
            Self::Postgres(s) => {
                s.list_canonical_operations_page(owner_scope, after_id, limit)
                    .await
            }
        }
    }

    async fn attach_provider_reference(
        &self,
        reference: &ProviderReference,
    ) -> Result<(), StoreError> {
        match self {
            Self::Sqlite(s) => s.attach_provider_reference(reference).await,
            Self::Postgres(s) => s.attach_provider_reference(reference).await,
        }
    }

    async fn get_provider_reference(
        &self,
        resource_id: Uuid,
        provider_name: &str,
    ) -> Result<ProviderReference, StoreError> {
        match self {
            Self::Sqlite(s) => s.get_provider_reference(resource_id, provider_name).await,
            Self::Postgres(s) => s.get_provider_reference(resource_id, provider_name).await,
        }
    }

    async fn insert_agent_command(
        &self,
        command: &AgentCommandRecord,
    ) -> Result<AgentCommandRecord, StoreError> {
        match self {
            Self::Sqlite(s) => s.insert_agent_command(command).await,
            Self::Postgres(s) => s.insert_agent_command(command).await,
        }
    }

    async fn get_agent_command(&self, command_id: &str) -> Result<AgentCommandRecord, StoreError> {
        match self {
            Self::Sqlite(s) => s.get_agent_command(command_id).await,
            Self::Postgres(s) => s.get_agent_command(command_id).await,
        }
    }

    async fn get_agent_command_by_idempotency_key(
        &self,
        idempotency_key: &str,
    ) -> Result<AgentCommandRecord, StoreError> {
        match self {
            Self::Sqlite(s) => {
                s.get_agent_command_by_idempotency_key(idempotency_key)
                    .await
            }
            Self::Postgres(s) => {
                s.get_agent_command_by_idempotency_key(idempotency_key)
                    .await
            }
        }
    }

    async fn get_agent_command_by_operation(
        &self,
        operation_id: Uuid,
    ) -> Result<AgentCommandRecord, StoreError> {
        match self {
            Self::Sqlite(s) => s.get_agent_command_by_operation(operation_id).await,
            Self::Postgres(s) => s.get_agent_command_by_operation(operation_id).await,
        }
    }

    async fn update_agent_command(
        &self,
        command_id: &str,
        state: AgentCommandState,
        accepted_sequence: u64,
        last_sequence: u64,
        provider_operation_id: Option<&str>,
        provider_resource_id: Option<&str>,
    ) -> Result<AgentCommandRecord, StoreError> {
        match self {
            Self::Sqlite(s) => {
                s.update_agent_command(
                    command_id,
                    state,
                    accepted_sequence,
                    last_sequence,
                    provider_operation_id,
                    provider_resource_id,
                )
                .await
            }
            Self::Postgres(s) => {
                s.update_agent_command(
                    command_id,
                    state,
                    accepted_sequence,
                    last_sequence,
                    provider_operation_id,
                    provider_resource_id,
                )
                .await
            }
        }
    }

    async fn list_recoverable_agent_commands(&self) -> Result<Vec<AgentCommandRecord>, StoreError> {
        match self {
            Self::Sqlite(s) => s.list_recoverable_agent_commands().await,
            Self::Postgres(s) => s.list_recoverable_agent_commands().await,
        }
    }

    async fn insert_artifact_transfer(
        &self,
        transfer: &ArtifactTransferRecord,
    ) -> Result<ArtifactTransferRecord, StoreError> {
        match self {
            Self::Sqlite(s) => s.insert_artifact_transfer(transfer).await,
            Self::Postgres(s) => s.insert_artifact_transfer(transfer).await,
        }
    }

    async fn get_artifact_transfer(
        &self,
        transfer_id: &str,
    ) -> Result<ArtifactTransferRecord, StoreError> {
        match self {
            Self::Sqlite(s) => s.get_artifact_transfer(transfer_id).await,
            Self::Postgres(s) => s.get_artifact_transfer(transfer_id).await,
        }
    }

    async fn rebind_artifact_transfer_epoch(
        &self,
        transfer_id: &str,
        expected_agent_epoch: &str,
        new_agent_epoch: &str,
    ) -> Result<ArtifactTransferRecord, StoreError> {
        match self {
            Self::Sqlite(s) => {
                s.rebind_artifact_transfer_epoch(transfer_id, expected_agent_epoch, new_agent_epoch)
                    .await
            }
            Self::Postgres(s) => {
                s.rebind_artifact_transfer_epoch(transfer_id, expected_agent_epoch, new_agent_epoch)
                    .await
            }
        }
    }

    async fn update_artifact_transfer(
        &self,
        transfer_id: &str,
        expected_agent_epoch: &str,
        update: ArtifactTransferUpdate,
    ) -> Result<ArtifactTransferRecord, StoreError> {
        match self {
            Self::Sqlite(s) => {
                s.update_artifact_transfer(transfer_id, expected_agent_epoch, update)
                    .await
            }
            Self::Postgres(s) => {
                s.update_artifact_transfer(transfer_id, expected_agent_epoch, update)
                    .await
            }
        }
    }

    async fn list_recoverable_artifact_transfers(
        &self,
    ) -> Result<Vec<ArtifactTransferRecord>, StoreError> {
        match self {
            Self::Sqlite(s) => s.list_recoverable_artifact_transfers().await,
            Self::Postgres(s) => s.list_recoverable_artifact_transfers().await,
        }
    }

    async fn expire_transfers_of_terminal_operations(&self) -> Result<u64, StoreError> {
        match self {
            Self::Sqlite(s) => s.expire_transfers_of_terminal_operations().await,
            Self::Postgres(s) => s.expire_transfers_of_terminal_operations().await,
        }
    }

    async fn insert_image_overlay(
        &self,
        overlay: &ImageOverlayOwnershipRecord,
    ) -> Result<ImageOverlayOwnershipRecord, StoreError> {
        match self {
            Self::Sqlite(s) => s.insert_image_overlay(overlay).await,
            Self::Postgres(s) => s.insert_image_overlay(overlay).await,
        }
    }

    async fn get_image_overlay(
        &self,
        overlay_id: &str,
    ) -> Result<ImageOverlayOwnershipRecord, StoreError> {
        match self {
            Self::Sqlite(s) => s.get_image_overlay(overlay_id).await,
            Self::Postgres(s) => s.get_image_overlay(overlay_id).await,
        }
    }

    async fn update_image_overlay(
        &self,
        overlay_id: &str,
        expected_identity: &ImageOverlayIdentity,
        update: ImageOverlayUpdate,
    ) -> Result<ImageOverlayOwnershipRecord, StoreError> {
        match self {
            Self::Sqlite(s) => {
                s.update_image_overlay(overlay_id, expected_identity, update)
                    .await
            }
            Self::Postgres(s) => {
                s.update_image_overlay(overlay_id, expected_identity, update)
                    .await
            }
        }
    }

    async fn list_image_overlays(
        &self,
        resource_id: Uuid,
    ) -> Result<Vec<ImageOverlayOwnershipRecord>, StoreError> {
        match self {
            Self::Sqlite(s) => s.list_image_overlays(resource_id).await,
            Self::Postgres(s) => s.list_image_overlays(resource_id).await,
        }
    }

    async fn count_image_overlay_references(
        &self,
        base_sha256: &str,
        base_format: &str,
    ) -> Result<u64, StoreError> {
        match self {
            Self::Sqlite(s) => {
                s.count_image_overlay_references(base_sha256, base_format)
                    .await
            }
            Self::Postgres(s) => {
                s.count_image_overlay_references(base_sha256, base_format)
                    .await
            }
        }
    }

    async fn delete_image_overlay(
        &self,
        overlay_id: &str,
        expected_identity: &ImageOverlayIdentity,
    ) -> Result<ImageOverlayOwnershipRecord, StoreError> {
        match self {
            Self::Sqlite(s) => s.delete_image_overlay(overlay_id, expected_identity).await,
            Self::Postgres(s) => s.delete_image_overlay(overlay_id, expected_identity).await,
        }
    }

    async fn increment_operation_retry(&self, operation_id: Uuid) -> Result<u8, StoreError> {
        match self {
            Self::Sqlite(s) => s.increment_operation_retry(operation_id).await,
            Self::Postgres(s) => s.increment_operation_retry(operation_id).await,
        }
    }

    async fn insert_resource_and_operation(
        &self,
        resource: &ResourceRecord,
        operation: &OperationRecord,
        expected_placement_allocation_id: Option<&str>,
    ) -> Result<(), StoreError> {
        match self {
            Self::Sqlite(s) => {
                s.insert_resource_and_operation(
                    resource,
                    operation,
                    expected_placement_allocation_id,
                )
                .await
            }
            Self::Postgres(s) => {
                s.insert_resource_and_operation(
                    resource,
                    operation,
                    expected_placement_allocation_id,
                )
                .await
            }
        }
    }

    async fn revive_resource_and_operation(
        &self,
        id: Uuid,
        expected_generation: i64,
        desired_state: &str,
        observed_state: &str,
        observed_generation: i64,
        provider_id: Option<&str>,
        operation: &OperationRecord,
        expected_placement_allocation_id: Option<&str>,
    ) -> Result<ResourceRecord, StoreError> {
        match self {
            Self::Sqlite(s) => {
                s.revive_resource_and_operation(
                    id,
                    expected_generation,
                    desired_state,
                    observed_state,
                    observed_generation,
                    provider_id,
                    operation,
                    expected_placement_allocation_id,
                )
                .await
            }
            Self::Postgres(s) => {
                s.revive_resource_and_operation(
                    id,
                    expected_generation,
                    desired_state,
                    observed_state,
                    observed_generation,
                    provider_id,
                    operation,
                    expected_placement_allocation_id,
                )
                .await
            }
        }
    }

    async fn readiness_check(&self) -> Result<(), StoreError> {
        self.readiness_check().await
    }
}
