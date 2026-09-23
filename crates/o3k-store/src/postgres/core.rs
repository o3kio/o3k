use async_trait::async_trait;
use sqlx::Row;
use uuid::Uuid;

use crate::StoredIdempotencyReservation;
use crate::{
    AgentCommandRecord, AgentCommandState, ArtifactTransferRecord, ArtifactTransferState,
    ArtifactTransferUpdate, CanonicalOperationLifecycleUpdate, CanonicalOperationRecord,
    DurableStore, IdempotencyReservation, IdempotencyReservationRequest, ImageOverlayIdentity,
    ImageOverlayOwnershipRecord, ImageOverlayState, ImageOverlayUpdate, LifecycleTerminalization,
    ObservationUpdate, OperationRecord, OperationState, ProviderReference, RepositoryPage,
    ResourceRecord, StoreError, validate_canonical_idempotent_operation_identity,
    validate_canonical_lifecycle_update,
};

use super::{
    PostgresStore,
    helpers::{
        insert_postgres_canonical_acceptance, map_pg_error, parse_uuid,
        postgres_existing_acceptance, postgres_existing_acceptance_tx, row_to_operation,
        row_to_resource, validate_existing_canonical_reservation,
        validate_image_overlay_transition,
    },
};

#[async_trait]
impl DurableStore for PostgresStore {
    async fn insert_resource(&self, resource: &ResourceRecord) -> Result<(), StoreError> {
        let id_str = resource.id.to_string();
        sqlx::query(
            "INSERT INTO resources (id, kind, project_id, generation, observed_generation, desired_state, observed_state, provider_id)
             VALUES ($1, $2, $3, $4, $5, $6, $7, $8)",
        )
        .bind(&id_str)
        .bind(&resource.kind)
        .bind(&resource.project_id)
        .bind(resource.generation)
        .bind(resource.observed_generation)
        .bind(&resource.desired_state)
        .bind(&resource.observed_state)
        .bind(&resource.provider_id)
        .execute(&self.pool)
        .await
        .map_err(map_pg_error)?;
        Ok(())
    }

    async fn get_resource(&self, id: Uuid) -> Result<ResourceRecord, StoreError> {
        let id_str = id.to_string();
        let row = sqlx::query("SELECT * FROM resources WHERE id = $1")
            .bind(&id_str)
            .fetch_optional(&self.pool)
            .await
            .map_err(StoreError::Database)?;

        match row {
            Some(row) => row_to_resource(&row),
            None => Err(StoreError::ResourceNotFound),
        }
    }

    async fn list_resources(
        &self,
        project_id: &str,
        kind: &str,
    ) -> Result<Vec<ResourceRecord>, StoreError> {
        let rows = sqlx::query(
            "SELECT * FROM resources WHERE project_id = $1 AND kind = $2 ORDER BY created_at ASC",
        )
        .bind(project_id)
        .bind(kind)
        .fetch_all(&self.pool)
        .await
        .map_err(StoreError::Database)?;

        rows.iter().map(row_to_resource).collect()
    }

    async fn list_resources_page(
        &self,
        project_id: &str,
        kind: &str,
        after_id: Option<&str>,
        limit: usize,
    ) -> Result<RepositoryPage<ResourceRecord>, StoreError> {
        let fetch_limit = crate::port::durable::bounded_fetch_limit(limit)?;
        let rows = if let Some(after_id) = after_id {
            sqlx::query("SELECT * FROM resources WHERE project_id = $1 AND kind = $2 AND id > $3 ORDER BY id LIMIT $4").bind(project_id).bind(kind).bind(after_id).bind(fetch_limit).fetch_all(&self.pool).await
        } else {
            sqlx::query("SELECT * FROM resources WHERE project_id = $1 AND kind = $2 ORDER BY id LIMIT $3").bind(project_id).bind(kind).bind(fetch_limit).fetch_all(&self.pool).await
        }.map_err(StoreError::Database)?;
        let mut items: Vec<_> = rows.iter().map(row_to_resource).collect::<Result<_, _>>()?;
        let has_more = items.len() > limit;
        if has_more {
            items.pop();
        }
        let continuation_key = if has_more {
            items.last().map(|r| r.id.to_string())
        } else {
            None
        };
        RepositoryPage::new(items, has_more, continuation_key, limit)
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
        let id_str = id.to_string();
        let res = sqlx::query(
            "UPDATE resources
             SET desired_state = $1, observed_state = $2, observed_generation = $3, provider_id = $4, generation = generation + 1
             WHERE id = $5 AND generation = $6",
        )
        .bind(desired_state)
        .bind(observed_state)
        .bind(observed_generation)
        .bind(provider_id)
        .bind(&id_str)
        .bind(expected_generation)
        .execute(&self.pool)
        .await
        .map_err(StoreError::Database)?;

        if res.rows_affected() == 0 {
            let exists = sqlx::query("SELECT 1 FROM resources WHERE id = $1")
                .bind(&id_str)
                .fetch_optional(&self.pool)
                .await
                .map_err(StoreError::Database)?;
            if exists.is_none() {
                return Err(StoreError::ResourceNotFound);
            }
            return Err(StoreError::StaleGeneration);
        }

        self.get_resource(id).await
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
        validate_canonical_lifecycle_update(lifecycle)?;
        let mut tx = self.pool.begin().await.map_err(StoreError::Database)?;
        let id_str = resource_id.to_string();
        let updated = sqlx::query(
            "UPDATE resources SET desired_state = $1, observed_state = $2, observed_generation = $3, provider_id = $4, generation = generation + 1 WHERE id = $5 AND generation = $6",
        )
        .bind(desired_state).bind(observed_state).bind(observed_generation)
        .bind(provider_id).bind(&id_str).bind(expected_generation)
        .execute(&mut *tx).await.map_err(StoreError::Database)?;
        if updated.rows_affected() == 0 {
            let exists = sqlx::query("SELECT 1 FROM resources WHERE id = $1")
                .bind(&id_str)
                .fetch_optional(&mut *tx)
                .await
                .map_err(StoreError::Database)?;
            return if exists.is_none() {
                Err(StoreError::ResourceNotFound)
            } else {
                Err(StoreError::StaleGeneration)
            };
        }
        let operation = sqlx::query("SELECT state FROM operations WHERE id = $1 FOR UPDATE")
            .bind(operation_id.to_string())
            .fetch_optional(&mut *tx)
            .await
            .map_err(StoreError::Database)?
            .ok_or(StoreError::OperationNotFound)?;
        let state: String = operation.try_get("state").map_err(StoreError::Database)?;
        if state == OperationState::Succeeded.as_str() || state == OperationState::Failed.as_str() {
            return Err(StoreError::Corrupt("operation already terminal".into()));
        }
        sqlx::query("UPDATE operations SET state = $1 WHERE id = $2")
            .bind(lifecycle.state.as_str())
            .bind(operation_id.to_string())
            .execute(&mut *tx)
            .await
            .map_err(StoreError::Database)?;
        let attempt = i32::try_from(lifecycle.attempt)
            .map_err(|_| StoreError::Corrupt("operation attempt exceeds PostgreSQL INT4".into()))?;
        sqlx::query("UPDATE canonical_operation_metadata SET attempt = $1, started_at = $2, finished_at = $3, error = $4 WHERE operation_id = $5")
            .bind(attempt).bind(&lifecycle.started_at).bind(&lifecycle.finished_at)
            .bind(&lifecycle.public_error).bind(operation_id.to_string())
            .execute(&mut *tx).await.map_err(StoreError::Database)?;
        tx.commit().await.map_err(StoreError::Database)?;
        self.get_resource(resource_id).await
    }

    async fn terminalize_lifecycle(
        &self,
        terminalization: &LifecycleTerminalization<'_>,
    ) -> Result<(OperationRecord, ResourceRecord), StoreError> {
        terminalization.validate()?;
        let mut tx = self.pool.begin().await.map_err(StoreError::Database)?;
        let op_id = terminalization.operation_id.to_string();
        let row = sqlx::query(
            "SELECT id, resource_id, kind, state, provider_operation_id, error_category, error_message FROM operations WHERE id = $1 FOR UPDATE",
        )
        .bind(&op_id)
        .fetch_optional(&mut *tx)
        .await
        .map_err(StoreError::Database)?
        .ok_or(StoreError::OperationNotFound)?;
        let current = row_to_operation(&row)?;
        if matches!(
            current.state,
            OperationState::Succeeded | OperationState::Failed
        ) {
            // Equivalent replay: the first terminalization committed the
            // resource projection in this same transaction, so re-applying it
            // could only double-bump the generation or clobber a newer
            // legitimate write. Fill in durable evidence the first write
            // lacked (mirroring `update_operation`'s terminal replay arm) and
            // leave the resource row untouched.
            if current
                .provider_operation_id
                .as_deref()
                .is_some_and(|existing| {
                    terminalization
                        .provider_operation_id
                        .is_some_and(|incoming| incoming != existing)
                })
            {
                return Err(StoreError::Corrupt(
                    "terminal operation provider identity conflicts with durable state".to_owned(),
                ));
            }
            if current.state != terminalization.terminal_state {
                return Err(StoreError::Corrupt(
                    "terminal operation state cannot conflict with durable state".to_owned(),
                ));
            }
            sqlx::query("UPDATE operations SET provider_operation_id = COALESCE($1, provider_operation_id), error_category = COALESCE($2, error_category), error_message = COALESCE($3, error_message) WHERE id = $4")
                .bind(terminalization.provider_operation_id)
                .bind(terminalization.error_category)
                .bind(terminalization.error_message)
                .bind(&op_id)
                .execute(&mut *tx)
                .await
                .map_err(StoreError::Database)?;
            tx.commit().await.map_err(StoreError::Database)?;
            return Ok((
                self.get_operation(terminalization.operation_id).await?,
                self.get_resource(terminalization.resource_id).await?,
            ));
        }
        sqlx::query("UPDATE operations SET state = $1, provider_operation_id = $2, error_category = $3, error_message = $4 WHERE id = $5")
            .bind(terminalization.terminal_state.as_str())
            .bind(terminalization.provider_operation_id)
            .bind(terminalization.error_category)
            .bind(terminalization.error_message)
            .bind(&op_id)
            .execute(&mut *tx)
            .await
            .map_err(StoreError::Database)?;
        let now = chrono::Utc::now().to_rfc3339();
        sqlx::query("UPDATE canonical_operation_metadata SET started_at=COALESCE(started_at,$1), finished_at=$2, error=$3 WHERE operation_id=$4")
            .bind(Some(now.clone()))
            .bind(Some(now))
            .bind(terminalization.error_category)
            .bind(&op_id)
            .execute(&mut *tx)
            .await
            .map_err(StoreError::Database)?;
        // The terminal resource projection is fenced on the caller's expected
        // generation: a stale writer rolls the whole terminalization back, so
        // no half-committed pair can exist (issue #1041).
        let res_id = terminalization.resource_id.to_string();
        let updated = sqlx::query(
            "UPDATE resources SET desired_state = $1, observed_state = $2, observed_generation = $3, provider_id = $4, generation = generation + 1 WHERE id = $5 AND generation = $6",
        )
        .bind(terminalization.desired_state)
        .bind(terminalization.observed_state)
        .bind(terminalization.observed_generation)
        .bind(terminalization.provider_id)
        .bind(&res_id)
        .bind(terminalization.expected_generation)
        .execute(&mut *tx)
        .await
        .map_err(StoreError::Database)?;
        if updated.rows_affected() == 0 {
            let exists = sqlx::query("SELECT 1 FROM resources WHERE id = $1")
                .bind(&res_id)
                .fetch_optional(&mut *tx)
                .await
                .map_err(StoreError::Database)?;
            return if exists.is_none() {
                Err(StoreError::ResourceNotFound)
            } else {
                Err(StoreError::StaleGeneration)
            };
        }
        tx.commit().await.map_err(StoreError::Database)?;
        Ok((
            self.get_operation(terminalization.operation_id).await?,
            self.get_resource(terminalization.resource_id).await?,
        ))
    }

    async fn update_resource_from_observation(
        &self,
        id: Uuid,
        update: &ObservationUpdate<'_>,
    ) -> Result<ResourceRecord, StoreError> {
        let mut tx = self.pool.begin().await.map_err(StoreError::Database)?;
        let id_str = id.to_string();

        let row = sqlx::query("SELECT id, kind, project_id, generation, observed_generation, desired_state, observed_state, provider_id FROM resources WHERE id = $1 FOR UPDATE")
            .bind(&id_str)
            .fetch_optional(&mut *tx)
            .await
            .map_err(StoreError::Database)?
            .ok_or(StoreError::ResourceNotFound)?;

        let current = row_to_resource(&row)?;
        if current.generation != update.expected_generation {
            return Err(StoreError::StaleGeneration);
        }

        let watermark = sqlx::query(
            "SELECT agent_epoch, observation_sequence FROM observation_watermarks WHERE resource_id = $1",
        )
        .bind(&id_str)
        .fetch_optional(&mut *tx)
        .await
        .map_err(StoreError::Database)?;

        if let Some(watermark) = watermark {
            let previous_epoch: String = watermark.get("agent_epoch");
            let previous_sequence: i64 = watermark.get("observation_sequence");
            if previous_epoch == update.agent_epoch
                && update.observation_sequence
                    <= u64::try_from(previous_sequence).unwrap_or(u64::MAX)
            {
                return Ok(current);
            }
        }

        sqlx::query("UPDATE resources SET generation = generation + 1, desired_state = $1, observed_state = $2, observed_generation = $3, provider_id = $4 WHERE id = $5 AND generation = $6")
            .bind(update.desired_state)
            .bind(update.observed_state)
            .bind(update.observed_generation)
            .bind(update.provider_id)
            .bind(&id_str)
            .bind(update.expected_generation)
            .execute(&mut *tx)
            .await
            .map_err(StoreError::Database)?;

        sqlx::query("INSERT INTO observation_watermarks (resource_id, agent_epoch, observation_sequence) VALUES ($1, $2, $3) ON CONFLICT(resource_id) DO UPDATE SET agent_epoch = EXCLUDED.agent_epoch, observation_sequence = EXCLUDED.observation_sequence")
            .bind(&id_str)
            .bind(update.agent_epoch)
            .bind(update.observation_sequence as i64)
            .execute(&mut *tx)
            .await
            .map_err(StoreError::Database)?;

        tx.commit().await.map_err(StoreError::Database)?;
        self.get_resource(id).await
    }

    async fn insert_operation(&self, operation: &OperationRecord) -> Result<(), StoreError> {
        let id_str = operation.id.to_string();
        let resource_id_str = operation.resource_id.to_string();
        sqlx::query(
            "INSERT INTO operations (id, resource_id, kind, state, provider_operation_id, error_category, error_message)
             VALUES ($1, $2, $3, $4, $5, $6, $7)",
        )
        .bind(&id_str)
        .bind(&resource_id_str)
        .bind(&operation.kind)
        .bind(operation.state.as_str())
        .bind(&operation.provider_operation_id)
        .bind(&operation.error_category)
        .bind(&operation.error_message)
        .execute(&self.pool)
        .await
        .map_err(map_pg_error)?;
        Ok(())
    }

    async fn get_idempotency_reservation(
        &self,
        owner_scope: &str,
        action: &str,
        key: &str,
    ) -> Result<Option<StoredIdempotencyReservation>, StoreError> {
        let row = sqlx::query(
            "SELECT fingerprint, operation_id FROM idempotency_reservations WHERE owner_scope = $1 AND action = $2 AND idempotency_key = $3",
        )
        .bind(owner_scope)
        .bind(action)
        .bind(key)
        .fetch_optional(&self.pool)
        .await
        .map_err(StoreError::Database)?;
        row.map(|row| {
            let fingerprint: String = row.try_get("fingerprint").map_err(StoreError::Database)?;
            let operation_id = Uuid::parse_str(
                row.try_get::<String, _>("operation_id")
                    .map_err(StoreError::Database)?
                    .as_str(),
            )
            .map_err(StoreError::InvalidUuid)?;
            Ok(StoredIdempotencyReservation {
                fingerprint,
                operation_id,
            })
        })
        .transpose()
    }

    async fn reserve_idempotent_operation(
        &self,
        request: &IdempotencyReservationRequest,
    ) -> Result<IdempotencyReservation, StoreError> {
        let result = sqlx::query("INSERT INTO idempotency_reservations (owner_scope, action, idempotency_key, fingerprint, operation_id) VALUES ($1, $2, $3, $4, $5)").bind(&request.owner_scope).bind(&request.action).bind(&request.key).bind(&request.fingerprint).bind(request.operation_id.to_string()).execute(&self.pool).await;
        match result {
            Ok(_) => Ok(IdempotencyReservation::Created(request.operation_id)),
            Err(sqlx::Error::Database(error)) if error.is_unique_violation() => {
                let row = sqlx::query("SELECT fingerprint, operation_id FROM idempotency_reservations WHERE owner_scope = $1 AND action = $2 AND idempotency_key = $3").bind(&request.owner_scope).bind(&request.action).bind(&request.key).fetch_one(&self.pool).await.map_err(StoreError::Database)?;
                let fingerprint: String =
                    row.try_get("fingerprint").map_err(StoreError::Database)?;
                let id: String = row.try_get("operation_id").map_err(StoreError::Database)?;
                if fingerprint != request.fingerprint {
                    return Ok(IdempotencyReservation::Conflict);
                }
                Ok(IdempotencyReservation::ExistingEquivalent(
                    Uuid::parse_str(&id).map_err(StoreError::InvalidUuid)?,
                ))
            }
            Err(error) => Err(StoreError::Database(error)),
        }
    }

    async fn create_or_replay_idempotent_operation(
        &self,
        operation: &OperationRecord,
        request: &IdempotencyReservationRequest,
    ) -> Result<IdempotencyReservation, StoreError> {
        if operation.id != request.operation_id {
            return Err(StoreError::Corrupt(
                "operation and idempotency identities differ".into(),
            ));
        }
        let mut tx = self.pool.begin().await.map_err(StoreError::Database)?;
        let inserted = sqlx::query("INSERT INTO operations (id, resource_id, kind, state, provider_operation_id, error_category, error_message) VALUES ($1,$2,$3,$4,$5,$6,$7)")
            .bind(operation.id.to_string()).bind(operation.resource_id.to_string()).bind(&operation.kind)
            .bind(operation.state.as_str()).bind(&operation.provider_operation_id)
            .bind(&operation.error_category).bind(&operation.error_message).execute(&mut *tx).await;
        let operation_inserted = match inserted {
            Ok(_) => true,
            Err(sqlx::Error::Database(error)) if error.is_unique_violation() => false,
            Err(error) => return Err(StoreError::Database(error)),
        };
        let result = sqlx::query("INSERT INTO idempotency_reservations (owner_scope, action, idempotency_key, fingerprint, operation_id) VALUES ($1,$2,$3,$4,$5)")
            .bind(&request.owner_scope).bind(&request.action).bind(&request.key).bind(&request.fingerprint)
            .bind(request.operation_id.to_string()).execute(&mut *tx).await;
        let outcome = match result {
            Ok(_) => IdempotencyReservation::Created(request.operation_id),
            Err(sqlx::Error::Database(error)) if error.is_unique_violation() => {
                let row = sqlx::query("SELECT fingerprint, operation_id FROM idempotency_reservations WHERE owner_scope=$1 AND action=$2 AND idempotency_key=$3")
                    .bind(&request.owner_scope).bind(&request.action).bind(&request.key).fetch_one(&mut *tx).await.map_err(StoreError::Database)?;
                let fingerprint: String =
                    row.try_get("fingerprint").map_err(StoreError::Database)?;
                let id = Uuid::parse_str(
                    &row.try_get::<String, _>("operation_id")
                        .map_err(StoreError::Database)?,
                )
                .map_err(StoreError::InvalidUuid)?;
                if fingerprint == request.fingerprint {
                    IdempotencyReservation::ExistingEquivalent(id)
                } else {
                    IdempotencyReservation::Conflict
                }
            }
            Err(error) => return Err(StoreError::Database(error)),
        };
        if operation_inserted
            && (matches!(outcome, IdempotencyReservation::Conflict)
                || matches!(outcome, IdempotencyReservation::ExistingEquivalent(id) if id != operation.id))
        {
            sqlx::query("DELETE FROM operations WHERE id=$1")
                .bind(operation.id.to_string())
                .execute(&mut *tx)
                .await
                .map_err(StoreError::Database)?;
        }
        if let IdempotencyReservation::ExistingEquivalent(id) = outcome {
            let exists = sqlx::query("SELECT 1 FROM operations WHERE id=$1")
                .bind(id.to_string())
                .fetch_optional(&mut *tx)
                .await
                .map_err(StoreError::Database)?
                .is_some();
            if !exists {
                return Err(StoreError::Corrupt(
                    "idempotency reservation references missing operation".into(),
                ));
            }
        }
        tx.commit().await.map_err(StoreError::Database)?;
        Ok(outcome)
    }

    async fn create_or_replay_canonical_idempotent_operation(
        &self,
        operation: &OperationRecord,
        canonical: &CanonicalOperationRecord,
        request: &IdempotencyReservationRequest,
    ) -> Result<IdempotencyReservation, StoreError> {
        if request.key.is_empty()
            || request.key.len() > IdempotencyReservationRequest::MAX_KEY_LENGTH
        {
            return Err(StoreError::Corrupt(
                "invalid idempotency key byte length".into(),
            ));
        }
        validate_canonical_idempotent_operation_identity(operation, canonical, request)?;
        let attempt = i32::try_from(canonical.attempt)
            .map_err(|_| StoreError::Corrupt("operation attempt exceeds storage range".into()))?;
        let mut tx = self.pool.begin().await.map_err(StoreError::Database)?;

        // Resolve an accepted request before inspecting the caller's new
        // proposal. A retry is identified by its scoped idempotency identity;
        // it must not depend on a newly proposed resource still existing.
        if let Some(reservation) = sqlx::query(
            "SELECT fingerprint, operation_id FROM idempotency_reservations
             WHERE owner_scope=$1 AND action=$2 AND idempotency_key=$3",
        )
        .bind(&request.owner_scope)
        .bind(&request.action)
        .bind(&request.key)
        .fetch_optional(&mut *tx)
        .await
        .map_err(StoreError::Database)?
        {
            let fingerprint: String = reservation
                .try_get("fingerprint")
                .map_err(StoreError::Database)?;
            if fingerprint != request.fingerprint {
                tx.commit().await.map_err(StoreError::Database)?;
                return Ok(IdempotencyReservation::Conflict);
            }
            let winning_id = Uuid::parse_str(
                &reservation
                    .try_get::<String, _>("operation_id")
                    .map_err(StoreError::Database)?,
            )
            .map_err(StoreError::InvalidUuid)?;
            validate_existing_canonical_reservation(&mut tx, winning_id, request).await?;
            tx.commit().await.map_err(StoreError::Database)?;
            return Ok(IdempotencyReservation::ExistingEquivalent(winning_id));
        }

        let resource_owner = sqlx::query("SELECT project_id FROM resources WHERE id=$1")
            .bind(operation.resource_id.to_string())
            .fetch_optional(&mut *tx)
            .await
            .map_err(StoreError::Database)?
            .ok_or(StoreError::ResourceNotFound)?
            .try_get::<String, _>("project_id")
            .map_err(StoreError::Database)?;
        if resource_owner != request.owner_scope {
            return Err(StoreError::Corrupt(
                "operation resource and canonical owner scopes differ".into(),
            ));
        }

        let operation_inserted = sqlx::query(
            "INSERT INTO operations
             (id, resource_id, kind, state, provider_operation_id, error_category, error_message)
             VALUES ($1,$2,$3,$4,$5,$6,$7)
             ON CONFLICT (id) DO NOTHING
             RETURNING id",
        )
        .bind(operation.id.to_string())
        .bind(operation.resource_id.to_string())
        .bind(&operation.kind)
        .bind(operation.state.as_str())
        .bind(&operation.provider_operation_id)
        .bind(&operation.error_category)
        .bind(&operation.error_message)
        .fetch_optional(&mut *tx)
        .await
        .map_err(StoreError::Database)?
        .is_some();

        if operation_inserted {
            sqlx::query(
                "INSERT INTO canonical_operation_metadata
                 (operation_id,service,action,actor,owner_scope,resource_type,resource_id,attempt,
                  created_at,started_at,finished_at,error,request_id)
                 VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11,$12,$13)",
            )
            .bind(canonical.id.to_string())
            .bind(&canonical.service)
            .bind(&canonical.action)
            .bind(&canonical.actor)
            .bind(&canonical.owner_scope)
            .bind(&canonical.resource_type)
            .bind(&canonical.resource_id)
            .bind(attempt)
            .bind(&canonical.created_at)
            .bind(&canonical.started_at)
            .bind(&canonical.finished_at)
            .bind(&canonical.error)
            .bind(&canonical.request_id)
            .execute(&mut *tx)
            .await
            .map_err(map_pg_error)?;
        }

        let reservation_inserted = sqlx::query(
            "INSERT INTO idempotency_reservations
             (owner_scope, action, idempotency_key, fingerprint, operation_id)
             VALUES ($1,$2,$3,$4,$5)
             ON CONFLICT (owner_scope, action, idempotency_key) DO NOTHING
             RETURNING operation_id",
        )
        .bind(&request.owner_scope)
        .bind(&request.action)
        .bind(&request.key)
        .bind(&request.fingerprint)
        .bind(request.operation_id.to_string())
        .fetch_optional(&mut *tx)
        .await
        .map_err(StoreError::Database)?
        .is_some();

        if reservation_inserted {
            if !operation_inserted {
                return Err(StoreError::Corrupt(
                    "new idempotency reservation references a pre-existing operation".into(),
                ));
            }
            tx.commit().await.map_err(StoreError::Database)?;
            return Ok(IdempotencyReservation::Created(operation.id));
        }

        if operation_inserted {
            // The competing reservation won. Removing the losing operation
            // cascades to its canonical metadata inside this transaction.
            sqlx::query("DELETE FROM operations WHERE id=$1")
                .bind(operation.id.to_string())
                .execute(&mut *tx)
                .await
                .map_err(StoreError::Database)?;
        }

        let reservation = sqlx::query(
            "SELECT fingerprint, operation_id FROM idempotency_reservations
             WHERE owner_scope=$1 AND action=$2 AND idempotency_key=$3",
        )
        .bind(&request.owner_scope)
        .bind(&request.action)
        .bind(&request.key)
        .fetch_one(&mut *tx)
        .await
        .map_err(StoreError::Database)?;
        let fingerprint: String = reservation
            .try_get("fingerprint")
            .map_err(StoreError::Database)?;
        if fingerprint != request.fingerprint {
            tx.commit().await.map_err(StoreError::Database)?;
            return Ok(IdempotencyReservation::Conflict);
        }
        let winning_id = Uuid::parse_str(
            &reservation
                .try_get::<String, _>("operation_id")
                .map_err(StoreError::Database)?,
        )
        .map_err(StoreError::InvalidUuid)?;

        validate_existing_canonical_reservation(&mut tx, winning_id, request).await?;
        tx.commit().await.map_err(StoreError::Database)?;
        Ok(IdempotencyReservation::ExistingEquivalent(winning_id))
    }

    async fn create_or_replay_canonical_scoped_operation(
        &self,
        operation: &OperationRecord,
        canonical: &CanonicalOperationRecord,
        request: &IdempotencyReservationRequest,
    ) -> Result<IdempotencyReservation, StoreError> {
        if operation.id != request.operation_id {
            return Err(StoreError::Corrupt(
                "operation and idempotency identities differ".into(),
            ));
        }
        crate::validate_canonical_idempotent_operation_identity(operation, canonical, request)?;
        let mut tx = self.pool.begin().await.map_err(StoreError::Database)?;
        sqlx::query("SELECT pg_advisory_xact_lock(hashtextextended($1,0))")
            .bind(format!(
                "{}\n{}\n{}",
                request.owner_scope, request.action, request.key
            ))
            .execute(&mut *tx)
            .await
            .map_err(StoreError::Database)?;
        if let Some(row) = sqlx::query("SELECT fingerprint, operation_id FROM idempotency_reservations WHERE owner_scope=$1 AND action=$2 AND idempotency_key=$3")
            .bind(&request.owner_scope).bind(&request.action).bind(&request.key)
            .fetch_optional(&mut *tx).await.map_err(StoreError::Database)?
        {
            let fingerprint: String = row.try_get("fingerprint").map_err(StoreError::Database)?;
            let existing = Uuid::parse_str(&row.try_get::<String, _>("operation_id").map_err(StoreError::Database)?)
                .map_err(StoreError::InvalidUuid)?;
            if fingerprint != request.fingerprint {
                tx.commit().await.map_err(StoreError::Database)?;
                return Ok(IdempotencyReservation::Conflict);
            }
            let op = sqlx::query("SELECT resource_id FROM operations WHERE id=$1")
                .bind(existing.to_string()).fetch_one(&mut *tx).await.map_err(StoreError::Database)?;
            let metadata = sqlx::query("SELECT owner_scope, action, resource_id FROM canonical_operation_metadata WHERE operation_id=$1")
                .bind(existing.to_string()).fetch_one(&mut *tx).await.map_err(StoreError::Database)?;
            if op.get::<String, _>("resource_id") != operation.resource_id.to_string()
                || metadata.get::<String, _>("owner_scope") != request.owner_scope
                || metadata.get::<String, _>("action") != request.action
                || metadata.get::<Option<String>, _>("resource_id") != Some(operation.resource_id.to_string())
            {
                return Err(StoreError::Corrupt("canonical scoped operation replay identity differs".into()));
            }
            tx.commit().await.map_err(StoreError::Database)?;
            return Ok(IdempotencyReservation::ExistingEquivalent(existing));
        }
        let owner_scope: Option<String> = match canonical.resource_type.as_str() {
            "network:network" => {
                sqlx::query_scalar("SELECT project_id FROM canonical_networks WHERE id=$1")
                    .bind(operation.resource_id.to_string())
                    .fetch_optional(&mut *tx)
                    .await
                    .map_err(StoreError::Database)?
            }
            "network:address_realm" => {
                sqlx::query_scalar("SELECT project_id FROM canonical_address_realms WHERE id=$1")
                    .bind(operation.resource_id.to_string())
                    .fetch_optional(&mut *tx)
                    .await
                    .map_err(StoreError::Database)?
            }
            _ => {
                return Err(StoreError::Corrupt(
                    "unsupported canonical scoped resource type".into(),
                ));
            }
        };
        if owner_scope.as_deref() != Some(canonical.owner_scope.as_str()) {
            return Err(StoreError::ResourceNotFound);
        }
        insert_postgres_canonical_acceptance(&mut tx, operation, canonical).await?;
        sqlx::query("INSERT INTO idempotency_reservations (owner_scope, action, idempotency_key, fingerprint, operation_id) VALUES ($1,$2,$3,$4,$5)")
            .bind(&request.owner_scope).bind(&request.action).bind(&request.key)
            .bind(&request.fingerprint).bind(request.operation_id.to_string())
            .execute(&mut *tx).await.map_err(map_pg_error)?;
        tx.commit().await.map_err(StoreError::Database)?;
        Ok(IdempotencyReservation::Created(operation.id))
    }

    async fn create_or_replay_canonical_resource_operation(
        &self,
        resource: &ResourceRecord,
        operation: &OperationRecord,
        canonical: &CanonicalOperationRecord,
        request: &IdempotencyReservationRequest,
        expected_placement_allocation_id: Option<&str>,
    ) -> Result<crate::CanonicalAcceptanceOutcome, StoreError> {
        crate::validate_canonical_resource_acceptance(resource, operation, canonical, request)?;
        if let Some(outcome) = postgres_existing_acceptance(&self.pool, request).await? {
            return Ok(outcome);
        }
        let mut tx = self.pool.begin().await.map_err(StoreError::Database)?;
        let lock_identity = format!(
            "{}\n{}\n{}",
            request.owner_scope, request.action, request.key
        );
        sqlx::query("SELECT pg_advisory_xact_lock(hashtextextended($1,0))")
            .bind(lock_identity)
            .execute(&mut *tx)
            .await
            .map_err(StoreError::Database)?;
        if let Some(outcome) = postgres_existing_acceptance_tx(&mut tx, request).await? {
            tx.commit().await.map_err(StoreError::Database)?;
            return Ok(outcome);
        }
        if let Some(allocation_id) = expected_placement_allocation_id
            && sqlx::query("SELECT 1 FROM placement_allocations WHERE id=$1 FOR SHARE")
                .bind(allocation_id)
                .fetch_optional(&mut *tx)
                .await
                .map_err(StoreError::Database)?
                .is_none()
        {
            return Err(StoreError::PlacementAllocationNotFound);
        }
        sqlx::query("INSERT INTO resources (id,kind,project_id,generation,observed_generation,desired_state,observed_state,provider_id) VALUES ($1,$2,$3,$4,$5,$6,$7,$8)")
            .bind(resource.id.to_string()).bind(&resource.kind).bind(&resource.project_id).bind(resource.generation)
            .bind(resource.observed_generation).bind(&resource.desired_state).bind(&resource.observed_state).bind(&resource.provider_id)
            .execute(&mut *tx).await.map_err(map_pg_error)?;
        insert_postgres_canonical_acceptance(&mut tx, operation, canonical).await?;
        let inserted = sqlx::query("INSERT INTO idempotency_reservations (owner_scope,action,idempotency_key,fingerprint,operation_id) VALUES ($1,$2,$3,$4,$5) ON CONFLICT (owner_scope,action,idempotency_key) DO NOTHING RETURNING operation_id")
            .bind(&request.owner_scope).bind(&request.action).bind(&request.key).bind(&request.fingerprint)
            .bind(request.operation_id.to_string()).fetch_optional(&mut *tx).await.map_err(StoreError::Database)?.is_some();
        if !inserted {
            tx.rollback().await.map_err(StoreError::Database)?;
            return postgres_existing_acceptance(&self.pool, request)
                .await?
                .ok_or(StoreError::IdempotencyConflict);
        }
        tx.commit().await.map_err(StoreError::Database)?;
        Ok(crate::CanonicalAcceptanceOutcome::Created {
            operation_id: operation.id,
            resource_id: resource.id,
        })
    }

    async fn create_or_replay_canonical_lifecycle_operation(
        &self,
        operation: &OperationRecord,
        canonical: &CanonicalOperationRecord,
        request: &IdempotencyReservationRequest,
    ) -> Result<crate::CanonicalAcceptanceOutcome, StoreError> {
        if let Some(outcome) = postgres_existing_acceptance(&self.pool, request).await? {
            return Ok(outcome);
        }
        let mut tx = self.pool.begin().await.map_err(StoreError::Database)?;
        let lock_identity = format!(
            "{}\n{}\n{}",
            request.owner_scope, request.action, request.key
        );
        sqlx::query("SELECT pg_advisory_xact_lock(hashtextextended($1,0))")
            .bind(lock_identity)
            .execute(&mut *tx)
            .await
            .map_err(StoreError::Database)?;
        if let Some(outcome) = postgres_existing_acceptance_tx(&mut tx, request).await? {
            tx.commit().await.map_err(StoreError::Database)?;
            return Ok(outcome);
        }
        let row = sqlx::query("SELECT * FROM resources WHERE id=$1 FOR SHARE")
            .bind(operation.resource_id.to_string())
            .fetch_optional(&mut *tx)
            .await
            .map_err(StoreError::Database)?
            .ok_or(StoreError::ResourceNotFound)?;
        let resource = row_to_resource(&row)?;
        crate::validate_canonical_resource_acceptance(&resource, operation, canonical, request)?;
        insert_postgres_canonical_acceptance(&mut tx, operation, canonical).await?;
        let inserted = sqlx::query("INSERT INTO idempotency_reservations (owner_scope,action,idempotency_key,fingerprint,operation_id) VALUES ($1,$2,$3,$4,$5) ON CONFLICT (owner_scope,action,idempotency_key) DO NOTHING RETURNING operation_id")
            .bind(&request.owner_scope).bind(&request.action).bind(&request.key).bind(&request.fingerprint)
            .bind(request.operation_id.to_string()).fetch_optional(&mut *tx).await.map_err(StoreError::Database)?.is_some();
        if !inserted {
            tx.rollback().await.map_err(StoreError::Database)?;
            return postgres_existing_acceptance(&self.pool, request)
                .await?
                .ok_or(StoreError::IdempotencyConflict);
        }
        tx.commit().await.map_err(StoreError::Database)?;
        Ok(crate::CanonicalAcceptanceOutcome::Created {
            operation_id: operation.id,
            resource_id: operation.resource_id,
        })
    }

    async fn get_operation(&self, id: Uuid) -> Result<OperationRecord, StoreError> {
        let id_str = id.to_string();
        let row = sqlx::query("SELECT * FROM operations WHERE id = $1")
            .bind(&id_str)
            .fetch_optional(&self.pool)
            .await
            .map_err(StoreError::Database)?;

        match row {
            Some(row) => row_to_operation(&row),
            None => Err(StoreError::OperationNotFound),
        }
    }

    async fn get_canonical_operation(
        &self,
        id: Uuid,
    ) -> Result<CanonicalOperationRecord, StoreError> {
        let row = sqlx::query("SELECT * FROM canonical_operation_metadata WHERE operation_id=$1")
            .bind(id.to_string())
            .fetch_optional(&self.pool)
            .await
            .map_err(StoreError::Database)?
            .ok_or(StoreError::OperationNotFound)?;
        let operation = self.get_operation(id).await?;
        let canonical = CanonicalOperationRecord {
            id,
            service: row.try_get("service").map_err(StoreError::Database)?,
            action: row.try_get("action").map_err(StoreError::Database)?,
            actor: row.try_get("actor").map_err(StoreError::Database)?,
            owner_scope: row.try_get("owner_scope").map_err(StoreError::Database)?,
            resource_type: row.try_get("resource_type").map_err(StoreError::Database)?,
            resource_id: row.try_get("resource_id").map_err(StoreError::Database)?,
            state: operation.state,
            attempt: u32::try_from(
                row.try_get::<i32, _>("attempt")
                    .map_err(StoreError::Database)?,
            )
            .map_err(|_| StoreError::Corrupt("invalid operation attempt".into()))?,
            created_at: row.try_get("created_at").map_err(StoreError::Database)?,
            started_at: row.try_get("started_at").map_err(StoreError::Database)?,
            finished_at: row.try_get("finished_at").map_err(StoreError::Database)?,
            error: row.try_get("error").map_err(StoreError::Database)?,
            request_id: row.try_get("request_id").map_err(StoreError::Database)?,
        };
        match canonical.resource_type.as_str() {
            "network:network" => {
                let owner = sqlx::query_scalar::<_, String>(
                    "SELECT project_id FROM canonical_networks WHERE id = $1",
                )
                .bind(operation.resource_id.to_string())
                .fetch_optional(&self.pool)
                .await
                .map_err(StoreError::Database)?;
                if let Some(owner) = owner {
                    if owner != canonical.owner_scope {
                        return Err(StoreError::Corrupt(
                            "canonical network operation owner differs from network owner".into(),
                        ));
                    }
                } else if sqlx::query_scalar::<_, String>(
                    "SELECT project_id FROM canonical_address_realms WHERE id = $1",
                )
                .bind(operation.resource_id.to_string())
                .fetch_optional(&self.pool)
                .await
                .map_err(StoreError::Database)?
                .is_some()
                {
                    return Err(StoreError::Corrupt(
                        "canonical network operation references an address realm".into(),
                    ));
                }
            }
            "network:address_realm" => {
                let owner = sqlx::query_scalar::<_, String>(
                    "SELECT project_id FROM canonical_address_realms WHERE id = $1",
                )
                .bind(operation.resource_id.to_string())
                .fetch_optional(&self.pool)
                .await
                .map_err(StoreError::Database)?;
                if let Some(owner) = owner {
                    if owner != canonical.owner_scope {
                        return Err(StoreError::Corrupt(
                            "canonical address realm operation owner differs from realm owner"
                                .into(),
                        ));
                    }
                } else if sqlx::query_scalar::<_, String>(
                    "SELECT project_id FROM canonical_networks WHERE id = $1",
                )
                .bind(operation.resource_id.to_string())
                .fetch_optional(&self.pool)
                .await
                .map_err(StoreError::Database)?
                .is_some()
                {
                    return Err(StoreError::Corrupt(
                        "canonical address realm operation references a network".into(),
                    ));
                }
            }
            _ => {}
        }
        match self.get_resource(operation.resource_id).await {
            Ok(resource) => {
                crate::validate_canonical_operation_read(&operation, &canonical, &resource)?
            }
            Err(StoreError::ResourceNotFound) => {
                crate::validate_canonical_scoped_operation_read(&operation, &canonical)?;
            }
            Err(error) => return Err(error),
        }
        Ok(canonical)
    }

    async fn update_operation(
        &self,
        id: Uuid,
        state: OperationState,
        provider_operation_id: Option<&str>,
        error_category: Option<&str>,
        error_message: Option<&str>,
    ) -> Result<OperationRecord, StoreError> {
        let id_str = id.to_string();
        let mut tx = self.pool.begin().await.map_err(StoreError::Database)?;

        let row = sqlx::query(
            "SELECT id, resource_id, kind, state, provider_operation_id, error_category, error_message FROM operations WHERE id = $1 FOR UPDATE",
        )
        .bind(&id_str)
        .fetch_optional(&mut *tx)
        .await
        .map_err(StoreError::Database)?
        .ok_or(StoreError::OperationNotFound)?;

        let current = row_to_operation(&row)?;
        if matches!(
            current.state,
            OperationState::Succeeded | OperationState::Failed
        ) {
            if current
                .provider_operation_id
                .as_deref()
                .is_some_and(|existing| {
                    provider_operation_id.is_some_and(|incoming| incoming != existing)
                })
            {
                return Err(StoreError::Corrupt(
                    "terminal operation provider identity conflicts with durable state".to_owned(),
                ));
            }
            if current.state != state {
                if matches!(state, OperationState::Succeeded | OperationState::Failed) {
                    return Err(StoreError::Corrupt(
                        "terminal operation state cannot conflict with durable state".to_owned(),
                    ));
                }
                return Ok(current);
            }

            sqlx::query("UPDATE operations SET provider_operation_id = COALESCE($1, provider_operation_id), error_category = COALESCE($2, error_category), error_message = COALESCE($3, error_message) WHERE id = $4")
                .bind(provider_operation_id)
                .bind(error_category)
                .bind(error_message)
                .bind(&id_str)
                .execute(&mut *tx)
                .await
                .map_err(StoreError::Database)?;

            tx.commit().await.map_err(StoreError::Database)?;
            return self.get_operation(id).await;
        }

        sqlx::query("UPDATE operations SET state = $1, provider_operation_id = $2, error_category = $3, error_message = $4 WHERE id = $5")
            .bind(state.as_str())
            .bind(provider_operation_id)
            .bind(error_category)
            .bind(error_message)
            .bind(&id_str)
            .execute(&mut *tx)
            .await
            .map_err(StoreError::Database)?;
        let now = chrono::Utc::now().to_rfc3339();
        let started_at = (!matches!(state, OperationState::Pending)).then_some(now.clone());
        let finished_at =
            matches!(state, OperationState::Succeeded | OperationState::Failed).then_some(now);
        sqlx::query("UPDATE canonical_operation_metadata SET started_at=COALESCE(started_at,$1), finished_at=$2, error=$3 WHERE operation_id=$4")
            .bind(started_at).bind(finished_at).bind(error_category).bind(&id_str)
            .execute(&mut *tx).await.map_err(StoreError::Database)?;

        tx.commit().await.map_err(StoreError::Database)?;
        self.get_operation(id).await
    }

    async fn update_canonical_operation_lifecycle(
        &self,
        id: Uuid,
        update: &crate::CanonicalOperationLifecycleUpdate,
    ) -> Result<CanonicalOperationRecord, StoreError> {
        crate::validate_canonical_lifecycle_update(update)?;
        let attempt = i32::try_from(update.attempt).map_err(|_| {
            StoreError::Corrupt("canonical operation attempt exceeds PostgreSQL INT4".into())
        })?;
        let id_str = id.to_string();
        let mut tx = self.pool.begin().await.map_err(StoreError::Database)?;
        let exists = sqlx::query("SELECT state FROM operations WHERE id = $1 FOR UPDATE")
            .bind(&id_str)
            .fetch_optional(&mut *tx)
            .await
            .map_err(StoreError::Database)?
            .ok_or(StoreError::OperationNotFound)?;
        let current: String = exists.try_get("state").map_err(StoreError::Database)?;
        if (current == OperationState::Succeeded.as_str()
            && update.state != OperationState::Succeeded)
            || (current == OperationState::Failed.as_str()
                && update.state != OperationState::Failed)
        {
            return Err(StoreError::Corrupt(
                "terminal operation state cannot regress".into(),
            ));
        }
        let metadata = sqlx::query("SELECT operation_id FROM canonical_operation_metadata WHERE operation_id = $1 FOR UPDATE")
            .bind(&id_str).fetch_optional(&mut *tx).await.map_err(StoreError::Database)?
            .ok_or_else(|| StoreError::Corrupt("canonical lifecycle metadata is missing".into()))?;
        let _ = metadata;
        sqlx::query("UPDATE operations SET state = $1 WHERE id = $2")
            .bind(update.state.as_str())
            .bind(&id_str)
            .execute(&mut *tx)
            .await
            .map_err(StoreError::Database)?;
        sqlx::query("UPDATE canonical_operation_metadata SET attempt = $1, started_at = $2, finished_at = $3, error = $4 WHERE operation_id = $5")
            .bind(attempt).bind(&update.started_at).bind(&update.finished_at).bind(&update.public_error).bind(&id_str)
            .execute(&mut *tx).await.map_err(StoreError::Database)?;
        tx.commit().await.map_err(StoreError::Database)?;
        self.get_canonical_operation(id).await
    }

    async fn list_non_terminal_lifecycle_operations(
        &self,
    ) -> Result<Vec<OperationRecord>, StoreError> {
        let rows = sqlx::query(
            "SELECT * FROM operations
             WHERE kind LIKE 'lifecycle:%' AND state NOT IN ('succeeded', 'failed')
             ORDER BY created_at ASC",
        )
        .fetch_all(&self.pool)
        .await
        .map_err(StoreError::Database)?;

        rows.iter().map(row_to_operation).collect()
    }

    async fn attach_provider_reference(
        &self,
        reference: &ProviderReference,
    ) -> Result<(), StoreError> {
        let resource_id_str = reference.resource_id.to_string();
        let res = sqlx::query(
            "INSERT INTO provider_refs (resource_id, provider_name, provider_resource_id)
             VALUES ($1, $2, $3)",
        )
        .bind(&resource_id_str)
        .bind(&reference.provider_name)
        .bind(&reference.provider_resource_id)
        .execute(&self.pool)
        .await;

        match res {
            Ok(_) => Ok(()),
            Err(sqlx::Error::Database(err)) if err.code().as_deref() == Some("23505") => {
                Err(StoreError::ProviderReferenceAlreadyExists)
            }
            Err(err) => Err(StoreError::Database(err)),
        }
    }

    async fn list_canonical_operations_page(
        &self,
        owner_scope: &str,
        after_id: Option<Uuid>,
        limit: u32,
    ) -> Result<Vec<CanonicalOperationRecord>, StoreError> {
        let rows = sqlx::query("SELECT m.*, o.state FROM canonical_operation_metadata m JOIN operations o ON o.id=m.operation_id WHERE m.owner_scope=$1 AND ($2::text IS NULL OR m.operation_id>$2) ORDER BY m.operation_id LIMIT $3")
            .bind(owner_scope).bind(after_id.map(|id| id.to_string())).bind(i64::from(limit)).fetch_all(&self.pool).await.map_err(StoreError::Database)?;
        rows.into_iter()
            .map(|row| {
                Ok(CanonicalOperationRecord {
                    id: Uuid::parse_str(
                        &row.try_get::<String, _>("operation_id")
                            .map_err(StoreError::Database)?,
                    )
                    .map_err(StoreError::InvalidUuid)?,
                    service: row.try_get("service").map_err(StoreError::Database)?,
                    action: row.try_get("action").map_err(StoreError::Database)?,
                    actor: row.try_get("actor").map_err(StoreError::Database)?,
                    owner_scope: row.try_get("owner_scope").map_err(StoreError::Database)?,
                    resource_type: row.try_get("resource_type").map_err(StoreError::Database)?,
                    resource_id: row.try_get("resource_id").map_err(StoreError::Database)?,
                    state: OperationState::parse(
                        &row.try_get::<String, _>("state")
                            .map_err(StoreError::Database)?,
                    )?,
                    attempt: u32::try_from(
                        row.try_get::<i32, _>("attempt")
                            .map_err(StoreError::Database)?,
                    )
                    .map_err(|_| StoreError::Corrupt("invalid operation attempt".into()))?,
                    created_at: row.try_get("created_at").map_err(StoreError::Database)?,
                    started_at: row.try_get("started_at").map_err(StoreError::Database)?,
                    finished_at: row.try_get("finished_at").map_err(StoreError::Database)?,
                    error: row.try_get("error").map_err(StoreError::Database)?,
                    request_id: row.try_get("request_id").map_err(StoreError::Database)?,
                })
            })
            .collect()
    }

    async fn get_provider_reference(
        &self,
        resource_id: Uuid,
        provider_name: &str,
    ) -> Result<ProviderReference, StoreError> {
        let resource_id_str = resource_id.to_string();
        let row = sqlx::query(
            "SELECT * FROM provider_refs WHERE resource_id = $1 AND provider_name = $2",
        )
        .bind(&resource_id_str)
        .bind(provider_name)
        .fetch_optional(&self.pool)
        .await
        .map_err(StoreError::Database)?;

        match row {
            Some(row) => Ok(ProviderReference {
                resource_id,
                provider_name: row.get("provider_name"),
                provider_resource_id: row.get("provider_resource_id"),
            }),
            None => Err(StoreError::ProviderReferenceNotFound),
        }
    }

    async fn insert_agent_command(
        &self,
        command: &AgentCommandRecord,
    ) -> Result<AgentCommandRecord, StoreError> {
        let operation_id_str = command.operation_id.to_string();
        let resource_id_str = command.resource_id.to_string();
        sqlx::query(
            "INSERT INTO agent_commands (command_id, idempotency_key, operation_id, resource_id, agent_id, agent_epoch, payload_fingerprint_sha256, payload, state, accepted_sequence, last_sequence, provider_operation_id, provider_resource_id, created_at, updated_at)
             VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11, $12, $13, CURRENT_TIMESTAMP, CURRENT_TIMESTAMP)",
        )
        .bind(&command.command_id)
        .bind(&command.idempotency_key)
        .bind(&operation_id_str)
        .bind(&resource_id_str)
        .bind(&command.agent_id)
        .bind(&command.agent_epoch)
        .bind(&command.payload_fingerprint_sha256)
        .bind(&command.payload)
        .bind(command.state.as_str())
        .bind(command.accepted_sequence as i64)
        .bind(command.last_sequence as i64)
        .bind(&command.provider_operation_id)
        .bind(&command.provider_resource_id)
        .execute(&self.pool)
        .await
        .map_err(map_pg_error)?;

        self.get_agent_command(&command.command_id).await
    }

    async fn get_agent_command(&self, command_id: &str) -> Result<AgentCommandRecord, StoreError> {
        let row = sqlx::query("SELECT * FROM agent_commands WHERE command_id = $1")
            .bind(command_id)
            .fetch_optional(&self.pool)
            .await
            .map_err(StoreError::Database)?;

        match row {
            Some(row) => {
                let op_id_str: String = row.get("operation_id");
                let op_id = parse_uuid(&op_id_str)?;
                let res_id_str: String = row.get("resource_id");
                let res_id = parse_uuid(&res_id_str)?;
                let state_str: String = row.get("state");
                let state = AgentCommandState::parse(&state_str)?;
                let acc_seq: i64 = row.get("accepted_sequence");
                let last_seq: i64 = row.get("last_sequence");

                Ok(AgentCommandRecord {
                    command_id: row.get("command_id"),
                    idempotency_key: row.get("idempotency_key"),
                    operation_id: op_id,
                    resource_id: res_id,
                    agent_id: row.get("agent_id"),
                    agent_epoch: row.get("agent_epoch"),
                    payload_fingerprint_sha256: row.get("payload_fingerprint_sha256"),
                    payload: row.get("payload"),
                    state,
                    accepted_sequence: acc_seq as u64,
                    last_sequence: last_seq as u64,
                    provider_operation_id: row.get("provider_operation_id"),
                    provider_resource_id: row.get("provider_resource_id"),
                })
            }
            None => Err(StoreError::Corrupt(format!(
                "agent command `{command_id}` not found"
            ))),
        }
    }

    async fn get_agent_command_by_idempotency_key(
        &self,
        idempotency_key: &str,
    ) -> Result<AgentCommandRecord, StoreError> {
        let row = sqlx::query("SELECT command_id FROM agent_commands WHERE idempotency_key = $1")
            .bind(idempotency_key)
            .fetch_optional(&self.pool)
            .await
            .map_err(StoreError::Database)?;

        match row {
            Some(row) => {
                let id: String = row.get("command_id");
                self.get_agent_command(&id).await
            }
            None => Err(StoreError::OperationNotFound),
        }
    }

    async fn get_agent_command_by_operation(
        &self,
        operation_id: Uuid,
    ) -> Result<AgentCommandRecord, StoreError> {
        let op_str = operation_id.to_string();
        let row = sqlx::query("SELECT command_id FROM agent_commands WHERE operation_id = $1")
            .bind(&op_str)
            .fetch_optional(&self.pool)
            .await
            .map_err(StoreError::Database)?;

        match row {
            Some(row) => {
                let id: String = row.get("command_id");
                self.get_agent_command(&id).await
            }
            None => Err(StoreError::OperationNotFound),
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
        let res = sqlx::query(
            "UPDATE agent_commands
             SET state = $1, accepted_sequence = $2, last_sequence = $3,
                 provider_operation_id = COALESCE($4, provider_operation_id),
                 provider_resource_id = COALESCE($5, provider_resource_id),
                 updated_at = CURRENT_TIMESTAMP
             WHERE command_id = $6",
        )
        .bind(state.as_str())
        .bind(accepted_sequence as i64)
        .bind(last_sequence as i64)
        .bind(provider_operation_id)
        .bind(provider_resource_id)
        .bind(command_id)
        .execute(&self.pool)
        .await
        .map_err(StoreError::Database)?;

        if res.rows_affected() == 0 {
            return Err(StoreError::Corrupt(format!(
                "agent command `{command_id}` not found"
            )));
        }

        self.get_agent_command(command_id).await
    }

    async fn list_recoverable_agent_commands(&self) -> Result<Vec<AgentCommandRecord>, StoreError> {
        let rows = sqlx::query(
            "SELECT command_id FROM agent_commands
            WHERE state IN ('pending', 'accepted', 'running', 'retryable', 'unknown_outcome')
             ORDER BY created_at ASC",
        )
        .fetch_all(&self.pool)
        .await
        .map_err(StoreError::Database)?;

        let mut commands = Vec::with_capacity(rows.len());
        for row in rows {
            let id: String = row.get("command_id");
            commands.push(self.get_agent_command(&id).await?);
        }
        Ok(commands)
    }

    async fn insert_artifact_transfer(
        &self,
        transfer: &ArtifactTransferRecord,
    ) -> Result<ArtifactTransferRecord, StoreError> {
        transfer.validate()?;
        let res_id_str = transfer.resource_id.to_string();
        let op_id_str = transfer.operation_id.to_string();

        let result = sqlx::query(
            "INSERT INTO artifact_transfers (transfer_id, command_id, operation_id, resource_id, agent_id, agent_epoch, artifact_id, artifact_kind, sha256, size_bytes, expires_at_unix_ms, format, chunk_size_bytes, chunk_count, state, contiguous_bytes, next_chunk_index, retry_count, created_at, updated_at)
             VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11, $12, $13, $14, $15, $16, $17, $18, CURRENT_TIMESTAMP, CURRENT_TIMESTAMP)",
        )
        .bind(&transfer.transfer_id)
        .bind(&transfer.command_id)
        .bind(&op_id_str)
        .bind(&res_id_str)
        .bind(&transfer.agent_id)
        .bind(&transfer.agent_epoch)
        .bind(&transfer.artifact_id)
        .bind(&transfer.artifact_kind)
        .bind(&transfer.sha256)
        .bind(transfer.size_bytes as i64)
        .bind(transfer.expires_at_unix_ms)
        .bind(&transfer.format)
        .bind(transfer.chunk_size_bytes as i64)
        .bind(transfer.chunk_count as i64)
        .bind(transfer.state.as_str())
        .bind(transfer.contiguous_bytes as i64)
        .bind(transfer.next_chunk_index as i64)
        .bind(transfer.retry_count as i32)
        .execute(&self.pool)
        .await;

        match result {
            Ok(_) => self.get_artifact_transfer(&transfer.transfer_id).await,
            Err(sqlx::Error::Database(err)) if err.code().as_deref() == Some("23505") => {
                let existing = self.get_artifact_transfer(&transfer.transfer_id).await?;
                if existing.transfer_id == transfer.transfer_id
                    && existing.command_id == transfer.command_id
                    && existing.operation_id == transfer.operation_id
                    && existing.resource_id == transfer.resource_id
                    && existing.agent_id == transfer.agent_id
                    && existing.agent_epoch == transfer.agent_epoch
                    && existing.artifact_id == transfer.artifact_id
                    && existing.artifact_kind == transfer.artifact_kind
                    && existing.sha256 == transfer.sha256
                    && existing.size_bytes == transfer.size_bytes
                    && existing.expires_at_unix_ms == transfer.expires_at_unix_ms
                    && existing.format == transfer.format
                    && existing.chunk_size_bytes == transfer.chunk_size_bytes
                    && existing.chunk_count == transfer.chunk_count
                {
                    Ok(existing)
                } else {
                    Err(StoreError::ArtifactTransferConflict(
                        "transfer identity conflicts with durable state".to_owned(),
                    ))
                }
            }
            Err(err) => Err(StoreError::Database(err)),
        }
    }

    async fn get_artifact_transfer(
        &self,
        transfer_id: &str,
    ) -> Result<ArtifactTransferRecord, StoreError> {
        let row = sqlx::query("SELECT transfer_id, command_id, operation_id, resource_id, agent_id, agent_epoch, artifact_id, artifact_kind, sha256, size_bytes, expires_at_unix_ms, format, chunk_size_bytes, chunk_count, state, contiguous_bytes, next_chunk_index, retry_count, created_at, updated_at FROM artifact_transfers WHERE transfer_id = $1")
            .bind(transfer_id)
            .fetch_optional(&self.pool)
            .await
            .map_err(StoreError::Database)?
            .ok_or(StoreError::ArtifactTransferNotFound)?;

        let op_id_str: String = row.get("operation_id");
        let res_id_str: String = row.get("resource_id");
        let state_str: String = row.get("state");
        let retry_count: i32 = row.get("retry_count");

        let rec = ArtifactTransferRecord {
            transfer_id: row.get("transfer_id"),
            command_id: row.get("command_id"),
            operation_id: parse_uuid(&op_id_str)?,
            resource_id: parse_uuid(&res_id_str)?,
            agent_id: row.get("agent_id"),
            agent_epoch: row.get("agent_epoch"),
            artifact_id: row.get("artifact_id"),
            artifact_kind: row.get("artifact_kind"),
            sha256: row.get("sha256"),
            size_bytes: row.get::<i64, _>("size_bytes") as u64,
            expires_at_unix_ms: row.get::<Option<i64>, _>("expires_at_unix_ms").ok_or_else(
                || StoreError::Corrupt("artifact transfer expiry is missing".to_owned()),
            )?,
            format: row.get("format"),
            chunk_size_bytes: row.get::<i64, _>("chunk_size_bytes") as u64,
            chunk_count: row.get::<i64, _>("chunk_count") as u64,
            state: ArtifactTransferState::parse(&state_str)?,
            contiguous_bytes: row.get::<i64, _>("contiguous_bytes") as u64,
            next_chunk_index: row.get::<i64, _>("next_chunk_index") as u64,
            retry_count: retry_count as u8,
            created_at: row.get("created_at"),
            updated_at: row.get("updated_at"),
        };
        rec.validate()?;
        Ok(rec)
    }

    async fn rebind_artifact_transfer_epoch(
        &self,
        transfer_id: &str,
        expected_agent_epoch: &str,
        new_agent_epoch: &str,
    ) -> Result<ArtifactTransferRecord, StoreError> {
        if expected_agent_epoch == new_agent_epoch {
            return self.get_artifact_transfer(transfer_id).await;
        }

        let res = sqlx::query(
            "UPDATE artifact_transfers
             SET agent_epoch = $1, updated_at = CURRENT_TIMESTAMP
             WHERE transfer_id = $2 AND agent_epoch = $3 AND state IN ('offered', 'receiving')",
        )
        .bind(new_agent_epoch)
        .bind(transfer_id)
        .bind(expected_agent_epoch)
        .execute(&self.pool)
        .await
        .map_err(StoreError::Database)?;

        if res.rows_affected() != 1 {
            let current = self.get_artifact_transfer(transfer_id).await?;
            if current.agent_epoch != expected_agent_epoch {
                return Err(StoreError::ArtifactTransferEpochConflict);
            }
            return Err(StoreError::ArtifactTransferConflict(
                "terminal artifact transfer cannot be rebound".to_owned(),
            ));
        }

        self.get_artifact_transfer(transfer_id).await
    }

    async fn update_artifact_transfer(
        &self,
        transfer_id: &str,
        expected_agent_epoch: &str,
        update: ArtifactTransferUpdate,
    ) -> Result<ArtifactTransferRecord, StoreError> {
        let mut tx = self.pool.begin().await.map_err(StoreError::Database)?;

        let current = self.get_artifact_transfer(transfer_id).await?;
        if current.agent_epoch != expected_agent_epoch {
            return Err(StoreError::ArtifactTransferEpochConflict);
        }
        update.validate_against(&current)?;

        if update
            == (ArtifactTransferUpdate {
                state: current.state,
                contiguous_bytes: current.contiguous_bytes,
                next_chunk_index: current.next_chunk_index,
                retry_count: current.retry_count,
            })
        {
            return Ok(current);
        }

        let res = sqlx::query(
            "UPDATE artifact_transfers
             SET state = $1, contiguous_bytes = $2, next_chunk_index = $3, retry_count = $4, updated_at = CURRENT_TIMESTAMP
             WHERE transfer_id = $5 AND agent_epoch = $6",
        )
        .bind(update.state.as_str())
        .bind(update.contiguous_bytes as i64)
        .bind(update.next_chunk_index as i64)
        .bind(update.retry_count as i32)
        .bind(transfer_id)
        .bind(expected_agent_epoch)
        .execute(&mut *tx)
        .await
        .map_err(StoreError::Database)?;

        if res.rows_affected() != 1 {
            return Err(StoreError::ArtifactTransferEpochConflict);
        }

        tx.commit().await.map_err(StoreError::Database)?;
        self.get_artifact_transfer(transfer_id).await
    }

    async fn list_recoverable_artifact_transfers(
        &self,
    ) -> Result<Vec<ArtifactTransferRecord>, StoreError> {
        let rows = sqlx::query(
            "SELECT transfer_id FROM artifact_transfers
             WHERE state IN ('offered', 'receiving')
             ORDER BY created_at ASC",
        )
        .fetch_all(&self.pool)
        .await
        .map_err(StoreError::Database)?;

        let mut transfers = Vec::with_capacity(rows.len());
        for row in rows {
            let id: String = row.get("transfer_id");
            transfers.push(self.get_artifact_transfer(&id).await?);
        }
        Ok(transfers)
    }

    async fn expire_transfers_of_terminal_operations(&self) -> Result<u64, StoreError> {
        let res = sqlx::query(
            "UPDATE artifact_transfers
             SET state = 'expired', updated_at = CURRENT_TIMESTAMP
             WHERE state NOT IN ('committed', 'rejected', 'expired')
               AND operation_id IN (SELECT id FROM operations WHERE state IN ('succeeded', 'failed'))",
        )
        .execute(&self.pool)
        .await
        .map_err(StoreError::Database)?;

        Ok(res.rows_affected())
    }

    async fn insert_image_overlay(
        &self,
        overlay: &ImageOverlayOwnershipRecord,
    ) -> Result<ImageOverlayOwnershipRecord, StoreError> {
        let res_id_str = overlay.identity.resource_id.to_string();
        let op_id_str = overlay.identity.operation_id.to_string();

        let res = sqlx::query(
            "INSERT INTO image_overlay_ownership (overlay_id, resource_id, operation_id, command_id, agent_id, agent_epoch, base_sha256, base_format, overlay_format, state, created_at, updated_at)
             VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, CURRENT_TIMESTAMP, CURRENT_TIMESTAMP)",
        )
        .bind(&overlay.overlay_id)
        .bind(&res_id_str)
        .bind(&op_id_str)
        .bind(&overlay.identity.command_id)
        .bind(&overlay.identity.agent_id)
        .bind(&overlay.identity.agent_epoch)
        .bind(&overlay.identity.base_sha256)
        .bind(&overlay.identity.base_format)
        .bind(&overlay.identity.overlay_format)
        .bind(overlay.state.as_str())
        .execute(&self.pool)
        .await;

        match res {
            Ok(_) => self.get_image_overlay(&overlay.overlay_id).await,
            Err(sqlx::Error::Database(err)) if err.code().as_deref() == Some("23505") => {
                let existing = self.get_image_overlay(&overlay.overlay_id).await;
                match existing {
                    Ok(existing)
                        if existing.overlay_id == overlay.overlay_id
                            && existing.identity == overlay.identity =>
                    {
                        Ok(existing)
                    }
                    Ok(_) => Err(StoreError::ImageOverlayConflict(
                        "overlay identity conflicts with durable state".to_owned(),
                    )),
                    Err(StoreError::ImageOverlayNotFound) => {
                        let count: i64 = sqlx::query_scalar(
                            "SELECT COUNT(*) FROM image_overlay_ownership WHERE resource_id = $1 AND operation_id = $2 AND command_id = $3",
                        )
                        .bind(&res_id_str)
                        .bind(&op_id_str)
                        .bind(&overlay.identity.command_id)
                        .fetch_one(&self.pool)
                        .await
                        .map_err(StoreError::Database)?;
                        if count != 0 {
                            Err(StoreError::ImageOverlayConflict(
                                "resource operation already owns an overlay".to_owned(),
                            ))
                        } else {
                            Err(StoreError::ImageOverlayNotFound)
                        }
                    }
                    Err(e) => Err(e),
                }
            }
            Err(err) => Err(StoreError::Database(err)),
        }
    }

    async fn get_image_overlay(
        &self,
        overlay_id: &str,
    ) -> Result<ImageOverlayOwnershipRecord, StoreError> {
        let row = sqlx::query("SELECT overlay_id, resource_id, operation_id, command_id, agent_id, agent_epoch, base_sha256, base_format, overlay_format, state, created_at, updated_at FROM image_overlay_ownership WHERE overlay_id = $1")
            .bind(overlay_id)
            .fetch_optional(&self.pool)
            .await
            .map_err(StoreError::Database)?
            .ok_or(StoreError::ImageOverlayNotFound)?;

        let res_id_str: String = row.get("resource_id");
        let op_id_str: String = row.get("operation_id");
        let state_str: String = row.get("state");

        Ok(ImageOverlayOwnershipRecord {
            overlay_id: row.get("overlay_id"),
            identity: ImageOverlayIdentity {
                resource_id: parse_uuid(&res_id_str)?,
                operation_id: parse_uuid(&op_id_str)?,
                command_id: row.get("command_id"),
                agent_id: row.get("agent_id"),
                agent_epoch: row.get("agent_epoch"),
                base_sha256: row.get("base_sha256"),
                base_format: row.get("base_format"),
                overlay_format: row.get("overlay_format"),
            },
            state: ImageOverlayState::parse(&state_str)?,
            created_at: row.get("created_at"),
            updated_at: row.get("updated_at"),
        })
    }

    async fn update_image_overlay(
        &self,
        overlay_id: &str,
        expected_identity: &ImageOverlayIdentity,
        update: ImageOverlayUpdate,
    ) -> Result<ImageOverlayOwnershipRecord, StoreError> {
        let mut tx = self.pool.begin().await.map_err(StoreError::Database)?;

        let current = self.get_image_overlay(overlay_id).await?;
        if current.identity.agent_epoch != expected_identity.agent_epoch {
            return Err(StoreError::ImageOverlayEpochConflict);
        }
        if current.identity != *expected_identity {
            return Err(StoreError::ImageOverlayConflict(
                "overlay identity conflict".to_owned(),
            ));
        }
        validate_image_overlay_transition(current.state, update.state)?;

        if current.state == update.state {
            return Ok(current);
        }

        let res = sqlx::query(
            "UPDATE image_overlay_ownership
             SET state = $1, updated_at = CURRENT_TIMESTAMP
             WHERE overlay_id = $2 AND agent_epoch = $3 AND state = $4",
        )
        .bind(update.state.as_str())
        .bind(overlay_id)
        .bind(&expected_identity.agent_epoch)
        .bind(current.state.as_str())
        .execute(&mut *tx)
        .await
        .map_err(StoreError::Database)?;

        if res.rows_affected() != 1 {
            return Err(StoreError::ImageOverlayConflict(
                "overlay update failed".to_owned(),
            ));
        }

        tx.commit().await.map_err(StoreError::Database)?;
        self.get_image_overlay(overlay_id).await
    }

    async fn list_image_overlays(
        &self,
        resource_id: Uuid,
    ) -> Result<Vec<ImageOverlayOwnershipRecord>, StoreError> {
        let res_id_str = resource_id.to_string();
        let rows = sqlx::query("SELECT overlay_id FROM image_overlay_ownership WHERE resource_id = $1 ORDER BY created_at ASC")
            .bind(&res_id_str)
            .fetch_all(&self.pool)
            .await
            .map_err(StoreError::Database)?;

        let mut overlays = Vec::with_capacity(rows.len());
        for row in rows {
            let id: String = row.get("overlay_id");
            overlays.push(self.get_image_overlay(&id).await?);
        }
        Ok(overlays)
    }

    async fn count_image_overlay_references(
        &self,
        base_sha256: &str,
        base_format: &str,
    ) -> Result<u64, StoreError> {
        let row = sqlx::query("SELECT COUNT(*) FROM image_overlay_ownership WHERE base_sha256 = $1 AND base_format = $2 AND state != 'deleted'")
            .bind(base_sha256)
            .bind(base_format)
            .fetch_one(&self.pool)
            .await
            .map_err(StoreError::Database)?;

        let count: i64 = row.get(0);
        Ok(count.max(0) as u64)
    }

    async fn delete_image_overlay(
        &self,
        overlay_id: &str,
        expected_identity: &ImageOverlayIdentity,
    ) -> Result<ImageOverlayOwnershipRecord, StoreError> {
        let current = self.get_image_overlay(overlay_id).await?;
        if current.state == ImageOverlayState::Deleted {
            if current.identity.agent_epoch != expected_identity.agent_epoch {
                return Err(StoreError::ImageOverlayEpochConflict);
            }
            if current.identity != *expected_identity {
                return Err(StoreError::ImageOverlayConflict(
                    "overlay identity conflicts with durable state".to_owned(),
                ));
            }
            return Ok(current);
        }
        let deleting = self
            .update_image_overlay(
                overlay_id,
                expected_identity,
                ImageOverlayUpdate {
                    state: ImageOverlayState::Deleting,
                },
            )
            .await?;
        if deleting.state == ImageOverlayState::Deleted {
            return Ok(deleting);
        }
        self.update_image_overlay(
            overlay_id,
            expected_identity,
            ImageOverlayUpdate {
                state: ImageOverlayState::Deleted,
            },
        )
        .await
    }

    async fn increment_operation_retry(&self, operation_id: Uuid) -> Result<u8, StoreError> {
        let mut tx = self.pool.begin().await.map_err(StoreError::Database)?;
        let op_id_str = operation_id.to_string();
        let current: Option<i64> = sqlx::query_scalar(
            "SELECT attempts FROM operation_retry_state WHERE operation_id = $1",
        )
        .bind(&op_id_str)
        .fetch_optional(&mut *tx)
        .await
        .map_err(StoreError::Database)?;
        let attempts = current.unwrap_or(0).saturating_add(1);
        sqlx::query(
            "INSERT INTO operation_retry_state (operation_id, attempts, updated_at)
             VALUES ($1, $2, CURRENT_TIMESTAMP)
             ON CONFLICT (operation_id) DO UPDATE
             SET attempts = $2, updated_at = CURRENT_TIMESTAMP",
        )
        .bind(&op_id_str)
        .bind(attempts)
        .execute(&mut *tx)
        .await
        .map_err(StoreError::Database)?;

        // Synchronise canonical operation attempt when canonical metadata
        // exists; a no-op for legacy operations without metadata.
        sqlx::query("UPDATE canonical_operation_metadata SET attempt = $1 WHERE operation_id = $2")
            .bind(attempts)
            .bind(&op_id_str)
            .execute(&mut *tx)
            .await
            .map_err(StoreError::Database)?;

        tx.commit().await.map_err(StoreError::Database)?;
        u8::try_from(attempts)
            .map_err(|_| StoreError::Corrupt("operation retry count exceeds limit".to_owned()))
    }

    async fn insert_resource_and_operation(
        &self,
        resource: &ResourceRecord,
        operation: &OperationRecord,
        expected_placement_allocation_id: Option<&str>,
    ) -> Result<(), StoreError> {
        let mut tx = self.pool.begin().await.map_err(StoreError::Database)?;

        if let Some(allocation_id) = expected_placement_allocation_id {
            let alloc_row = sqlx::query("SELECT 1 FROM placement_allocations WHERE id = $1")
                .bind(allocation_id)
                .fetch_optional(&mut *tx)
                .await
                .map_err(StoreError::Database)?;
            if alloc_row.is_none() {
                return Err(StoreError::PlacementAllocationNotFound);
            }
        }

        let res_id_str = resource.id.to_string();
        sqlx::query(
            "INSERT INTO resources (id, kind, project_id, generation, observed_generation, desired_state, observed_state, provider_id)
             VALUES ($1, $2, $3, $4, $5, $6, $7, $8)",
        )
        .bind(&res_id_str)
        .bind(&resource.kind)
        .bind(&resource.project_id)
        .bind(resource.generation)
        .bind(resource.observed_generation)
        .bind(&resource.desired_state)
        .bind(&resource.observed_state)
        .bind(&resource.provider_id)
        .execute(&mut *tx)
        .await
        .map_err(map_pg_error)?;

        let op_id_str = operation.id.to_string();
        sqlx::query(
            "INSERT INTO operations (id, resource_id, kind, state, provider_operation_id, error_category, error_message)
             VALUES ($1, $2, $3, $4, $5, $6, $7)",
        )
        .bind(&op_id_str)
        .bind(&res_id_str)
        .bind(&operation.kind)
        .bind(operation.state.as_str())
        .bind(&operation.provider_operation_id)
        .bind(&operation.error_category)
        .bind(&operation.error_message)
        .execute(&mut *tx)
        .await
        .map_err(map_pg_error)?;

        tx.commit().await.map_err(StoreError::Database)?;
        Ok(())
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
        let mut tx = self.pool.begin().await.map_err(StoreError::Database)?;

        if let Some(allocation_id) = expected_placement_allocation_id {
            let alloc_row = sqlx::query("SELECT 1 FROM placement_allocations WHERE id = $1")
                .bind(allocation_id)
                .fetch_optional(&mut *tx)
                .await
                .map_err(StoreError::Database)?;
            if alloc_row.is_none() {
                return Err(StoreError::PlacementAllocationNotFound);
            }
        }

        let id_str = id.to_string();
        let res = sqlx::query(
            "UPDATE resources
             SET desired_state = $1, observed_state = $2, observed_generation = $3, provider_id = $4, generation = generation + 1
             WHERE id = $5 AND generation = $6",
        )
        .bind(desired_state)
        .bind(observed_state)
        .bind(observed_generation)
        .bind(provider_id)
        .bind(&id_str)
        .bind(expected_generation)
        .execute(&mut *tx)
        .await
        .map_err(StoreError::Database)?;

        if res.rows_affected() == 0 {
            return Err(StoreError::StaleGeneration);
        }

        let op_id_str = operation.id.to_string();
        sqlx::query(
            "INSERT INTO operations (id, resource_id, kind, state, provider_operation_id, error_category, error_message)
             VALUES ($1, $2, $3, $4, $5, $6, $7)",
        )
        .bind(&op_id_str)
        .bind(&id_str)
        .bind(&operation.kind)
        .bind(operation.state.as_str())
        .bind(&operation.provider_operation_id)
        .bind(&operation.error_category)
        .bind(&operation.error_message)
        .execute(&mut *tx)
        .await
        .map_err(map_pg_error)?;

        tx.commit().await.map_err(StoreError::Database)?;
        self.get_resource(id).await
    }

    async fn readiness_check(&self) -> Result<(), StoreError> {
        self.readiness_check().await
    }
}
