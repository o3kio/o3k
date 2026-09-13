use async_trait::async_trait;
use sqlx::Row;

use crate::{
    PlacementAllocationRecord, PlacementCapacityClassRecord, PlacementCapacitySummary,
    PlacementIntentRecord, PlacementInventoryRecord, PlacementProviderRecord,
    PlacementProviderStateRecord, PlacementReconcileRecord, PlacementRepository,
    PlacementResourceRecord, StoreError,
};

use super::PostgresStore;

/// PostgreSQL returns placement quantities as signed `BIGINT`. A negative
/// aggregate is corruption, not a valid capacity, so it fails closed.
fn pg_placement_u64(value: i64) -> Result<u64, StoreError> {
    u64::try_from(value)
        .map_err(|_| StoreError::Corrupt("negative placement value in durable state".to_owned()))
}

#[async_trait]
impl PlacementRepository for PostgresStore {
    async fn get_provider(
        &self,
        provider_id: &str,
    ) -> Result<Option<PlacementProviderRecord>, StoreError> {
        let row = sqlx::query(
            "SELECT id, node_id, state, generation, parent_provider_id, location FROM placement_providers WHERE id = $1",
        )
        .bind(provider_id)
        .fetch_optional(&self.pool)
        .await
        .map_err(StoreError::Database)?;

        let Some(row) = row else {
            return Ok(None);
        };
        let provider = PlacementProviderRecord {
            id: row.get("id"),
            node_id: row.get("node_id"),
            state: row.get("state"),
            generation: row.get::<i64, _>("generation") as u64,
            inventories: self.load_placement_inventories(provider_id).await?,
            allocations: self.load_placement_allocations(provider_id).await?,
            parent_provider_id: row.get("parent_provider_id"),
            traits: self.load_provider_traits(provider_id).await?,
            failure_domains: self.load_provider_failure_domains(provider_id).await?,
            location: row.get("location"),
        };
        Ok(Some(provider))
    }

    async fn list_providers(&self) -> Result<Vec<PlacementProviderRecord>, StoreError> {
        let rows = sqlx::query(
            "SELECT id, node_id, state, generation, parent_provider_id, location FROM placement_providers ORDER BY id",
        )
        .fetch_all(&self.pool)
        .await
        .map_err(StoreError::Database)?;

        let mut providers = Vec::new();
        for row in rows {
            let provider_id: String = row.get("id");
            let provider = PlacementProviderRecord {
                id: row.get("id"),
                node_id: row.get("node_id"),
                state: row.get("state"),
                generation: row.get::<i64, _>("generation") as u64,
                inventories: self.load_placement_inventories(&provider_id).await?,
                allocations: self.load_placement_allocations(&provider_id).await?,
                parent_provider_id: row.get("parent_provider_id"),
                traits: self.load_provider_traits(&provider_id).await?,
                failure_domains: self.load_provider_failure_domains(&provider_id).await?,
                location: row.get("location"),
            };
            providers.push(provider);
        }
        Ok(providers)
    }

    async fn list_providers_bounded(
        &self,
        after_id: Option<&str>,
        limit: usize,
    ) -> Result<Vec<PlacementProviderRecord>, StoreError> {
        let limit = i64::try_from(limit)
            .map_err(|_| StoreError::Corrupt("placement page limit out of range".to_owned()))?;
        let rows = sqlx::query(
            "SELECT id, node_id, state, generation, parent_provider_id, location FROM placement_providers \
             WHERE ($1::text IS NULL OR id > $1) \
             ORDER BY id \
             LIMIT $2",
        )
        .bind(after_id)
        .bind(limit)
        .fetch_all(&self.pool)
        .await
        .map_err(StoreError::Database)?;
        let mut providers = Vec::with_capacity(rows.len());
        for row in rows {
            let provider_id: String = row.get("id");
            let provider = PlacementProviderRecord {
                id: row.get("id"),
                node_id: row.get("node_id"),
                state: row.get("state"),
                generation: row.get::<i64, _>("generation") as u64,
                inventories: self.load_placement_inventories(&provider_id).await?,
                allocations: Vec::new(),
                parent_provider_id: row.get("parent_provider_id"),
                traits: self.load_provider_traits(&provider_id).await?,
                failure_domains: self.load_provider_failure_domains(&provider_id).await?,
                location: row.get("location"),
            };
            providers.push(provider);
        }
        Ok(providers)
    }

    async fn list_provider_states(
        &self,
        after_id: Option<&str>,
        limit: usize,
    ) -> Result<Vec<PlacementProviderStateRecord>, StoreError> {
        let limit = i64::try_from(limit)
            .map_err(|_| StoreError::Corrupt("placement page limit out of range".to_owned()))?;
        let rows = sqlx::query(
            "SELECT id, state FROM placement_providers \
             WHERE ($1::text IS NULL OR id > $1) \
             ORDER BY id \
             LIMIT $2",
        )
        .bind(after_id)
        .bind(limit)
        .fetch_all(&self.pool)
        .await
        .map_err(StoreError::Database)?;
        Ok(rows
            .iter()
            .map(|row| PlacementProviderStateRecord {
                id: row.get("id"),
                state: row.get("state"),
            })
            .collect())
    }

    async fn capacity_summary(&self, limit: usize) -> Result<PlacementCapacitySummary, StoreError> {
        let bound = i64::try_from(limit).map_err(|_| {
            StoreError::Corrupt("placement aggregate limit out of range".to_owned())
        })?;
        let rows = sqlx::query(
            "SELECT resource_class, \
                    COALESCE(SUM(FLOOR(total * allocation_ratio)::BIGINT), 0)::BIGINT AS allocatable, \
                    COALESCE(SUM(reserved), 0)::BIGINT AS reserved, \
                    COALESCE(SUM(used), 0)::BIGINT AS allocated \
             FROM placement_inventories \
             GROUP BY resource_class \
             ORDER BY resource_class \
             LIMIT $1",
        )
        .bind(bound + 1)
        .fetch_all(&self.pool)
        .await
        .map_err(StoreError::Database)?;
        if rows.len() > limit {
            return Err(StoreError::Corrupt(
                "placement resource class inventory exceeds the bounded aggregate limit".to_owned(),
            ));
        }
        let mut classes = Vec::with_capacity(rows.len());
        for row in &rows {
            classes.push(PlacementCapacityClassRecord {
                resource_class: row.get("resource_class"),
                allocatable: pg_placement_u64(row.get("allocatable"))?,
                reserved: pg_placement_u64(row.get("reserved"))?,
                allocated: pg_placement_u64(row.get("allocated"))?,
            });
        }
        let state_rows = sqlx::query(
            "SELECT state, COUNT(*) AS provider_count FROM placement_providers GROUP BY state",
        )
        .fetch_all(&self.pool)
        .await
        .map_err(StoreError::Database)?;
        let mut summary = PlacementCapacitySummary {
            classes,
            ..PlacementCapacitySummary::default()
        };
        for row in &state_rows {
            let state: String = row.get("state");
            let count = pg_placement_u64(row.get("provider_count"))?;
            match state.as_str() {
                "Enabled" => summary.providers_enabled = count,
                "Draining" => summary.providers_draining = count,
                "Unavailable" => summary.providers_unavailable = count,
                "Deleted" => summary.providers_deleted = count,
                other => {
                    return Err(StoreError::Corrupt(format!(
                        "unknown placement provider state in durable state: {other:?}"
                    )));
                }
            }
        }
        // Providers with at least one over-allocated class (drifted/corrupt
        // durable invariant), so diagnostics can degrade capacity even when an
        // over-allocation is masked by another provider's slack.
        let over_allocated: i64 = sqlx::query_scalar(
            "SELECT COUNT(DISTINCT provider_id) FROM placement_inventories \
             WHERE used > FLOOR(total * allocation_ratio)::BIGINT - reserved",
        )
        .fetch_one(&self.pool)
        .await
        .map_err(StoreError::Database)?;
        summary.providers_over_allocated = pg_placement_u64(over_allocated)?;
        Ok(summary)
    }

    async fn register_provider(
        &self,
        node_id: &str,
        inventories: &[PlacementInventoryRecord],
    ) -> Result<PlacementProviderRecord, StoreError> {
        let mut tx = self.pool.begin().await.map_err(StoreError::Database)?;

        let row = sqlx::query(
            "INSERT INTO placement_providers (id, node_id, state, generation)
             VALUES ($1, $1, 'Enabled', 1)
             ON CONFLICT (node_id) DO UPDATE
             SET state = 'Enabled', generation = placement_providers.generation + 1
             RETURNING id, node_id, state, generation",
        )
        .bind(node_id)
        .fetch_one(&mut *tx)
        .await
        .map_err(StoreError::Database)?;

        let id: String = row.get("id");
        for inv in inventories {
            sqlx::query(
                "INSERT INTO placement_inventories (provider_id, resource_class, total, reserved, allocation_ratio, used)
                 VALUES ($1, $2, $3, $4, $5, $6)
                 ON CONFLICT (provider_id, resource_class) DO UPDATE
                 SET total = EXCLUDED.total, reserved = EXCLUDED.reserved, allocation_ratio = EXCLUDED.allocation_ratio",
            )
            .bind(&id)
            .bind(&inv.resource_class)
            .bind(inv.total as i64)
            .bind(inv.reserved as i64)
            .bind(inv.allocation_ratio)
            .bind(inv.used as i64)
            .execute(&mut *tx)
            .await
            .map_err(StoreError::Database)?;
        }

        tx.commit().await.map_err(StoreError::Database)?;
        self.get_provider(&id)
            .await?
            .ok_or(StoreError::PlacementProviderNotFound)
    }

    async fn register_provider_metadata(
        &self,
        node_id: &str,
        inventories: &[PlacementInventoryRecord],
        parent_provider_id: Option<&str>,
        traits: &[String],
        failure_domains: &[String],
        location: Option<&str>,
    ) -> Result<PlacementProviderRecord, StoreError> {
        PostgresStore::register_provider_metadata(
            self,
            node_id,
            inventories,
            parent_provider_id,
            traits,
            failure_domains,
            location,
        )
        .await
    }

    async fn update_provider_metadata(
        &self,
        provider_id: &str,
        expected_generation: u64,
        parent_provider_id: Option<&str>,
        traits: &[String],
        failure_domains: &[String],
        location: Option<&str>,
    ) -> Result<PlacementProviderRecord, StoreError> {
        PostgresStore::update_provider_metadata(
            self,
            provider_id,
            expected_generation,
            parent_provider_id,
            traits,
            failure_domains,
            location,
        )
        .await
    }

    async fn sync_provider(
        &self,
        node_id: &str,
        state: &str,
        inventories: &[PlacementInventoryRecord],
    ) -> Result<PlacementProviderRecord, StoreError> {
        let mut tx = self.pool.begin().await.map_err(StoreError::Database)?;

        let row = sqlx::query(
            "INSERT INTO placement_providers (id, node_id, state, generation)
             VALUES ($1, $1, $2, 1)
             ON CONFLICT (node_id) DO UPDATE
             SET state = EXCLUDED.state, generation = placement_providers.generation + 1
             RETURNING id, node_id, state, generation",
        )
        .bind(node_id)
        .bind(state)
        .fetch_one(&mut *tx)
        .await
        .map_err(StoreError::Database)?;

        let id: String = row.get("id");
        for inv in inventories {
            sqlx::query(
                "INSERT INTO placement_inventories (provider_id, resource_class, total, reserved, allocation_ratio, used)
                 VALUES ($1, $2, $3, $4, $5, $6)
                 ON CONFLICT (provider_id, resource_class) DO UPDATE
                 SET total = EXCLUDED.total, reserved = EXCLUDED.reserved, allocation_ratio = EXCLUDED.allocation_ratio",
            )
            .bind(&id)
            .bind(&inv.resource_class)
            .bind(inv.total as i64)
            .bind(inv.reserved as i64)
            .bind(inv.allocation_ratio)
            .bind(inv.used as i64)
            .execute(&mut *tx)
            .await
            .map_err(StoreError::Database)?;
        }

        tx.commit().await.map_err(StoreError::Database)?;
        self.get_provider(&id)
            .await?
            .ok_or(StoreError::PlacementProviderNotFound)
    }

    async fn refresh_inventories(
        &self,
        provider_id: &str,
        expected_generation: u64,
        inventories: &[PlacementInventoryRecord],
    ) -> Result<PlacementProviderRecord, StoreError> {
        let mut tx = self.pool.begin().await.map_err(StoreError::Database)?;

        let res = sqlx::query(
            "UPDATE placement_providers
             SET generation = generation + 1
             WHERE id = $1 AND generation = $2",
        )
        .bind(provider_id)
        .bind(expected_generation as i64)
        .execute(&mut *tx)
        .await
        .map_err(StoreError::Database)?;

        if res.rows_affected() == 0 {
            let exists = sqlx::query("SELECT 1 FROM placement_providers WHERE id = $1")
                .bind(provider_id)
                .fetch_optional(&mut *tx)
                .await
                .map_err(StoreError::Database)?;
            if exists.is_none() {
                return Err(StoreError::PlacementProviderNotFound);
            }
            return Err(StoreError::PlacementStaleGeneration);
        }

        for inv in inventories {
            sqlx::query(
                "INSERT INTO placement_inventories (provider_id, resource_class, total, reserved, allocation_ratio, used)
                 VALUES ($1, $2, $3, $4, $5, $6)
                 ON CONFLICT (provider_id, resource_class) DO UPDATE
                 SET total = EXCLUDED.total, reserved = EXCLUDED.reserved, allocation_ratio = EXCLUDED.allocation_ratio",
            )
            .bind(provider_id)
            .bind(&inv.resource_class)
            .bind(inv.total as i64)
            .bind(inv.reserved as i64)
            .bind(inv.allocation_ratio)
            .bind(inv.used as i64)
            .execute(&mut *tx)
            .await
            .map_err(StoreError::Database)?;
        }

        tx.commit().await.map_err(StoreError::Database)?;
        self.get_provider(provider_id)
            .await?
            .ok_or(StoreError::PlacementProviderNotFound)
    }

    async fn set_provider_state(&self, provider_id: &str, state: &str) -> Result<(), StoreError> {
        let res = sqlx::query(
            "UPDATE placement_providers SET state = $1, generation = generation + 1 WHERE id = $2",
        )
        .bind(state)
        .bind(provider_id)
        .execute(&self.pool)
        .await
        .map_err(StoreError::Database)?;

        if res.rows_affected() == 0 {
            return Err(StoreError::PlacementProviderNotFound);
        }
        Ok(())
    }

    async fn commit_allocation(
        &self,
        provider_id: &str,
        expected_generation: u64,
        allocation: &PlacementAllocationRecord,
    ) -> Result<PlacementAllocationRecord, StoreError> {
        let mut tx = self.pool.begin().await.map_err(StoreError::Database)?;

        let existing_alloc_row =
            sqlx::query("SELECT provider_id, consumer_id FROM placement_allocations WHERE id = $1")
                .bind(&allocation.id)
                .fetch_optional(&mut *tx)
                .await
                .map_err(StoreError::Database)?;
        if let Some(row) = existing_alloc_row {
            let pid: String = row.get("provider_id");
            let cid: String = row.get("consumer_id");
            let res_rows = sqlx::query("SELECT resource_class, amount FROM placement_allocation_resources WHERE allocation_id = $1 ORDER BY resource_class")
                .bind(&allocation.id)
                .fetch_all(&mut *tx)
                .await
                .map_err(StoreError::Database)?;
            let mut resources = Vec::new();
            for r in res_rows {
                resources.push(PlacementResourceRecord {
                    resource_class: r.get("resource_class"),
                    amount: r.get::<i64, _>("amount") as u64,
                });
            }
            let mut expected_resources = allocation.resources.clone();
            expected_resources.sort_by(|a, b| a.resource_class.cmp(&b.resource_class));
            if pid == provider_id
                && cid == allocation.consumer_id
                && resources == expected_resources
            {
                return Ok(allocation.clone());
            }
            return Err(StoreError::PlacementAllocationConflict);
        }

        let prov_row =
            sqlx::query("SELECT generation FROM placement_providers WHERE id = $1 FOR UPDATE")
                .bind(provider_id)
                .fetch_optional(&mut *tx)
                .await
                .map_err(StoreError::Database)?;

        let Some(prov_row) = prov_row else {
            return Err(StoreError::PlacementProviderNotFound);
        };
        let current_gen: i64 = prov_row.get("generation");
        if current_gen as u64 != expected_generation {
            return Err(StoreError::PlacementStaleGeneration);
        }

        sqlx::query(
            "INSERT INTO placement_allocations (id, provider_id, consumer_id)
             VALUES ($1, $2, $3)
             ON CONFLICT (id) DO NOTHING",
        )
        .bind(&allocation.id)
        .bind(provider_id)
        .bind(&allocation.consumer_id)
        .execute(&mut *tx)
        .await
        .map_err(StoreError::Database)?;

        for res in &allocation.resources {
            sqlx::query(
                "INSERT INTO placement_allocation_resources (allocation_id, resource_class, amount)
                 VALUES ($1, $2, $3)
                 ON CONFLICT (allocation_id, resource_class) DO UPDATE SET amount = EXCLUDED.amount",
            )
            .bind(&allocation.id)
            .bind(&res.resource_class)
            .bind(res.amount as i64)
            .execute(&mut *tx)
            .await
            .map_err(StoreError::Database)?;

            sqlx::query(
                "UPDATE placement_inventories SET used = used + $1 WHERE provider_id = $2 AND resource_class = $3",
            )
            .bind(res.amount as i64)
            .bind(provider_id)
            .bind(&res.resource_class)
            .execute(&mut *tx)
            .await
            .map_err(StoreError::Database)?;
        }

        sqlx::query("UPDATE placement_providers SET generation = generation + 1 WHERE id = $1")
            .bind(provider_id)
            .execute(&mut *tx)
            .await
            .map_err(StoreError::Database)?;

        tx.commit().await.map_err(StoreError::Database)?;
        Ok(allocation.clone())
    }

    async fn release_allocation(
        &self,
        provider_id: &str,
        allocation_id: &str,
    ) -> Result<(), StoreError> {
        let mut tx = self.pool.begin().await.map_err(StoreError::Database)?;

        let provider_exists = sqlx::query("SELECT 1 FROM placement_providers WHERE id = $1")
            .bind(provider_id)
            .fetch_optional(&mut *tx)
            .await
            .map_err(StoreError::Database)?;
        if provider_exists.is_none() {
            return Err(StoreError::PlacementProviderNotFound);
        }

        let res_rows = sqlx::query(
            "SELECT r.resource_class, r.amount
             FROM placement_allocation_resources r
             JOIN placement_allocations a ON a.id = r.allocation_id
             WHERE r.allocation_id = $1 AND a.provider_id = $2",
        )
        .bind(allocation_id)
        .bind(provider_id)
        .fetch_all(&mut *tx)
        .await
        .map_err(StoreError::Database)?;

        if res_rows.is_empty() {
            return Ok(());
        }

        for row in res_rows {
            let rc: String = row.get("resource_class");
            let amt: i64 = row.get("amount");
            sqlx::query(
                "UPDATE placement_inventories SET used = used - $1 WHERE provider_id = $2 AND resource_class = $3",
            )
            .bind(amt)
            .bind(provider_id)
            .bind(&rc)
            .execute(&mut *tx)
            .await
            .map_err(StoreError::Database)?;
        }

        sqlx::query("DELETE FROM placement_allocations WHERE id = $1 AND provider_id = $2")
            .bind(allocation_id)
            .bind(provider_id)
            .execute(&mut *tx)
            .await
            .map_err(StoreError::Database)?;

        sqlx::query("UPDATE placement_providers SET generation = generation + 1 WHERE id = $1")
            .bind(provider_id)
            .execute(&mut *tx)
            .await
            .map_err(StoreError::Database)?;

        tx.commit().await.map_err(StoreError::Database)?;
        Ok(())
    }

    async fn upsert_intent(
        &self,
        intent: &PlacementIntentRecord,
    ) -> Result<PlacementIntentRecord, StoreError> {
        let mut tx = self.pool.begin().await.map_err(StoreError::Database)?;

        sqlx::query(
            "INSERT INTO placement_allocation_intents (id, provider_id, consumer_id)
             VALUES ($1, $2, $3)
             ON CONFLICT (id) DO UPDATE SET provider_id = EXCLUDED.provider_id, consumer_id = EXCLUDED.consumer_id",
        )
        .bind(&intent.id)
        .bind(&intent.provider_id)
        .bind(&intent.consumer_id)
        .execute(&mut *tx)
        .await
        .map_err(StoreError::Database)?;

        sqlx::query("DELETE FROM placement_allocation_intent_resources WHERE intent_id = $1")
            .bind(&intent.id)
            .execute(&mut *tx)
            .await
            .map_err(StoreError::Database)?;

        for res in &intent.resources {
            sqlx::query(
                "INSERT INTO placement_allocation_intent_resources (intent_id, resource_class, amount)
                 VALUES ($1, $2, $3)",
            )
            .bind(&intent.id)
            .bind(&res.resource_class)
            .bind(res.amount as i64)
            .execute(&mut *tx)
            .await
            .map_err(StoreError::Database)?;
        }

        tx.commit().await.map_err(StoreError::Database)?;
        Ok(intent.clone())
    }

    async fn get_intent(
        &self,
        allocation_id: &str,
    ) -> Result<Option<PlacementIntentRecord>, StoreError> {
        let row = sqlx::query(
            "SELECT id, provider_id, consumer_id FROM placement_allocation_intents WHERE id = $1",
        )
        .bind(allocation_id)
        .fetch_optional(&self.pool)
        .await
        .map_err(StoreError::Database)?;

        let Some(row) = row else {
            return Ok(None);
        };
        let resources = self.load_intent_resources(allocation_id).await?;
        Ok(Some(PlacementIntentRecord {
            id: row.get("id"),
            provider_id: row.get("provider_id"),
            consumer_id: row.get("consumer_id"),
            resources,
        }))
    }

    async fn list_intents(&self) -> Result<Vec<PlacementIntentRecord>, StoreError> {
        let rows = sqlx::query(
            "SELECT id, provider_id, consumer_id FROM placement_allocation_intents ORDER BY id",
        )
        .fetch_all(&self.pool)
        .await
        .map_err(StoreError::Database)?;

        let mut intents = Vec::new();
        for row in rows {
            let intent_id: String = row.get("id");
            let resources = self.load_intent_resources(&intent_id).await?;
            intents.push(PlacementIntentRecord {
                id: row.get("id"),
                provider_id: row.get("provider_id"),
                consumer_id: row.get("consumer_id"),
                resources,
            });
        }
        Ok(intents)
    }

    async fn delete_intent(&self, allocation_id: &str) -> Result<(), StoreError> {
        sqlx::query("DELETE FROM placement_allocation_intents WHERE id = $1")
            .bind(allocation_id)
            .execute(&self.pool)
            .await
            .map_err(StoreError::Database)?;
        Ok(())
    }

    async fn reconcile_consumers(
        &self,
        durable_consumer_ids: &[String],
    ) -> Result<PlacementReconcileRecord, StoreError> {
        let mut tx = self.pool.begin().await.map_err(StoreError::Database)?;

        let alloc_rows = if durable_consumer_ids.is_empty() {
            sqlx::query("SELECT id, provider_id, consumer_id FROM placement_allocations")
                .fetch_all(&mut *tx)
                .await
                .map_err(StoreError::Database)?
        } else {
            sqlx::query(
                "SELECT id, provider_id, consumer_id FROM placement_allocations WHERE NOT (consumer_id = ANY($1))",
            )
            .bind(durable_consumer_ids)
            .fetch_all(&mut *tx)
            .await
            .map_err(StoreError::Database)?
        };

        let mut orphaned_allocations = Vec::new();
        for row in alloc_rows {
            let aid: String = row.get("id");
            let pid: String = row.get("provider_id");
            let cid: String = row.get("consumer_id");

            let res_rows = sqlx::query(
                "SELECT resource_class, amount FROM placement_allocation_resources WHERE allocation_id = $1",
            )
            .bind(&aid)
            .fetch_all(&mut *tx)
            .await
            .map_err(StoreError::Database)?;

            let mut resources = Vec::new();
            for rrow in res_rows {
                let rc: String = rrow.get("resource_class");
                let amt: i64 = rrow.get("amount");
                resources.push(PlacementResourceRecord {
                    resource_class: rc.clone(),
                    amount: amt as u64,
                });
                sqlx::query(
                    "UPDATE placement_inventories SET used = used - $1 WHERE provider_id = $2 AND resource_class = $3",
                )
                .bind(amt)
                .bind(&pid)
                .bind(&rc)
                .execute(&mut *tx)
                .await
                .map_err(StoreError::Database)?;
            }

            sqlx::query("DELETE FROM placement_allocations WHERE id = $1")
                .bind(&aid)
                .execute(&mut *tx)
                .await
                .map_err(StoreError::Database)?;

            orphaned_allocations.push(PlacementAllocationRecord {
                id: aid,
                provider_id: pid,
                consumer_id: cid,
                resources,
            });
        }

        let intent_rows = if durable_consumer_ids.is_empty() {
            sqlx::query("SELECT id, provider_id, consumer_id FROM placement_allocation_intents")
                .fetch_all(&mut *tx)
                .await
                .map_err(StoreError::Database)?
        } else {
            sqlx::query(
                "SELECT id, provider_id, consumer_id FROM placement_allocation_intents WHERE NOT (consumer_id = ANY($1))",
            )
            .bind(durable_consumer_ids)
            .fetch_all(&mut *tx)
            .await
            .map_err(StoreError::Database)?
        };

        let mut abandoned_intents = Vec::new();
        for row in intent_rows {
            let iid: String = row.get("id");
            let pid: String = row.get("provider_id");
            let cid: String = row.get("consumer_id");

            let res_rows = sqlx::query(
                "SELECT resource_class, amount FROM placement_allocation_intent_resources WHERE intent_id = $1",
            )
            .bind(&iid)
            .fetch_all(&mut *tx)
            .await
            .map_err(StoreError::Database)?;

            let mut resources = Vec::new();
            for rrow in res_rows {
                resources.push(PlacementResourceRecord {
                    resource_class: rrow.get("resource_class"),
                    amount: rrow.get::<i64, _>("amount") as u64,
                });
            }

            sqlx::query("DELETE FROM placement_allocation_intents WHERE id = $1")
                .bind(&iid)
                .execute(&mut *tx)
                .await
                .map_err(StoreError::Database)?;

            abandoned_intents.push(PlacementIntentRecord {
                id: iid,
                provider_id: pid,
                consumer_id: cid,
                resources,
            });
        }

        tx.commit().await.map_err(StoreError::Database)?;
        Ok(PlacementReconcileRecord {
            orphaned_allocations,
            abandoned_intents,
        })
    }

    async fn import_provider(&self, provider: &PlacementProviderRecord) -> Result<(), StoreError> {
        let mut tx = self.pool.begin().await.map_err(StoreError::Database)?;

        sqlx::query(
            "INSERT INTO placement_providers (id, node_id, state, generation)
             VALUES ($1, $2, $3, $4)
             ON CONFLICT (id) DO UPDATE
             SET node_id = EXCLUDED.node_id, state = EXCLUDED.state, generation = EXCLUDED.generation",
        )
        .bind(&provider.id)
        .bind(&provider.node_id)
        .bind(&provider.state)
        .bind(provider.generation as i64)
        .execute(&mut *tx)
        .await
        .map_err(StoreError::Database)?;

        sqlx::query(
            "UPDATE placement_providers SET parent_provider_id = $1, location = $2 WHERE id = $3",
        )
        .bind(&provider.parent_provider_id)
        .bind(&provider.location)
        .bind(&provider.id)
        .execute(&mut *tx)
        .await
        .map_err(StoreError::Database)?;
        sqlx::query("DELETE FROM placement_provider_traits WHERE provider_id = $1")
            .bind(&provider.id)
            .execute(&mut *tx)
            .await
            .map_err(StoreError::Database)?;
        for trait_name in &provider.traits {
            sqlx::query(
                "INSERT INTO placement_provider_traits(provider_id, trait) VALUES ($1, $2)",
            )
            .bind(&provider.id)
            .bind(trait_name)
            .execute(&mut *tx)
            .await
            .map_err(StoreError::Database)?;
        }
        sqlx::query("DELETE FROM placement_provider_failure_domains WHERE provider_id = $1")
            .bind(&provider.id)
            .execute(&mut *tx)
            .await
            .map_err(StoreError::Database)?;
        for domain in &provider.failure_domains {
            sqlx::query("INSERT INTO placement_provider_failure_domains(provider_id, failure_domain_id) VALUES ($1, $2)").bind(&provider.id).bind(domain).execute(&mut *tx).await.map_err(StoreError::Database)?;
        }

        for inv in &provider.inventories {
            sqlx::query(
                "INSERT INTO placement_inventories (provider_id, resource_class, total, reserved, allocation_ratio, used)
                 VALUES ($1, $2, $3, $4, $5, $6)
                 ON CONFLICT (provider_id, resource_class) DO UPDATE
                 SET total = EXCLUDED.total, reserved = EXCLUDED.reserved, allocation_ratio = EXCLUDED.allocation_ratio, used = EXCLUDED.used",
            )
            .bind(&provider.id)
            .bind(&inv.resource_class)
            .bind(inv.total as i64)
            .bind(inv.reserved as i64)
            .bind(inv.allocation_ratio)
            .bind(inv.used as i64)
            .execute(&mut *tx)
            .await
            .map_err(StoreError::Database)?;
        }

        tx.commit().await.map_err(StoreError::Database)?;
        Ok(())
    }
}

impl PostgresStore {
    async fn load_provider_traits(&self, provider_id: &str) -> Result<Vec<String>, StoreError> {
        let rows = sqlx::query(
            "SELECT trait FROM placement_provider_traits WHERE provider_id = $1 ORDER BY trait",
        )
        .bind(provider_id)
        .fetch_all(&self.pool)
        .await
        .map_err(StoreError::Database)?;
        Ok(rows.iter().map(|row| row.get("trait")).collect())
    }

    async fn load_provider_failure_domains(
        &self,
        provider_id: &str,
    ) -> Result<Vec<String>, StoreError> {
        let rows = sqlx::query("SELECT failure_domain_id FROM placement_provider_failure_domains WHERE provider_id = $1 ORDER BY failure_domain_id")
            .bind(provider_id).fetch_all(&self.pool).await.map_err(StoreError::Database)?;
        Ok(rows
            .iter()
            .map(|row| row.get("failure_domain_id"))
            .collect())
    }

    async fn register_provider_metadata(
        &self,
        node_id: &str,
        inventories: &[PlacementInventoryRecord],
        parent_provider_id: Option<&str>,
        traits: &[String],
        failure_domains: &[String],
        location: Option<&str>,
    ) -> Result<PlacementProviderRecord, StoreError> {
        if parent_provider_id == Some(node_id) || traits.iter().any(|value| value.trim().is_empty())
        {
            return Err(StoreError::Corrupt(
                "invalid placement provider metadata".to_owned(),
            ));
        }
        if let Some(parent) = parent_provider_id
            && self.get_provider(parent).await?.is_none()
        {
            return Err(StoreError::PlacementProviderNotFound);
        }
        let provider = self.register_provider(node_id, inventories).await?;
        self.update_provider_metadata(
            &provider.id,
            provider.generation,
            parent_provider_id,
            traits,
            failure_domains,
            location,
        )
        .await
    }

    async fn update_provider_metadata(
        &self,
        provider_id: &str,
        expected_generation: u64,
        parent_provider_id: Option<&str>,
        traits: &[String],
        failure_domains: &[String],
        location: Option<&str>,
    ) -> Result<PlacementProviderRecord, StoreError> {
        if parent_provider_id == Some(provider_id) || traits.iter().any(|v| v.trim().is_empty()) {
            return Err(StoreError::Corrupt(
                "invalid placement provider metadata".to_owned(),
            ));
        }
        let mut tx = self.pool.begin().await.map_err(StoreError::Database)?;
        let current: Option<i64> =
            sqlx::query_scalar("SELECT generation FROM placement_providers WHERE id = $1")
                .bind(provider_id)
                .fetch_optional(&mut *tx)
                .await
                .map_err(StoreError::Database)?;
        let Some(current) = current else {
            return Err(StoreError::PlacementProviderNotFound);
        };
        if u64::try_from(current).ok() != Some(expected_generation) {
            return Err(StoreError::PlacementStaleGeneration);
        }
        if let Some(parent) = parent_provider_id {
            let exists: Option<String> =
                sqlx::query_scalar("SELECT id FROM placement_providers WHERE id = $1")
                    .bind(parent)
                    .fetch_optional(&mut *tx)
                    .await
                    .map_err(StoreError::Database)?;
            if exists.is_none() {
                return Err(StoreError::PlacementProviderNotFound);
            }
        }
        // Lock the provider rows and validate the proposed ancestor chain in
        // the same transaction.  Without this, two writers could race to
        // install reciprocal parents and persist a cycle.
        let hierarchy_rows = sqlx::query(
            "SELECT id, parent_provider_id FROM placement_providers ORDER BY id FOR UPDATE",
        )
        .fetch_all(&mut *tx)
        .await
        .map_err(StoreError::Database)?;
        let mut seen = std::collections::BTreeSet::new();
        let mut cursor = parent_provider_id.map(str::to_owned);
        for _ in 0..64 {
            let Some(id) = cursor else { break };
            if !seen.insert(id.clone()) || id == provider_id {
                return Err(StoreError::Corrupt(
                    "placement provider hierarchy cycle".to_owned(),
                ));
            }
            cursor = hierarchy_rows
                .iter()
                .find(|row| row.get::<String, _>("id") == id)
                .and_then(|row| row.get::<Option<String>, _>("parent_provider_id"));
        }
        if cursor.is_some() {
            return Err(StoreError::Corrupt(
                "placement provider hierarchy exceeds depth limit".to_owned(),
            ));
        }
        let updated = sqlx::query("UPDATE placement_providers SET parent_provider_id = $1, location = $2, generation = generation + 1 WHERE id = $3 AND generation = $4")
            .bind(parent_provider_id).bind(location).bind(provider_id).bind(i64::try_from(expected_generation).map_err(|_| StoreError::Corrupt("generation out of range".to_owned()))?).execute(&mut *tx).await.map_err(StoreError::Database)?;
        if updated.rows_affected() != 1 {
            return Err(StoreError::PlacementStaleGeneration);
        }
        sqlx::query("DELETE FROM placement_provider_traits WHERE provider_id = $1")
            .bind(provider_id)
            .execute(&mut *tx)
            .await
            .map_err(StoreError::Database)?;
        for value in traits
            .iter()
            .map(String::as_str)
            .collect::<std::collections::BTreeSet<_>>()
        {
            sqlx::query(
                "INSERT INTO placement_provider_traits(provider_id, trait) VALUES ($1, $2)",
            )
            .bind(provider_id)
            .bind(value)
            .execute(&mut *tx)
            .await
            .map_err(StoreError::Database)?;
        }
        sqlx::query("DELETE FROM placement_provider_failure_domains WHERE provider_id = $1")
            .bind(provider_id)
            .execute(&mut *tx)
            .await
            .map_err(StoreError::Database)?;
        for value in failure_domains
            .iter()
            .map(String::as_str)
            .collect::<std::collections::BTreeSet<_>>()
        {
            sqlx::query("INSERT INTO placement_provider_failure_domains(provider_id, failure_domain_id) VALUES ($1, $2)").bind(provider_id).bind(value).execute(&mut *tx).await.map_err(StoreError::Database)?;
        }
        tx.commit().await.map_err(StoreError::Database)?;
        self.get_provider(provider_id)
            .await?
            .ok_or(StoreError::PlacementProviderNotFound)
    }
    async fn load_placement_inventories(
        &self,
        provider_id: &str,
    ) -> Result<Vec<PlacementInventoryRecord>, StoreError> {
        let rows = sqlx::query(
            "SELECT resource_class, total, reserved, allocation_ratio, used FROM placement_inventories WHERE provider_id = $1 ORDER BY resource_class",
        )
        .bind(provider_id)
        .fetch_all(&self.pool)
        .await
        .map_err(StoreError::Database)?;

        Ok(rows
            .into_iter()
            .map(|r| PlacementInventoryRecord {
                resource_class: r.get("resource_class"),
                total: r.get::<i64, _>("total") as u64,
                reserved: r.get::<i64, _>("reserved") as u64,
                allocation_ratio: r.get::<f64, _>("allocation_ratio"),
                used: r.get::<i64, _>("used") as u64,
            })
            .collect())
    }

    async fn load_placement_allocations(
        &self,
        provider_id: &str,
    ) -> Result<Vec<PlacementAllocationRecord>, StoreError> {
        let rows = sqlx::query(
            "SELECT id, provider_id, consumer_id FROM placement_allocations WHERE provider_id = $1 ORDER BY id",
        )
        .bind(provider_id)
        .fetch_all(&self.pool)
        .await
        .map_err(StoreError::Database)?;

        let mut allocations = Vec::new();
        for row in rows {
            let aid: String = row.get("id");
            let resources = self.load_allocation_resources(&aid).await?;
            allocations.push(PlacementAllocationRecord {
                id: aid,
                provider_id: row.get("provider_id"),
                consumer_id: row.get("consumer_id"),
                resources,
            });
        }
        Ok(allocations)
    }

    async fn load_allocation_resources(
        &self,
        allocation_id: &str,
    ) -> Result<Vec<PlacementResourceRecord>, StoreError> {
        let rows = sqlx::query(
            "SELECT resource_class, amount FROM placement_allocation_resources WHERE allocation_id = $1 ORDER BY resource_class",
        )
        .bind(allocation_id)
        .fetch_all(&self.pool)
        .await
        .map_err(StoreError::Database)?;

        Ok(rows
            .into_iter()
            .map(|r| PlacementResourceRecord {
                resource_class: r.get("resource_class"),
                amount: r.get::<i64, _>("amount") as u64,
            })
            .collect())
    }

    async fn load_intent_resources(
        &self,
        intent_id: &str,
    ) -> Result<Vec<PlacementResourceRecord>, StoreError> {
        let rows = sqlx::query(
            "SELECT resource_class, amount FROM placement_allocation_intent_resources WHERE intent_id = $1 ORDER BY resource_class",
        )
        .bind(intent_id)
        .fetch_all(&self.pool)
        .await
        .map_err(StoreError::Database)?;

        Ok(rows
            .into_iter()
            .map(|r| PlacementResourceRecord {
                resource_class: r.get("resource_class"),
                amount: r.get::<i64, _>("amount") as u64,
            })
            .collect())
    }
}
