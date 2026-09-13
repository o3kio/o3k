use super::{
    SqliteStore,
    helpers::{
        placement_allocation_from_row, placement_i64, placement_intent_from_row,
        placement_inventory_from_row, placement_provider_from_row, placement_resource_from_row,
        placement_u64, resource_from_row,
    },
};
use async_trait::async_trait;
use sqlx::Row;
use uuid::Uuid;

use crate::{
    ObservationUpdate, PlacementAllocationRecord, PlacementCapacityClassRecord,
    PlacementCapacitySummary, PlacementIntentRecord, PlacementInventoryRecord,
    PlacementProviderRecord, PlacementProviderStateRecord, PlacementReconcileRecord,
    PlacementRepository, PlacementResourceRecord, ResourceRecord, StoreError,
};

impl SqliteStore {
    pub async fn register_provider_metadata(
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

    pub async fn update_provider_metadata(
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
            sqlx::query_scalar("SELECT generation FROM placement_providers WHERE id = ?")
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
                sqlx::query_scalar("SELECT id FROM placement_providers WHERE id = ?")
                    .bind(parent)
                    .fetch_optional(&mut *tx)
                    .await
                    .map_err(StoreError::Database)?;
            if exists.is_none() {
                return Err(StoreError::PlacementProviderNotFound);
            }
        }
        // Validate the complete proposed ancestor chain while the write
        // transaction holds SQLite's writer lock.  This closes the race where
        // two concurrent updates could otherwise create A -> B and B -> A.
        let hierarchy_rows =
            sqlx::query("SELECT id, parent_provider_id FROM placement_providers ORDER BY id")
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
        let updated = sqlx::query("UPDATE placement_providers SET parent_provider_id = ?, location = ?, generation = generation + 1 WHERE id = ? AND generation = ?")
            .bind(parent_provider_id).bind(location).bind(provider_id).bind(i64::try_from(expected_generation).map_err(|_| StoreError::Corrupt("generation out of range".to_owned()))?)
            .execute(&mut *tx).await.map_err(StoreError::Database)?;
        if updated.rows_affected() != 1 {
            return Err(StoreError::PlacementStaleGeneration);
        }
        sqlx::query("DELETE FROM placement_provider_traits WHERE provider_id = ?")
            .bind(provider_id)
            .execute(&mut *tx)
            .await
            .map_err(StoreError::Database)?;
        for value in traits
            .iter()
            .map(String::as_str)
            .collect::<std::collections::BTreeSet<_>>()
        {
            sqlx::query("INSERT INTO placement_provider_traits(provider_id, trait) VALUES (?, ?)")
                .bind(provider_id)
                .bind(value)
                .execute(&mut *tx)
                .await
                .map_err(StoreError::Database)?;
        }
        sqlx::query("DELETE FROM placement_provider_failure_domains WHERE provider_id = ?")
            .bind(provider_id)
            .execute(&mut *tx)
            .await
            .map_err(StoreError::Database)?;
        for value in failure_domains
            .iter()
            .map(String::as_str)
            .collect::<std::collections::BTreeSet<_>>()
        {
            sqlx::query("INSERT INTO placement_provider_failure_domains(provider_id, failure_domain_id) VALUES (?, ?)").bind(provider_id).bind(value).execute(&mut *tx).await.map_err(StoreError::Database)?;
        }
        tx.commit().await.map_err(StoreError::Database)?;
        self.get_provider(provider_id)
            .await?
            .ok_or(StoreError::PlacementProviderNotFound)
    }
    pub async fn get_provider(
        &self,
        provider_id: &str,
    ) -> Result<Option<PlacementProviderRecord>, StoreError> {
        let row = sqlx::query(
            "SELECT id, node_id, state, generation, parent_provider_id, location FROM placement_providers WHERE id = ?",
        )
        .bind(provider_id)
        .fetch_optional(&self.pool)
        .await
        .map_err(StoreError::Database)?;
        let Some(row) = row else {
            return Ok(None);
        };
        let mut provider = placement_provider_from_row(&row)?;
        provider.inventories = self.load_placement_inventories(provider_id).await?;
        provider.allocations = self.load_placement_allocations(provider_id).await?;
        provider.traits = self.load_provider_traits(provider_id).await?;
        provider.failure_domains = self.load_provider_failure_domains(provider_id).await?;
        Ok(Some(provider))
    }

    pub async fn list_providers(&self) -> Result<Vec<PlacementProviderRecord>, StoreError> {
        let rows = sqlx::query(
            "SELECT id, node_id, state, generation, parent_provider_id, location FROM placement_providers ORDER BY id",
        )
        .fetch_all(&self.pool)
        .await
        .map_err(StoreError::Database)?;
        let mut providers = Vec::new();
        for row in rows {
            let provider_id: String = row.get("id");
            let mut provider = placement_provider_from_row(&row)?;
            provider.inventories = self.load_placement_inventories(&provider_id).await?;
            provider.allocations = self.load_placement_allocations(&provider_id).await?;
            provider.traits = self.load_provider_traits(&provider_id).await?;
            provider.failure_domains = self.load_provider_failure_domains(&provider_id).await?;
            providers.push(provider);
        }
        Ok(providers)
    }

    pub async fn list_providers_bounded(
        &self,
        after_id: Option<&str>,
        limit: usize,
    ) -> Result<Vec<PlacementProviderRecord>, StoreError> {
        let limit = i64::try_from(limit)
            .map_err(|_| StoreError::Corrupt("placement page limit out of range".to_owned()))?;
        let rows = sqlx::query(
            "SELECT id, node_id, state, generation, parent_provider_id, location FROM placement_providers \
             WHERE (?1 IS NULL OR id > ?1) \
             ORDER BY id \
             LIMIT ?2",
        )
        .bind(after_id)
        .bind(limit)
        .fetch_all(&self.pool)
        .await
        .map_err(StoreError::Database)?;
        let mut providers = Vec::with_capacity(rows.len());
        for row in rows {
            let provider_id: String = row.get("id");
            let mut provider = placement_provider_from_row(&row)?;
            // Inventories only: allocations are intentionally omitted (see
            // the port contract). `used` already reflects durable allocation.
            provider.inventories = self.load_placement_inventories(&provider_id).await?;
            provider.traits = self.load_provider_traits(&provider_id).await?;
            provider.failure_domains = self.load_provider_failure_domains(&provider_id).await?;
            providers.push(provider);
        }
        Ok(providers)
    }

    pub async fn list_provider_states(
        &self,
        after_id: Option<&str>,
        limit: usize,
    ) -> Result<Vec<PlacementProviderStateRecord>, StoreError> {
        let limit = i64::try_from(limit)
            .map_err(|_| StoreError::Corrupt("placement page limit out of range".to_owned()))?;
        let rows = sqlx::query(
            "SELECT id, state FROM placement_providers \
             WHERE (?1 IS NULL OR id > ?1) \
             ORDER BY id \
             LIMIT ?2",
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
                    COALESCE(SUM(CAST(total * allocation_ratio AS INTEGER)), 0) AS allocatable, \
                    COALESCE(SUM(reserved), 0) AS reserved, \
                    COALESCE(SUM(used), 0) AS allocated \
             FROM placement_inventories \
             GROUP BY resource_class \
             ORDER BY resource_class \
             LIMIT ?",
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
                allocatable: placement_u64(row.get("allocatable"))?,
                reserved: placement_u64(row.get("reserved"))?,
                allocated: placement_u64(row.get("allocated"))?,
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
            let count = placement_u64(row.get("provider_count"))?;
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
        // Providers with at least one resource class over-allocated beyond
        // allocatable (a drifted/corrupt durable invariant). This lets the
        // diagnostics projection degrade capacity even when one provider's
        // over-allocation is masked by another provider's slack.
        let over_allocated: i64 = sqlx::query_scalar(
            "SELECT COUNT(DISTINCT provider_id) FROM placement_inventories \
             WHERE used > CAST(total * allocation_ratio AS INTEGER) - reserved",
        )
        .fetch_one(&self.pool)
        .await
        .map_err(StoreError::Database)?;
        summary.providers_over_allocated = placement_u64(over_allocated)?;
        Ok(summary)
    }

    async fn load_placement_inventories(
        &self,
        provider_id: &str,
    ) -> Result<Vec<PlacementInventoryRecord>, StoreError> {
        let rows = sqlx::query(
            "SELECT resource_class, total, reserved, allocation_ratio, used FROM placement_inventories WHERE provider_id = ? ORDER BY resource_class",
        )
        .bind(provider_id)
        .fetch_all(&self.pool)
        .await
        .map_err(StoreError::Database)?;
        rows.iter().map(placement_inventory_from_row).collect()
    }

    async fn load_provider_traits(&self, provider_id: &str) -> Result<Vec<String>, StoreError> {
        let rows = sqlx::query(
            "SELECT trait FROM placement_provider_traits WHERE provider_id = ? ORDER BY trait",
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
        let rows = sqlx::query("SELECT failure_domain_id FROM placement_provider_failure_domains WHERE provider_id = ? ORDER BY failure_domain_id")
            .bind(provider_id).fetch_all(&self.pool).await.map_err(StoreError::Database)?;
        Ok(rows
            .iter()
            .map(|row| row.get("failure_domain_id"))
            .collect())
    }

    async fn load_placement_allocations(
        &self,
        provider_id: &str,
    ) -> Result<Vec<PlacementAllocationRecord>, StoreError> {
        let rows = sqlx::query(
            "SELECT id, provider_id, consumer_id FROM placement_allocations WHERE provider_id = ? ORDER BY id",
        )
        .bind(provider_id)
        .fetch_all(&self.pool)
        .await
        .map_err(StoreError::Database)?;
        let mut allocations = Vec::new();
        for row in rows {
            let allocation_id: String = row.get("id");
            let mut allocation = placement_allocation_from_row(&row)?;
            allocation.resources = self.load_allocation_resources(&allocation_id).await?;
            allocations.push(allocation);
        }
        Ok(allocations)
    }

    async fn load_allocation_resources(
        &self,
        allocation_id: &str,
    ) -> Result<Vec<PlacementResourceRecord>, StoreError> {
        let rows = sqlx::query(
            "SELECT resource_class, amount FROM placement_allocation_resources WHERE allocation_id = ? ORDER BY resource_class",
        )
        .bind(allocation_id)
        .fetch_all(&self.pool)
        .await
        .map_err(StoreError::Database)?;
        rows.iter().map(placement_resource_from_row).collect()
    }

    async fn load_placement_intents(&self) -> Result<Vec<PlacementIntentRecord>, StoreError> {
        let rows = sqlx::query(
            "SELECT id, provider_id, consumer_id FROM placement_allocation_intents ORDER BY id",
        )
        .fetch_all(&self.pool)
        .await
        .map_err(StoreError::Database)?;
        let mut intents = Vec::new();
        for row in rows {
            let intent_id: String = row.get("id");
            let mut intent = placement_intent_from_row(&row)?;
            intent.resources = self.load_intent_resources(&intent_id).await?;
            intents.push(intent);
        }
        Ok(intents)
    }

    async fn load_intent_resources(
        &self,
        intent_id: &str,
    ) -> Result<Vec<PlacementResourceRecord>, StoreError> {
        let rows = sqlx::query(
            "SELECT resource_class, amount FROM placement_allocation_intent_resources WHERE intent_id = ? ORDER BY resource_class",
        )
        .bind(intent_id)
        .fetch_all(&self.pool)
        .await
        .map_err(StoreError::Database)?;
        rows.iter().map(placement_resource_from_row).collect()
    }

    /// Recomputes the `used` amount per inventory class from the durable
    /// allocations of the provider. Reported `used` values are never trusted:
    /// usage is derived from the allocation rows so a capability refresh
    /// cannot erase reservations or make them available twice.
    async fn recompute_placement_used(
        connection: &mut sqlx::sqlite::SqliteConnection,
        provider_id: &str,
        inventories: &[PlacementInventoryRecord],
    ) -> Result<Vec<u64>, StoreError> {
        let mut used = Vec::with_capacity(inventories.len());
        for inventory in inventories {
            let sum: i64 = sqlx::query_scalar(
                "SELECT COALESCE(SUM(r.amount), 0) FROM placement_allocations a JOIN placement_allocation_resources r ON r.allocation_id = a.id WHERE a.provider_id = ? AND r.resource_class = ?",
            )
            .bind(provider_id)
            .bind(&inventory.resource_class)
            .fetch_one(&mut *connection)
            .await
            .map_err(StoreError::Database)?;
            used.push(placement_u64(sum)?);
        }
        Ok(used)
    }

    /// Replaces the inventory rows of a provider, applying the recomputed
    /// `used` values alongside the caller-supplied totals.
    async fn replace_placement_inventories(
        connection: &mut sqlx::sqlite::SqliteConnection,
        provider_id: &str,
        inventories: &[PlacementInventoryRecord],
        used: &[u64],
    ) -> Result<(), StoreError> {
        sqlx::query("DELETE FROM placement_inventories WHERE provider_id = ?")
            .bind(provider_id)
            .execute(&mut *connection)
            .await
            .map_err(StoreError::Database)?;
        for (inventory, used) in inventories.iter().zip(used) {
            sqlx::query(
                "INSERT INTO placement_inventories (provider_id, resource_class, total, reserved, allocation_ratio, used) VALUES (?, ?, ?, ?, ?, ?)",
            )
            .bind(provider_id)
            .bind(&inventory.resource_class)
            .bind(placement_i64(inventory.total)?)
            .bind(placement_i64(inventory.reserved)?)
            .bind(inventory.allocation_ratio)
            .bind(placement_i64(*used)?)
            .execute(&mut *connection)
            .await
            .map_err(StoreError::Database)?;
        }
        Ok(())
    }

    /// Loads one allocation with its resources inside a transaction.
    async fn load_allocation_in_transaction(
        connection: &mut sqlx::sqlite::SqliteConnection,
        allocation_id: &str,
    ) -> Result<Option<PlacementAllocationRecord>, StoreError> {
        let row = sqlx::query(
            "SELECT id, provider_id, consumer_id FROM placement_allocations WHERE id = ?",
        )
        .bind(allocation_id)
        .fetch_optional(&mut *connection)
        .await
        .map_err(StoreError::Database)?;
        let Some(row) = row else {
            return Ok(None);
        };
        let mut allocation = placement_allocation_from_row(&row)?;
        let rows = sqlx::query(
            "SELECT resource_class, amount FROM placement_allocation_resources WHERE allocation_id = ? ORDER BY resource_class",
        )
        .bind(allocation_id)
        .fetch_all(&mut *connection)
        .await
        .map_err(StoreError::Database)?;
        allocation.resources = rows
            .iter()
            .map(placement_resource_from_row)
            .collect::<Result<_, _>>()?;
        Ok(Some(allocation))
    }

    /// Loads one allocation with its resources inside a transaction, scoped
    /// to the owning provider: an allocation committed on another provider
    /// is not visible to this lookup.
    async fn load_allocation_in_transaction_for_provider(
        connection: &mut sqlx::sqlite::SqliteConnection,
        allocation_id: &str,
        provider_id: &str,
    ) -> Result<Option<PlacementAllocationRecord>, StoreError> {
        let row = sqlx::query(
            "SELECT id, provider_id, consumer_id FROM placement_allocations WHERE id = ? AND provider_id = ?",
        )
        .bind(allocation_id)
        .bind(provider_id)
        .fetch_optional(&mut *connection)
        .await
        .map_err(StoreError::Database)?;
        let Some(row) = row else {
            return Ok(None);
        };
        let mut allocation = placement_allocation_from_row(&row)?;
        let rows = sqlx::query(
            "SELECT resource_class, amount FROM placement_allocation_resources WHERE allocation_id = ? ORDER BY resource_class",
        )
        .bind(allocation_id)
        .fetch_all(&mut *connection)
        .await
        .map_err(StoreError::Database)?;
        allocation.resources = rows
            .iter()
            .map(placement_resource_from_row)
            .collect::<Result<_, _>>()?;
        Ok(Some(allocation))
    }

    /// Loads one intent with its resources inside a transaction.
    async fn load_intent_in_transaction(
        connection: &mut sqlx::sqlite::SqliteConnection,
        intent_id: &str,
    ) -> Result<Option<PlacementIntentRecord>, StoreError> {
        let row = sqlx::query(
            "SELECT id, provider_id, consumer_id FROM placement_allocation_intents WHERE id = ?",
        )
        .bind(intent_id)
        .fetch_optional(&mut *connection)
        .await
        .map_err(StoreError::Database)?;
        let Some(row) = row else {
            return Ok(None);
        };
        let mut intent = placement_intent_from_row(&row)?;
        let rows = sqlx::query(
            "SELECT resource_class, amount FROM placement_allocation_intent_resources WHERE intent_id = ? ORDER BY resource_class",
        )
        .bind(intent_id)
        .fetch_all(&mut *connection)
        .await
        .map_err(StoreError::Database)?;
        intent.resources = rows
            .iter()
            .map(placement_resource_from_row)
            .collect::<Result<_, _>>()?;
        Ok(Some(intent))
    }

    fn validate_placement_allocation(
        allocation: &PlacementAllocationRecord,
    ) -> Result<(), StoreError> {
        if allocation.id.is_empty()
            || allocation.provider_id.is_empty()
            || allocation.consumer_id.is_empty()
            || allocation.resources.is_empty()
            || allocation
                .resources
                .iter()
                .any(|resource| resource.amount == 0)
        {
            return Err(StoreError::Corrupt(
                "invalid placement allocation".to_owned(),
            ));
        }
        Ok(())
    }

    fn validate_placement_intent(intent: &PlacementIntentRecord) -> Result<(), StoreError> {
        if intent.id.is_empty()
            || intent.provider_id.is_empty()
            || intent.consumer_id.is_empty()
            || intent.resources.is_empty()
            || intent.resources.iter().any(|resource| resource.amount == 0)
        {
            return Err(StoreError::Corrupt(
                "invalid placement allocation intent".to_owned(),
            ));
        }
        Ok(())
    }

    /// Finalizes a BEGIN IMMEDIATE transaction: COMMIT on success, or a
    /// best-effort ROLLBACK preserving the original error on failure. BEGIN
    /// IMMEDIATE acquires the write lock up front so the configured
    /// busy_timeout applies instead of failing immediately with
    /// SQLITE_BUSY_SNAPSHOT on the deferred read-to-write upgrade.
    pub(crate) async fn commit_or_rollback<T>(
        connection: &mut sqlx::sqlite::SqliteConnection,
        outcome: Result<T, StoreError>,
    ) -> Result<T, StoreError> {
        match outcome {
            Ok(value) => match sqlx::query("COMMIT").execute(&mut *connection).await {
                Ok(_) => Ok(value),
                Err(error) => {
                    let _ = sqlx::query("ROLLBACK").execute(&mut *connection).await;
                    Err(StoreError::Database(error))
                }
            },
            Err(error) => {
                let _ = sqlx::query("ROLLBACK").execute(&mut *connection).await;
                Err(error)
            }
        }
    }

    pub async fn register_provider(
        &self,
        node_id: &str,
        inventories: &[PlacementInventoryRecord],
    ) -> Result<PlacementProviderRecord, StoreError> {
        let mut connection = self.pool.acquire().await.map_err(StoreError::Database)?;
        sqlx::query("BEGIN IMMEDIATE")
            .execute(&mut *connection)
            .await
            .map_err(StoreError::Database)?;
        let outcome: Result<(), StoreError> = async {
            sqlx::query(
                "INSERT OR IGNORE INTO placement_providers (id, node_id, state, generation) VALUES (?, ?, 'Enabled', 0)",
            )
            .bind(node_id)
            .bind(node_id)
            .execute(&mut *connection)
            .await
            .map_err(StoreError::Database)?;
            let used = SqliteStore::recompute_placement_used(&mut connection, node_id, inventories)
                .await?;
            SqliteStore::replace_placement_inventories(
                &mut connection,
                node_id,
                inventories,
                &used,
            )
            .await?;
            sqlx::query(
                "UPDATE placement_providers SET generation = generation + 1 WHERE id = ?",
            )
            .bind(node_id)
            .execute(&mut *connection)
            .await
            .map_err(StoreError::Database)?;
            Ok(())
        }
        .await;
        SqliteStore::commit_or_rollback(&mut connection, outcome).await?;
        drop(connection);
        self.get_provider(node_id)
            .await?
            .ok_or(StoreError::PlacementProviderNotFound)
    }

    pub async fn sync_provider(
        &self,
        node_id: &str,
        state: &str,
        inventories: &[PlacementInventoryRecord],
    ) -> Result<PlacementProviderRecord, StoreError> {
        if state.is_empty() {
            return Err(StoreError::Corrupt(
                "placement provider state is empty".to_owned(),
            ));
        }
        let mut connection = self.pool.acquire().await.map_err(StoreError::Database)?;
        sqlx::query("BEGIN IMMEDIATE")
            .execute(&mut *connection)
            .await
            .map_err(StoreError::Database)?;
        let outcome: Result<(), StoreError> = async {
            sqlx::query(
                "INSERT OR IGNORE INTO placement_providers (id, node_id, state, generation) VALUES (?, ?, ?, 0)",
            )
            .bind(node_id)
            .bind(node_id)
            .bind(state)
            .execute(&mut *connection)
            .await
            .map_err(StoreError::Database)?;
            sqlx::query("UPDATE placement_providers SET state = ? WHERE id = ?")
                .bind(state)
                .bind(node_id)
                .execute(&mut *connection)
                .await
                .map_err(StoreError::Database)?;
            let used = SqliteStore::recompute_placement_used(&mut connection, node_id, inventories)
                .await?;
            SqliteStore::replace_placement_inventories(
                &mut connection,
                node_id,
                inventories,
                &used,
            )
            .await?;
            sqlx::query(
                "UPDATE placement_providers SET generation = generation + 1 WHERE id = ?",
            )
            .bind(node_id)
            .execute(&mut *connection)
            .await
            .map_err(StoreError::Database)?;
            Ok(())
        }
        .await;
        SqliteStore::commit_or_rollback(&mut connection, outcome).await?;
        drop(connection);
        self.get_provider(node_id)
            .await?
            .ok_or(StoreError::PlacementProviderNotFound)
    }

    pub async fn refresh_inventories(
        &self,
        provider_id: &str,
        expected_generation: u64,
        inventories: &[PlacementInventoryRecord],
    ) -> Result<PlacementProviderRecord, StoreError> {
        let mut connection = self.pool.acquire().await.map_err(StoreError::Database)?;
        sqlx::query("BEGIN IMMEDIATE")
            .execute(&mut *connection)
            .await
            .map_err(StoreError::Database)?;
        let outcome: Result<(), StoreError> = async {
            let row = sqlx::query("SELECT id FROM placement_providers WHERE id = ?")
                .bind(provider_id)
                .fetch_optional(&mut *connection)
                .await
                .map_err(StoreError::Database)?;
            if row.is_none() {
                return Err(StoreError::PlacementProviderNotFound);
            }
            let result = sqlx::query(
                "UPDATE placement_providers SET generation = generation + 1 WHERE id = ? AND generation = ?",
            )
            .bind(provider_id)
            .bind(placement_i64(expected_generation)?)
            .execute(&mut *connection)
            .await
            .map_err(StoreError::Database)?;
            if result.rows_affected() == 0 {
                return Err(StoreError::PlacementStaleGeneration);
            }
            let used = SqliteStore::recompute_placement_used(
                &mut connection,
                provider_id,
                inventories,
            )
            .await?;
            SqliteStore::replace_placement_inventories(
                &mut connection,
                provider_id,
                inventories,
                &used,
            )
            .await?;
            Ok(())
        }
        .await;
        SqliteStore::commit_or_rollback(&mut connection, outcome).await?;
        drop(connection);
        self.get_provider(provider_id)
            .await?
            .ok_or(StoreError::PlacementProviderNotFound)
    }

    pub async fn set_provider_state(
        &self,
        provider_id: &str,
        state: &str,
    ) -> Result<(), StoreError> {
        if state.is_empty() {
            return Err(StoreError::Corrupt(
                "placement provider state is empty".to_owned(),
            ));
        }
        let mut connection = self.pool.acquire().await.map_err(StoreError::Database)?;
        sqlx::query("BEGIN IMMEDIATE")
            .execute(&mut *connection)
            .await
            .map_err(StoreError::Database)?;
        let outcome: Result<(), StoreError> = async {
            let row = sqlx::query("SELECT id FROM placement_providers WHERE id = ?")
                .bind(provider_id)
                .fetch_optional(&mut *connection)
                .await
                .map_err(StoreError::Database)?;
            if row.is_none() {
                return Err(StoreError::PlacementProviderNotFound);
            }
            sqlx::query(
                "UPDATE placement_providers SET state = ?, generation = generation + 1 WHERE id = ?",
            )
            .bind(state)
            .bind(provider_id)
            .execute(&mut *connection)
            .await
            .map_err(StoreError::Database)?;
            Ok(())
        }
        .await;
        SqliteStore::commit_or_rollback(&mut connection, outcome).await
    }

    /// Commits one allocation to a provider. Allocation ids are globally
    /// unique: a same-id allocation on another provider is a conflict, not
    /// an idempotent retry. This prevents double allocation, which the
    /// legacy in-memory ledger could not.
    pub async fn commit_allocation(
        &self,
        provider_id: &str,
        expected_generation: u64,
        allocation: &PlacementAllocationRecord,
    ) -> Result<PlacementAllocationRecord, StoreError> {
        Self::validate_placement_allocation(allocation)?;
        let mut connection = self.pool.acquire().await.map_err(StoreError::Database)?;
        sqlx::query("BEGIN IMMEDIATE")
            .execute(&mut *connection)
            .await
            .map_err(StoreError::Database)?;
        let outcome: Result<PlacementAllocationRecord, StoreError> = async {
            let existing = SqliteStore::load_allocation_in_transaction(
                &mut connection,
                &allocation.id,
            )
            .await?;
            if let Some(existing) = existing {
                if existing == *allocation {
                    return Ok(existing);
                }
                return Err(StoreError::PlacementAllocationConflict);
            }
            let provider_row = sqlx::query("SELECT id FROM placement_providers WHERE id = ?")
                .bind(provider_id)
                .fetch_optional(&mut *connection)
                .await
                .map_err(StoreError::Database)?;
            if provider_row.is_none() {
                return Err(StoreError::PlacementProviderNotFound);
            }
            let result = sqlx::query(
                "UPDATE placement_providers SET generation = generation + 1 WHERE id = ? AND generation = ?",
            )
            .bind(provider_id)
            .bind(placement_i64(expected_generation)?)
            .execute(&mut *connection)
            .await
            .map_err(StoreError::Database)?;
            if result.rows_affected() == 0 {
                return Err(StoreError::PlacementStaleGeneration);
            }
            for resource in &allocation.resources {
                sqlx::query(
                    "UPDATE placement_inventories SET used = used + ? WHERE provider_id = ? AND resource_class = ?",
                )
                .bind(placement_i64(resource.amount)?)
                .bind(provider_id)
                .bind(&resource.resource_class)
                .execute(&mut *connection)
                .await
                .map_err(StoreError::Database)?;
            }
            sqlx::query(
                "INSERT INTO placement_allocations (id, provider_id, consumer_id) VALUES (?, ?, ?)",
            )
            .bind(&allocation.id)
            .bind(&allocation.provider_id)
            .bind(&allocation.consumer_id)
            .execute(&mut *connection)
            .await
            .map_err(StoreError::Database)?;
            for resource in &allocation.resources {
                sqlx::query(
                    "INSERT INTO placement_allocation_resources (allocation_id, resource_class, amount) VALUES (?, ?, ?)",
                )
                .bind(&allocation.id)
                .bind(&resource.resource_class)
                .bind(placement_i64(resource.amount)?)
                .execute(&mut *connection)
                .await
                .map_err(StoreError::Database)?;
            }
            Ok(allocation.clone())
        }
        .await;
        SqliteStore::commit_or_rollback(&mut connection, outcome).await
    }

    pub async fn release_allocation(
        &self,
        provider_id: &str,
        allocation_id: &str,
    ) -> Result<(), StoreError> {
        let mut connection = self.pool.acquire().await.map_err(StoreError::Database)?;
        sqlx::query("BEGIN IMMEDIATE")
            .execute(&mut *connection)
            .await
            .map_err(StoreError::Database)?;
        let outcome: Result<(), StoreError> = async {
            let provider_row = sqlx::query("SELECT id FROM placement_providers WHERE id = ?")
                .bind(provider_id)
                .fetch_optional(&mut *connection)
                .await
                .map_err(StoreError::Database)?;
            if provider_row.is_none() {
                return Err(StoreError::PlacementProviderNotFound);
            }
            // The allocation is scoped to the owning provider: an
            // allocation committed on another provider is not visible here,
            // mirroring the per-provider in-memory ledger where a
            // wrong-provider release is a no-op without a generation bump.
            let Some(existing) = SqliteStore::load_allocation_in_transaction_for_provider(
                &mut connection,
                allocation_id,
                provider_id,
            )
            .await?
            else {
                return Ok(());
            };
            sqlx::query("DELETE FROM placement_allocations WHERE id = ? AND provider_id = ?")
                .bind(allocation_id)
                .bind(provider_id)
                .execute(&mut *connection)
                .await
                .map_err(StoreError::Database)?;
            for resource in &existing.resources {
                sqlx::query(
                    "UPDATE placement_inventories SET used = MAX(used - ?, 0) WHERE provider_id = ? AND resource_class = ?",
                )
                .bind(placement_i64(resource.amount)?)
                .bind(provider_id)
                .bind(&resource.resource_class)
                .execute(&mut *connection)
                .await
                .map_err(StoreError::Database)?;
            }
            sqlx::query("UPDATE placement_providers SET generation = generation + 1 WHERE id = ?")
                .bind(provider_id)
                .execute(&mut *connection)
                .await
                .map_err(StoreError::Database)?;
            Ok(())
        }
        .await;
        SqliteStore::commit_or_rollback(&mut connection, outcome).await
    }

    pub async fn upsert_intent(
        &self,
        intent: &PlacementIntentRecord,
    ) -> Result<PlacementIntentRecord, StoreError> {
        Self::validate_placement_intent(intent)?;
        let mut connection = self.pool.acquire().await.map_err(StoreError::Database)?;
        sqlx::query("BEGIN IMMEDIATE")
            .execute(&mut *connection)
            .await
            .map_err(StoreError::Database)?;
        let outcome: Result<PlacementIntentRecord, StoreError> = async {
            sqlx::query(
                "INSERT OR IGNORE INTO placement_allocation_intents (id, provider_id, consumer_id) VALUES (?, ?, ?)",
            )
            .bind(&intent.id)
            .bind(&intent.provider_id)
            .bind(&intent.consumer_id)
            .execute(&mut *connection)
            .await
            .map_err(StoreError::Database)?;
            for resource in &intent.resources {
                sqlx::query(
                    "INSERT OR IGNORE INTO placement_allocation_intent_resources (intent_id, resource_class, amount) VALUES (?, ?, ?)",
                )
                .bind(&intent.id)
                .bind(&resource.resource_class)
                .bind(placement_i64(resource.amount)?)
                .execute(&mut *connection)
                .await
                .map_err(StoreError::Database)?;
            }
            let Some(stored) =
                SqliteStore::load_intent_in_transaction(&mut connection, &intent.id).await?
            else {
                return Err(StoreError::PlacementIntentConflict);
            };
            if stored == *intent {
                Ok(stored)
            } else {
                Err(StoreError::PlacementIntentConflict)
            }
        }
        .await;
        SqliteStore::commit_or_rollback(&mut connection, outcome).await
    }

    pub async fn get_intent(
        &self,
        allocation_id: &str,
    ) -> Result<Option<PlacementIntentRecord>, StoreError> {
        let row = sqlx::query(
            "SELECT id, provider_id, consumer_id FROM placement_allocation_intents WHERE id = ?",
        )
        .bind(allocation_id)
        .fetch_optional(&self.pool)
        .await
        .map_err(StoreError::Database)?;
        let Some(row) = row else {
            return Ok(None);
        };
        let mut intent = placement_intent_from_row(&row)?;
        intent.resources = self.load_intent_resources(&intent.id).await?;
        Ok(Some(intent))
    }

    pub async fn list_intents(&self) -> Result<Vec<PlacementIntentRecord>, StoreError> {
        self.load_placement_intents().await
    }

    pub async fn delete_intent(&self, allocation_id: &str) -> Result<(), StoreError> {
        sqlx::query("DELETE FROM placement_allocation_intents WHERE id = ?")
            .bind(allocation_id)
            .execute(&self.pool)
            .await
            .map_err(StoreError::Database)?;
        Ok(())
    }

    pub async fn reconcile_consumers(
        &self,
        durable_consumer_ids: &[String],
    ) -> Result<PlacementReconcileRecord, StoreError> {
        let mut connection = self.pool.acquire().await.map_err(StoreError::Database)?;
        sqlx::query("BEGIN IMMEDIATE")
            .execute(&mut *connection)
            .await
            .map_err(StoreError::Database)?;
        let outcome: Result<PlacementReconcileRecord, StoreError> = async {
            let mut allocations = Vec::new();
            let rows = sqlx::query(
                "SELECT id, provider_id, consumer_id FROM placement_allocations ORDER BY id",
            )
            .fetch_all(&mut *connection)
            .await
            .map_err(StoreError::Database)?;
            for row in rows {
                let allocation_id: String = row.get("id");
                let mut allocation = placement_allocation_from_row(&row)?;
                let resource_rows = sqlx::query(
                    "SELECT resource_class, amount FROM placement_allocation_resources WHERE allocation_id = ? ORDER BY resource_class",
                )
                .bind(&allocation_id)
                .fetch_all(&mut *connection)
                .await
                .map_err(StoreError::Database)?;
                allocation.resources = resource_rows
                    .iter()
                    .map(placement_resource_from_row)
                    .collect::<Result<_, _>>()?;
                allocations.push(allocation);
            }
            let mut intents = Vec::new();
            let rows = sqlx::query(
                "SELECT id, provider_id, consumer_id FROM placement_allocation_intents ORDER BY id",
            )
            .fetch_all(&mut *connection)
            .await
            .map_err(StoreError::Database)?;
            for row in rows {
                let intent_id: String = row.get("id");
                let mut intent = placement_intent_from_row(&row)?;
                let resource_rows = sqlx::query(
                    "SELECT resource_class, amount FROM placement_allocation_intent_resources WHERE intent_id = ? ORDER BY resource_class",
                )
                .bind(&intent_id)
                .fetch_all(&mut *connection)
                .await
                .map_err(StoreError::Database)?;
                intent.resources = resource_rows
                    .iter()
                    .map(placement_resource_from_row)
                    .collect::<Result<_, _>>()?;
                intents.push(intent);
            }
            // ASR-018: the caller-provided consumer snapshot may predate this
            // transaction. Re-check the durable compute-consumer resources
            // inside the same transaction (mirroring the caller's
            // `compute_instance` + non-DELETED filter) so a consumer that
            // became durable while the write lock was contended is never
            // treated as orphaned — an allocation must never be released
            // beneath a live consumer.
            let mut live_consumer_ids = durable_consumer_ids.to_vec();
            let resource_rows = sqlx::query(
                "SELECT id FROM resources WHERE kind = 'compute_instance' AND observed_state != 'DELETED'",
            )
            .fetch_all(&mut *connection)
            .await
            .map_err(StoreError::Database)?;
            for row in resource_rows {
                let id: String = row.get("id");
                if !live_consumer_ids.contains(&id) {
                    live_consumer_ids.push(id);
                }
            }
            let orphaned: Vec<PlacementAllocationRecord> = allocations
                .iter()
                .filter(|allocation| {
                    !live_consumer_ids
                        .iter()
                        .any(|consumer_id| consumer_id == &allocation.consumer_id)
                })
                .cloned()
                .collect();
            let abandoned: Vec<PlacementIntentRecord> = intents
                .iter()
                .filter(|intent| {
                    !live_consumer_ids
                        .iter()
                        .any(|consumer_id| consumer_id == &intent.consumer_id)
                })
                .cloned()
                .collect();
            let mut affected_providers = Vec::new();
            for allocation in &orphaned {
                if !affected_providers.contains(&allocation.provider_id) {
                    affected_providers.push(allocation.provider_id.clone());
                }
                sqlx::query("DELETE FROM placement_allocations WHERE id = ?")
                    .bind(&allocation.id)
                    .execute(&mut *connection)
                    .await
                    .map_err(StoreError::Database)?;
            }
            for provider_id in &affected_providers {
                sqlx::query(
                    "UPDATE placement_inventories SET used = COALESCE((SELECT SUM(r.amount) FROM placement_allocations a JOIN placement_allocation_resources r ON r.allocation_id = a.id WHERE a.provider_id = placement_inventories.provider_id AND r.resource_class = placement_inventories.resource_class), 0) WHERE provider_id = ?",
                )
                .bind(provider_id)
                .execute(&mut *connection)
                .await
                .map_err(StoreError::Database)?;
                sqlx::query(
                    "UPDATE placement_providers SET generation = generation + 1 WHERE id = ?",
                )
                .bind(provider_id)
                .execute(&mut *connection)
                .await
                .map_err(StoreError::Database)?;
            }
            for intent in &abandoned {
                sqlx::query("DELETE FROM placement_allocation_intents WHERE id = ?")
                    .bind(&intent.id)
                    .execute(&mut *connection)
                    .await
                    .map_err(StoreError::Database)?;
            }
            Ok(PlacementReconcileRecord {
                orphaned_allocations: orphaned,
                abandoned_intents: abandoned,
            })
        }
        .await;
        SqliteStore::commit_or_rollback(&mut connection, outcome).await
    }

    pub async fn import_provider(
        &self,
        provider: &PlacementProviderRecord,
    ) -> Result<(), StoreError> {
        let mut connection = self.pool.acquire().await.map_err(StoreError::Database)?;
        sqlx::query("BEGIN IMMEDIATE")
            .execute(&mut *connection)
            .await
            .map_err(StoreError::Database)?;
        let outcome: Result<(), StoreError> = async {
            sqlx::query(
                "INSERT OR IGNORE INTO placement_providers (id, node_id, state, generation) VALUES (?, ?, ?, ?)",
            )
            .bind(&provider.id)
            .bind(&provider.node_id)
            .bind(&provider.state)
            .bind(placement_i64(provider.generation)?)
            .execute(&mut *connection)
            .await
            .map_err(StoreError::Database)?;
            sqlx::query("UPDATE placement_providers SET parent_provider_id = ?, location = ? WHERE id = ?")
                .bind(&provider.parent_provider_id).bind(&provider.location).bind(&provider.id)
                .execute(&mut *connection).await.map_err(StoreError::Database)?;
            sqlx::query("DELETE FROM placement_provider_traits WHERE provider_id = ?").bind(&provider.id).execute(&mut *connection).await.map_err(StoreError::Database)?;
            for trait_name in &provider.traits {
                sqlx::query("INSERT INTO placement_provider_traits(provider_id, trait) VALUES (?, ?)").bind(&provider.id).bind(trait_name).execute(&mut *connection).await.map_err(StoreError::Database)?;
            }
            sqlx::query("DELETE FROM placement_provider_failure_domains WHERE provider_id = ?").bind(&provider.id).execute(&mut *connection).await.map_err(StoreError::Database)?;
            for domain in &provider.failure_domains {
                sqlx::query("INSERT INTO placement_provider_failure_domains(provider_id, failure_domain_id) VALUES (?, ?)").bind(&provider.id).bind(domain).execute(&mut *connection).await.map_err(StoreError::Database)?;
            }
            sqlx::query("DELETE FROM placement_inventories WHERE provider_id = ?")
                .bind(&provider.id)
                .execute(&mut *connection)
                .await
                .map_err(StoreError::Database)?;
            for inventory in &provider.inventories {
                sqlx::query(
                    "INSERT INTO placement_inventories (provider_id, resource_class, total, reserved, allocation_ratio, used) VALUES (?, ?, ?, ?, ?, ?)",
                )
                .bind(&provider.id)
                .bind(&inventory.resource_class)
                .bind(placement_i64(inventory.total)?)
                .bind(placement_i64(inventory.reserved)?)
                .bind(inventory.allocation_ratio)
                .bind(placement_i64(inventory.used)?)
                .execute(&mut *connection)
                .await
                .map_err(StoreError::Database)?;
            }
            for allocation in &provider.allocations {
                let exists: Option<i64> =
                    sqlx::query_scalar("SELECT 1 FROM placement_allocations WHERE id = ?")
                        .bind(&allocation.id)
                        .fetch_optional(&mut *connection)
                        .await
                        .map_err(StoreError::Database)?;
                if exists.is_some() {
                    continue;
                }
                sqlx::query(
                    "INSERT INTO placement_allocations (id, provider_id, consumer_id) VALUES (?, ?, ?)",
                )
                .bind(&allocation.id)
                .bind(&allocation.provider_id)
                .bind(&allocation.consumer_id)
                .execute(&mut *connection)
                .await
                .map_err(StoreError::Database)?;
                for resource in &allocation.resources {
                    sqlx::query(
                        "INSERT INTO placement_allocation_resources (allocation_id, resource_class, amount) VALUES (?, ?, ?)",
                    )
                    .bind(&allocation.id)
                    .bind(&resource.resource_class)
                    .bind(placement_i64(resource.amount)?)
                    .execute(&mut *connection)
                    .await
                    .map_err(StoreError::Database)?;
                }
            }
            Ok(())
        }
        .await;
        SqliteStore::commit_or_rollback(&mut connection, outcome).await
    }

    /// Runs one attempt of the observation update inside a BEGIN IMMEDIATE
    /// transaction. Errors are rolled back best-effort; the original error
    /// stays authoritative.
    pub(super) async fn apply_observation_update(
        &self,
        id: Uuid,
        update: &ObservationUpdate<'_>,
    ) -> Result<ResourceRecord, StoreError> {
        let mut connection = self.pool.acquire().await.map_err(StoreError::Database)?;
        sqlx::query("BEGIN IMMEDIATE")
            .execute(&mut *connection)
            .await
            .map_err(StoreError::Database)?;
        let outcome = self
            .observation_update_in_transaction(&mut connection, id, update)
            .await;
        match outcome {
            Ok(record) => match sqlx::query("COMMIT").execute(&mut *connection).await {
                Ok(_) => Ok(record),
                Err(error) => {
                    let _ = sqlx::query("ROLLBACK").execute(&mut *connection).await;
                    Err(StoreError::Database(error))
                }
            },
            Err(error) => {
                let _ = sqlx::query("ROLLBACK").execute(&mut *connection).await;
                Err(error)
            }
        }
    }

    async fn observation_update_in_transaction(
        &self,
        connection: &mut sqlx::sqlite::SqliteConnection,
        id: Uuid,
        update: &ObservationUpdate<'_>,
    ) -> Result<ResourceRecord, StoreError> {
        let ObservationUpdate {
            expected_generation,
            desired_state,
            observed_state,
            observed_generation,
            provider_id,
            agent_epoch,
            observation_sequence,
        } = update;
        let transaction = connection;
        let resource_row = sqlx::query("SELECT id, kind, project_id, generation, observed_generation, desired_state, observed_state, provider_id FROM resources WHERE id = ?")
            .bind(id.to_string())
            .fetch_optional(&mut *transaction)
            .await
            .map_err(StoreError::Database)?
            .ok_or(StoreError::ResourceNotFound)?;
        let current = resource_from_row(&resource_row)?;
        if current.generation != *expected_generation {
            return Err(StoreError::StaleGeneration);
        }
        let watermark = sqlx::query(
            "SELECT agent_epoch, observation_sequence FROM observation_watermarks WHERE resource_id = ?",
        )
        .bind(id.to_string())
        .fetch_optional(&mut *transaction)
        .await
        .map_err(StoreError::Database)?;
        if let Some(watermark) = watermark {
            let previous_epoch: String = watermark.get("agent_epoch");
            let previous_sequence: i64 = watermark.get("observation_sequence");
            if previous_epoch == *agent_epoch
                && *observation_sequence <= u64::try_from(previous_sequence).unwrap_or(u64::MAX)
            {
                // Already applied: committing the read-only transaction is
                // equivalent to the previous explicit rollback.
                return Ok(current);
            }
        }
        sqlx::query("UPDATE resources SET generation = generation + 1, desired_state = ?, observed_state = ?, observed_generation = ?, provider_id = ? WHERE id = ? AND generation = ?")
            .bind(*desired_state)
            .bind(*observed_state)
            .bind(*observed_generation)
            .bind(*provider_id)
            .bind(id.to_string())
            .bind(*expected_generation)
            .execute(&mut *transaction)
            .await
            .map_err(StoreError::Database)?;
        sqlx::query("INSERT INTO observation_watermarks (resource_id, agent_epoch, observation_sequence) VALUES (?, ?, ?) ON CONFLICT(resource_id) DO UPDATE SET agent_epoch = excluded.agent_epoch, observation_sequence = excluded.observation_sequence")
            .bind(id.to_string())
            .bind(*agent_epoch)
            .bind(i64::try_from(*observation_sequence).map_err(|_| StoreError::Corrupt("observation sequence exceeds SQLite range".to_owned()))?)
            .execute(&mut *transaction)
            .await
            .map_err(StoreError::Database)?;
        let updated_row = sqlx::query("SELECT id, kind, project_id, generation, observed_generation, desired_state, observed_state, provider_id FROM resources WHERE id = ?")
            .bind(id.to_string())
            .fetch_one(&mut *transaction)
            .await
            .map_err(StoreError::Database)?;
        let updated = resource_from_row(&updated_row)?;
        Ok(updated)
    }
}

#[async_trait]
impl PlacementRepository for SqliteStore {
    async fn get_provider(
        &self,
        provider_id: &str,
    ) -> Result<Option<PlacementProviderRecord>, StoreError> {
        self.get_provider(provider_id).await
    }

    async fn list_providers(&self) -> Result<Vec<PlacementProviderRecord>, StoreError> {
        self.list_providers().await
    }

    async fn list_providers_bounded(
        &self,
        after_id: Option<&str>,
        limit: usize,
    ) -> Result<Vec<PlacementProviderRecord>, StoreError> {
        self.list_providers_bounded(after_id, limit).await
    }

    async fn list_provider_states(
        &self,
        after_id: Option<&str>,
        limit: usize,
    ) -> Result<Vec<PlacementProviderStateRecord>, StoreError> {
        self.list_provider_states(after_id, limit).await
    }

    async fn capacity_summary(&self, limit: usize) -> Result<PlacementCapacitySummary, StoreError> {
        self.capacity_summary(limit).await
    }

    async fn register_provider(
        &self,
        node_id: &str,
        inventories: &[PlacementInventoryRecord],
    ) -> Result<PlacementProviderRecord, StoreError> {
        self.register_provider(node_id, inventories).await
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
        self.register_provider_metadata(
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
        self.update_provider_metadata(
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
        self.sync_provider(node_id, state, inventories).await
    }

    async fn refresh_inventories(
        &self,
        provider_id: &str,
        expected_generation: u64,
        inventories: &[PlacementInventoryRecord],
    ) -> Result<PlacementProviderRecord, StoreError> {
        self.refresh_inventories(provider_id, expected_generation, inventories)
            .await
    }

    async fn set_provider_state(&self, provider_id: &str, state: &str) -> Result<(), StoreError> {
        self.set_provider_state(provider_id, state).await
    }

    async fn commit_allocation(
        &self,
        provider_id: &str,
        expected_generation: u64,
        allocation: &PlacementAllocationRecord,
    ) -> Result<PlacementAllocationRecord, StoreError> {
        self.commit_allocation(provider_id, expected_generation, allocation)
            .await
    }

    async fn release_allocation(
        &self,
        provider_id: &str,
        allocation_id: &str,
    ) -> Result<(), StoreError> {
        self.release_allocation(provider_id, allocation_id).await
    }

    async fn upsert_intent(
        &self,
        intent: &PlacementIntentRecord,
    ) -> Result<PlacementIntentRecord, StoreError> {
        self.upsert_intent(intent).await
    }

    async fn get_intent(
        &self,
        allocation_id: &str,
    ) -> Result<Option<PlacementIntentRecord>, StoreError> {
        self.get_intent(allocation_id).await
    }

    async fn list_intents(&self) -> Result<Vec<PlacementIntentRecord>, StoreError> {
        self.list_intents().await
    }

    async fn delete_intent(&self, allocation_id: &str) -> Result<(), StoreError> {
        self.delete_intent(allocation_id).await
    }

    async fn reconcile_consumers(
        &self,
        durable_consumer_ids: &[String],
    ) -> Result<PlacementReconcileRecord, StoreError> {
        self.reconcile_consumers(durable_consumer_ids).await
    }

    async fn import_provider(&self, provider: &PlacementProviderRecord) -> Result<(), StoreError> {
        self.import_provider(provider).await
    }
}
