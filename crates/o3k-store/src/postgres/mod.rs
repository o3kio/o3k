use std::{str::FromStr, time::Duration};

use sqlx::{
    PgPool, Row,
    postgres::{PgConnectOptions, PgPoolOptions},
};

use crate::{DatabaseHealth, NetworkRepository, StoreError};

#[derive(Clone, Debug)]
pub struct PostgresStore {
    pub(crate) pool: PgPool,
}

mod audit_store;
mod bootstrap;
mod building_block;
mod composition;
mod compute;
mod core;
mod governance;
mod helpers;
mod identity;
mod image;
mod metering;
mod network;
mod placement;
mod quota;
mod relationship;
mod topology;
mod volume_attachment;

impl PostgresStore {
    pub async fn connect(database_url: &str) -> Result<Self, StoreError> {
        let options = PgConnectOptions::from_str(database_url).map_err(StoreError::Database)?;
        let pool = PgPoolOptions::new()
            .max_connections(50)
            .acquire_timeout(Duration::from_secs(5))
            .connect_with(options)
            .await
            .map_err(StoreError::Database)?;

        let store = Self { pool };
        store.migrate().await?;
        store.backfill_canonical_network_state().await?;
        Ok(store)
    }

    pub async fn connect_pool(pool: PgPool) -> Result<Self, StoreError> {
        let store = Self { pool };
        store.migrate().await?;
        store.backfill_canonical_network_state().await?;
        Ok(store)
    }

    pub async fn migrate(&self) -> Result<(), StoreError> {
        sqlx::migrate!("./migrations_postgres")
            .run(&self.pool)
            .await
            .map_err(StoreError::Migration)
    }

    #[must_use]
    pub fn pool(&self) -> &PgPool {
        &self.pool
    }

    pub async fn database_health(&self) -> Result<DatabaseHealth, StoreError> {
        let row = sqlx::query("SELECT version()")
            .fetch_one(&self.pool)
            .await
            .map_err(StoreError::Database)?;
        let ver: String = row.get(0);
        Ok(DatabaseHealth {
            status: "ok".to_owned(),
            journal_mode: "postgres".to_owned(),
            foreign_keys: true,
            integrity_check: ver,
            page_count: 0,
            page_size: 0,
            wal_checkpoint_status: None,
        })
    }

    pub async fn readiness_check(&self) -> Result<(), StoreError> {
        sqlx::query("SELECT 1")
            .execute(&self.pool)
            .await
            .map_err(StoreError::Database)?;
        Ok(())
    }

    #[doc(hidden)]
    pub async fn clean_tables_for_testing(&self) -> Result<(), StoreError> {
        sqlx::query(
            "TRUNCATE TABLE
                resources, operations, canonical_operation_metadata, idempotency_reservations,
                provider_refs, observation_watermarks,
                keypairs, server_keypairs, agent_commands, artifact_transfers,
                image_overlay_ownership, volume_attachments,
                federated_bindings, keystone_domains, keystone_projects, keystone_users, keystone_roles,
                keystone_role_assignments, keystone_services, keystone_endpoints, keystone_regions,
                image_metadata, network_intents, network_networks, network_subnets, network_ports,
                canonical_realm_encapsulation_bindings, canonical_endpoints, canonical_address_pools, canonical_address_realms, canonical_networks,
                network_security_group_bindings, network_security_group_rules, network_security_groups,
                placement_providers, placement_inventories, placement_allocations,
                placement_allocation_resources, placement_allocation_intents, placement_allocation_intent_resources,
                building_blocks,
                quota_limits, quota_reservations, quota_reservation_amounts,
                metering_authority, metering_intervals, metering_aggregates,
                topology_regions, topology_availability_domains, failure_domains, topology_bindings,
                controller_sessions, work_leases
            CASCADE",
        )
        .execute(&self.pool)
        .await
        .map_err(StoreError::Database)?;
        Ok(())
    }
}
