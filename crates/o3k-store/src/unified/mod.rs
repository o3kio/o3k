//! Unified O3K store abstraction supporting both SQLite and PostgreSQL backends.

use std::path::Path;
use uuid::Uuid;

use crate::{
    DatabaseHealth, DurableStore, PostgresStore, ResourceRelationshipRecord, SqliteStore,
    StoreError,
};

mod audit;
mod building_block;
mod composition;
mod compute;
mod coordination;
mod core;
mod governance;
mod identity;
mod image;
mod metering;
mod network;
mod placement;
mod policy;
mod quota;
mod relationship;
mod storage;
mod topology;
mod volume_attachment;

#[derive(Clone, Debug)]
pub enum O3kStore {
    Sqlite(SqliteStore),
    Postgres(PostgresStore),
}

impl O3kStore {
    pub async fn connect_sqlite_file(path: &Path) -> Result<Self, StoreError> {
        let store = SqliteStore::connect_file(path).await?;
        Ok(Self::Sqlite(store))
    }

    pub async fn connect_sqlite_memory() -> Result<Self, StoreError> {
        let store = SqliteStore::connect("sqlite::memory:").await?;
        Ok(Self::Sqlite(store))
    }

    pub async fn connect_postgres(url: &str) -> Result<Self, StoreError> {
        let store = PostgresStore::connect(url).await?;
        Ok(Self::Postgres(store))
    }

    pub async fn database_health(&self) -> Result<DatabaseHealth, StoreError> {
        match self {
            Self::Sqlite(s) => s.database_health().await,
            Self::Postgres(s) => s.database_health().await,
        }
    }

    pub async fn readiness_check(&self) -> Result<(), StoreError> {
        match self {
            Self::Sqlite(s) => s.readiness_check().await,
            Self::Postgres(s) => s.readiness_check().await,
        }
    }

    pub async fn reserve_relationship(
        &self,
        record: &ResourceRelationshipRecord,
    ) -> Result<ResourceRelationshipRecord, StoreError> {
        match self {
            Self::Sqlite(store) => store.reserve_relationship(record).await,
            Self::Postgres(store) => store.reserve_relationship(record).await,
        }
    }

    pub async fn get_relationship(
        &self,
        parent: Uuid,
        slot: &str,
    ) -> Result<ResourceRelationshipRecord, StoreError> {
        match self {
            Self::Sqlite(store) => store.get_relationship(parent, slot).await,
            Self::Postgres(store) => store.get_relationship(parent, slot).await,
        }
    }

    pub async fn list_relationships(
        &self,
        parent: Uuid,
    ) -> Result<Vec<ResourceRelationshipRecord>, StoreError> {
        match self {
            Self::Sqlite(store) => store.list_relationships(parent).await,
            Self::Postgres(store) => store.list_relationships(parent).await,
        }
    }

    /// Dispatch the bounded relationship page to the concrete database store.
    /// This inherent method is intentionally distinct from the repository
    /// trait adapter so trait calls cannot recurse through the adapter.
    pub async fn list_relationships_page(
        &self,
        parent: Uuid,
        after_slot: Option<&str>,
        limit: u32,
    ) -> Result<Vec<ResourceRelationshipRecord>, StoreError> {
        match self {
            Self::Sqlite(store) => {
                store
                    .list_relationships_page(parent, after_slot, limit)
                    .await
            }
            Self::Postgres(store) => {
                store
                    .list_relationships_page(parent, after_slot, limit)
                    .await
            }
        }
    }

    pub async fn bind_relationship(
        &self,
        parent: Uuid,
        slot: &str,
        child: Uuid,
        child_operation: Uuid,
    ) -> Result<ResourceRelationshipRecord, StoreError> {
        match self {
            Self::Sqlite(store) => {
                store
                    .bind_relationship(parent, slot, child, child_operation)
                    .await
            }
            Self::Postgres(store) => {
                store
                    .bind_relationship(parent, slot, child, child_operation)
                    .await
            }
        }
    }

    pub async fn set_relationship_state(
        &self,
        parent: Uuid,
        slot: &str,
        state: &str,
    ) -> Result<ResourceRelationshipRecord, StoreError> {
        match self {
            Self::Sqlite(store) => store.set_relationship_state(parent, slot, state).await,
            Self::Postgres(store) => store.set_relationship_state(parent, slot, state).await,
        }
    }
}
