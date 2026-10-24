//! Read-only SQLite inspection helpers used by the backup capture and verify
//! paths.
//!
//! These queries own the raw SQL so the CLI backup modules stay at the
//! artifact/orchestration boundary. Every query here reads an open snapshot or
//! a private copy; none of them mutates the live store.

use sqlx::{Row as _, SqlitePool};

use crate::{
    SqliteStore, StoreError,
    state_inventory::{
        LiveCatalogObject, is_internal_sqlite_object, normalize_catalog_definition, sha256_hex,
    },
};

/// Enumerates the live `sqlite_master` objects of an open snapshot.
pub(crate) async fn live_catalog_objects(
    pool: &SqlitePool,
) -> Result<Vec<LiveCatalogObject>, StoreError> {
    let rows = sqlx::query(
        "SELECT type, name, sql FROM sqlite_master \
         WHERE sql IS NOT NULL AND name NOT GLOB 'sqlite_*' \
         ORDER BY type, name",
    )
    .fetch_all(pool)
    .await
    .map_err(StoreError::Database)?;
    let mut objects = Vec::with_capacity(rows.len());
    for row in rows {
        let kind: String = row.try_get(0).map_err(StoreError::Database)?;
        let name: String = row.try_get(1).map_err(StoreError::Database)?;
        let sql: String = row.try_get(2).map_err(StoreError::Database)?;
        if is_internal_sqlite_object(&name) {
            continue;
        }
        let definition = normalize_catalog_definition(&kind, &sql).ok_or_else(|| {
            StoreError::Corrupt(format!(
                "snapshot catalog object {kind} {name:?} has an unsupported definition"
            ))
        })?;
        objects.push(LiveCatalogObject {
            kind,
            name,
            definition_sha256: sha256_hex(&definition),
        });
    }
    Ok(objects)
}

/// Lists the live SQLite tables owned by the opened store.
pub(crate) async fn live_tables(store: &SqliteStore) -> Result<Vec<String>, StoreError> {
    sqlx::query_scalar(
        "SELECT name FROM sqlite_master \
         WHERE type = 'table' AND name NOT LIKE 'sqlite_%' \
         ORDER BY name",
    )
    .fetch_all(&store.pool)
    .await
    .map_err(StoreError::Database)
}
