//! Read-only live PostgreSQL catalog inspection used by the state-inventory
//! capture comparison.
//!
//! Every query stays inside the approved PostgreSQL persistence boundary, so
//! `state_inventory` keeps only orchestration and identity rules.
//!
//! PostgreSQL stores no authored DDL. The reader therefore reports object
//! identity (`kind`, `name`) plus the `pg_get_*` rendering for diagnostics.
//! Explicitly named constraints are intentionally not enumerated: `pg_constraint`
//! cannot distinguish a reviewed named constraint from an implicitly named
//! `PRIMARY KEY`/`UNIQUE`/`FOREIGN KEY`/`CHECK`, and those implicit constraints
//! live inside the owning table's baseline digest.

use sqlx::{PgPool, Row as _};

use crate::{StoreError, state_inventory::PostgresLiveCatalogObject};

/// Enumerates tables, views, sequences, explicit indexes, functions and
/// triggers in the current schema of an open PostgreSQL database.
pub(crate) async fn live_catalog_objects(
    pool: &PgPool,
) -> Result<Vec<PostgresLiveCatalogObject>, StoreError> {
    let mut objects = Vec::new();

    let relations = sqlx::query(
        "SELECT c.relkind::text AS relkind, c.relname::text AS name, \
                CASE WHEN c.relkind IN ('v', 'm') \
                     THEN pg_catalog.pg_get_viewdef(c.oid, true) END AS definition \
         FROM pg_catalog.pg_class c \
         JOIN pg_catalog.pg_namespace n ON n.oid = c.relnamespace \
         WHERE n.nspname = pg_catalog.current_schema() \
           AND c.relkind IN ('r', 'p', 'v', 'm') \
         ORDER BY c.relname",
    )
    .fetch_all(pool)
    .await
    .map_err(StoreError::Database)?;
    for row in relations {
        let relkind: String = row.try_get("relkind").map_err(StoreError::Database)?;
        let definition: Option<String> = row.try_get("definition").map_err(StoreError::Database)?;
        let kind = if relkind == "v" || relkind == "m" {
            "view"
        } else {
            "table"
        };
        objects.push(PostgresLiveCatalogObject {
            kind: kind.to_owned(),
            name: row.try_get("name").map_err(StoreError::Database)?,
            definition,
        });
    }

    let sequences = sqlx::query(
        "SELECT c.relname::text AS name \
         FROM pg_catalog.pg_class c \
         JOIN pg_catalog.pg_namespace n ON n.oid = c.relnamespace \
         WHERE n.nspname = pg_catalog.current_schema() AND c.relkind = 'S' \
         ORDER BY c.relname",
    )
    .fetch_all(pool)
    .await
    .map_err(StoreError::Database)?;
    for row in sequences {
        objects.push(PostgresLiveCatalogObject {
            kind: "sequence".to_owned(),
            name: row.try_get("name").map_err(StoreError::Database)?,
            definition: None,
        });
    }

    let indexes = sqlx::query(
        "SELECT i.relname::text AS name, \
                pg_catalog.pg_get_indexdef(x.indexrelid) AS definition \
         FROM pg_catalog.pg_index x \
         JOIN pg_catalog.pg_class i ON i.oid = x.indexrelid \
         JOIN pg_catalog.pg_namespace n ON n.oid = i.relnamespace \
         WHERE n.nspname = pg_catalog.current_schema() \
           AND NOT x.indisprimary \
           AND NOT EXISTS ( \
               SELECT 1 FROM pg_catalog.pg_constraint con \
               WHERE con.conindid = x.indexrelid \
                 AND con.conrelid = x.indrelid \
                 AND con.contype IN ('p', 'u', 'x') \
           ) \
         ORDER BY i.relname",
    )
    .fetch_all(pool)
    .await
    .map_err(StoreError::Database)?;
    for row in indexes {
        objects.push(PostgresLiveCatalogObject {
            kind: "index".to_owned(),
            name: row.try_get("name").map_err(StoreError::Database)?,
            definition: row.try_get("definition").map_err(StoreError::Database)?,
        });
    }

    let functions = sqlx::query(
        "SELECT p.proname::text AS name, \
                pg_catalog.pg_get_function_identity_arguments(p.oid) AS signature, \
                pg_catalog.pg_get_functiondef(p.oid) AS definition \
         FROM pg_catalog.pg_proc p \
         JOIN pg_catalog.pg_namespace n ON n.oid = p.pronamespace \
         WHERE n.nspname = pg_catalog.current_schema() \
         ORDER BY p.proname, signature",
    )
    .fetch_all(pool)
    .await
    .map_err(StoreError::Database)?;
    for row in functions {
        let name: String = row.try_get("name").map_err(StoreError::Database)?;
        let signature: String = row.try_get("signature").map_err(StoreError::Database)?;
        objects.push(PostgresLiveCatalogObject {
            kind: "function".to_owned(),
            name: format!("{name}({signature})"),
            definition: row.try_get("definition").map_err(StoreError::Database)?,
        });
    }

    let triggers = sqlx::query(
        "SELECT t.relname::text AS table_name, tg.tgname::text AS name, \
                pg_catalog.pg_get_triggerdef(tg.oid, true) AS definition \
         FROM pg_catalog.pg_trigger tg \
         JOIN pg_catalog.pg_class t ON t.oid = tg.tgrelid \
         JOIN pg_catalog.pg_namespace n ON n.oid = t.relnamespace \
         WHERE n.nspname = pg_catalog.current_schema() AND NOT tg.tgisinternal \
         ORDER BY t.relname, tg.tgname",
    )
    .fetch_all(pool)
    .await
    .map_err(StoreError::Database)?;
    for row in triggers {
        let table: String = row.try_get("table_name").map_err(StoreError::Database)?;
        let name: String = row.try_get("name").map_err(StoreError::Database)?;
        objects.push(PostgresLiveCatalogObject {
            kind: "trigger".to_owned(),
            name: format!("{table}.{name}"),
            definition: row.try_get("definition").map_err(StoreError::Database)?,
        });
    }

    objects.sort_by(|left, right| {
        (left.kind.as_str(), left.name.as_str()).cmp(&(right.kind.as_str(), right.name.as_str()))
    });
    Ok(objects)
}
