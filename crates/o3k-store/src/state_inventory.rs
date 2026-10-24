//! Canonical durable-state inventory (PP6 D13).
//!
//! [`STATE_INVENTORY_V1`] is the committed baseline inventory of O3K durable
//! state. Its entries have the exact shape required by
//! `contracts/control-plane-backup-v1.proposed.schema.json`
//! (`$defs.repository_inventory_entry`) and accepted by `validate_inventory`
//! in `bins/o3k/src/backup.rs`: `repository_id`, `state_family`,
//! `empty_state_included`, `sqlite_objects`, `postgres_objects` and
//! `migration_ids`.
//!
//! # Registry
//!
//! [`REPOSITORY_FAMILIES`] is the reviewed, hand-maintained mapping from a
//! stable repository id to the tables owned by that repository and to one of
//! the nine contract state families. It is derived from the SQLite and
//! PostgreSQL migration trees and from the repository registration in this
//! crate, and it must never be generated automatically at runtime. Several
//! repositories may share one contract state family; every one of the nine
//! families must be represented in the generated inventory.
//!
//! # Generation and drift gate
//!
//! The baseline is generated from both migration trees by the regeneration
//! test, which compares the result byte-for-byte with the committed file and
//! fails on drift. Set `O3K_REGENERATE_INVENTORY=1` to rewrite the file for
//! local review; the test refuses regeneration whenever `CI` is set, so CI can
//! only detect drift, never rewrite the baseline.
//!
//! Every baseline entry sets `empty_state_included` to `false`: the baseline
//! records schema coverage, while emptiness is a property of one captured
//! snapshot and is decided at capture time.
//!
//! # Catalog object digests
//!
//! `definition_sha256` is the lowercase hex SHA-256 of a normalized catalog
//! definition parsed from the committed migration SQL. SQLite objects are
//! derived by applying `migrations/` (and the runtime `operations` rebuild that
//! `SqliteStore` performs after SQLx migrations) in an empty in-memory store and
//! reading the resulting `sqlite_master`; PostgreSQL objects are parsed
//! independently from `migrations_postgres/`.
//!
//! The registry emits these kinds:
//!
//! - **table** — every `CREATE TABLE` in the migration tree. A later
//!   `ALTER TABLE ... ADD COLUMN`, `DROP COLUMN` or `RENAME COLUMN` action is
//!   merged into the normalized definition in migration order. The SQLite side
//!   reads the definition SQLite itself stores, so an ALTER effect is never
//!   applied twice;
//! - **view** — every `CREATE [OR REPLACE] [MATERIALIZED] [TEMP] VIEW`;
//! - **sequence** — every `CREATE [TEMPORARY] SEQUENCE` (PostgreSQL only);
//! - **index** — every `CREATE [UNIQUE] INDEX` (SQLite and PostgreSQL);
//! - **constraint** — every explicitly named constraint, from
//!   `ALTER TABLE ... ADD CONSTRAINT` and from inline `CONSTRAINT <name>`
//!   clauses inside `CREATE TABLE`. A later `DROP CONSTRAINT` removes the
//!   object;
//! - **trigger** — every `CREATE [OR REPLACE] TRIGGER` (SQLite and PostgreSQL);
//! - **function** — every `CREATE [OR REPLACE] FUNCTION` (PostgreSQL only).
//!
//! Implicit (unnamed) `PRIMARY KEY`, `UNIQUE`, `FOREIGN KEY` and `CHECK`
//! clauses are **not** separate catalog objects: they remain inside the owning
//! table's normalized definition digest, and SQLite exposes no stable catalog
//! identity for them. An explicitly named inline constraint is emitted as a
//! `constraint` object *and* stays inside the table definition, because the
//! table digest must describe the complete authored table. For the same reason
//! a `DROP CONSTRAINT` of an implicit, server-named constraint leaves its text
//! in the table digest: the parser has no authored name to remove.
//!
//! # Catalog object identity and ownership
//!
//! Indexes, triggers and constraints are assigned to the repository entry that
//! owns the table named by their `ON <table>` clause or `ALTER TABLE` context. A
//! view, sequence or function has no table owner, so each reviewed one must be
//! listed in `GENERIC_VIEW_OWNERS`, `GENERIC_SEQUENCE_OWNERS` or
//! `GENERIC_FUNCTION_OWNERS` and is assigned to the named repository. An
//! unlisted object fails generation instead of being silently dropped. Every
//! catalog object is assigned to exactly one repository entry.
//!
//! Emitted object names are the collision-safe catalog identity, not only the
//! bare PostgreSQL name:
//!
//! - functions are named `name(normalized argument list)`, because PostgreSQL
//!   allows overloads that share a name;
//! - triggers are named `<table>.<name>`, because trigger names are unique only
//!   per table;
//! - constraints keep their SQL name (PostgreSQL identifies a constraint by
//!   table and name); a repository that ends up owning two constraints with the
//!   same name fails generation;
//! - tables, views, sequences and indexes keep their catalog name.
//!
//! Normalization rules:
//!
//! 1. `--` line comments and `/* */` block comments are removed. SQLite
//!    `[...]` quoting, SQL `'...'`/`"..."`/`` `...` `` quoting and PostgreSQL
//!    dollar-quoted strings (`$$...$$`, `$tag$...$tag$`) are preserved;
//! 2. for a table, the definition is the exact `CREATE TABLE` statement from
//!    `CREATE` through the parenthesis that closes the column/constraint list;
//!    for every other kind it is the whole statement through the terminator
//!    (the PostgreSQL function body is the complete dollar-quoted string, and a
//!    named constraint is normalized to `ALTER TABLE ... ADD CONSTRAINT ...`).
//!    The trailing `;` is excluded;
//! 3. runs of whitespace outside quoted identifiers and string literals
//!    collapse to one space, and the result is trimmed. Whitespace inside a
//!    dollar-quoted function body is collapsed by the same rule; the body text
//!    is otherwise preserved verbatim;
//! 4. whitespace that depends only on layout is removed outside quoted
//!    identifiers and string literals: after `(`, after `,`, before `)` and
//!    before `,`;
//! 5. an `IF NOT EXISTS` qualifier is removed;
//! 6. identifiers, keywords and literals keep their original spelling, case
//!    and quoting;
//! 7. when one tree creates the same object more than once (a table rebuild,
//!    for example `0036_native_attachment_reuse.sql`, or a
//!    `DROP TRIGGER`/`CREATE TRIGGER` pair), the last `CREATE` in
//!    migration-stem order is the effective definition, and a later `DROP`
//!    removes the object. A `DROP` of an object that the tree itself never
//!    creates is ignored.
//!
//! `migration_ids` lists, sorted and unique, every migration file stem that
//! names the repository's tables in a DDL statement: `CREATE TABLE`,
//! `ALTER TABLE`, `DROP TABLE`, `CREATE [UNIQUE] INDEX ... ON` and
//! `CREATE TRIGGER ... ON`. It also lists every stem that defines or drops one
//! of the repository's catalog objects (views, sequences, indexes, constraints,
//! functions and triggers), so an object-defining migration is recorded even
//! when the repository owns no table. Stems from both migration trees are
//! included because the two trees do not share a numbering scheme. A repository
//! with no such migration still fails with `RepositoryWithoutMigrations`.
//!
//! # Capture-time live catalog comparison
//!
//! Snapshot facts enumerate the captured snapshot's `sqlite_master` objects
//! (`table`, `index`, `view`, `trigger`) and compare them against every
//! baseline entry's `sqlite_objects`: a missing object, an extra object or a
//! normalized-definition mismatch fails the capture with exit 2
//! `store-catalog-mismatch` **before** anything is staged. SQLite-internal
//! names (`sqlite_*`, including `sqlite_autoindex_*`) are excluded;
//! `_sqlx_migrations` is compared because the baseline explicitly claims it as
//! framework state (see **Framework and internal objects**). The same
//! normalization function is used for the generated digest and the live
//! `sqlite_master.sql` digest, so layout or `IF NOT EXISTS` differences do not
//! produce false mismatches. Trigger objects are compared under the same
//! `<table>.<name>` identity the baseline uses.
//!
//! PostgreSQL exposes no stored authored DDL, so
//! [`postgres_live_catalog_objects`] enumerates object identity from
//! `pg_catalog` (tables, views, sequences, explicit indexes, functions and
//! triggers) and [`verify_postgres_catalog_against_baseline`] compares that
//! identity — kind and name in both directions — against the entry's
//! `postgres_objects`. Definition digests remain the migration-tree drift gate:
//! catalog renderings (`pg_get_viewdef`, `pg_get_indexdef`,
//! `pg_get_triggerdef`, `pg_get_functiondef`) are not byte-identical to the
//! authored migration SQL and cannot reproduce its normalized digest.
//!
//! # Framework and internal objects
//!
//! Internal framework objects are not part of the reviewed table registry.
//! SQLx creates `_sqlx_migrations` on both backends; its reviewed DDL is
//! recorded verbatim from `sqlx-sqlite 0.8.6` (`src/migrate.rs`) and
//! `sqlx-postgres 0.8.6` (`src/migrate.rs`). SQLite also reserves
//! `sqlite_sequence`, which it materializes only once a table declares
//! `AUTOINCREMENT`; the current reviewed migrations declare none, so the
//! inventory claims that object only if a future migration does.
//!
//! Those objects belong to the `release_and_install_metadata` state family:
//! they record which release migrations were applied. Because every applied
//! migration is recorded there, that entry's `migration_ids` is the full
//! migration lineage of both trees. A live catalog comparison must still
//! classify SQLite-internal names through [`is_internal_sqlite_table`].

use std::{
    collections::{BTreeMap, BTreeSet},
    path::PathBuf,
};

#[cfg(test)]
use std::{fs, path::Path};

use sha2::{Digest, Sha256};

use serde::{Deserialize, Serialize};

use crate::{SqliteStore, StoreError};

/// Format marker for the committed canonical state inventory.
pub const STATE_INVENTORY_FORMAT: &str = "o3k-state-inventory-v1";

/// PostgreSQL server major bound into the committed baseline (D10).
///
/// Source: SPEC-0050 §3 "PostgreSQL profile" requires PostgreSQL 16, and
/// `docs/pp/PP6_TECHNICAL_CONTRACT_APPROVAL.md` D10 accepts "PostgreSQL 16
/// only". The baseline must be regenerated if that policy moves.
pub const POSTGRES_MAJOR: u16 = 16;

/// Maximum number of entries accepted by the backup manifest contract.
pub const MAX_INVENTORY_ENTRIES: usize = 512;

/// The nine contract state families. Every one must appear in the inventory.
pub const STATE_FAMILIES: [&str; 9] = [
    "canonical_resources",
    "operations_and_reconciliation",
    "placement_allocations_and_provider_mappings",
    "topology_and_building_blocks",
    "iam_and_security_scope",
    "bootstrap_enrollment_and_revocation",
    "audit_and_governance",
    "o3k_owned_configuration",
    "release_and_install_metadata",
];

/// Catalog object kinds accepted by the backup manifest contract.
pub const CATALOG_KINDS: [&str; 7] = [
    "table",
    "view",
    "sequence",
    "index",
    "constraint",
    "function",
    "trigger",
];

/// Repository id owning the framework migration bookkeeping tables.
pub const RELEASE_METADATA_REPOSITORY_ID: &str = "release_and_install_metadata";

/// One reviewed repository family: the durability boundary, its contract
/// state family, and the exact tables it owns.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct RepositoryFamily {
    /// Stable repository id, used verbatim as the entry's `repository_id`.
    pub repository_id: &'static str,
    /// One of [`STATE_FAMILIES`].
    pub state_family: &'static str,
    /// Tables owned by this repository, sorted and unique across the registry.
    pub tables: &'static [&'static str],
}

/// Reviewed repository-family registry used to derive the canonical inventory.
///
/// Each repository is a stable durability boundary: the tables in one
/// repository are captured, compared, and restored together. Table names are
/// sorted within every repository and appear exactly once across the registry.
/// `release_and_install_metadata` is not listed here because its objects are
/// framework-created and cannot be parsed from the migration trees.
pub const REPOSITORY_FAMILIES: &[RepositoryFamily] = &[
    RepositoryFamily {
        repository_id: "audit",
        state_family: "audit_and_governance",
        tables: &["audit_events"],
    },
    RepositoryFamily {
        repository_id: "bootstrap",
        state_family: "bootstrap_enrollment_and_revocation",
        tables: &["bootstrap_state", "enrollment_grants"],
    },
    RepositoryFamily {
        repository_id: "canonical_network",
        state_family: "canonical_resources",
        tables: &[
            "canonical_address_pools",
            "canonical_address_realms",
            "canonical_endpoints",
            "canonical_fabric_host_transport_identities",
            "canonical_l3_gateway_attachments",
            "canonical_l3_gateways",
            "canonical_networks",
            "canonical_realm_encapsulation_bindings",
        ],
    },
    RepositoryFamily {
        repository_id: "canonical_policy",
        state_family: "canonical_resources",
        tables: &[
            "canonical_network_policies",
            "canonical_network_policy_rules",
            "canonical_policy_attachments",
            "canonical_policy_realizations",
            "canonical_reusable_network_policies",
        ],
    },
    RepositoryFamily {
        repository_id: "composition",
        state_family: "o3k_owned_configuration",
        tables: &["building_blocks", "cloud_profiles"],
    },
    RepositoryFamily {
        repository_id: "coordination",
        state_family: "operations_and_reconciliation",
        tables: &[
            "controller_sessions",
            "work_lease_fence_counters",
            "work_leases",
        ],
    },
    RepositoryFamily {
        repository_id: "core_resources",
        state_family: "canonical_resources",
        tables: &["provider_refs", "resource_relationships", "resources"],
    },
    RepositoryFamily {
        repository_id: "identity",
        state_family: "iam_and_security_scope",
        tables: &[
            "federated_bindings",
            "keypairs",
            "keystone_domains",
            "keystone_endpoints",
            "keystone_projects",
            "keystone_regions",
            "keystone_role_assignments",
            "keystone_roles",
            "keystone_services",
            "keystone_users",
            "operator_assignments",
            "server_keypairs",
        ],
    },
    RepositoryFamily {
        repository_id: "image",
        state_family: "canonical_resources",
        tables: &[
            "artifact_transfers",
            "image_metadata",
            "image_overlay_ownership",
        ],
    },
    RepositoryFamily {
        repository_id: "metering",
        state_family: "audit_and_governance",
        tables: &[
            "metering_aggregates",
            "metering_authority",
            "metering_intervals",
        ],
    },
    RepositoryFamily {
        repository_id: "native_storage",
        state_family: "canonical_resources",
        tables: &[
            "native_snapshots",
            "native_storage_backends",
            "native_volume_attachments",
            "native_volumes",
            "volume_attachments",
        ],
    },
    RepositoryFamily {
        repository_id: "network",
        state_family: "canonical_resources",
        tables: &[
            "network_address_allocations",
            "network_intents",
            "network_networks",
            "network_ports",
            "network_security_group_bindings",
            "network_security_group_rules",
            "network_security_groups",
            "network_subnets",
        ],
    },
    RepositoryFamily {
        repository_id: "operations",
        state_family: "operations_and_reconciliation",
        tables: &[
            "agent_commands",
            "canonical_operation_metadata",
            "idempotency_reservations",
            "network_plan_work",
            "observation_watermarks",
            "operation_retry_state",
            "operations",
        ],
    },
    RepositoryFamily {
        repository_id: "placement",
        state_family: "placement_allocations_and_provider_mappings",
        tables: &[
            "placement_allocation_intent_resources",
            "placement_allocation_intents",
            "placement_allocation_resources",
            "placement_allocations",
            "placement_inventories",
            "placement_provider_failure_domains",
            "placement_provider_traits",
            "placement_providers",
        ],
    },
    RepositoryFamily {
        repository_id: "quota",
        state_family: "iam_and_security_scope",
        tables: &[
            "quota_limits",
            "quota_reservation_amounts",
            "quota_reservations",
        ],
    },
    RepositoryFamily {
        repository_id: "topology",
        state_family: "topology_and_building_blocks",
        tables: &[
            "failure_domains",
            "topology_availability_domains",
            "topology_bindings",
            "topology_regions",
        ],
    },
];

/// The reviewed, committed baseline derived from [`REPOSITORY_FAMILIES`] and
/// both migration trees. Never edit this file by hand; regenerate it and
/// review the diff.
pub const STATE_INVENTORY_V1: &str = include_str!("../state_inventory_v1.json");

/// Framework-owned SQLite objects that are never part of O3K durable state.
pub const INTERNAL_SQLITE_TABLES: &[&str] = &["_sqlx_migrations", "sqlite_sequence"];

/// Returns true for framework-owned SQLite table names.
///
/// A live-catalog comparison must exclude these names before comparing against
/// [`baseline_state_inventory`]. PostgreSQL's `_sqlx_migrations` is likewise
/// framework state even though the database creates it, not the migration
/// files.
pub fn is_internal_sqlite_table(name: &str) -> bool {
    INTERNAL_SQLITE_TABLES.contains(&name)
}

/// Returns true for SQLite-internal catalog names that a live comparison must
/// exclude (`sqlite_*`, including `sqlite_autoindex_*` and
/// `sqlite_sequence`).
///
/// `_sqlx_migrations` is **not** excluded: the baseline explicitly claims that
/// framework-owned table and the capture-time comparison verifies its
/// reviewed definition.
pub fn is_internal_sqlite_object(name: &str) -> bool {
    name.starts_with("sqlite_")
}

/// One object read from the captured snapshot's live `sqlite_master`.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct LiveCatalogObject {
    pub kind: String,
    pub name: String,
    pub definition_sha256: String,
}

/// A live catalog difference between the snapshot and the committed baseline.
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
pub enum CatalogMismatch {
    #[error("snapshot catalog object {kind} {name:?} is missing")]
    Missing { kind: String, name: String },
    #[error("snapshot catalog object {kind} {name:?} is not in the baseline inventory")]
    Unexpected { kind: String, name: String },
    #[error("snapshot catalog object {kind} {name:?} has a different normalized definition")]
    Definition { kind: String, name: String },
}

/// Enumerates the live `sqlite_master` objects of an open snapshot.
///
/// Rows without SQL text (SQLite's implicit `sqlite_autoindex_*` entries) and
/// `sqlite_*` internal names are excluded. Every remaining object is normalized
/// with [`normalize_catalog_definition`], the same function used to generate the
/// committed baseline digest.
pub async fn sqlite_live_catalog_objects(
    pool: &sqlx::SqlitePool,
) -> Result<Vec<LiveCatalogObject>, StoreError> {
    crate::sqlite::live_catalog_objects(pool).await
}

/// Compares the live snapshot catalog with every baseline entry's
/// `sqlite_objects`.
///
/// The comparison is exact in both directions and compares normalized
/// definition digests, not only names. The first difference in sorted order is
/// returned so the failure is deterministic.
pub fn verify_sqlite_catalog_against_baseline(
    inventory: &[serde_json::Value],
    live: &[LiveCatalogObject],
) -> Result<(), CatalogMismatch> {
    let mut expected = std::collections::BTreeMap::new();
    for entry in inventory {
        let Some(objects) = entry
            .get("sqlite_objects")
            .and_then(|value| value.as_array())
        else {
            continue;
        };
        for object in objects {
            let (Some(kind), Some(name), Some(digest)) = (
                object.get("kind").and_then(|value| value.as_str()),
                object.get("name").and_then(|value| value.as_str()),
                object
                    .get("definition_sha256")
                    .and_then(|value| value.as_str()),
            ) else {
                continue;
            };
            // SQLite materializes `sqlite_*` objects (notably
            // `sqlite_sequence` for AUTOINCREMENT tables) that a live catalog
            // comparison deliberately excludes. A reviewed baseline that
            // claims such an object must not make every capture fail.
            if is_internal_sqlite_object(name) {
                continue;
            }
            expected.insert((kind.to_owned(), name.to_owned()), digest.to_owned());
        }
    }
    let mut actual = std::collections::BTreeMap::new();
    for object in live {
        actual.insert(
            (object.kind.clone(), object.name.clone()),
            object.definition_sha256.clone(),
        );
    }

    for (key, digest) in &expected {
        match actual.get(key) {
            None => {
                return Err(CatalogMismatch::Missing {
                    kind: key.0.clone(),
                    name: key.1.clone(),
                });
            }
            Some(actual_digest) if actual_digest != digest => {
                return Err(CatalogMismatch::Definition {
                    kind: key.0.clone(),
                    name: key.1.clone(),
                });
            }
            Some(_) => {}
        }
    }
    for key in actual.keys() {
        if !expected.contains_key(key) {
            return Err(CatalogMismatch::Unexpected {
                kind: key.0.clone(),
                name: key.1.clone(),
            });
        }
    }
    Ok(())
}

/// One catalog object read from a live PostgreSQL database's `pg_catalog`.
///
/// PostgreSQL does not retain the authored DDL, so the live reader records
/// identity (`kind`, `name`) plus the best-effort catalog rendering from the
/// relevant `pg_get_*` function. The rendering is diagnostic: definition
/// digests in the baseline are derived from the migration SQL and cannot be
/// recomputed from a catalog rendering.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PostgresLiveCatalogObject {
    pub kind: String,
    pub name: String,
    pub definition: Option<String>,
}

/// Enumerates the live catalog objects of an open PostgreSQL database.
///
/// The query lives in [`crate::postgres`] so all raw SQL stays inside the
/// approved persistence boundary. Identity uses the same collision-safe names
/// as the baseline: `<table>.<name>` for triggers and
/// `name(normalized argument list)` for functions.
pub async fn postgres_live_catalog_objects(
    pool: &sqlx::PgPool,
) -> Result<Vec<PostgresLiveCatalogObject>, StoreError> {
    crate::postgres::live_catalog_objects(pool).await
}

/// Compares the live PostgreSQL catalog with every baseline entry's
/// `postgres_objects`.
///
/// The comparison is exact in both directions over `(kind, name)` and the first
/// difference in sorted order is returned so the failure is deterministic.
///
/// Two deliberate exclusions keep the live comparison honest:
///
/// - `constraint` objects are not compared. `pg_constraint` cannot distinguish
///   a reviewed explicitly named constraint from an implicitly named
///   `PRIMARY KEY`/`UNIQUE`/`FOREIGN KEY`/`CHECK`, and the implicit ones live
///   inside the table digest. A constraint change is caught by the
///   migration-tree drift gate instead.
/// - Definition digests are not compared: see [`PostgresLiveCatalogObject`].
pub fn verify_postgres_catalog_against_baseline(
    inventory: &[serde_json::Value],
    live: &[PostgresLiveCatalogObject],
) -> Result<(), CatalogMismatch> {
    let mut expected = std::collections::BTreeSet::new();
    for entry in inventory {
        let Some(objects) = entry
            .get("postgres_objects")
            .and_then(|value| value.as_array())
        else {
            continue;
        };
        for object in objects {
            let (Some(kind), Some(name)) = (
                object.get("kind").and_then(|value| value.as_str()),
                object.get("name").and_then(|value| value.as_str()),
            ) else {
                continue;
            };
            if kind == "constraint" {
                continue;
            }
            expected.insert((kind.to_owned(), name.to_owned()));
        }
    }
    let actual: std::collections::BTreeSet<(String, String)> = live
        .iter()
        .map(|object| (object.kind.clone(), object.name.clone()))
        .collect();

    for (kind, name) in &expected {
        if !actual.contains(&(kind.clone(), name.clone())) {
            return Err(CatalogMismatch::Missing {
                kind: kind.clone(),
                name: name.clone(),
            });
        }
    }
    for (kind, name) in &actual {
        if !expected.contains(&(kind.clone(), name.clone())) {
            return Err(CatalogMismatch::Unexpected {
                kind: kind.clone(),
                name: name.clone(),
            });
        }
    }
    Ok(())
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct InventoryDocument {
    format: String,
    /// SQLite library version of the generator that produced the SQLite
    /// catalog (from `SELECT sqlite_version()`), so a toolchain change is
    /// visible in the baseline binding rather than silently redefining the
    /// generated `sqlite_master` text.
    sqlite_version: String,
    /// PostgreSQL server major that the baseline was generated for (D10).
    postgres_major: u16,
    /// SHA-256 of every SQLite and PostgreSQL migration file, keyed by its
    /// repository-relative path (`migrations/...` / `migrations_postgres/...`).
    migration_files: BTreeMap<String, String>,
    repositories: Vec<RepositoryInventoryEntry>,
}

/// Version/binding facts carried alongside the repository inventory.
///
/// This is deliberately separate from [`baseline_state_inventory`]: the
/// artifact manifest consumes only the repository entries, while the baseline
/// drift gate and D10 checks bind the PostgreSQL major and the exact migration
/// file bytes.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct BaselineBinding {
    /// SQLite library version the SQLite catalog was generated with.
    pub sqlite_version: String,
    /// PostgreSQL server major the baseline was generated against.
    pub postgres_major: u16,
    /// Lowercase hex SHA-256 for every migration file in both trees.
    pub migration_files: BTreeMap<String, String>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct RepositoryInventoryEntry {
    repository_id: String,
    state_family: String,
    empty_state_included: bool,
    sqlite_objects: Vec<CatalogObject>,
    postgres_objects: Vec<CatalogObject>,
    migration_ids: Vec<String>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct CatalogObject {
    kind: String,
    schema: String,
    name: String,
    definition_sha256: String,
}

/// Errors raised while generating, parsing, or comparing the canonical state
/// inventory.
#[derive(Debug, thiserror::Error)]
pub enum StateInventoryError {
    #[error("cannot read state inventory migration directory {path}: {source}")]
    ReadDirectory {
        path: PathBuf,
        #[source]
        source: std::io::Error,
    },
    #[error("cannot read state inventory migration file {path}: {source}")]
    ReadMigration {
        path: PathBuf,
        #[source]
        source: std::io::Error,
    },
    #[error("state inventory JSON is invalid: {0}")]
    Json(#[from] serde_json::Error),
    #[error("unsupported state inventory format {found:?}; expected {expected:?}")]
    UnsupportedFormat {
        found: String,
        expected: &'static str,
    },
    #[error("committed state inventory is invalid: {0}")]
    InvalidBaseline(String),
    #[error("state inventory registry repeats repository id {0:?}")]
    DuplicateRepository(String),
    #[error("state inventory registry assigns table {table:?} to both {first:?} and {second:?}")]
    DuplicateTable {
        table: String,
        first: String,
        second: String,
    },
    #[error(
        "state inventory registry lists repository {repository:?} with unsorted tables: {tables:?}"
    )]
    UnsortedRepository {
        repository: String,
        tables: Vec<String>,
    },
    #[error(
        "state inventory registry uses unknown state family {family:?} for repository {repository:?}"
    )]
    UnknownStateFamily { repository: String, family: String },
    #[error(
        "migration tree defines tables absent from REPOSITORY_FAMILIES: {tables:?}. \
         Add them to a reviewed repository family, then regenerate with \
         `O3K_REGENERATE_INVENTORY=1 cargo test -p o3k-store --all-features state_inventory` \
         and commit crates/o3k-store/state_inventory_v1.json."
    )]
    UnregisteredTables { tables: Vec<String> },
    #[error(
        "REPOSITORY_FAMILIES registers tables that the {tree} migration tree never creates, \
         or that are absent from the migration tree: {tables:?}. \
         Correct the registry, then regenerate with \
         `O3K_REGENERATE_INVENTORY=1 cargo test -p o3k-store --all-features state_inventory` \
         and commit crates/o3k-store/state_inventory_v1.json."
    )]
    MissingCreateTable {
        tree: &'static str,
        tables: Vec<String>,
    },
    #[error(
        "repository {repository:?} has no migration that creates or alters its tables; \
         every inventory entry needs a non-empty migration_ids list"
    )]
    RepositoryWithoutMigrations { repository: String },
    #[error("state inventory omits contract state families: {families:?}")]
    MissingStateFamily { families: Vec<String> },
    #[error(
        "state inventory registry assigns index/trigger {kind} {name:?} to unregistered table \
         {table:?} in the {tree} migration tree"
    )]
    UnregisteredCatalogObject {
        tree: &'static str,
        kind: &'static str,
        name: String,
        table: String,
    },
    #[error(
        "the {tree} migration tree defines function {name:?} with no reviewed repository owner; \
         add it to GENERIC_FUNCTION_OWNERS in crates/o3k-store/src/state_inventory.rs"
    )]
    UnassignedFunction { tree: &'static str, name: String },
    #[error(
        "the {tree} migration tree defines view {name:?} with no reviewed repository owner; \
         add it to GENERIC_VIEW_OWNERS in crates/o3k-store/src/state_inventory.rs"
    )]
    UnassignedView { tree: &'static str, name: String },
    #[error(
        "the {tree} migration tree defines sequence {name:?} with no reviewed repository owner; \
         add it to GENERIC_SEQUENCE_OWNERS in crates/o3k-store/src/state_inventory.rs"
    )]
    UnassignedSequence { tree: &'static str, name: String },
    #[error(
        "the {tree} migration tree uses unsupported ALTER TABLE action on {table:?}: {action:?}; \
         extend the state-inventory parser or remove the statement"
    )]
    UnsupportedAlterTable {
        tree: &'static str,
        table: String,
        action: String,
    },
    #[error(
        "repository {repository:?} would emit two {field} objects with kind {kind:?} and name \
         {name:?}; catalog object names must be unique inside a repository entry"
    )]
    DuplicateCatalogObject {
        repository: String,
        field: &'static str,
        kind: String,
        name: String,
    },
    #[error(
        "the {tree} migration tree creates catalog object {kind} {name:?}, which this generator \
         does not emit; extend the generator or remove the object"
    )]
    UnsupportedCatalogObject {
        tree: &'static str,
        kind: &'static str,
        name: String,
    },
    #[error(
        "state inventory baseline drift: {detail}. \
         Run `O3K_REGENERATE_INVENTORY=1 cargo test -p o3k-store --all-features state_inventory` \
         to regenerate, then review and commit crates/o3k-store/state_inventory_v1.json. \
         Never auto-update the baseline in CI."
    )]
    BaselineDrift { detail: String },
}

/// Parses the committed baseline into verifier-ready JSON values.
///
/// Each value has the contract `repository_inventory_entry` shape consumed by
/// the PP6 artifact verifier, with exactly the keys `repository_id`,
/// `state_family`, `empty_state_included`, `sqlite_objects`,
/// `postgres_objects` and `migration_ids`. Entries are sorted by
/// `repository_id`; every value is validated against the contract rules before
/// it is returned.
pub fn baseline_state_inventory() -> Result<Vec<serde_json::Value>, StateInventoryError> {
    let document: InventoryDocument = serde_json::from_str(STATE_INVENTORY_V1)?;
    validate_document(&document)?;
    let mut values = Vec::with_capacity(document.repositories.len());
    for repository in document.repositories {
        values.push(serde_json::to_value(repository)?);
    }
    Ok(values)
}

/// Loads the version/binding facts from the committed baseline.
///
/// [`baseline_state_inventory`] intentionally keeps returning only repository
/// entries so the artifact manifest entry shape is unchanged.
pub fn baseline_binding() -> Result<BaselineBinding, StateInventoryError> {
    let document: InventoryDocument = serde_json::from_str(STATE_INVENTORY_V1)?;
    validate_document(&document)?;
    Ok(BaselineBinding {
        sqlite_version: document.sqlite_version,
        postgres_major: document.postgres_major,
        migration_files: document.migration_files,
    })
}

fn validate_document(document: &InventoryDocument) -> Result<(), StateInventoryError> {
    if document.format != STATE_INVENTORY_FORMAT {
        return Err(StateInventoryError::UnsupportedFormat {
            found: document.format.clone(),
            expected: STATE_INVENTORY_FORMAT,
        });
    }
    if document.postgres_major < 12 {
        return Err(StateInventoryError::InvalidBaseline(format!(
            "unsupported PostgreSQL major {}",
            document.postgres_major
        )));
    }
    let version = &document.sqlite_version;
    if version.is_empty()
        || !version.contains(|c: char| c.is_ascii_digit())
        || !version
            .chars()
            .all(|c| c.is_ascii_digit() || c == '.' || c.is_ascii_alphabetic())
    {
        return Err(StateInventoryError::InvalidBaseline(format!(
            "invalid SQLite generator version {version:?}"
        )));
    }
    if document.migration_files.is_empty() {
        return Err(StateInventoryError::InvalidBaseline(
            "migration file binding is empty".to_owned(),
        ));
    }
    for (path, digest) in &document.migration_files {
        let relative = path
            .strip_prefix("migrations/")
            .or_else(|| path.strip_prefix("migrations_postgres/"));
        if relative.is_none_or(|name| {
            name.is_empty() || name.contains('/') || !name.ends_with(".sql") || !is_sha256(digest)
        }) {
            return Err(StateInventoryError::InvalidBaseline(format!(
                "invalid migration file binding for {path:?}"
            )));
        }
    }
    if document.repositories.is_empty() || document.repositories.len() > MAX_INVENTORY_ENTRIES {
        return Err(StateInventoryError::InvalidBaseline(format!(
            "repository inventory size {} is outside 1..={MAX_INVENTORY_ENTRIES}",
            document.repositories.len()
        )));
    }

    let mut ids = BTreeSet::new();
    let mut families = BTreeSet::new();
    let mut previous_repository: Option<&str> = None;
    for entry in &document.repositories {
        if !is_contract_identifier(&entry.repository_id) {
            return Err(StateInventoryError::InvalidBaseline(format!(
                "repository id {:?} is not a contract identifier",
                entry.repository_id
            )));
        }
        if !ids.insert(entry.repository_id.as_str()) {
            return Err(StateInventoryError::InvalidBaseline(format!(
                "duplicate repository id {:?}",
                entry.repository_id
            )));
        }
        if previous_repository.is_some_and(|previous| previous >= entry.repository_id.as_str()) {
            return Err(StateInventoryError::InvalidBaseline(format!(
                "repositories are not uniquely sorted: {:?}",
                entry.repository_id
            )));
        }
        previous_repository = Some(&entry.repository_id);
        if !STATE_FAMILIES.contains(&entry.state_family.as_str()) {
            return Err(StateInventoryError::InvalidBaseline(format!(
                "repository {:?} has unknown state family {:?}",
                entry.repository_id, entry.state_family
            )));
        }
        families.insert(entry.state_family.as_str());
        validate_objects(
            &entry.repository_id,
            "sqlite_objects",
            &entry.sqlite_objects,
        )?;
        validate_objects(
            &entry.repository_id,
            "postgres_objects",
            &entry.postgres_objects,
        )?;
        if entry.migration_ids.is_empty() {
            return Err(StateInventoryError::InvalidBaseline(format!(
                "repository {:?} has no migration ids",
                entry.repository_id
            )));
        }
        let mut migration_ids = BTreeSet::new();
        for migration_id in &entry.migration_ids {
            if !is_contract_identifier(migration_id) || !migration_ids.insert(migration_id.as_str())
            {
                return Err(StateInventoryError::InvalidBaseline(format!(
                    "repository {:?} has an invalid or duplicate migration id {:?}",
                    entry.repository_id, migration_id
                )));
            }
        }
    }

    let missing: Vec<&str> = STATE_FAMILIES
        .iter()
        .filter(|family| !families.contains(**family))
        .copied()
        .collect();
    if !missing.is_empty() {
        return Err(StateInventoryError::MissingStateFamily {
            families: missing.into_iter().map(str::to_owned).collect(),
        });
    }
    Ok(())
}

fn validate_objects(
    repository_id: &str,
    field: &str,
    objects: &[CatalogObject],
) -> Result<(), StateInventoryError> {
    if objects.is_empty() {
        return Err(StateInventoryError::InvalidBaseline(format!(
            "repository {repository_id:?} has no {field}"
        )));
    }
    let mut keys = BTreeSet::new();
    for object in objects {
        if !CATALOG_KINDS.contains(&object.kind.as_str())
            || object.schema.is_empty()
            || object.name.is_empty()
            || !is_sha256(&object.definition_sha256)
        {
            return Err(StateInventoryError::InvalidBaseline(format!(
                "repository {repository_id:?} has an invalid {field} object {:?}",
                object.name
            )));
        }
        if !keys.insert((
            object.kind.as_str(),
            object.schema.as_str(),
            object.name.as_str(),
        )) {
            return Err(StateInventoryError::InvalidBaseline(format!(
                "repository {repository_id:?} repeats {field} object {:?}",
                object.name
            )));
        }
    }
    Ok(())
}

/// Contract identifier syntax shared by repository ids and migration ids:
/// `^[A-Za-z0-9][A-Za-z0-9._:-]*$`, at most 160 bytes.
fn is_contract_identifier(value: &str) -> bool {
    let mut bytes = value.bytes();
    let Some(first) = bytes.next() else {
        return false;
    };
    value.len() <= 160
        && first.is_ascii_alphanumeric()
        && bytes
            .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'.' | b'_' | b':' | b'-'))
}

fn is_sha256(value: &str) -> bool {
    value.len() == 64
        && value
            .bytes()
            .all(|byte| byte.is_ascii_hexdigit() && !byte.is_ascii_uppercase())
}

/// Lists the live SQLite tables owned by the opened store.
///
/// The query excludes SQLite-internal `sqlite_*` objects but intentionally
/// includes `_sqlx_migrations`; callers comparing this against the canonical
/// inventory must drop names accepted by [`is_internal_sqlite_table`].
pub async fn sqlite_live_tables(store: &SqliteStore) -> Result<Vec<String>, StoreError> {
    crate::sqlite::live_tables(store).await
}

/// Reviewed framework DDL for SQLite `_sqlx_migrations`, verbatim from
/// `sqlx-sqlite 0.8.6` `src/migrate.rs`.
#[cfg(test)]
const SQLITE_SQLX_MIGRATIONS_DDL: &str = "CREATE TABLE IF NOT EXISTS _sqlx_migrations (
    version BIGINT PRIMARY KEY,
    description TEXT NOT NULL,
    installed_on TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP,
    success BOOLEAN NOT NULL,
    checksum BLOB NOT NULL,
    execution_time BIGINT NOT NULL
)";

/// Reviewed framework DDL for PostgreSQL `_sqlx_migrations`, verbatim from
/// `sqlx-postgres 0.8.6` `src/migrate.rs`.
#[cfg(test)]
const POSTGRES_SQLX_MIGRATIONS_DDL: &str = "CREATE TABLE IF NOT EXISTS _sqlx_migrations (
    version BIGINT PRIMARY KEY,
    description TEXT NOT NULL,
    installed_on TIMESTAMPTZ NOT NULL DEFAULT now(),
    success BOOLEAN NOT NULL,
    checksum BYTEA NOT NULL,
    execution_time BIGINT NOT NULL
)";

/// SQLite's definition of the `sqlite_sequence` table it materializes for
/// `AUTOINCREMENT` tables.
#[cfg(test)]
const SQLITE_SEQUENCE_DDL: &str = "CREATE TABLE sqlite_sequence(name,seq)";

#[cfg(test)]
fn generate_inventory_from_trees(
    sqlite_migrations_dir: &Path,
    postgres_migrations_dir: &Path,
) -> Result<String, StateInventoryError> {
    generate_inventory_from_trees_with_owners(
        sqlite_migrations_dir,
        postgres_migrations_dir,
        &REVIEWED_GENERIC_OWNERS,
    )
}

#[cfg(test)]
fn generate_inventory_from_trees_with_owners(
    sqlite_migrations_dir: &Path,
    postgres_migrations_dir: &Path,
    owners: &GenericOwners<'_>,
) -> Result<String, StateInventoryError> {
    let sqlite = scan_sqlite_live_tree(sqlite_migrations_dir)?;
    let postgres = scan_migration_tree(postgres_migrations_dir, "PostgreSQL")?;
    render_inventory_with_owners(
        &sqlite,
        &postgres,
        REPOSITORY_FAMILIES,
        migration_file_hashes(sqlite_migrations_dir, postgres_migrations_dir)?,
        owners,
    )
}

#[cfg(test)]
fn generate_inventory_from_sqlite_tree(
    migrations_dir: &Path,
) -> Result<String, StateInventoryError> {
    let sqlite = scan_migration_tree(migrations_dir, "SQLite")?;
    let postgres_migrations_dir =
        PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("migrations_postgres");
    render_inventory(
        &sqlite,
        &scan_migration_tree(&postgres_migrations_dir, "PostgreSQL")?,
        REPOSITORY_FAMILIES,
        migration_file_hashes(migrations_dir, &postgres_migrations_dir)?,
    )
}

#[cfg(test)]
fn generate_inventory_with_registry(
    sqlite_migrations_dir: &Path,
    postgres_migrations_dir: &Path,
    families: &[RepositoryFamily],
) -> Result<String, StateInventoryError> {
    let sqlite = scan_migration_tree(sqlite_migrations_dir, "SQLite")?;
    let postgres = scan_migration_tree(postgres_migrations_dir, "PostgreSQL")?;
    render_inventory(
        &sqlite,
        &postgres,
        families,
        migration_file_hashes(sqlite_migrations_dir, postgres_migrations_dir)?,
    )
}

/// Generates an inventory from a live SQLite scan of `sqlite_migrations_dir`
/// and a parsed PostgreSQL scan of `postgres_migrations_dir`, with caller
/// supplied generic object owners.
#[cfg(test)]
fn generate_inventory_with_owners(
    sqlite_migrations_dir: &Path,
    postgres_migrations_dir: &Path,
    families: &[RepositoryFamily],
    owners: &GenericOwners<'_>,
) -> Result<String, StateInventoryError> {
    let sqlite = scan_sqlite_live_tree(sqlite_migrations_dir)?;
    let postgres = scan_migration_tree(postgres_migrations_dir, "PostgreSQL")?;
    render_inventory_with_owners(
        &sqlite,
        &postgres,
        families,
        migration_file_hashes(sqlite_migrations_dir, postgres_migrations_dir)?,
        owners,
    )
}

/// Generic owner tables for catalog objects without a table owner.
#[cfg(test)]
#[derive(Clone, Copy)]
struct GenericOwners<'a> {
    functions: &'a [(&'a str, &'a str)],
    views: &'a [(&'a str, &'a str)],
    sequences: &'a [(&'a str, &'a str)],
}

#[cfg(test)]
const REVIEWED_GENERIC_OWNERS: GenericOwners<'static> = GenericOwners {
    functions: GENERIC_FUNCTION_OWNERS,
    views: GENERIC_VIEW_OWNERS,
    sequences: GENERIC_SEQUENCE_OWNERS,
};

/// One reviewed catalog-object definition parsed from a migration tree.
#[cfg(test)]
#[derive(Debug, Clone, PartialEq, Eq)]
struct ObjectDefinition {
    kind: &'static str,
    /// Emitted, collision-safe catalog name.
    name: String,
    /// Owner table from `ON <table>`/`ALTER TABLE`; `None` for views,
    /// sequences and functions.
    table: Option<String>,
    definition: String,
}

/// One migration tree: effective table definitions, collision-safe catalog
/// object maps, per-table and per-object migration lineage, and the migration
/// stems it contains.
#[cfg(test)]
struct MigrationTree {
    tree: &'static str,
    definitions: BTreeMap<String, String>,
    views: BTreeMap<String, ObjectDefinition>,
    sequences: BTreeMap<String, ObjectDefinition>,
    indexes: BTreeMap<String, ObjectDefinition>,
    constraints: BTreeMap<(String, String), ObjectDefinition>,
    triggers: BTreeMap<(String, String), ObjectDefinition>,
    functions: BTreeMap<(String, String), ObjectDefinition>,
    references: BTreeMap<String, BTreeSet<String>>,
    /// Migration stems that define the object identified by `(kind, name)`.
    object_stems: BTreeMap<(String, String), BTreeSet<String>>,
    stems: BTreeSet<String>,
    autoincrement: bool,
}

#[cfg(test)]
impl MigrationTree {
    fn empty(tree: &'static str) -> Self {
        Self {
            tree,
            definitions: BTreeMap::new(),
            views: BTreeMap::new(),
            sequences: BTreeMap::new(),
            indexes: BTreeMap::new(),
            constraints: BTreeMap::new(),
            triggers: BTreeMap::new(),
            functions: BTreeMap::new(),
            references: BTreeMap::new(),
            object_stems: BTreeMap::new(),
            stems: BTreeSet::new(),
            autoincrement: false,
        }
    }

    /// Records that `stem` defines the object named `(kind, name)`.
    fn record_object_stem(&mut self, stem: &str, kind: &str, name: &str) {
        self.object_stems
            .entry((kind.to_owned(), name.to_owned()))
            .or_default()
            .insert(stem.to_owned());
    }
}

/// Reviewed assignment of the generic operation-integrity functions.
///
/// A PostgreSQL function has no `ON <table>` clause, so it cannot be assigned
/// to a repository by table ownership. Every reviewed function must appear
/// here (by bare name; the owner applies to every overload); [`render_inventory`]
/// fails on an unlisted function instead of silently omitting it.
#[cfg(test)]
const GENERIC_FUNCTION_OWNERS: &[(&str, &str)] = &[
    ("o3k_delete_generic_resource_operations", "operations"),
    ("o3k_validate_operation_resource_reference", "operations"),
];

/// Reviewed assignment of views that have no table owner.
///
/// No reviewed migration creates a view yet, but the generator emits them and a
/// live SQLite/PostgreSQL capture must not silently drop one. Add
/// `(view name, repository id)` here when a migration introduces one.
#[cfg(test)]
const GENERIC_VIEW_OWNERS: &[(&str, &str)] = &[];

/// Reviewed assignment of sequences that have no table owner.
#[cfg(test)]
const GENERIC_SEQUENCE_OWNERS: &[(&str, &str)] = &[];

#[cfg(test)]
fn migration_paths(migrations_dir: &Path) -> Result<Vec<PathBuf>, StateInventoryError> {
    let entries =
        fs::read_dir(migrations_dir).map_err(|source| StateInventoryError::ReadDirectory {
            path: migrations_dir.to_path_buf(),
            source,
        })?;
    let mut migration_paths = Vec::new();
    for entry in entries {
        let entry = entry.map_err(|source| StateInventoryError::ReadDirectory {
            path: migrations_dir.to_path_buf(),
            source,
        })?;
        let path = entry.path();
        if path.extension().and_then(|extension| extension.to_str()) == Some("sql") {
            migration_paths.push(path);
        }
    }
    migration_paths.sort();
    Ok(migration_paths)
}

/// SHA-256 of every raw `.sql` file in both migration trees, keyed by the
/// committed repository-relative path.
#[cfg(test)]
fn migration_file_hashes(
    sqlite_dir: &Path,
    postgres_dir: &Path,
) -> Result<BTreeMap<String, String>, StateInventoryError> {
    let mut hashes = BTreeMap::new();
    for (directory, prefix) in [
        (sqlite_dir, "migrations/"),
        (postgres_dir, "migrations_postgres/"),
    ] {
        for path in migration_paths(directory)? {
            let name = path
                .file_name()
                .and_then(|name| name.to_str())
                .ok_or_else(|| {
                    StateInventoryError::InvalidBaseline(format!(
                        "migration file {} has no UTF-8 name",
                        path.display()
                    ))
                })?;
            let bytes = fs::read(&path).map_err(|source| StateInventoryError::ReadMigration {
                path: path.clone(),
                source,
            })?;
            hashes.insert(format!("{prefix}{name}"), sha256_hex_bytes(&bytes));
        }
    }
    Ok(hashes)
}

/// Reads one migration file and returns its stem and comment-free SQL.
#[cfg(test)]
fn read_migration_code(path: &Path) -> Result<(String, String), StateInventoryError> {
    let stem = path
        .file_stem()
        .map(|stem| stem.to_string_lossy().into_owned())
        .ok_or_else(|| {
            StateInventoryError::InvalidBaseline(format!(
                "migration file {} has no file stem",
                path.display()
            ))
        })?;
    let sql = fs::read_to_string(path).map_err(|source| StateInventoryError::ReadMigration {
        path: path.to_path_buf(),
        source,
    })?;
    Ok((stem, strip_sql_comments(&sql)))
}

#[cfg(test)]
fn scan_migration_tree(
    migrations_dir: &Path,
    tree: &'static str,
) -> Result<MigrationTree, StateInventoryError> {
    let migration_paths = migration_paths(migrations_dir)?;
    let mut scanned = MigrationTree::empty(tree);
    for path in migration_paths {
        let (stem, code) = read_migration_code(&path)?;
        if code.to_ascii_uppercase().contains("AUTOINCREMENT") {
            scanned.autoincrement = true;
        }
        scanned.stems.insert(stem.clone());
        for statement in split_sql_statements(&code) {
            apply_migration_statement(&mut scanned, &stem, statement)?;
        }
        for table in migration_table_references(&code) {
            scanned
                .references
                .entry(table)
                .or_default()
                .insert(stem.clone());
        }
    }
    if scanned.definitions.is_empty() {
        return Err(StateInventoryError::InvalidBaseline(format!(
            "migration directory {} defines no tables",
            migrations_dir.display()
        )));
    }
    Ok(scanned)
}

/// Applies one statement of a migration file to the tree being scanned.
///
/// Statements are applied in source order so a table rebuild, an `ALTER TABLE`
/// effect and a later `DROP` interact exactly as they do when the migration is
/// executed. ALTER effects are merged here for every parsed tree; the SQLite
/// side of the committed baseline is read from a live `sqlite_master` instead,
/// where SQLite has already applied them, so no effect is applied twice.
#[cfg(test)]
fn apply_migration_statement(
    scanned: &mut MigrationTree,
    stem: &str,
    statement: &str,
) -> Result<(), StateInventoryError> {
    let tree = scanned.tree;
    let context = |detail: String| {
        StateInventoryError::InvalidBaseline(format!("{tree} migration {stem}: {detail}"))
    };

    for (table, definition) in parse_create_tables(statement) {
        insert_table_definition(scanned, stem, &table, definition);
    }
    for (name, definition) in parse_create_views(statement).map_err(context)? {
        scanned.record_object_stem(stem, "view", &name);
        scanned.views.insert(
            name.clone(),
            ObjectDefinition {
                kind: "view",
                name,
                table: None,
                definition,
            },
        );
    }
    for (name, definition) in parse_create_sequences(statement).map_err(context)? {
        scanned.record_object_stem(stem, "sequence", &name);
        scanned.sequences.insert(
            name.clone(),
            ObjectDefinition {
                kind: "sequence",
                name,
                table: None,
                definition,
            },
        );
    }
    for (name, table, definition) in parse_create_indexes(statement).map_err(context)? {
        scanned.record_object_stem(stem, "index", &name);
        scanned.indexes.insert(
            name.clone(),
            ObjectDefinition {
                kind: "index",
                name,
                table: Some(table),
                definition,
            },
        );
    }
    for (table, name, definition) in parse_create_triggers(statement).map_err(context)? {
        let emitted = trigger_catalog_name(&table, &name);
        scanned.record_object_stem(stem, "trigger", &emitted);
        scanned.triggers.insert(
            (table.clone(), name),
            ObjectDefinition {
                kind: "trigger",
                name: emitted,
                table: Some(table),
                definition,
            },
        );
    }
    for (name, signature, definition) in parse_create_functions(statement).map_err(context)? {
        let emitted = function_catalog_name(&name, &signature);
        scanned.record_object_stem(stem, "function", &emitted);
        scanned.functions.insert(
            (name, signature),
            ObjectDefinition {
                kind: "function",
                name: emitted,
                table: None,
                definition,
            },
        );
    }
    for (table, action) in parse_alter_table_actions(statement).map_err(context)? {
        apply_alter_table_action(scanned, stem, &table, action).map_err(context)?;
    }
    for drop in parse_drop_objects(statement).map_err(context)? {
        apply_drop(scanned, drop);
    }
    if let Some((kind, name)) = unsupported_catalog_statement(statement) {
        return Err(StateInventoryError::UnsupportedCatalogObject { tree, kind, name });
    }
    Ok(())
}

/// Replaces a table definition and rebuilds its inline named constraints.
#[cfg(test)]
fn insert_table_definition(
    scanned: &mut MigrationTree,
    stem: &str,
    table: &str,
    definition: String,
) {
    scanned.constraints.retain(|(owner, _), _| owner != table);
    for (name, constraint_definition) in parse_inline_constraints(table, &definition) {
        scanned.record_object_stem(stem, "constraint", &name);
        scanned.constraints.insert(
            (table.to_owned(), name.clone()),
            ObjectDefinition {
                kind: "constraint",
                name,
                table: Some(table.to_owned()),
                definition: constraint_definition,
            },
        );
    }
    scanned.definitions.insert(table.to_owned(), definition);
}

/// Applies one `ALTER TABLE` action to the table definition or constraint map.
#[cfg(test)]
fn apply_alter_table_action(
    scanned: &mut MigrationTree,
    stem: &str,
    table: &str,
    action: AlterTableAction,
) -> Result<(), String> {
    if let AlterTableAction::DropConstraint { name } = &action {
        scanned
            .constraints
            .remove(&(table.to_owned(), name.clone()));
        return Ok(());
    }
    let Some(definition) = scanned.definitions.get(table).cloned() else {
        return Err(format!(
            "ALTER TABLE targets table {table:?} with no CREATE TABLE"
        ));
    };
    let mut items = table_definition_items(&definition)
        .ok_or_else(|| format!("table {table:?} definition has no column list"))?;
    match action {
        AlterTableAction::AddColumn {
            name,
            definition: column,
            if_not_exists,
        } => {
            if let Some(index) = items
                .iter()
                .position(|item| column_name(item).as_deref() == Some(name.as_str()))
            {
                if !if_not_exists {
                    items[index] = column;
                }
            } else {
                items.push(column);
            }
        }
        AlterTableAction::AddTableItem { item } => items.push(item),
        AlterTableAction::DropColumn { name } => {
            items.retain(|item| column_name(item).as_deref() != Some(name.as_str()));
        }
        AlterTableAction::RenameColumn { from, to } => {
            if let Some(item) = items
                .iter_mut()
                .find(|item| column_name(item).as_deref() == Some(from.as_str()))
            {
                *item = rename_column_item(item, &to);
            }
        }
        AlterTableAction::AddConstraint {
            name,
            definition: constraint_definition,
        } => {
            let constraint = ObjectDefinition {
                kind: "constraint",
                name: name.clone(),
                table: Some(table.to_owned()),
                definition: constraint_definition,
            };
            scanned.record_object_stem(stem, "constraint", &name);
            scanned
                .constraints
                .insert((table.to_owned(), name), constraint);
            return Ok(());
        }
        AlterTableAction::DropConstraint { .. } => unreachable!("handled above"),
        AlterTableAction::RenameTable => return Ok(()),
    }
    scanned.definitions.insert(
        table.to_owned(),
        rebuild_table_definition(&definition, &items),
    );
    Ok(())
}

#[cfg(test)]
fn apply_drop(scanned: &mut MigrationTree, drop: DropObject) {
    match drop {
        DropObject::Table(table) => {
            scanned.definitions.remove(&table);
            scanned.constraints.retain(|(owner, _), _| owner != &table);
            scanned
                .indexes
                .retain(|_, object| object.table.as_deref() != Some(table.as_str()));
            scanned.triggers.retain(|(owner, _), _| owner != &table);
        }
        DropObject::Index(name) => {
            scanned.indexes.remove(&name);
        }
        DropObject::Trigger { table, name } => {
            if let Some(table) = table {
                scanned.triggers.remove(&(table, name));
            } else {
                scanned.triggers.retain(|(_, trigger), _| trigger != &name);
            }
        }
        DropObject::View(name) => {
            scanned.views.remove(&name);
        }
        DropObject::Sequence(name) => {
            scanned.sequences.remove(&name);
        }
    }
}

/// Builds the SQLite side of the baseline by executing the reviewed migration
/// files in an empty in-memory database and reading the resulting
/// `sqlite_master` definitions.
///
/// This is required because SQLite rewrites a table's stored `CREATE TABLE`
/// text when a later migration runs `ALTER TABLE ... ADD COLUMN`. Parsing only
/// `CREATE TABLE` statements would produce a digest that the capture-time live
/// catalog comparison can never match. The effective definition is therefore
/// the definition SQLite itself records. The committed baseline is tied to the
/// bundled SQLite version used by the build and by the artifact binary.
///
/// Views created by a migration or by the runtime schema are emitted as
/// `view` objects instead of being rejected. Sequences are PostgreSQL-only, so
/// the SQLite tree has none. Definition digests are derived from the statement
/// text with the same normalization as the parsed PostgreSQL tree.
#[cfg(test)]
fn scan_sqlite_live_tree(migrations_dir: &Path) -> Result<MigrationTree, StateInventoryError> {
    use sqlx::Row as _;

    let migration_paths = migration_paths(migrations_dir)?;
    // The parsed tree supplies the migration lineage and object-defining
    // migration ids; only the catalog definitions are replaced by the live
    // `sqlite_master` text below.
    let parsed = scan_migration_tree(migrations_dir, "SQLite")?;
    let mut scanned = MigrationTree {
        definitions: BTreeMap::new(),
        indexes: BTreeMap::new(),
        triggers: BTreeMap::new(),
        views: BTreeMap::new(),
        sequences: BTreeMap::new(),
        constraints: BTreeMap::new(),
        functions: BTreeMap::new(),
        references: parsed.references,
        object_stems: parsed.object_stems,
        stems: parsed.stems,
        autoincrement: parsed.autoincrement,
        tree: "SQLite",
    };
    let mut migration_sql = Vec::with_capacity(migration_paths.len());
    for path in &migration_paths {
        let (stem, code) = read_migration_code(path)?;
        if code.to_ascii_uppercase().contains("AUTOINCREMENT") {
            scanned.autoincrement = true;
        }
        let sql =
            fs::read_to_string(path).map_err(|source| StateInventoryError::ReadMigration {
                path: path.clone(),
                source,
            })?;
        migration_sql.push((stem, sql));
    }

    let runtime = tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()
        .map_err(|error| {
            StateInventoryError::InvalidBaseline(format!(
                "cannot build the SQLite catalog runtime: {error}"
            ))
        })?;
    let rows = runtime.block_on(async {
        let pool = sqlx::sqlite::SqlitePoolOptions::new()
            .max_connections(1)
            .connect("sqlite::memory:")
            .await
            .map_err(|error| {
                StateInventoryError::InvalidBaseline(format!(
                    "cannot open the in-memory SQLite catalog: {error}"
                ))
            })?;
        for (stem, sql) in &migration_sql {
            sqlx::raw_sql(sql).execute(&pool).await.map_err(|error| {
                StateInventoryError::InvalidBaseline(format!(
                    "SQLite migration {stem} does not apply to an empty catalog: {error}"
                ))
            })?;
        }
        crate::sqlite::apply_test_runtime_schema(&pool)
            .await
            .map_err(|error| {
                StateInventoryError::InvalidBaseline(format!(
                    "SQLite runtime schema migration failed: {error}"
                ))
            })?;
        let rows = sqlx::query(
            "SELECT type, name, tbl_name, sql FROM sqlite_master \
             WHERE sql IS NOT NULL AND name NOT GLOB 'sqlite_*' \
             ORDER BY type, name",
        )
        .fetch_all(&pool)
        .await
        .map_err(|error| {
            StateInventoryError::InvalidBaseline(format!(
                "cannot read the in-memory SQLite catalog: {error}"
            ))
        })?;
        pool.close().await;
        Ok::<_, StateInventoryError>(rows)
    })?;

    for row in rows {
        let kind: String = row.try_get(0).map_err(|error| {
            StateInventoryError::InvalidBaseline(format!("SQLite catalog type: {error}"))
        })?;
        let name: String = row.try_get(1).map_err(|error| {
            StateInventoryError::InvalidBaseline(format!("SQLite catalog name: {error}"))
        })?;
        let table: String = row.try_get(2).map_err(|error| {
            StateInventoryError::InvalidBaseline(format!("SQLite catalog owner: {error}"))
        })?;
        let sql: String = row.try_get(3).map_err(|error| {
            StateInventoryError::InvalidBaseline(format!("SQLite catalog SQL: {error}"))
        })?;
        let definition = normalize_catalog_definition(&kind, &sql).ok_or_else(|| {
            StateInventoryError::UnsupportedCatalogObject {
                tree: "SQLite",
                kind: "catalog",
                name: name.clone(),
            }
        })?;
        match kind.as_str() {
            "table" => {
                scanned.definitions.insert(name, definition);
            }
            "index" => {
                scanned.indexes.insert(
                    name.clone(),
                    ObjectDefinition {
                        kind: "index",
                        name,
                        table: Some(table.to_ascii_lowercase()),
                        definition,
                    },
                );
            }
            "trigger" => {
                let table = table.to_ascii_lowercase();
                scanned.triggers.insert(
                    (table.clone(), name.clone()),
                    ObjectDefinition {
                        kind: "trigger",
                        name: trigger_catalog_name(&table, &name),
                        table: Some(table),
                        definition,
                    },
                );
            }
            "view" => {
                scanned.views.insert(
                    name.clone(),
                    ObjectDefinition {
                        kind: "view",
                        name,
                        table: None,
                        definition,
                    },
                );
            }
            _ => {}
        }
    }
    if scanned.definitions.is_empty() {
        return Err(StateInventoryError::InvalidBaseline(format!(
            "migration directory {} defines no tables",
            migrations_dir.display()
        )));
    }
    Ok(scanned)
}
fn strip_sql_comments(sql: &str) -> String {
    let characters: Vec<char> = sql.chars().collect();
    let mut stripped = String::with_capacity(sql.len());
    let mut index = 0;
    let mut quote: Option<char> = None;
    while index < characters.len() {
        let character = characters[index];
        if let Some(terminator) = quote {
            stripped.push(character);
            if character == terminator {
                if characters.get(index + 1) == Some(&terminator) {
                    if let Some(escaped) = characters.get(index + 1) {
                        stripped.push(*escaped);
                    }
                    index += 2;
                    continue;
                }
                quote = None;
            }
            index += 1;
            continue;
        }
        match character {
            '\'' | '"' | '`' => {
                quote = Some(character);
                stripped.push(character);
                index += 1;
            }
            '[' => {
                quote = Some(']');
                stripped.push(character);
                index += 1;
            }
            '$' => {
                let mut cursor = index + 1;
                while cursor < characters.len()
                    && (characters[cursor].is_ascii_alphanumeric() || characters[cursor] == '_')
                {
                    cursor += 1;
                }
                if characters.get(cursor) == Some(&'$') {
                    let delimiter: Vec<char> = characters[index..=cursor].to_vec();
                    for character in &delimiter {
                        stripped.push(*character);
                    }
                    let body_start = cursor + 1;
                    let mut end = body_start;
                    while end + delimiter.len() <= characters.len() {
                        if characters[end..end + delimiter.len()] == delimiter[..] {
                            end += delimiter.len();
                            break;
                        }
                        end += 1;
                    }
                    let end = end.min(characters.len());
                    for character in &characters[body_start..end] {
                        stripped.push(*character);
                    }
                    index = end;
                } else {
                    stripped.push(character);
                    index += 1;
                }
            }
            '-' if characters.get(index + 1) == Some(&'-') => {
                index += 2;
                while index < characters.len() && characters[index] != '\n' {
                    index += 1;
                }
                if index < characters.len() {
                    stripped.push('\n');
                    index += 1;
                }
            }
            '/' if characters.get(index + 1) == Some(&'*') => {
                index += 2;
                stripped.push(' ');
                while index < characters.len() {
                    if characters[index] == '*' && characters.get(index + 1) == Some(&'/') {
                        index += 2;
                        break;
                    }
                    index += 1;
                }
            }
            _ => {
                stripped.push(character);
                index += 1;
            }
        }
    }
    stripped
}

#[derive(Debug)]
struct Token {
    text: String,
    quoted: bool,
    start: usize,
    end: usize,
}

/// Returns the delimiter and the index just past the opening delimiter when a
/// PostgreSQL dollar quote starts at `index` (`$$` or `$tag$`).
fn dollar_quote_open(bytes: &[u8], index: usize) -> Option<(String, usize)> {
    if bytes.get(index) != Some(&b'$') {
        return None;
    }
    let mut cursor = index + 1;
    while cursor < bytes.len() && (bytes[cursor].is_ascii_alphanumeric() || bytes[cursor] == b'_') {
        cursor += 1;
    }
    if bytes.get(cursor) != Some(&b'$') {
        return None;
    }
    Some((
        String::from_utf8_lossy(&bytes[index..=cursor]).into_owned(),
        cursor + 1,
    ))
}

/// Index just past the closing delimiter of a dollar-quoted string, or the end
/// of input when it is unterminated.
fn dollar_quote_close(bytes: &[u8], body_start: usize, delimiter: &str) -> usize {
    let delimiter = delimiter.as_bytes();
    let mut cursor = body_start;
    while cursor + delimiter.len() <= bytes.len() {
        if &bytes[cursor..cursor + delimiter.len()] == delimiter {
            return cursor + delimiter.len();
        }
        cursor += 1;
    }
    bytes.len()
}

/// Splits SQL into tokens, recording byte offsets in `code`. Quoted
/// identifiers, string literals and PostgreSQL dollar-quoted bodies become
/// single tokens; parentheses, commas and statement terminators become their
/// own tokens.
fn tokenize(code: &str) -> Vec<Token> {
    let bytes = code.as_bytes();
    let mut tokens = Vec::new();
    let mut index = 0;
    while index < bytes.len() {
        let byte = bytes[index];
        if byte.is_ascii_whitespace() {
            index += 1;
            continue;
        }
        match byte {
            b'\'' | b'"' | b'`' => {
                let start = index;
                index += 1;
                while index < bytes.len() {
                    if bytes[index] == byte {
                        if bytes.get(index + 1) == Some(&byte) {
                            index += 2;
                            continue;
                        }
                        index += 1;
                        break;
                    }
                    index += 1;
                }
                let content_end = if index > start + 1 && bytes.get(index - 1) == Some(&byte) {
                    index - 1
                } else {
                    index
                };
                let text = code[start + 1..content_end].to_owned();
                tokens.push(Token {
                    text,
                    quoted: true,
                    start,
                    end: index,
                });
            }
            b'[' => {
                let start = index;
                index += 1;
                while index < bytes.len() && bytes[index] != b']' {
                    index += 1;
                }
                let text = code[start + 1..index].to_owned();
                index = (index + 1).min(bytes.len());
                tokens.push(Token {
                    text,
                    quoted: true,
                    start,
                    end: index,
                });
            }
            b'$' => {
                if let Some((delimiter, body_start)) = dollar_quote_open(bytes, index) {
                    let start = index;
                    index = dollar_quote_close(bytes, body_start, &delimiter);
                    tokens.push(Token {
                        text: code[start..index].to_owned(),
                        quoted: true,
                        start,
                        end: index,
                    });
                } else {
                    let start = index;
                    while index < bytes.len()
                        && !bytes[index].is_ascii_whitespace()
                        && !matches!(
                            bytes[index],
                            b'(' | b')' | b',' | b';' | b'\'' | b'"' | b'`'
                        )
                    {
                        index += 1;
                    }
                    tokens.push(Token {
                        text: code[start..index].to_owned(),
                        quoted: false,
                        start,
                        end: index,
                    });
                }
            }
            b'(' | b')' | b',' | b';' => {
                tokens.push(Token {
                    text: (byte as char).to_string(),
                    quoted: false,
                    start: index,
                    end: index + 1,
                });
                index += 1;
            }
            _ => {
                let start = index;
                while index < bytes.len()
                    && !bytes[index].is_ascii_whitespace()
                    && !matches!(
                        bytes[index],
                        b'(' | b')' | b',' | b';' | b'\'' | b'"' | b'`'
                    )
                {
                    index += 1;
                }
                tokens.push(Token {
                    text: code[start..index].to_owned(),
                    quoted: false,
                    start,
                    end: index,
                });
            }
        }
    }
    tokens
}

fn is_keyword(tokens: &[Token], index: usize, keyword: &str) -> bool {
    tokens
        .get(index)
        .is_some_and(|token| !token.quoted && token.text.eq_ignore_ascii_case(keyword))
}

fn skip_exists_clause(tokens: &[Token], index: usize) -> usize {
    if is_keyword(tokens, index, "if") {
        if is_keyword(tokens, index + 1, "not") && is_keyword(tokens, index + 2, "exists") {
            return index + 3;
        }
        if is_keyword(tokens, index + 1, "exists") {
            return index + 2;
        }
    }
    index
}

/// Returns `(table, normalized definition)` for every `CREATE TABLE` statement
/// in `code`, in file order.
fn parse_create_tables(code: &str) -> Vec<(String, String)> {
    let tokens = tokenize(code);
    let mut statements = Vec::new();
    let mut index = 0;
    while index < tokens.len() {
        if is_keyword(&tokens, index, "create") && is_keyword(&tokens, index + 1, "table") {
            let name_index = skip_exists_clause(&tokens, index + 2);
            let Some(name) = tokens.get(name_index) else {
                index += 1;
                continue;
            };
            let mut open = name_index + 1;
            while open < tokens.len() && (tokens[open].quoted || tokens[open].text != "(") {
                open += 1;
            }
            let mut depth = 0_i32;
            let mut close = None;
            for (offset, token) in tokens.iter().enumerate().skip(open) {
                if token.quoted {
                    continue;
                }
                match token.text.as_str() {
                    "(" => depth += 1,
                    ")" => {
                        depth -= 1;
                        if depth == 0 {
                            close = Some(offset);
                            break;
                        }
                    }
                    _ => {}
                }
            }
            if let Some(close) = close {
                let definition =
                    normalized_definition(&code[tokens[index].start..tokens[close].end]);
                statements.push((name.text.to_ascii_lowercase(), definition));
                index = close;
            }
        }
        index += 1;
    }
    statements
}

/// Normalizes a catalog definition of any supported kind.
///
/// Tables are reduced to the `CREATE TABLE ... ( ... )` form; every other kind
/// keeps its whole statement (minus the terminator). Returns `None` for a kind
/// whose definition grammar this module does not understand.
pub fn normalize_catalog_definition(kind: &str, statement: &str) -> Option<String> {
    let code = strip_sql_comments(statement);
    match kind {
        "table" => parse_create_tables(&code)
            .into_iter()
            .next()
            .map(|(_, definition)| definition),
        "index" | "trigger" | "function" | "view" | "sequence" | "constraint" => {
            Some(normalized_definition(code.trim()))
        }
        _ => None,
    }
}

/// Index of the token that terminates the statement starting at `start`.
///
/// With `block_aware`, `BEGIN`/`CASE` ... `END` blocks keep their inner
/// semicolons from terminating the statement (SQLite trigger bodies).
#[cfg(test)]
fn statement_terminator(tokens: &[Token], start: usize, block_aware: bool) -> usize {
    let mut depth = 0_i32;
    for (offset, token) in tokens.iter().enumerate().skip(start) {
        if token.quoted {
            continue;
        }
        if block_aware {
            if token.text.eq_ignore_ascii_case("begin") || token.text.eq_ignore_ascii_case("case") {
                depth += 1;
            } else if token.text.eq_ignore_ascii_case("end") {
                depth = (depth - 1).max(0);
            }
        }
        if token.text == ";" && (!block_aware || depth == 0) {
            return offset;
        }
    }
    tokens.len()
}

/// Returns `(name, owner table, normalized definition)` for every
/// `CREATE [UNIQUE] INDEX` statement in `code`, in file order.
#[cfg(test)]
fn parse_create_indexes(code: &str) -> Result<Vec<(String, String, String)>, String> {
    let tokens = tokenize(code);
    let mut indexes = Vec::new();
    let mut index = 0;
    while index < tokens.len() {
        if is_keyword(&tokens, index, "create") {
            let mut at = index + 1;
            if is_keyword(&tokens, at, "unique") {
                at += 1;
            }
            if is_keyword(&tokens, at, "index") {
                let mut name_index = at + 1;
                if is_keyword(&tokens, name_index, "concurrently") {
                    name_index += 1;
                }
                let name_index = skip_exists_clause(&tokens, name_index);
                let name = tokens
                    .get(name_index)
                    .ok_or_else(|| "CREATE INDEX has no name".to_owned())?;
                let mut cursor = name_index + 1;
                while cursor < tokens.len()
                    && !is_keyword(&tokens, cursor, "on")
                    && tokens[cursor].text != ";"
                {
                    cursor += 1;
                }
                if !is_keyword(&tokens, cursor, "on") {
                    return Err(format!("CREATE INDEX {:?} has no ON clause", name.text));
                }
                let mut table_index = cursor + 1;
                if is_keyword(&tokens, table_index, "only") {
                    table_index += 1;
                }
                let table = tokens
                    .get(table_index)
                    .ok_or_else(|| format!("CREATE INDEX {:?} has no owner table", name.text))?;
                let terminator = statement_terminator(&tokens, index, false);
                let end = tokens
                    .get(terminator)
                    .map_or(code.len(), |token| token.start);
                let definition = normalized_definition(&code[tokens[index].start..end]);
                indexes.push((
                    name.text.to_ascii_lowercase(),
                    table.text.to_ascii_lowercase(),
                    definition,
                ));
                index = terminator;
            }
        }
        index += 1;
    }
    Ok(indexes)
}

/// Emitted, collision-safe catalog name for a trigger.
///
/// PostgreSQL trigger names are unique only per table, so the inventory uses
/// `<table>.<name>` as the object identity.
#[cfg(test)]
fn trigger_catalog_name(table: &str, name: &str) -> String {
    format!("{table}.{name}")
}

/// Emitted, collision-safe catalog name for a function.
///
/// PostgreSQL functions are identified by name plus argument types, so the
/// inventory uses `name(normalized argument list)` as the object identity.
#[cfg(test)]
fn function_catalog_name(name: &str, signature: &str) -> String {
    format!("{name}({signature})")
}

/// Normalizes a function argument list: layout-only whitespace is removed and
/// the original spelling, case and quoting are preserved.
#[cfg(test)]
fn normalized_signature(signature: &str) -> String {
    tidy_punctuation(&collapse_whitespace(signature))
        .trim()
        .to_owned()
}

/// Returns `(owner table, name, normalized definition)` for every
/// `CREATE [OR REPLACE] TRIGGER` statement in `code`, in file order.
#[cfg(test)]
fn parse_create_triggers(code: &str) -> Result<Vec<(String, String, String)>, String> {
    let tokens = tokenize(code);
    let mut triggers = Vec::new();
    let mut index = 0;
    while index < tokens.len() {
        if is_keyword(&tokens, index, "create") {
            let mut at = index + 1;
            if is_keyword(&tokens, at, "or") && is_keyword(&tokens, at + 1, "replace") {
                at += 2;
            }
            if is_keyword(&tokens, at, "trigger") {
                let name_index = skip_exists_clause(&tokens, at + 1);
                let name = tokens
                    .get(name_index)
                    .ok_or_else(|| "CREATE TRIGGER has no name".to_owned())?;
                let mut cursor = name_index + 1;
                while cursor < tokens.len()
                    && !is_keyword(&tokens, cursor, "on")
                    && tokens[cursor].text != ";"
                    && !is_keyword(&tokens, cursor, "begin")
                    && !is_keyword(&tokens, cursor, "execute")
                {
                    cursor += 1;
                }
                if !is_keyword(&tokens, cursor, "on") {
                    return Err(format!("CREATE TRIGGER {:?} has no ON clause", name.text));
                }
                let mut table_index = cursor + 1;
                if is_keyword(&tokens, table_index, "only") {
                    table_index += 1;
                }
                let table = tokens
                    .get(table_index)
                    .ok_or_else(|| format!("CREATE TRIGGER {:?} has no owner table", name.text))?;
                let terminator = statement_terminator(&tokens, index, true);
                let end = tokens
                    .get(terminator)
                    .map_or(code.len(), |token| token.start);
                let definition = normalized_definition(&code[tokens[index].start..end]);
                triggers.push((
                    table.text.to_ascii_lowercase(),
                    name.text.to_ascii_lowercase(),
                    definition,
                ));
                index = terminator;
            }
        }
        index += 1;
    }
    Ok(triggers)
}

/// Splits one `CREATE FUNCTION` argument list at `open`.
///
/// Returns the index of the matching closing parenthesis and the normalized
/// argument signature.
#[cfg(test)]
fn function_argument_signature(
    tokens: &[Token],
    code: &str,
    open: usize,
) -> Result<(usize, String), String> {
    if tokens.get(open).is_none_or(|token| token.text != "(") {
        return Err("CREATE FUNCTION has no argument list".to_owned());
    }
    let mut depth = 0_i32;
    for (offset, token) in tokens.iter().enumerate().skip(open) {
        if token.quoted {
            continue;
        }
        match token.text.as_str() {
            "(" => depth += 1,
            ")" => {
                depth -= 1;
                if depth == 0 {
                    let signature = normalized_signature(&code[tokens[open].end..token.start]);
                    return Ok((offset, signature));
                }
            }
            _ => {}
        }
    }
    Err("CREATE FUNCTION argument list is unterminated".to_owned())
}

/// Returns `(name, normalized argument signature, normalized definition)` for
/// every `CREATE [OR REPLACE] FUNCTION` statement in `code`, in file order.
#[cfg(test)]
fn parse_create_functions(code: &str) -> Result<Vec<(String, String, String)>, String> {
    let tokens = tokenize(code);
    let mut functions = Vec::new();
    let mut index = 0;
    while index < tokens.len() {
        if is_keyword(&tokens, index, "create") {
            let mut at = index + 1;
            if is_keyword(&tokens, at, "or") && is_keyword(&tokens, at + 1, "replace") {
                at += 2;
            }
            if is_keyword(&tokens, at, "function") {
                let name = tokens
                    .get(at + 1)
                    .ok_or_else(|| "CREATE FUNCTION has no name".to_owned())?;
                let (_, signature) = function_argument_signature(&tokens, code, at + 2)?;
                let terminator = statement_terminator(&tokens, index, false);
                let end = tokens
                    .get(terminator)
                    .map_or(code.len(), |token| token.start);
                let definition = normalized_definition(&code[tokens[index].start..end]);
                functions.push((name.text.to_ascii_lowercase(), signature, definition));
                index = terminator;
            }
        }
        index += 1;
    }
    Ok(functions)
}

/// Returns `(name, normalized definition)` for every
/// `CREATE [OR REPLACE] [MATERIALIZED] [TEMP] VIEW` statement in `code`, in
/// file order.
#[cfg(test)]
fn parse_create_views(code: &str) -> Result<Vec<(String, String)>, String> {
    let tokens = tokenize(code);
    let mut views = Vec::new();
    let mut index = 0;
    while index < tokens.len() {
        if is_keyword(&tokens, index, "create") {
            let mut at = index + 1;
            if is_keyword(&tokens, at, "or") && is_keyword(&tokens, at + 1, "replace") {
                at += 2;
            }
            if is_keyword(&tokens, at, "materialized") {
                at += 1;
            }
            if is_keyword(&tokens, at, "temp") || is_keyword(&tokens, at, "temporary") {
                at += 1;
            }
            if is_keyword(&tokens, at, "view") {
                let name_index = skip_exists_clause(&tokens, at + 1);
                let name = tokens
                    .get(name_index)
                    .ok_or_else(|| "CREATE VIEW has no name".to_owned())?;
                let terminator = statement_terminator(&tokens, index, false);
                let end = tokens
                    .get(terminator)
                    .map_or(code.len(), |token| token.start);
                views.push((
                    name.text.to_ascii_lowercase(),
                    normalized_definition(&code[tokens[index].start..end]),
                ));
                index = terminator;
            }
        }
        index += 1;
    }
    Ok(views)
}

/// Returns `(name, normalized definition)` for every
/// `CREATE [TEMPORARY|UNLOGGED] SEQUENCE` statement in `code`, in file order.
#[cfg(test)]
fn parse_create_sequences(code: &str) -> Result<Vec<(String, String)>, String> {
    let tokens = tokenize(code);
    let mut sequences = Vec::new();
    let mut index = 0;
    while index < tokens.len() {
        if is_keyword(&tokens, index, "create") {
            let mut at = index + 1;
            if is_keyword(&tokens, at, "temp")
                || is_keyword(&tokens, at, "temporary")
                || is_keyword(&tokens, at, "unlogged")
            {
                at += 1;
            }
            if is_keyword(&tokens, at, "sequence") {
                let name_index = skip_exists_clause(&tokens, at + 1);
                let name = tokens
                    .get(name_index)
                    .ok_or_else(|| "CREATE SEQUENCE has no name".to_owned())?;
                let terminator = statement_terminator(&tokens, index, false);
                let end = tokens
                    .get(terminator)
                    .map_or(code.len(), |token| token.start);
                sequences.push((
                    name.text.to_ascii_lowercase(),
                    normalized_definition(&code[tokens[index].start..end]),
                ));
                index = terminator;
            }
        }
        index += 1;
    }
    Ok(sequences)
}

/// One effect of an `ALTER TABLE` statement.
#[cfg(test)]
#[derive(Debug, Clone, PartialEq, Eq)]
enum AlterTableAction {
    AddColumn {
        name: String,
        definition: String,
        if_not_exists: bool,
    },
    /// An unnamed table constraint (`ADD PRIMARY KEY ...`), which stays inside
    /// the table definition digest like every other implicit constraint.
    AddTableItem {
        item: String,
    },
    DropColumn {
        name: String,
    },
    RenameColumn {
        from: String,
        to: String,
    },
    AddConstraint {
        name: String,
        definition: String,
    },
    DropConstraint {
        name: String,
    },
    /// `ALTER TABLE ... RENAME TO`; the parsed tree does not move definitions
    /// between names (no reviewed PostgreSQL migration uses it, and the SQLite
    /// baseline is read from the live catalog).
    RenameTable,
}

/// Returns `(table, action)` for every effect of every `ALTER TABLE` statement
/// in `code`, in file order.
#[cfg(test)]
fn parse_alter_table_actions(code: &str) -> Result<Vec<(String, AlterTableAction)>, String> {
    let tokens = tokenize(code);
    let mut actions = Vec::new();
    let mut index = 0;
    while index < tokens.len() {
        if is_keyword(&tokens, index, "alter") && is_keyword(&tokens, index + 1, "table") {
            let mut at = skip_exists_clause(&tokens, index + 2);
            if is_keyword(&tokens, at, "only") {
                at += 1;
            }
            let table = tokens
                .get(at)
                .ok_or_else(|| "ALTER TABLE has no table name".to_owned())?;
            let table_name = table.text.to_ascii_lowercase();
            let terminator = statement_terminator(&tokens, index, false);
            let mut cursor = at + 1;
            let mut depth = 0_i32;
            let mut action_start = cursor;
            while cursor < terminator {
                if depth == 0 && !tokens[cursor].quoted && tokens[cursor].text == "," {
                    if action_start < cursor {
                        actions.push((
                            table_name.clone(),
                            classify_alter_action(
                                &tokens,
                                action_start,
                                cursor,
                                &table_name,
                                code,
                            )?,
                        ));
                    }
                    action_start = cursor + 1;
                } else if !tokens[cursor].quoted {
                    match tokens[cursor].text.as_str() {
                        "(" => depth += 1,
                        ")" => depth -= 1,
                        _ => {}
                    }
                }
                cursor += 1;
            }
            if action_start < terminator {
                actions.push((
                    table_name.clone(),
                    classify_alter_action(&tokens, action_start, terminator, &table_name, code)?,
                ));
            }
            index = terminator;
        }
        index += 1;
    }
    Ok(actions)
}

#[cfg(test)]
fn classify_alter_action(
    tokens: &[Token],
    start: usize,
    end: usize,
    table: &str,
    code: &str,
) -> Result<AlterTableAction, String> {
    let action_text = || normalized_definition(&code[tokens[start].start..tokens[end - 1].end]);
    if is_keyword(tokens, start, "add") {
        let mut at = start + 1;
        if is_keyword(tokens, at, "column") {
            at += 1;
        }
        if is_keyword(tokens, at, "constraint") {
            let name = tokens
                .get(at + 1)
                .ok_or_else(|| "ALTER TABLE ADD CONSTRAINT has no constraint name".to_owned())?;
            let rest = normalized_definition(&code[name.start..tokens[end - 1].end]);
            return Ok(AlterTableAction::AddConstraint {
                name: name.text.to_ascii_lowercase(),
                definition: format!("ALTER TABLE {table} ADD CONSTRAINT {rest}"),
            });
        }
        if ["primary", "unique", "check", "foreign", "exclude"]
            .iter()
            .any(|keyword| is_keyword(tokens, at, keyword))
        {
            return Ok(AlterTableAction::AddTableItem {
                item: normalized_definition(&code[tokens[start + 1].start..tokens[end - 1].end]),
            });
        }
        let if_not_exists = is_keyword(tokens, at, "if")
            && is_keyword(tokens, at + 1, "not")
            && is_keyword(tokens, at + 2, "exists");
        let name_index = skip_exists_clause(tokens, at);
        let name = tokens
            .get(name_index)
            .ok_or_else(|| "ALTER TABLE ADD COLUMN has no column name".to_owned())?;
        return Ok(AlterTableAction::AddColumn {
            name: name.text.to_ascii_lowercase(),
            definition: normalized_definition(&code[name.start..tokens[end - 1].end]),
            if_not_exists,
        });
    }
    if is_keyword(tokens, start, "drop") {
        if is_keyword(tokens, start + 1, "constraint") {
            let name_index = skip_exists_clause(tokens, start + 2);
            let name = tokens
                .get(name_index)
                .ok_or_else(|| "ALTER TABLE DROP CONSTRAINT has no constraint name".to_owned())?;
            return Ok(AlterTableAction::DropConstraint {
                name: name.text.to_ascii_lowercase(),
            });
        }
        let mut at = start + 1;
        if is_keyword(tokens, at, "column") {
            at += 1;
        }
        let name_index = skip_exists_clause(tokens, at);
        let name = tokens
            .get(name_index)
            .ok_or_else(|| "ALTER TABLE DROP COLUMN has no column name".to_owned())?;
        return Ok(AlterTableAction::DropColumn {
            name: name.text.to_ascii_lowercase(),
        });
    }
    if is_keyword(tokens, start, "rename") {
        if is_keyword(tokens, start + 1, "to") {
            return Ok(AlterTableAction::RenameTable);
        }
        let mut at = start + 1;
        if is_keyword(tokens, at, "column") {
            at += 1;
        }
        let from = tokens
            .get(at)
            .ok_or_else(|| "ALTER TABLE RENAME COLUMN has no source column".to_owned())?;
        if !is_keyword(tokens, at + 1, "to") {
            return Err(format!(
                "ALTER TABLE RENAME COLUMN {:?} has no TO clause",
                from.text
            ));
        }
        let to = tokens
            .get(at + 2)
            .ok_or_else(|| "ALTER TABLE RENAME COLUMN has no target column".to_owned())?;
        return Ok(AlterTableAction::RenameColumn {
            from: from.text.to_ascii_lowercase(),
            to: to.text.clone(),
        });
    }
    Err(format!(
        "unsupported ALTER TABLE action {:?}",
        action_text()
    ))
}

/// A catalog object removed by a `DROP` statement.
#[cfg(test)]
#[derive(Debug, Clone, PartialEq, Eq)]
enum DropObject {
    Table(String),
    Index(String),
    Trigger { table: Option<String>, name: String },
    View(String),
    Sequence(String),
}

/// Returns every catalog object dropped by `code`, in file order.
#[cfg(test)]
fn parse_drop_objects(code: &str) -> Result<Vec<DropObject>, String> {
    let tokens = tokenize(code);
    let mut drops = Vec::new();
    let mut index = 0;
    while index < tokens.len() {
        if !is_keyword(&tokens, index, "drop") {
            index += 1;
            continue;
        }
        let mut at = index + 1;
        if is_keyword(&tokens, at, "materialized") {
            at += 1;
        }
        if is_keyword(&tokens, at, "table") {
            let names = drop_name_list(&tokens, skip_exists_clause(&tokens, at + 1));
            for name in names {
                drops.push(DropObject::Table(name));
            }
        } else if is_keyword(&tokens, at, "index") {
            let mut name_index = at + 1;
            if is_keyword(&tokens, name_index, "concurrently") {
                name_index += 1;
            }
            let names = drop_name_list(&tokens, skip_exists_clause(&tokens, name_index));
            for name in names {
                drops.push(DropObject::Index(name));
            }
        } else if is_keyword(&tokens, at, "view") {
            for name in drop_name_list(&tokens, skip_exists_clause(&tokens, at + 1)) {
                drops.push(DropObject::View(name));
            }
        } else if is_keyword(&tokens, at, "sequence") {
            for name in drop_name_list(&tokens, skip_exists_clause(&tokens, at + 1)) {
                drops.push(DropObject::Sequence(name));
            }
        } else if is_keyword(&tokens, at, "trigger") {
            let name_index = skip_exists_clause(&tokens, at + 1);
            let name = tokens
                .get(name_index)
                .ok_or_else(|| "DROP TRIGGER has no trigger name".to_owned())?;
            let mut table = None;
            let limit = statement_terminator(&tokens, index, true).min(tokens.len());
            for cursor in name_index + 1..limit {
                if is_keyword(&tokens, cursor, "on") {
                    if let Some(owner) = tokens.get(cursor + 1) {
                        table = Some(owner.text.to_ascii_lowercase());
                    }
                    break;
                }
            }
            drops.push(DropObject::Trigger {
                table,
                name: name.text.to_ascii_lowercase(),
            });
        } else {
            index += 1;
            continue;
        }
        index += 1;
    }
    Ok(drops)
}

/// Collects the identifier list that follows a `DROP <kind> [IF EXISTS]`
/// clause, stopping at an option keyword.
#[cfg(test)]
fn drop_name_list(tokens: &[Token], start: usize) -> Vec<String> {
    let mut names = Vec::new();
    let mut cursor = start;
    while let Some(token) = tokens.get(cursor) {
        if token.text == ";" {
            break;
        }
        if token.quoted {
            names.push(token.text.to_ascii_lowercase());
        } else if is_keyword(tokens, cursor, "cascade") || is_keyword(tokens, cursor, "restrict") {
            break;
        } else if token.text != "," {
            names.push(token.text.to_ascii_lowercase());
        }
        cursor += 1;
    }
    names
}

/// Returns a statement kind and name for an object-creating statement the
/// generator does not model.
///
/// Silently omitting a catalog object would make the inventory lie, so an
/// unmodelled `CREATE TYPE`/`ALTER SEQUENCE` (and similar) fails generation.
#[cfg(test)]
fn unsupported_catalog_statement(code: &str) -> Option<(&'static str, String)> {
    const UNSUPPORTED_CREATE: [&str; 6] =
        ["type", "domain", "extension", "policy", "rule", "aggregate"];
    const UNSUPPORTED_ALTER: [&str; 5] = ["sequence", "type", "domain", "policy", "rule"];
    let tokens = tokenize(code);
    let mut index = 0;
    while index < tokens.len() {
        let keywords: &[&str] = if is_keyword(&tokens, index, "create") {
            &UNSUPPORTED_CREATE
        } else if is_keyword(&tokens, index, "alter") {
            &UNSUPPORTED_ALTER
        } else {
            index += 1;
            continue;
        };
        if let Some(kind) = keywords
            .iter()
            .find(|keyword| is_keyword(&tokens, index + 1, keyword))
        {
            let name_index = skip_exists_clause(&tokens, index + 2);
            let name = tokens
                .get(name_index)
                .map_or_else(|| "<unnamed>".to_owned(), |token| token.text.clone());
            return Some((kind, name));
        }
        index += 1;
    }
    None
}

/// Splits comment-free SQL into statements, keeping `BEGIN ... END` blocks
/// (SQLite trigger bodies) intact.
#[cfg(test)]
fn split_sql_statements(code: &str) -> Vec<&str> {
    let tokens = tokenize(code);
    let mut statements = Vec::new();
    let mut start = 0;
    while start < tokens.len() {
        let terminator = statement_terminator(&tokens, start, true);
        let end = tokens
            .get(terminator)
            .map_or(code.len(), |token| token.start);
        let statement = code[tokens[start].start..end].trim();
        if !statement.is_empty() {
            statements.push(statement);
        }
        start = terminator + 1;
    }
    statements
}

/// Splits the body of a normalized `CREATE TABLE` definition into top-level
/// column/constraint items.
#[cfg(test)]
fn table_definition_items(definition: &str) -> Option<Vec<String>> {
    let open = table_body_open(definition)?;
    let close = definition.rfind(')')?;
    if close <= open {
        return None;
    }
    Some(split_definition_body(&definition[open + 1..close]))
}

/// Rebuilds a normalized table definition after item edits.
#[cfg(test)]
fn rebuild_table_definition(definition: &str, items: &[String]) -> String {
    let Some(open) = table_body_open(definition) else {
        return definition.to_owned();
    };
    format!("{}{})", &definition[..=open], items.join(","))
}

/// Byte offset of the opening parenthesis of a table definition.
#[cfg(test)]
fn table_body_open(definition: &str) -> Option<usize> {
    let mut quote: Option<char> = None;
    for (offset, character) in definition.char_indices() {
        if let Some(terminator) = quote {
            if character == terminator {
                quote = None;
            }
            continue;
        }
        match character {
            '\'' | '"' | '`' => quote = Some(character),
            '[' => quote = Some(']'),
            '(' => return Some(offset),
            _ => {}
        }
    }
    None
}

#[cfg(test)]
fn split_definition_body(body: &str) -> Vec<String> {
    let mut items = Vec::new();
    let mut depth = 0_i32;
    let mut quote: Option<char> = None;
    let mut start = 0;
    let mut characters = body.char_indices().peekable();
    while let Some((offset, character)) = characters.next() {
        if let Some(terminator) = quote {
            if character == terminator {
                if terminator != ']'
                    && characters
                        .peek()
                        .is_some_and(|(_, next)| *next == terminator)
                {
                    characters.next();
                } else {
                    quote = None;
                }
            }
            continue;
        }
        match character {
            '\'' | '"' | '`' => quote = Some(character),
            '[' => quote = Some(']'),
            '(' => depth += 1,
            ')' => depth -= 1,
            ',' if depth == 0 => {
                items.push(body[start..offset].trim().to_owned());
                start = offset + 1;
            }
            _ => {}
        }
    }
    let tail = body[start..].trim();
    if !tail.is_empty() {
        items.push(tail.to_owned());
    }
    items
}

/// Column name of a table-definition item, or `None` for an implicit table
/// constraint.
#[cfg(test)]
fn column_name(item: &str) -> Option<String> {
    let tokens = tokenize(item);
    let first = tokens.first()?;
    if [
        "primary",
        "unique",
        "check",
        "foreign",
        "constraint",
        "exclude",
        "like",
    ]
    .iter()
    .any(|keyword| is_keyword(&tokens, 0, keyword))
    {
        return None;
    }
    Some(first.text.to_ascii_lowercase())
}

#[cfg(test)]
fn rename_column_item(item: &str, to: &str) -> String {
    let tokens = tokenize(item);
    let Some(first) = tokens.first() else {
        return item.to_owned();
    };
    format!("{to}{}", &item[first.end..])
}

/// Returns `(constraint name, canonical definition)` for every inline
/// `CONSTRAINT <name>` item of a normalized table definition.
///
/// The canonical definition uses the same `ALTER TABLE ... ADD CONSTRAINT ...`
/// form as an explicitly altered constraint, so an inline and an altered
/// constraint with identical bodies produce the same digest.
#[cfg(test)]
fn parse_inline_constraints(table: &str, definition: &str) -> Vec<(String, String)> {
    let Some(items) = table_definition_items(definition) else {
        return Vec::new();
    };
    let mut constraints = Vec::new();
    for item in items {
        let tokens = tokenize(&item);
        if !is_keyword(&tokens, 0, "constraint") {
            continue;
        }
        let Some(name) = tokens.get(1) else {
            continue;
        };
        constraints.push((
            name.text.to_ascii_lowercase(),
            format!("ALTER TABLE {table} ADD CONSTRAINT {}", &item[name.start..]),
        ));
    }
    constraints
}

/// Returns every table named by a DDL statement in `code`.
#[cfg(test)]
fn migration_table_references(code: &str) -> BTreeSet<String> {
    let tokens = tokenize(code);
    let mut references = BTreeSet::new();
    let mut index = 0;
    while index < tokens.len() {
        if is_keyword(&tokens, index, "create") {
            if is_keyword(&tokens, index + 1, "table") {
                if let Some(name) = tokens.get(skip_exists_clause(&tokens, index + 2)) {
                    references.insert(name.text.to_ascii_lowercase());
                }
            } else {
                let mut at = index + 1;
                if is_keyword(&tokens, at, "unique") {
                    at += 1;
                }
                if is_keyword(&tokens, at, "index") {
                    let name_index = skip_exists_clause(&tokens, at + 1);
                    if is_keyword(&tokens, name_index + 1, "on") {
                        let mut table_index = name_index + 2;
                        if is_keyword(&tokens, table_index, "only") {
                            table_index += 1;
                        }
                        if let Some(name) = tokens.get(table_index) {
                            references.insert(name.text.to_ascii_lowercase());
                        }
                    }
                } else {
                    let mut at = index + 1;
                    if is_keyword(&tokens, at, "or") && is_keyword(&tokens, at + 1, "replace") {
                        at += 2;
                    }
                    if is_keyword(&tokens, at, "trigger") {
                        let mut cursor = skip_exists_clause(&tokens, at + 1) + 1;
                        let limit = cursor.saturating_add(48).min(tokens.len());
                        while cursor < limit {
                            if is_keyword(&tokens, cursor, "on") {
                                if let Some(name) = tokens.get(cursor + 1) {
                                    references.insert(name.text.to_ascii_lowercase());
                                }
                                break;
                            }
                            if is_keyword(&tokens, cursor, "begin")
                                || is_keyword(&tokens, cursor, "execute")
                            {
                                break;
                            }
                            cursor += 1;
                        }
                    }
                }
            }
        } else if (is_keyword(&tokens, index, "alter") && is_keyword(&tokens, index + 1, "table"))
            || (is_keyword(&tokens, index, "drop") && is_keyword(&tokens, index + 1, "table"))
        {
            let mut at = skip_exists_clause(&tokens, index + 2);
            if is_keyword(&tokens, at, "only") {
                at += 1;
            }
            if let Some(name) = tokens.get(at) {
                references.insert(name.text.to_ascii_lowercase());
            }
        }
        index += 1;
    }
    references
}

/// Collapses whitespace runs outside quoted identifiers and string literals,
/// removes the spaces that only depend on layout (after `(`, after `,`, before
/// `)` and before `,`), and removes an `IF NOT EXISTS` qualifier.
fn normalized_definition(statement: &str) -> String {
    let collapsed = collapse_whitespace(statement);
    strip_if_not_exists(&tidy_punctuation(&collapsed))
}

/// Removes whitespace introduced only by statement layout around parentheses
/// and commas, outside quoted identifiers and string literals.
fn tidy_punctuation(input: &str) -> String {
    let mut tidied = String::with_capacity(input.len());
    let mut characters = input.chars().peekable();
    let mut quote: Option<char> = None;
    while let Some(character) = characters.next() {
        if let Some(terminator) = quote {
            tidied.push(character);
            if character == terminator {
                if characters.peek() == Some(&terminator) {
                    if let Some(escaped) = characters.next() {
                        tidied.push(escaped);
                    }
                } else {
                    quote = None;
                }
            }
            continue;
        }
        match character {
            '\'' | '"' | '`' => {
                quote = Some(character);
                tidied.push(character);
            }
            '[' => {
                quote = Some(']');
                tidied.push(character);
            }
            '(' => {
                tidied.push('(');
                while characters.peek() == Some(&' ') {
                    characters.next();
                }
            }
            ',' => {
                while tidied.ends_with(' ') {
                    tidied.pop();
                }
                tidied.push(',');
                while characters.peek() == Some(&' ') {
                    characters.next();
                }
            }
            ')' => {
                while tidied.ends_with(' ') {
                    tidied.pop();
                }
                tidied.push(')');
            }
            _ => tidied.push(character),
        }
    }
    tidied
}

fn collapse_whitespace(input: &str) -> String {
    let mut collapsed = String::with_capacity(input.len());
    let mut characters = input.chars().peekable();
    let mut quote: Option<char> = None;
    let mut pending_space = false;
    while let Some(character) = characters.next() {
        if let Some(terminator) = quote {
            collapsed.push(character);
            if character == terminator {
                if characters.peek() == Some(&terminator) {
                    if let Some(escaped) = characters.next() {
                        collapsed.push(escaped);
                    }
                } else {
                    quote = None;
                }
            }
            continue;
        }
        match character {
            '\'' | '"' | '`' => {
                if pending_space && !collapsed.is_empty() {
                    collapsed.push(' ');
                }
                pending_space = false;
                quote = Some(character);
                collapsed.push(character);
            }
            '[' => {
                if pending_space && !collapsed.is_empty() {
                    collapsed.push(' ');
                }
                pending_space = false;
                quote = Some(']');
                collapsed.push(character);
            }
            character if character.is_whitespace() => {
                pending_space = !collapsed.is_empty();
            }
            character => {
                if pending_space {
                    collapsed.push(' ');
                }
                pending_space = false;
                collapsed.push(character);
            }
        }
    }
    collapsed
}

/// Removes every `IF NOT EXISTS` qualifier regardless of the object keyword
/// (`CREATE TABLE`, `CREATE UNIQUE INDEX`, `CREATE TRIGGER`, ...).
fn strip_if_not_exists(statement: &str) -> String {
    let lowercase = statement.to_ascii_lowercase();
    let needle = " if not exists ";
    let mut stripped = String::with_capacity(statement.len());
    let mut offset = 0;
    while let Some(position) = lowercase[offset..].find(needle) {
        let start = offset + position;
        stripped.push_str(&statement[offset..start]);
        stripped.push(' ');
        offset = start + needle.len();
    }
    stripped.push_str(&statement[offset..]);
    stripped
}

pub(crate) fn sha256_hex(value: &str) -> String {
    sha256_hex_bytes(value.as_bytes())
}

fn sha256_hex_bytes(value: &[u8]) -> String {
    use std::fmt::Write as _;

    let digest = Sha256::digest(value);
    let mut encoded = String::with_capacity(64);
    for byte in digest {
        let _ = write!(encoded, "{byte:02x}");
    }
    encoded
}

/// SQLite library version used by the generator, from the same linked library
/// that renders the live `sqlite_master` catalog. A libsqlite change therefore
/// appears as baseline drift and requires a reviewed regeneration.
#[cfg(test)]
fn generator_sqlite_version() -> Result<String, StateInventoryError> {
    let runtime = tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()
        .map_err(|error| {
            StateInventoryError::InvalidBaseline(format!(
                "cannot build the SQLite version runtime: {error}"
            ))
        })?;
    runtime.block_on(async {
        let pool = sqlx::sqlite::SqlitePoolOptions::new()
            .max_connections(1)
            .connect("sqlite::memory:")
            .await
            .map_err(|error| {
                StateInventoryError::InvalidBaseline(format!(
                    "cannot open an in-memory SQLite version probe: {error}"
                ))
            })?;
        sqlx::query_scalar::<_, String>("SELECT sqlite_version()")
            .fetch_one(&pool)
            .await
            .map_err(|error| {
                StateInventoryError::InvalidBaseline(format!(
                    "cannot read the SQLite generator version: {error}"
                ))
            })
    })
}

#[cfg(test)]
fn render_inventory(
    sqlite: &MigrationTree,
    postgres: &MigrationTree,
    families: &[RepositoryFamily],
    migration_files: BTreeMap<String, String>,
) -> Result<String, StateInventoryError> {
    render_inventory_with_owners(
        sqlite,
        postgres,
        families,
        migration_files,
        &REVIEWED_GENERIC_OWNERS,
    )
}

#[cfg(test)]
fn render_inventory_with_owners(
    sqlite: &MigrationTree,
    postgres: &MigrationTree,
    families: &[RepositoryFamily],
    migration_files: BTreeMap<String, String>,
    owners: &GenericOwners<'_>,
) -> Result<String, StateInventoryError> {
    let mut repository_ids = BTreeSet::new();
    let mut table_repositories: BTreeMap<String, String> = BTreeMap::new();
    let mut registered = BTreeSet::new();

    for family in families {
        if !is_contract_identifier(family.repository_id) {
            return Err(StateInventoryError::InvalidBaseline(format!(
                "repository id {:?} is not a contract identifier",
                family.repository_id
            )));
        }
        if !repository_ids.insert(family.repository_id.to_owned()) {
            return Err(StateInventoryError::DuplicateRepository(
                family.repository_id.to_owned(),
            ));
        }
        if !STATE_FAMILIES.contains(&family.state_family) {
            return Err(StateInventoryError::UnknownStateFamily {
                repository: family.repository_id.to_owned(),
                family: family.state_family.to_owned(),
            });
        }
        if !family.tables.windows(2).all(|pair| pair[0] < pair[1])
            || family.tables.iter().any(|table| table.is_empty())
        {
            return Err(StateInventoryError::UnsortedRepository {
                repository: family.repository_id.to_owned(),
                tables: family
                    .tables
                    .iter()
                    .map(|table| (*table).to_owned())
                    .collect(),
            });
        }
        for table in family.tables.iter() {
            if let Some(first) =
                table_repositories.insert((*table).to_owned(), family.repository_id.to_owned())
            {
                return Err(StateInventoryError::DuplicateTable {
                    table: (*table).to_owned(),
                    first,
                    second: family.repository_id.to_owned(),
                });
            }
            registered.insert((*table).to_owned());
        }
    }

    for tree in [sqlite, postgres] {
        let defined: BTreeSet<String> = tree.definitions.keys().cloned().collect();
        let unregistered: Vec<String> = defined.difference(&registered).cloned().collect();
        if !unregistered.is_empty() {
            return Err(StateInventoryError::UnregisteredTables {
                tables: unregistered,
            });
        }
        let missing: Vec<String> = registered.difference(&defined).cloned().collect();
        if !missing.is_empty() {
            return Err(StateInventoryError::MissingCreateTable {
                tree: tree.tree,
                tables: missing,
            });
        }
    }

    for tree in [sqlite, postgres] {
        for object in tree.indexes.values() {
            require_registered_owner(tree, "index", object, &table_repositories)?;
        }
        for object in tree.constraints.values() {
            require_registered_owner(tree, "constraint", object, &table_repositories)?;
        }
        for object in tree.triggers.values() {
            require_registered_owner(tree, "trigger", object, &table_repositories)?;
        }
        for object in tree.views.values() {
            let Some(repository) = generic_owner(owners.views, &object.name) else {
                return Err(StateInventoryError::UnassignedView {
                    tree: tree.tree,
                    name: object.name.clone(),
                });
            };
            require_known_repository(tree, "view", &object.name, repository, &repository_ids)?;
        }
        for object in tree.sequences.values() {
            let Some(repository) = generic_owner(owners.sequences, &object.name) else {
                return Err(StateInventoryError::UnassignedSequence {
                    tree: tree.tree,
                    name: object.name.clone(),
                });
            };
            require_known_repository(tree, "sequence", &object.name, repository, &repository_ids)?;
        }
        for (name, _) in tree.functions.keys() {
            let Some(repository) = generic_owner(owners.functions, name) else {
                return Err(StateInventoryError::UnassignedFunction {
                    tree: tree.tree,
                    name: name.clone(),
                });
            };
            require_known_repository(tree, "function", name, repository, &repository_ids)?;
        }
    }
    for (kind, owners) in [
        ("function", owners.functions),
        ("view", owners.views),
        ("sequence", owners.sequences),
    ] {
        let mut names = BTreeSet::new();
        for (name, _) in owners {
            if !names.insert(*name) {
                return Err(StateInventoryError::InvalidBaseline(format!(
                    "{kind} {name:?} is listed twice in its generic owner table"
                )));
            }
        }
    }

    let mut entries = Vec::with_capacity(families.len() + 1);
    for family in families {
        let sqlite_objects = family_objects(sqlite, "main", family, owners)?;
        let postgres_objects = family_objects(postgres, "public", family, owners)?;
        ensure_unique_objects(family, "sqlite_objects", &sqlite_objects)?;
        ensure_unique_objects(family, "postgres_objects", &postgres_objects)?;
        let mut migration_ids = BTreeSet::new();
        for table in family.tables.iter() {
            for tree in [sqlite, postgres] {
                if let Some(stems) = tree.references.get(*table) {
                    migration_ids.extend(stems.iter().cloned());
                }
            }
        }
        // Object-defining migrations are recorded even when the repository owns
        // no table, so an object-only repository still has a migration lineage.
        for object in sqlite_objects.iter().chain(postgres_objects.iter()) {
            for tree in [sqlite, postgres] {
                if let Some(stems) = tree
                    .object_stems
                    .get(&(object.kind.clone(), object.name.clone()))
                {
                    migration_ids.extend(stems.iter().cloned());
                }
            }
        }
        if migration_ids.is_empty() {
            return Err(StateInventoryError::RepositoryWithoutMigrations {
                repository: family.repository_id.to_owned(),
            });
        }
        entries.push(RepositoryInventoryEntry {
            repository_id: family.repository_id.to_owned(),
            state_family: family.state_family.to_owned(),
            empty_state_included: false,
            sqlite_objects,
            postgres_objects,
            migration_ids: migration_ids.into_iter().collect(),
        });
    }
    verify_single_assignment(sqlite, &entries, false)?;
    verify_single_assignment(postgres, &entries, true)?;
    entries.push(release_metadata_entry(sqlite, postgres));
    entries.sort_by(|left, right| left.repository_id.cmp(&right.repository_id));

    let present: BTreeSet<&str> = entries
        .iter()
        .map(|entry| entry.state_family.as_str())
        .collect();
    let missing: Vec<String> = STATE_FAMILIES
        .iter()
        .filter(|family| !present.contains(**family))
        .map(|family| (*family).to_owned())
        .collect();
    if !missing.is_empty() {
        return Err(StateInventoryError::MissingStateFamily { families: missing });
    }

    let document = InventoryDocument {
        format: STATE_INVENTORY_FORMAT.to_owned(),
        sqlite_version: generator_sqlite_version()?,
        postgres_major: POSTGRES_MAJOR,
        migration_files,
        repositories: entries,
    };
    let mut json = serde_json::to_string_pretty(&document)?;
    json.push('\n');
    Ok(json)
}

#[cfg(test)]
fn catalog_table(
    tree: &MigrationTree,
    schema: &str,
    table: &str,
) -> Result<CatalogObject, StateInventoryError> {
    let definition =
        tree.definitions
            .get(table)
            .ok_or_else(|| StateInventoryError::MissingCreateTable {
                tree: tree.tree,
                tables: vec![table.to_owned()],
            })?;
    Ok(CatalogObject {
        kind: "table".to_owned(),
        schema: schema.to_owned(),
        name: table.to_owned(),
        definition_sha256: sha256_hex(definition),
    })
}

#[cfg(test)]
fn catalog_non_table(schema: &str, object: &ObjectDefinition) -> CatalogObject {
    CatalogObject {
        kind: object.kind.to_owned(),
        schema: schema.to_owned(),
        name: object.name.clone(),
        definition_sha256: sha256_hex(&object.definition),
    }
}

#[cfg(test)]
fn require_registered_owner(
    tree: &MigrationTree,
    kind: &'static str,
    object: &ObjectDefinition,
    table_repositories: &BTreeMap<String, String>,
) -> Result<(), StateInventoryError> {
    let table = object.table.as_deref().unwrap_or_default();
    if table_repositories.contains_key(table) {
        return Ok(());
    }
    Err(StateInventoryError::UnregisteredCatalogObject {
        tree: tree.tree,
        kind,
        name: object.name.clone(),
        table: table.to_owned(),
    })
}

#[cfg(test)]
fn generic_owner<'a>(owners: &'a [(&'a str, &'a str)], name: &str) -> Option<&'a str> {
    owners
        .iter()
        .find(|(object, _)| *object == name)
        .map(|(_, repository)| *repository)
}

#[cfg(test)]
fn require_known_repository(
    tree: &MigrationTree,
    kind: &str,
    name: &str,
    repository: &str,
    repository_ids: &BTreeSet<String>,
) -> Result<(), StateInventoryError> {
    if repository_ids.contains(repository) {
        return Ok(());
    }
    Err(StateInventoryError::InvalidBaseline(format!(
        "{kind} {name:?} in the {} migration tree is assigned to unknown repository {repository:?}",
        tree.tree
    )))
}

#[cfg(test)]
fn ensure_unique_objects(
    family: &RepositoryFamily,
    field: &'static str,
    objects: &[CatalogObject],
) -> Result<(), StateInventoryError> {
    let mut keys = BTreeSet::new();
    for object in objects {
        if !keys.insert((object.kind.as_str(), object.name.as_str())) {
            return Err(StateInventoryError::DuplicateCatalogObject {
                repository: family.repository_id.to_owned(),
                field,
                kind: object.kind.clone(),
                name: object.name.clone(),
            });
        }
    }
    Ok(())
}

/// Verifies that every parsed catalog object of `tree` appears in exactly one
/// repository entry.
#[cfg(test)]
fn verify_single_assignment(
    tree: &MigrationTree,
    entries: &[RepositoryInventoryEntry],
    postgres: bool,
) -> Result<(), StateInventoryError> {
    let mut assigned: BTreeMap<(String, String), usize> = BTreeMap::new();
    for entry in entries {
        let objects = if postgres {
            &entry.postgres_objects
        } else {
            &entry.sqlite_objects
        };
        for object in objects {
            *assigned
                .entry((object.kind.clone(), object.name.clone()))
                .or_default() += 1;
        }
    }

    let mut parsed = BTreeSet::new();
    for table in tree.definitions.keys() {
        parsed.insert(("table".to_owned(), table.clone()));
    }
    for object in tree.views.values() {
        parsed.insert((object.kind.to_owned(), object.name.clone()));
    }
    for object in tree.sequences.values() {
        parsed.insert((object.kind.to_owned(), object.name.clone()));
    }
    for object in tree.indexes.values() {
        parsed.insert((object.kind.to_owned(), object.name.clone()));
    }
    for object in tree.constraints.values() {
        parsed.insert((object.kind.to_owned(), object.name.clone()));
    }
    for object in tree.triggers.values() {
        parsed.insert((object.kind.to_owned(), object.name.clone()));
    }
    for object in tree.functions.values() {
        parsed.insert((object.kind.to_owned(), object.name.clone()));
    }
    for key in &parsed {
        match assigned.get(key) {
            Some(1) => {}
            Some(count) => {
                return Err(StateInventoryError::InvalidBaseline(format!(
                    "{} {} object {key:?} is assigned to {count} repository entries",
                    tree.tree,
                    if postgres { "PostgreSQL" } else { "SQLite" }
                )));
            }
            None => {
                return Err(StateInventoryError::InvalidBaseline(format!(
                    "{} catalog object {key:?} is assigned to no repository entry",
                    tree.tree
                )));
            }
        }
    }
    for (key, count) in &assigned {
        if !parsed.contains(key) {
            return Err(StateInventoryError::InvalidBaseline(format!(
                "{} catalog object {key:?} has no parsed definition ({count} assignment(s))",
                tree.tree
            )));
        }
    }
    Ok(())
}

/// Every catalog object owned by one repository entry: its tables in registry
/// order, then views, sequences, indexes, constraints, triggers and
/// (PostgreSQL only) functions in name order.
#[cfg(test)]
fn family_objects(
    tree: &MigrationTree,
    schema: &str,
    family: &RepositoryFamily,
    owners: &GenericOwners<'_>,
) -> Result<Vec<CatalogObject>, StateInventoryError> {
    let mut objects = Vec::new();
    for table in family.tables.iter() {
        objects.push(catalog_table(tree, schema, table)?);
    }
    for object in tree.views.values() {
        if generic_owner(owners.views, &object.name) == Some(family.repository_id) {
            objects.push(catalog_non_table(schema, object));
        }
    }
    for object in tree.sequences.values() {
        if generic_owner(owners.sequences, &object.name) == Some(family.repository_id) {
            objects.push(catalog_non_table(schema, object));
        }
    }
    for object in tree.indexes.values() {
        if object
            .table
            .as_deref()
            .is_some_and(|table| family.tables.contains(&table))
        {
            objects.push(catalog_non_table(schema, object));
        }
    }
    for object in tree.constraints.values() {
        if object
            .table
            .as_deref()
            .is_some_and(|table| family.tables.contains(&table))
        {
            objects.push(catalog_non_table(schema, object));
        }
    }
    for object in tree.triggers.values() {
        if object
            .table
            .as_deref()
            .is_some_and(|table| family.tables.contains(&table))
        {
            objects.push(catalog_non_table(schema, object));
        }
    }
    for ((name, _), object) in &tree.functions {
        if generic_owner(owners.functions, name) == Some(family.repository_id) {
            objects.push(catalog_non_table(schema, object));
        }
    }
    Ok(objects)
}

/// The framework-owned release/install bookkeeping entry.
///
/// Both backends record applied migrations in `_sqlx_migrations`, so the entry
/// carries the full migration lineage of both trees. SQLite's
/// `sqlite_sequence` is claimed only when a reviewed migration declares
/// `AUTOINCREMENT`.
#[cfg(test)]
fn release_metadata_entry(
    sqlite: &MigrationTree,
    postgres: &MigrationTree,
) -> RepositoryInventoryEntry {
    let mut sqlite_objects = vec![CatalogObject {
        kind: "table".to_owned(),
        schema: "main".to_owned(),
        name: "_sqlx_migrations".to_owned(),
        definition_sha256: sha256_hex(&normalized_definition(SQLITE_SQLX_MIGRATIONS_DDL)),
    }];
    if sqlite.autoincrement {
        sqlite_objects.push(CatalogObject {
            kind: "table".to_owned(),
            schema: "main".to_owned(),
            name: "sqlite_sequence".to_owned(),
            definition_sha256: sha256_hex(&normalized_definition(SQLITE_SEQUENCE_DDL)),
        });
    }
    let postgres_objects = vec![CatalogObject {
        kind: "table".to_owned(),
        schema: "public".to_owned(),
        name: "_sqlx_migrations".to_owned(),
        definition_sha256: sha256_hex(&normalized_definition(POSTGRES_SQLX_MIGRATIONS_DDL)),
    }];
    let mut migration_ids = BTreeSet::new();
    migration_ids.extend(sqlite.stems.iter().cloned());
    migration_ids.extend(postgres.stems.iter().cloned());

    RepositoryInventoryEntry {
        repository_id: RELEASE_METADATA_REPOSITORY_ID.to_owned(),
        state_family: "release_and_install_metadata".to_owned(),
        empty_state_included: false,
        sqlite_objects,
        postgres_objects,
        migration_ids: migration_ids.into_iter().collect(),
    }
}

#[cfg(test)]
fn ensure_matches_committed(generated: &str) -> Result<(), StateInventoryError> {
    if generated == STATE_INVENTORY_V1 {
        return Ok(());
    }
    Err(StateInventoryError::BaselineDrift {
        detail: describe_drift(generated, STATE_INVENTORY_V1),
    })
}

#[cfg(test)]
fn describe_drift(generated: &str, committed: &str) -> String {
    let Ok(generated_document) = serde_json::from_str::<InventoryDocument>(generated) else {
        return "generated inventory is not valid JSON".to_owned();
    };
    let Ok(committed_document) = serde_json::from_str::<InventoryDocument>(committed) else {
        return "committed inventory is not valid JSON".to_owned();
    };
    let generated_entries = entry_map(&generated_document);
    let committed_entries = entry_map(&committed_document);

    let mut repositories = BTreeSet::new();
    repositories.extend(generated_entries.keys().cloned());
    repositories.extend(committed_entries.keys().cloned());

    let mut changes = Vec::new();
    if generated_document.sqlite_version != committed_document.sqlite_version {
        changes.push(format!(
            "SQLite generator version changed from {} to {}",
            committed_document.sqlite_version, generated_document.sqlite_version
        ));
    }
    if generated_document.postgres_major != committed_document.postgres_major {
        changes.push(format!(
            "PostgreSQL major changed from {} to {}",
            committed_document.postgres_major, generated_document.postgres_major
        ));
    }
    if generated_document.migration_files != committed_document.migration_files {
        let mut changed: Vec<&str> = generated_document
            .migration_files
            .keys()
            .chain(committed_document.migration_files.keys())
            .filter(|path| {
                generated_document.migration_files.get(*path)
                    != committed_document.migration_files.get(*path)
            })
            .map(String::as_str)
            .collect();
        changed.sort_unstable();
        changed.dedup();
        changes.push(format!(
            "migration file binding changed for: {}",
            changed.join(", ")
        ));
    }
    for repository in repositories {
        match (
            generated_entries.get(&repository),
            committed_entries.get(&repository),
        ) {
            (Some(generated_entry), Some(committed_entry)) => {
                let generated_objects = entry_object_keys(generated_entry);
                let committed_objects = entry_object_keys(committed_entry);
                let added: Vec<_> = generated_objects
                    .difference(&committed_objects)
                    .map(|(kind, name)| format!("{kind}:{name}"))
                    .collect();
                let removed: Vec<_> = committed_objects
                    .difference(&generated_objects)
                    .map(|(kind, name)| format!("{kind}:{name}"))
                    .collect();
                if !added.is_empty() {
                    changes.push(format!(
                        "catalog object(s) added to repository {repository:?}: {}",
                        added.join(", ")
                    ));
                }
                if !removed.is_empty() {
                    changes.push(format!(
                        "catalog object(s) removed from repository {repository:?}: {}",
                        removed.join(", ")
                    ));
                }
            }
            (Some(generated_entry), None) => changes.push(format!(
                "repository {repository:?} is new with tables: {}",
                entry_tables(generated_entry)
                    .into_iter()
                    .collect::<Vec<_>>()
                    .join(", ")
            )),
            (None, Some(committed_entry)) => changes.push(format!(
                "repository {repository:?} is missing with tables: {}",
                entry_tables(committed_entry)
                    .into_iter()
                    .collect::<Vec<_>>()
                    .join(", ")
            )),
            (None, None) => {}
        }
    }
    if changes.is_empty() {
        changes.push(
            "serialized content differs (object digests, state family or migration ids changed)"
                .to_owned(),
        );
    }
    changes.join("; ")
}

#[cfg(test)]
fn entry_map(document: &InventoryDocument) -> BTreeMap<String, &RepositoryInventoryEntry> {
    document
        .repositories
        .iter()
        .map(|entry| (entry.repository_id.clone(), entry))
        .collect()
}

#[cfg(test)]
fn entry_tables(entry: &RepositoryInventoryEntry) -> BTreeSet<String> {
    entry
        .sqlite_objects
        .iter()
        .filter(|object| object.kind == "table")
        .map(|object| object.name.clone())
        .collect()
}

#[cfg(test)]
fn entry_object_keys(entry: &RepositoryInventoryEntry) -> BTreeSet<(String, String)> {
    entry
        .sqlite_objects
        .iter()
        .chain(entry.postgres_objects.iter())
        .map(|object| (object.kind.clone(), object.name.clone()))
        .collect()
}

#[cfg(test)]
mod tests {
    #![allow(clippy::expect_used)]
    use super::*;
    use serde_json::Value;

    const DRIFT_PROBE_TABLES: &[&str] = &["drift_gate_probe"];

    fn drift_probe_family() -> RepositoryFamily {
        RepositoryFamily {
            repository_id: "drift_probe",
            state_family: "o3k_owned_configuration",
            tables: DRIFT_PROBE_TABLES,
        }
    }

    struct ScratchDirectory(PathBuf);

    impl ScratchDirectory {
        fn new(prefix: &str) -> Result<Self, std::io::Error> {
            let path = std::env::temp_dir().join(format!("{prefix}-{}", uuid::Uuid::now_v7()));
            fs::create_dir_all(&path)?;
            Ok(Self(path))
        }

        fn path(&self) -> &Path {
            &self.0
        }
    }

    impl Drop for ScratchDirectory {
        fn drop(&mut self) {
            let _ = fs::remove_dir_all(&self.0);
        }
    }

    fn manifest_dir() -> PathBuf {
        PathBuf::from(env!("CARGO_MANIFEST_DIR"))
    }

    fn copy_migrations(source: &Path, destination: &Path) -> Result<(), std::io::Error> {
        for entry in fs::read_dir(source)? {
            let entry = entry?;
            let path = entry.path();
            if path.extension().and_then(|extension| extension.to_str()) == Some("sql") {
                fs::copy(&path, destination.join(entry.file_name()))?;
            }
        }
        Ok(())
    }

    /// Copies both reviewed migration trees into scratch directories and adds
    /// `probe_sql` to both.
    fn scratch_trees(
        probe_sql: Option<&str>,
    ) -> Result<(ScratchDirectory, ScratchDirectory), Box<dyn std::error::Error>> {
        scratch_trees_with_probes(probe_sql, probe_sql)
    }

    /// Copies both reviewed migration trees into scratch directories with
    /// independent SQLite and PostgreSQL probe migrations.
    fn scratch_trees_with_probes(
        sqlite_sql: Option<&str>,
        postgres_sql: Option<&str>,
    ) -> Result<(ScratchDirectory, ScratchDirectory), Box<dyn std::error::Error>> {
        let sqlite = ScratchDirectory::new("o3k-state-inventory-sqlite")?;
        let postgres = ScratchDirectory::new("o3k-state-inventory-postgres")?;
        copy_migrations(&manifest_dir().join("migrations"), sqlite.path())?;
        copy_migrations(&manifest_dir().join("migrations_postgres"), postgres.path())?;
        if let Some(sql) = sqlite_sql {
            fs::write(sqlite.path().join("9999_drift_probe.sql"), sql)?;
        }
        if let Some(sql) = postgres_sql {
            fs::write(postgres.path().join("9999_drift_probe.sql"), sql)?;
        }
        Ok((sqlite, postgres))
    }

    /// Parses one standalone migration file as a full migration tree.
    fn parsed_probe_tree(
        prefix: &str,
        tree: &'static str,
        sql: &str,
    ) -> Result<MigrationTree, Box<dyn std::error::Error>> {
        let scratch = ScratchDirectory::new(prefix)?;
        fs::write(scratch.path().join("0001_probe.sql"), sql)?;
        Ok(scan_migration_tree(scratch.path(), tree)?)
    }

    fn generated_document(
        generated: &str,
    ) -> Result<InventoryDocument, Box<dyn std::error::Error>> {
        Ok(serde_json::from_str(generated)?)
    }

    fn generated_entry<'a>(
        document: &'a InventoryDocument,
        repository_id: &str,
    ) -> &'a RepositoryInventoryEntry {
        document
            .repositories
            .iter()
            .find(|entry| entry.repository_id == repository_id)
            .expect("generated repository entry")
    }

    fn object_names(entry: &RepositoryInventoryEntry, kind: &str) -> Vec<String> {
        entry
            .sqlite_objects
            .iter()
            .chain(entry.postgres_objects.iter())
            .filter(|object| object.kind == kind)
            .map(|object| object.name.clone())
            .collect()
    }

    #[test]
    fn committed_baseline_matches_both_migration_trees() -> Result<(), Box<dyn std::error::Error>> {
        let root = manifest_dir();
        let generated = generate_inventory_from_trees(
            &root.join("migrations"),
            &root.join("migrations_postgres"),
        )?;

        let regenerate = regeneration_requested(
            std::env::var("O3K_REGENERATE_INVENTORY").ok().as_deref(),
            std::env::var("CI").ok().as_deref(),
        )?;
        if regenerate {
            fs::write(root.join("state_inventory_v1.json"), &generated)?;
            println!(
                "regenerate and review crates/o3k-store/state_inventory_v1.json before committing"
            );
            return Ok(());
        }

        ensure_matches_committed(&generated)?;
        Ok(())
    }

    /// Regeneration is a local, reviewed maintenance action; CI must never
    /// rewrite the committed baseline (F34).
    fn regeneration_requested(
        regenerate: Option<&str>,
        ci: Option<&str>,
    ) -> Result<bool, std::io::Error> {
        let requested = regenerate == Some("1");
        if requested && ci.is_some_and(|value| !value.trim().is_empty()) {
            return Err(std::io::Error::other(
                "O3K_REGENERATE_INVENTORY=1 is refused while CI is set; \
                 regenerate locally, review the diff and commit the baseline",
            ));
        }
        Ok(requested)
    }

    #[test]
    fn regeneration_is_refused_in_ci() {
        assert!(!matches!(regeneration_requested(None, None), Ok(true)));
        assert!(matches!(regeneration_requested(Some("1"), None), Ok(true)));
        assert!(!matches!(
            regeneration_requested(Some("0"), Some("true")),
            Ok(true)
        ));
        for ci in ["true", "1", "gitlab"] {
            assert!(
                regeneration_requested(Some("1"), Some(ci)).is_err(),
                "CI={ci} must refuse regeneration"
            );
        }
        assert!(matches!(
            regeneration_requested(Some("1"), Some("  ")),
            Ok(true)
        ));
    }

    /// Mirrors `validate_inventory`, `valid_objects`, `valid_ids` and
    /// `is_sha256` in `bins/o3k/src/backup.rs:1458-1575`. Those functions are
    /// private to the `o3k` binary crate, so the contract rules are replicated
    /// here rather than imported.
    fn assert_contract_inventory(inventory: &[Value]) {
        const CONTRACT_FAMILIES: [&str; 9] = [
            "canonical_resources",
            "operations_and_reconciliation",
            "placement_allocations_and_provider_mappings",
            "topology_and_building_blocks",
            "iam_and_security_scope",
            "bootstrap_enrollment_and_revocation",
            "audit_and_governance",
            "o3k_owned_configuration",
            "release_and_install_metadata",
        ];
        const CONTRACT_KINDS: [&str; 7] = [
            "table",
            "view",
            "sequence",
            "index",
            "constraint",
            "function",
            "trigger",
        ];
        fn valid_identifier(value: &str) -> bool {
            let mut bytes = value.bytes();
            bytes
                .next()
                .is_some_and(|first| first.is_ascii_alphanumeric())
                && value.len() <= 160
                && bytes.all(|byte| {
                    byte.is_ascii_alphanumeric() || matches!(byte, b'.' | b'_' | b':' | b'-')
                })
        }
        fn valid_digest(value: &str) -> bool {
            value.len() == 64
                && value
                    .bytes()
                    .all(|byte| byte.is_ascii_hexdigit() && !byte.is_ascii_uppercase())
        }
        fn valid_objects(entry: &Value, field: &str) -> bool {
            let Some(objects) = entry.get(field).and_then(Value::as_array) else {
                return false;
            };
            if objects.is_empty() {
                return false;
            }
            let mut keys = BTreeSet::new();
            objects.iter().all(|object| {
                let kind = object
                    .get("kind")
                    .and_then(Value::as_str)
                    .unwrap_or_default();
                let schema = object
                    .get("schema")
                    .and_then(Value::as_str)
                    .unwrap_or_default();
                let name = object
                    .get("name")
                    .and_then(Value::as_str)
                    .unwrap_or_default();
                let digest = object
                    .get("definition_sha256")
                    .and_then(Value::as_str)
                    .unwrap_or_default();
                CONTRACT_KINDS.contains(&kind)
                    && !schema.is_empty()
                    && !name.is_empty()
                    && valid_digest(digest)
                    && keys.insert((kind, schema, name))
                    && object.as_object().is_some_and(|fields| fields.len() == 4)
            })
        }
        fn valid_ids(entry: &Value, field: &str) -> bool {
            let Some(values) = entry.get(field).and_then(Value::as_array) else {
                return false;
            };
            if values.is_empty() {
                return false;
            }
            let mut ids = BTreeSet::new();
            values.iter().all(|value| {
                value.as_str().is_some_and(|id| {
                    !id.is_empty() && valid_identifier(id) && ids.insert(id.to_owned())
                })
            })
        }

        assert!(
            !inventory.is_empty() && inventory.len() <= MAX_INVENTORY_ENTRIES,
            "inventory size {} is outside 1..={MAX_INVENTORY_ENTRIES}",
            inventory.len()
        );
        let mut ids = BTreeSet::new();
        let mut families = BTreeSet::new();
        for entry in inventory {
            let id = entry
                .get("repository_id")
                .and_then(Value::as_str)
                .unwrap_or_default();
            let family = entry
                .get("state_family")
                .and_then(Value::as_str)
                .unwrap_or_default();
            assert!(
                !id.is_empty() && ids.insert(id) && CONTRACT_FAMILIES.contains(&family),
                "invalid or duplicate inventory entry {id:?}/{family:?}"
            );
            assert!(valid_identifier(id), "repository id {id:?} is malformed");
            families.insert(family);
            assert!(
                entry
                    .get("empty_state_included")
                    .and_then(Value::as_bool)
                    .is_some(),
                "repository {id:?} has no empty_state_included boolean"
            );
            assert!(
                valid_objects(entry, "sqlite_objects"),
                "repository {id:?} has invalid sqlite objects"
            );
            assert!(
                valid_objects(entry, "postgres_objects"),
                "repository {id:?} has invalid postgres objects"
            );
            assert!(
                valid_ids(entry, "migration_ids"),
                "repository {id:?} has invalid migration ids"
            );
            assert!(
                entry.as_object().is_some_and(|fields| {
                    fields.len() == 6
                        && fields.contains_key("repository_id")
                        && fields.contains_key("state_family")
                        && fields.contains_key("empty_state_included")
                        && fields.contains_key("sqlite_objects")
                        && fields.contains_key("postgres_objects")
                        && fields.contains_key("migration_ids")
                }),
                "repository {id:?} has extra or missing entry fields"
            );
        }
        for family in CONTRACT_FAMILIES {
            assert!(
                families.contains(family),
                "inventory omits canonical state family {family:?}"
            );
        }
    }

    #[test]
    fn catalog_comparison_ignores_expected_sqlite_internal_objects()
    -> Result<(), Box<dyn std::error::Error>> {
        // A future AUTOINCREMENT migration may claim `sqlite_sequence` in the
        // baseline. The live catalog excludes every `sqlite_*` name, so the
        // expected map must exclude them too instead of reporting a missing
        // object on every capture.
        let inventory = vec![serde_json::json!({
            "repository_id": "release",
            "state_family": "release_and_install_metadata",
            "empty_state_included": false,
            "sqlite_objects": [
                {
                    "kind": "table",
                    "schema": "main",
                    "name": "_sqlx_migrations",
                    "definition_sha256": "a".repeat(64)
                },
                {
                    "kind": "table",
                    "schema": "main",
                    "name": "sqlite_sequence",
                    "definition_sha256": "b".repeat(64)
                }
            ],
            "postgres_objects": [{
                "kind": "table",
                "schema": "public",
                "name": "_sqlx_migrations",
                "definition_sha256": "c".repeat(64)
            }],
            "migration_ids": ["0001_initial"]
        })];
        let live = vec![LiveCatalogObject {
            kind: "table".to_owned(),
            name: "_sqlx_migrations".to_owned(),
            definition_sha256: "a".repeat(64),
        }];
        assert_eq!(
            verify_sqlite_catalog_against_baseline(&inventory, &live),
            Ok(())
        );
        Ok(())
    }

    #[test]
    fn baseline_state_inventory_satisfies_the_artifact_contract()
    -> Result<(), Box<dyn std::error::Error>> {
        let inventory = baseline_state_inventory()?;
        assert_contract_inventory(&inventory);

        let mut previous: Option<String> = None;
        for entry in &inventory {
            let repository_id = entry["repository_id"]
                .as_str()
                .ok_or("repository_id is not a string")?;
            assert!(
                previous
                    .as_deref()
                    .is_none_or(|previous| previous < repository_id)
            );
            previous = Some(repository_id.to_owned());
            assert!(
                !entry["empty_state_included"]
                    .as_bool()
                    .ok_or("empty_state_included is not a boolean")?
            );
        }
        Ok(())
    }

    #[test]
    fn baseline_state_inventory_covers_the_reviewed_registry()
    -> Result<(), Box<dyn std::error::Error>> {
        let inventory = baseline_state_inventory()?;
        assert_eq!(inventory.len(), REPOSITORY_FAMILIES.len() + 1);

        let mut by_family: BTreeMap<&str, Vec<&str>> = BTreeMap::new();
        for entry in &inventory {
            let repository_id = entry["repository_id"]
                .as_str()
                .ok_or("repository_id is not a string")?;
            let state_family = entry["state_family"]
                .as_str()
                .ok_or("state_family is not a string")?;
            by_family
                .entry(state_family)
                .or_default()
                .push(repository_id);
        }
        assert_eq!(by_family.len(), STATE_FAMILIES.len());

        let mut total_tables = 0;
        for family in REPOSITORY_FAMILIES {
            let entry = inventory
                .iter()
                .find(|entry| entry["repository_id"].as_str() == Some(family.repository_id))
                .ok_or_else(|| format!("missing repository {}", family.repository_id))?;
            assert_eq!(entry["state_family"].as_str(), Some(family.state_family));
            let tables: Vec<&str> = entry["sqlite_objects"]
                .as_array()
                .ok_or("sqlite_objects is not an array")?
                .iter()
                .filter(|object| object["kind"].as_str() == Some("table"))
                .map(|object| object["name"].as_str().unwrap_or_default())
                .collect();
            assert_eq!(tables, family.tables.to_vec());
            let postgres_tables: Vec<&str> = entry["postgres_objects"]
                .as_array()
                .ok_or("postgres_objects is not an array")?
                .iter()
                .filter(|object| object["kind"].as_str() == Some("table"))
                .map(|object| object["name"].as_str().unwrap_or_default())
                .collect();
            assert_eq!(postgres_tables, family.tables.to_vec());
            total_tables += tables.len();
        }
        assert_eq!(total_tables, 77);

        let release = inventory
            .iter()
            .find(|entry| entry["repository_id"].as_str() == Some(RELEASE_METADATA_REPOSITORY_ID))
            .ok_or("missing release_and_install_metadata entry")?;
        assert_eq!(
            release["state_family"].as_str(),
            Some("release_and_install_metadata")
        );
        let sqlite_names: Vec<&str> = release["sqlite_objects"]
            .as_array()
            .ok_or("sqlite_objects is not an array")?
            .iter()
            .map(|object| object["name"].as_str().unwrap_or_default())
            .collect();
        assert_eq!(sqlite_names, ["_sqlx_migrations"]);
        assert_eq!(
            release["postgres_objects"][0]["schema"].as_str(),
            Some("public")
        );
        assert!(is_internal_sqlite_table("_sqlx_migrations"));
        assert!(is_internal_sqlite_table("sqlite_sequence"));
        assert!(!is_internal_sqlite_table("resources"));
        Ok(())
    }

    #[test]
    fn baseline_binding_covers_every_migration_file() -> Result<(), Box<dyn std::error::Error>> {
        let binding = baseline_binding()?;
        assert_eq!(binding.postgres_major, POSTGRES_MAJOR);
        assert_eq!(
            binding.sqlite_version,
            generator_sqlite_version()?,
            "the committed SQLite generator version must match this toolchain"
        );

        let mut expected = BTreeMap::new();
        let mut file_count = 0;
        for (directory, prefix) in [
            (manifest_dir().join("migrations"), "migrations/"),
            (
                manifest_dir().join("migrations_postgres"),
                "migrations_postgres/",
            ),
        ] {
            for path in migration_paths(&directory)? {
                let name = path
                    .file_name()
                    .and_then(|name| name.to_str())
                    .ok_or_else(|| {
                        format!("migration file {} has no UTF-8 name", path.display())
                    })?;
                let bytes = fs::read(&path)
                    .map_err(|error| format!("cannot read {}: {error}", path.display()))?;
                expected.insert(format!("{prefix}{name}"), sha256_hex_bytes(&bytes));
                file_count += 1;
            }
        }
        assert!(file_count > 0, "migration trees are empty");
        assert_eq!(
            binding.migration_files.len(),
            file_count,
            "the baseline must bind every migration file"
        );
        assert_eq!(binding.migration_files, expected);
        Ok(())
    }

    #[test]
    fn changing_a_migration_file_fails_the_drift_gate() -> Result<(), Box<dyn std::error::Error>> {
        let (sqlite, postgres) = scratch_trees(None)?;
        let before = generate_inventory_from_trees(sqlite.path(), postgres.path())?;

        // A comment-only change does not alter any parsed catalog definition,
        // so only the migration-file hash binding can catch it.
        let path = postgres.path().join("0001_initial.sql");
        let mut contents = fs::read_to_string(&path)?;
        contents.push_str("\n-- drift probe\n");
        fs::write(&path, contents)?;

        let after = generate_inventory_from_trees(sqlite.path(), postgres.path())?;
        assert_ne!(before, after, "file hash binding must change");
        let error = match ensure_matches_committed(&after) {
            Ok(()) => return Err("an edited migration file must fail the drift gate".into()),
            Err(error) => error,
        };
        let message = error.to_string();
        assert!(
            message.contains("migration file binding changed"),
            "{message}"
        );
        assert!(message.contains("0001_initial.sql"), "{message}");
        Ok(())
    }

    #[test]
    fn unregistered_migration_table_fails_generation_with_regeneration_instructions()
    -> Result<(), Box<dyn std::error::Error>> {
        let (sqlite, postgres) = scratch_trees(Some(
            "CREATE TABLE drift_gate_probe (id TEXT PRIMARY KEY);\n",
        ))?;
        let error = match generate_inventory_with_registry(
            sqlite.path(),
            postgres.path(),
            REPOSITORY_FAMILIES,
        ) {
            Ok(_) => return Err("an unregistered migration table must fail".into()),
            Err(error) => error,
        };
        let message = error.to_string();
        println!("unregistered migration table drift gate: {message}");
        assert!(message.contains("drift_gate_probe"), "{message}");
        assert!(message.contains("O3K_REGENERATE_INVENTORY=1"), "{message}");
        Ok(())
    }

    #[test]
    fn registry_table_absent_from_the_migration_tree_fails_generation()
    -> Result<(), Box<dyn std::error::Error>> {
        let (sqlite, postgres) = scratch_trees(None)?;
        let mut families = REPOSITORY_FAMILIES.to_vec();
        families.push(RepositoryFamily {
            repository_id: "registry_only",
            state_family: "o3k_owned_configuration",
            tables: &["registry_only_probe"],
        });
        let error =
            match generate_inventory_with_registry(sqlite.path(), postgres.path(), &families) {
                Ok(_) => {
                    return Err("a registry table absent from the migration tree must fail".into());
                }
                Err(error) => error,
            };
        let message = error.to_string();
        println!("missing migration table drift gate: {message}");
        assert!(message.contains("registry_only_probe"), "{message}");
        assert!(message.contains("SQLite migration tree"), "{message}");
        assert!(message.contains("O3K_REGENERATE_INVENTORY=1"), "{message}");
        Ok(())
    }

    #[test]
    fn baseline_comparison_fails_when_a_migration_adds_a_table()
    -> Result<(), Box<dyn std::error::Error>> {
        let (sqlite, postgres) = scratch_trees(Some(
            "CREATE TABLE drift_gate_probe (id TEXT PRIMARY KEY);\n",
        ))?;
        let mut families = REPOSITORY_FAMILIES.to_vec();
        families.push(drift_probe_family());
        let generated =
            generate_inventory_with_registry(sqlite.path(), postgres.path(), &families)?;
        let error = match ensure_matches_committed(&generated) {
            Ok(()) => {
                return Err(
                    "a migration table missing from the committed baseline must fail".into(),
                );
            }
            Err(error) => error,
        };
        let message = error.to_string();
        println!("committed baseline drift gate: {message}");
        assert!(message.contains("drift_gate_probe"), "{message}");
        assert!(message.contains("repository \"drift_probe\""), "{message}");
        assert!(message.contains("O3K_REGENERATE_INVENTORY=1"), "{message}");
        Ok(())
    }

    #[test]
    fn drift_description_reports_added_and_removed_entries()
    -> Result<(), Box<dyn std::error::Error>> {
        let base = serde_json::json!({
            "format": STATE_INVENTORY_FORMAT,
            "sqlite_version": generator_sqlite_version().expect("sqlite version"),
            "postgres_major": POSTGRES_MAJOR,
            "migration_files": {
                "migrations/0001_alpha.sql": "0".repeat(64),
                "migrations_postgres/0001_alpha.sql": "0".repeat(64)
            },
            "repositories": [{
                "repository_id": "alpha",
                "state_family": "canonical_resources",
                "empty_state_included": false,
                "sqlite_objects": [{
                    "kind": "table", "schema": "main", "name": "alpha_table",
                    "definition_sha256": "0".repeat(64)
                }],
                "postgres_objects": [{
                    "kind": "table", "schema": "public", "name": "alpha_table",
                    "definition_sha256": "0".repeat(64)
                }],
                "migration_ids": ["0001_alpha"]
            }]
        });
        let mut added = base.clone();
        let objects = added["repositories"][0]["sqlite_objects"]
            .as_array_mut()
            .ok_or("sqlite_objects is not an array")?;
        objects.push(serde_json::json!({
            "kind": "table", "schema": "main", "name": "alpha_added",
            "definition_sha256": "1".repeat(64)
        }));
        objects.push(serde_json::json!({
            "kind": "index", "schema": "main", "name": "alpha_idx_added",
            "definition_sha256": "2".repeat(64)
        }));
        objects.push(serde_json::json!({
            "kind": "function", "schema": "main", "name": "alpha_fn_added",
            "definition_sha256": "4".repeat(64)
        }));
        let message = describe_drift(&added.to_string(), &base.to_string());
        assert!(message.contains("catalog object(s) added"), "{message}");
        assert!(message.contains("alpha_added"), "{message}");
        assert!(message.contains("index:alpha_idx_added"), "{message}");
        assert!(message.contains("function:alpha_fn_added"), "{message}");

        let mut removed_object = base.clone();
        let objects = removed_object["repositories"][0]["sqlite_objects"]
            .as_array_mut()
            .ok_or("sqlite_objects is not an array")?;
        objects.push(serde_json::json!({
            "kind": "trigger", "schema": "main", "name": "alpha_trigger",
            "definition_sha256": "3".repeat(64)
        }));
        objects.push(serde_json::json!({
            "kind": "function", "schema": "main", "name": "alpha_fn",
            "definition_sha256": "5".repeat(64)
        }));
        let message = describe_drift(&base.to_string(), &removed_object.to_string());
        assert!(message.contains("catalog object(s) removed"), "{message}");
        assert!(message.contains("trigger:alpha_trigger"), "{message}");
        assert!(message.contains("function:alpha_fn"), "{message}");

        let mut removed = base.clone();
        removed["repositories"]
            .as_array_mut()
            .ok_or("repositories is not an array")?
            .clear();
        let message = describe_drift(&removed.to_string(), &base.to_string());
        assert!(message.contains("is missing"), "{message}");
        assert!(message.contains("alpha_table"), "{message}");

        let message = describe_drift(&base.to_string(), &base.to_string());
        assert!(message.contains("serialized content differs"), "{message}");
        Ok(())
    }

    #[test]
    fn sqlite_live_tables_reports_migrated_tables_and_internal_sqlx_table()
    -> Result<(), Box<dyn std::error::Error>> {
        let runtime = tokio::runtime::Builder::new_current_thread()
            .enable_all()
            .build()?;
        runtime.block_on(async {
            let store = SqliteStore::connect("sqlite::memory:").await?;
            let live = sqlite_live_tables(&store).await?;
            assert!(live.windows(2).all(|pair| pair[0] < pair[1]));
            assert!(live.iter().any(|table| table == "resources"));
            assert!(live.iter().any(|table| table == "_sqlx_migrations"));
            assert!(!live.iter().any(|table| table.starts_with("sqlite_")));
            Ok::<_, Box<dyn std::error::Error>>(())
        })
    }

    #[test]
    fn create_table_parser_handles_if_not_exists_quoting_and_comments() {
        let sql = "\
-- CREATE TABLE commented_out (id TEXT);
CREATE TABLE plain (id TEXT);
create table if not exists \"quoted_name\" (id TEXT);
CREATE TABLE `backticked` (
    id TEXT
);
CREATE TABLE [bracketed] (id TEXT);
";
        let names: Vec<String> = parse_create_tables(&strip_sql_comments(sql))
            .into_iter()
            .map(|(name, _)| name)
            .collect();
        assert_eq!(
            names,
            ["plain", "quoted_name", "backticked", "bracketed"]
                .into_iter()
                .map(str::to_owned)
                .collect::<Vec<_>>()
        );
    }

    #[test]
    fn create_table_definition_normalization_is_deterministic() {
        let one_line = "CREATE TABLE IF NOT EXISTS demo (id TEXT PRIMARY KEY, kind TEXT NOT NULL);";
        let multi_line = "CREATE TABLE demo (\n    id   TEXT\tPRIMARY KEY,\n    -- a comment\n    kind TEXT NOT NULL\n)";
        let plain = "CREATE TABLE demo (id TEXT PRIMARY KEY);";

        let one = parse_create_tables(&strip_sql_comments(one_line));
        let many = parse_create_tables(&strip_sql_comments(multi_line));
        let plain = parse_create_tables(&strip_sql_comments(plain));
        assert_eq!(one.len(), 1);
        assert_eq!(many.len(), 1);
        assert_eq!(plain.len(), 1);
        assert_eq!(one[0].1, many[0].1);
        assert_eq!(
            one[0].1,
            "CREATE TABLE demo (id TEXT PRIMARY KEY,kind TEXT NOT NULL)"
        );
        assert_ne!(one[0].1, plain[0].1);

        let quoted = parse_create_tables("CREATE TABLE \"a b\" (id TEXT);");
        assert_eq!(quoted.len(), 1);
        assert_eq!(quoted[0].0, "a b");
        assert_eq!(quoted[0].1, "CREATE TABLE \"a b\" (id TEXT)");
    }

    #[test]
    fn table_references_cover_create_alter_index_and_trigger_statements() {
        let sql = "\
CREATE TABLE alpha (id TEXT);
ALTER TABLE beta ADD COLUMN kind TEXT;
CREATE UNIQUE INDEX alpha_idx ON alpha (id);
CREATE TRIGGER guard AFTER INSERT ON gamma BEGIN SELECT 1; END;
DROP TABLE delta;
";
        let references = migration_table_references(&strip_sql_comments(sql));
        assert_eq!(
            references,
            ["alpha", "beta", "delta", "gamma"]
                .into_iter()
                .map(str::to_owned)
                .collect()
        );
    }

    #[test]
    fn generate_inventory_from_sqlite_tree_rejects_sqlite_only_tables()
    -> Result<(), Box<dyn std::error::Error>> {
        let scratch = ScratchDirectory::new("o3k-state-inventory-sqlite-only")?;
        copy_migrations(&manifest_dir().join("migrations"), scratch.path())?;
        fs::write(
            scratch.path().join("9999_sqlite_only.sql"),
            "CREATE TABLE drift_gate_probe (id TEXT PRIMARY KEY);\n",
        )?;
        let error = match generate_inventory_from_sqlite_tree(scratch.path()) {
            Ok(_) => return Err("a SQLite-only table must fail generation".into()),
            Err(error) => error,
        };
        assert!(error.to_string().contains("drift_gate_probe"));
        Ok(())
    }

    fn entry<'a>(inventory: &'a [Value], repository_id: &str) -> &'a Value {
        inventory
            .iter()
            .find(|entry| entry["repository_id"].as_str() == Some(repository_id))
            .expect("repository entry")
    }

    fn has_object(entry: &Value, field: &str, kind: &str, name: &str) -> bool {
        entry[field].as_array().is_some_and(|objects| {
            objects.iter().any(|object| {
                object["kind"].as_str() == Some(kind) && object["name"].as_str() == Some(name)
            })
        })
    }

    #[test]
    fn baseline_inventory_includes_indexes_triggers_and_functions()
    -> Result<(), Box<dyn std::error::Error>> {
        let inventory = baseline_state_inventory()?;
        let operations = entry(&inventory, "operations");
        let core_resources = entry(&inventory, "core_resources");
        let audit = entry(&inventory, "audit");

        assert!(has_object(
            operations,
            "sqlite_objects",
            "index",
            "operations_resource_idx"
        ));
        assert!(has_object(
            operations,
            "sqlite_objects",
            "trigger",
            "operations.operations_validate_resource_reference"
        ));
        assert!(has_object(
            operations,
            "postgres_objects",
            "index",
            "operations_resource_idx"
        ));
        assert!(has_object(
            operations,
            "postgres_objects",
            "trigger",
            "operations.operations_validate_resource_reference"
        ));
        assert!(has_object(
            core_resources,
            "postgres_objects",
            "trigger",
            "resources.resources_delete_generic_operations"
        ));
        assert!(has_object(
            operations,
            "postgres_objects",
            "function",
            "o3k_validate_operation_resource_reference()"
        ));
        assert!(has_object(
            operations,
            "postgres_objects",
            "function",
            "o3k_delete_generic_resource_operations()"
        ));
        assert!(has_object(
            audit,
            "sqlite_objects",
            "index",
            "idx_audit_scope_service_event"
        ));

        for entry in &inventory {
            for field in ["sqlite_objects", "postgres_objects"] {
                for object in entry[field].as_array().ok_or("object array")? {
                    let digest = object["definition_sha256"]
                        .as_str()
                        .ok_or("object digest")?;
                    assert!(is_sha256(digest), "{field} digest {digest:?}");
                    assert!(
                        CATALOG_KINDS.contains(&object["kind"].as_str().unwrap_or_default()),
                        "unexpected kind in {field}"
                    );
                }
            }
        }
        Ok(())
    }

    #[test]
    fn baseline_comparison_detects_added_indexes_and_triggers()
    -> Result<(), Box<dyn std::error::Error>> {
        let (sqlite, postgres) = scratch_trees(Some(
            "CREATE INDEX drift_gate_probe_idx ON resources (project_id);\n\
             CREATE TRIGGER drift_gate_probe_trigger\n\
             BEFORE INSERT ON operations BEGIN SELECT 1; END;\n",
        ))?;
        let generated =
            generate_inventory_with_registry(sqlite.path(), postgres.path(), REPOSITORY_FAMILIES)?;
        let error = match ensure_matches_committed(&generated) {
            Ok(()) => return Err("an added index/trigger must fail the drift gate".into()),
            Err(error) => error,
        };
        let message = error.to_string();
        println!("index/trigger drift gate: {message}");
        assert!(message.contains("index:drift_gate_probe_idx"), "{message}");
        assert!(
            message.contains("trigger:operations.drift_gate_probe_trigger"),
            "{message}"
        );
        assert!(message.contains("core_resources"), "{message}");
        assert!(message.contains("operations"), "{message}");
        Ok(())
    }

    #[test]
    fn generation_rejects_an_index_owned_by_an_unregistered_table()
    -> Result<(), Box<dyn std::error::Error>> {
        let (sqlite, postgres) = scratch_trees(Some(
            "CREATE INDEX drift_gate_probe_idx ON drift_gate_probe (id);\n",
        ))?;
        let error = match generate_inventory_with_registry(
            sqlite.path(),
            postgres.path(),
            REPOSITORY_FAMILIES,
        ) {
            Ok(_) => return Err("an index on an unregistered table must fail".into()),
            Err(error) => error,
        };
        let message = error.to_string();
        assert!(message.contains("drift_gate_probe_idx"), "{message}");
        assert!(message.contains("unregistered table"), "{message}");
        Ok(())
    }

    #[test]
    fn generation_rejects_a_function_without_a_reviewed_owner()
    -> Result<(), Box<dyn std::error::Error>> {
        let (sqlite, postgres) = scratch_trees(Some(
            "CREATE OR REPLACE FUNCTION drift_gate_probe_fn()\n\
             RETURNS trigger LANGUAGE plpgsql AS $$\n\
             BEGIN RETURN NEW; END;\n\
             $$;\n",
        ))?;
        let error = match generate_inventory_with_registry(
            sqlite.path(),
            postgres.path(),
            REPOSITORY_FAMILIES,
        ) {
            Ok(_) => return Err("an unowned function must fail generation".into()),
            Err(error) => error,
        };
        let message = error.to_string();
        assert!(message.contains("drift_gate_probe_fn"), "{message}");
        assert!(message.contains("GENERIC_FUNCTION_OWNERS"), "{message}");
        Ok(())
    }

    #[test]
    fn index_trigger_and_function_normalization_is_deterministic() {
        let index_one = "CREATE UNIQUE INDEX IF NOT EXISTS idx ON demo (a, b);";
        let index_many = "CREATE UNIQUE INDEX idx\n    ON demo (a,   b)";
        let one = parse_create_indexes(&strip_sql_comments(index_one)).expect("index one");
        let many = parse_create_indexes(&strip_sql_comments(index_many)).expect("index many");
        assert_eq!(one.len(), 1);
        assert_eq!(many.len(), 1);
        assert_eq!(one[0].0, "idx");
        assert_eq!(one[0].1, "demo");
        assert_eq!(one[0].2, many[0].2);
        assert_eq!(one[0].2, "CREATE UNIQUE INDEX idx ON demo (a,b)");

        let trigger_one = "CREATE TRIGGER guard BEFORE INSERT ON demo BEGIN SELECT 1; END;";
        let trigger_many = "CREATE TRIGGER guard\n  BEFORE INSERT ON demo\n  BEGIN SELECT 1; END";
        let one = parse_create_triggers(&strip_sql_comments(trigger_one)).expect("trigger one");
        let many = parse_create_triggers(&strip_sql_comments(trigger_many)).expect("trigger many");
        assert_eq!(one.len(), 1);
        assert_eq!(many.len(), 1);
        assert_eq!(one[0].0, "demo");
        assert_eq!(one[0].1, "guard");
        assert_eq!(one[0].2, many[0].2);
        assert!(!one[0].2.ends_with(';'));

        let function_one = "CREATE OR REPLACE FUNCTION f() RETURNS trigger LANGUAGE plpgsql AS $$ BEGIN RETURN NEW; END; $$;";
        let function_many = "CREATE OR REPLACE FUNCTION f()\nRETURNS trigger\nLANGUAGE plpgsql\nAS $$\nBEGIN RETURN NEW; END;\n$$";
        let one = parse_create_functions(&strip_sql_comments(function_one)).expect("function one");
        let many =
            parse_create_functions(&strip_sql_comments(function_many)).expect("function many");
        assert_eq!(one.len(), 1);
        assert_eq!(many.len(), 1);
        assert_eq!(one[0].0, "f");
        assert_eq!(one[0].1, "");
        assert_eq!(one[0].2, many[0].2);
        assert!(one[0].2.contains("$$"));
        assert!(!one[0].2.ends_with(';'));
    }

    const PROBE_VIEW_SQL: &str = "CREATE VIEW drift_gate_probe_view AS SELECT id FROM resources;\n";

    #[test]
    fn postgres_alter_table_add_column_updates_the_table_definition()
    -> Result<(), Box<dyn std::error::Error>> {
        let tree = parsed_probe_tree(
            "o3k-state-inventory-alter-add",
            "PostgreSQL",
            "CREATE TABLE demo (id TEXT PRIMARY KEY);\n\
             ALTER TABLE demo\n    ADD COLUMN first_col TEXT NOT NULL DEFAULT 'x';\n\
             ALTER TABLE demo ADD COLUMN IF NOT EXISTS second_col INTEGER NOT NULL DEFAULT 0\n    CHECK (second_col >= 0);\n",
        )?;
        assert_eq!(
            tree.definitions.get("demo").map(String::as_str),
            Some(
                "CREATE TABLE demo (id TEXT PRIMARY KEY,first_col TEXT NOT NULL DEFAULT 'x',\
                 second_col INTEGER NOT NULL DEFAULT 0 CHECK (second_col >= 0))"
            )
        );
        Ok(())
    }

    #[test]
    fn alter_table_effects_are_normalized_deterministically()
    -> Result<(), Box<dyn std::error::Error>> {
        let one_line = parsed_probe_tree(
            "o3k-state-inventory-alter-one-line",
            "PostgreSQL",
            "CREATE TABLE demo (id TEXT);\n\
             ALTER TABLE demo ADD COLUMN a TEXT, ADD COLUMN b INTEGER NOT NULL;\n",
        )?;
        let multi_line = parsed_probe_tree(
            "o3k-state-inventory-alter-multi-line",
            "PostgreSQL",
            "CREATE TABLE demo (\n    id TEXT\n);\n\
             ALTER TABLE demo\n    ADD COLUMN a TEXT,\n    ADD COLUMN b INTEGER NOT NULL;\n",
        )?;
        assert_eq!(
            one_line.definitions.get("demo").map(String::as_str),
            Some("CREATE TABLE demo (id TEXT,a TEXT,b INTEGER NOT NULL)")
        );
        assert_eq!(
            one_line.definitions.get("demo"),
            multi_line.definitions.get("demo")
        );
        assert_eq!(
            sha256_hex(one_line.definitions.get("demo").expect("one line")),
            sha256_hex(multi_line.definitions.get("demo").expect("multi line"))
        );

        // Later column drops and renames fold into the same definition.
        let edited = parsed_probe_tree(
            "o3k-state-inventory-alter-drop-rename",
            "PostgreSQL",
            "CREATE TABLE demo (id TEXT, gone TEXT, old_name TEXT);\n\
             ALTER TABLE demo\n    DROP COLUMN gone;\n\
             ALTER TABLE demo RENAME COLUMN old_name TO new_name;\n",
        )?;
        assert_eq!(
            edited.definitions.get("demo").map(String::as_str),
            Some("CREATE TABLE demo (id TEXT,new_name TEXT)")
        );
        Ok(())
    }

    #[test]
    fn postgres_alter_table_add_and_drop_constraint_updates_constraints()
    -> Result<(), Box<dyn std::error::Error>> {
        let tree = parsed_probe_tree(
            "o3k-state-inventory-alter-constraint",
            "PostgreSQL",
            "CREATE TABLE demo (id TEXT, other TEXT);\n\
             ALTER TABLE demo\n    ADD CONSTRAINT demo_id_unique UNIQUE (id);\n\
             ALTER TABLE demo ADD CONSTRAINT demo_other_check CHECK (other IS NOT NULL);\n",
        )?;
        assert_eq!(tree.constraints.len(), 2);
        let added = tree
            .constraints
            .get(&("demo".to_owned(), "demo_id_unique".to_owned()))
            .expect("added constraint");
        assert_eq!(added.kind, "constraint");
        assert_eq!(added.name, "demo_id_unique");
        assert_eq!(added.table.as_deref(), Some("demo"));
        assert_eq!(
            added.definition,
            "ALTER TABLE demo ADD CONSTRAINT demo_id_unique UNIQUE (id)"
        );

        let dropped = parsed_probe_tree(
            "o3k-state-inventory-alter-constraint-drop",
            "PostgreSQL",
            "CREATE TABLE demo (id TEXT);\n\
             ALTER TABLE demo ADD CONSTRAINT demo_id_unique UNIQUE (id);\n\
             ALTER TABLE demo DROP CONSTRAINT IF EXISTS demo_id_unique;\n\
             ALTER TABLE demo DROP CONSTRAINT IF EXISTS never_created;\n",
        )?;
        assert!(
            dropped.constraints.is_empty(),
            "a dropped constraint must not stay in the tree"
        );
        Ok(())
    }

    #[test]
    fn parse_create_views_and_sequences_handles_or_replace_and_if_not_exists() {
        let code = strip_sql_comments(
            "CREATE VIEW plain_view AS SELECT 1;\n\
             CREATE OR REPLACE VIEW replaced_view AS SELECT 2;\n\
             CREATE VIEW IF NOT EXISTS kept_view AS SELECT 3;\n\
             CREATE MATERIALIZED VIEW mat_view AS SELECT 4;\n",
        );
        let views = parse_create_views(&code).expect("views");
        let names: Vec<&str> = views.iter().map(|(name, _)| name.as_str()).collect();
        assert_eq!(
            names,
            ["plain_view", "replaced_view", "kept_view", "mat_view"]
        );
        assert_eq!(views[0].1, "CREATE VIEW plain_view AS SELECT 1");
        assert_eq!(
            views[1].1,
            "CREATE OR REPLACE VIEW replaced_view AS SELECT 2"
        );
        assert_eq!(views[2].1, "CREATE VIEW kept_view AS SELECT 3");
        assert!(views[3].1.starts_with("CREATE MATERIALIZED VIEW mat_view"));

        let code = strip_sql_comments(
            "CREATE SEQUENCE plain_seq;\n\
             CREATE SEQUENCE IF NOT EXISTS kept_seq START WITH 5;\n\
             CREATE TEMPORARY SEQUENCE temp_seq;\n",
        );
        let sequences = parse_create_sequences(&code).expect("sequences");
        let names: Vec<&str> = sequences.iter().map(|(name, _)| name.as_str()).collect();
        assert_eq!(names, ["plain_seq", "kept_seq", "temp_seq"]);
        assert_eq!(sequences[0].1, "CREATE SEQUENCE plain_seq");
        assert_eq!(sequences[1].1, "CREATE SEQUENCE kept_seq START WITH 5");
        assert_eq!(sequences[2].1, "CREATE TEMPORARY SEQUENCE temp_seq");
    }

    #[test]
    fn sqlite_views_are_emitted_from_the_live_catalog() -> Result<(), Box<dyn std::error::Error>> {
        let scratch = ScratchDirectory::new("o3k-state-inventory-sqlite-view")?;
        fs::write(
            scratch.path().join("0001_probe.sql"),
            "CREATE TABLE demo (id TEXT PRIMARY KEY);\n\
             CREATE VIEW demo_view AS SELECT id FROM demo;\n",
        )?;
        let tree = scan_sqlite_live_tree(scratch.path())?;
        let view = tree.views.get("demo_view").expect("live view object");
        assert_eq!(view.kind, "view");
        assert_eq!(view.name, "demo_view");
        assert_eq!(view.table, None);
        assert!(
            view.definition
                .starts_with("CREATE VIEW demo_view AS SELECT"),
            "{}",
            view.definition
        );

        // The production live reader accepts a view instead of rejecting it.
        let runtime = tokio::runtime::Builder::new_current_thread()
            .enable_all()
            .build()?;
        runtime.block_on(async {
            let store = SqliteStore::connect("sqlite::memory:").await?;
            sqlx::query("CREATE VIEW live_probe_view AS SELECT id FROM resources")
                .execute(&store.pool)
                .await?;
            let live = sqlite_live_catalog_objects(&store.pool).await?;
            assert!(
                live.iter()
                    .any(|object| object.kind == "view" && object.name == "live_probe_view"),
                "live catalog must include the view"
            );
            assert!(
                live.iter().any(|object| object.kind == "trigger"
                    && object.name == "operations.operations_validate_resource_reference"),
                "live trigger identity must match the baseline <table>.<name> form"
            );
            Ok::<_, Box<dyn std::error::Error>>(())
        })?;

        // A migrated store (without the probe view) matches the committed
        // baseline through the exact capture-time comparison.
        runtime.block_on(async {
            let store = SqliteStore::connect("sqlite::memory:").await?;
            let live = sqlite_live_catalog_objects(&store.pool).await?;
            let inventory = baseline_state_inventory()?;
            verify_sqlite_catalog_against_baseline(&inventory, &live)?;
            Ok::<_, Box<dyn std::error::Error>>(())
        })?;

        // A generated inventory carries the view in both backend catalogs.
        let (sqlite, postgres) = scratch_trees(Some(PROBE_VIEW_SQL))?;
        let owners = GenericOwners {
            views: &[("drift_gate_probe_view", "core_resources")],
            ..REVIEWED_GENERIC_OWNERS
        };
        let generated =
            generate_inventory_from_trees_with_owners(sqlite.path(), postgres.path(), &owners)?;
        let document = generated_document(&generated)?;
        let core = generated_entry(&document, "core_resources");
        assert!(object_names(core, "view").contains(&"drift_gate_probe_view".to_owned()));
        Ok(())
    }

    #[test]
    fn inline_named_constraints_are_emitted_with_table_owner()
    -> Result<(), Box<dyn std::error::Error>> {
        let inline = parsed_probe_tree(
            "o3k-state-inventory-inline-constraint",
            "PostgreSQL",
            "CREATE TABLE demo (id TEXT, other TEXT, \
             CONSTRAINT demo_inline_unique UNIQUE (id));\n",
        )?;
        assert_eq!(inline.constraints.len(), 1);
        let constraint = inline
            .constraints
            .get(&("demo".to_owned(), "demo_inline_unique".to_owned()))
            .expect("inline constraint");
        assert_eq!(constraint.kind, "constraint");
        assert_eq!(constraint.name, "demo_inline_unique");
        assert_eq!(constraint.table.as_deref(), Some("demo"));
        assert_eq!(
            constraint.definition,
            "ALTER TABLE demo ADD CONSTRAINT demo_inline_unique UNIQUE (id)"
        );
        assert!(
            inline
                .definitions
                .get("demo")
                .expect("table definition")
                .contains("CONSTRAINT demo_inline_unique UNIQUE (id)"),
            "the table digest must still describe the authored table"
        );

        let altered = parsed_probe_tree(
            "o3k-state-inventory-altered-constraint",
            "PostgreSQL",
            "CREATE TABLE demo (id TEXT, other TEXT);\n\
             ALTER TABLE demo ADD CONSTRAINT demo_inline_unique UNIQUE (id);\n",
        )?;
        assert_eq!(
            altered
                .constraints
                .get(&("demo".to_owned(), "demo_inline_unique".to_owned()))
                .expect("altered constraint")
                .definition,
            constraint.definition
        );

        let implicit = parsed_probe_tree(
            "o3k-state-inventory-implicit-constraint",
            "PostgreSQL",
            "CREATE TABLE demo (id TEXT PRIMARY KEY, code TEXT UNIQUE, \
             other TEXT REFERENCES resources(id), CHECK (other <> ''));\n",
        )?;
        assert!(
            implicit.constraints.is_empty(),
            "implicit constraints stay inside the table definition digest"
        );
        Ok(())
    }

    #[test]
    fn function_overloads_and_per_table_trigger_names_do_not_collide()
    -> Result<(), Box<dyn std::error::Error>> {
        let tree = parsed_probe_tree(
            "o3k-state-inventory-collisions",
            "PostgreSQL",
            "CREATE TABLE alpha (id TEXT);\n\
             CREATE TABLE beta (id TEXT);\n\
             CREATE OR REPLACE FUNCTION guard_fn(integer) RETURNS trigger LANGUAGE plpgsql \
             AS $$ BEGIN RETURN NEW; END; $$;\n\
             CREATE OR REPLACE FUNCTION guard_fn(text) RETURNS trigger LANGUAGE plpgsql \
             AS $$ BEGIN RETURN NEW; END; $$;\n\
             CREATE TRIGGER guard BEFORE INSERT ON alpha BEGIN SELECT 1; END;\n\
             CREATE TRIGGER guard BEFORE INSERT ON beta BEGIN SELECT 1; END;\n",
        )?;
        assert_eq!(tree.functions.len(), 2, "both overloads must survive");
        let integer = tree
            .functions
            .get(&("guard_fn".to_owned(), "integer".to_owned()))
            .expect("integer overload");
        assert_eq!(integer.name, "guard_fn(integer)");
        let text = tree
            .functions
            .get(&("guard_fn".to_owned(), "text".to_owned()))
            .expect("text overload");
        assert_eq!(text.name, "guard_fn(text)");
        assert_ne!(integer.definition, text.definition);
        assert!(integer.definition.contains("$$"));

        assert_eq!(tree.triggers.len(), 2, "both triggers must survive");
        let alpha = tree
            .triggers
            .get(&("alpha".to_owned(), "guard".to_owned()))
            .expect("alpha trigger");
        assert_eq!(alpha.name, "alpha.guard");
        let beta = tree
            .triggers
            .get(&("beta".to_owned(), "guard".to_owned()))
            .expect("beta trigger");
        assert_eq!(beta.name, "beta.guard");
        assert_ne!(alpha.definition, beta.definition);
        Ok(())
    }

    #[test]
    fn every_catalog_object_has_exactly_one_repository() -> Result<(), Box<dyn std::error::Error>> {
        let sqlite = scan_sqlite_live_tree(&manifest_dir().join("migrations"))?;
        let postgres =
            scan_migration_tree(&manifest_dir().join("migrations_postgres"), "PostgreSQL")?;
        let inventory = baseline_state_inventory()?;

        for (tree, field) in [(&sqlite, "sqlite_objects"), (&postgres, "postgres_objects")] {
            let mut counts: BTreeMap<(String, String), usize> = BTreeMap::new();
            for entry in &inventory {
                for object in entry[field].as_array().ok_or("object array")? {
                    let key = (
                        object["kind"].as_str().unwrap_or_default().to_owned(),
                        object["name"].as_str().unwrap_or_default().to_owned(),
                    );
                    *counts.entry(key).or_default() += 1;
                }
            }
            let mut expected: BTreeSet<(String, String)> = BTreeSet::new();
            for table in tree.definitions.keys() {
                expected.insert(("table".to_owned(), table.clone()));
            }
            for object in tree
                .views
                .values()
                .chain(tree.sequences.values())
                .chain(tree.indexes.values())
                .chain(tree.constraints.values())
                .chain(tree.triggers.values())
                .chain(tree.functions.values())
            {
                expected.insert((object.kind.to_owned(), object.name.clone()));
            }
            for key in &expected {
                assert_eq!(
                    counts.get(key),
                    Some(&1),
                    "{} object {key:?} must be owned by exactly one repository",
                    tree.tree
                );
            }
            for (key, count) in &counts {
                if !expected.contains(key) {
                    assert_eq!(*count, 1, "{} framework object {key:?}", tree.tree);
                    assert!(
                        key.0 == "table"
                            && (key.1 == "_sqlx_migrations" || key.1 == "sqlite_sequence"),
                        "unexpected {} catalog object {key:?}",
                        tree.tree
                    );
                }
            }
        }
        Ok(())
    }

    #[test]
    fn migration_ids_cover_object_defining_migrations() -> Result<(), Box<dyn std::error::Error>> {
        let sqlite = scan_sqlite_live_tree(&manifest_dir().join("migrations"))?;
        let postgres =
            scan_migration_tree(&manifest_dir().join("migrations_postgres"), "PostgreSQL")?;
        let inventory = baseline_state_inventory()?;
        for entry in &inventory {
            let migration_ids: BTreeSet<&str> = entry["migration_ids"]
                .as_array()
                .ok_or("migration ids")?
                .iter()
                .filter_map(|id| id.as_str())
                .collect();
            for field in ["sqlite_objects", "postgres_objects"] {
                for object in entry[field].as_array().ok_or("object array")? {
                    let key = (
                        object["kind"].as_str().unwrap_or_default().to_owned(),
                        object["name"].as_str().unwrap_or_default().to_owned(),
                    );
                    for tree in [&sqlite, &postgres] {
                        if let Some(stems) = tree.object_stems.get(&key) {
                            for stem in stems {
                                assert!(
                                    migration_ids.contains(stem.as_str()),
                                    "repository {:?} omits object-defining migration {stem} for {key:?}",
                                    entry["repository_id"]
                                );
                            }
                        }
                    }
                }
            }
        }

        // A repository that owns only an object still records the migration
        // that defines it, and a repository with no objects keeps the
        // RepositoryWithoutMigrations failure.
        let (sqlite, postgres) = scratch_trees(Some(PROBE_VIEW_SQL))?;
        let mut families = REPOSITORY_FAMILIES.to_vec();
        families.push(RepositoryFamily {
            repository_id: "object_only_probe",
            state_family: "o3k_owned_configuration",
            tables: &[],
        });
        let owners = GenericOwners {
            views: &[("drift_gate_probe_view", "object_only_probe")],
            ..REVIEWED_GENERIC_OWNERS
        };
        let generated =
            generate_inventory_with_owners(sqlite.path(), postgres.path(), &families, &owners)?;
        let document = generated_document(&generated)?;
        let object_only = generated_entry(&document, "object_only_probe");
        assert_eq!(
            object_only.migration_ids,
            vec!["9999_drift_probe".to_owned()]
        );
        assert!(
            object_only
                .sqlite_objects
                .iter()
                .any(|object| object.kind == "view")
        );
        assert!(
            object_only
                .postgres_objects
                .iter()
                .any(|object| object.kind == "view")
        );

        families.push(RepositoryFamily {
            repository_id: "empty_probe",
            state_family: "o3k_owned_configuration",
            tables: &[],
        });
        let error = match generate_inventory_with_owners(
            sqlite.path(),
            postgres.path(),
            &families,
            &owners,
        ) {
            Ok(_) => return Err("a repository without migrations must fail".into()),
            Err(error) => error,
        };
        assert!(
            matches!(
                error,
                StateInventoryError::RepositoryWithoutMigrations { .. }
            ),
            "{error}"
        );
        Ok(())
    }

    #[test]
    fn baseline_inventory_includes_views_sequences_and_constraints()
    -> Result<(), Box<dyn std::error::Error>> {
        // The committed baseline records the reviewed named constraint. No
        // reviewed migration creates a view or sequence yet, so those two kinds
        // are proven through a generated inventory below.
        let inventory = baseline_state_inventory()?;
        let canonical_network = entry(&inventory, "canonical_network");
        assert!(has_object(
            canonical_network,
            "postgres_objects",
            "constraint",
            "canonical_address_realms_id_project_unique"
        ));

        let postgres_sql = format!(
            "{PROBE_VIEW_SQL}\
             CREATE SEQUENCE drift_gate_probe_seq START WITH 1;\n\
             ALTER TABLE resources ADD CONSTRAINT drift_gate_probe_unique UNIQUE (id);\n"
        );
        let (sqlite, postgres) =
            scratch_trees_with_probes(Some(PROBE_VIEW_SQL), Some(&postgres_sql))?;
        let owners = GenericOwners {
            views: &[("drift_gate_probe_view", "core_resources")],
            sequences: &[("drift_gate_probe_seq", "core_resources")],
            ..REVIEWED_GENERIC_OWNERS
        };
        let generated = generate_inventory_with_owners(
            sqlite.path(),
            postgres.path(),
            REPOSITORY_FAMILIES,
            &owners,
        )?;
        let document = generated_document(&generated)?;
        let core = generated_entry(&document, "core_resources");
        assert!(
            core.sqlite_objects
                .iter()
                .any(|object| object.kind == "view" && object.name == "drift_gate_probe_view")
        );
        assert!(
            core.postgres_objects
                .iter()
                .any(|object| object.kind == "view" && object.name == "drift_gate_probe_view")
        );
        assert!(
            core.postgres_objects
                .iter()
                .any(|object| object.kind == "sequence" && object.name == "drift_gate_probe_seq")
        );
        assert!(
            core.postgres_objects
                .iter()
                .any(|object| object.kind == "constraint"
                    && object.name == "drift_gate_probe_unique")
        );
        assert!(
            !core
                .sqlite_objects
                .iter()
                .any(|object| object.kind == "sequence"),
            "sequences are PostgreSQL-only"
        );
        Ok(())
    }

    /// Drift-gate probe for a view and a named constraint added to a migration
    /// tree: the committed baseline must reject both additions.
    #[test]
    fn baseline_comparison_detects_added_views_and_constraints()
    -> Result<(), Box<dyn std::error::Error>> {
        let postgres_sql = format!(
            "{PROBE_VIEW_SQL}\
             ALTER TABLE resources ADD CONSTRAINT drift_gate_probe_unique UNIQUE (id);\n"
        );
        let (sqlite, postgres) =
            scratch_trees_with_probes(Some(PROBE_VIEW_SQL), Some(&postgres_sql))?;
        let owners = GenericOwners {
            views: &[("drift_gate_probe_view", "core_resources")],
            ..REVIEWED_GENERIC_OWNERS
        };
        let generated = generate_inventory_with_owners(
            sqlite.path(),
            postgres.path(),
            REPOSITORY_FAMILIES,
            &owners,
        )?;
        let error = match ensure_matches_committed(&generated) {
            Ok(()) => return Err("an added view/constraint must fail the drift gate".into()),
            Err(error) => error,
        };
        let message = error.to_string();
        println!("view/constraint drift gate: {message}");
        assert!(message.contains("view:drift_gate_probe_view"), "{message}");
        assert!(
            message.contains("constraint:drift_gate_probe_unique"),
            "{message}"
        );
        assert!(message.contains("core_resources"), "{message}");
        Ok(())
    }

    #[test]
    fn postgres_catalog_comparison_checks_identity_and_ignores_constraints()
    -> Result<(), Box<dyn std::error::Error>> {
        let inventory = vec![serde_json::json!({
            "repository_id": "probe",
            "state_family": "canonical_resources",
            "empty_state_included": false,
            "sqlite_objects": [{
                "kind": "table", "schema": "main", "name": "probe_table",
                "definition_sha256": "a".repeat(64)
            }],
            "postgres_objects": [
                {
                    "kind": "table", "schema": "public", "name": "probe_table",
                    "definition_sha256": "b".repeat(64)
                },
                {
                    "kind": "index", "schema": "public", "name": "probe_idx",
                    "definition_sha256": "c".repeat(64)
                },
                {
                    "kind": "constraint", "schema": "public", "name": "probe_unique",
                    "definition_sha256": "d".repeat(64)
                },
                {
                    "kind": "function", "schema": "public", "name": "probe_fn()",
                    "definition_sha256": "e".repeat(64)
                }
            ],
            "migration_ids": ["0001_probe"]
        })];
        let live = vec![
            PostgresLiveCatalogObject {
                kind: "table".to_owned(),
                name: "probe_table".to_owned(),
                definition: None,
            },
            PostgresLiveCatalogObject {
                kind: "index".to_owned(),
                name: "probe_idx".to_owned(),
                definition: Some("CREATE INDEX probe_idx ON public.probe_table (id)".to_owned()),
            },
            PostgresLiveCatalogObject {
                kind: "function".to_owned(),
                name: "probe_fn()".to_owned(),
                definition: Some("CREATE FUNCTION probe_fn()".to_owned()),
            },
        ];
        // The named constraint is intentionally not part of the live identity.
        assert_eq!(
            verify_postgres_catalog_against_baseline(&inventory, &live),
            Ok(())
        );

        let mut unexpected = live.clone();
        unexpected.push(PostgresLiveCatalogObject {
            kind: "view".to_owned(),
            name: "probe_view".to_owned(),
            definition: None,
        });
        assert_eq!(
            verify_postgres_catalog_against_baseline(&inventory, &unexpected),
            Err(CatalogMismatch::Unexpected {
                kind: "view".to_owned(),
                name: "probe_view".to_owned(),
            })
        );

        let missing = [live[0].clone()];
        assert_eq!(
            verify_postgres_catalog_against_baseline(&inventory, &missing),
            Err(CatalogMismatch::Missing {
                kind: "function".to_owned(),
                name: "probe_fn()".to_owned(),
            })
        );
        Ok(())
    }
}
