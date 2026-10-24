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
//! - **table** — every `CREATE TABLE` in the migration tree;
//! - **index** — every `CREATE [UNIQUE] INDEX` (SQLite and PostgreSQL);
//! - **trigger** — every `CREATE [OR REPLACE] TRIGGER` (SQLite and PostgreSQL);
//! - **function** — every `CREATE [OR REPLACE] FUNCTION` (PostgreSQL only).
//!
//! Views and sequences are accepted by the contract but no reviewed migration
//! creates one; a future `CREATE VIEW`/`CREATE SEQUENCE` fails generation
//! instead of being silently omitted. Explicit named constraints (for example
//! `ALTER TABLE ... ADD CONSTRAINT` in the PostgreSQL tree) are not emitted as
//! `constraint` objects; the reviewed catalog coverage is tables, indexes,
//! triggers and functions.
//!
//! Indexes and triggers are assigned to the repository entry that owns the
//! table named by their `ON <table>` clause. A PostgreSQL function has no table
//! owner; each reviewed function must be listed in
//! `GENERIC_FUNCTION_OWNERS` and is assigned to the named repository (both
//! current functions are generic operation-integrity functions and belong to
//! `operations`). An unlisted function fails generation instead of being
//! silently dropped.
//!
//! Normalization rules:
//!
//! 1. `--` line comments and `/* */` block comments are removed. SQLite
//!    `[...]` quoting, SQL `'...'`/`"..."`/`` `...` `` quoting and PostgreSQL
//!    dollar-quoted strings (`$$...$$`, `$tag$...$tag$`) are preserved;
//! 2. for a table, the definition is the exact `CREATE TABLE` statement from
//!    `CREATE` through the parenthesis that closes the column/constraint list;
//!    for indexes, triggers and functions it is the whole statement through the
//!    terminator (the PostgreSQL function body is the complete dollar-quoted
//!    string). The trailing `;` is excluded;
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
//!    migration-stem order is the effective definition. A `DROP` of an object
//!    that the tree itself never creates is ignored.
//!
//! `migration_ids` lists, sorted and unique, every migration file stem that
//! names the repository's tables in a DDL statement: `CREATE TABLE`,
//! `ALTER TABLE`, `DROP TABLE`, `CREATE [UNIQUE] INDEX ... ON` and
//! `CREATE TRIGGER ... ON`. Stems from both migration trees are included
//! because the two trees do not share a numbering scheme.
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
//! produce false mismatches.
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
    use sqlx::Row as _;

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
    sqlx::query_scalar(
        "SELECT name FROM sqlite_master \
         WHERE type = 'table' AND name NOT LIKE 'sqlite_%' \
         ORDER BY name",
    )
    .fetch_all(&store.pool)
    .await
    .map_err(StoreError::Database)
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
    let sqlite = scan_sqlite_live_tree(sqlite_migrations_dir)?;
    let postgres = scan_migration_tree(postgres_migrations_dir, "PostgreSQL")?;
    render_inventory(
        &sqlite,
        &postgres,
        REPOSITORY_FAMILIES,
        migration_file_hashes(sqlite_migrations_dir, postgres_migrations_dir)?,
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

/// One reviewed non-table definition parsed from a migration tree.
#[cfg(test)]
#[derive(Debug, Clone, PartialEq, Eq)]
struct ObjectDefinition {
    kind: &'static str,
    /// Owner table from `ON <table>`; `None` only for functions.
    table: Option<String>,
    definition: String,
}

/// One migration tree: effective table definitions, one owner per non-table
/// object, per-table migration lineage, and the migration stems it contains.
#[cfg(test)]
struct MigrationTree {
    tree: &'static str,
    definitions: BTreeMap<String, String>,
    indexes: BTreeMap<String, ObjectDefinition>,
    triggers: BTreeMap<String, ObjectDefinition>,
    functions: BTreeMap<String, ObjectDefinition>,
    references: BTreeMap<String, BTreeSet<String>>,
    stems: BTreeSet<String>,
    autoincrement: bool,
}

/// Reviewed assignment of the generic operation-integrity functions.
///
/// A PostgreSQL function has no `ON <table>` clause, so it cannot be assigned
/// to a repository by table ownership. Every reviewed function must appear
/// here; [`render_inventory`] fails on an unlisted function instead of silently
/// omitting it.
#[cfg(test)]
const GENERIC_FUNCTION_OWNERS: &[(&str, &str)] = &[
    ("o3k_delete_generic_resource_operations", "operations"),
    ("o3k_validate_operation_resource_reference", "operations"),
];

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

#[cfg(test)]
fn scan_migration_tree(
    migrations_dir: &Path,
    tree: &'static str,
) -> Result<MigrationTree, StateInventoryError> {
    let migration_paths = migration_paths(migrations_dir)?;

    let mut scanned = MigrationTree {
        tree,
        definitions: BTreeMap::new(),
        indexes: BTreeMap::new(),
        triggers: BTreeMap::new(),
        functions: BTreeMap::new(),
        references: BTreeMap::new(),
        stems: BTreeSet::new(),
        autoincrement: false,
    };
    for path in migration_paths {
        let stem = path
            .file_stem()
            .map(|stem| stem.to_string_lossy().into_owned())
            .ok_or_else(|| {
                StateInventoryError::InvalidBaseline(format!(
                    "migration file {} has no file stem",
                    path.display()
                ))
            })?;
        let sql =
            fs::read_to_string(&path).map_err(|source| StateInventoryError::ReadMigration {
                path: path.clone(),
                source,
            })?;
        let code = strip_sql_comments(&sql);
        if code.to_ascii_uppercase().contains("AUTOINCREMENT") {
            scanned.autoincrement = true;
        }
        scanned.stems.insert(stem.clone());
        for (table, definition) in parse_create_tables(&code) {
            scanned.definitions.insert(table, definition);
        }
        let context = |detail: String| {
            StateInventoryError::InvalidBaseline(format!("{tree} migration {stem}: {detail}"))
        };
        for (name, table, definition) in parse_create_indexes(&code).map_err(context)? {
            scanned.indexes.insert(
                name,
                ObjectDefinition {
                    kind: "index",
                    table: Some(table),
                    definition,
                },
            );
        }
        for (name, table, definition) in parse_create_triggers(&code).map_err(context)? {
            scanned.triggers.insert(
                name,
                ObjectDefinition {
                    kind: "trigger",
                    table: Some(table),
                    definition,
                },
            );
        }
        for (name, definition) in parse_create_functions(&code).map_err(context)? {
            scanned.functions.insert(
                name,
                ObjectDefinition {
                    kind: "function",
                    table: None,
                    definition,
                },
            );
        }
        if let Some((kind, name)) = unsupported_create_object(&code) {
            return Err(StateInventoryError::UnsupportedCatalogObject { tree, kind, name });
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
#[cfg(test)]
fn scan_sqlite_live_tree(migrations_dir: &Path) -> Result<MigrationTree, StateInventoryError> {
    use sqlx::Row as _;

    let migration_paths = migration_paths(migrations_dir)?;
    let mut scanned = MigrationTree {
        tree: "SQLite",
        definitions: BTreeMap::new(),
        indexes: BTreeMap::new(),
        triggers: BTreeMap::new(),
        functions: BTreeMap::new(),
        references: BTreeMap::new(),
        stems: BTreeSet::new(),
        autoincrement: false,
    };
    let mut migration_sql = Vec::with_capacity(migration_paths.len());
    for path in &migration_paths {
        let stem = path
            .file_stem()
            .map(|stem| stem.to_string_lossy().into_owned())
            .ok_or_else(|| {
                StateInventoryError::InvalidBaseline(format!(
                    "migration file {} has no file stem",
                    path.display()
                ))
            })?;
        let sql =
            fs::read_to_string(path).map_err(|source| StateInventoryError::ReadMigration {
                path: path.clone(),
                source,
            })?;
        let code = strip_sql_comments(&sql);
        if code.to_ascii_uppercase().contains("AUTOINCREMENT") {
            scanned.autoincrement = true;
        }
        scanned.stems.insert(stem.clone());
        for table in migration_table_references(&code) {
            scanned
                .references
                .entry(table)
                .or_default()
                .insert(stem.clone());
        }
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
                    name,
                    ObjectDefinition {
                        kind: "index",
                        table: Some(table.to_ascii_lowercase()),
                        definition,
                    },
                );
            }
            "trigger" => {
                scanned.triggers.insert(
                    name,
                    ObjectDefinition {
                        kind: "trigger",
                        table: Some(table.to_ascii_lowercase()),
                        definition,
                    },
                );
            }
            "view" => {
                return Err(StateInventoryError::UnsupportedCatalogObject {
                    tree: "SQLite",
                    kind: "view",
                    name,
                });
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
                let name_index = skip_exists_clause(&tokens, at + 1);
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

/// Returns `(name, owner table, normalized definition)` for every
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
                    name.text.to_ascii_lowercase(),
                    table.text.to_ascii_lowercase(),
                    definition,
                ));
                index = terminator;
            }
        }
        index += 1;
    }
    Ok(triggers)
}

/// Returns `(name, normalized definition)` for every
/// `CREATE [OR REPLACE] FUNCTION` statement in `code`, in file order.
#[cfg(test)]
fn parse_create_functions(code: &str) -> Result<Vec<(String, String)>, String> {
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
                let terminator = statement_terminator(&tokens, index, false);
                let end = tokens
                    .get(terminator)
                    .map_or(code.len(), |token| token.start);
                let definition = normalized_definition(&code[tokens[index].start..end]);
                functions.push((name.text.to_ascii_lowercase(), definition));
                index = terminator;
            }
        }
        index += 1;
    }
    Ok(functions)
}

/// Returns the first `CREATE VIEW`/`CREATE MATERIALIZED VIEW`/`CREATE
/// SEQUENCE` in `code`, which the generator does not emit.
#[cfg(test)]
fn unsupported_create_object(code: &str) -> Option<(&'static str, String)> {
    let tokens = tokenize(code);
    let mut index = 0;
    while index < tokens.len() {
        if is_keyword(&tokens, index, "create") {
            let mut at = index + 1;
            if is_keyword(&tokens, at, "materialized") {
                at += 1;
            }
            let kind = if is_keyword(&tokens, at, "view") {
                Some("view")
            } else if is_keyword(&tokens, at, "sequence") {
                Some("sequence")
            } else {
                None
            };
            if let Some(kind) = kind {
                let name_index = skip_exists_clause(&tokens, at + 1);
                let name = tokens
                    .get(name_index)
                    .map_or_else(|| "<unnamed>".to_owned(), |token| token.text.clone());
                return Some((kind, name));
            }
        }
        index += 1;
    }
    None
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

fn sha256_hex(value: &str) -> String {
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
        for (kind, objects) in [("index", &tree.indexes), ("trigger", &tree.triggers)] {
            for (name, object) in objects {
                let table = object.table.as_deref().unwrap_or_default();
                if !table_repositories.contains_key(table) {
                    return Err(StateInventoryError::UnregisteredCatalogObject {
                        tree: tree.tree,
                        kind,
                        name: name.clone(),
                        table: table.to_owned(),
                    });
                }
            }
        }
        for name in tree.functions.keys() {
            let Some((_, repository)) = GENERIC_FUNCTION_OWNERS
                .iter()
                .find(|(function, _)| *function == name.as_str())
            else {
                return Err(StateInventoryError::UnassignedFunction {
                    tree: tree.tree,
                    name: name.clone(),
                });
            };
            if !repository_ids.contains(*repository) {
                return Err(StateInventoryError::InvalidBaseline(format!(
                    "function {name:?} is assigned to unknown repository {repository:?}"
                )));
            }
        }
    }

    let mut entries = Vec::with_capacity(families.len() + 1);
    for family in families {
        let sqlite_objects = family_objects(sqlite, "main", family)?;
        let postgres_objects = family_objects(postgres, "public", family)?;
        let mut migration_ids = BTreeSet::new();
        for table in family.tables.iter() {
            for tree in [sqlite, postgres] {
                if let Some(stems) = tree.references.get(*table) {
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
fn catalog_non_table(schema: &str, name: &str, object: &ObjectDefinition) -> CatalogObject {
    CatalogObject {
        kind: object.kind.to_owned(),
        schema: schema.to_owned(),
        name: name.to_owned(),
        definition_sha256: sha256_hex(&object.definition),
    }
}

/// Every catalog object owned by one repository entry: its tables in registry
/// order, then indexes, triggers and (PostgreSQL only) functions in name order.
#[cfg(test)]
fn family_objects(
    tree: &MigrationTree,
    schema: &str,
    family: &RepositoryFamily,
) -> Result<Vec<CatalogObject>, StateInventoryError> {
    let mut objects = Vec::new();
    for table in family.tables.iter() {
        objects.push(catalog_table(tree, schema, table)?);
    }
    for (name, object) in &tree.indexes {
        if object
            .table
            .as_deref()
            .is_some_and(|table| family.tables.contains(&table))
        {
            objects.push(catalog_non_table(schema, name, object));
        }
    }
    for (name, object) in &tree.triggers {
        if object
            .table
            .as_deref()
            .is_some_and(|table| family.tables.contains(&table))
        {
            objects.push(catalog_non_table(schema, name, object));
        }
    }
    for (name, object) in &tree.functions {
        if GENERIC_FUNCTION_OWNERS
            .iter()
            .any(|(function, repository)| {
                *function == name.as_str() && *repository == family.repository_id
            })
        {
            objects.push(catalog_non_table(schema, name, object));
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
        let sqlite = ScratchDirectory::new("o3k-state-inventory-sqlite")?;
        let postgres = ScratchDirectory::new("o3k-state-inventory-postgres")?;
        copy_migrations(&manifest_dir().join("migrations"), sqlite.path())?;
        copy_migrations(&manifest_dir().join("migrations_postgres"), postgres.path())?;
        if let Some(sql) = probe_sql {
            fs::write(sqlite.path().join("9999_drift_probe.sql"), sql)?;
            fs::write(postgres.path().join("9999_drift_probe.sql"), sql)?;
        }
        Ok((sqlite, postgres))
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
            "operations_validate_resource_reference"
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
            "operations_validate_resource_reference"
        ));
        assert!(has_object(
            core_resources,
            "postgres_objects",
            "trigger",
            "resources_delete_generic_operations"
        ));
        assert!(has_object(
            operations,
            "postgres_objects",
            "function",
            "o3k_validate_operation_resource_reference"
        ));
        assert!(has_object(
            operations,
            "postgres_objects",
            "function",
            "o3k_delete_generic_resource_operations"
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
            message.contains("trigger:drift_gate_probe_trigger"),
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
        assert_eq!(one[0].0, "guard");
        assert_eq!(one[0].1, "demo");
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
        assert_eq!(one[0].1, many[0].1);
        assert!(one[0].1.contains("$$"));
        assert!(!one[0].1.ends_with(';'));
    }
}
