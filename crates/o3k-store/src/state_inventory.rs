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
//! review; CI must never set it.
//!
//! Every baseline entry sets `empty_state_included` to `false`: the baseline
//! records schema coverage, while emptiness is a property of one captured
//! snapshot and is decided at capture time.
//!
//! # Catalog object digests
//!
//! `definition_sha256` is the lowercase hex SHA-256 of a normalized catalog
//! definition parsed from the committed migration SQL. SQLite objects are
//! computed from `migrations/` and PostgreSQL objects independently from
//! `migrations_postgres/`. Normalization rules:
//!
//! 1. `--` line comments and `/* */` block comments are removed;
//! 2. the definition is the exact `CREATE TABLE` statement from `CREATE`
//!    through the parenthesis that closes the column/constraint list, without
//!    the trailing `;`;
//! 3. runs of whitespace outside quoted identifiers and string literals
//!    collapse to one space, and the result is trimmed;
//! 4. whitespace that depends only on layout is removed outside quoted
//!    identifiers and string literals: after `(`, after `,`, before `)` and
//!    before `,`;
//! 5. an `IF NOT EXISTS` qualifier is removed;
//! 6. identifiers, keywords and literals keep their original spelling, case
//!    and quoting;
//! 7. when one tree creates the same table more than once (a table rebuild,
//!    for example `0036_native_attachment_reuse.sql`), the last `CREATE TABLE`
//!    in migration-stem order is the effective definition.
//!
//! `migration_ids` lists, sorted and unique, every migration file stem that
//! names the repository's tables in a DDL statement: `CREATE TABLE`,
//! `ALTER TABLE`, `DROP TABLE`, `CREATE [UNIQUE] INDEX ... ON` and
//! `CREATE TRIGGER ... ON`. Stems from both migration trees are included
//! because the two trees do not share a numbering scheme.
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

use std::{collections::BTreeSet, path::PathBuf};

#[cfg(test)]
use std::{collections::BTreeMap, fs, path::Path};

#[cfg(test)]
use sha2::{Digest, Sha256};

use serde::{Deserialize, Serialize};

use crate::{SqliteStore, StoreError};

/// Format marker for the committed canonical state inventory.
pub const STATE_INVENTORY_FORMAT: &str = "o3k-state-inventory-v1";

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

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct InventoryDocument {
    format: String,
    repositories: Vec<RepositoryInventoryEntry>,
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

fn validate_document(document: &InventoryDocument) -> Result<(), StateInventoryError> {
    if document.format != STATE_INVENTORY_FORMAT {
        return Err(StateInventoryError::UnsupportedFormat {
            found: document.format.clone(),
            expected: STATE_INVENTORY_FORMAT,
        });
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
    let sqlite = scan_migration_tree(sqlite_migrations_dir, "SQLite")?;
    let postgres = scan_migration_tree(postgres_migrations_dir, "PostgreSQL")?;
    render_inventory(&sqlite, &postgres, REPOSITORY_FAMILIES)
}

#[cfg(test)]
fn generate_inventory_from_sqlite_tree(
    migrations_dir: &Path,
) -> Result<String, StateInventoryError> {
    let sqlite = scan_migration_tree(migrations_dir, "SQLite")?;
    render_inventory(
        &sqlite,
        &scan_migration_tree(
            &PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("migrations_postgres"),
            "PostgreSQL",
        )?,
        REPOSITORY_FAMILIES,
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
    render_inventory(&sqlite, &postgres, families)
}

/// One migration tree: effective table definitions, per-table migration
/// lineage, and the migration stems it contains.
#[cfg(test)]
struct MigrationTree {
    tree: &'static str,
    definitions: BTreeMap<String, String>,
    references: BTreeMap<String, BTreeSet<String>>,
    stems: BTreeSet<String>,
    autoincrement: bool,
}

#[cfg(test)]
fn scan_migration_tree(
    migrations_dir: &Path,
    tree: &'static str,
) -> Result<MigrationTree, StateInventoryError> {
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

    let mut scanned = MigrationTree {
        tree,
        definitions: BTreeMap::new(),
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

/// Removes `--` line comments and `/* */` block comments while preserving
/// quoted identifiers and string literals, so offsets remain valid for slicing
/// statement definitions out of the returned text.
///
/// PostgreSQL dollar-quoted strings are not used by the reviewed migrations and
/// are not handled.
#[cfg(test)]
fn strip_sql_comments(sql: &str) -> String {
    let mut stripped = String::with_capacity(sql.len());
    let mut characters = sql.chars().peekable();
    let mut quote: Option<char> = None;
    while let Some(character) = characters.next() {
        if let Some(terminator) = quote {
            stripped.push(character);
            if character == terminator {
                if characters.peek() == Some(&terminator) {
                    if let Some(escaped) = characters.next() {
                        stripped.push(escaped);
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
                stripped.push(character);
            }
            '[' => {
                quote = Some(']');
                stripped.push(character);
            }
            '-' if characters.peek() == Some(&'-') => {
                for next in characters.by_ref() {
                    if next == '\n' {
                        stripped.push('\n');
                        break;
                    }
                }
            }
            '/' if characters.peek() == Some(&'*') => {
                characters.next();
                stripped.push(' ');
                let mut previous = '\0';
                for next in characters.by_ref() {
                    if previous == '*' && next == '/' {
                        break;
                    }
                    previous = next;
                }
            }
            _ => stripped.push(character),
        }
    }
    stripped
}

#[cfg(test)]
#[derive(Debug)]
struct Token {
    text: String,
    quoted: bool,
    start: usize,
    end: usize,
}

/// Splits SQL into tokens, recording byte offsets in `code`. Quoted
/// identifiers and string literals become single tokens; parentheses and
/// commas become their own tokens; statement separators are dropped.
#[cfg(test)]
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
            b'(' | b')' | b',' => {
                tokens.push(Token {
                    text: (byte as char).to_string(),
                    quoted: false,
                    start: index,
                    end: index + 1,
                });
                index += 1;
            }
            b';' => index += 1,
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

#[cfg(test)]
fn is_keyword(tokens: &[Token], index: usize, keyword: &str) -> bool {
    tokens
        .get(index)
        .is_some_and(|token| !token.quoted && token.text.eq_ignore_ascii_case(keyword))
}

#[cfg(test)]
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
#[cfg(test)]
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
#[cfg(test)]
fn normalized_definition(statement: &str) -> String {
    let collapsed = collapse_whitespace(statement);
    strip_if_not_exists(&tidy_punctuation(&collapsed))
}

/// Removes whitespace introduced only by statement layout around parentheses
/// and commas, outside quoted identifiers and string literals.
#[cfg(test)]
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

#[cfg(test)]
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

#[cfg(test)]
fn strip_if_not_exists(statement: &str) -> String {
    let mut parts = statement.splitn(5, ' ');
    let (Some(create), Some(table), Some(if_), Some(not), Some(rest)) = (
        parts.next(),
        parts.next(),
        parts.next(),
        parts.next(),
        parts.next(),
    ) else {
        return statement.to_owned();
    };
    if if_.eq_ignore_ascii_case("IF")
        && not.eq_ignore_ascii_case("NOT")
        && rest
            .get(.."EXISTS ".len())
            .is_some_and(|prefix| prefix.eq_ignore_ascii_case("EXISTS "))
    {
        return format!("{create} {table} {}", &rest["EXISTS ".len()..]);
    }
    statement.to_owned()
}

#[cfg(test)]
fn sha256_hex(value: &str) -> String {
    use std::fmt::Write as _;

    let digest = Sha256::digest(value.as_bytes());
    let mut encoded = String::with_capacity(64);
    for byte in digest {
        let _ = write!(encoded, "{byte:02x}");
    }
    encoded
}

#[cfg(test)]
fn render_inventory(
    sqlite: &MigrationTree,
    postgres: &MigrationTree,
    families: &[RepositoryFamily],
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

    let mut entries = Vec::with_capacity(families.len() + 1);
    for family in families {
        let sqlite_objects = family
            .tables
            .iter()
            .map(|table| catalog_table(sqlite, "main", table))
            .collect::<Result<Vec<_>, _>>()?;
        let postgres_objects = family
            .tables
            .iter()
            .map(|table| catalog_table(postgres, "public", table))
            .collect::<Result<Vec<_>, _>>()?;
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
    for repository in repositories {
        match (
            generated_entries.get(&repository),
            committed_entries.get(&repository),
        ) {
            (Some(generated_entry), Some(committed_entry)) => {
                let generated_tables = entry_tables(generated_entry);
                let committed_tables = entry_tables(committed_entry);
                let added: Vec<_> = generated_tables
                    .difference(&committed_tables)
                    .cloned()
                    .collect();
                let removed: Vec<_> = committed_tables
                    .difference(&generated_tables)
                    .cloned()
                    .collect();
                if !added.is_empty() {
                    changes.push(format!(
                        "table(s) added to repository {repository:?}: {}",
                        added.join(", ")
                    ));
                }
                if !removed.is_empty() {
                    changes.push(format!(
                        "table(s) removed from repository {repository:?}: {}",
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
        .map(|object| object.name.clone())
        .collect()
}

#[cfg(test)]
mod tests {
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

        if std::env::var("O3K_REGENERATE_INVENTORY").as_deref() == Ok("1") {
            fs::write(root.join("state_inventory_v1.json"), &generated)?;
            println!(
                "regenerate and review crates/o3k-store/state_inventory_v1.json before committing"
            );
            return Ok(());
        }

        ensure_matches_committed(&generated)?;
        Ok(())
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
                .map(|object| object["name"].as_str().unwrap_or_default())
                .collect();
            assert_eq!(tables, family.tables.to_vec());
            let postgres_tables: Vec<&str> = entry["postgres_objects"]
                .as_array()
                .ok_or("postgres_objects is not an array")?
                .iter()
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
        added["repositories"][0]["sqlite_objects"]
            .as_array_mut()
            .ok_or("sqlite_objects is not an array")?
            .push(serde_json::json!({
                "kind": "table", "schema": "main", "name": "alpha_added",
                "definition_sha256": "1".repeat(64)
            }));
        let message = describe_drift(&added.to_string(), &base.to_string());
        assert!(message.contains("table(s) added"), "{message}");
        assert!(message.contains("alpha_added"), "{message}");

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
}
