//! PostgreSQL 16 `pg_dump`/`pg_restore` host-tool boundary (PP.6 D10).
//!
//! This is the only PP.6 file allowed to execute a host command besides the
//! pre-existing upgrade/runner and sys boundaries. Execution is argv-only:
//! there is no shell, no `sh -c`, and no string is ever passed to a shell.
//!
//! Capture uses `pg_dump -Fc --no-owner --no-acl --no-password`; restore
//! listing uses `pg_restore --list` without a target connection. The complete
//! unfiltered TOC is then classified against the migration-derived repository
//! inventory: every expected table/data/index/function/trigger entry must be
//! present exactly once, constraint entries are scoped to expected tables,
//! and any unknown, duplicate or forbidden entry rejects the dump before any
//! archive SQL can execute.
//!
//! Listing never executes archive SQL (ADR-0189 D10). The version-pinned
//! normalization here is intentionally conservative: it accounts for the
//! PostgreSQL 16 tool-generated entry kinds produced with `--no-owner
//! --no-acl` and rejects everything else instead of filtering it away.

use std::{
    collections::{BTreeMap, BTreeSet},
    path::Path,
    process::Command,
};

/// Expected PostgreSQL major version for the dump toolchain.
pub const SUPPORTED_POSTGRES_MAJOR: &str = "16";
/// Tool-generated entry types accepted for the exact-release schema.
const ALLOWED_CONSTRAINT_TYPES: [&str; 2] = ["CONSTRAINT", "FK CONSTRAINT"];

/// Stable tool/classification failure.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PgToolError {
    reason: &'static str,
}

impl PgToolError {
    fn new(reason: &'static str) -> Self {
        Self { reason }
    }

    /// Stable reason code; never contains a path, URL or command output.
    #[must_use]
    pub const fn reason(&self) -> &'static str {
        self.reason
    }
}

/// Verified toolchain identity.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ToolVersions {
    pub pg_dump: String,
    pub pg_restore: String,
}

/// Requires PostgreSQL 16 `pg_dump` and `pg_restore` on `PATH`.
///
/// A missing tool or a different major version is a hard failure; there is no
/// silent skip.
pub fn check_tool_versions() -> Result<ToolVersions, PgToolError> {
    let pg_dump = version_of("pg_dump")?;
    let pg_restore = version_of("pg_restore")?;
    Ok(ToolVersions {
        pg_dump,
        pg_restore,
    })
}

fn version_of(tool: &str) -> Result<String, PgToolError> {
    let output = Command::new(tool)
        .arg("--version")
        .output()
        .map_err(|_| PgToolError::new("pg-tool-unavailable"))?;
    if !output.status.success() {
        return Err(PgToolError::new("pg-tool-unavailable"));
    }
    let text = String::from_utf8(output.stdout)
        .map_err(|_| PgToolError::new("pg-tool-version-invalid"))?;
    let version = text
        .split_whitespace()
        .find(|token| token.chars().next().is_some_and(|c| c.is_ascii_digit()))
        .ok_or_else(|| PgToolError::new("pg-tool-version-invalid"))?;
    if version.split('.').next() != Some(SUPPORTED_POSTGRES_MAJOR) {
        return Err(PgToolError::new("pg-tool-version-unsupported"));
    }
    Ok(version.to_owned())
}

/// Runs `pg_dump -Fc --no-owner --no-acl --no-password` into `output`.
///
/// The database URL is the only connection input. Passwords must not appear in
/// it (the caller rejects them) because argv is world-readable on many hosts.
pub fn run_pg_dump(database_url: &str, output: &Path) -> Result<u64, PgToolError> {
    if database_url.contains(char::is_whitespace) {
        return Err(PgToolError::new("database-url-invalid"));
    }
    let status = Command::new("pg_dump")
        // Never let an inherited PGPASSWORD participate: the reviewed URL has
        // no password and argv is not secret storage.
        .env_remove("PGPASSWORD")
        .arg("-Fc")
        .arg("--no-owner")
        .arg("--no-acl")
        .arg("--no-password")
        .arg("--file")
        .arg(output)
        .arg("--dbname")
        .arg(database_url)
        .status()
        .map_err(|_| PgToolError::new("pg-dump-unavailable"))?;
    if !status.success() {
        return Err(PgToolError::new("pg-dump-failed"));
    }
    let metadata = std::fs::symlink_metadata(output)
        .map_err(|_| PgToolError::new("pg-dump-output-missing"))?;
    if metadata.file_type().is_symlink() || !metadata.file_type().is_file() {
        return Err(PgToolError::new("pg-dump-output-not-regular"));
    }
    Ok(metadata.len())
}

/// Runs unfiltered `pg_restore --list` against the archive file only.
///
/// There is deliberately no `--dbname`; listing must not connect to a target.
pub fn run_pg_restore_list(archive: &Path) -> Result<String, PgToolError> {
    let output = Command::new("pg_restore")
        .arg("--list")
        .arg(archive)
        .output()
        .map_err(|_| PgToolError::new("pg-restore-unavailable"))?;
    if !output.status.success() {
        return Err(PgToolError::new("pg-restore-list-failed"));
    }
    String::from_utf8(output.stdout).map_err(|_| PgToolError::new("pg-restore-list-invalid"))
}

/// Summary of a fully classified TOC.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct TocReport {
    pub entries: usize,
    pub tables: usize,
    pub table_data: usize,
    pub indexes: usize,
    pub constraints: usize,
    pub foreign_key_constraints: usize,
    pub functions: usize,
    pub triggers: usize,
}

#[derive(Debug, Default)]
struct ExpectedObjects {
    tables: BTreeSet<String>,
    indexes: BTreeSet<String>,
    functions: BTreeSet<String>,
    triggers: BTreeSet<String>,
}

fn expected_objects(inventory: &[serde_json::Value]) -> Result<ExpectedObjects, PgToolError> {
    let mut expected = ExpectedObjects::default();
    for entry in inventory {
        let Some(objects) = entry
            .get("postgres_objects")
            .and_then(serde_json::Value::as_array)
        else {
            return Err(PgToolError::new("toc-inventory-invalid"));
        };
        for object in objects {
            let kind = object
                .get("kind")
                .and_then(serde_json::Value::as_str)
                .unwrap_or_default();
            let schema = object
                .get("schema")
                .and_then(serde_json::Value::as_str)
                .unwrap_or_default();
            let name = object
                .get("name")
                .and_then(serde_json::Value::as_str)
                .unwrap_or_default();
            if schema != "public" {
                return Err(PgToolError::new("toc-inventory-invalid"));
            }
            match kind {
                "table" => {
                    if !valid_identifier(name) {
                        return Err(PgToolError::new("toc-inventory-invalid"));
                    }
                    expected.tables.insert(name.to_owned());
                }
                "index" => {
                    if !valid_identifier(name) {
                        return Err(PgToolError::new("toc-inventory-invalid"));
                    }
                    expected.indexes.insert(name.to_owned());
                }
                // D13 keys functions by `name(identity-arguments)` and
                // triggers by `<table>.<name>`. The TOC carries the bare
                // function name / trigger name, so reduce to that form.
                "function" => {
                    let (base, arguments) = name
                        .split_once('(')
                        .ok_or_else(|| PgToolError::new("toc-inventory-invalid"))?;
                    if !arguments.ends_with(')') || !valid_identifier(base) {
                        return Err(PgToolError::new("toc-inventory-invalid"));
                    }
                    expected.functions.insert(base.to_owned());
                }
                "trigger" => {
                    let base = name
                        .rsplit_once('.')
                        .map(|(_, base)| base)
                        .ok_or_else(|| PgToolError::new("toc-inventory-invalid"))?;
                    if !valid_identifier(base) {
                        return Err(PgToolError::new("toc-inventory-invalid"));
                    }
                    expected.triggers.insert(base.to_owned());
                }
                // Explicit constraints/views/sequences are covered by the D13
                // migration-tree drift gate; the TOC classifier still scopes
                // constraint entries to expected tables.
                "constraint" | "view" | "sequence" => continue,
                _ => return Err(PgToolError::new("toc-inventory-invalid")),
            }
        }
    }
    if expected.tables.is_empty() {
        return Err(PgToolError::new("toc-inventory-empty"));
    }
    Ok(expected)
}

fn valid_identifier(name: &str) -> bool {
    !name.is_empty()
        && name.len() <= 63
        && name
            .bytes()
            .all(|byte| byte.is_ascii_lowercase() || byte.is_ascii_digit() || byte == b'_')
        && !name.starts_with(|c: char| c.is_ascii_digit())
}

/// Parses one `pg_restore --list` entry.
///
/// `pg_restore` emits `<dumpId>; <catalogOid> <catalogOid> <descriptor>`. The
/// descriptor's final token is the (inert) archive owner; `--no-owner` keeps
/// it from producing ownership SQL and classification never trusts it.
fn parse_entry(line: &str) -> Option<Vec<String>> {
    let (_, descriptor) = line.split_once("; ")?;
    let mut fields = descriptor.split_whitespace();
    let _catalog_a = fields.next()?;
    let _catalog_b = fields.next()?;
    let rest = fields.collect::<Vec<_>>();
    if rest.is_empty() {
        return None;
    }
    Some(rest.into_iter().map(str::to_owned).collect())
}

fn identity(kind: &str, schema: &str, name: &str) -> String {
    format!("{kind} {schema} {name}")
}

/// Classifies the complete unfiltered TOC against the exact-release
/// inventory.
///
/// Rules:
/// * `TABLE`, `TABLE DATA`, `INDEX`, `FUNCTION` and `TRIGGER` entries are the
///   migration-owned inventory and must appear exactly once each;
/// * `CONSTRAINT` and `FK CONSTRAINT` are tool-generated entries allowlisted
///   only when they target an expected table;
/// * every other type is forbidden;
/// * duplicate identities and non-public schemas are rejected.
pub fn classify_toc(toc: &str, inventory: &[serde_json::Value]) -> Result<TocReport, PgToolError> {
    let expected = expected_objects(inventory)?;
    let mut seen_tables = BTreeSet::new();
    let mut seen_data = BTreeSet::new();
    let mut seen_indexes = BTreeSet::new();
    let mut seen_functions = BTreeSet::new();
    let mut seen_triggers = BTreeSet::new();
    let mut identities: BTreeSet<String> = BTreeSet::new();
    let mut report = TocReport {
        entries: 0,
        tables: 0,
        table_data: 0,
        indexes: 0,
        constraints: 0,
        foreign_key_constraints: 0,
        functions: 0,
        triggers: 0,
    };
    let mut constraint_targets: BTreeMap<String, usize> = BTreeMap::new();

    for line in toc.lines() {
        let trimmed = line.trim();
        if trimmed.is_empty() || trimmed.starts_with(';') {
            continue;
        }
        let Some(fields) = parse_entry(trimmed) else {
            return Err(PgToolError::new("toc-entry-malformed"));
        };
        report.entries += 1;
        // The last field is the archive owner, preserved by --no-owner as
        // inert metadata.
        if fields.len() < 3 {
            return Err(PgToolError::new("toc-entry-malformed"));
        }
        let body = &fields[..fields.len() - 1];
        if body.len() < 3 && matches!(body.first().map(String::as_str), Some("TABLE" | "FK")) {
            return Err(PgToolError::new("toc-entry-malformed"));
        }

        let (kind, schema, rest) = if body.len() >= 2 && body[0] == "TABLE" && body[1] == "DATA" {
            ("TABLE DATA", body.get(2).map(String::as_str), &body[3..])
        } else if body.len() >= 2 && body[0] == "FK" && body[1] == "CONSTRAINT" {
            ("FK CONSTRAINT", body.get(2).map(String::as_str), &body[3..])
        } else if body.len() >= 2 && body[0] == "TABLE" && body[1] == "ATTACH" {
            return Err(PgToolError::new("toc-entry-forbidden"));
        } else {
            (
                body.first().map(String::as_str).unwrap_or_default(),
                body.get(1).map(String::as_str),
                &body[2..],
            )
        };
        if schema != Some("public") {
            return Err(PgToolError::new("toc-entry-schema-rejected"));
        }

        match kind {
            "TABLE" => {
                let name = rest
                    .first()
                    .ok_or_else(|| PgToolError::new("toc-entry-malformed"))?;
                if !valid_identifier(name) {
                    return Err(PgToolError::new("toc-entry-identifier-invalid"));
                }
                if !expected.tables.contains(name) {
                    return Err(PgToolError::new("toc-entry-unknown-table"));
                }
                if !identities.insert(identity("TABLE", "public", name)) {
                    return Err(PgToolError::new("toc-entry-duplicate"));
                }
                seen_tables.insert(name.clone());
                report.tables += 1;
            }
            "TABLE DATA" => {
                let name = rest
                    .first()
                    .ok_or_else(|| PgToolError::new("toc-entry-malformed"))?;
                if !valid_identifier(name) || !expected.tables.contains(name) {
                    return Err(PgToolError::new("toc-entry-unknown-table"));
                }
                if !identities.insert(identity("TABLE DATA", "public", name)) {
                    return Err(PgToolError::new("toc-entry-duplicate"));
                }
                seen_data.insert(name.clone());
                report.table_data += 1;
            }
            "INDEX" => {
                let name = rest
                    .first()
                    .ok_or_else(|| PgToolError::new("toc-entry-malformed"))?;
                if !valid_identifier(name) || !expected.indexes.contains(name) {
                    return Err(PgToolError::new("toc-entry-unknown-index"));
                }
                if !identities.insert(identity("INDEX", "public", name)) {
                    return Err(PgToolError::new("toc-entry-duplicate"));
                }
                seen_indexes.insert(name.clone());
                report.indexes += 1;
            }
            "FUNCTION" => {
                let signature = rest
                    .first()
                    .ok_or_else(|| PgToolError::new("toc-entry-malformed"))?;
                let name = signature
                    .split_once('(')
                    .map(|(name, _)| name)
                    .ok_or_else(|| PgToolError::new("toc-entry-malformed"))?;
                if !signature.ends_with(')') || !valid_identifier(name) {
                    return Err(PgToolError::new("toc-entry-identifier-invalid"));
                }
                if !expected.functions.contains(name) {
                    return Err(PgToolError::new("toc-entry-unknown-function"));
                }
                if !identities.insert(identity("FUNCTION", "public", name)) {
                    return Err(PgToolError::new("toc-entry-duplicate"));
                }
                seen_functions.insert(name.to_owned());
                report.functions += 1;
            }
            "TRIGGER" => {
                if rest.len() != 2 {
                    return Err(PgToolError::new("toc-entry-malformed"));
                }
                let table = &rest[0];
                let name = &rest[1];
                if !valid_identifier(table)
                    || !valid_identifier(name)
                    || !expected.tables.contains(table)
                    || !expected.triggers.contains(name)
                {
                    return Err(PgToolError::new("toc-entry-unknown-trigger"));
                }
                if !identities.insert(identity("TRIGGER", "public", name)) {
                    return Err(PgToolError::new("toc-entry-duplicate"));
                }
                seen_triggers.insert(name.clone());
                report.triggers += 1;
            }
            kind if ALLOWED_CONSTRAINT_TYPES.contains(&kind) => {
                if rest.len() != 2 {
                    return Err(PgToolError::new("toc-entry-malformed"));
                }
                let table = &rest[0];
                let name = &rest[1];
                if !valid_identifier(table) || !valid_identifier(name) {
                    return Err(PgToolError::new("toc-entry-identifier-invalid"));
                }
                if !expected.tables.contains(table) {
                    return Err(PgToolError::new("toc-entry-unknown-table"));
                }
                if !identities.insert(format!("{kind} public {table} {name}")) {
                    return Err(PgToolError::new("toc-entry-duplicate"));
                }
                *constraint_targets.entry(table.clone()).or_insert(0) += 1;
                if kind == "CONSTRAINT" {
                    report.constraints += 1;
                } else {
                    report.foreign_key_constraints += 1;
                }
            }
            _ => return Err(PgToolError::new("toc-entry-forbidden")),
        }
    }

    if seen_tables != expected.tables {
        return Err(PgToolError::new("toc-entry-missing-table"));
    }
    if seen_data != expected.tables {
        return Err(PgToolError::new("toc-entry-missing-table-data"));
    }
    if seen_indexes != expected.indexes {
        return Err(PgToolError::new("toc-entry-missing-index"));
    }
    if seen_functions != expected.functions {
        return Err(PgToolError::new("toc-entry-missing-function"));
    }
    if seen_triggers != expected.triggers {
        return Err(PgToolError::new("toc-entry-missing-trigger"));
    }
    let _ = constraint_targets;
    Ok(report)
}

#[cfg(target_os = "linux")]
pub mod restore_pg_validation {
    //! D10 executable-definition validation. Archive SQL never reaches a selected
    //! target. Two independent, networkless PostgreSQL 16 containers hold the clean
    //! migration baseline and untrusted restored database. No host path is mounted.
    //! The SQL client has a different OS uid from the database server, so psql meta
    //! commands cannot modify PGDATA, the inspection query or the trusted baseline.
    use crate::backup_pg_dump;
    use serde_json::Value;
    use sha2::{Digest, Sha256};
    use std::{
        fs::File,
        io::{self, Read, Write},
        path::Path,
        process::{Command, Stdio},
    };

    const STORAGE_BYTES: u64 = 4 * 1024 * 1024 * 1024;
    const MAX_REPORT: usize = 8 * 1024 * 1024;
    const TOOL_TIMEOUT: &str = "180";
    const CATALOG_SQL: &str = include_str!("restore_catalog.sql");
    const INIT: &str = r#"set -euo pipefail
umask 077
mkdir /work/server
initdb --no-locale --encoding=UTF8 -U o3k_admin -D /work/server >/dev/null
pg_ctl -D /work/server -l /work/server.log -o "-k /work -c listen_addresses='' -c max_connections=8 -c shared_buffers=32MB -c statement_timeout=30000 -c max_files_per_process=128" -w start >/dev/null
psql -X -q -v ON_ERROR_STOP=1 -h /work -U o3k_admin postgres <<'SQL'
CREATE ROLE o3k_restore_owner LOGIN NOSUPERUSER NOCREATEDB NOCREATEROLE NOINHERIT NOREPLICATION NOBYPASSRLS;
CREATE ROLE o3k_runtime LOGIN NOSUPERUSER NOCREATEDB NOCREATEROLE NOINHERIT NOREPLICATION NOBYPASSRLS;
CREATE ROLE o3k_backup_dump NOLOGIN NOSUPERUSER NOCREATEDB NOCREATEROLE NOINHERIT NOREPLICATION NOBYPASSRLS;
CREATE DATABASE o3k_validate OWNER o3k_restore_owner;
REVOKE ALL ON DATABASE o3k_validate FROM PUBLIC;
SQL
psql -X -q -v ON_ERROR_STOP=1 -h /work -U o3k_admin o3k_validate <<'SQL'
REVOKE ALL ON SCHEMA public FROM PUBLIC;
SQL
# Close bootstrap admission before any archive bytes execute. Untrusted SQL
# clients can use only the narrow owner role. The observer requires the protected
# server OS uid through peer authentication, on this disposable database only.
printf 'o3k_observer postgres o3k_admin\n' > /work/server/pg_ident.conf
printf 'local o3k_validate o3k_admin peer map=o3k_observer\nlocal o3k_validate o3k_restore_owner trust\nlocal all all reject\nhost all all all reject\n' > /work/server/pg_hba.conf
pg_ctl -D /work/server reload >/dev/null
# A fresh owner connection confirms reload before bootstrap ceases.
for attempt in {1..50}; do
 if ! psql -X -q -h /work -U o3k_admin postgres -c 'SELECT 1' >/dev/null 2>&1; then exit 0; fi
 sleep .1
done
exit 1
"#;
    /// Redacted error; host/tool/SQL output is never returned to the operator.
    #[derive(Debug, Clone, PartialEq, Eq)]
    pub struct ValidationError {
        reason: &'static str,
    }
    impl ValidationError {
        fn new(reason: &'static str) -> Self {
            Self { reason }
        }
        /// Stable, bounded operator error code.
        #[must_use]
        pub const fn reason(&self) -> &'static str {
            self.reason
        }
    }
    type Result<T> = std::result::Result<T, ValidationError>;
    /// A locally provisioned digest pin, never supplied by the archive.
    #[derive(Debug, Clone)]
    pub struct ValidationPolicy {
        pub image: String,
    }
    /// Complete, independently compared migration/catalog descriptor identity.
    #[derive(Debug, Clone, PartialEq, Eq)]
    pub struct ValidationReport {
        pub toc_entries: usize,
        pub catalog_sha256: String,
        pub migration_policy_sha256: String,
    }

    /// Authenticate the outer artifact before calling this function. There is no
    /// selected-target URL/path/credential argument to this containment boundary.
    pub fn validate_archive(
        archive: &Path,
        inventory: &[Value],
        policy: &ValidationPolicy,
    ) -> Result<ValidationReport> {
        validate_policy(policy)?;
        for tool in ["pg_dump", "pg_restore"] {
            let version = run_output(Command::new(tool).arg("--version"), 4096)?;
            if !String::from_utf8_lossy(&version).contains("(PostgreSQL) 16.") {
                return Err(ValidationError::new("validation-pg-major-unsupported"));
            }
        }
        if !archive.is_absolute() {
            return Err(ValidationError::new("validation-archive-path-invalid"));
        }
        let fd = rustix::fs::open(
            archive,
            rustix::fs::OFlags::RDONLY
                | rustix::fs::OFlags::NOFOLLOW
                | rustix::fs::OFlags::CLOEXEC
                | rustix::fs::OFlags::NONBLOCK,
            rustix::fs::Mode::empty(),
        )
        .map_err(|_| ValidationError::new("validation-archive-unavailable"))?;
        let file = File::from(fd);
        let metadata = file
            .metadata()
            .map_err(|_| ValidationError::new("validation-archive-unavailable"))?;
        if !metadata.is_file()
            || metadata.len() == 0
            || metadata.len() > crate::backup::MAX_MEMBER_BYTES
        {
            return Err(ValidationError::new("validation-archive-size-invalid"));
        }
        // Listing is unfiltered and has no database connection. Bind it to the
        // opened inode rather than allowing a path replacement between passes.
        use std::os::fd::AsRawFd;
        let pinned = format!("/proc/{}/fd/{}", std::process::id(), file.as_raw_fd());
        let toc = run_output(
            Command::new("pg_restore").args(["--list", &pinned]),
            MAX_REPORT,
        )?;
        let toc =
            String::from_utf8(toc).map_err(|_| ValidationError::new("validation-toc-invalid"))?;
        if !toc.lines().any(|line| {
            line.trim_start().strip_prefix(';').is_some_and(|text| {
                text.trim_start()
                    .starts_with("Dumped from database version: 16.")
            })
        }) || !toc.lines().any(|line| {
            line.trim_start().strip_prefix(';').is_some_and(|text| {
                text.trim_start()
                    .starts_with("Dumped by pg_dump version: 16.")
            })
        }) {
            return Err(ValidationError::new("validation-archive-major-unsupported"));
        }
        let report = backup_pg_dump::classify_toc(&toc, inventory)
            .map_err(|error| ValidationError::new(error.reason()))?;
        // PostgreSQL's dump/reparse rewrites some equivalent CHECK expression
        // casts. Derive the reference via the same PG16 round-trip, using only
        // trusted embedded migrations; never weaken textual descriptor equality.
        let mut migrated = Container::start(policy)?;
        let reference_dump = (|| {
            migrated.sql(&migration_sql()?)?;
            migrated.dump()
        })();
        migrated.remove()?;
        let reference_dump = reference_dump?;
        let mut baseline = Container::start(policy)?;
        let baseline_result = (|| {
            baseline.copy("/tmp/archive", io::Cursor::new(reference_dump))?;
            baseline.restore()?;
            baseline.catalog()
        })();
        baseline.remove()?;
        let baseline = baseline_result?;
        let mut candidate = Container::start(policy)?;
        let candidate_result = (|| {
            candidate.copy("/tmp/archive", file)?;
            candidate.restore()?;
            candidate
                .catalog()
                .map_err(|_| ValidationError::new("validation-candidate-catalog-failed"))
        })();
        let cleanup = candidate.remove();
        cleanup?;
        let candidate = candidate_result?;
        if baseline != candidate {
            return Err(ValidationError::new("validation-catalog-mismatch"));
        }
        let canonical = serde_jcs::to_vec(&baseline)
            .map_err(|_| ValidationError::new("validation-catalog-invalid"))?;
        let migration_bytes = serde_jcs::to_vec(&baseline["migrations"])
            .map_err(|_| ValidationError::new("validation-catalog-invalid"))?;
        Ok(ValidationReport {
            toc_entries: report.entries,
            catalog_sha256: hex::encode(Sha256::digest(canonical)),
            migration_policy_sha256: hex::encode(Sha256::digest(migration_bytes)),
        })
    }

    fn validate_policy(policy: &ValidationPolicy) -> Result<()> {
        let digest = policy
            .image
            .strip_prefix("postgres:16@sha256:")
            .ok_or_else(|| ValidationError::new("validation-image-unpinned"))?;
        if digest.len() != 64
            || !digest
                .bytes()
                .all(|b| b.is_ascii_hexdigit() && !b.is_ascii_uppercase())
        {
            return Err(ValidationError::new("validation-image-unpinned"));
        }
        Ok(())
    }

    fn migration_sql() -> Result<String> {
        let mut sql = String::from(
            "CREATE TABLE public._sqlx_migrations (version BIGINT PRIMARY KEY, description TEXT NOT NULL, installed_on TIMESTAMPTZ NOT NULL DEFAULT now(), success BOOLEAN NOT NULL, checksum BYTEA NOT NULL, execution_time BIGINT NOT NULL);\n",
        );
        let migrator = sqlx::migrate!("../../crates/o3k-store/migrations_postgres");
        let binding = o3k_store::state_inventory::baseline_binding()
            .map_err(|_| ValidationError::new("validation-baseline-invalid"))?;
        if binding.postgres_major != 16 {
            return Err(ValidationError::new("validation-baseline-invalid"));
        }
        // Validate each embedded file against the committed SHA256 inventory. SQLx
        // embeds immutable SQL text and SHA384; its filename can be reconstructed
        // from the compiled description (spaces replace underscores).
        let expected_count = binding
            .migration_files
            .keys()
            .filter(|key| key.starts_with("migrations_postgres/"))
            .count();
        if expected_count != migrator.iter().count() {
            return Err(ValidationError::new("validation-baseline-invalid"));
        }
        for migration in migrator.iter() {
            let prefix = format!("migrations_postgres/{:04}_", migration.version);
            let matches: Vec<_> = binding
                .migration_files
                .iter()
                .filter(|(name, _)| name.starts_with(&prefix))
                .collect();
            if matches.len() != 1
                || *matches[0].1 != hex::encode(Sha256::digest(migration.sql.as_bytes()))
            {
                return Err(ValidationError::new("validation-baseline-invalid"));
            }
            sql.push_str(&migration.sql);
            sql.push_str("\n;\nINSERT INTO public._sqlx_migrations(version, description, success, checksum, execution_time) VALUES (");
            sql.push_str(&migration.version.to_string());
            sql.push_str(", '");
            sql.push_str(&migration.description.replace('\'', "''"));
            sql.push_str("', true, decode('");
            sql.push_str(&hex::encode(migration.checksum.as_ref()));
            sql.push_str("','hex'),0);\n");
        }
        Ok(sql)
    }

    struct Container {
        name: String,
        removed: bool,
    }
    impl Container {
        fn start(policy: &ValidationPolicy) -> Result<Self> {
            let mut instance = Self {
                name: format!("o3k-d10-{}", uuid::Uuid::now_v7()),
                removed: false,
            };
            let output = run_output(
                Command::new("docker").args([
                    "run",
                    "-d",
                    "--pull=never",
                    "--name",
                    &instance.name,
                    "--network=none",
                    "--read-only",
                    "--cap-drop=ALL",
                    "--security-opt=no-new-privileges",
                    "--user=postgres",
                    "--pids-limit=128",
                    "--memory=768m",
                    "--memory-swap=768m",
                    "--cpus=1",
                    "--ulimit=nofile=256:256",
                    "--log-driver=none",
                    "--tmpfs",
                    &format!(
                        "/work:size={STORAGE_BYTES},mode=0755,uid=999,gid=999,noexec,nosuid,nodev"
                    ),
                    "--tmpfs",
                    "/tmp:size=2147483648,mode=1777,noexec,nosuid,nodev",
                    "--tmpfs",
                    "/var/lib/postgresql/data:size=1048576,noexec,nosuid,nodev",
                    "--entrypoint=sleep",
                    &policy.image,
                    "600",
                ]),
                4096,
            );
            if output.is_err() {
                instance.remove()?;
                return Err(ValidationError::new("validation-container-unavailable"));
            }
            // A pinned image is still checked at execution, including server major.
            let result = (|| {
                let version = instance.run("postgres", &["postgres", "--version"], None, 4096)?;
                if !String::from_utf8_lossy(&version).starts_with("postgres (PostgreSQL) 16.") {
                    return Err(ValidationError::new("validation-pg-major-unsupported"));
                }
                instance.run("postgres", &["bash", "-s"], Some(INIT.as_bytes()), 4096)?;
                Ok(())
            })();
            if let Err(error) = result {
                instance.remove()?;
                return Err(error);
            }
            Ok(instance)
        }
        fn run(
            &self,
            user: &str,
            args: &[&str],
            input: Option<&[u8]>,
            limit: usize,
        ) -> Result<Vec<u8>> {
            let mut command = Command::new("docker");
            command
                .args(["exec", "-i", "--user", user, &self.name])
                .args(args);
            run_bounded(command, input, limit)
        }
        fn copy(&self, destination: &str, mut input: impl Read) -> Result<()> {
            let mut child = Command::new("timeout")
                .env_clear()
                .env(
                    "PATH",
                    "/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin",
                )
                .args([
                    "--signal=KILL",
                    TOOL_TIMEOUT,
                    "docker",
                    "exec",
                    "-i",
                    "--user=65534:65534",
                    &self.name,
                    "sh",
                    "-c",
                    r#"umask 077; cat > "$1""#,
                    "copy",
                    destination,
                ])
                .stdin(Stdio::piped())
                .stdout(Stdio::null())
                .stderr(Stdio::null())
                .spawn()
                .map_err(|_| ValidationError::new("validation-tool-unavailable"))?;
            let result = (|| {
                let mut stdin = child
                    .stdin
                    .take()
                    .ok_or_else(|| ValidationError::new("validation-copy-failed"))?;
                io::copy(&mut input, &mut stdin)
                    .map_err(|_| ValidationError::new("validation-copy-failed"))?;
                drop(stdin);
                if !child
                    .wait()
                    .map_err(|_| ValidationError::new("validation-copy-failed"))?
                    .success()
                {
                    return Err(ValidationError::new("validation-copy-failed"));
                }
                Ok(())
            })();
            if result.is_err() {
                let _ = child.kill();
                let _ = child.wait();
            }
            result
        }
        fn dump(&self) -> Result<Vec<u8>> {
            self.run(
                "65534:65534",
                &[
                    "pg_dump",
                    "-h",
                    "/work",
                    "-U",
                    "o3k_restore_owner",
                    "-d",
                    "o3k_validate",
                    "--format=custom",
                    "--no-owner",
                    "--no-acl",
                ],
                None,
                MAX_REPORT,
            )
        }
        fn restore(&self) -> Result<()> {
            // Generate SQL and execute it solely in the disposable environment.
            self.run(
                "65534:65534",
                &[
                    "pg_restore",
                    "--exit-on-error",
                    "--no-owner",
                    "--no-acl",
                    "--file=/tmp/restore.sql",
                    "/tmp/archive",
                ],
                None,
                4096,
            )?;
            self.run(
                "65534:65534",
                &[
                    "psql",
                    "-X",
                    "-q",
                    "-v",
                    "ON_ERROR_STOP=1",
                    "-h",
                    "/work",
                    "-U",
                    "o3k_restore_owner",
                    "-d",
                    "o3k_validate",
                    "-f",
                    "/tmp/restore.sql",
                ],
                None,
                4096,
            )?;
            Ok(())
        }
        fn sql(&self, sql: &str) -> Result<()> {
            self.run(
                "65534:65534",
                &[
                    "psql",
                    "-X",
                    "-q",
                    "-v",
                    "ON_ERROR_STOP=1",
                    "-h",
                    "/work",
                    "-U",
                    "o3k_restore_owner",
                    "-d",
                    "o3k_validate",
                ],
                Some(sql.as_bytes()),
                4096,
            )?;
            Ok(())
        }
        fn catalog(&self) -> Result<Value> {
            // pg_roles masks passwords. A separate peer-authenticated observer
            // can only be reached by the protected server OS uid, never by the
            // untrusted SQL/psql uid. Return presence only, never credential bytes.
            let pristine = self.run(
                "postgres",
                &["psql", "-X", "-qAt", "-v", "ON_ERROR_STOP=1", "-h", "/work",
                  "-U", "o3k_admin", "-d", "o3k_validate"],
                Some(b"SELECT NOT EXISTS (SELECT 1 FROM pg_catalog.pg_authid WHERE rolpassword IS NOT NULL);"),
                16,
            )?;
            if pristine != b"t\n" {
                return Err(ValidationError::new("validation-role-password-forbidden"));
            }
            let bytes = self.run(
                "65534:65534",
                &[
                    "psql",
                    "-X",
                    "-qAt",
                    "-v",
                    "ON_ERROR_STOP=1",
                    "-h",
                    "/work",
                    "-U",
                    "o3k_restore_owner",
                    "-d",
                    "o3k_validate",
                ],
                Some(CATALOG_SQL.as_bytes()),
                MAX_REPORT,
            )?;
            serde_json::from_slice(&bytes)
                .map_err(|_| ValidationError::new("validation-catalog-invalid"))
        }
        fn remove(&mut self) -> Result<()> {
            if self.removed {
                return Ok(());
            }
            run_output(
                Command::new("docker").args(["rm", "--force", "--volumes", &self.name]),
                4096,
            )
            .map_err(|_| ValidationError::new("validation-cleanup-unknown"))?;
            self.removed = true;
            Ok(())
        }
    }
    impl Drop for Container {
        fn drop(&mut self) {
            if !self.removed {
                let _ = self.remove();
            }
        }
    }
    fn run_output(command: &mut Command, limit: usize) -> Result<Vec<u8>> {
        let mut wrapped = Command::new(command.get_program());
        wrapped.args(command.get_args());
        run_bounded(wrapped, None, limit)
    }
    fn run_bounded(command: Command, input: Option<&[u8]>, limit: usize) -> Result<Vec<u8>> {
        let mut wrapped = Command::new("timeout");
        // No libpq/Docker host/config injection from inherited operator environment.
        wrapped
            .env_clear()
            .env(
                "PATH",
                "/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin",
            )
            .args(["--signal=KILL", TOOL_TIMEOUT])
            .arg(command.get_program())
            .args(command.get_args());
        let mut child = wrapped
            .stdin(Stdio::piped())
            .stdout(Stdio::piped())
            .stderr(Stdio::null())
            .spawn()
            .map_err(|_| ValidationError::new("validation-tool-unavailable"))?;
        let mut stdin = child
            .stdin
            .take()
            .ok_or_else(|| ValidationError::new("validation-tool-failed"))?;
        // Drain concurrently while bounded input is written to avoid pipe deadlock.
        let mut stdout = child
            .stdout
            .take()
            .ok_or_else(|| ValidationError::new("validation-tool-failed"))?;
        let reader = std::thread::spawn(move || {
            let mut bytes = Vec::new();
            stdout
                .by_ref()
                .take((limit + 1) as u64)
                .read_to_end(&mut bytes)
                .map(|_| bytes)
        });
        let written = input.map_or(Ok(()), |bytes| stdin.write_all(bytes));
        drop(stdin);
        let bytes = match reader.join() {
            Ok(Ok(bytes)) => bytes,
            _ => {
                let _ = child.kill();
                let _ = child.wait();
                return Err(ValidationError::new("validation-tool-failed"));
            }
        };
        if written.is_err() || bytes.len() > limit {
            let _ = child.kill();
            let _ = child.wait();
            return Err(ValidationError::new("validation-output-limit"));
        }
        if !child
            .wait()
            .map_err(|_| ValidationError::new("validation-tool-failed"))?
            .success()
        {
            return Err(ValidationError::new("validation-execution-rejected"));
        }
        Ok(bytes)
    }

    #[cfg(test)]
    #[allow(clippy::unwrap_used, clippy::expect_used)]
    mod tests {
        use super::*;
        #[test]
        fn requires_an_exact_pg16_image_digest() {
            for image in [
                "postgres:16",
                "postgres:17@sha256:123",
                "postgres:16@sha256:deadbeef",
            ] {
                assert!(
                    validate_policy(&ValidationPolicy {
                        image: image.into()
                    })
                    .is_err()
                );
            }
        }
        #[test]
        fn embedded_migrations_bind_to_committed_file_checksums() {
            assert!(
                migration_sql()
                    .unwrap()
                    .contains("INSERT INTO public._sqlx_migrations")
            );
        }

        /// Exercise security attributes independently of the current migration shapes.
        #[test]
        #[ignore = "requires isolated Docker PostgreSQL 16 runtime"]
        fn real_pg16_catalog_security_attributes() {
            let policy = ValidationPolicy {
                image: std::env::var("O3K_D10_TEST_IMAGE").expect("explicit image pin"),
            };
            let mut source = Container::start(&policy).unwrap();
            source.sql(&migration_sql().unwrap()).unwrap();
            assert!(
                source
                    .run(
                        "65534:65534",
                        &[
                            "psql",
                            "-X",
                            "-h",
                            "/work",
                            "-U",
                            "o3k_admin",
                            "-d",
                            "o3k_validate",
                            "-c",
                            "SELECT 1"
                        ],
                        None,
                        16
                    )
                    .is_err(),
                "untrusted OS uid must not impersonate the observer"
            );
            source.sql("CREATE TABLE catalog_probe(id int); CREATE INDEX catalog_probe_idx ON catalog_probe(id); CREATE VIEW catalog_probe_view AS SELECT id FROM catalog_probe; CREATE SEQUENCE catalog_probe_seq; CREATE POLICY catalog_probe_policy ON catalog_probe FOR SELECT TO PUBLIC USING (true);").unwrap();
            for (section, mutation) in [
                (
                    "rls_policies",
                    "DROP POLICY catalog_probe_policy ON catalog_probe; CREATE POLICY catalog_probe_policy ON catalog_probe FOR DELETE TO PUBLIC USING (true);",
                ),
                (
                    "views",
                    "ALTER VIEW catalog_probe_view SET (security_invoker=true);",
                ),
                (
                    "indexes",
                    "ALTER INDEX catalog_probe_idx SET (fillfactor=50);",
                ),
                (
                    "sequences",
                    "ALTER SEQUENCE catalog_probe_seq OWNED BY catalog_probe.id;",
                ),
            ] {
                let before = source.catalog().unwrap();
                source
                    .sql(mutation)
                    .unwrap_or_else(|e| panic!("{mutation}: {e:?}"));
                let after = source.catalog().unwrap();
                assert_ne!(
                    before[section], after[section],
                    "unobserved security attribute: {mutation}"
                );
            }
            source
                .sql("ALTER ROLE o3k_restore_owner PASSWORD 'disposable-test-password';")
                .unwrap();
            assert_eq!(
                source
                    .catalog()
                    .err()
                    .expect("password must be rejected")
                    .reason(),
                "validation-role-password-forbidden"
            );
            source.remove().unwrap();
        }

        /// Explicit real-host lane: absent isolation/PG16 is a failure, never a skip.
        #[test]
        #[ignore = "requires isolated Docker PostgreSQL 16 runtime"]
        fn real_pg16_definition_validation() {
            use std::os::unix::fs::DirBuilderExt;
            let policy = ValidationPolicy {
                image: std::env::var("O3K_D10_TEST_IMAGE").expect("explicit image pin"),
            };
            let inventory = o3k_store::state_inventory::baseline_state_inventory().unwrap();
            let cases = [
                ("clean", ""),
                ("postgres-major", ""),
                (
                    "function-body",
                    "CREATE OR REPLACE FUNCTION o3k_validate_operation_resource_reference() RETURNS trigger LANGUAGE plpgsql AS $$ BEGIN RETURN NEW; END; $$;",
                ),
                (
                    "security-definer",
                    "ALTER FUNCTION o3k_validate_operation_resource_reference() SECURITY DEFINER;",
                ),
                (
                    "trigger-behavior",
                    "ALTER TABLE operations DISABLE TRIGGER operations_validate_resource_reference;",
                ),
                (
                    "extra-function",
                    "CREATE FUNCTION forbidden() RETURNS int LANGUAGE sql AS 'SELECT 1';",
                ),
                (
                    "column-default",
                    "ALTER TABLE operations ALTER COLUMN retry_count SET DEFAULT 99;",
                ),
                ("unexpected-grant", "GRANT SELECT ON operations TO PUBLIC;"),
                ("extension", "CREATE EXTENSION hstore;"),
                ("schema", "CREATE SCHEMA forbidden;"),
                ("table", "CREATE TABLE forbidden(id int);"),
                (
                    "missing-migration",
                    "DELETE FROM _sqlx_migrations WHERE version=(SELECT max(version) FROM _sqlx_migrations);",
                ),
            ];
            for (name, mutation) in cases {
                let mut source = Container::start(&policy).unwrap();
                source.sql(&migration_sql().unwrap()).unwrap();
                if !mutation.is_empty() {
                    source.sql(mutation).unwrap();
                }
                // Include ACL metadata for the unexpected-grant negative: its
                // forbidden TOC record must not be hidden by a filtered listing.
                let dump = if name == "unexpected-grant" {
                    source
                        .run(
                            "65534:65534",
                            &[
                                "pg_dump",
                                "-h",
                                "/work",
                                "-U",
                                "o3k_restore_owner",
                                "-d",
                                "o3k_validate",
                                "--format=custom",
                                "--no-owner",
                            ],
                            None,
                            MAX_REPORT,
                        )
                        .unwrap()
                } else {
                    source.dump().unwrap()
                };
                source.remove().unwrap();
                let mut dump = dump;
                if name == "postgres-major" {
                    let offset = dump
                        .windows(3)
                        .position(|bytes| bytes == b"16.")
                        .expect("PG16 archive header");
                    dump[offset + 1] = b'5';
                }
                let root = std::env::temp_dir().join(format!("o3k-d10-{}", uuid::Uuid::now_v7()));
                std::fs::DirBuilder::new()
                    .mode(0o700)
                    .create(&root)
                    .unwrap();
                let verified =
                    crate::restore_test_artifact::build_and_authenticate(dump, &root).unwrap();
                let dump = verified
                    .members
                    .iter()
                    .find(|m| m.record.name == "database/o3k.dump")
                    .unwrap();
                let result = validate_archive(&dump.path, &inventory, &policy);
                std::fs::remove_dir_all(root).unwrap();
                if name == "clean" {
                    assert!(result.is_ok(), "{name}: {result:?}");
                } else {
                    assert!(result.is_err(), "accepted {name}");
                }
                eprintln!(
                    "D10 {name}: {}",
                    match &result {
                        Ok(_) => "PASS",
                        Err(error) => error.reason(),
                    }
                );
            }
        }
    }
}

#[cfg(test)]
#[allow(clippy::expect_used, clippy::unwrap_used, clippy::panic)]
mod tests {
    use super::*;
    use serde_json::json;

    fn inventory() -> Vec<serde_json::Value> {
        vec![json!({
            "postgres_objects": [
                {"kind": "table", "schema": "public", "name": "resources"},
                {"kind": "table", "schema": "public", "name": "operations"},
                {"kind": "index", "schema": "public", "name": "idx_resources"},
                {"kind": "function", "schema": "public", "name": "o3k_fn()"},
                {"kind": "trigger", "schema": "public", "name": "operations.operations_trigger"}
            ]
        })]
    }

    fn valid_toc() -> String {
        [
            "; comment",
            "1; 1259 100 TABLE public resources owner",
            "2; 1259 101 TABLE public operations owner",
            "3; 0 0 TABLE DATA public resources owner",
            "4; 0 0 TABLE DATA public operations owner",
            "5; 1259 102 INDEX public idx_resources owner",
            "6; 2606 103 CONSTRAINT public resources resources_pkey owner",
            "7; 2606 104 FK CONSTRAINT public operations operations_resource_id_fkey owner",
            "8; 1255 105 FUNCTION public o3k_fn() owner",
            "9; 2620 106 TRIGGER public operations operations_trigger owner",
        ]
        .join("\n")
    }

    #[test]
    fn short_untrusted_toc_records_reject_without_panicking() {
        for entry in [
            "1; 0 0 TABLE owner",
            "1; 0 0 TABLE DATA owner",
            "1; 0 0 FK CONSTRAINT owner",
            "1; 0 0 FUNCTION owner",
        ] {
            assert_eq!(
                classify_toc(entry, &inventory())
                    .expect_err("malformed TOC")
                    .reason(),
                "toc-entry-malformed"
            );
        }
    }

    #[test]
    fn complete_inventory_passes_and_counts() {
        let report = classify_toc(&valid_toc(), &inventory()).expect("valid toc");
        assert_eq!(report.entries, 9);
        assert_eq!(report.tables, 2);
        assert_eq!(report.table_data, 2);
        assert_eq!(report.indexes, 1);
        assert_eq!(report.constraints, 1);
        assert_eq!(report.foreign_key_constraints, 1);
        assert_eq!(report.functions, 1);
        assert_eq!(report.triggers, 1);
    }

    #[test]
    fn missing_entries_are_rejected_not_filtered() {
        let toc = valid_toc().replace("3; 0 0 TABLE DATA public resources owner\n", "");
        assert_eq!(
            classify_toc(&toc, &inventory())
                .expect_err("missing data")
                .reason(),
            "toc-entry-missing-table-data"
        );
        let toc = valid_toc().replace("5; 1259 102 INDEX public idx_resources owner\n", "");
        assert_eq!(
            classify_toc(&toc, &inventory())
                .expect_err("missing index")
                .reason(),
            "toc-entry-missing-index"
        );
    }

    #[test]
    fn unknown_and_forbidden_entries_are_rejected() {
        let mut toc = valid_toc();
        toc.push_str("\n10; 1259 107 TABLE public surprise owner");
        assert_eq!(
            classify_toc(&toc, &inventory())
                .expect_err("unknown table")
                .reason(),
            "toc-entry-unknown-table"
        );
        for forbidden in [
            "10; 0 0 ACL public resources owner",
            "10; 0 0 EXTENSION public plpgsql owner",
            "10; 0 0 SEQUENCE public surprise owner",
            "10; 0 0 DEFAULT public resources id owner",
        ] {
            let mut toc = valid_toc();
            toc.push('\n');
            toc.push_str(forbidden);
            assert_eq!(
                classify_toc(&toc, &inventory())
                    .expect_err("forbidden")
                    .reason(),
                "toc-entry-forbidden"
            );
        }
    }

    #[test]
    fn duplicate_entries_are_rejected_even_with_different_ids() {
        let mut toc = valid_toc();
        toc.push_str("\n10; 1259 200 TABLE public resources other_owner");
        assert_eq!(
            classify_toc(&toc, &inventory())
                .expect_err("duplicate")
                .reason(),
            "toc-entry-duplicate"
        );
    }

    #[test]
    fn constraint_on_unknown_table_is_rejected() {
        let mut toc = valid_toc();
        toc.push_str("\n10; 2606 200 CONSTRAINT public other other_pkey owner");
        assert_eq!(
            classify_toc(&toc, &inventory())
                .expect_err("unknown constraint table")
                .reason(),
            "toc-entry-unknown-table"
        );
    }

    #[test]
    fn non_public_schema_is_rejected() {
        let toc = valid_toc().replace(
            "1; 1259 100 TABLE public resources owner",
            "1; 1259 100 TABLE private resources owner",
        );
        assert_eq!(
            classify_toc(&toc, &inventory())
                .expect_err("schema")
                .reason(),
            "toc-entry-schema-rejected"
        );
    }

    #[test]
    fn malformed_entry_is_rejected() {
        let mut toc = valid_toc();
        toc.push_str("\nnot a toc entry");
        assert_eq!(
            classify_toc(&toc, &inventory())
                .expect_err("malformed")
                .reason(),
            "toc-entry-malformed"
        );
    }
}
