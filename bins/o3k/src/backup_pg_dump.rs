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
            if schema != "public" || !valid_identifier(name) {
                return Err(PgToolError::new("toc-inventory-invalid"));
            }
            match kind {
                "table" => {
                    expected.tables.insert(name.to_owned());
                }
                "index" => {
                    expected.indexes.insert(name.to_owned());
                }
                "function" => {
                    expected.functions.insert(name.to_owned());
                }
                "trigger" => {
                    expected.triggers.insert(name.to_owned());
                }
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
        if fields.len() < 2 {
            return Err(PgToolError::new("toc-entry-malformed"));
        }
        let body = &fields[..fields.len() - 1];

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
                {"kind": "function", "schema": "public", "name": "o3k_fn"},
                {"kind": "trigger", "schema": "public", "name": "operations_trigger"}
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
