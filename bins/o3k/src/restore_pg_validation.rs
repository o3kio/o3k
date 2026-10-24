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
# Close bootstrap admission before any archive bytes execute. Only the narrow
# owner role is admitted, on one local socket, to one disposable database.
printf 'local o3k_validate o3k_restore_owner trust\nlocal all all reject\nhost all all all reject\n' > /work/server/pg_hba.conf
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
    let toc = String::from_utf8(toc).map_err(|_| ValidationError::new("validation-toc-invalid"))?;
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
            let _ = instance.remove();
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
    let bytes = reader
        .join()
        .map_err(|_| ValidationError::new("validation-tool-failed"))?
        .map_err(|_| ValidationError::new("validation-tool-failed"))?;
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
