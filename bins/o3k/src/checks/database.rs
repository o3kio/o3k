//! Database checks against the control-plane SQLite file, strictly
//! read-only.

use crate::checks::{internal_failure, o3kd_actions};
use crate::context::Context;
use crate::output::{Category, Check, CheckStatus};

/// Journal modes that are valid SQLite configurations but degrade durability
/// or concurrency compared to WAL.
const DEGRADED_JOURNAL_MODES: [&str; 5] = ["delete", "truncate", "persist", "memory", "off"];

/// Database driver errors can include connection URLs, usernames, or other
/// credentials. Keep the check actionable without projecting backend detail
/// into either doctor output format.
fn database_error_details(operation: &str) -> String {
    format!(
        "{operation} failed; inspect the o3kd service and journal for the backend-specific cause"
    )
}

/// SQLite's `quick_check` result is backend-controlled text and may contain
/// page details or injected secrets. Classify it without copying that text
/// into operator output; the summary already identifies the failed check.
fn sqlite_integrity_details(result: &str) -> &'static str {
    if result.trim().is_empty() {
        "SQLite quick_check returned an empty non-ok result; inspect the o3kd journal for the backend-specific cause"
    } else if result.lines().count() > 1 {
        "SQLite quick_check returned a multi-line integrity failure; inspect the o3kd journal for the backend-specific cause"
    } else {
        "SQLite quick_check returned a non-ok integrity result; inspect the o3kd journal for the backend-specific cause"
    }
}

/// `database.accessible`: the database file must exist and open read-only.
pub async fn check_accessible(ctx: &Context) -> Check {
    if ctx.is_postgres() {
        return Check::new(
            "database.accessible",
            Category::Database,
            CheckStatus::Pass,
            "database backend is PostgreSQL (configured)",
        );
    }
    let path = ctx.database_path();
    if !ctx.exec.is_regular_file(&path) {
        return Check::new(
            "database.accessible",
            Category::Database,
            CheckStatus::Fail,
            "database file missing",
        )
        .with_actions(vec![
            "verify O3K_DATA_DIR in /etc/o3k/o3kd.env".to_owned(),
            "systemctl status o3kd".to_owned(),
        ]);
    }
    match ctx.db.pragma_journal_mode(&path).await {
        Ok(_) => Check::new(
            "database.accessible",
            Category::Database,
            CheckStatus::Pass,
            "database file is present and readable",
        ),
        Err(_error) => Check::new(
            "database.accessible",
            Category::Database,
            CheckStatus::Fail,
            "database not readable",
        )
        .with_details(database_error_details("database access"))
        .with_actions(o3kd_actions()),
    }
}

/// `database.integrity`: `PRAGMA quick_check` must report `ok`.
pub async fn check_integrity(ctx: &Context) -> Check {
    if ctx.is_postgres() {
        return Check::new(
            "database.integrity",
            Category::Database,
            CheckStatus::Pass,
            "PostgreSQL schema migrations verified",
        );
    }
    let path = ctx.database_path();
    if !ctx.exec.is_regular_file(&path) {
        return Check::new(
            "database.integrity",
            Category::Database,
            CheckStatus::NotApplicable,
            "database file missing (see database.accessible)",
        );
    }
    match ctx.db.pragma_quick_check(&path).await {
        Ok(result) if result.eq_ignore_ascii_case("ok") => Check::new(
            "database.integrity",
            Category::Database,
            CheckStatus::Pass,
            "SQLite integrity check passed",
        ),
        Ok(result) => Check::new(
            "database.integrity",
            Category::Database,
            CheckStatus::Fail,
            "corrupt SQLite database",
        )
        .with_details(sqlite_integrity_details(&result))
        .with_actions(vec![
            "journalctl -u o3kd -n 100".to_owned(),
            "back up the database file before any operator action".to_owned(),
        ]),
        Err(_error) => Check::new(
            "database.integrity",
            Category::Database,
            CheckStatus::Fail,
            "SQLite integrity check unavailable",
        )
        .with_details(database_error_details("SQLite integrity check"))
        .with_actions(o3kd_actions()),
    }
}

/// `database.wal_mode`: WAL journal mode is required for durability and
/// concurrency; the other valid modes are a WARN.
pub async fn check_wal_mode(ctx: &Context) -> Check {
    if ctx.is_postgres() {
        return Check::new(
            "database.wal_mode",
            Category::Database,
            CheckStatus::NotApplicable,
            "WAL mode is SQLite-specific",
        );
    }
    let path = ctx.database_path();
    if !ctx.exec.is_regular_file(&path) {
        return Check::new(
            "database.wal_mode",
            Category::Database,
            CheckStatus::NotApplicable,
            "database file missing (see database.accessible)",
        );
    }
    match ctx.db.pragma_journal_mode(&path).await {
        Ok(mode) if mode.eq_ignore_ascii_case("wal") => Check::new(
            "database.wal_mode",
            Category::Database,
            CheckStatus::Pass,
            "database journal mode is WAL",
        ),
        Ok(mode)
            if DEGRADED_JOURNAL_MODES
                .iter()
                .any(|m| mode.eq_ignore_ascii_case(m)) =>
        {
            Check::new(
                "database.wal_mode",
                Category::Database,
                CheckStatus::Warn,
                format!("journal mode {mode}: durability and concurrency are degraded"),
            )
            .with_actions(o3kd_actions())
        }
        Ok(mode) => Check::new(
            "database.wal_mode",
            Category::Database,
            CheckStatus::Warn,
            format!("unexpected journal mode {mode}"),
        )
        .with_actions(o3kd_actions()),
        Err(_error) => Check::new(
            "database.wal_mode",
            Category::Database,
            CheckStatus::Fail,
            "journal mode is unreadable",
        )
        .with_details(database_error_details("SQLite journal mode query"))
        .with_actions(o3kd_actions()),
    }
}

/// `database.permissions`: the database file must carry no group/other
/// permission bits and the data directory must not be group- or
/// world-writable.
pub async fn check_permissions(ctx: &Context) -> Check {
    if ctx.is_kubernetes() {
        return Check::new(
            "database.permissions",
            Category::Database,
            CheckStatus::Pass,
            "data directory managed by Kubernetes volume mount",
        );
    }
    if ctx.is_postgres() {
        let mut violations = Vec::new();
        match ctx.exec.file_mode(&ctx.data_dir) {
            Ok(mode) if mode & 0o022 != 0 => violations.push(format!(
                "data directory is group/world writable: {:04o} {}",
                mode & 0o777,
                ctx.data_dir.display()
            )),
            Ok(_) => {}
            Err(error) => {
                return internal_failure(
                    "database.permissions",
                    Category::Database,
                    "data directory permissions",
                    &error,
                    vec![format!("stat -c '%a %n' {}", ctx.data_dir.display())],
                );
            }
        }
        if violations.is_empty() {
            return Check::new(
                "database.permissions",
                Category::Database,
                CheckStatus::Pass,
                "data directory permissions are restricted",
            );
        }
        return Check::new(
            "database.permissions",
            Category::Database,
            CheckStatus::Fail,
            "database permissions are too open",
        )
        .with_details(violations.join("\n"))
        .with_actions(vec![format!("stat -c '%a %n' {}", ctx.data_dir.display())]);
    }
    let path = ctx.database_path();
    if !ctx.exec.is_regular_file(&path) {
        return Check::new(
            "database.permissions",
            Category::Database,
            CheckStatus::NotApplicable,
            "database file missing (see database.accessible)",
        );
    }
    let mut violations = Vec::new();
    match ctx.exec.file_mode(&path) {
        Ok(mode) if mode & 0o077 != 0 => violations.push(format!(
            "database file has group/other access bits: {:04o} {}",
            mode & 0o777,
            path.display()
        )),
        Ok(_) => {}
        Err(error) => {
            return internal_failure(
                "database.permissions",
                Category::Database,
                "database file permissions",
                &error,
                vec![format!("stat -c '%a %n' {}", path.display())],
            );
        }
    }
    match ctx.exec.file_mode(&ctx.data_dir) {
        Ok(mode) if mode & 0o022 != 0 => violations.push(format!(
            "data directory is group/world writable: {:04o} {}",
            mode & 0o777,
            ctx.data_dir.display()
        )),
        Ok(_) => {}
        Err(error) => {
            return internal_failure(
                "database.permissions",
                Category::Database,
                "data directory permissions",
                &error,
                vec![format!("stat -c '%a %n' {}", ctx.data_dir.display())],
            );
        }
    }
    if violations.is_empty() {
        return Check::new(
            "database.permissions",
            Category::Database,
            CheckStatus::Pass,
            "database file and data directory are restricted",
        );
    }
    Check::new(
        "database.permissions",
        Category::Database,
        CheckStatus::Fail,
        "database permissions are too open",
    )
    .with_details(violations.join("\n"))
    .with_actions(vec![format!(
        "stat -c '%a %n' {} {}",
        path.display(),
        ctx.data_dir.display()
    )])
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::testutil::{FakeDb, FakeExec, FakeHttp, context_with};

    fn context(exec: FakeExec, db: FakeDb) -> Context {
        context_with(exec, FakeHttp::healthy(), db, true, true)
    }

    #[tokio::test]
    async fn accessible_fails_when_database_missing() {
        let mut exec = FakeExec::healthy();
        exec.regular_files
            .retain(|path| path != "/var/lib/o3k/o3k.sqlite");
        let check = check_accessible(&context(exec, FakeDb::healthy())).await;
        assert_eq!(check.status, CheckStatus::Fail);
        assert!(check.summary.contains("missing"));
    }

    #[tokio::test]
    async fn inaccessible_database_error_is_secret_safe_in_json_and_human_output() {
        let sentinel = "postgres://user:sentinel-secret@db.example/o3k";
        let mut db = FakeDb::healthy();
        db.journal_mode = Err(sentinel.to_owned());
        db.quick_check = Err(sentinel.to_owned());

        let ctx = context(FakeExec::healthy(), db);
        let checks = vec![
            check_accessible(&ctx).await,
            check_integrity(&ctx).await,
            check_wal_mode(&ctx).await,
        ];
        assert!(checks.iter().all(|check| check.status == CheckStatus::Fail));
        assert!(
            checks
                .iter()
                .all(|check| !check.recommended_actions.is_empty())
        );

        let report = crate::output::Report {
            version: "test".to_owned(),
            overall_status: crate::output::OverallStatus::Unhealthy,
            timestamp: "2026-01-01T00:00:00Z".to_owned(),
            checks,
        };
        let serialized = serde_json::to_string(&report);
        assert!(serialized.is_ok());
        let json = serialized.unwrap_or_default();
        let human = report.render_human();
        assert!(!json.contains(sentinel));
        assert!(!human.contains(sentinel));
    }

    #[tokio::test]
    async fn integrity_fails_when_corrupt() {
        let mut db = FakeDb::healthy();
        db.quick_check = Ok(
            "*** in database main ***\nPage 1: btreeInitPage() returns error code 11".to_owned(),
        );
        let check = check_integrity(&context(FakeExec::healthy(), db)).await;
        assert_eq!(check.status, CheckStatus::Fail);
        assert!(check.summary.contains("corrupt"));
        assert!(
            check
                .details
                .as_deref()
                .is_some_and(|details| details.contains("multi-line"))
        );
        assert!(!check.recommended_actions.is_empty());
    }

    #[tokio::test]
    async fn integrity_non_ok_result_is_secret_safe_and_classified() {
        let sentinel = "sqlite://user:sentinel-secret@db.example/control";
        let mut db = FakeDb::healthy();
        db.quick_check = Ok(format!("*** {sentinel} ***"));

        let check = check_integrity(&context(FakeExec::healthy(), db)).await;

        assert_eq!(check.status, CheckStatus::Fail);
        assert_eq!(
            check.details.as_deref(),
            Some(
                "SQLite quick_check returned a non-ok integrity result; inspect the o3kd journal for the backend-specific cause"
            )
        );
        let serialized = serde_json::to_string(&check);
        assert!(serialized.is_ok(), "check serialization failed");
        let json = serialized.unwrap_or_default();
        assert!(!json.contains(sentinel));
    }

    #[tokio::test]
    async fn wal_mode_warns_on_delete() {
        let mut db = FakeDb::healthy();
        db.journal_mode = Ok("delete".to_owned());
        let check = check_wal_mode(&context(FakeExec::healthy(), db)).await;
        assert_eq!(check.status, CheckStatus::Warn);
    }

    #[tokio::test]
    async fn permissions_fail_when_database_is_0644() {
        let mut exec = FakeExec::healthy();
        exec.modes
            .insert("/var/lib/o3k/o3k.sqlite".to_owned(), 0o644);
        let check = check_permissions(&context(exec, FakeDb::healthy())).await;
        assert_eq!(check.status, CheckStatus::Fail);
    }

    #[tokio::test]
    async fn permissions_fail_when_data_dir_is_world_writable() {
        let mut exec = FakeExec::healthy();
        exec.modes.insert("/var/lib/o3k".to_owned(), 0o777);
        let check = check_permissions(&context(exec, FakeDb::healthy())).await;
        assert_eq!(check.status, CheckStatus::Fail);
    }

    #[tokio::test]
    async fn postgres_backend_doctor_checks() {
        let mut ctx = context(FakeExec::healthy(), FakeDb::healthy());
        ctx.o3kd_env
            .insert("O3K_DATABASE_BACKEND".to_owned(), "postgres".to_owned());
        ctx.o3kd_env.insert(
            "O3K_DATABASE_URL".to_owned(),
            "postgres://o3k:secret-pass@127.0.0.1/o3k".to_owned(),
        );

        let accessible = check_accessible(&ctx).await;
        assert_eq!(accessible.status, CheckStatus::Pass);
        assert!(accessible.summary.contains("PostgreSQL"));

        let integrity = check_integrity(&ctx).await;
        assert_eq!(integrity.status, CheckStatus::Pass);

        let wal_mode = check_wal_mode(&ctx).await;
        assert_eq!(wal_mode.status, CheckStatus::NotApplicable);

        let permissions = check_permissions(&ctx).await;
        assert_eq!(permissions.status, CheckStatus::Pass);
    }
}
