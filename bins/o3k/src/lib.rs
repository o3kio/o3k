//! O3K operator CLI library.
//!
//! The `o3k` binary is the O3K operator command-line tool: `o3k doctor`
//! (strictly read-only, secret-safe diagnostics of a TestLab installation,
//! issue #617), `o3k upgrade` / `o3k rollback` (installation lifecycle
//! orchestration, issue #626), and `o3k version`.
//!
//! Design authorities: `docs/plan/o3k-doctor.md` and
//! `docs/plan/o3k-upgrade.md`; machine output contracts:
//! `contracts/o3k-doctor-output.schema.json` and the upgrade JSON field
//! list in `docs/plan/o3k-upgrade.md` §1. Doctor never mutates host state;
//! the upgrade engine mutates only through the bounded [`upgrade::UpgradeIo`]
//! seam and its durable state file.

// This contract-checked prerequisite is intentionally not wired into a
// supported operator journey yet. Keep it private until capture coordination,
// trust lifecycle, and replay/crash recovery are implemented.
#[allow(dead_code)]
pub(crate) mod backup;
pub mod checks;
pub mod context;
pub mod db;
pub mod engine;
pub mod native_cli;
pub mod output;
pub mod sys;
#[cfg(test)]
pub mod testutil;
pub mod upgrade;
pub mod version;

pub use context::{Context, DoctorDb, Exec, HttpClient, HttpResponse, UnitState};
pub use db::SqlxDoctorDb;
pub use engine::{overall_status, run_all};
pub use output::{
    Category, Check, CheckStatus, OverallStatus, Report, now_utc_rfc3339, rfc3339_from_epoch_secs,
};
pub use sys::{SystemExec, SystemHttpClient};
pub use version::ReleaseVersion;

/// Usage text for the CLI root.
pub const USAGE: &str = "\
o3k — O3K operator CLI

Usage:
  o3k doctor            run read-only installation diagnostics
  o3k doctor --json     machine-readable diagnostics (JSON on stdout)
  o3k version           print the binary and installed release versions
  sudo o3k upgrade [--to vX.Y.Z] [--check] [--yes] [--json]
                        upgrade the installation to a newer release
  sudo o3k rollback [--yes] [--json]
                        restore the previous release from the latest backup
  o3k --version         print the version and exit
  o3k --help            print this help and exit

Commands:
  doctor                diagnose the local O3K installation (read-only)
  version               print the binary version and the installed release
  upgrade               upgrade to a newer official release; --check runs
                        the read-only preflight only (no download, no
                        mutation); --json emits the machine-readable result
  rollback              restore the previous release from the most recent
                        eligible O3K backup; --json emits the result

Exit codes:
  0                     diagnostics healthy, upgrade committed, check
                        passed, rollback completed, version printed
  1                     diagnostics warning/unhealthy, upgrade/rollback
                        failed or blocked (including preflight)
  2                     usage error";
