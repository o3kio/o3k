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

// Test-only crash hooks may never ship in an optimized build: they force
// hard process exits from production code paths.
#[cfg(all(feature = "backup-test-hooks", not(debug_assertions)))]
compile_error!("backup-test-hooks is a debug-only test feature");

// Artifact format primitives (manifest contract, member encryption, streaming
// verify, offline signing input). Kept crate-private: the operator journey goes
// through `backup_create` and `backup_artifact`, and a PP.6 backup claim still
// requires protected-test and human exact-head review evidence.
#[allow(dead_code)]
pub(crate) mod backup;
// PP.6 backup artifact driver (SPEC-0050 §8, ADR-0189): assembles the
// encrypted artifact manifest from a quiesced snapshot, drives the accepted
// offline two-phase signing flow, and publishes by linking the verified
// inode with no replace. Linux-only like the handoff primitives in o3k-store.
#[cfg(target_os = "linux")]
pub mod backup_artifact;
// PP.6 backup capture executor (SPEC-0050 §8, ADR-0189): drives the
// authenticated store-lock handoff, captures the snapshot, and hands it to
// `backup_artifact`. Linux-only like the handoff primitives in o3k-store.
#[cfg(target_os = "linux")]
pub mod backup_create;
// PP.6 PostgreSQL capture orchestration (D4 barrier + D10 dump classification).
// Linux-only like the handoff primitives in o3k-store.
#[cfg(target_os = "linux")]
pub mod backup_pg;
// PP.6 PostgreSQL `pg_dump`/`pg_restore --list` argv-only host boundary. This
// is a narrowly approved execution adapter; it never uses a shell.
#[cfg(target_os = "linux")]
pub mod backup_pg_dump;
// Shared `o3k backup` data-directory resolution (packaged `/var/lib/o3k`,
// `O3K_DATA_DIR`, `/etc/o3k/o3kd.env`). Linux-only like the backup commands.
#[cfg(target_os = "linux")]
pub mod backup_data_dir;
// Root-owned installation trust/key configuration and the D9 staging
// reservation bound for the authenticated backup artifact (SPEC-0050 §8,
// ADR-0189). Trust loading derives the canonical identity from o3k-store and
// uses Linux no-follow file primitives; the reservation keeps a POSIX statvfs
// preflight and enforces the remaining reservation with a non-sparse hold file
// allocated through `fallocate(2)`.
#[cfg(unix)]
pub mod backup_reservation;
#[cfg(target_os = "linux")]
pub mod backup_trust;
#[cfg(target_os = "linux")]
pub mod backup_verify;
pub mod checks;
pub mod context;
pub mod db;
pub mod engine;
pub mod native_cli;
pub mod output;
#[cfg(target_os = "linux")]
pub use backup_pg_dump::restore_pg_validation;
#[cfg(target_os = "linux")]
pub mod recovery_files;
#[cfg(target_os = "linux")]
pub mod recovery_identity;
#[cfg(target_os = "linux")]
pub mod recovery_installation;
#[cfg(target_os = "linux")]
pub mod recovery_migration_publisher;
#[cfg(target_os = "linux")]
pub mod recovery_migration_selector;
#[cfg(target_os = "linux")]
pub mod recovery_prepare;
#[cfg(target_os = "linux")]
pub mod recovery_provision;
#[cfg(target_os = "linux")]
pub mod recovery_reanchor;
#[cfg(target_os = "linux")]
pub mod recovery_trust;
#[cfg(target_os = "linux")]
pub mod recovery_trust_update;
#[cfg(target_os = "linux")]
pub mod restore_fence;
#[cfg(target_os = "linux")]
pub mod restore_journal;
#[cfg(target_os = "linux")]
pub mod restore_preflight;
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

#[cfg(all(test, target_os = "linux"))]
mod restore_test_artifact;
