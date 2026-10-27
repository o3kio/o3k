//! Upgrade/rollback state machine driver (plan §8–§10).
//!
//! `run_upgrade` walks the 12 upgrade phases with the per-phase failure
//! policy from plan §9; `run_rollback` restores the immediately previous
//! eligible backup. The engine itself performs no host I/O beyond the
//! durable state file, the rollback chain, and the [`UpgradeIo`] seam, so
//! every path is deterministically testable.
//!
//! Resumption rule: the persisted state is reloaded on every invocation.
//! A recorded phase of `BACKUP_CREATED` or later (with a valid backup)
//! resumes from that phase; anything earlier is discarded and the attempt
//! restarts (no mutation has happened yet). A terminal `FAILED_UPGRADE` or
//! `ROLLED_BACK` state refuses a new upgrade with recovery instructions.
//! File timestamps are never consulted.

use crate::upgrade::backup::{BackupManifest, RecordKind, RollbackChain, RollbackRecord};
use crate::upgrade::fence::UpgradeFence;
use crate::upgrade::output::UpgradeStatus;
use crate::upgrade::state::{UpgradePhase, UpgradeState, default_state_path};
use crate::version::ReleaseVersion;
use async_trait::async_trait;
use std::path::PathBuf;

/// The installed release read from `share/o3k/release-manifest.json`.
#[derive(Debug, Clone)]
pub struct InstalledRelease {
    pub version: ReleaseVersion,
    pub commit: Option<String>,
    pub profile: String,
}

/// A downloaded and verified release bundle.
#[derive(Debug, Clone)]
pub struct VerifiedBundle {
    pub version: ReleaseVersion,
    pub dir: PathBuf,
    pub installer_sha256: String,
    /// SHA-256 of the downloaded release tarball, computed by the verifier.
    /// It is persisted into the installed release manifest so backup
    /// artifacts can bind the exact release artifact.
    pub release_artifact_sha256: String,
}

/// Outcome of one full doctor run.
#[derive(Debug, Clone)]
pub struct DoctorOutcome {
    /// False only when the overall doctor verdict is `unhealthy`
    /// (warning-only installations still pass the post-upgrade gate).
    pub healthy: bool,
    pub overall: String,
}

/// The concurrent-invocation lock. Dropping the guard releases the lock
/// (best effort); the engine also releases it explicitly at the end.
pub struct LockGuard {
    path: PathBuf,
}

pub struct StorePhaseGuard {
    _lock: Option<o3k_store::StoreAccessLock>,
}
impl StorePhaseGuard {
    pub(crate) fn empty() -> Self {
        Self { _lock: None }
    }
    pub(crate) fn from_lock(lock: o3k_store::StoreAccessLock) -> Self {
        Self { _lock: Some(lock) }
    }
}

impl LockGuard {
    /// Wraps a lock-file path (used by the real runner and the test fake).
    #[must_use]
    pub(crate) fn new(path: PathBuf) -> Self {
        Self { path }
    }
}

impl Drop for LockGuard {
    fn drop(&mut self) {
        let _ = std::fs::remove_file(&self.path);
    }
}

/// Everything the upgrade engine needs from the host. Implemented for real
/// hosts by [`crate::upgrade::runner::SystemUpgradeIo`] and by a
/// configurable fake in the engine tests.
#[async_trait]
pub trait UpgradeIo: Send + Sync {
    /// Takes the concurrent-invocation lock; fails while another upgrade or
    /// rollback holds it.
    async fn acquire_lock(&self) -> Result<LockGuard, String>;
    /// Releases the lock held by `guard` (the guard also releases on drop).
    async fn release_lock(&self, guard: LockGuard) -> Result<(), String>;
    async fn acquire_store_phase_lock(&self) -> Result<StorePhaseGuard, String> {
        Ok(StorePhaseGuard::empty())
    }
    /// Reads the installed release manifest.
    async fn read_installed_manifest(&self) -> Result<InstalledRelease, String>;
    /// Resolves the target release: the requested version, or the newest
    /// published release in the installed channel family.
    async fn resolve_target(
        &self,
        requested: Option<ReleaseVersion>,
    ) -> Result<ReleaseVersion, String>;
    /// Downloads the official release assets and verifies the bundle
    /// (checksum, installer match, manifest, archive safety).
    async fn download_and_verify(&self, target: &ReleaseVersion) -> Result<VerifiedBundle, String>;
    /// Runs the read-only preflight against the recorded state and (when
    /// present) the verified bundle.
    async fn preflight(&self, state: &UpgradeState, bundle: &VerifiedBundle) -> Result<(), String>;
    /// Creates and verifies the backup; returns the backup id.
    async fn create_backup(&self, state: &UpgradeState) -> Result<String, String>;
    /// Stops `o3k-compute` then `o3kd` with bounded waits.
    async fn stop_services(&self) -> Result<(), String>;
    /// Atomically replaces the installed binaries and release metadata from
    /// the verified bundle.
    async fn switch_binaries(&self, bundle: &VerifiedBundle) -> Result<(), String>;
    /// Starts `o3kd`, waits for readiness, and verifies the observed schema
    /// version against the target release's declared schema version.
    /// Returns the observed post-start schema version.
    async fn apply_migrations_and_start_control(&self, backup_id: &str) -> Result<u32, String>;
    /// Starts `o3k-compute` and waits for agent registration.
    async fn start_compute(&self) -> Result<(), String>;
    /// Runs `o3k doctor` end to end (read-only).
    async fn run_doctor(&self) -> Result<DoctorOutcome, String>;
    /// Public API smoke: token, server list, placement consistency.
    async fn verify_public_api(&self) -> Result<(), String>;
    /// Appends the backup record to the rollback chain (idempotent).
    async fn commit(&self, backup_id: &str) -> Result<(), String>;
    /// Validates and performs a rollback to the given backup (binaries,
    /// manifest, DB when required, service restart, doctor, API smoke).
    async fn rollback_to_backup(&self, backup_id: &str) -> Result<(), String>;
}

/// Arguments of one `o3k upgrade` invocation.
#[derive(Debug, Clone)]
pub struct UpgradeArgs {
    pub requested: Option<ReleaseVersion>,
    pub check_only: bool,
    /// Accepted for CLI compatibility; the engine never prompts, so the
    /// flag does not change behavior.
    pub assume_yes: bool,
    /// Post-start doctor convergence: the agent re-publishes inventory
    /// asynchronously after registering, so the doctor gate retries a
    /// bounded number of times before failing (defaults 5 x 15s; the
    /// portable test suite shrinks them via env knobs).
    pub doctor_retry_attempts: u32,
    pub doctor_retry_delay_ms: u64,
}

impl Default for UpgradeArgs {
    fn default() -> Self {
        Self {
            requested: None,
            check_only: false,
            assume_yes: false,
            doctor_retry_attempts: 5,
            doctor_retry_delay_ms: 15_000,
        }
    }
}

/// File-system locations the engine owns (state file, rollback chain).
#[derive(Debug, Clone)]
pub struct UpgradePaths {
    pub state_file: PathBuf,
    pub chain_file: PathBuf,
    pub backup_dir: PathBuf,
}

impl UpgradePaths {
    /// Resolves the sandboxable defaults from the process environment.
    #[must_use]
    pub fn from_env() -> Self {
        Self {
            state_file: default_state_path(),
            chain_file: crate::upgrade::backup::default_chain_path(),
            backup_dir: crate::upgrade::backup::default_backup_dir(),
        }
    }
}

/// The observable result of one invocation.
#[derive(Debug, Clone)]
pub struct UpgradeOutcome {
    pub source_version: Option<ReleaseVersion>,
    pub target_version: Option<ReleaseVersion>,
    pub phase: UpgradePhase,
    pub backup_id: Option<String>,
    pub status: UpgradeStatus,
    pub rollback_performed: bool,
    pub doctor_status: Option<String>,
    /// Human-readable failure description (rendered on stderr; never part
    /// of the machine output).
    pub error: Option<String>,
}

/// Runs an upgrade against the environment-derived paths.
pub async fn run_upgrade(io: &dyn UpgradeIo, args: &UpgradeArgs) -> UpgradeOutcome {
    run_upgrade_with_paths(io, args, &UpgradePaths::from_env()).await
}

/// Runs a rollback against the environment-derived paths.
pub async fn run_rollback(io: &dyn UpgradeIo) -> UpgradeOutcome {
    run_rollback_with_paths(io, &UpgradePaths::from_env()).await
}

/// Builds a Failed outcome.
#[must_use]
fn fail_outcome(
    source_version: Option<ReleaseVersion>,
    target_version: Option<ReleaseVersion>,
    phase: UpgradePhase,
    backup_id: Option<String>,
    rollback_performed: bool,
    doctor_status: Option<String>,
    error: Option<String>,
) -> UpgradeOutcome {
    UpgradeOutcome {
        source_version,
        target_version,
        phase,
        backup_id,
        status: UpgradeStatus::Failed,
        rollback_performed,
        doctor_status,
        error,
    }
}

/// Discovers the installed release, resolves the target, and applies the
/// version-level fence (same version, downgrade, channel). The target
/// profile and `upgrade_from.min_version` fence live inside the target
/// manifest and are enforced during [`UpgradeIo::download_and_verify`].
async fn discover(
    io: &dyn UpgradeIo,
    args: &UpgradeArgs,
) -> Result<(UpgradeState, ReleaseVersion), UpgradeOutcome> {
    let release = io.read_installed_manifest().await.map_err(|error| {
        fail_outcome(
            None,
            None,
            UpgradePhase::Discovered,
            None,
            false,
            None,
            Some(error),
        )
    })?;
    let target = io
        .resolve_target(args.requested.clone())
        .await
        .map_err(|error| {
            fail_outcome(
                Some(release.version.clone()),
                None,
                UpgradePhase::Discovered,
                None,
                false,
                None,
                Some(error),
            )
        })?;
    let fence = UpgradeFence::new(
        release.version.clone(),
        target.clone(),
        None,
        (release.profile.clone(), release.profile.clone()),
    );
    fence.decide().map_err(|kind| {
        fail_outcome(
            Some(release.version.clone()),
            Some(target.clone()),
            UpgradePhase::Discovered,
            None,
            false,
            None,
            Some(kind.to_string()),
        )
    })?;
    Ok((
        UpgradeState::discovered(release.version.clone(), target.clone()),
        target,
    ))
}

/// Persists the FAILED_UPGRADE terminal state (best effort; a persist
/// failure must not mask the original error).
fn persist_failed_state(state: &mut UpgradeState, paths: &UpgradePaths) {
    state.advance(UpgradePhase::FailedUpgrade);
    let _ = state.persist(&paths.state_file);
}

/// Validates the recorded backup of an in-progress upgrade; the backup is
/// the resumption anchor and must be intact.
fn validate_resume_backup(backup_id: &str, paths: &UpgradePaths) -> Result<(), String> {
    let manifest_path = paths.backup_dir.join(backup_id).join("backup.json");
    let bytes = std::fs::read(&manifest_path).map_err(|error| {
        format!(
            "the in-progress upgrade backup {} is unreadable: {error}",
            manifest_path.display()
        )
    })?;
    BackupManifest::validate(&bytes)
        .map(|_| ())
        .map_err(|error| format!("the in-progress upgrade backup is invalid: {error}"))
}

/// The upgrade driver with explicit paths (unit tests use sandbox paths).
#[allow(clippy::too_many_lines)]
pub async fn run_upgrade_with_paths(
    io: &dyn UpgradeIo,
    args: &UpgradeArgs,
    paths: &UpgradePaths,
) -> UpgradeOutcome {
    let guard = match io.acquire_lock().await {
        Ok(guard) => guard,
        Err(error) => {
            let status = if args.check_only {
                UpgradeStatus::CheckBlocked
            } else {
                UpgradeStatus::Failed
            };
            return UpgradeOutcome {
                source_version: None,
                target_version: None,
                phase: UpgradePhase::Discovered,
                backup_id: None,
                status,
                rollback_performed: false,
                doctor_status: None,
                error: Some(error),
            };
        }
    };
    let result = run_upgrade_locked(io, args, paths).await;
    let _ = io.release_lock(guard).await;
    result
}

/// The upgrade driver after lock acquisition.
#[allow(clippy::too_many_lines)]
async fn run_upgrade_locked(
    io: &dyn UpgradeIo,
    args: &UpgradeArgs,
    paths: &UpgradePaths,
) -> UpgradeOutcome {
    let state = match UpgradeState::load(&paths.state_file) {
        Ok(state) => state,
        Err(error) => {
            return fail_outcome(
                None,
                None,
                UpgradePhase::Discovered,
                None,
                false,
                None,
                Some(error),
            );
        }
    };

    // Terminal recovery states refuse a new upgrade with instructions.
    if let Some(existing) = &state {
        match existing.phase {
            UpgradePhase::FailedUpgrade => {
                return fail_outcome(
                    Some(existing.source_version.clone()),
                    Some(existing.target_version.clone()),
                    existing.phase,
                    existing.backup_id.clone(),
                    false,
                    existing.doctor_status.clone(),
                    Some(
                        "a previous upgrade failed; run `sudo o3k rollback` to restore the \
                         previous release, then re-run `sudo o3k upgrade`"
                            .to_owned(),
                    ),
                );
            }
            UpgradePhase::RolledBack => {
                return fail_outcome(
                    Some(existing.source_version.clone()),
                    Some(existing.target_version.clone()),
                    existing.phase,
                    existing.backup_id.clone(),
                    false,
                    existing.doctor_status.clone(),
                    Some(
                        "a rollback is in progress; run `sudo o3k rollback` to complete it"
                            .to_owned(),
                    ),
                );
            }
            _ => {}
        }
    }

    // Read-only check mode: an in-progress state blocks the verdict.
    if args.check_only {
        if state.is_some() {
            return UpgradeOutcome {
                source_version: state.as_ref().map(|s| s.source_version.clone()),
                target_version: state.as_ref().map(|s| s.target_version.clone()),
                phase: UpgradePhase::PreflightPassed,
                backup_id: None,
                status: UpgradeStatus::CheckBlocked,
                rollback_performed: false,
                doctor_status: None,
                error: Some(
                    "an upgrade is already in progress on this host; run `sudo o3k upgrade` \
                     to resume it or `sudo o3k rollback` to restore the previous release"
                        .to_owned(),
                ),
            };
        }
        let (fresh, target) = match discover(io, args).await {
            Ok(pair) => pair,
            Err(outcome) => {
                return UpgradeOutcome {
                    status: UpgradeStatus::CheckBlocked,
                    error: outcome.error,
                    ..outcome
                };
            }
        };
        // No download in check mode: preflight receives an empty bundle and
        // skips bundle-dependent checks.
        let empty_bundle = VerifiedBundle {
            version: target.clone(),
            dir: PathBuf::new(),
            installer_sha256: String::new(),
            release_artifact_sha256: String::new(),
        };
        return match io.preflight(&fresh, &empty_bundle).await {
            Ok(()) => UpgradeOutcome {
                source_version: Some(fresh.source_version),
                target_version: Some(target),
                phase: UpgradePhase::PreflightPassed,
                backup_id: None,
                status: UpgradeStatus::CheckPassed,
                rollback_performed: false,
                doctor_status: None,
                error: None,
            },
            Err(error) => UpgradeOutcome {
                source_version: Some(fresh.source_version),
                target_version: Some(target),
                phase: UpgradePhase::PreflightPassed,
                backup_id: None,
                status: UpgradeStatus::CheckBlocked,
                rollback_performed: false,
                doctor_status: None,
                error: Some(error),
            },
        };
    }

    // Resumption: a recorded phase at BACKUP_CREATED or later resumes; the
    // backup must validate. Earlier phases never mutated the system.
    let resume_phase = state.as_ref().and_then(|existing| {
        (existing.phase >= UpgradePhase::BackupCreated).then_some(existing.phase)
    });
    if let Some(recorded) = resume_phase
        && let Some(existing) = &state
    {
        match &existing.backup_id {
            None if recorded == UpgradePhase::BackupCreated => {
                // create_backup never completed; it re-runs below.
            }
            None => {
                return fail_outcome(
                    Some(existing.source_version.clone()),
                    Some(existing.target_version.clone()),
                    recorded,
                    None,
                    false,
                    None,
                    Some(
                        "the in-progress upgrade state has no backup id; run \
                         `sudo o3k rollback` or reinstall the previous release"
                            .to_owned(),
                    ),
                );
            }
            Some(backup_id) => {
                if let Err(error) = validate_resume_backup(backup_id, paths) {
                    return fail_outcome(
                        Some(existing.source_version.clone()),
                        Some(existing.target_version.clone()),
                        recorded,
                        Some(backup_id.clone()),
                        false,
                        None,
                        Some(format!("{error}; run `sudo o3k rollback` to recover")),
                    );
                }
            }
        }
    }

    // Establish the working state: resume the recorded attempt or start a
    // fresh DISCOVERED record.
    let (mut state, mut phase, target) = match resume_phase {
        Some(recorded) => {
            let Some(loaded) = state else {
                return fail_outcome(
                    None,
                    None,
                    UpgradePhase::Discovered,
                    None,
                    false,
                    None,
                    Some("the upgrade state disappeared mid-run".to_owned()),
                );
            };
            let target = loaded.target_version.clone();
            (loaded, recorded, target)
        }
        None => {
            let (fresh, target) = match discover(io, args).await {
                Ok(pair) => pair,
                Err(outcome) => return outcome,
            };
            if let Err(error) = fresh.persist(&paths.state_file) {
                return fail_outcome(
                    Some(fresh.source_version.clone()),
                    Some(target.clone()),
                    fresh.phase,
                    None,
                    false,
                    None,
                    Some(error),
                );
            }
            (fresh, UpgradePhase::ReleaseDownloaded, target)
        }
    };
    let source_version = state.source_version.clone();
    let mut backup_id = state.backup_id.clone();
    let mut bundle: Option<VerifiedBundle> = None;
    let mut store_phase_guard: Option<StorePhaseGuard> = None;
    let mut doctor_status: Option<String> = None;

    // Phase loop: each phase persists its state BEFORE its side effects and
    // every action is safe to re-execute, so an interruption resumes
    // exactly where it stopped.
    while phase < UpgradePhase::Committed {
        if phase >= UpgradePhase::BackupCreated && bundle.is_none() {
            // A resumed run re-obtains the verified bundle (a fresh run
            // already holds it from RELEASE_DOWNLOADED). create_backup
            // needs it too for the migration-compatibility decision.
            match io.download_and_verify(&target).await {
                Ok(downloaded) => bundle = Some(downloaded),
                Err(error) => {
                    return fail_outcome(
                        Some(source_version.clone()),
                        Some(target.clone()),
                        phase,
                        backup_id.clone(),
                        false,
                        doctor_status,
                        Some(error),
                    );
                }
            }
        }

        let action: Result<(), String> =
            match phase {
                UpgradePhase::ReleaseDownloaded => {
                    io.download_and_verify(&target).await.map(|downloaded| {
                        bundle = Some(downloaded);
                    })
                }
                UpgradePhase::ReleaseVerified => Ok(()),
                UpgradePhase::PreflightPassed => match &bundle {
                    Some(verified) => io.preflight(&state, verified).await,
                    None => Err("the verified bundle is unavailable".to_owned()),
                },
                UpgradePhase::BackupCreated => match &backup_id {
                    Some(_) => Ok(()),
                    None => io.create_backup(&state).await.map(|id| {
                        backup_id = Some(id.clone());
                        state.backup_id = Some(id);
                    }),
                },
                UpgradePhase::ServicesStopped => io.stop_services().await,
                UpgradePhase::BinariesInstalled => match &bundle {
                    Some(verified) => match io.acquire_store_phase_lock().await {
                        Ok(guard) => {
                            store_phase_guard = Some(guard);
                            io.switch_binaries(verified).await
                        }
                        Err(error) => Err(error),
                    },
                    None => Err("the verified bundle is unavailable".to_owned()),
                },
                UpgradePhase::MigrationsApplied => {
                    drop(store_phase_guard.take());
                    io.apply_migrations_and_start_control(backup_id.as_deref().unwrap_or(""))
                        .await
                        .map(|_schema| ())
                }
                UpgradePhase::ServicesStarted => io.start_compute().await,
                UpgradePhase::HealthVerified => io.verify_public_api().await,
                UpgradePhase::DoctorPassed => {
                    // Bounded convergence wait: after o3k-compute registers it
                    // re-publishes placement inventory asynchronously, so a
                    // point-in-time doctor run can transiently FAIL. Retry up
                    // to the configured budget before failing the upgrade.
                    let mut last: Option<DoctorOutcome> = None;
                    let mut last_error: Option<String> = None;
                    for _attempt in 0..args.doctor_retry_attempts {
                        match io.run_doctor().await {
                            Ok(outcome) => {
                                last = Some(outcome);
                                if last.as_ref().is_some_and(|report| report.healthy) {
                                    break;
                                }
                            }
                            Err(error) => last_error = Some(error),
                        }
                        tokio::time::sleep(std::time::Duration::from_millis(
                            args.doctor_retry_delay_ms,
                        ))
                        .await;
                    }
                    match last {
                        Some(outcome) => {
                            doctor_status = Some(outcome.overall.clone());
                            if outcome.healthy {
                                Ok(())
                            } else {
                                Err(format!(
                                    "doctor reports an unhealthy installation: {}",
                                    outcome.overall
                                ))
                            }
                        }
                        None => Err(last_error
                            .unwrap_or_else(|| "doctor never produced a report".to_owned())),
                    }
                }
                UpgradePhase::Committed
                | UpgradePhase::Discovered
                | UpgradePhase::FailedUpgrade
                | UpgradePhase::RolledBack => {
                    Err("internal error: unexpected upgrade phase".to_owned())
                }
            };

        match action {
            Ok(()) => {
                phase = match phase {
                    UpgradePhase::ReleaseDownloaded => UpgradePhase::ReleaseVerified,
                    UpgradePhase::ReleaseVerified => UpgradePhase::PreflightPassed,
                    UpgradePhase::PreflightPassed => UpgradePhase::BackupCreated,
                    UpgradePhase::BackupCreated => UpgradePhase::ServicesStopped,
                    UpgradePhase::ServicesStopped => UpgradePhase::BinariesInstalled,
                    UpgradePhase::BinariesInstalled => UpgradePhase::MigrationsApplied,
                    UpgradePhase::MigrationsApplied => UpgradePhase::ServicesStarted,
                    UpgradePhase::ServicesStarted => UpgradePhase::HealthVerified,
                    UpgradePhase::HealthVerified => UpgradePhase::DoctorPassed,
                    UpgradePhase::DoctorPassed => UpgradePhase::Committed,
                    _ => UpgradePhase::FailedUpgrade,
                };
                state.advance(phase);
                if let Err(error) = state.persist(&paths.state_file) {
                    return fail_outcome(
                        Some(source_version.clone()),
                        Some(target.clone()),
                        phase,
                        backup_id.clone(),
                        false,
                        doctor_status.clone(),
                        Some(error),
                    );
                }
            }
            Err(error) => match phase {
                UpgradePhase::ReleaseDownloaded
                | UpgradePhase::ReleaseVerified
                | UpgradePhase::PreflightPassed
                | UpgradePhase::BackupCreated => {
                    // No mutation yet: clear the state and fail (§9).
                    let _ = UpgradeState::clear(&paths.state_file);
                    return fail_outcome(
                        Some(source_version.clone()),
                        Some(target.clone()),
                        phase,
                        None,
                        false,
                        doctor_status,
                        Some(error),
                    );
                }
                UpgradePhase::ServicesStopped => {
                    // Stopping is non-destructive and binaries are intact;
                    // the state (already at SERVICES_STOPPED) is kept so a
                    // re-run resumes.
                    return fail_outcome(
                        Some(source_version.clone()),
                        Some(target.clone()),
                        phase,
                        backup_id.clone(),
                        false,
                        doctor_status,
                        Some(format!("{error}; re-run `sudo o3k upgrade` to resume")),
                    );
                }
                UpgradePhase::BinariesInstalled
                | UpgradePhase::MigrationsApplied
                | UpgradePhase::ServicesStarted
                | UpgradePhase::HealthVerified
                | UpgradePhase::DoctorPassed => {
                    // Post-mutation failure: exactly one automatic rollback
                    // attempt per invocation (§9) — this arm always returns,
                    // so no upgrade↔rollback loop is possible. A resumed
                    // invocation gets its own single attempt.
                    let Some(id) = backup_id.clone() else {
                        persist_failed_state(&mut state, paths);
                        return fail_outcome(
                            Some(source_version.clone()),
                            Some(target.clone()),
                            UpgradePhase::FailedUpgrade,
                            None,
                            false,
                            doctor_status,
                            Some(
                                "no backup id recorded for the rollback; run \
                                 `sudo o3k rollback` to restore the previous release"
                                    .to_owned(),
                            ),
                        );
                    };
                    match io.rollback_to_backup(&id).await {
                        Ok(()) => {
                            // Restored: clear the in-progress state and report.
                            let _ = UpgradeState::clear(&paths.state_file);
                            return fail_outcome(
                                Some(source_version.clone()),
                                Some(target.clone()),
                                phase,
                                Some(id),
                                true,
                                doctor_status,
                                Some(format!(
                                    "{error}; the previous release was restored by an \
                                     automatic rollback"
                                )),
                            );
                        }
                        Err(rollback_error) => {
                            persist_failed_state(&mut state, paths);
                            return fail_outcome(
                                Some(source_version.clone()),
                                Some(target.clone()),
                                UpgradePhase::FailedUpgrade,
                                Some(id),
                                false,
                                doctor_status,
                                Some(format!(
                                    "{error}; the automatic rollback also failed \
                                     ({rollback_error}); the host is in a recoverable \
                                     FAILED_UPGRADE state — run `sudo o3k rollback` to \
                                     restore the previous release"
                                )),
                            );
                        }
                    }
                }
                UpgradePhase::Committed
                | UpgradePhase::Discovered
                | UpgradePhase::FailedUpgrade
                | UpgradePhase::RolledBack => {
                    return fail_outcome(
                        Some(source_version.clone()),
                        Some(target.clone()),
                        phase,
                        backup_id.clone(),
                        false,
                        doctor_status,
                        Some("internal error: unexpected upgrade phase".to_owned()),
                    );
                }
            },
        }
    }

    // COMMITTED: write the backup record into the rollback chain and clear
    // the in-progress state (plan §2). A commit failure keeps the state so
    // a re-run completes the commit (the chain append deduplicates).
    let Some(id) = backup_id.clone() else {
        return fail_outcome(
            Some(source_version.clone()),
            Some(target.clone()),
            UpgradePhase::Committed,
            None,
            false,
            doctor_status,
            Some("no backup id recorded; cannot commit".to_owned()),
        );
    };
    if let Err(error) = io.commit(&id).await {
        return fail_outcome(
            Some(source_version.clone()),
            Some(target.clone()),
            UpgradePhase::Committed,
            Some(id),
            false,
            doctor_status,
            Some(format!(
                "{error}; the release is installed and verified — re-run \
                 `sudo o3k upgrade` to complete the commit"
            )),
        );
    }
    if let Err(error) = UpgradeState::clear(&paths.state_file) {
        return fail_outcome(
            Some(source_version.clone()),
            Some(target.clone()),
            UpgradePhase::Committed,
            Some(id),
            false,
            doctor_status,
            Some(format!(
                "the upgrade committed but the state file could not be cleared: {error}"
            )),
        );
    }
    UpgradeOutcome {
        source_version: Some(source_version),
        target_version: Some(target),
        phase: UpgradePhase::Committed,
        backup_id: Some(id),
        status: UpgradeStatus::Committed,
        rollback_performed: false,
        doctor_status,
        error: None,
    }
}

/// The rollback driver with explicit paths.
pub async fn run_rollback_with_paths(io: &dyn UpgradeIo, paths: &UpgradePaths) -> UpgradeOutcome {
    let guard = match io.acquire_lock().await {
        Ok(guard) => guard,
        Err(error) => {
            return fail_outcome(
                None,
                None,
                UpgradePhase::RolledBack,
                None,
                false,
                None,
                Some(error),
            );
        }
    };
    let result = run_rollback_locked(io, paths).await;
    let _ = io.release_lock(guard).await;
    result
}

/// The rollback driver after lock acquisition (plan §10).
#[allow(clippy::too_many_lines)]
async fn run_rollback_locked(io: &dyn UpgradeIo, paths: &UpgradePaths) -> UpgradeOutcome {
    let state = match UpgradeState::load(&paths.state_file) {
        Ok(state) => state,
        Err(error) => {
            return fail_outcome(
                None,
                None,
                UpgradePhase::RolledBack,
                None,
                false,
                None,
                Some(error),
            );
        }
    };
    // Selection: the in-progress/failed upgrade's recorded backup wins;
    // otherwise the most recent eligible chain record. Records written by a
    // previous rollback are never eligible (a second rollback is a no-op
    // with a notice).
    let backup_id = match state.as_ref().and_then(|s| s.backup_id.clone()) {
        Some(id) => Some(id),
        None => match RollbackChain::load(&paths.chain_file) {
            Ok(Some(chain)) => chain.latest_eligible_backup().map(|m| m.backup_id.clone()),
            Ok(None) => None,
            Err(error) => {
                return fail_outcome(
                    None,
                    None,
                    UpgradePhase::RolledBack,
                    None,
                    false,
                    None,
                    Some(format!("cannot read the rollback chain: {error}")),
                );
            }
        },
    };
    let Some(backup_id) = backup_id else {
        return fail_outcome(
            None,
            None,
            UpgradePhase::RolledBack,
            None,
            false,
            None,
            Some(
                "no eligible O3K backup exists; nothing to roll back (a rollback was already \
                 performed, or no upgrade has been committed on this host)"
                    .to_owned(),
            ),
        );
    };

    // Persist the ROLLED_BACK phase before the restore side effects so an
    // interruption re-runs the rollback (all steps are safe to re-execute).
    let mut rollback_state = match state {
        Some(existing) => existing,
        None => {
            let record = match load_backup_manifest(&backup_id, paths) {
                Ok(record) => record,
                Err(error) => {
                    return fail_outcome(
                        None,
                        None,
                        UpgradePhase::RolledBack,
                        Some(backup_id.clone()),
                        false,
                        None,
                        Some(error),
                    );
                }
            };
            UpgradeState {
                source_version: record.source_version,
                target_version: record.target_version,
                phase: UpgradePhase::RolledBack,
                backup_id: Some(backup_id.clone()),
                started_at: crate::output::now_utc_rfc3339(),
                updated_at: crate::output::now_utc_rfc3339(),
                rollback_performed: false,
                doctor_status: None,
            }
        }
    };
    rollback_state.advance(UpgradePhase::RolledBack);
    if let Err(error) = rollback_state.persist(&paths.state_file) {
        return fail_outcome(
            Some(rollback_state.source_version.clone()),
            Some(rollback_state.target_version.clone()),
            UpgradePhase::RolledBack,
            Some(backup_id.clone()),
            false,
            None,
            Some(error),
        );
    }

    match io.rollback_to_backup(&backup_id).await {
        Ok(()) => {
            // Record the rollback in the chain; a second rollback then finds
            // no eligible backup (plan §10).
            let record = match load_backup_manifest(&backup_id, paths) {
                Ok(record) => record,
                Err(error) => {
                    return fail_outcome(
                        Some(rollback_state.source_version.clone()),
                        Some(rollback_state.target_version.clone()),
                        UpgradePhase::RolledBack,
                        Some(backup_id.clone()),
                        true,
                        None,
                        Some(format!(
                            "the rollback completed but could not be recorded: {error}"
                        )),
                    );
                }
            };
            if let Err(error) = RollbackChain::append(
                &paths.chain_file,
                RollbackRecord {
                    manifest: record,
                    kind: RecordKind::Rollback,
                },
            ) {
                return fail_outcome(
                    Some(rollback_state.source_version.clone()),
                    Some(rollback_state.target_version.clone()),
                    UpgradePhase::RolledBack,
                    Some(backup_id.clone()),
                    true,
                    None,
                    Some(format!(
                        "the rollback completed but could not be recorded: {error}"
                    )),
                );
            }
            if let Err(error) = UpgradeState::clear(&paths.state_file) {
                return fail_outcome(
                    Some(rollback_state.source_version.clone()),
                    Some(rollback_state.target_version.clone()),
                    UpgradePhase::RolledBack,
                    Some(backup_id.clone()),
                    true,
                    None,
                    Some(format!(
                        "the rollback completed but the state file could not be cleared: {error}"
                    )),
                );
            }
            UpgradeOutcome {
                source_version: Some(rollback_state.source_version),
                target_version: Some(rollback_state.target_version),
                phase: UpgradePhase::RolledBack,
                backup_id: Some(backup_id),
                status: UpgradeStatus::RolledBack,
                rollback_performed: true,
                doctor_status: None,
                error: None,
            }
        }
        Err(error) => {
            persist_failed_state(&mut rollback_state, paths);
            fail_outcome(
                Some(rollback_state.source_version.clone()),
                Some(rollback_state.target_version.clone()),
                UpgradePhase::FailedUpgrade,
                Some(backup_id),
                false,
                None,
                Some(format!(
                    "rollback failed: {error}; the host is in a recoverable FAILED_UPGRADE \
                     state — re-run `sudo o3k rollback`"
                )),
            )
        }
    }
}

/// Loads and validates the backup manifest for one backup id.
fn load_backup_manifest(backup_id: &str, paths: &UpgradePaths) -> Result<BackupManifest, String> {
    let manifest_path = paths.backup_dir.join(backup_id).join("backup.json");
    let bytes = std::fs::read(&manifest_path)
        .map_err(|error| format!("cannot read the backup manifest: {error}"))?;
    BackupManifest::validate(&bytes)
}

/// Whether a phase records post-backup progress (used by tests to assert
/// resumption decisions).
#[cfg(test)]
fn is_resumable(phase: UpgradePhase) -> bool {
    phase >= UpgradePhase::BackupCreated
}

/// Convenience for the tests: a loaded state record or None.
#[cfg(test)]
fn parse_state(bytes: &[u8]) -> Option<UpgradeState> {
    serde_json::from_slice(bytes).ok()
}

#[cfg(test)]
mod tests {
    #![allow(clippy::assertions_on_constants)]
    use super::*;
    use std::collections::BTreeMap;
    use std::sync::Mutex;
    use std::sync::atomic::{AtomicUsize, Ordering};

    static TEMP_COUNTER: AtomicUsize = AtomicUsize::new(0);

    fn version(major: u64, minor: u64, patch: u64, prerelease: &[&str]) -> ReleaseVersion {
        ReleaseVersion::new(
            major,
            minor,
            patch,
            prerelease.iter().map(|id| (*id).to_owned()).collect(),
        )
    }

    /// A unique sandbox for one test run.
    fn sandbox() -> UpgradePaths {
        let n = TEMP_COUNTER.fetch_add(1, Ordering::Relaxed);
        let root = std::env::temp_dir().join(format!("o3k-engine-test-{}-{n}", std::process::id()));
        UpgradePaths {
            state_file: root.join("state.json"),
            chain_file: root.join("backups").join("backup-chain.json"),
            backup_dir: root.join("backups"),
        }
    }

    fn cleanup(paths: &UpgradePaths) {
        if let Some(parent) = paths.state_file.parent() {
            let _ = std::fs::remove_dir_all(parent);
        }
    }

    fn backup_manifest(backup_id: &str) -> BackupManifest {
        BackupManifest {
            backup_id: backup_id.to_owned(),
            source_version: version(0, 2, 0, &["alpha", "2"]),
            target_version: version(0, 3, 0, &["alpha", "1"]),
            source_commit: Some("d6351864".to_owned()),
            created_at: "2026-01-01T00:00:00Z".to_owned(),
            binary_sha256: BTreeMap::from([("o3kd".to_owned(), "a".repeat(64))]),
            schema_version_before: 17,
            db_restore_required_on_rollback: false,
        }
    }

    /// Writes a valid backup manifest into the sandbox backup dir.
    fn seed_backup(paths: &UpgradePaths, backup_id: &str) {
        let dir = paths.backup_dir.join(backup_id);
        let _ = std::fs::create_dir_all(&dir);
        let bytes = serde_json::to_vec(&backup_manifest(backup_id)).unwrap_or_default();
        let _ = std::fs::write(dir.join("backup.json"), bytes);
    }

    /// Seeds a persisted upgrade state at the given phase.
    fn seed_state(paths: &UpgradePaths, phase: UpgradePhase, backup_id: Option<&str>) {
        let mut state = UpgradeState::discovered(
            version(0, 2, 0, &["alpha", "2"]),
            version(0, 3, 0, &["alpha", "1"]),
        );
        state.phase = phase;
        state.backup_id = backup_id.map(str::to_owned);
        let _ = state.persist(&paths.state_file);
    }

    struct FakeUpgradeIo {
        log: Mutex<Vec<String>>,
        lock_ok: bool,
        installed: Result<InstalledRelease, String>,
        target: Result<ReleaseVersion, String>,
        download: Result<VerifiedBundle, String>,
        preflight: Result<(), String>,
        backup: Result<String, String>,
        stop: Result<(), String>,
        switch: Result<(), String>,
        migrate: Result<u32, String>,
        start_compute: Result<(), String>,
        doctor: Result<DoctorOutcome, String>,
        api: Result<(), String>,
        commit: Result<(), String>,
        rollback: Result<(), String>,
        /// Mirrors the real entry deny: when set, `rollback_to_backup` denies
        /// at its mutation entry (before stopping services or touching the
        /// database), exactly like `SystemUpgradeIo`.
        rollback_entry_deny: Option<String>,
        commit_chain: Option<PathBuf>,
    }

    impl FakeUpgradeIo {
        fn happy() -> Self {
            Self {
                log: Mutex::new(Vec::new()),
                lock_ok: true,
                installed: Ok(InstalledRelease {
                    version: version(0, 2, 0, &["alpha", "2"]),
                    commit: Some("d6351864".to_owned()),
                    profile: "libvirt".to_owned(),
                }),
                target: Ok(version(0, 3, 0, &["alpha", "1"])),
                download: Ok(VerifiedBundle {
                    version: version(0, 3, 0, &["alpha", "1"]),
                    dir: PathBuf::from("/tmp/o3k-fake-bundle"),
                    installer_sha256: "a".repeat(64),
                    release_artifact_sha256: "b".repeat(64),
                }),
                preflight: Ok(()),
                backup: Ok("backup-1".to_owned()),
                stop: Ok(()),
                switch: Ok(()),
                migrate: Ok(17),
                start_compute: Ok(()),
                doctor: Ok(DoctorOutcome {
                    healthy: true,
                    overall: "healthy".to_owned(),
                }),
                api: Ok(()),
                commit: Ok(()),
                rollback: Ok(()),
                rollback_entry_deny: None,
                commit_chain: None,
            }
        }

        fn record(&self, method: &str) {
            if let Ok(mut log) = self.log.lock() {
                log.push(method.to_owned());
            }
        }

        fn record_owned(&self, method: String) {
            if let Ok(mut log) = self.log.lock() {
                log.push(method);
            }
        }

        fn calls(&self, method: &str) -> usize {
            match self.log.lock() {
                Ok(log) => log.iter().filter(|entry| entry.as_str() == method).count(),
                Err(_) => 0,
            }
        }
    }

    #[async_trait]
    impl UpgradeIo for FakeUpgradeIo {
        async fn acquire_lock(&self) -> Result<LockGuard, String> {
            self.record("lock");
            if self.lock_ok {
                Ok(LockGuard::new(
                    std::env::temp_dir().join("o3k-engine-fake.lock"),
                ))
            } else {
                Err("another o3k upgrade is running".to_owned())
            }
        }

        async fn release_lock(&self, _guard: LockGuard) -> Result<(), String> {
            Ok(())
        }

        async fn read_installed_manifest(&self) -> Result<InstalledRelease, String> {
            self.record("installed");
            self.installed.clone()
        }

        async fn resolve_target(
            &self,
            requested: Option<ReleaseVersion>,
        ) -> Result<ReleaseVersion, String> {
            self.record("resolve_target");
            match requested {
                Some(requested) => Ok(requested),
                None => self.target.clone(),
            }
        }

        async fn download_and_verify(
            &self,
            _target: &ReleaseVersion,
        ) -> Result<VerifiedBundle, String> {
            self.record("download");
            self.download.clone()
        }

        async fn preflight(
            &self,
            _state: &UpgradeState,
            _bundle: &VerifiedBundle,
        ) -> Result<(), String> {
            self.record("preflight");
            self.preflight.clone()
        }

        async fn create_backup(&self, _state: &UpgradeState) -> Result<String, String> {
            self.record("create_backup");
            self.backup.clone()
        }

        async fn stop_services(&self) -> Result<(), String> {
            self.record("stop");
            self.stop.clone()
        }

        async fn switch_binaries(&self, _bundle: &VerifiedBundle) -> Result<(), String> {
            self.record("switch");
            self.switch.clone()
        }

        async fn apply_migrations_and_start_control(
            &self,
            _backup_id: &str,
        ) -> Result<u32, String> {
            self.record("migrate");
            self.migrate.clone()
        }

        async fn start_compute(&self) -> Result<(), String> {
            self.record("start_compute");
            self.start_compute.clone()
        }

        async fn run_doctor(&self) -> Result<DoctorOutcome, String> {
            self.record("doctor");
            self.doctor.clone()
        }

        async fn verify_public_api(&self) -> Result<(), String> {
            self.record("api");
            self.api.clone()
        }

        async fn commit(&self, backup_id: &str) -> Result<(), String> {
            self.record("commit");
            if let Err(error) = &self.commit {
                return Err(error.clone());
            }
            if let Some(chain_file) = &self.commit_chain {
                let manifest = backup_manifest(backup_id);
                if let Err(error) = RollbackChain::append(
                    chain_file,
                    RollbackRecord {
                        manifest,
                        kind: RecordKind::Backup,
                    },
                ) {
                    return Err(format!("chain append failed: {error}"));
                }
            }
            Ok(())
        }

        async fn rollback_to_backup(&self, backup_id: &str) -> Result<(), String> {
            self.record_owned(format!("rollback:{backup_id}"));
            if let Some(reason) = &self.rollback_entry_deny {
                return Err(reason.clone());
            }
            self.rollback.clone()
        }
    }

    fn upgrade_args() -> UpgradeArgs {
        UpgradeArgs {
            requested: None,
            check_only: false,
            assume_yes: true,
            // Tests must never sleep for the production retry budget.
            doctor_retry_attempts: 2,
            doctor_retry_delay_ms: 1,
        }
    }

    /// The happy path runs every phase in order and commits.
    #[tokio::test]
    async fn happy_path_commits_and_clears_state() {
        let paths = sandbox();
        let mut io = FakeUpgradeIo::happy();
        io.commit_chain = Some(paths.chain_file.clone());
        let outcome = run_upgrade_with_paths(&io, &upgrade_args(), &paths).await;
        assert_eq!(outcome.status, UpgradeStatus::Committed);
        assert_eq!(outcome.phase, UpgradePhase::Committed);
        assert_eq!(outcome.backup_id.as_deref(), Some("backup-1"));
        assert!(!outcome.rollback_performed);
        assert_eq!(outcome.doctor_status.as_deref(), Some("healthy"));
        assert!(outcome.error.is_none());
        for method in [
            "installed",
            "resolve_target",
            "download",
            "preflight",
            "create_backup",
            "stop",
            "switch",
            "migrate",
            "start_compute",
            "api",
            "doctor",
            "commit",
        ] {
            assert_eq!(io.calls(method), 1, "{method} must run exactly once");
        }
        assert_eq!(io.calls("rollback:backup-1"), 0, "no rollback on success");
        let state = UpgradeState::load(&paths.state_file);
        let Ok(state) = state else {
            assert!(false, "state must load");
            return;
        };
        assert!(state.is_none(), "COMMITTED must clear the state file");
        let chain = RollbackChain::load(&paths.chain_file);
        let Some(chain) = chain.ok().flatten() else {
            assert!(false, "chain must exist after commit");
            return;
        };
        assert_eq!(chain.backups.len(), 1);
        assert_eq!(chain.backups[0].kind, RecordKind::Backup);
        cleanup(&paths);
    }

    /// `upgrade --check` runs preflight only: no download, no mutation.
    #[tokio::test]
    async fn check_passes_without_mutation() {
        let paths = sandbox();
        let io = FakeUpgradeIo::happy();
        let args = UpgradeArgs {
            check_only: true,
            ..upgrade_args()
        };
        let outcome = run_upgrade_with_paths(&io, &args, &paths).await;
        assert_eq!(outcome.status, UpgradeStatus::CheckPassed);
        assert_eq!(io.calls("preflight"), 1);
        assert_eq!(io.calls("download"), 0, "--check never downloads");
        assert_eq!(io.calls("create_backup"), 0);
        let state = UpgradeState::load(&paths.state_file);
        let Ok(state) = state else {
            assert!(false, "state must load");
            return;
        };
        assert!(state.is_none(), "--check never writes state");
        cleanup(&paths);
    }

    /// A failing preflight blocks the check with exit-1 semantics.
    #[tokio::test]
    async fn check_blocks_on_preflight_failure() {
        let paths = sandbox();
        let mut io = FakeUpgradeIo::happy();
        io.preflight = Err("unsupported distro".to_owned());
        let args = UpgradeArgs {
            check_only: true,
            ..upgrade_args()
        };
        let outcome = run_upgrade_with_paths(&io, &args, &paths).await;
        assert_eq!(outcome.status, UpgradeStatus::CheckBlocked);
        assert!(
            outcome
                .error
                .as_deref()
                .is_some_and(|e| e.contains("distro"))
        );
        cleanup(&paths);
    }

    /// A held lock blocks both check and upgrade.
    #[tokio::test]
    async fn lock_contention_blocks_both_modes() {
        let paths = sandbox();
        let mut io = FakeUpgradeIo::happy();
        io.lock_ok = false;
        let outcome = run_upgrade_with_paths(&io, &upgrade_args(), &paths).await;
        assert_eq!(outcome.status, UpgradeStatus::Failed);
        assert!(
            outcome
                .error
                .as_deref()
                .is_some_and(|e| e.contains("another o3k upgrade is running"))
        );
        assert_eq!(io.calls("installed"), 0, "locked out: no work may run");
        let args = UpgradeArgs {
            check_only: true,
            ..upgrade_args()
        };
        let outcome = run_upgrade_with_paths(&io, &args, &paths).await;
        assert_eq!(outcome.status, UpgradeStatus::CheckBlocked);
        cleanup(&paths);
    }

    /// The fence refuses a requested downgrade before any side effect.
    #[tokio::test]
    async fn fence_refuses_downgrade() {
        let paths = sandbox();
        let io = FakeUpgradeIo::happy();
        let args = UpgradeArgs {
            requested: Some(version(0, 1, 0, &["alpha", "9"])),
            ..upgrade_args()
        };
        let outcome = run_upgrade_with_paths(&io, &args, &paths).await;
        assert_eq!(outcome.status, UpgradeStatus::Failed);
        assert_eq!(outcome.phase, UpgradePhase::Discovered);
        assert!(
            outcome
                .error
                .as_deref()
                .is_some_and(|e| e.contains("downgrade"))
        );
        assert_eq!(io.calls("download"), 0);
        cleanup(&paths);
    }

    /// The fence refuses upgrading to the already-installed version.
    #[tokio::test]
    async fn fence_refuses_same_version() {
        let paths = sandbox();
        let io = FakeUpgradeIo::happy();
        let args = UpgradeArgs {
            requested: Some(version(0, 2, 0, &["alpha", "2"])),
            ..upgrade_args()
        };
        let outcome = run_upgrade_with_paths(&io, &args, &paths).await;
        assert_eq!(outcome.status, UpgradeStatus::Failed);
        assert!(
            outcome
                .error
                .as_deref()
                .is_some_and(|e| e.contains("already installed"))
        );
        cleanup(&paths);
    }

    /// The fence refuses a cross-channel target.
    #[tokio::test]
    async fn fence_refuses_channel_mismatch() {
        let paths = sandbox();
        let io = FakeUpgradeIo::happy();
        let args = UpgradeArgs {
            requested: Some(version(0, 3, 0, &[])),
            ..upgrade_args()
        };
        let outcome = run_upgrade_with_paths(&io, &args, &paths).await;
        assert_eq!(outcome.status, UpgradeStatus::Failed);
        assert!(
            outcome
                .error
                .as_deref()
                .is_some_and(|e| e.contains("channel"))
        );
        cleanup(&paths);
    }

    /// Download failure: no mutation, state cleared, no rollback.
    #[tokio::test]
    async fn download_failure_clears_state_without_rollback() {
        let paths = sandbox();
        let mut io = FakeUpgradeIo::happy();
        io.download = Err("checksum mismatch".to_owned());
        let outcome = run_upgrade_with_paths(&io, &upgrade_args(), &paths).await;
        assert_eq!(outcome.status, UpgradeStatus::Failed);
        assert!(
            outcome
                .error
                .as_deref()
                .is_some_and(|e| e.contains("checksum"))
        );
        assert_eq!(io.calls("rollback:backup-1"), 0);
        let state = UpgradeState::load(&paths.state_file);
        let Ok(state) = state else {
            assert!(false, "state must load");
            return;
        };
        assert!(state.is_none(), "failed download must clear the state");
        cleanup(&paths);
    }

    /// Preflight failure: no mutation, state cleared, no rollback.
    #[tokio::test]
    async fn preflight_failure_clears_state_without_rollback() {
        let paths = sandbox();
        let mut io = FakeUpgradeIo::happy();
        io.preflight = Err("ownership manifest violation".to_owned());
        let outcome = run_upgrade_with_paths(&io, &upgrade_args(), &paths).await;
        assert_eq!(outcome.status, UpgradeStatus::Failed);
        assert_eq!(io.calls("create_backup"), 0);
        assert_eq!(io.calls("rollback:backup-1"), 0);
        let state = UpgradeState::load(&paths.state_file);
        let Ok(state) = state else {
            assert!(false, "state must load");
            return;
        };
        assert!(state.is_none());
        cleanup(&paths);
    }

    /// Backup failure: no mutation, state cleared, no rollback.
    #[tokio::test]
    async fn backup_failure_clears_state_without_rollback() {
        let paths = sandbox();
        let mut io = FakeUpgradeIo::happy();
        io.backup = Err("insufficient disk space".to_owned());
        let outcome = run_upgrade_with_paths(&io, &upgrade_args(), &paths).await;
        assert_eq!(outcome.status, UpgradeStatus::Failed);
        assert_eq!(io.calls("stop"), 0);
        assert_eq!(io.calls("rollback:backup-1"), 0);
        let state = UpgradeState::load(&paths.state_file);
        let Ok(state) = state else {
            assert!(false, "state must load");
            return;
        };
        assert!(state.is_none());
        cleanup(&paths);
    }

    /// Stop failure keeps the recorded state so a re-run resumes; binaries
    /// are untouched, so no rollback runs.
    #[tokio::test]
    async fn stop_failure_keeps_state_without_rollback() {
        let paths = sandbox();
        let mut io = FakeUpgradeIo::happy();
        io.stop = Err("o3kd failed to stop".to_owned());
        let outcome = run_upgrade_with_paths(&io, &upgrade_args(), &paths).await;
        assert_eq!(outcome.status, UpgradeStatus::Failed);
        assert_eq!(io.calls("switch"), 0);
        assert_eq!(io.calls("rollback:backup-1"), 0);
        let state = UpgradeState::load(&paths.state_file);
        let Some(state) = state.ok().flatten() else {
            assert!(false, "state must persist for resumption");
            return;
        };
        assert_eq!(state.phase, UpgradePhase::ServicesStopped);
        assert_eq!(state.backup_id.as_deref(), Some("backup-1"));
        cleanup(&paths);
    }

    /// Binary-switch failure triggers exactly one automatic rollback.
    #[tokio::test]
    async fn switch_failure_rolls_back_once() {
        let paths = sandbox();
        let mut io = FakeUpgradeIo::happy();
        io.switch = Err("rename failed".to_owned());
        let outcome = run_upgrade_with_paths(&io, &upgrade_args(), &paths).await;
        assert_eq!(outcome.status, UpgradeStatus::Failed);
        assert!(outcome.rollback_performed);
        assert_eq!(io.calls("rollback:backup-1"), 1, "exactly one rollback");
        assert_eq!(io.calls("commit"), 0);
        let state = UpgradeState::load(&paths.state_file);
        let Ok(state) = state else {
            assert!(false, "state must load");
            return;
        };
        assert!(state.is_none(), "a successful rollback clears the state");
        cleanup(&paths);
    }

    /// A restore-quarantine deny at the rollback mutation entry fails the
    /// upgrade without performing a rollback and preserves the failed state
    /// for an operator disposition (the automatic rollback path has no fresh
    /// acquire_lock, so the entry itself must deny).
    #[tokio::test]
    async fn rollback_entry_deny_fails_without_rollback() {
        let paths = sandbox();
        let mut io = FakeUpgradeIo::happy();
        io.switch = Err("rename failed".to_owned());
        io.rollback_entry_deny =
            Some("upgrade or rollback denied by restore quarantine: designated".to_owned());
        let outcome = run_upgrade_with_paths(&io, &upgrade_args(), &paths).await;
        assert_eq!(outcome.status, UpgradeStatus::Failed);
        assert!(
            !outcome.rollback_performed,
            "a denied rollback must not be reported as performed"
        );
        assert_eq!(io.calls("rollback:backup-1"), 1, "the entry was attempted");
        assert!(outcome.error.is_some(), "deny surfaces an error");
        let error = outcome.error.unwrap_or_default();
        assert!(
            error.contains("restore quarantine"),
            "unexpected error: {error}"
        );
        cleanup(&paths);
    }

    /// Migration failure triggers exactly one automatic rollback.
    #[tokio::test]
    async fn migration_failure_rolls_back_once() {
        let paths = sandbox();
        let mut io = FakeUpgradeIo::happy();
        io.migrate = Err("schema version mismatch".to_owned());
        let outcome = run_upgrade_with_paths(&io, &upgrade_args(), &paths).await;
        assert_eq!(outcome.status, UpgradeStatus::Failed);
        assert!(outcome.rollback_performed);
        assert_eq!(io.calls("rollback:backup-1"), 1);
        cleanup(&paths);
    }

    /// Compute startup failure triggers exactly one automatic rollback.
    #[tokio::test]
    async fn start_compute_failure_rolls_back_once() {
        let paths = sandbox();
        let mut io = FakeUpgradeIo::happy();
        io.start_compute = Err("agent never registered".to_owned());
        let outcome = run_upgrade_with_paths(&io, &upgrade_args(), &paths).await;
        assert_eq!(outcome.status, UpgradeStatus::Failed);
        assert!(outcome.rollback_performed);
        assert_eq!(io.calls("rollback:backup-1"), 1);
        cleanup(&paths);
    }

    /// An unhealthy doctor run refuses the commit and rolls back.
    #[tokio::test]
    async fn unhealthy_doctor_rolls_back() {
        let paths = sandbox();
        let mut io = FakeUpgradeIo::happy();
        io.doctor = Ok(DoctorOutcome {
            healthy: false,
            overall: "unhealthy".to_owned(),
        });
        let outcome = run_upgrade_with_paths(&io, &upgrade_args(), &paths).await;
        assert_eq!(outcome.status, UpgradeStatus::Failed);
        assert!(outcome.rollback_performed);
        assert_eq!(outcome.doctor_status.as_deref(), Some("unhealthy"));
        assert_eq!(io.calls("commit"), 0);
        assert_eq!(io.calls("rollback:backup-1"), 1);
        cleanup(&paths);
    }

    /// A public-API smoke failure rolls back instead of committing.
    #[tokio::test]
    async fn api_smoke_failure_rolls_back() {
        let paths = sandbox();
        let mut io = FakeUpgradeIo::happy();
        io.api = Err("server list mismatch".to_owned());
        let outcome = run_upgrade_with_paths(&io, &upgrade_args(), &paths).await;
        assert_eq!(outcome.status, UpgradeStatus::Failed);
        assert!(outcome.rollback_performed);
        assert_eq!(io.calls("rollback:backup-1"), 1);
        assert_eq!(io.calls("doctor"), 0, "doctor runs after the API smoke");
        cleanup(&paths);
    }

    /// When the automatic rollback also fails, the state is terminal
    /// FAILED_UPGRADE with the backup id, and the rollback runs exactly
    /// once (no endless upgrade↔rollback loop).
    #[tokio::test]
    async fn failed_rollback_persists_failed_state_without_looping() {
        let paths = sandbox();
        let mut io = FakeUpgradeIo::happy();
        io.migrate = Err("schema version mismatch".to_owned());
        io.rollback = Err("restore failed".to_owned());
        let outcome = run_upgrade_with_paths(&io, &upgrade_args(), &paths).await;
        assert_eq!(outcome.status, UpgradeStatus::Failed);
        assert!(!outcome.rollback_performed);
        assert_eq!(
            io.calls("rollback:backup-1"),
            1,
            "one automatic rollback attempt per invocation"
        );
        assert!(
            outcome
                .error
                .as_deref()
                .is_some_and(|e| e.contains("sudo o3k rollback"))
        );
        let state = UpgradeState::load(&paths.state_file);
        let Some(state) = state.ok().flatten() else {
            assert!(false, "FAILED_UPGRADE state must persist");
            return;
        };
        assert_eq!(state.phase, UpgradePhase::FailedUpgrade);
        assert_eq!(state.backup_id.as_deref(), Some("backup-1"));
        cleanup(&paths);
    }

    /// An upgrade while a FAILED_UPGRADE state exists is refused with
    /// recovery instructions and performs no work.
    #[tokio::test]
    async fn second_upgrade_while_failed_state_is_refused() {
        let paths = sandbox();
        seed_state(&paths, UpgradePhase::FailedUpgrade, Some("backup-1"));
        let io = FakeUpgradeIo::happy();
        let outcome = run_upgrade_with_paths(&io, &upgrade_args(), &paths).await;
        assert_eq!(outcome.status, UpgradeStatus::Failed);
        assert!(
            outcome
                .error
                .as_deref()
                .is_some_and(|e| e.contains("sudo o3k rollback"))
        );
        assert_eq!(io.calls("installed"), 0, "refused before any work");
        cleanup(&paths);
    }

    /// A ROLLED_BACK state (interrupted rollback) also refuses a new
    /// upgrade.
    #[tokio::test]
    async fn upgrade_while_rolled_back_state_is_refused() {
        let paths = sandbox();
        seed_state(&paths, UpgradePhase::RolledBack, Some("backup-1"));
        let io = FakeUpgradeIo::happy();
        let outcome = run_upgrade_with_paths(&io, &upgrade_args(), &paths).await;
        assert_eq!(outcome.status, UpgradeStatus::Failed);
        assert!(
            outcome
                .error
                .as_deref()
                .is_some_and(|e| e.contains("sudo o3k rollback"))
        );
        cleanup(&paths);
    }

    /// Resumption works from every post-backup phase with a valid backup.
    #[tokio::test]
    async fn resume_after_each_phase_completes() {
        for phase in [
            UpgradePhase::BackupCreated,
            UpgradePhase::ServicesStopped,
            UpgradePhase::BinariesInstalled,
            UpgradePhase::MigrationsApplied,
            UpgradePhase::ServicesStarted,
            UpgradePhase::HealthVerified,
            UpgradePhase::DoctorPassed,
            UpgradePhase::Committed,
        ] {
            let paths = sandbox();
            seed_state(&paths, phase, Some("backup-1"));
            seed_backup(&paths, "backup-1");
            let mut io = FakeUpgradeIo::happy();
            io.commit_chain = Some(paths.chain_file.clone());
            let outcome = run_upgrade_with_paths(&io, &upgrade_args(), &paths).await;
            assert!(
                outcome.status == UpgradeStatus::Committed,
                "resume from {phase:?} must commit, got {:?} ({:?})",
                outcome.status,
                outcome.error
            );
            assert_eq!(
                io.calls("create_backup"),
                0,
                "resume from {phase:?} must not re-create the backup"
            );
            assert_eq!(io.calls("commit"), 1, "resume from {phase:?} commits");
            cleanup(&paths);
        }
    }

    /// Resumption needs a valid backup; anything else fails closed.
    #[tokio::test]
    async fn resume_requires_a_valid_backup() {
        for backup in [None, Some("backup-1")] {
            let paths = sandbox();
            // MigrationsApplied with a backup id but no backup directory.
            seed_state(&paths, UpgradePhase::MigrationsApplied, backup);
            let io = FakeUpgradeIo::happy();
            let outcome = run_upgrade_with_paths(&io, &upgrade_args(), &paths).await;
            assert_eq!(outcome.status, UpgradeStatus::Failed);
            assert!(
                outcome
                    .error
                    .as_deref()
                    .is_some_and(|e| e.contains("backup")),
                "resume with {backup:?} must fail closed"
            );
            assert_eq!(io.calls("migrate"), 0, "no work before validation");
            cleanup(&paths);
        }
    }

    /// Resuming at BACKUP_CREATED without a recorded id re-runs
    /// create_backup.
    #[tokio::test]
    async fn resume_reruns_create_backup_when_no_id_recorded() {
        let paths = sandbox();
        seed_state(&paths, UpgradePhase::BackupCreated, None);
        let mut io = FakeUpgradeIo::happy();
        io.commit_chain = Some(paths.chain_file.clone());
        let outcome = run_upgrade_with_paths(&io, &upgrade_args(), &paths).await;
        assert_eq!(outcome.status, UpgradeStatus::Committed);
        assert_eq!(io.calls("create_backup"), 1);
        cleanup(&paths);
    }

    /// A leftover pre-backup state (no mutation happened) is discarded and
    /// the upgrade restarts from DISCOVERED.
    #[tokio::test]
    async fn leftover_pre_backup_state_is_discarded() {
        let paths = sandbox();
        seed_state(&paths, UpgradePhase::PreflightPassed, None);
        let mut io = FakeUpgradeIo::happy();
        io.commit_chain = Some(paths.chain_file.clone());
        let outcome = run_upgrade_with_paths(&io, &upgrade_args(), &paths).await;
        assert_eq!(outcome.status, UpgradeStatus::Committed);
        assert_eq!(io.calls("installed"), 1, "discovery re-runs");
        assert_eq!(io.calls("create_backup"), 1);
        cleanup(&paths);
    }

    /// An unreadable state file fails closed.
    #[tokio::test]
    async fn corrupt_state_file_fails_closed() {
        let paths = sandbox();
        if let Some(parent) = paths.state_file.parent() {
            let _ = std::fs::create_dir_all(parent);
        }
        let _ = std::fs::write(&paths.state_file, b"{broken");
        let io = FakeUpgradeIo::happy();
        let outcome = run_upgrade_with_paths(&io, &upgrade_args(), &paths).await;
        assert_eq!(outcome.status, UpgradeStatus::Failed);
        assert!(
            outcome
                .error
                .as_deref()
                .is_some_and(|e| e.contains("invalid"))
        );
        assert_eq!(io.calls("installed"), 0);
        cleanup(&paths);
    }

    /// A commit failure keeps the COMMITTED state so a re-run completes it.
    #[tokio::test]
    async fn commit_failure_keeps_state_for_retry() {
        let paths = sandbox();
        seed_backup(&paths, "backup-1");
        let mut io = FakeUpgradeIo::happy();
        io.commit = Err("chain unwritable".to_owned());
        let outcome = run_upgrade_with_paths(&io, &upgrade_args(), &paths).await;
        assert_eq!(outcome.status, UpgradeStatus::Failed);
        assert_eq!(
            io.calls("rollback:backup-1"),
            0,
            "commit failure never rolls back"
        );
        let state = UpgradeState::load(&paths.state_file);
        let Some(state) = state.ok().flatten() else {
            assert!(false, "COMMITTED state must persist for retry");
            return;
        };
        assert_eq!(state.phase, UpgradePhase::Committed);
        // A second run completes the commit.
        io.commit = Ok(());
        io.commit_chain = Some(paths.chain_file.clone());
        let outcome = run_upgrade_with_paths(&io, &upgrade_args(), &paths).await;
        assert_eq!(outcome.status, UpgradeStatus::Committed);
        // The second run resumed: discovery ran once in total, in the
        // first (fresh) run only.
        assert_eq!(io.calls("installed"), 1, "resumed: discovery skipped");
        cleanup(&paths);
    }

    /// Rollback happy path: chain selection, restore, chain record, state
    /// cleared.
    #[tokio::test]
    async fn rollback_restores_and_records() {
        let paths = sandbox();
        seed_backup(&paths, "backup-1");
        let chain_file = paths.chain_file.clone();
        let _ = RollbackChain::append(
            &chain_file,
            RollbackRecord {
                manifest: backup_manifest("backup-1"),
                kind: RecordKind::Backup,
            },
        );
        let io = FakeUpgradeIo::happy();
        let outcome = run_rollback_with_paths(&io, &paths).await;
        assert_eq!(outcome.status, UpgradeStatus::RolledBack);
        assert_eq!(outcome.phase, UpgradePhase::RolledBack);
        assert!(outcome.rollback_performed);
        assert_eq!(io.calls("rollback:backup-1"), 1);
        let chain = RollbackChain::load(&paths.chain_file);
        let Some(chain) = chain.ok().flatten() else {
            assert!(false, "chain must exist");
            return;
        };
        assert_eq!(chain.backups.len(), 2, "backup + rollback records");
        assert_eq!(chain.backups[1].kind, RecordKind::Rollback);
        let state = UpgradeState::load(&paths.state_file);
        let Ok(state) = state else {
            assert!(false, "state must load");
            return;
        };
        assert!(state.is_none(), "a completed rollback clears the state");
        cleanup(&paths);
    }

    /// With no chain and no state there is nothing to roll back: notice,
    /// exit-1 semantics.
    #[tokio::test]
    async fn rollback_without_backup_is_a_notice() {
        let paths = sandbox();
        let io = FakeUpgradeIo::happy();
        let outcome = run_rollback_with_paths(&io, &paths).await;
        assert_eq!(outcome.status, UpgradeStatus::Failed);
        assert!(
            outcome
                .error
                .as_deref()
                .is_some_and(|e| e.contains("nothing to roll back"))
        );
        assert_eq!(io.calls("rollback:backup-1"), 0);
        cleanup(&paths);
    }

    /// A second rollback is a no-op with a notice: rollback records are
    /// never eligible.
    #[tokio::test]
    async fn second_rollback_is_a_noop_notice() {
        let paths = sandbox();
        seed_backup(&paths, "backup-1");
        let _ = RollbackChain::append(
            &paths.chain_file,
            RollbackRecord {
                manifest: backup_manifest("backup-1"),
                kind: RecordKind::Rollback,
            },
        );
        let io = FakeUpgradeIo::happy();
        let outcome = run_rollback_with_paths(&io, &paths).await;
        assert_eq!(outcome.status, UpgradeStatus::Failed);
        assert!(
            outcome
                .error
                .as_deref()
                .is_some_and(|e| e.contains("nothing to roll back"))
        );
        assert_eq!(io.calls("rollback:backup-1"), 0);
        cleanup(&paths);
    }

    /// A FAILED_UPGRADE state selects its recorded backup even when the
    /// chain has no record yet.
    #[tokio::test]
    async fn rollback_uses_failed_state_backup_id() {
        let paths = sandbox();
        seed_state(&paths, UpgradePhase::FailedUpgrade, Some("backup-1"));
        seed_backup(&paths, "backup-1");
        let io = FakeUpgradeIo::happy();
        let outcome = run_rollback_with_paths(&io, &paths).await;
        assert_eq!(outcome.status, UpgradeStatus::RolledBack);
        assert_eq!(io.calls("rollback:backup-1"), 1);
        cleanup(&paths);
    }

    /// A failed rollback persists FAILED_UPGRADE with the backup id.
    #[tokio::test]
    async fn failed_rollback_persists_failed_state() {
        let paths = sandbox();
        seed_backup(&paths, "backup-1");
        let _ = RollbackChain::append(
            &paths.chain_file,
            RollbackRecord {
                manifest: backup_manifest("backup-1"),
                kind: RecordKind::Backup,
            },
        );
        let mut io = FakeUpgradeIo::happy();
        io.rollback = Err("restore failed".to_owned());
        let outcome = run_rollback_with_paths(&io, &paths).await;
        assert_eq!(outcome.status, UpgradeStatus::Failed);
        let state = UpgradeState::load(&paths.state_file);
        let Some(state) = state.ok().flatten() else {
            assert!(false, "FAILED_UPGRADE state must persist");
            return;
        };
        assert_eq!(state.phase, UpgradePhase::FailedUpgrade);
        assert_eq!(state.backup_id.as_deref(), Some("backup-1"));
        cleanup(&paths);
    }

    /// Resumability classification helper matches the engine rule.
    #[test]
    fn resumability_classification() {
        assert!(!is_resumable(UpgradePhase::Discovered));
        assert!(!is_resumable(UpgradePhase::PreflightPassed));
        assert!(is_resumable(UpgradePhase::BackupCreated));
        assert!(is_resumable(UpgradePhase::Committed));
        assert!(is_resumable(UpgradePhase::FailedUpgrade));
    }

    /// The FAILED_UPGRADE state survives a parse round-trip (the runner and
    /// the doctor check read it back).
    #[test]
    fn failed_state_parses_back() {
        let state = UpgradeState {
            source_version: version(0, 2, 0, &["alpha", "2"]),
            target_version: version(0, 3, 0, &["alpha", "1"]),
            phase: UpgradePhase::FailedUpgrade,
            backup_id: Some("backup-1".to_owned()),
            started_at: "2026-01-01T00:00:00Z".to_owned(),
            updated_at: "2026-01-01T00:00:00Z".to_owned(),
            rollback_performed: false,
            doctor_status: Some("unhealthy".to_owned()),
        };
        let bytes = serde_json::to_vec(&state).unwrap_or_default();
        let parsed = parse_state(&bytes);
        let Some(parsed) = parsed else {
            assert!(false, "state must parse back");
            return;
        };
        assert_eq!(parsed.phase, UpgradePhase::FailedUpgrade);
        assert_eq!(parsed.backup_id.as_deref(), Some("backup-1"));
        assert_eq!(parsed.doctor_status.as_deref(), Some("unhealthy"));
    }
}
