//! Real host implementation of [`crate::upgrade::engine::UpgradeIo`]
//! (plan §3, §5–§8, §10).
//!
//! Commands run through the bounded runner from [`crate::sys`]; downloads
//! use `curl -sfL` (guaranteed by the installer's platform guard); service
//! stop/start re-observes on timeout instead of guessing; the doctor runs
//! via the installed `o3k` binary. Every path is sandboxable through the
//! `O3K_UPGRADE_*` environment overrides so process tests never touch real
//! host state.

use crate::context::{
    DEFAULT_COMPUTE_HEALTH_ADDR, DEFAULT_LISTEN_ADDR, Exec, HttpClient, current_euid,
    parse_env_file,
};
use crate::sys::{SystemExec, SystemHttpClient, run_bounded_with_timeout, stderr_message};
use crate::upgrade::backup::{BackupManifest, RecordKind, RollbackChain, RollbackRecord};
use crate::upgrade::engine::{
    DoctorOutcome, InstalledRelease, LockGuard, UpgradeIo, VerifiedBundle,
};
use crate::upgrade::fence::{FenceError, UpgradeFence};
use crate::upgrade::state::{UpgradeState, default_state_path, env_path, write_atomic};
use crate::version::ReleaseVersion;
use async_trait::async_trait;
use sha2::{Digest, Sha256};
use sqlx::sqlite::{SqliteConnectOptions, SqlitePoolOptions};
use std::collections::BTreeMap;
use std::io::Write;
use std::path::{Path, PathBuf};
use std::process::Command;
use std::time::{Duration, Instant, SystemTime, UNIX_EPOCH};

/// GitHub Releases API for the official O3K Rust repository.
pub const DEFAULT_RELEASES_URL: &str = "https://api.github.com/repos/o3kio/o3k/releases";
/// The canonical GitHub release-asset download base. The asset naming is a
/// fixed release contract (`o3k-<version>-linux-x86_64.tar.gz(.sha256)` +
/// `install.sh` under `v<version>/`), so when the releases API is
/// unreachable the engine can construct the same URLs directly — integrity
/// still comes from the published checksums, never from the API.
pub const DEFAULT_DOWNLOAD_BASE: &str = "https://github.com/o3kio/o3k/releases/download";
/// Bound on release-asset downloads (a release is tens of MB).
const DOWNLOAD_TIMEOUT: Duration = Duration::from_secs(300);
/// Bound on the GitHub API call.
const API_TIMEOUT: Duration = Duration::from_secs(60);
/// Bound on one systemctl stop/start invocation.
const SERVICE_TIMEOUT: Duration = Duration::from_secs(120);
/// Bound on service state re-observation after a timeout.
const OBSERVE_TIMEOUT: Duration = Duration::from_secs(60);
/// Bound on the doctor invocation.
const DOCTOR_TIMEOUT: Duration = Duration::from_secs(180);
/// Bound on archive listing/extraction.
const TAR_TIMEOUT: Duration = Duration::from_secs(120);
/// Disk-space floor for an upgrade (200 MB, plan §5).
const DISK_FLOOR_BYTES: u64 = 200 * 1024 * 1024;
/// Backup size factor over the current database size (plan §5).
const DISK_DB_FACTOR_NUMERATOR: u64 = 5;
const DISK_DB_FACTOR_DENOMINATOR: u64 = 2;
/// Upper bound on a file the runner will hash into memory.
const MAX_HASH_BYTES: u64 = 512 * 1024 * 1024;

/// The installed binaries of the libvirt profile.
const BINARIES: [&str; 3] = ["o3kd", "o3k", "o3k-compute"];

/// The real [`UpgradeIo`]. All paths resolve from the `O3K_UPGRADE_*`
/// environment overrides at construction time.
pub struct SystemUpgradeIo {
    pub prefix: PathBuf,
    pub bin_dir: PathBuf,
    pub config_dir: PathBuf,
    pub data_dir: PathBuf,
    pub state_file: PathBuf,
    pub backup_dir: PathBuf,
    pub download_dir: PathBuf,
    pub releases_url: String,
    pub download_base: String,
}

impl SystemUpgradeIo {
    /// Resolves the sandboxable paths from the process environment.
    #[must_use]
    pub fn from_env() -> Self {
        let prefix = env_path("O3K_UPGRADE_PREFIX").unwrap_or_else(|| PathBuf::from("/usr/local"));
        let data_dir = crate::upgrade::state::default_data_dir();
        Self {
            bin_dir: env_path("O3K_UPGRADE_BIN_DIR").unwrap_or_else(|| prefix.join("bin")),
            config_dir: env_path("O3K_UPGRADE_CONFIG_DIR")
                .unwrap_or_else(|| PathBuf::from("/etc/o3k")),
            data_dir: data_dir.clone(),
            state_file: default_state_path(),
            backup_dir: crate::upgrade::backup::default_backup_dir(),
            download_dir: env_path("O3K_UPGRADE_DOWNLOAD_DIR")
                .unwrap_or_else(|| data_dir.join("upgrade-download")),
            releases_url: std::env::var("O3K_UPGRADE_RELEASES_URL")
                .unwrap_or_else(|_| DEFAULT_RELEASES_URL.to_owned()),
            download_base: std::env::var("O3K_UPGRADE_DOWNLOAD_BASE")
                .unwrap_or_else(|_| DEFAULT_DOWNLOAD_BASE.to_owned()),
            prefix,
        }
    }

    /// The lock file guarding concurrent invocations. Derived from the
    /// state-file path so sandbox overrides apply (same exclusivity
    /// semantics as the plan's `/run/lock` flock: a live holder refuses,
    /// a dead holder's lock is reclaimed).
    #[must_use]
    fn lock_path(&self) -> PathBuf {
        let mut name = self.state_file.as_os_str().to_os_string();
        name.push(".lock");
        PathBuf::from(name)
    }

    /// Re-evaluate the original upgrade path when the binary switch has
    /// already installed the target manifest. The persisted attempt and its
    /// matching backup are required; ordinary same-version upgrades stay denied.
    fn validate_bundle_upgrade_fence(
        &self,
        installed: &InstalledRelease,
        target: &ReleaseVersion,
        target_profile: &str,
        min_version: Option<&str>,
    ) -> Result<(), FenceError> {
        let decide = |source| {
            UpgradeFence::from_manifest_values(
                source,
                target.clone(),
                &installed.profile,
                target_profile,
                min_version,
            )?
            .decide()
        };
        match decide(installed.version.clone()) {
            Err(FenceError::SameVersion) => {
                let source = self.resume_source(target).ok_or(FenceError::SameVersion)?;
                decide(source)
            }
            result => result,
        }
    }

    fn resume_source(&self, target: &ReleaseVersion) -> Option<ReleaseVersion> {
        use crate::upgrade::state::UpgradePhase;
        let state = UpgradeState::load(&self.state_file).ok()??;
        // BinariesInstalled is persisted before the switch. Earlier phases
        // cannot legitimately have installed the target; terminal states
        // cannot authorize a new attempt.
        if state.target_version != *target
            || !matches!(
                state.phase,
                UpgradePhase::BinariesInstalled
                    | UpgradePhase::MigrationsApplied
                    | UpgradePhase::ServicesStarted
                    | UpgradePhase::HealthVerified
                    | UpgradePhase::DoctorPassed
            )
            || state.rollback_performed
        {
            return None;
        }
        let backup_id = state.backup_id.as_deref()?;
        let mut components = Path::new(backup_id).components();
        if !matches!(components.next(), Some(std::path::Component::Normal(_)))
            || components.next().is_some()
        {
            return None;
        }
        let bytes = std::fs::read(self.backup_dir.join(backup_id).join("backup.json")).ok()?;
        let backup = BackupManifest::validate(&bytes).ok()?;
        (backup.backup_id == backup_id
            && backup.source_version == state.source_version
            && backup.target_version == state.target_version)
            .then_some(state.source_version)
    }

    /// Installed share directory (`<prefix>/share/o3k`).
    #[must_use]
    fn share_dir(&self) -> PathBuf {
        self.prefix.join("share/o3k")
    }

    /// The control-plane SQLite database.
    #[must_use]
    fn database_path(&self) -> PathBuf {
        self.data_dir.join("o3k.sqlite")
    }

    /// The bundle directory for a target version inside the download dir.
    #[must_use]
    fn bundle_dir_for(&self, target: &ReleaseVersion) -> PathBuf {
        self.download_dir.join(format!("o3k-{target}"))
    }

    /// SHA-256 (lowercase hex) of a file's bytes.
    fn sha256_file(path: &Path) -> Result<String, String> {
        let size = std::fs::metadata(path)
            .map_err(|error| format!("cannot stat {}: {error}", path.display()))?
            .len();
        if size > MAX_HASH_BYTES {
            return Err(format!("{} is too large to hash", path.display()));
        }
        let bytes = std::fs::read(path)
            .map_err(|error| format!("cannot read {}: {error}", path.display()))?;
        let digest = Sha256::digest(&bytes);
        let mut hex = String::with_capacity(64);
        for byte in digest {
            use std::fmt::Write as _;
            let _ = write!(hex, "{byte:02x}");
        }
        Ok(hex)
    }

    /// Whether a pid describes a live (non-zombie) process, mirroring
    /// [`SystemExec::proc_alive`].
    fn pid_alive(pid: u32) -> bool {
        let Ok(stat) = std::fs::read_to_string(format!("/proc/{pid}/stat")) else {
            return false;
        };
        stat.split_whitespace().nth(2) != Some("Z")
    }

    /// `curl -sfL <url>` with the output captured on stdout.
    async fn curl_stdout(&self, url: &str, timeout: Duration) -> Result<String, String> {
        let mut command = Command::new("curl");
        command.args(["-sfL", "--max-time", &format!("{}", timeout.as_secs()), url]);
        self.run_curl(&mut command, url, timeout)
            .await
            .map(|bytes| String::from_utf8_lossy(&bytes).into_owned())
    }

    /// `curl -sfL -o <dest> <url>`.
    async fn curl_to_file(&self, url: &str, dest: &Path, timeout: Duration) -> Result<(), String> {
        let mut command = Command::new("curl");
        command.args([
            "-sfL",
            "--max-time",
            &format!("{}", timeout.as_secs()),
            "-o",
            &dest.display().to_string(),
            url,
        ]);
        self.run_curl(&mut command, url, timeout).await.map(|_| ())
    }

    /// Shared bounded curl runner.
    async fn run_curl(
        &self,
        command: &mut Command,
        url: &str,
        timeout: Duration,
    ) -> Result<Vec<u8>, String> {
        match run_bounded_with_timeout(command, timeout + Duration::from_secs(30)) {
            Ok(outcome) if outcome.completed && outcome.output.status.success() => {
                Ok(outcome.output.stdout)
            }
            Ok(outcome) if !outcome.completed => Err(format!("curl {url} timed out")),
            Ok(outcome) => Err(stderr_message(&outcome.output)),
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => {
                Err("curl is not installed (required by the installer's platform guard)".to_owned())
            }
            Err(error) => Err(format!("curl failed to start: {error}")),
        }
    }

    /// Lists a tarball's entries (`tar -tzf` / `tar -tvzf`).
    fn tar_listing(tarball: &Path, listing: &str) -> Result<String, String> {
        let mut command = Command::new("tar");
        command.arg(listing).arg(tarball);
        match run_bounded_with_timeout(&mut command, TAR_TIMEOUT) {
            Ok(outcome) if outcome.completed && outcome.output.status.success() => {
                Ok(String::from_utf8_lossy(&outcome.output.stdout).into_owned())
            }
            Ok(outcome) if !outcome.completed => {
                Err(format!("tar listing of {} timed out", tarball.display()))
            }
            Ok(outcome) => Err(stderr_message(&outcome.output)),
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => {
                Err("tar is not installed".to_owned())
            }
            Err(error) => Err(format!("tar failed to start: {error}")),
        }
    }

    /// Extracts a tarball into a directory (`tar -xzf -C`).
    fn tar_extract(tarball: &Path, destination: &Path) -> Result<(), String> {
        let mut command = Command::new("tar");
        command.arg("-xzf").arg(tarball).arg("-C").arg(destination);
        match run_bounded_with_timeout(&mut command, TAR_TIMEOUT) {
            Ok(outcome) if outcome.completed && outcome.output.status.success() => Ok(()),
            Ok(outcome) if !outcome.completed => {
                Err(format!("extraction of {} timed out", tarball.display()))
            }
            Ok(outcome) => Err(stderr_message(&outcome.output)),
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => {
                Err("tar is not installed".to_owned())
            }
            Err(error) => Err(format!("tar failed to start: {error}")),
        }
    }

    /// Copies `src` onto `dest` atomically with the given mode (temp file in
    /// the destination directory + rename).
    fn install_file(src: &Path, dest: &Path, mode: u32) -> Result<(), String> {
        use std::os::unix::fs::PermissionsExt;
        let parent = dest
            .parent()
            .ok_or_else(|| format!("{} has no parent directory", dest.display()))?;
        if !parent.is_dir() {
            return Err(format!("{} is not a directory", parent.display()));
        }
        let name = dest
            .file_name()
            .and_then(|name| name.to_str())
            .ok_or_else(|| format!("{} has no file name", dest.display()))?;
        // create_new: a pre-placed symlink/regular file at the temp path can
        // never redirect the copy (root runs this, but defense in depth).
        let temp = parent.join(format!(".{name}.{}.tmp", std::process::id()));
        let result = (|| -> std::io::Result<()> {
            let mut target = std::fs::OpenOptions::new()
                .write(true)
                .create_new(true)
                .open(&temp)?;
            std::io::copy(&mut std::fs::File::open(src)?, &mut target)?;
            drop(target);
            std::fs::set_permissions(&temp, std::fs::Permissions::from_mode(mode))?;
            std::fs::rename(&temp, dest)?;
            // Best-effort durability of the rename.
            let _ = std::fs::File::open(parent).and_then(|dir| dir.sync_all());
            Ok(())
        })();
        if let Err(error) = result {
            let _ = std::fs::remove_file(&temp);
            return Err(format!(
                "cannot install {} as {}: {error}",
                src.display(),
                dest.display()
            ));
        }
        Ok(())
    }

    /// Recursively copies regular files and directories, preserving modes.
    fn copy_tree(src: &Path, dest: &Path) -> Result<(), String> {
        let metadata = std::fs::metadata(src)
            .map_err(|error| format!("cannot stat {}: {error}", src.display()))?;
        if metadata.is_dir() {
            std::fs::create_dir_all(dest)
                .map_err(|error| format!("cannot create {}: {error}", dest.display()))?;
            Self::copy_mode(src, dest)?;
            let entries = std::fs::read_dir(src)
                .map_err(|error| format!("cannot list {}: {error}", src.display()))?;
            for entry in entries {
                let entry =
                    entry.map_err(|error| format!("cannot list {}: {error}", src.display()))?;
                let name = entry.file_name();
                Self::copy_tree(&entry.path(), &dest.join(name))?;
            }
            Ok(())
        } else if metadata.is_file() {
            Self::install_file(src, dest, Self::mode_of(src)?)
        } else {
            Err(format!(
                "unsupported entry type in {} (only regular files and directories are backed up)",
                src.display()
            ))
        }
    }

    /// Permission bits of a path (`mode & 0o7777`).
    fn mode_of(path: &Path) -> Result<u32, String> {
        use std::os::unix::fs::PermissionsExt;
        let metadata = std::fs::metadata(path)
            .map_err(|error| format!("cannot stat {}: {error}", path.display()))?;
        Ok(metadata.permissions().mode() & 0o7777)
    }

    /// Copies a path's permission bits onto another path.
    fn copy_mode(src: &Path, dest: &Path) -> Result<(), String> {
        use std::os::unix::fs::PermissionsExt;
        let mode = Self::mode_of(src)?;
        std::fs::set_permissions(dest, std::fs::Permissions::from_mode(mode))
            .map_err(|error| format!("cannot set mode on {}: {error}", dest.display()))
    }

    /// Opens a read-write SQLite connection (busy timeout; used for the
    /// WAL checkpoint and the VACUUM INTO snapshot).
    async fn open_connection(
        &self,
        path: &Path,
    ) -> Result<sqlx::pool::PoolConnection<sqlx::Sqlite>, String> {
        let options = SqliteConnectOptions::new()
            .filename(path)
            .create_if_missing(false)
            .busy_timeout(Duration::from_secs(30));
        let pool = SqlitePoolOptions::new()
            .max_connections(1)
            .acquire_timeout(Duration::from_secs(10))
            .connect_with(options)
            .await
            .map_err(|error| format!("database is not readable: {error}"))?;
        pool.acquire()
            .await
            .map_err(|error| format!("database is not readable: {error}"))
    }

    /// Opens a read-only SQLite connection.
    async fn open_read_only_connection(
        &self,
        path: &Path,
    ) -> Result<sqlx::pool::PoolConnection<sqlx::Sqlite>, String> {
        let options = SqliteConnectOptions::new()
            .filename(path)
            .read_only(true)
            .create_if_missing(false);
        let pool = SqlitePoolOptions::new()
            .max_connections(1)
            .acquire_timeout(Duration::from_secs(10))
            .connect_with(options)
            .await
            .map_err(|error| format!("database is not readable: {error}"))?;
        pool.acquire()
            .await
            .map_err(|error| format!("database is not readable: {error}"))
    }

    /// Maximum applied migration version from `_sqlx_migrations` (plain
    /// sqlx — the upgrade engine never links the concrete store).
    async fn schema_version(&self, db: &Path) -> Result<i64, String> {
        let mut connection = self.open_read_only_connection(db).await?;
        let row: Option<i64> = sqlx::query_scalar("SELECT MAX(version) FROM _sqlx_migrations")
            .fetch_one(&mut *connection)
            .await
            .map_err(|error| format!("schema version query failed: {error}"))?;
        row.ok_or_else(|| "the _sqlx_migrations table has no rows".to_owned())
    }

    /// `PRAGMA quick_check` must report `ok`.
    async fn quick_check(&self, path: &Path) -> Result<(), String> {
        let mut connection = self.open_read_only_connection(path).await?;
        let row: String = sqlx::query_scalar("PRAGMA quick_check")
            .fetch_one(&mut *connection)
            .await
            .map_err(|error| format!("integrity check failed: {error}"))?;
        if row == "ok" {
            Ok(())
        } else {
            Err(format!("quick_check reported: {row}"))
        }
    }

    /// WAL checkpoint before the snapshot (mirrors the store's
    /// backup-to-file ordering).
    async fn checkpoint(&self, db: &Path) -> Result<(), String> {
        let mut connection = self.open_connection(db).await?;
        let _row: (i64, i64, i64) = sqlx::query_as("PRAGMA wal_checkpoint(FULL)")
            .fetch_one(&mut *connection)
            .await
            .map_err(|error| format!("WAL checkpoint failed: {error}"))?;
        Ok(())
    }

    /// `VACUUM INTO <target>` — the crash-consistent snapshot.
    async fn vacuum_into(&self, db: &Path, target: &Path) -> Result<(), String> {
        let mut connection = self.open_connection(db).await?;
        let escaped = target.display().to_string().replace('\'', "''");
        sqlx::query(&format!("VACUUM INTO '{escaped}'"))
            .execute(&mut *connection)
            .await
            .map_err(|error| format!("database snapshot failed: {error}"))?;
        Ok(())
    }

    /// The target release's manifest from the download dir.
    fn bundle_manifest(&self, target: &ReleaseVersion) -> Result<serde_json::Value, String> {
        let path = self.bundle_dir_for(target).join("manifest.json");
        let contents = std::fs::read_to_string(&path).map_err(|error| {
            format!(
                "the target release manifest is missing from {}: {error}",
                path.display()
            )
        })?;
        serde_json::from_str(&contents)
            .map_err(|error| format!("the target release manifest is not valid JSON: {error}"))
    }

    /// The declared schema version of the target release (fail closed when
    /// absent, plan §7). make-release.sh emits it as a JSON string
    /// (`"17"`), so both string and number forms are accepted.
    fn target_schema_version(&self, target: &ReleaseVersion) -> Result<i64, String> {
        let manifest = self.bundle_manifest(target)?;
        let declared = manifest
            .get("schema_version")
            .and_then(|value| {
                value
                    .as_i64()
                    .or_else(|| value.as_str().and_then(|text| text.parse::<i64>().ok()))
            })
            .ok_or_else(|| {
                "the target release manifest does not declare schema_version; refusing to \
                 decide migration compatibility"
                    .to_owned()
            })?;
        Ok(declared)
    }

    /// The control-plane listen address from the installed env file.
    fn listen_addr(&self) -> String {
        parse_env_file(&self.config_dir.join("o3kd.env"))
            .get("O3K_LISTEN_ADDR")
            .cloned()
            .unwrap_or_else(|| DEFAULT_LISTEN_ADDR.to_owned())
    }

    /// The compute-agent health address from the installed env file.
    fn compute_health_addr(&self) -> String {
        parse_env_file(&self.config_dir.join("o3k-compute.env"))
            .get("O3K_COMPUTE_HEALTH_ADDR")
            .cloned()
            .unwrap_or_else(|| DEFAULT_COMPUTE_HEALTH_ADDR.to_owned())
    }

    /// Stops one systemd unit: bounded stop, then re-observation until the
    /// unit is inactive (a timeout is an unknown outcome, never a guess).
    async fn stop_unit(&self, unit: &str) -> Result<(), String> {
        let mut command = Command::new("systemctl");
        command.args(["stop", unit]);
        match run_bounded_with_timeout(&mut command, SERVICE_TIMEOUT) {
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => {
                return Err("systemctl is not installed".to_owned());
            }
            Err(error) => return Err(format!("systemctl failed to start: {error}")),
            Ok(_) => {}
        }
        let exec = SystemExec::new(current_euid() == 0);
        let deadline = Instant::now() + OBSERVE_TIMEOUT;
        loop {
            let state = exec.systemctl_is_active(unit).await;
            match state {
                crate::context::UnitState::Inactive | crate::context::UnitState::NotFound => {
                    return Ok(());
                }
                crate::context::UnitState::Failed => {
                    return Err(format!("{unit} failed while stopping"));
                }
                crate::context::UnitState::Active | crate::context::UnitState::Unknown => {}
            }
            if Instant::now() >= deadline {
                return Err(format!("{unit} did not stop in time"));
            }
            tokio::time::sleep(Duration::from_secs(2)).await;
        }
    }

    /// Starts one systemd unit and waits until it reports active.
    async fn start_unit(&self, unit: &str) -> Result<(), String> {
        let mut command = Command::new("systemctl");
        command.args(["start", unit]);
        let outcome = match run_bounded_with_timeout(&mut command, SERVICE_TIMEOUT) {
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => {
                return Err("systemctl is not installed".to_owned());
            }
            Err(error) => return Err(format!("systemctl failed to start: {error}")),
            Ok(outcome) => outcome,
        };
        if outcome.completed && !outcome.output.status.success() {
            return Err(format!(
                "systemctl start {unit}: {}",
                stderr_message(&outcome.output)
            ));
        }
        let exec = SystemExec::new(current_euid() == 0);
        let deadline = Instant::now() + OBSERVE_TIMEOUT;
        loop {
            let state = exec.systemctl_is_active(unit).await;
            match state {
                crate::context::UnitState::Active => return Ok(()),
                crate::context::UnitState::Failed => {
                    return Err(format!("{unit} failed while starting"));
                }
                crate::context::UnitState::Inactive
                | crate::context::UnitState::NotFound
                | crate::context::UnitState::Unknown => {}
            }
            if Instant::now() >= deadline {
                return Err(format!("{unit} did not become active in time"));
            }
            tokio::time::sleep(Duration::from_secs(2)).await;
        }
    }

    /// Waits until a local HTTP endpoint answers 200.
    async fn wait_http_ready(&self, url: &str) -> Result<(), String> {
        let client = SystemHttpClient;
        let deadline = Instant::now() + OBSERVE_TIMEOUT;
        loop {
            match client.get(url).await {
                Ok(response) if response.status == 200 => return Ok(()),
                _ => {}
            }
            if Instant::now() >= deadline {
                return Err(format!("{url} never became ready"));
            }
            tokio::time::sleep(Duration::from_secs(2)).await;
        }
    }

    /// Runs `o3k doctor --json` (from PATH so test sandboxes can shim it;
    /// on a real host PATH resolves the installed binary) and parses the
    /// report. The doctor's sandbox overrides (O3K_DOCTOR_*) pass through
    /// the inherited environment.
    async fn doctor_report(&self) -> Result<serde_json::Value, String> {
        let mut command = Command::new("o3k");
        command.args(["doctor", "--json"]);
        match run_bounded_with_timeout(&mut command, DOCTOR_TIMEOUT) {
            Ok(outcome) if outcome.completed && outcome.output.status.success() => {
                let stdout = String::from_utf8_lossy(&outcome.output.stdout);
                serde_json::from_str(&stdout)
                    .map_err(|error| format!("doctor output is not JSON: {error}"))
            }
            Ok(outcome) if !outcome.completed => Err("o3k doctor timed out".to_owned()),
            Ok(outcome) => {
                // Doctor prints its JSON report to stdout and exits 1 for
                // BOTH warning and unhealthy installations (stderr is often
                // empty). The upgrade gate accepts healthy AND warning, so
                // parse the stdout and only fail on `unhealthy` — or when
                // no report can be parsed at all.
                let stdout = String::from_utf8_lossy(&outcome.output.stdout);
                let report = serde_json::from_str::<serde_json::Value>(&stdout);
                match report {
                    Ok(report) => {
                        let overall = report
                            .get("overall_status")
                            .and_then(serde_json::Value::as_str)
                            .unwrap_or("unknown");
                        if overall == "healthy" || overall == "warning" {
                            return Ok(report);
                        }
                        let failing = report
                            .get("checks")
                            .and_then(serde_json::Value::as_array)
                            .map(|checks| {
                                checks
                                    .iter()
                                    .filter(|check| {
                                        check.get("status").and_then(serde_json::Value::as_str)
                                            == Some("FAIL")
                                    })
                                    .filter_map(|check| {
                                        check.get("id").and_then(serde_json::Value::as_str)
                                    })
                                    .collect::<Vec<_>>()
                                    .join(", ")
                            })
                            .unwrap_or_default();
                        let summary = if failing.is_empty() {
                            format!("overall {overall}")
                        } else {
                            format!("overall {overall}; FAIL: {failing}")
                        };
                        Err(format!(
                            "o3k doctor reported an unhealthy installation: {summary}"
                        ))
                    }
                    Err(_) => {
                        let stderr = stderr_message(&outcome.output);
                        if stderr == "command failed without a message" {
                            Err("o3k doctor exited non-zero without a report".to_owned())
                        } else {
                            Err(stderr)
                        }
                    }
                }
            }
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => {
                Err("o3k is not installed (PATH lookup failed)".to_owned())
            }
            Err(error) => Err(format!("o3k doctor failed to start: {error}")),
        }
    }

    /// Parses `hash  ./path` sums lines into `name -> hash` for the
    /// installed binaries.
    fn parse_sums_entries(contents: &str) -> BTreeMap<String, String> {
        let mut entries = BTreeMap::new();
        for line in contents.lines() {
            let mut fields = line.split_whitespace();
            let Some(hash) = fields.next() else {
                continue;
            };
            let Some(path) = fields.next() else {
                continue;
            };
            let name = path.rsplit('/').next().unwrap_or(path);
            if BINARIES.contains(&name) {
                entries.insert(name.to_owned(), hash.to_owned());
            }
        }
        entries
    }

    /// Asserts the installed ownership manifest parses and every entry
    /// exists (preflight, read-only).
    fn check_ownership_manifest(&self) -> Result<(), String> {
        let manifest = self.share_dir().join(".o3k-installed");
        let contents = std::fs::read_to_string(&manifest)
            .map_err(|error| format!("cannot read {}: {error}", manifest.display()))?;
        let mut lines = contents.lines();
        let header = lines
            .next()
            .ok_or_else(|| "the ownership manifest is empty".to_owned())?;
        if header != format!("o3k-installed-v1 prefix={}", self.prefix.display()) {
            return Err(format!("unrecognized ownership manifest header: {header}"));
        }
        for entry in lines {
            let entry = entry.trim();
            if entry.is_empty() {
                continue;
            }
            if !self.prefix.join(entry).is_file() {
                return Err(format!("missing installed file: {entry}"));
            }
        }
        Ok(())
    }

    /// Asserts the installed binaries match the installed SHA256SUMS
    /// (preflight, read-only; a mismatch is never silently upgraded).
    fn check_installed_binary_hashes(&self) -> Result<(), String> {
        let sums = self.share_dir().join("SHA256SUMS");
        if !sums.is_file() {
            // No reference exists: doctor warns; the preflight only refuses
            // on a proven mismatch (plan §5 "where it exists").
            return Ok(());
        }
        let contents = std::fs::read_to_string(&sums)
            .map_err(|error| format!("cannot read {}: {error}", sums.display()))?;
        let entries = Self::parse_sums_entries(&contents);
        for name in BINARIES {
            let Some(expected) = entries.get(name) else {
                return Err(format!(
                    "no reference hash for {name} in the installed SHA256SUMS"
                ));
            };
            let actual = Self::sha256_file(&self.bin_dir.join(name))?;
            if !actual.eq_ignore_ascii_case(expected) {
                return Err(format!(
                    "installed binary {name} does not match the installed SHA256SUMS; \
                     refusing to upgrade a modified installation"
                ));
            }
        }
        Ok(())
    }

    /// Asserts the preflight doctor gate: no FAIL in the release category.
    async fn check_doctor_gate(&self) -> Result<(), String> {
        let report = self.doctor_report().await?;
        let checks = report
            .get("checks")
            .and_then(serde_json::Value::as_array)
            .map(Vec::as_slice)
            .unwrap_or(&[]);
        for check in checks {
            let category = check.get("category").and_then(serde_json::Value::as_str);
            let status = check.get("status").and_then(serde_json::Value::as_str);
            if category == Some("release") && status == Some("FAIL") {
                let id = check
                    .get("id")
                    .and_then(serde_json::Value::as_str)
                    .unwrap_or("unknown");
                let summary = check
                    .get("summary")
                    .and_then(serde_json::Value::as_str)
                    .unwrap_or("");
                return Err(format!(
                    "doctor reports a release-blocking failure: {id}: {summary}"
                ));
            }
        }
        Ok(())
    }

    /// Asserts supported distro and architecture (plan §5).
    fn check_platform(&self) -> Result<(), String> {
        let contents = std::fs::read_to_string("/etc/os-release")
            .map_err(|error| format!("cannot read /etc/os-release: {error}"))?;
        let mut id = None;
        let mut version_id = None;
        for line in contents.lines() {
            let Some((key, value)) = line.split_once('=') else {
                continue;
            };
            let value = value.trim().trim_matches('"');
            match key {
                "ID" => id = Some(value.to_owned()),
                "VERSION_ID" => version_id = Some(value.to_owned()),
                _ => {}
            }
        }
        let os_supported = matches!(
            (id.as_deref(), version_id.as_deref()),
            (Some("ubuntu"), Some("24.04")) | (Some("debian"), Some("12"))
        );
        let arch_ok = std::env::consts::ARCH == "x86_64";
        if os_supported && arch_ok {
            return Ok(());
        }
        Err(format!(
            "unsupported platform: {} {} on {} (supported: ubuntu 24.04 or debian 12 on x86_64)",
            id.unwrap_or_else(|| "unknown".to_owned()),
            version_id.unwrap_or_else(|| "unknown".to_owned()),
            std::env::consts::ARCH
        ))
    }

    /// Asserts enough free disk for the upgrade (plan §5: 2.5x DB size +
    /// 200 MB floor plus the extracted bundle, measured).
    async fn check_disk_space(&self, bundle: &VerifiedBundle) -> Result<(), String> {
        let db_size = std::fs::metadata(self.database_path())
            .map(|metadata| metadata.len())
            .unwrap_or(0);
        let bundle_size = Self::dir_size(&bundle.dir);
        let required = DISK_FLOOR_BYTES
            + db_size.saturating_mul(DISK_DB_FACTOR_NUMERATOR) / DISK_DB_FACTOR_DENOMINATOR
            + bundle_size;
        let probe = Self::nearest_existing_ancestor(&self.data_dir);
        let exec = SystemExec::new(current_euid() == 0);
        let available_kib = exec.df_avail_kib(&probe).await?;
        let available = available_kib.saturating_mul(1024);
        if available < required {
            return Err(format!(
                "not enough free disk on {}: need at least {} MiB, have {} MiB",
                probe.display(),
                required / (1024 * 1024),
                available / (1024 * 1024)
            ));
        }
        Ok(())
    }

    /// Recursive size of a directory (0 when absent).
    fn dir_size(dir: &Path) -> u64 {
        let Ok(entries) = std::fs::read_dir(dir) else {
            return 0;
        };
        let mut total = 0;
        for entry in entries.flatten() {
            let path = entry.path();
            total += match std::fs::metadata(&path) {
                Ok(metadata) if metadata.is_dir() => Self::dir_size(&path),
                Ok(metadata) => metadata.len(),
                Err(_) => 0,
            };
        }
        total
    }

    /// Walks up to the nearest existing ancestor (mirrors the preflight
    /// script's space probe).
    fn nearest_existing_ancestor(path: &Path) -> PathBuf {
        let mut current = path.to_path_buf();
        while !current.exists() {
            let Some(parent) = current.parent() else {
                return PathBuf::from("/");
            };
            if parent == current {
                return PathBuf::from("/");
            }
            current = parent.to_path_buf();
        }
        current
    }

    /// Looks the target's asset URLs up through the releases API (primary
    /// source; the caller falls back to the canonical naming contract).
    async fn release_assets_from_api(
        &self,
        target: &ReleaseVersion,
        tarball_name: &str,
    ) -> Result<ReleaseAssets, String> {
        let body = self.curl_stdout(&self.releases_url, API_TIMEOUT).await?;
        let value: serde_json::Value = serde_json::from_str(&body)
            .map_err(|error| format!("releases API response is not JSON: {error}"))?;
        let releases = value
            .as_array()
            .ok_or_else(|| "releases API response is not a list".to_owned())?;
        for release in releases {
            let assets = release
                .get("assets")
                .and_then(serde_json::Value::as_array)
                .cloned()
                .unwrap_or_default();
            let find = |name: &str| -> Option<String> {
                assets
                    .iter()
                    .find(|asset| {
                        asset.get("name").and_then(serde_json::Value::as_str) == Some(name)
                    })
                    .and_then(|asset| {
                        asset
                            .get("browser_download_url")
                            .and_then(serde_json::Value::as_str)
                            .map(str::to_owned)
                    })
            };
            if find(tarball_name).is_none() {
                continue;
            }
            let tarball = find(tarball_name)
                .ok_or_else(|| format!("the release asset {tarball_name} has no download URL"))?;
            let sha256 = find(&format!("{tarball_name}.sha256"));
            let install = find("install.sh");
            return match (sha256, install) {
                (Some(sha256), Some(install)) => Ok(ReleaseAssets {
                    tarball,
                    sha256,
                    install,
                }),
                _ => Err(
                    "the release assets are incomplete (missing .sha256 or install.sh)".to_owned(),
                ),
            };
        }
        Err(format!("no published release asset found for o3k-{target}"))
    }

    /// Fetches the official release asset URLs for a target version. The
    /// releases API is the primary source; when it is unreachable, empty,
    /// or missing the target's assets, the canonical asset naming contract
    /// is used directly against the download base (integrity still comes
    /// from the published checksums, never from the API).
    async fn fetch_release_assets(&self, target: &ReleaseVersion) -> Result<ReleaseAssets, String> {
        let tarball_name = format!("o3k-{target}-linux-x86_64.tar.gz");
        match self.release_assets_from_api(target, &tarball_name).await {
            Ok(assets) => Ok(assets),
            Err(_api_error) => {
                // Canonical fallback: the asset naming is a fixed release
                // contract; checksum verification still gates integrity.
                Ok(Self::canonical_assets(
                    &self.download_base,
                    target,
                    &tarball_name,
                ))
            }
        }
    }

    /// The canonical asset URLs under the download base (the release asset
    /// naming contract, independent of the API).
    #[must_use]
    fn canonical_assets(base: &str, target: &ReleaseVersion, tarball_name: &str) -> ReleaseAssets {
        let base = base.trim_end_matches('/');
        ReleaseAssets {
            tarball: format!("{base}/v{target}/{tarball_name}"),
            sha256: format!("{base}/v{target}/{tarball_name}.sha256"),
            install: format!("{base}/v{target}/install.sh"),
        }
    }

    /// Resolves the newest published release in the installed channel
    /// family (plan §3).
    async fn latest_published(&self, installed: &ReleaseVersion) -> Result<ReleaseVersion, String> {
        let body = self.curl_stdout(&self.releases_url, API_TIMEOUT).await?;
        let value: serde_json::Value = serde_json::from_str(&body)
            .map_err(|error| format!("releases API response is not JSON: {error}"))?;
        let releases = value
            .as_array()
            .ok_or_else(|| "releases API response is not a list".to_owned())?;
        let mut best: Option<ReleaseVersion> = None;
        for release in releases {
            let assets = release
                .get("assets")
                .and_then(serde_json::Value::as_array)
                .cloned()
                .unwrap_or_default();
            for asset in assets {
                let Some(name) = asset.get("name").and_then(serde_json::Value::as_str) else {
                    continue;
                };
                let Some(version) = version_from_asset_name(name) else {
                    continue;
                };
                if version.channel() == installed.channel()
                    && version > *installed
                    && best.as_ref().is_none_or(|current| version > *current)
                {
                    best = Some(version);
                }
            }
        }
        best.ok_or_else(|| {
            format!(
                "no newer release found in the {} channel family",
                installed.channel()
            )
        })
    }

    /// Validates and extracts the tarball; returns the bundle directory.
    async fn extract_bundle(
        &self,
        tarball: &Path,
        target: &ReleaseVersion,
        work: &Path,
    ) -> Result<PathBuf, String> {
        validate_tar_entries(tarball)?;
        let extract = work.join("extract");
        std::fs::create_dir_all(&extract)
            .map_err(|error| format!("cannot create {}: {error}", extract.display()))?;
        Self::tar_extract(tarball, &extract)?;
        let bundle_dir = extract.join(format!("o3k-{target}"));
        if !bundle_dir.is_dir() {
            return Err(format!(
                "the release archive does not contain the expected bundle directory: o3k-{target}"
            ));
        }
        Ok(bundle_dir)
    }

    /// Asserts the bundle's SHA256SUMS covers exactly the extracted
    /// regular files (the sums file itself is not self-listed).
    fn verify_sums_coverage(&self, bundle_dir: &Path) -> Result<(), String> {
        let sums = bundle_dir.join("SHA256SUMS");
        let contents = std::fs::read_to_string(&sums)
            .map_err(|error| format!("cannot read {}: {error}", sums.display()))?;
        let mut entries: BTreeMap<String, String> = BTreeMap::new();
        for line in contents.lines() {
            let mut fields = line.split_whitespace();
            let Some(hash) = fields.next() else {
                continue;
            };
            let Some(path) = fields.next() else {
                continue;
            };
            entries.insert(path.to_owned(), hash.to_lowercase());
        }
        if entries.is_empty() {
            return Err("the bundle's SHA256SUMS is empty".to_owned());
        }
        let files = Self::walk_files(bundle_dir);
        let prefix = bundle_dir.display().to_string();
        for file in &files {
            if file == &sums {
                continue;
            }
            let relative = file
                .strip_prefix(&prefix)
                .map(|rel| format!("./{}", rel.display()))
                .unwrap_or_else(|_| format!("./{}", file.display()));
            let Some(expected) = entries.get(&relative) else {
                return Err(format!("SHA256SUMS does not cover {relative}"));
            };
            let actual = Self::sha256_file(file)?;
            if !actual.eq_ignore_ascii_case(expected) {
                return Err(format!("SHA256SUMS mismatch for {relative}"));
            }
        }
        for relative in entries.keys() {
            let file = bundle_dir.join(relative.trim_start_matches("./"));
            if !file.is_file() {
                return Err(format!("SHA256SUMS entry {relative} is not a regular file"));
            }
        }
        Ok(())
    }

    /// Recursive regular-file listing, sorted for determinism.
    fn walk_files(dir: &Path) -> Vec<PathBuf> {
        let mut files = Vec::new();
        if let Ok(entries) = std::fs::read_dir(dir) {
            for entry in entries.flatten() {
                let path = entry.path();
                match std::fs::metadata(&path) {
                    Ok(metadata) if metadata.is_dir() => files.extend(Self::walk_files(&path)),
                    Ok(metadata) if metadata.is_file() => files.push(path),
                    _ => {}
                }
            }
        }
        files.sort();
        files
    }
}

/// URLs of one release's three required assets.
struct ReleaseAssets {
    tarball: String,
    sha256: String,
    install: String,
}

/// Extracts the version from an `o3k-<version>-linux-x86_64.tar.gz` asset
/// name.
fn version_from_asset_name(name: &str) -> Option<ReleaseVersion> {
    let version_text = name
        .strip_prefix("o3k-")?
        .strip_suffix("-linux-x86_64.tar.gz")?;
    version_text.parse().ok()
}

/// Validates one archive entry name (mirrors `packaging/get-o3k.sh`
/// `safe_extract`): relative `./` entries only, no `..` components.
fn validate_entry_name(entry: &str) -> Result<(), String> {
    if entry.is_empty() {
        return Err("release archive contains an empty entry".to_owned());
    }
    if !entry.starts_with("./") {
        return Err(format!(
            "unsafe release archive entry (must start with ./): {entry}"
        ));
    }
    if entry.contains("/../") || entry.ends_with("/..") || entry == ".." {
        return Err(format!(
            "unsafe release archive entry (.. component): {entry}"
        ));
    }
    Ok(())
}

/// Validates one verbose listing line's entry type (mirrors `safe_extract`):
/// no symlinks, devices, fifos, or sockets.
fn validate_entry_type_line(line: &str) -> Result<(), String> {
    if line.contains(" -> ") {
        return Err("unsafe release archive entry (symlink)".to_owned());
    }
    match line.chars().next() {
        Some('l' | 'b' | 'c' | 'p' | 's') => {
            Err("unsafe release archive entry (device, fifo, or link)".to_owned())
        }
        _ => Ok(()),
    }
}

/// Validates a tarball's entries before extraction.
fn validate_tar_entries(tarball: &Path) -> Result<(), String> {
    let names = SystemUpgradeIo::tar_listing(tarball, "-tzf")?;
    for line in names.lines() {
        validate_entry_name(line.trim())?;
    }
    let verbose = SystemUpgradeIo::tar_listing(tarball, "-tvzf")?;
    for line in verbose.lines() {
        validate_entry_type_line(line)?;
    }
    Ok(())
}

#[async_trait]
impl UpgradeIo for SystemUpgradeIo {
    async fn acquire_lock(&self) -> Result<LockGuard, String> {
        let lock_path = self.lock_path();
        if let Some(parent) = lock_path.parent()
            && !parent.exists()
        {
            std::fs::create_dir_all(parent)
                .map_err(|error| format!("cannot create {}: {error}", parent.display()))?;
        }
        for attempt in 0..2 {
            use std::os::unix::fs::OpenOptionsExt;
            let mut options = std::fs::OpenOptions::new();
            options.write(true).create_new(true);
            options.mode(0o600);
            match options.open(&lock_path) {
                Ok(mut file) => {
                    let _ = writeln!(file, "{}", std::process::id());
                    return Ok(LockGuard::new(lock_path));
                }
                Err(error) if error.kind() == std::io::ErrorKind::AlreadyExists => {
                    let holder = std::fs::read_to_string(&lock_path)
                        .ok()
                        .and_then(|contents| contents.trim().parse::<u32>().ok());
                    let stale = holder.is_some_and(|pid| !Self::pid_alive(pid));
                    if !stale {
                        return Err(format!(
                            "another o3k upgrade or rollback is running (lock {})",
                            lock_path.display()
                        ));
                    }
                    if attempt == 0 {
                        let _ = std::fs::remove_file(&lock_path);
                        continue;
                    }
                    return Err(format!(
                        "cannot take the upgrade lock {}: raced with another invocation",
                        lock_path.display()
                    ));
                }
                Err(error) => {
                    return Err(format!(
                        "cannot take the upgrade lock {}: {error}",
                        lock_path.display()
                    ));
                }
            }
        }
        Err(format!(
            "cannot take the upgrade lock {}: raced with another invocation",
            lock_path.display()
        ))
    }

    async fn release_lock(&self, _guard: LockGuard) -> Result<(), String> {
        // Dropping the guard removes the lock file.
        Ok(())
    }

    async fn read_installed_manifest(&self) -> Result<InstalledRelease, String> {
        let manifest = self.share_dir().join("release-manifest.json");
        let contents = std::fs::read_to_string(&manifest)
            .map_err(|error| format!("cannot read {}: {error}", manifest.display()))?;
        let value: serde_json::Value = serde_json::from_str(&contents).map_err(|error| {
            format!("the installed release manifest is not valid JSON: {error}")
        })?;
        let version = value
            .get("version")
            .and_then(serde_json::Value::as_str)
            .ok_or_else(|| "the installed release manifest has no version".to_owned())?;
        let version: ReleaseVersion = version.parse().map_err(|_| {
            format!("the installed release version {version} is not a valid release version")
        })?;
        let commit = value
            .get("source_commit")
            .and_then(serde_json::Value::as_str)
            .filter(|commit| !commit.is_empty())
            .map(str::to_owned);
        let profile = value
            .get("profile")
            .and_then(serde_json::Value::as_str)
            .filter(|profile| !profile.is_empty())
            .map(str::to_owned)
            .unwrap_or_else(|| "libvirt".to_owned());
        Ok(InstalledRelease {
            version,
            commit,
            profile,
        })
    }

    async fn resolve_target(
        &self,
        requested: Option<ReleaseVersion>,
    ) -> Result<ReleaseVersion, String> {
        match requested {
            Some(version) => Ok(version),
            None => {
                let installed = self.read_installed_manifest().await?;
                self.latest_published(&installed.version).await
            }
        }
    }

    async fn download_and_verify(&self, target: &ReleaseVersion) -> Result<VerifiedBundle, String> {
        let assets = self.fetch_release_assets(target).await?;
        std::fs::create_dir_all(&self.download_dir)
            .map_err(|error| format!("cannot create {}: {error}", self.download_dir.display()))?;
        let work = self
            .download_dir
            .join(format!(".download-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&work);
        std::fs::create_dir_all(&work)
            .map_err(|error| format!("cannot create {}: {error}", work.display()))?;
        let cleanup = |error: String| -> Result<VerifiedBundle, String> {
            let _ = std::fs::remove_dir_all(&work);
            Err(error)
        };
        let tarball = work.join("release.tar.gz");
        let sums_file = work.join("release.tar.gz.sha256");
        let install = work.join("install.sh");
        if let Err(error) = self
            .curl_to_file(&assets.tarball, &tarball, DOWNLOAD_TIMEOUT)
            .await
        {
            return cleanup(format!("download failed: {error}"));
        }
        if let Err(error) = self
            .curl_to_file(&assets.sha256, &sums_file, API_TIMEOUT)
            .await
        {
            return cleanup(format!("checksum download failed: {error}"));
        }
        if let Err(error) = self
            .curl_to_file(&assets.install, &install, API_TIMEOUT)
            .await
        {
            return cleanup(format!("installer download failed: {error}"));
        }
        // Tarball checksum vs the published .sha256.
        let published = std::fs::read_to_string(&sums_file)
            .map_err(|error| format!("cannot read the published checksum: {error}"))?;
        let published = published
            .split_whitespace()
            .next()
            .ok_or_else(|| "the published checksum file is empty".to_owned())?;
        let actual = Self::sha256_file(&tarball)?;
        if !actual.eq_ignore_ascii_case(published) {
            return cleanup(format!(
                "release archive checksum mismatch (expected {published}, got {actual})"
            ));
        }
        // Extract after entry validation.
        let bundle_dir = match self.extract_bundle(&tarball, target, &work).await {
            Ok(bundle_dir) => bundle_dir,
            Err(error) => return cleanup(error),
        };
        // The bundle manifest must declare the requested version.
        let manifest: serde_json::Value =
            match std::fs::read_to_string(bundle_dir.join("manifest.json"))
                .map_err(|error| format!("the bundle has no manifest.json: {error}"))
                .and_then(|contents| {
                    serde_json::from_str(&contents)
                        .map_err(|error| format!("the bundle manifest is not valid JSON: {error}"))
                }) {
                Ok(manifest) => manifest,
                Err(error) => return cleanup(error),
            };
        let manifest_version = manifest
            .get("version")
            .and_then(serde_json::Value::as_str)
            .ok_or_else(|| "the bundle manifest has no version".to_owned())
            .and_then(|version| {
                version
                    .parse::<ReleaseVersion>()
                    .map_err(|_| format!("the bundle manifest version {version} is invalid"))
            });
        let manifest_version = match manifest_version {
            Ok(version) => version,
            Err(error) => return cleanup(error),
        };
        if manifest_version != *target {
            return cleanup(format!(
                "the bundle declares version {manifest_version}, expected {target}"
            ));
        }
        let target_profile = manifest
            .get("profile")
            .and_then(serde_json::Value::as_str)
            .unwrap_or("libvirt");
        // The installed manifest may be unavailable mid-upgrade (resume);
        // profile equality with libvirt is enforced directly.
        if target_profile != "libvirt" {
            return cleanup(format!(
                "the target release belongs to the {target_profile} profile; this host \
                 runs the libvirt profile"
            ));
        }
        // installer_sha256: the bundle install.sh must byte-match the
        // published install.sh asset and the manifest's declared digest.
        let installer_sha256 = manifest
            .get("installer_sha256")
            .and_then(serde_json::Value::as_str)
            .ok_or_else(|| "the bundle manifest has no installer_sha256".to_owned())?;
        let published_installer = Self::sha256_file(&install)?;
        if !published_installer.eq_ignore_ascii_case(installer_sha256) {
            return cleanup(
                "the published install.sh does not match the bundle manifest's installer_sha256"
                    .to_owned(),
            );
        }
        // The published install.sh asset is exported byte-for-byte from
        // packaging/get-o3k.sh (make-release.sh drift-gates it by cmp), so
        // the bundle comparison must target that file — the bundle's
        // packaging/install.sh is the state installer, a different script.
        let bundle_installer = Self::sha256_file(&bundle_dir.join("packaging/get-o3k.sh"))?;
        if !bundle_installer.eq_ignore_ascii_case(installer_sha256) {
            return cleanup(
                "the bundle's get-o3k.sh does not match the published install.sh".to_owned(),
            );
        }
        // upgrade_from fence (profile + min_version live in the target
        // manifest, plan §4).
        let min_version = manifest
            .get("upgrade_from")
            .and_then(|fence| fence.get("min_version"))
            .and_then(serde_json::Value::as_str);
        let installed = self.read_installed_manifest().await?;
        if let Err(kind) =
            self.validate_bundle_upgrade_fence(&installed, target, target_profile, min_version)
        {
            return cleanup(kind.to_string());
        }
        // SHA256SUMS coverage: exactly the extracted regular files.
        if let Err(error) = self.verify_sums_coverage(&bundle_dir) {
            return cleanup(error);
        }
        // Move into the canonical bundle location (fresh, never merged).
        let final_dir = self.bundle_dir_for(target);
        let _ = std::fs::remove_dir_all(&final_dir);
        if let Err(error) = std::fs::rename(&bundle_dir, &final_dir) {
            return cleanup(format!("cannot install the bundle directory: {error}"));
        }
        let _ = std::fs::remove_dir_all(&work);
        Ok(VerifiedBundle {
            version: target.clone(),
            dir: final_dir,
            installer_sha256: installer_sha256.to_lowercase(),
        })
    }

    async fn preflight(
        &self,
        _state: &UpgradeState,
        bundle: &VerifiedBundle,
    ) -> Result<(), String> {
        let mut failures = Vec::new();
        // O3K_UPGRADE_ASSUME_ROOT=1 is a documented sandbox knob for the
        // rootless portable test suite only: it skips the early UX gate, but
        // every actual mutation (service stop/start, binary replacement,
        // /var/lib/o3k writes) still fails without real root, so nothing is
        // weakened.
        if current_euid() != 0 && std::env::var("O3K_UPGRADE_ASSUME_ROOT").as_deref() != Ok("1") {
            failures.push("preflight requires root (run with sudo)".to_owned());
        }
        if let Err(error) = self.check_platform() {
            failures.push(error);
        }
        if let Err(error) = self.check_disk_space(bundle).await {
            failures.push(error);
        }
        if let Err(error) = self.check_ownership_manifest() {
            failures.push(error);
        }
        if let Err(error) = self.check_installed_binary_hashes() {
            failures.push(error);
        }
        let database = self.database_path();
        if !database.is_file() {
            failures.push("the control-plane database is missing".to_owned());
        } else {
            if let Err(error) = self.quick_check(&database).await {
                failures.push(format!("database integrity: {error}"));
            }
            if let Err(error) = self.schema_version(&database).await {
                failures.push(format!("database schema: {error}"));
            }
            match self.open_read_only_connection(&database).await {
                Ok(mut connection) => {
                    let mode: String = sqlx::query_scalar("PRAGMA journal_mode")
                        .fetch_one(&mut *connection)
                        .await
                        .unwrap_or_else(|_| "unknown".to_owned());
                    if mode != "wal" {
                        failures.push(format!("database journal mode is {mode}, expected wal"));
                    }
                }
                Err(error) => failures.push(format!("database access: {error}")),
            }
        }
        if let Err(error) = self.check_doctor_gate().await {
            failures.push(error);
        }
        if failures.is_empty() {
            Ok(())
        } else {
            Err(failures.join("; "))
        }
    }

    async fn create_backup(&self, state: &UpgradeState) -> Result<String, String> {
        let epoch = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .map(|duration| duration.as_secs())
            .unwrap_or(0);
        let backup_id = format!(
            "o3k-upgrade-{}-{}-{epoch}",
            state.source_version, state.target_version
        );
        let dir = self.backup_dir.join(&backup_id);
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir_all(&dir)
            .map_err(|error| format!("cannot create {}: {error}", dir.display()))?;
        // The backup root and the backup directory are private (0700),
        // regardless of the umask.
        {
            use std::os::unix::fs::PermissionsExt;
            std::fs::set_permissions(&self.backup_dir, std::fs::Permissions::from_mode(0o700))
                .map_err(|error| {
                    format!("cannot set mode on {}: {error}", self.backup_dir.display())
                })?;
            std::fs::set_permissions(&dir, std::fs::Permissions::from_mode(0o700))
                .map_err(|error| format!("cannot set mode on {}: {error}", dir.display()))?;
        }
        // 1. Database snapshot (WAL checkpoint + VACUUM INTO).
        let database = self.database_path();
        if !database.is_file() {
            return Err("the control-plane database is missing".to_owned());
        }
        self.checkpoint(&database).await?;
        let snapshot = dir.join("o3k.sqlite.backup");
        self.vacuum_into(&database, &snapshot).await?;
        use std::os::unix::fs::PermissionsExt;
        std::fs::set_permissions(&snapshot, std::fs::Permissions::from_mode(0o600))
            .map_err(|error| format!("cannot set mode on the snapshot: {error}"))?;
        if std::fs::metadata(&snapshot)
            .map(|metadata| metadata.len())
            .unwrap_or(0)
            == 0
        {
            return Err("the database snapshot is empty".to_owned());
        }
        self.quick_check(&snapshot).await?;
        // 2. Configuration copy (original modes, credentials verbatim).
        let config_backup = dir.join("config");
        std::fs::create_dir_all(&config_backup)
            .map_err(|error| format!("cannot create {}: {error}", config_backup.display()))?;
        Self::copy_tree(&self.config_dir, &config_backup)?;
        // 3. Installed release metadata.
        let release_backup = dir.join("release");
        std::fs::create_dir_all(&release_backup)
            .map_err(|error| format!("cannot create {}: {error}", release_backup.display()))?;
        for name in ["release-manifest.json", "SHA256SUMS", ".o3k-installed"] {
            let src = self.share_dir().join(name);
            if !src.is_file() {
                return Err(format!("installed release metadata is missing: {name}"));
            }
            Self::install_file(&src, &release_backup.join(name), Self::mode_of(&src)?)?;
        }
        // 4. The old binary set (the rollback source, plan §9).
        let bin_backup = dir.join("bin");
        std::fs::create_dir_all(&bin_backup)
            .map_err(|error| format!("cannot create {}: {error}", bin_backup.display()))?;
        let mut binary_sha256 = BTreeMap::new();
        for name in BINARIES {
            let src = self.bin_dir.join(name);
            if !src.is_file() {
                return Err(format!("installed binary is missing: {name}"));
            }
            binary_sha256.insert(name.to_owned(), Self::sha256_file(&src)?);
            Self::install_file(&src, &bin_backup.join(name), 0o755)?;
        }
        // 5. The migration-compatibility decision (plan §7): fail closed
        // when either side's schema version is unknown.
        let schema_before = self.schema_version(&database).await?;
        let target_schema = self.target_schema_version(&state.target_version)?;
        let installed = self.read_installed_manifest().await?;
        let manifest = BackupManifest {
            backup_id: backup_id.clone(),
            source_version: state.source_version.clone(),
            target_version: state.target_version.clone(),
            source_commit: installed.commit,
            created_at: crate::output::now_utc_rfc3339(),
            binary_sha256,
            schema_version_before: schema_before,
            db_restore_required_on_rollback: schema_before != target_schema,
        };
        let bytes = serde_json::to_vec(&manifest)
            .map_err(|error| format!("cannot serialize the backup manifest: {error}"))?;
        write_atomic(&dir.join("backup.json"), &bytes)?;
        // 6. Verify the backup before any mutation (plan §6).
        let readback = std::fs::read(dir.join("backup.json"))
            .map_err(|error| format!("cannot read back the backup manifest: {error}"))?;
        BackupManifest::validate(&readback)?;
        if Self::mode_of(&dir.join("backup.json"))? & 0o777 != 0o600 {
            return Err("the backup manifest is not private (0600)".to_owned());
        }
        if Self::mode_of(&dir)? & 0o777 != 0o700 {
            return Err("the backup directory is not private (0700)".to_owned());
        }
        Ok(backup_id)
    }

    async fn stop_services(&self) -> Result<(), String> {
        // Compute first, then control (§8): the agent must not observe a
        // half-upgraded control plane.
        self.stop_unit("o3k-compute.service").await?;
        self.stop_unit("o3kd.service").await?;
        Ok(())
    }

    async fn switch_binaries(&self, bundle: &VerifiedBundle) -> Result<(), String> {
        let bundle_bin = bundle.dir.join("bin");
        // Re-verify the three binaries against the bundle sums before any
        // rename (defense in depth on top of download verification).
        let sums = std::fs::read_to_string(bundle.dir.join("SHA256SUMS"))
            .map_err(|error| format!("cannot read the bundle SHA256SUMS: {error}"))?;
        let entries = Self::parse_sums_entries(&sums);
        for name in BINARIES {
            let Some(expected) = entries.get(name) else {
                return Err(format!("the bundle SHA256SUMS has no entry for {name}"));
            };
            let actual = Self::sha256_file(&bundle_bin.join(name))?;
            if !actual.eq_ignore_ascii_case(expected) {
                return Err(format!("the bundle binary {name} fails its checksum"));
            }
        }
        for name in BINARIES {
            Self::install_file(&bundle_bin.join(name), &self.bin_dir.join(name), 0o755)?;
        }
        // Release metadata (the pure-binary-swap journey keeps the
        // ownership ledger entries unchanged: the recorded paths remain
        // valid). The downloaded install.sh is never executed (plan §3).
        Self::install_file(
            &bundle.dir.join("manifest.json"),
            &self.share_dir().join("release-manifest.json"),
            0o644,
        )?;
        Self::install_file(
            &bundle.dir.join("SHA256SUMS"),
            &self.share_dir().join("SHA256SUMS"),
            0o644,
        )?;
        Ok(())
    }

    async fn apply_migrations_and_start_control(&self, backup_id: &str) -> Result<u32, String> {
        if !self
            .backup_dir
            .join(backup_id)
            .join("backup.json")
            .is_file()
        {
            return Err(format!("the backup {backup_id} is missing"));
        }
        self.start_unit("o3kd.service").await?;
        self.wait_http_ready(&format!("http://{}/healthz", self.listen_addr()))
            .await?;
        self.wait_http_ready(&format!("http://{}/readyz", self.listen_addr()))
            .await?;
        // o3kd applies its embedded migrations at startup; verify the
        // observed schema version matches the target manifest (plan §7).
        let observed = self.schema_version(&self.database_path()).await?;
        let expected =
            self.target_schema_version(&self.bundle_manifest_target(backup_id).await?)?;
        if observed != expected {
            return Err(format!(
                "schema version mismatch after control-plane start: observed {observed}, \
                 expected {expected}"
            ));
        }
        u32::try_from(observed)
            .map_err(|_| format!("schema version {observed} does not fit the upgrade contract"))
    }

    async fn start_compute(&self) -> Result<(), String> {
        self.start_unit("o3k-compute.service").await?;
        self.wait_http_ready(&format!("http://{}/readyz", self.compute_health_addr()))
            .await
    }

    async fn run_doctor(&self) -> Result<DoctorOutcome, String> {
        let report = self.doctor_report().await?;
        let overall = report
            .get("overall_status")
            .and_then(serde_json::Value::as_str)
            .unwrap_or("unknown")
            .to_owned();
        let healthy = matches!(overall.as_str(), "healthy" | "warning");
        Ok(DoctorOutcome { healthy, overall })
    }

    async fn verify_public_api(&self) -> Result<(), String> {
        let client = SystemHttpClient;
        let listen = self.listen_addr();
        for endpoint in ["/v3", "/placement"] {
            let url = format!("http://{listen}{endpoint}");
            let response = client
                .get(&url)
                .await
                .map_err(|error| format!("{endpoint}: {error}"))?;
            if response.status != 200 {
                return Err(format!("{endpoint}: HTTP {}", response.status));
            }
        }
        // Token smoke against the installed admin credentials (the
        // password is only ever placed in the request body, never logged).
        let openrc = parse_env_file(&self.config_dir.join("admin-openrc"));
        let auth_url = openrc
            .get("OS_AUTH_URL")
            .cloned()
            .unwrap_or_else(|| format!("http://{listen}/v3"));
        let user = openrc
            .get("OS_USERNAME")
            .cloned()
            .unwrap_or_else(|| "admin".to_owned());
        let password = openrc.get("OS_PASSWORD").cloned().unwrap_or_default();
        let project = openrc
            .get("OS_PROJECT_NAME")
            .cloned()
            .unwrap_or_else(|| "admin".to_owned());
        let user_domain = openrc
            .get("OS_USER_DOMAIN_NAME")
            .cloned()
            .unwrap_or_else(|| "Default".to_owned());
        let project_domain = openrc
            .get("OS_PROJECT_DOMAIN_NAME")
            .cloned()
            .unwrap_or_else(|| "Default".to_owned());
        let body = serde_json::json!({
            "auth": {
                "identity": {
                    "methods": ["password"],
                    "password": {
                        "user": {
                            "name": user,
                            "password": password,
                            "domain": {"name": user_domain}
                        }
                    }
                },
                "scope": {
                    "project": {"name": project, "domain": {"name": project_domain}}
                }
            }
        });
        let token_url = format!("{}/auth/tokens", auth_url.trim_end_matches('/'));
        let response = client
            .post_json(
                &token_url,
                &serde_json::to_string(&body)
                    .map_err(|error| format!("cannot build the token request: {error}"))?,
            )
            .await
            .map_err(|error| format!("token request failed: {error}"))?;
        if response.status != 201 {
            return Err(format!("token request: HTTP {}", response.status));
        }
        Ok(())
    }

    async fn commit(&self, backup_id: &str) -> Result<(), String> {
        let manifest_path = self.backup_dir.join(backup_id).join("backup.json");
        let bytes = std::fs::read(&manifest_path)
            .map_err(|error| format!("cannot read the backup manifest: {error}"))?;
        let manifest = BackupManifest::validate(&bytes)?;
        RollbackChain::append(
            &self.backup_dir.join("backup-chain.json"),
            RollbackRecord {
                manifest,
                kind: RecordKind::Backup,
            },
        )
    }

    async fn rollback_to_backup(&self, backup_id: &str) -> Result<(), String> {
        let dir = self.backup_dir.join(backup_id);
        let bytes = std::fs::read(dir.join("backup.json"))
            .map_err(|error| format!("cannot read the backup manifest: {error}"))?;
        let manifest = BackupManifest::validate(&bytes)?;
        // Validate the saved binary set against the recorded hashes.
        for (name, expected) in &manifest.binary_sha256 {
            let saved = dir.join("bin").join(name);
            if !saved.is_file() {
                return Err(format!("the backup is missing the saved binary {name}"));
            }
            let actual = Self::sha256_file(&saved)?;
            if !actual.eq_ignore_ascii_case(expected) {
                return Err(format!(
                    "the saved binary {name} fails its recorded checksum; the backup is \
                     tampered or corrupt"
                ));
            }
        }
        // Validate the database snapshot when a restore is required.
        if manifest.db_restore_required_on_rollback {
            let snapshot = dir.join("o3k.sqlite.backup");
            if !snapshot.is_file()
                || std::fs::metadata(&snapshot)
                    .map(|metadata| metadata.len())
                    .unwrap_or(0)
                    == 0
            {
                return Err("the backup database snapshot is missing or empty".to_owned());
            }
            self.quick_check(&snapshot).await?;
        }
        // Stop, restore, restart (plan §10).
        self.stop_services().await?;
        for name in BINARIES {
            let saved = dir.join("bin").join(name);
            Self::install_file(&saved, &self.bin_dir.join(name), 0o755)?;
        }
        for name in ["release-manifest.json", "SHA256SUMS", ".o3k-installed"] {
            let saved = dir.join("release").join(name);
            if !saved.is_file() {
                return Err(format!(
                    "the backup is missing the saved release metadata {name}"
                ));
            }
            Self::install_file(&saved, &self.share_dir().join(name), Self::mode_of(&saved)?)?;
        }
        if manifest.db_restore_required_on_rollback {
            let snapshot = dir.join("o3k.sqlite.backup");
            let database = self.database_path();
            let _ = std::fs::remove_file(database.with_extension("sqlite-wal"));
            let _ = std::fs::remove_file(database.with_extension("sqlite-shm"));
            Self::install_file(&snapshot, &database, 0o600)?;
        }
        // Config files are only restored when a recorded migration changed
        // them; the first real journey has none (plan §10).
        self.start_unit("o3kd.service").await?;
        self.wait_http_ready(&format!("http://{}/readyz", self.listen_addr()))
            .await?;
        self.start_unit("o3k-compute.service").await?;
        self.wait_http_ready(&format!("http://{}/readyz", self.compute_health_addr()))
            .await?;
        let doctor = self.run_doctor().await?;
        if !doctor.healthy {
            return Err(format!(
                "doctor reports an unhealthy installation after the rollback: {}",
                doctor.overall
            ));
        }
        self.verify_public_api().await
    }
}

impl SystemUpgradeIo {
    /// The target version recorded in a backup manifest.
    async fn bundle_manifest_target(&self, backup_id: &str) -> Result<ReleaseVersion, String> {
        let bytes = std::fs::read(self.backup_dir.join(backup_id).join("backup.json"))
            .map_err(|error| format!("cannot read the backup manifest: {error}"))?;
        let manifest = BackupManifest::validate(&bytes)?;
        Ok(manifest.target_version)
    }
}

#[cfg(test)]
mod tests {
    #![allow(clippy::assertions_on_constants)]
    use super::*;

    /// Entry-name validation mirrors `safe_extract` exactly.
    #[test]
    fn entry_names_must_be_relative_and_safe() {
        assert!(validate_entry_name("./bin/o3kd").is_ok());
        assert!(validate_entry_name("./o3k-0.3.0-alpha.1/manifest.json").is_ok());
        assert!(
            validate_entry_name("bin/o3kd").is_err(),
            "must start with ./"
        );
        assert!(
            validate_entry_name("/etc/passwd").is_err(),
            "absolute paths are unsafe"
        );
        assert!(
            validate_entry_name("./a/../b").is_err(),
            ".. components are unsafe"
        );
        assert!(validate_entry_name("./a/..").is_err());
        assert!(validate_entry_name("..").is_err());
        assert!(validate_entry_name("").is_err(), "empty entries are unsafe");
    }

    /// Entry-type validation refuses links and special files.
    #[test]
    fn entry_types_must_be_regular() {
        assert!(validate_entry_type_line("-rw-r--r-- o/o 123 2026-01-01 00:00 ./bin/o3kd").is_ok());
        assert!(validate_entry_type_line("drwxr-xr-x o/o 0 2026-01-01 00:00 ./bin").is_ok());
        assert!(
            validate_entry_type_line("lrwxrwxrwx o/o 0 2026-01-01 00:00 ./link -> /etc/passwd")
                .is_err()
        );
        for kind in ['l', 'b', 'c', 'p', 's'] {
            let line = format!("{kind}rw-r--r-- o/o 123 2026-01-01 00:00 ./entry");
            assert!(
                validate_entry_type_line(&line).is_err(),
                "{line} must be refused"
            );
        }
    }

    /// Asset names parse back to versions.
    #[test]
    fn asset_names_parse_versions() {
        assert_eq!(
            version_from_asset_name("o3k-0.3.0-alpha.1-linux-x86_64.tar.gz"),
            Some(ReleaseVersion::new(
                0,
                3,
                0,
                vec!["alpha".to_owned(), "1".to_owned()]
            ))
        );
        assert_eq!(
            version_from_asset_name("o3k-0.3.0-linux-x86_64.tar.gz").map(|v| v.to_string()),
            Some("0.3.0".to_owned())
        );
        assert_eq!(
            version_from_asset_name("other-0.3.0-linux-x86_64.tar.gz"),
            None
        );
        assert_eq!(
            version_from_asset_name("o3k-0.3.0-linux-x86_64.tar.gz.sha256"),
            None
        );
        assert_eq!(
            version_from_asset_name("o3k-not-a-version-linux-x86_64.tar.gz"),
            None
        );
    }

    /// The sums parser extracts the three binaries by basename.
    #[test]
    fn sums_parser_extracts_binary_hashes() {
        let contents = "\
aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa  ./o3k-0.3.0-alpha.1/bin/o3kd
bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb  ./o3k-0.3.0-alpha.1/bin/o3k
cccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccc  ./o3k-0.3.0-alpha.1/bin/o3k-compute
dddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddd  ./docs/readme.md
";
        let entries = SystemUpgradeIo::parse_sums_entries(contents);
        assert_eq!(entries.len(), 3);
        assert_eq!(
            entries.get("o3kd").map(String::as_str),
            Some("aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa")
        );
        assert_eq!(
            entries.get("o3k-compute").map(String::as_str),
            Some("cccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccc")
        );
        assert!(!entries.contains_key("readme.md"));
    }

    /// sha256 of a known input (empty string, per NIST test vector).
    #[test]
    fn sha256_matches_the_empty_digest() {
        let dir = std::env::temp_dir().join(format!("o3k-runner-test-{}", std::process::id()));
        let _ = std::fs::create_dir_all(&dir);
        let path = dir.join("empty.bin");
        let _ = std::fs::write(&path, b"");
        let digest = SystemUpgradeIo::sha256_file(&path);
        let Ok(digest) = digest else {
            assert!(false, "hashing must succeed");
            return;
        };
        assert_eq!(
            digest,
            "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"
        );
        let _ = std::fs::remove_dir_all(&dir);
    }

    /// The disk-space floor covers 2.5x the DB size plus the 200 MB floor.
    #[test]
    fn disk_floor_formula() {
        let required = DISK_FLOOR_BYTES
            + 100_000_000u64.saturating_mul(DISK_DB_FACTOR_NUMERATOR) / DISK_DB_FACTOR_DENOMINATOR;
        assert_eq!(required, DISK_FLOOR_BYTES + 250_000_000);
    }

    /// The lock path derives from the state file so sandbox overrides
    /// isolate concurrent invocations.
    #[test]
    fn lock_path_derives_from_state_file() {
        let io = SystemUpgradeIo {
            prefix: PathBuf::from("/usr/local"),
            bin_dir: PathBuf::from("/usr/local/bin"),
            config_dir: PathBuf::from("/etc/o3k"),
            data_dir: PathBuf::from("/var/lib/o3k"),
            state_file: PathBuf::from("/sandbox/state.json"),
            backup_dir: PathBuf::from("/sandbox/backups"),
            download_dir: PathBuf::from("/sandbox/download"),
            releases_url: DEFAULT_RELEASES_URL.to_owned(),
            download_base: DEFAULT_DOWNLOAD_BASE.to_owned(),
        };
        assert_eq!(io.lock_path(), PathBuf::from("/sandbox/state.json.lock"));
    }

    #[test]
    fn same_version_resume_requires_matching_durable_backup() -> Result<(), String> {
        use crate::upgrade::state::UpgradePhase;
        let root = std::env::temp_dir().join(format!(
            "o3k-resume-fence-{}-{}",
            std::process::id(),
            SystemTime::now()
                .duration_since(UNIX_EPOCH)
                .map_err(|error| error.to_string())?
                .as_nanos()
        ));
        std::fs::create_dir(&root).map_err(|error| error.to_string())?;
        let state_file = root.join("state.json");
        let backup_dir = root.join("backups");
        let source: ReleaseVersion = "0.2.0-alpha.2"
            .parse::<ReleaseVersion>()
            .map_err(|error| error.to_string())?;
        let target: ReleaseVersion = "0.3.0-alpha.1"
            .parse::<ReleaseVersion>()
            .map_err(|error| error.to_string())?;
        let backup_id = "backup-1";
        let mut state = UpgradeState::discovered(source.clone(), target.clone());
        state.phase = UpgradePhase::BinariesInstalled;
        state.backup_id = Some(backup_id.to_owned());
        let dir = backup_dir.join(backup_id);
        std::fs::create_dir_all(&dir).map_err(|error| error.to_string())?;
        let mut manifest = BackupManifest {
            backup_id: backup_id.to_owned(),
            source_version: source.clone(),
            target_version: target.clone(),
            source_commit: None,
            created_at: "2026-01-01T00:00:00Z".to_owned(),
            binary_sha256: [("o3kd".to_owned(), "a".repeat(64))].into_iter().collect(),
            schema_version_before: 1,
            db_restore_required_on_rollback: false,
        };
        let io = SystemUpgradeIo {
            prefix: root.clone(),
            bin_dir: root.join("bin"),
            config_dir: root.join("etc"),
            data_dir: root.clone(),
            state_file,
            backup_dir,
            download_dir: root.join("download"),
            releases_url: DEFAULT_RELEASES_URL.to_owned(),
            download_base: DEFAULT_DOWNLOAD_BASE.to_owned(),
        };
        let installed = InstalledRelease {
            version: target.clone(),
            profile: "libvirt".to_owned(),
            commit: None,
        };
        let check = |profile, minimum| {
            io.validate_bundle_upgrade_fence(&installed, &target, profile, minimum)
        };
        let write_manifest = |manifest: &BackupManifest| -> Result<(), String> {
            std::fs::write(
                dir.join("backup.json"),
                serde_json::to_vec(manifest).map_err(|error| error.to_string())?,
            )
            .map_err(|error| error.to_string())?;
            Ok(())
        };
        write_manifest(&manifest)?;
        assert_eq!(check("libvirt", None), Err(FenceError::SameVersion));
        for phase in [
            UpgradePhase::BinariesInstalled,
            UpgradePhase::MigrationsApplied,
            UpgradePhase::ServicesStarted,
            UpgradePhase::HealthVerified,
            UpgradePhase::DoctorPassed,
        ] {
            state.phase = phase;
            state
                .persist(&io.state_file)
                .map_err(|error| error.to_string())?;
            assert_eq!(check("libvirt", Some("0.2.0-alpha.2")), Ok(()), "{phase:?}");
        }
        assert_eq!(check("other", None), Err(FenceError::ProfileMismatch));
        assert_eq!(
            check("libvirt", Some("0.2.0-alpha.3")),
            Err(FenceError::UnsupportedPathBelowMin)
        );
        assert_eq!(
            check("libvirt", Some("invalid")),
            Err(FenceError::BadVersion)
        );
        for phase in [
            UpgradePhase::Discovered,
            UpgradePhase::BackupCreated,
            UpgradePhase::ServicesStopped,
            UpgradePhase::Committed,
            UpgradePhase::FailedUpgrade,
            UpgradePhase::RolledBack,
        ] {
            state.phase = phase;
            state
                .persist(&io.state_file)
                .map_err(|error| error.to_string())?;
            assert_eq!(
                check("libvirt", None),
                Err(FenceError::SameVersion),
                "{phase:?}"
            );
        }
        state.phase = UpgradePhase::BinariesInstalled;
        state.rollback_performed = true;
        state
            .persist(&io.state_file)
            .map_err(|error| error.to_string())?;
        assert!(check("libvirt", None).is_err());
        state.rollback_performed = false;
        state
            .persist(&io.state_file)
            .map_err(|error| error.to_string())?;
        for field in ["id", "source", "target"] {
            let mut foreign = manifest.clone();
            match field {
                "id" => foreign.backup_id = "foreign".to_owned(),
                "source" => foreign.source_version = target.clone(),
                _ => foreign.target_version = source.clone(),
            }
            write_manifest(&foreign)?;
            assert!(check("libvirt", None).is_err(), "foreign {field}");
        }
        write_manifest(&manifest)?;
        state.backup_id = Some("../backup-1".to_owned());
        state
            .persist(&io.state_file)
            .map_err(|error| error.to_string())?;
        assert!(check("libvirt", None).is_err());
        state.backup_id = None;
        state
            .persist(&io.state_file)
            .map_err(|error| error.to_string())?;
        assert!(check("libvirt", None).is_err());
        state.backup_id = Some(backup_id.to_owned());
        state.target_version = source.clone();
        state
            .persist(&io.state_file)
            .map_err(|error| error.to_string())?;
        assert!(check("libvirt", None).is_err());
        state.target_version = target.clone();
        state
            .persist(&io.state_file)
            .map_err(|error| error.to_string())?;
        for invalid_source in ["0.3.0-alpha.1", "0.4.0-alpha.1", "0.2.0-beta.1"] {
            let invalid_source = invalid_source
                .parse::<ReleaseVersion>()
                .map_err(|error| error.to_string())?;
            manifest.source_version = invalid_source.clone();
            state.source_version = invalid_source;
            state
                .persist(&io.state_file)
                .map_err(|error| error.to_string())?;
            write_manifest(&manifest)?;
            assert!(check("libvirt", None).is_err());
        }
        manifest.source_version = source.clone();
        state.source_version = source;
        state
            .persist(&io.state_file)
            .map_err(|error| error.to_string())?;
        write_manifest(&manifest)?;
        assert_eq!(check("libvirt", None), Ok(()));
        std::fs::write(dir.join("backup.json"), b"{}").map_err(|error| error.to_string())?;
        assert!(check("libvirt", None).is_err());
        std::fs::remove_file(dir.join("backup.json")).map_err(|error| error.to_string())?;
        assert!(check("libvirt", None).is_err());
        std::fs::write(&io.state_file, b"{}").map_err(|error| error.to_string())?;
        assert!(check("libvirt", None).is_err());
        std::fs::remove_dir_all(root).map_err(|error| error.to_string())?;
        Ok(())
    }

    #[test]
    fn canonical_assets_follow_the_release_naming_contract() {
        let target = match "0.4.0-alpha.1".parse::<ReleaseVersion>() {
            Ok(version) => version,
            Err(_) => {
                assert!(false, "the literal version must parse");
                return;
            }
        };
        let assets = SystemUpgradeIo::canonical_assets(
            "https://github.com/o3kio/o3k/releases/download/",
            &target,
            "o3k-0.4.0-alpha.1-linux-x86_64.tar.gz",
        );
        assert_eq!(
            assets.tarball,
            "https://github.com/o3kio/o3k/releases/download/v0.4.0-alpha.1/o3k-0.4.0-alpha.1-linux-x86_64.tar.gz"
        );
        assert_eq!(
            assets.sha256,
            "https://github.com/o3kio/o3k/releases/download/v0.4.0-alpha.1/o3k-0.4.0-alpha.1-linux-x86_64.tar.gz.sha256"
        );
        assert_eq!(
            assets.install,
            "https://github.com/o3kio/o3k/releases/download/v0.4.0-alpha.1/install.sh"
        );
    }
}
