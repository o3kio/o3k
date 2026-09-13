//! Resolved execution context for a doctor run plus the three trait-based
//! seams (process execution, HTTP, database) that make every check
//! deterministically testable without root or shell shims.

use crate::db::{AllocationRow, EpochRow, InstanceRow, InventoryRow, PortRow, ProviderRow};
use async_trait::async_trait;
use std::collections::BTreeMap;
use std::path::{Path, PathBuf};
use std::sync::Arc;

/// Default O3K data directory when `/etc/o3k/o3kd.env` does not declare one.
pub const DEFAULT_DATA_DIR: &str = "/var/lib/o3k";
/// Default O3K configuration directory.
pub const DEFAULT_CONFIG_DIR: &str = "/etc/o3k";
/// Default control-plane listen address (mirrors `o3k-config`).
pub const DEFAULT_LISTEN_ADDR: &str = "127.0.0.1:8080";
/// Default compute-agent health address (mirrors `bins/o3k-compute`).
pub const DEFAULT_COMPUTE_HEALTH_ADDR: &str = "127.0.0.1:9100";

/// Outcome of a `systemctl is-active <unit>` probe. `NotFound` means the
/// unit does not exist (systemctl exit 4) or the systemctl binary is
/// missing.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum UnitState {
    Active,
    Inactive,
    Failed,
    NotFound,
    Unknown,
}

/// Minimal HTTP response captured by the HTTP seam. The body is JSON text in
/// practice; it must never be logged or printed except for extracting the
/// specific fields a check needs.
#[derive(Debug, Clone, Default)]
pub struct HttpResponse {
    pub status: u16,
    /// Header names stored lowercase for lookup.
    pub headers: Vec<(String, String)>,
    pub body: String,
}

impl HttpResponse {
    /// Case-insensitive lookup of a captured response header.
    #[must_use]
    pub fn header(&self, name: &str) -> Option<&str> {
        self.headers
            .iter()
            .find(|(key, _)| key.eq_ignore_ascii_case(name))
            .map(|(_, value)| value.as_str())
    }
}

/// Process-execution seam: every host command doctor needs goes through this
/// trait so tests can drive classifications deterministically.
#[async_trait]
pub trait Exec: Send + Sync {
    /// Runs `systemctl is-active <unit>` with a bounded timeout.
    async fn systemctl_is_active(&self, unit: &str) -> UnitState;
    /// Runs `virsh -c qemu:///system uri`, optionally as `sudo -u <user> --`.
    async fn virsh_uri(&self, user: Option<&str>) -> Result<String, String>;
    /// Runs `virsh -c qemu:///system list --all --name`; non-empty lines.
    async fn virsh_list_names(&self) -> Result<Vec<String>, String>;
    /// Runs `ip -o link show`; returns interface names.
    async fn ip_link_names(&self) -> Result<Vec<String>, String>;
    /// Runs `df -Pk <path>`; returns available KiB on the second row.
    async fn df_avail_kib(&self, path: &Path) -> Result<u64, String>;
    /// Whether `/proc/<pid>` describes a live (non-zombie) process.
    fn proc_alive(&self, pid: u32) -> bool;
    /// The process command line from `/proc/<pid>/cmdline`, lossy-decoded.
    fn proc_cmdline(&self, pid: u32) -> Option<String>;
    /// The kernel start-time (clock ticks, `/proc/<pid>/stat` field 22) as a
    /// decimal string, mirroring `o3k-dhcp::process_starttime`.
    fn proc_start_time_ticks(&self, pid: u32) -> Option<String>;
    /// Reads a whole UTF-8 text file.
    fn read_file(&self, path: &Path) -> Result<String, String>;
    /// Lists the names of the entries of a directory (files only, in
    /// lexical order). A missing directory is an empty list.
    fn read_dir_names(&self, path: &Path) -> Result<Vec<String>, String>;
    /// Whether a path is a regular file (not a directory, symlink, or device).
    fn is_regular_file(&self, path: &Path) -> bool;
    /// Whether a path is a character device (used for `/dev/kvm`).
    fn is_char_device(&self, path: &Path) -> bool;
    /// Whether a path is a directory.
    fn is_dir(&self, path: &Path) -> bool;
    /// Permission bits (`mode & 0o7777`) of a path.
    fn file_mode(&self, path: &Path) -> Result<u32, String>;
    /// Lowercase hex SHA-256 of a file's bytes.
    fn sha256_file(&self, path: &Path) -> Result<String, String>;
}

/// HTTP seam: only plain `http://` GET/POST with a JSON body are needed.
#[async_trait]
pub trait HttpClient: Send + Sync {
    /// Performs an HTTP/1.1 GET with a bounded connect/read/write timeout.
    async fn get(&self, url: &str) -> Result<HttpResponse, String>;
    /// Performs an HTTP/1.1 POST with `Content-Type: application/json`.
    async fn post_json(&self, url: &str, body: &str) -> Result<HttpResponse, String>;
    async fn post_json_with_header(
        &self,
        url: &str,
        body: &str,
        header: Option<(&str, &str)>,
    ) -> Result<HttpResponse, String> {
        let _ = header;
        self.post_json(url, body).await
    }
    async fn delete(&self, url: &str) -> Result<HttpResponse, String>;
    async fn post_json_with_idempotency(
        &self,
        url: &str,
        body: &str,
        key: Option<&str>,
    ) -> Result<HttpResponse, String> {
        let _ = key;
        self.post_json(url, body).await
    }
    async fn delete_with_idempotency(
        &self,
        url: &str,
        key: Option<&str>,
    ) -> Result<HttpResponse, String> {
        let _ = key;
        self.delete(url).await
    }
}

/// Database seam: strictly read-only SQLite access. Every method takes the
/// database path so a single seam instance serves any data directory.
#[async_trait]
pub trait DoctorDb: Send + Sync {
    /// `PRAGMA journal_mode` as a scalar.
    async fn pragma_journal_mode(&self, path: &Path) -> Result<String, String>;
    /// `PRAGMA quick_check` as a scalar (healthy databases return `ok`).
    async fn pragma_quick_check(&self, path: &Path) -> Result<String, String>;
    /// All rows of `placement_providers`.
    async fn placement_providers(&self, path: &Path) -> Result<Vec<ProviderRow>, String>;
    /// All rows of `placement_inventories`.
    async fn placement_inventories(&self, path: &Path) -> Result<Vec<InventoryRow>, String>;
    /// Summed allocation amounts per (provider, resource class) for the live
    /// compute consumers (mirrors `o3k-store::reconcile_consumers` read-only).
    async fn live_allocation_resources(&self, path: &Path) -> Result<Vec<AllocationRow>, String>;
    /// Latest persisted `agent_epoch` per durable source
    /// (`observation_watermarks`, `agent_commands` per agent).
    async fn latest_epochs(&self, path: &Path) -> Result<Vec<EpochRow>, String>;
    /// Compute instances (`resources` rows of kind `compute_instance`) with
    /// their display name extracted from the durable desired state.
    async fn compute_instances(&self, path: &Path) -> Result<Vec<InstanceRow>, String>;
    /// All rows of `network_ports`.
    async fn network_ports(&self, path: &Path) -> Result<Vec<PortRow>, String>;
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub enum DeploymentMode {
    #[default]
    Systemd,
    Kubernetes,
}

/// Resolved doctor context: paths, addresses, in-memory environment maps,
/// and the three seams. The environment maps are kept in memory only and
/// must never be printed or serialized.
pub struct Context {
    pub data_dir: PathBuf,
    pub config_dir: PathBuf,
    pub listen_addr: String,
    pub compute_health_addr: String,
    pub compute_data_dir: PathBuf,
    pub deployment_mode: DeploymentMode,
    /// Root where `bins/o3k-compute` opens its `DhcpService`
    /// (`<compute_data_dir>/dhcp`).
    pub dhcp_root: PathBuf,
    /// Root where `bins/o3k-compute` persists `ownership.json`
    /// (`<compute_data_dir>/network`).
    pub network_root: PathBuf,
    /// True for the installed libvirt profile (`O3K_PROVIDER=agent` in
    /// `o3kd.env` or a systemd `o3k-compute.service` unit file).
    pub libvirt_profile: bool,
    /// Whether doctor runs with the real root uid.
    pub is_root: bool,
    /// Installation prefix candidates, preferred order.
    pub prefix_candidates: Vec<PathBuf>,
    pub tls_dir: PathBuf,
    /// Parsed `/etc/o3k/o3kd.env` (kept in memory only).
    pub o3kd_env: BTreeMap<String, String>,
    /// Parsed `/etc/o3k/o3k-compute.env` (kept in memory only).
    pub compute_env: BTreeMap<String, String>,
    pub exec: Arc<dyn Exec>,
    pub http: Arc<dyn HttpClient>,
    pub db: Arc<dyn DoctorDb>,
}

impl Context {
    /// Resolves the context from the installed configuration files. Missing
    /// or unreadable env files degrade to empty maps, never to errors.
    ///
    /// Testing/sandbox overrides (read from the process environment, not
    /// user-facing flags): `O3K_DOCTOR_CONFIG_DIR`, `O3K_DOCTOR_DATA_DIR`,
    /// and `O3K_DOCTOR_PREFIX` redirect doctor at a disposable sandbox so
    /// process tests and acceptance fixtures never touch real state.
    #[must_use]
    pub fn load(exec: Arc<dyn Exec>, http: Arc<dyn HttpClient>, db: Arc<dyn DoctorDb>) -> Self {
        let config_dir = path_override("O3K_DOCTOR_CONFIG_DIR")
            .unwrap_or_else(|| PathBuf::from(DEFAULT_CONFIG_DIR));
        let mut o3kd_env = parse_env_file(&config_dir.join("o3kd.env"));
        for (key, val) in std::env::vars() {
            if key.starts_with("O3K_") {
                o3kd_env.insert(key, val);
            }
        }
        let compute_env = parse_env_file(&config_dir.join("o3k-compute.env"));
        let deployment_mode = if std::env::var("O3K_DEPLOYMENT_MODE")
            .map(|v| v.to_ascii_lowercase())
            .as_deref()
            == Ok("kubernetes")
            || std::env::var("O3K_DEPLOYMENT_PROFILE")
                .map(|v| v.to_ascii_lowercase())
                .as_deref()
                == Ok("kubernetes")
            || o3kd_env
                .get("O3K_DEPLOYMENT_MODE")
                .map(|v| v.to_ascii_lowercase())
                .as_deref()
                == Some("kubernetes")
            || o3kd_env
                .get("O3K_DEPLOYMENT_PROFILE")
                .map(|v| v.to_ascii_lowercase())
                .as_deref()
                == Some("kubernetes")
            || std::env::var("KUBERNETES_SERVICE_HOST").is_ok()
        {
            DeploymentMode::Kubernetes
        } else {
            DeploymentMode::Systemd
        };
        let data_dir = path_override("O3K_DOCTOR_DATA_DIR").unwrap_or_else(|| {
            PathBuf::from(
                o3kd_env
                    .get("O3K_DATA_DIR")
                    .map(String::as_str)
                    .unwrap_or(DEFAULT_DATA_DIR),
            )
        });
        let listen_addr = o3kd_env
            .get("O3K_LISTEN_ADDR")
            .cloned()
            .unwrap_or_else(|| DEFAULT_LISTEN_ADDR.to_owned());
        let compute_health_addr = compute_env
            .get("O3K_COMPUTE_HEALTH_ADDR")
            .cloned()
            .unwrap_or_else(|| DEFAULT_COMPUTE_HEALTH_ADDR.to_owned());
        let compute_data_dir = compute_env
            .get("O3K_COMPUTE_DATA_DIR")
            .map(PathBuf::from)
            .unwrap_or_else(|| data_dir.join("compute"));
        let libvirt_profile = o3kd_env.get("O3K_PROVIDER").map(String::as_str) == Some("agent")
            || Path::new("/etc/systemd/system/o3k-compute.service").is_file();
        let prefix_candidates = path_override("O3K_DOCTOR_PREFIX")
            .map(|prefix| vec![prefix])
            .unwrap_or_else(|| vec![PathBuf::from("/usr/local"), PathBuf::from("/usr")]);
        Self {
            data_dir,
            config_dir: config_dir.clone(),
            listen_addr,
            compute_health_addr,
            dhcp_root: compute_data_dir.join("dhcp"),
            network_root: compute_data_dir.join("network"),
            compute_data_dir,
            deployment_mode,
            libvirt_profile,
            is_root: current_euid() == 0,
            prefix_candidates,
            tls_dir: config_dir.join("tls"),
            o3kd_env,
            compute_env,
            exec,
            http,
            db,
        }
    }

    /// True when running in Kubernetes deployment mode.
    #[must_use]
    pub fn is_kubernetes(&self) -> bool {
        self.deployment_mode == DeploymentMode::Kubernetes
    }

    /// Path of the control-plane SQLite database.
    #[must_use]
    pub fn database_path(&self) -> PathBuf {
        self.data_dir.join("o3k.sqlite")
    }

    /// Database backend configured in o3kd.env (`sqlite` or `postgres`).
    #[must_use]
    pub fn database_backend(&self) -> &str {
        self.o3kd_env
            .get("O3K_DATABASE_BACKEND")
            .map(String::as_str)
            .unwrap_or("sqlite")
    }

    /// True when PostgreSQL database backend is configured.
    #[must_use]
    pub fn is_postgres(&self) -> bool {
        let backend = self.database_backend();
        backend.eq_ignore_ascii_case("postgres") || backend.eq_ignore_ascii_case("postgresql")
    }

    /// Path of the network ownership manifest.
    #[must_use]
    pub fn ownership_path(&self) -> PathBuf {
        self.network_root.join("ownership.json")
    }

    /// Path of the DHCP durable state (bindings live in `state.json`).
    #[must_use]
    pub fn dhcp_state_path(&self) -> PathBuf {
        self.dhcp_root.join("state.json")
    }

    /// Path of the admin OpenRC client credentials.
    #[must_use]
    pub fn admin_openrc_path(&self) -> PathBuf {
        self.config_dir.join("admin-openrc")
    }
}

/// Reads a testing/sandbox path override. Empty values are ignored; this is
/// the only way doctor can be redirected at a disposable sandbox.
#[must_use]
fn path_override(key: &str) -> Option<PathBuf> {
    match std::env::var(key) {
        Ok(value) if !value.trim().is_empty() => Some(PathBuf::from(value)),
        _ => None,
    }
}

/// Real uid (first field of the `Uid:` line) read from `/proc/self/status`
/// without libc. Returns a non-zero sentinel on any read failure; only a
/// parsed zero marks root.
#[must_use]
pub fn current_euid() -> u32 {
    let Ok(status) = std::fs::read_to_string("/proc/self/status") else {
        return u32::MAX;
    };
    for line in status.lines() {
        let Some(rest) = line.strip_prefix("Uid:") else {
            continue;
        };
        let Some(real) = rest.split_whitespace().next() else {
            return u32::MAX;
        };
        return real.parse().unwrap_or(u32::MAX);
    }
    u32::MAX
}

/// Leniently parses a `KEY=VALUE` shell environment file. Missing files and
/// unparsable lines are ignored; matching single/double quotes around a
/// value are stripped. Values are never logged.
#[must_use]
pub fn parse_env_file(path: &Path) -> BTreeMap<String, String> {
    let Ok(contents) = std::fs::read_to_string(path) else {
        return BTreeMap::new();
    };
    parse_env_contents(&contents)
}

/// Leniently parses `KEY=VALUE` lines (optionally prefixed with `export `)
/// from already-read text. Unparsable lines are ignored; matching
/// single/double quotes around a value are stripped. Values are never logged.
#[must_use]
pub fn parse_env_contents(contents: &str) -> BTreeMap<String, String> {
    let mut map = BTreeMap::new();
    for line in contents.lines() {
        let line = line.trim();
        if line.is_empty() || line.starts_with('#') {
            continue;
        }
        let line = line.strip_prefix("export ").unwrap_or(line);
        let Some((key, value)) = line.split_once('=') else {
            continue;
        };
        let key = key.trim();
        let mut value = value.trim().to_owned();
        if key.is_empty() {
            continue;
        }
        if value.len() >= 2 {
            let bytes = value.as_bytes();
            let (first, last) = (bytes[0], bytes[value.len() - 1]);
            if (first == b'\'' && last == b'\'') || (first == b'"' && last == b'"') {
                value = value[1..value.len() - 1].to_owned();
            }
        }
        map.insert(key.to_owned(), value);
    }
    map
}

/// Strips newlines and bounds the length of an error message so it stays a
/// short, single-line sanitized description suitable for output.
#[must_use]
pub fn sanitize_error(message: &str) -> String {
    let single_line = message.replace(['\r', '\n'], " ");
    if single_line.len() <= 200 {
        single_line
    } else {
        let mut truncated = single_line.chars().take(197).collect::<String>();
        truncated.push_str("...");
        truncated
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn deployment_mode_default_is_systemd() {
        assert_eq!(DeploymentMode::default(), DeploymentMode::Systemd);
    }

    #[test]
    fn parse_env_contents_handles_exports_quotes_comments() {
        let text = r#"
            # comment
            export O3K_KEY_1="value1"
            O3K_KEY_2='value2'
            O3K_KEY_3=value3
            export EMPTY_VAL=
            INVALID_LINE
        "#;
        let map = parse_env_contents(text);
        assert_eq!(map.get("O3K_KEY_1").map(String::as_str), Some("value1"));
        assert_eq!(map.get("O3K_KEY_2").map(String::as_str), Some("value2"));
        assert_eq!(map.get("O3K_KEY_3").map(String::as_str), Some("value3"));
        assert_eq!(map.get("EMPTY_VAL").map(String::as_str), Some(""));
    }

    #[test]
    fn sanitize_error_truncates_long_strings_and_strips_newlines() {
        let msg = "line1\nline2\rline3";
        assert_eq!(sanitize_error(msg), "line1 line2 line3");

        let long = "a".repeat(300);
        let sanitized = sanitize_error(&long);
        assert_eq!(sanitized.len(), 200);
        assert!(sanitized.ends_with("..."));
    }
}
