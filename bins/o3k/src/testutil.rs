//! Deterministic fake seams for the doctor checks (test-only).
//!
//! Every field is plain data so each test can drive exactly the state it
//! needs; defaults are chosen to make the "healthy" fixture minimal.

#![cfg(test)]

use crate::context::{DoctorDb, Exec, HttpClient, HttpResponse, UnitState};
use crate::db::{
    AllocationRow, EpochRow, InstanceRow, InventoryRow, MigrationCounts, PortRow, ProviderRow,
    WorkLeaseRow,
};
use async_trait::async_trait;
use std::collections::BTreeMap;
use std::path::{Path, PathBuf};

/// Configurable fake for the process/HTTP/filesystem seam.
pub struct FakeExec {
    pub units: BTreeMap<String, UnitState>,
    pub virsh_uri_results: BTreeMap<String, Result<String, String>>,
    pub virsh_domains: Result<Vec<String>, String>,
    pub links: Vec<String>,
    pub df_kib: u64,
    pub df_error: Option<String>,
    /// pid -> (alive, cmdline, start-time-ticks)
    pub procs: BTreeMap<u32, (bool, String, String)>,
    /// path string -> contents
    pub files: BTreeMap<String, Result<String, String>>,
    /// path string -> mode bits
    pub modes: BTreeMap<String, u32>,
    /// path strings that are regular files
    pub regular_files: Vec<String>,
    /// path strings that are char devices
    pub char_devices: Vec<String>,
    /// path strings that are directories
    pub dirs: Vec<String>,
    /// path string -> file names
    pub dir_listings: BTreeMap<String, Vec<String>>,
    /// path string -> sha256 hex
    pub digests: BTreeMap<String, String>,
}

impl Default for FakeExec {
    fn default() -> Self {
        Self {
            units: BTreeMap::new(),
            virsh_uri_results: BTreeMap::new(),
            virsh_domains: Ok(Vec::new()),
            links: Vec::new(),
            df_kib: 0,
            df_error: None,
            procs: BTreeMap::new(),
            files: BTreeMap::new(),
            modes: BTreeMap::new(),
            regular_files: Vec::new(),
            char_devices: Vec::new(),
            dirs: Vec::new(),
            dir_listings: BTreeMap::new(),
            digests: BTreeMap::new(),
        }
    }
}

/// The healthy instance id used by the canned fixtures; its domain name is
/// derived with the same `o3k-libvirt` naming.
pub const HEALTHY_INSTANCE_ID: &str = "inst-1";

impl FakeExec {
    /// A fake whose filesystem state is healthy for a libvirt-profile
    /// install under `/var/lib/o3k` with config in `/etc/o3k`.
    #[must_use]
    pub fn healthy() -> Self {
        let domain = crate::checks::stable_domain_name(HEALTHY_INSTANCE_ID);
        let mut fake = Self {
            units: BTreeMap::from([
                ("o3kd.service".to_owned(), UnitState::Active),
                ("o3k-compute.service".to_owned(), UnitState::Active),
            ]),
            virsh_uri_results: BTreeMap::from([
                ("o3k-compute".to_owned(), Ok("qemu:///system".to_owned())),
                ("o3k".to_owned(), Err("access denied".to_owned())),
            ]),
            virsh_domains: Ok(vec![domain]),
            links: vec![
                "lo".to_owned(),
                "o3k-br0".to_owned(),
                "o3ktap-00000001".to_owned(),
            ],
            df_kib: 8 * 1_048_576,
            procs: BTreeMap::from([(
                123,
                (
                    true,
                    "/usr/sbin/dnsmasq --conf-file=/var/lib/o3k/compute/dhcp/dnsmasq.conf"
                        .to_owned(),
                    "987".to_owned(),
                ),
            )]),
            dir_listings: BTreeMap::from([(
                "/var/lib/o3k/compute/dhcp".to_owned(),
                vec!["dnsmasq-1.pid".to_owned()],
            )]),
            ..Self::default()
        };
        fake.regular_files = vec![
            "/var/lib/o3k/o3k.sqlite".to_owned(),
            "/etc/o3k/o3kd.env".to_owned(),
            "/etc/o3k/o3k-compute.env".to_owned(),
            "/etc/o3k/admin-openrc".to_owned(),
            "/etc/o3k/clouds.yaml".to_owned(),
            "/etc/o3k/tls/ca.pem".to_owned(),
            "/etc/o3k/tls/server.pem".to_owned(),
            "/etc/o3k/tls/server-key.pem".to_owned(),
            "/etc/o3k/tls/agent.pem".to_owned(),
            "/etc/o3k/tls/agent-key.pem".to_owned(),
            "/etc/o3k/tls/agent-id".to_owned(),
            "/etc/o3k/tls/agent-fingerprint".to_owned(),
            "/var/lib/o3k/compute/network/ownership.json".to_owned(),
            "/usr/local/share/o3k/release-manifest.json".to_owned(),
            "/usr/local/share/o3k/.o3k-installed".to_owned(),
            "/usr/local/share/o3k/SHA256SUMS".to_owned(),
            "/usr/local/bin/o3kd".to_owned(),
            "/usr/local/bin/o3k".to_owned(),
            "/usr/local/bin/o3k-compute".to_owned(),
            "/usr/local/share/o3k/o3kd.service".to_owned(),
            "/usr/local/share/o3k/o3k-compute.service".to_owned(),
            "/var/lib/o3k/backups/backup-chain.json".to_owned(),
        ];
        fake.char_devices = vec!["/dev/kvm".to_owned()];
        fake.dirs = vec!["/var/lib/o3k".to_owned(), "/usr/local/share/o3k".to_owned()];
        fake.files = BTreeMap::from([
            (
                "/etc/os-release".to_owned(),
                Ok("ID=ubuntu\nVERSION_ID=\"24.04\"\n".to_owned()),
            ),
            (
                "/etc/o3k/o3kd.env".to_owned(),
                Ok(
                    "O3K_DATA_DIR=/var/lib/o3k\nO3K_PROVIDER=agent\nO3K_LISTEN_ADDR=127.0.0.1:8080\n"
                        .to_owned(),
                ),
            ),
            (
                "/etc/o3k/o3k-compute.env".to_owned(),
                Ok(
                    "O3K_COMPUTE_DATA_DIR=/var/lib/o3k/compute\nO3K_COMPUTE_HEALTH_ADDR=127.0.0.1:9100\n"
                        .to_owned(),
                ),
            ),
            (
                "/etc/o3k/admin-openrc".to_owned(),
                Ok(
                    "export OS_AUTH_URL=http://127.0.0.1:8080/v3\n\
                     export OS_USERNAME=admin\n\
                     export OS_PASSWORD=fake-password\n\
                     export OS_PROJECT_NAME=admin\n\
                     export OS_USER_DOMAIN_NAME=Default\n\
                     export OS_PROJECT_DOMAIN_NAME=Default\n\
                     export OS_IDENTITY_API_VERSION=3\n"
                        .to_owned(),
                ),
            ),
            (
                "/etc/o3k/tls/agent-fingerprint".to_owned(),
                Ok("0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef"
                    .to_owned()),
            ),
            (
                "/etc/o3k/tls/agent-id".to_owned(),
                Ok("agent-1".to_owned()),
            ),
            (
                "/usr/local/share/o3k/release-manifest.json".to_owned(),
                Ok("{\"version\": \"0.2.0-alpha.2\"}".to_owned()),
            ),
            (
                "/usr/local/share/o3k/.o3k-installed".to_owned(),
                Ok(
                    "o3k-installed-v1 prefix=/usr/local\nbin/o3kd\nbin/o3k\nbin/o3k-compute\nshare/o3k/o3kd.service\nshare/o3k/o3k-compute.service\n"
                        .to_owned(),
                ),
            ),
            (
                "/usr/local/share/o3k/SHA256SUMS".to_owned(),
                Ok(
                    "0000000000000000000000000000000000000000000000000000000000000000  ./o3k-0.2.0-alpha.2/bin/o3kd\n\
                     0000000000000000000000000000000000000000000000000000000000000000  ./o3k-0.2.0-alpha.2/bin/o3k\n\
                     0000000000000000000000000000000000000000000000000000000000000000  ./o3k-0.2.0-alpha.2/bin/o3k-compute\n"
                        .to_owned(),
                ),
            ),
            (
                "/var/lib/o3k/compute/network/ownership.json".to_owned(),
                Ok(
                    "{\"bridge\": {\"name\": \"o3k-br0\", \"uplink\": null, \"created_by_o3k\": true}, \
                     \"taps\": {\"o3ktap-00000001\": {\"interface\": \"o3ktap-00000001\", \"instance_id\": \"inst-1\", \"port_id\": \"port-1\", \"mac\": \"02:00:00:00:00:01\", \"bridge\": \"o3k-br0\", \"created_by_o3k\": true}}}"
                        .to_owned(),
                ),
            ),
            (
                "/var/lib/o3k/backups/backup-chain.json".to_owned(),
                Ok(
                    "{\"backups\":[{\"backup_id\":\"o3k-upgrade-0.1.0-alpha.1-0.2.0-alpha.2-1712345678\",\
                     \"source_version\":\"0.1.0-alpha.1\",\"target_version\":\"0.2.0-alpha.2\",\
                     \"source_commit\":\"d6351864\",\"created_at\":\"2026-01-01T00:00:00Z\",\
                     \"binary_sha256\":{\"o3kd\":\"0000000000000000000000000000000000000000000000000000000000000000\"},\
                     \"schema_version_before\":17,\"db_restore_required_on_rollback\":false,\
                     \"kind\":\"backup\"}]}"
                        .to_owned(),
                ),
            ),
            (
                "/var/lib/o3k/compute/dhcp/dnsmasq-1.pid".to_owned(),
                Ok("123\n".to_owned()),
            ),
            (
                "/var/lib/o3k/compute/dhcp/dnsmasq-1.pid.owner".to_owned(),
                Ok("987\n".to_owned()),
            ),
        ]);
        fake.modes = BTreeMap::from([
            ("/etc/o3k/o3kd.env".to_owned(), 0o600),
            ("/etc/o3k/o3k-compute.env".to_owned(), 0o600),
            ("/etc/o3k/admin-openrc".to_owned(), 0o600),
            ("/etc/o3k/clouds.yaml".to_owned(), 0o600),
            ("/etc/o3k/tls/server-key.pem".to_owned(), 0o640),
            ("/etc/o3k/tls/agent-key.pem".to_owned(), 0o640),
            ("/etc/o3k".to_owned(), 0o755),
            ("/var/lib/o3k".to_owned(), 0o755),
            ("/var/lib/o3k/o3k.sqlite".to_owned(), 0o600),
        ]);
        fake.digests = BTreeMap::from([
            (
                "/usr/local/bin/o3kd".to_owned(),
                "0000000000000000000000000000000000000000000000000000000000000000".to_owned(),
            ),
            (
                "/usr/local/bin/o3k".to_owned(),
                "0000000000000000000000000000000000000000000000000000000000000000".to_owned(),
            ),
            (
                "/usr/local/bin/o3k-compute".to_owned(),
                "0000000000000000000000000000000000000000000000000000000000000000".to_owned(),
            ),
        ]);
        fake
    }

    /// Adds an O3K-patterned domain for an instance id to the virsh listing.
    pub fn with_domain_for(&mut self, instance_id: &str) {
        let domain = crate::checks::stable_domain_name(instance_id);
        if let Ok(domains) = self.virsh_domains.as_mut()
            && !domains.contains(&domain)
        {
            domains.push(domain);
        }
    }
}

#[async_trait]
impl Exec for FakeExec {
    async fn systemctl_is_active(&self, unit: &str) -> UnitState {
        self.units.get(unit).copied().unwrap_or(UnitState::NotFound)
    }

    async fn virsh_uri(&self, user: Option<&str>) -> Result<String, String> {
        let key = user.unwrap_or("");
        self.virsh_uri_results
            .get(key)
            .cloned()
            .unwrap_or(Err("access denied".to_owned()))
    }

    async fn virsh_list_names(&self) -> Result<Vec<String>, String> {
        self.virsh_domains.clone()
    }

    async fn ip_link_names(&self) -> Result<Vec<String>, String> {
        Ok(self.links.clone())
    }

    async fn df_avail_kib(&self, _path: &Path) -> Result<u64, String> {
        match &self.df_error {
            Some(error) => Err(error.clone()),
            None => Ok(self.df_kib),
        }
    }

    fn proc_alive(&self, pid: u32) -> bool {
        self.procs.get(&pid).is_some_and(|proc| proc.0)
    }

    fn proc_cmdline(&self, pid: u32) -> Option<String> {
        self.procs.get(&pid).map(|proc| proc.1.clone())
    }

    fn proc_start_time_ticks(&self, pid: u32) -> Option<String> {
        self.procs.get(&pid).map(|proc| proc.2.clone())
    }

    fn read_file(&self, path: &Path) -> Result<String, String> {
        self.files
            .get(&path.display().to_string())
            .cloned()
            .unwrap_or(Err(format!(
                "No such file or directory: {}",
                path.display()
            )))
    }

    fn read_dir_names(&self, path: &Path) -> Result<Vec<String>, String> {
        Ok(self
            .dir_listings
            .get(&path.display().to_string())
            .cloned()
            .unwrap_or_default())
    }

    fn is_regular_file(&self, path: &Path) -> bool {
        self.regular_files
            .iter()
            .any(|candidate| candidate == &path.display().to_string())
    }

    fn is_char_device(&self, path: &Path) -> bool {
        self.char_devices
            .iter()
            .any(|candidate| candidate == &path.display().to_string())
    }

    fn is_dir(&self, path: &Path) -> bool {
        self.dirs
            .iter()
            .any(|candidate| candidate == &path.display().to_string())
    }

    fn file_mode(&self, path: &Path) -> Result<u32, String> {
        self.modes
            .get(&path.display().to_string())
            .copied()
            .ok_or_else(|| format!("no mode recorded for {}", path.display()))
    }

    fn sha256_file(&self, path: &Path) -> Result<String, String> {
        let key = path.display().to_string();
        self.digests
            .get(&key)
            .cloned()
            .ok_or_else(|| format!("no digest recorded for {key}"))
    }
}

/// Configurable fake for the HTTP seam, keyed by `"METHOD url"`.
#[derive(Default)]
pub struct FakeHttp {
    pub responses: BTreeMap<String, Result<HttpResponse, String>>,
}

impl FakeHttp {
    /// A fake whose endpoints answer the way a healthy control plane and
    /// compute agent do.
    #[must_use]
    pub fn healthy() -> Self {
        let mut responses = BTreeMap::new();
        for path in ["/healthz", "/readyz", "/v3", "/placement"] {
            responses.insert(
                format!("GET http://127.0.0.1:8080{path}"),
                Ok(HttpResponse {
                    status: 200,
                    headers: Vec::new(),
                    body: if path == "/readyz" {
                        "{\"status\":\"ready\"}".to_owned()
                    } else {
                        "{\"status\":\"ok\"}".to_owned()
                    },
                }),
            );
        }
        responses.insert(
            "GET http://127.0.0.1:9100/readyz".to_owned(),
            Ok(HttpResponse {
                status: 200,
                headers: Vec::new(),
                body:
                    "{\"status\":\"ready\",\"agent_id\":\"compute-agent\",\"agent_epoch\":\"42\"}"
                        .to_owned(),
            }),
        );
        responses.insert(
            "POST http://127.0.0.1:8080/v3/auth/tokens".to_owned(),
            Ok(HttpResponse {
                status: 201,
                headers: vec![("x-subject-token".to_owned(), "token".to_owned())],
                body: "{\"token\":{}}".to_owned(),
            }),
        );
        Self { responses }
    }

    /// Installs (or replaces) one canned response.
    pub fn with(&mut self, key: impl Into<String>, response: Result<HttpResponse, String>) {
        self.responses.insert(key.into(), response);
    }
}

#[async_trait]
impl HttpClient for FakeHttp {
    async fn get(&self, url: &str) -> Result<HttpResponse, String> {
        self.responses
            .get(&format!("GET {url}"))
            .cloned()
            .unwrap_or(Err(format!("unmocked GET {url}")))
    }

    async fn post_json(&self, url: &str, _body: &str) -> Result<HttpResponse, String> {
        self.responses
            .get(&format!("POST {url}"))
            .cloned()
            .unwrap_or(Err(format!("unmocked POST {url}")))
    }
    async fn delete(&self, url: &str) -> Result<HttpResponse, String> {
        self.responses
            .get(&format!("DELETE {url}"))
            .cloned()
            .unwrap_or(Err(format!("unmocked DELETE {url}")))
    }
}

/// Configurable fake for the database seam.
#[derive(Clone)]
pub struct FakeDb {
    pub journal_mode: Result<String, String>,
    pub quick_check: Result<String, String>,
    pub providers: Vec<ProviderRow>,
    pub inventories: Vec<InventoryRow>,
    pub allocations: Vec<AllocationRow>,
    pub epochs: Vec<EpochRow>,
    pub instances: Vec<InstanceRow>,
    pub ports: Vec<PortRow>,
    pub active_sessions: Result<u64, String>,
    pub work_leases: Result<Vec<WorkLeaseRow>, String>,
    /// When set, every row read below fails with this backend error text.
    pub read_error: Option<String>,
    pub postgres_reachable: Result<(), String>,
    pub postgres_migrations: Result<MigrationCounts, String>,
}

impl Default for FakeDb {
    fn default() -> Self {
        Self {
            journal_mode: Ok("wal".to_owned()),
            quick_check: Ok("ok".to_owned()),
            providers: Vec::new(),
            inventories: Vec::new(),
            allocations: Vec::new(),
            epochs: Vec::new(),
            instances: Vec::new(),
            ports: Vec::new(),
            active_sessions: Ok(1),
            work_leases: Ok(Vec::new()),
            read_error: None,
            postgres_reachable: Ok(()),
            postgres_migrations: Ok(MigrationCounts {
                applied: 1,
                failed: 0,
            }),
        }
    }
}

impl FakeDb {
    /// A fake whose placement/instance state is consistent and healthy.
    #[must_use]
    pub fn healthy() -> Self {
        Self {
            journal_mode: Ok("wal".to_owned()),
            quick_check: Ok("ok".to_owned()),
            providers: vec![ProviderRow {
                id: "provider-1".to_owned(),
                node_id: "node-1".to_owned(),
                state: "ready".to_owned(),
                generation: 1,
            }],
            inventories: vec![
                InventoryRow {
                    provider_id: "provider-1".to_owned(),
                    resource_class: "VCPU".to_owned(),
                    total: 8,
                    reserved: 0,
                    allocation_ratio: 1.0,
                    used: 2,
                },
                InventoryRow {
                    provider_id: "provider-1".to_owned(),
                    resource_class: "MEMORY_MB".to_owned(),
                    total: 16_384,
                    reserved: 0,
                    allocation_ratio: 1.0,
                    used: 2_048,
                },
                InventoryRow {
                    provider_id: "provider-1".to_owned(),
                    resource_class: "DISK_GB".to_owned(),
                    total: 10,
                    reserved: 0,
                    allocation_ratio: 1.0,
                    used: 1,
                },
            ],
            allocations: vec![
                AllocationRow {
                    provider_id: "provider-1".to_owned(),
                    resource_class: "VCPU".to_owned(),
                    amount: 2,
                },
                AllocationRow {
                    provider_id: "provider-1".to_owned(),
                    resource_class: "MEMORY_MB".to_owned(),
                    amount: 2_048,
                },
                AllocationRow {
                    provider_id: "provider-1".to_owned(),
                    resource_class: "DISK_GB".to_owned(),
                    amount: 1,
                },
            ],
            epochs: vec![EpochRow {
                source: "observation_watermarks".to_owned(),
                agent_id: String::new(),
                agent_epoch: "42".to_owned(),
            }],
            instances: vec![InstanceRow {
                id: HEALTHY_INSTANCE_ID.to_owned(),
                name: "test-vm".to_owned(),
                observed_state: "active".to_owned(),
            }],
            ports: Vec::new(),
            active_sessions: Ok(1),
            work_leases: Ok(Vec::new()),
            read_error: None,
            postgres_reachable: Ok(()),
            postgres_migrations: Ok(MigrationCounts {
                applied: 1,
                failed: 0,
            }),
        }
    }
}

#[async_trait]
impl DoctorDb for FakeDb {
    async fn pragma_journal_mode(&self, _path: &Path) -> Result<String, String> {
        self.journal_mode.clone()
    }

    async fn pragma_quick_check(&self, _path: &Path) -> Result<String, String> {
        self.quick_check.clone()
    }

    async fn placement_providers(&self, _path: &Path) -> Result<Vec<ProviderRow>, String> {
        if let Some(error) = &self.read_error {
            return Err(error.clone());
        }
        Ok(self.providers.clone())
    }

    async fn placement_inventories(&self, _path: &Path) -> Result<Vec<InventoryRow>, String> {
        if let Some(error) = &self.read_error {
            return Err(error.clone());
        }
        Ok(self.inventories.clone())
    }

    async fn live_allocation_resources(&self, _path: &Path) -> Result<Vec<AllocationRow>, String> {
        if let Some(error) = &self.read_error {
            return Err(error.clone());
        }
        Ok(self.allocations.clone())
    }

    async fn latest_epochs(&self, _path: &Path) -> Result<Vec<EpochRow>, String> {
        if let Some(error) = &self.read_error {
            return Err(error.clone());
        }
        Ok(self.epochs.clone())
    }

    async fn compute_instances(&self, _path: &Path) -> Result<Vec<InstanceRow>, String> {
        if let Some(error) = &self.read_error {
            return Err(error.clone());
        }
        Ok(self.instances.clone())
    }

    async fn network_ports(&self, _path: &Path) -> Result<Vec<PortRow>, String> {
        if let Some(error) = &self.read_error {
            return Err(error.clone());
        }
        Ok(self.ports.clone())
    }

    async fn postgres_reachable(&self, _url: &str) -> Result<(), String> {
        self.postgres_reachable.clone()
    }

    async fn postgres_migration_counts(&self, _url: &str) -> Result<MigrationCounts, String> {
        self.postgres_migrations.clone()
    }

    async fn active_controller_sessions(
        &self,
        _path: &Path,
        _use_postgres: bool,
        _postgres_url: Option<&str>,
    ) -> Result<u64, String> {
        self.active_sessions.clone()
    }

    async fn active_work_leases(
        &self,
        _path: &Path,
        _use_postgres: bool,
        _postgres_url: Option<&str>,
    ) -> Result<Vec<WorkLeaseRow>, String> {
        self.work_leases.clone()
    }
}

/// Builds a [`crate::context::Context`] whose seams and in-memory env maps
/// are fully deterministic.
pub fn context_with(
    exec: FakeExec,
    http: FakeHttp,
    db: FakeDb,
    libvirt_profile: bool,
    is_root: bool,
) -> crate::context::Context {
    let mut o3kd_env = BTreeMap::new();
    o3kd_env.insert("O3K_DATA_DIR".to_owned(), "/var/lib/o3k".to_owned());
    o3kd_env.insert("O3K_LISTEN_ADDR".to_owned(), "127.0.0.1:8080".to_owned());
    if libvirt_profile {
        o3kd_env.insert("O3K_PROVIDER".to_owned(), "agent".to_owned());
        o3kd_env.insert(
            "O3K_COMPUTE_AUTHORIZED_AGENTS".to_owned(),
            "agent-1=0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef".to_owned(),
        );
    }
    let mut compute_env = BTreeMap::new();
    compute_env.insert(
        "O3K_COMPUTE_DATA_DIR".to_owned(),
        "/var/lib/o3k/compute".to_owned(),
    );
    compute_env.insert(
        "O3K_COMPUTE_HEALTH_ADDR".to_owned(),
        "127.0.0.1:9100".to_owned(),
    );
    let data_dir = PathBuf::from("/var/lib/o3k");
    let compute_data_dir = PathBuf::from("/var/lib/o3k/compute");
    crate::context::Context {
        data_dir,
        config_dir: PathBuf::from("/etc/o3k"),
        listen_addr: "127.0.0.1:8080".to_owned(),
        compute_health_addr: "127.0.0.1:9100".to_owned(),
        compute_data_dir: compute_data_dir.clone(),
        deployment_mode: crate::context::DeploymentMode::Systemd,
        dhcp_root: compute_data_dir.join("dhcp"),
        network_root: compute_data_dir.join("network"),
        libvirt_profile,
        is_root,
        prefix_candidates: vec![PathBuf::from("/usr/local"), PathBuf::from("/usr")],
        tls_dir: PathBuf::from("/etc/o3k/tls"),
        o3kd_env,
        compute_env,
        exec: std::sync::Arc::new(exec),
        http: std::sync::Arc::new(http),
        db: std::sync::Arc::new(db),
    }
}
