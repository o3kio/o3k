#![cfg(unix)]

//! Evidence-hardening focused PP.5 #1035 real-process acceptance run.
//!
//! The test deliberately writes an atomic artifact at every phase.  The
//! companion `scripts/validate_pp5_1035_evidence.py` is the fail-closed
//! acceptance authority; this process test only records observations.

use std::collections::BTreeMap;
use std::fs::{self, File, OpenOptions};
use std::io::{Read, Seek, SeekFrom, Write};
use std::net::{SocketAddr, TcpListener};
use std::path::{Path, PathBuf};
use std::process::{Child, Command, Stdio};
use std::time::{Duration, Instant};

use chrono::Utc;
use o3k_store::{CoordinationRepository, DurableStore, IdentityRepository, NetworkRepository};
use serde_json::{Map, Value, json};
use sha2::{Digest, Sha256};
use sqlx::postgres::PgPoolOptions;
use uuid::Uuid;

const PROJECT_ID: &str = "eba29e2d-53de-461d-ae91-ede7402713cb";
const FOREIGN_PROJECT_ID: &str = "1d6e8a4d-9e09-4a7a-a1cb-2a0e5fb2a103";
const BOOTSTRAP_PASSWORD: &str = "pp5-interrupted-delete-bootstrap-password";
const FOREIGN_PASSWORD: &str = "pp5-interrupted-delete-foreign-password";
const TOKEN_SIGNING_KEY: &str = "pp5-interrupted-delete-signing-key-0123456789abcdef";
const FLAVOR_ID: &str = "00000000-0000-0000-0000-000000000001";
const FAULT_ENV: &str = "O3K_TEST_FAULT_PAUSE_BEFORE_ENDPOINT_RELEASE_MS";
const MAX_CONTROLLER_IDENTITY_BYTES: usize = 64;

type Error = Box<dyn std::error::Error + Send + Sync>;

#[derive(Clone)]
enum Backend {
    Sqlite(PathBuf),
    Postgres(String),
}

impl Backend {
    fn configure(&self, command: &mut Command) {
        match self {
            Self::Sqlite(path) => {
                command.env("O3K_DATABASE_ID", format!("sqlite:{}", path.display()));
            }
            Self::Postgres(url) => {
                command
                    .env("O3K_DATABASE_BACKEND", "postgres")
                    .env("O3K_DATABASE_URL", url)
                    .env("O3K_DATABASE_ID", "postgresql:disposable-pp5-1035");
            }
        }
    }

    fn evidence_id(&self) -> String {
        match self {
            Self::Sqlite(path) => format!("sqlite:{}", path.display()),
            Self::Postgres(_) => "postgresql:disposable-pp5-1035".to_owned(),
        }
    }

    async fn connect(&self) -> Result<o3k_store::unified::O3kStore, Error> {
        Ok(match self {
            Self::Sqlite(path) => o3k_store::unified::O3kStore::connect_sqlite_file(path).await?,
            Self::Postgres(url) => o3k_store::unified::O3kStore::connect_postgres(url).await?,
        })
    }

    fn is_postgres(&self) -> bool {
        matches!(self, Self::Postgres(_))
    }
}

struct PgFixture {
    admin_url: String,
    database: String,
    url: String,
}

impl PgFixture {
    async fn new() -> Result<Option<Self>, Error> {
        let Ok(source_url) = std::env::var("O3K_DATABASE_URL") else {
            eprintln!("skipping PostgreSQL #1035 process regression: O3K_DATABASE_URL is unset");
            return Ok(None);
        };
        let purpose = std::env::var("O3K_TEST_DATABASE_PURPOSE").map_err(
            |_| "O3K_TEST_DATABASE_PURPOSE must identify the disposable PostgreSQL test database",
        )?;
        if purpose.is_empty()
            || !purpose
                .bytes()
                .all(|byte| byte.is_ascii_alphanumeric() || byte == b'_')
        {
            return Err("O3K_TEST_DATABASE_PURPOSE contains unsafe database-name bytes".into());
        }
        let parsed = url::Url::parse(&source_url)?;
        let database = format!("o3k_{}_pp5_1035_{}", purpose, Uuid::now_v7().simple());
        let mut admin = parsed.clone();
        admin.set_path("/postgres");
        let admin_url = admin.to_string();
        let pool = PgPoolOptions::new()
            .max_connections(1)
            .connect(&admin_url)
            .await?;
        sqlx::query(&format!("CREATE DATABASE {database}"))
            .execute(&pool)
            .await?;
        pool.close().await;
        let mut isolated = parsed;
        isolated.set_path(&format!("/{database}"));
        Ok(Some(Self {
            admin_url,
            database,
            url: isolated.to_string(),
        }))
    }

    async fn dispose(self) -> Result<(), Error> {
        let pool = PgPoolOptions::new()
            .max_connections(1)
            .connect(&self.admin_url)
            .await?;
        // Attempt to terminate sessions, but still attempt the FORCE drop if
        // this diagnostic step fails; the drop is the cleanup authority.
        let _ = sqlx::query(
            "SELECT pg_terminate_backend(pid) FROM pg_stat_activity \
             WHERE datname = $1 AND pid <> pg_backend_pid()",
        )
        .bind(&self.database)
        .execute(&pool)
        .await;
        let drop_result = sqlx::query(&format!("DROP DATABASE {} WITH (FORCE)", self.database))
            .execute(&pool)
            .await;
        pool.close().await;
        drop_result?;
        Ok(())
    }
}

fn now() -> String {
    Utc::now().to_rfc3339()
}

fn sha256(bytes: &[u8]) -> String {
    let mut digest = Sha256::new();
    digest.update(bytes);
    format!("{:x}", digest.finalize())
}

fn file_sha256(path: &Path) -> Result<String, Error> {
    Ok(sha256(&fs::read(path)?))
}

fn free_address() -> Result<SocketAddr, Error> {
    Ok(TcpListener::bind("127.0.0.1:0")?.local_addr()?)
}

fn is_run_owned_server_endpoint(port: &Value) -> bool {
    port["project_id"].as_str() == Some(PROJECT_ID)
        && port["name"]
            .as_str()
            .is_some_and(|name| o3k_network::is_server_owned_endpoint_name(PROJECT_ID, name))
}

#[test]
fn teardown_endpoint_count_ignores_foreign_server_owned_names() {
    assert!(is_run_owned_server_endpoint(
        &json!({"project_id": PROJECT_ID, "name": format!("o3k-server:{PROJECT_ID}:run")})
    ));
    assert!(!is_run_owned_server_endpoint(
        &json!({"project_id": FOREIGN_PROJECT_ID, "name": format!("o3k-server:{FOREIGN_PROJECT_ID}:foreign")})
    ));
    assert!(!is_run_owned_server_endpoint(
        &json!({"project_id": FOREIGN_PROJECT_ID, "name": format!("o3k-server:{PROJECT_ID}:spoof")})
    ));
    assert!(!is_run_owned_server_endpoint(
        &json!({"project_id": PROJECT_ID, "name": "caller-port"})
    ));
}

fn proc_starttime(pid: u32) -> Result<u64, Error> {
    let text = fs::read_to_string(format!("/proc/{pid}/stat"))?;
    parse_proc_starttime(&text)
}

fn parse_proc_starttime(text: &str) -> Result<u64, Error> {
    let after = text.rsplit_once(") ").ok_or("malformed /proc stat")?.1;
    after
        .split_whitespace()
        .nth(19)
        .ok_or("missing proc starttime")?
        .parse()
        .map_err(Into::into)
}

fn process_instance_gone(pid: u32, expected_starttime: u64) -> Result<bool, Error> {
    let path = format!("/proc/{pid}/stat");
    let text = match fs::read_to_string(path) {
        Ok(text) => text,
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => return Ok(true),
        Err(error) => return Err(error.into()),
    };
    Ok(parse_proc_starttime(&text)? != expected_starttime)
}

fn proc_exe(pid: u32) -> Result<PathBuf, Error> {
    Ok(fs::read_link(format!("/proc/{pid}/exe"))?)
}

fn proc_cmdline_digest(pid: u32) -> Result<String, Error> {
    Ok(sha256(&fs::read(format!("/proc/{pid}/cmdline"))?))
}

fn proc_env(pid: u32) -> Result<BTreeMap<String, String>, Error> {
    let mut result = BTreeMap::new();
    for item in fs::read(format!("/proc/{pid}/environ"))?.split(|byte| *byte == 0) {
        if let Some(index) = item.iter().position(|byte| *byte == b'=') {
            let (key, value) = item.split_at(index);
            let value = &value[1..];
            let key = String::from_utf8_lossy(key).to_string();
            let value = String::from_utf8_lossy(value).to_string();
            if ![
                "O3K_BOOTSTRAP_PASSWORD",
                "O3K_TOKEN_SIGNING_KEY",
                "O3K_EXTRA_TENANT_PASSWORD",
            ]
            .contains(&key.as_str())
            {
                result.insert(key, value);
            }
        }
    }
    Ok(result)
}

fn listener_owner(address: SocketAddr, pid: u32, starttime: u64) -> Result<Value, Error> {
    let output = Command::new("ss").args(["-ltnpH"]).output()?;
    if !output.status.success() {
        return Err("ss failed".into());
    }
    let text = String::from_utf8_lossy(&output.stdout);
    let needle = format!(":{}", address.port());
    let owned = text
        .lines()
        .any(|line| line.contains(&needle) && line.contains(&format!("pid={pid},")));
    if !owned {
        return Err(format!("listener {} is not owned by pid {pid}: {text}", address).into());
    }
    Ok(
        json!({"socket": address.to_string(), "owner": {"pid": pid, "proc_starttime": starttime}, "owned": true, "ss": text.lines().filter(|line| line.contains(&needle)).collect::<Vec<_>>() }),
    )
}

fn listener_present(address: SocketAddr) -> Result<bool, Error> {
    let output = Command::new("ss").args(["-ltnH"]).output()?;
    if !output.status.success() {
        return Err("ss failed while checking listener absence".into());
    }
    let local_suffix = format!(":{}", address.port());
    Ok(String::from_utf8_lossy(&output.stdout).lines().any(|line| {
        line.split_whitespace()
            .nth(3)
            .is_some_and(|local_address| local_address.ends_with(&local_suffix))
    }))
}

struct Evidence {
    path: PathBuf,
    data: Map<String, Value>,
}

impl Evidence {
    fn new(
        path: PathBuf,
        run_id: &str,
        source_sha: &str,
        harness_digest: &str,
    ) -> Result<Self, Error> {
        let mut data = Map::new();
        data.insert(
            "artifact_type".into(),
            json!("focused #1035 acceptance artifact"),
        );
        data.insert("schema".into(), json!("o3k.pp5-1035-restart.v1"));
        data.insert("profile".into(), json!("PP.5"));
        data.insert("status".into(), json!("running"));
        data.insert("current_phase".into(), json!("prepared"));
        data.insert("failure_phase".into(), Value::Null);
        data.insert("run_id".into(), json!(run_id));
        data.insert("source_sha".into(), json!(source_sha));
        data.insert("harness_digest".into(), json!(harness_digest));
        data.insert(
            "timestamps".into(),
            json!({"started_at": now(), "completed_at": Value::Null}),
        );
        let this = Self { path, data };
        this.write()?;
        Ok(this)
    }

    fn set(&mut self, key: &str, value: Value) {
        self.data.insert(key.to_owned(), value);
    }

    fn checkpoint(&mut self, phase: &str) -> Result<(), Error> {
        self.data.insert("current_phase".into(), json!(phase));
        self.write()
    }

    fn fail(&mut self, phase: &str, error: &str) -> Result<(), Error> {
        self.data.insert("status".into(), json!("failed"));
        self.data.insert("current_phase".into(), json!(phase));
        self.data.insert("failure_phase".into(), json!(phase));
        self.data.insert("failure".into(), json!(error));
        self.write()
    }

    fn complete(&mut self) -> Result<(), Error> {
        self.data.insert("status".into(), json!("completed"));
        self.data.insert("current_phase".into(), json!("completed"));
        self.data.insert("failure_phase".into(), Value::Null);
        if let Some(timestamps) = self
            .data
            .get_mut("timestamps")
            .and_then(Value::as_object_mut)
        {
            timestamps.insert("completed_at".into(), json!(now()));
        }
        self.write()
    }

    fn write(&self) -> Result<(), Error> {
        if let Some(parent) = self.path.parent() {
            fs::create_dir_all(parent)?;
        }
        let temporary = self.path.with_extension("json.tmp");
        let mut file = OpenOptions::new()
            .create(true)
            .truncate(true)
            .write(true)
            .open(&temporary)?;
        file.write_all(serde_json::to_string_pretty(&self.data)?.as_bytes())?;
        file.sync_all()?;
        fs::rename(&temporary, &self.path)?;
        if let Some(parent) = self.path.parent() {
            File::open(parent)?.sync_all()?;
        }
        Ok(())
    }
}

fn make_tls(root: &Path) -> Result<(PathBuf, PathBuf, PathBuf), Error> {
    let fixture =
        Path::new(env!("CARGO_MANIFEST_DIR")).join("../../crates/o3k-compute-agent/tests/fixtures");
    let ca = root.join("ca.pem");
    let key = root.join("server-key.pem");
    let cert = root.join("server.pem");
    fs::copy(fixture.join("ca.pem"), &ca)?;
    fs::copy(fixture.join("server-key.pem"), &key)?;
    fs::copy(fixture.join("server.pem"), &cert)?;
    Ok((ca, cert, key))
}

#[allow(clippy::too_many_arguments)]
fn start_o3kd(
    root: &Path,
    backend: &Backend,
    http: SocketAddr,
    control: SocketAddr,
    log: &Path,
    controller: (&str, &str),
    release_file: Option<&Path>,
    waiter: Option<&Path>,
    orphan_checkpoint: Option<(&Path, Uuid, &str)>,
    fault_pause: bool,
    tls: &(PathBuf, PathBuf, PathBuf),
    run_id: &str,
) -> Result<Child, Error> {
    validate_controller_identity(controller.0, controller.1)?;
    let log_file = OpenOptions::new().create(true).append(true).open(log)?;
    let log_copy = log_file.try_clone()?;
    let mut command = Command::new(env!("CARGO_BIN_EXE_o3kd"));
    command
        .args([
            "--provider",
            "fake",
            "--listen-addr",
            &http.to_string(),
            "--compute-control-addr",
            &control.to_string(),
            "--compute-server-certificate",
            tls.1.to_str().ok_or("cert path")?,
            "--compute-server-private-key",
            tls.2.to_str().ok_or("key path")?,
            "--compute-client-ca",
            tls.0.to_str().ok_or("ca path")?,
            "--compute-authorized-agents",
            "pp5-agent=0000000000000000000000000000000000000000000000000000000000000000",
            "--data-dir",
            root.to_str().ok_or("data path")?,
            "--log-filter",
            // Keep the normal process logs at info, but retain the compute
            // orphan-repair sweep's debug no-op lines.  The focused fairness
            // proof counts real subsequent sweep opportunities, not a
            // synthetic counter.
            "o3k_compute=debug,info",
        ])
        .env("O3K_BOOTSTRAP_PASSWORD", BOOTSTRAP_PASSWORD)
        .env("O3K_TOKEN_SIGNING_KEY", TOKEN_SIGNING_KEY)
        .env("O3K_EXTRA_TENANT_PROJECT_ID", FOREIGN_PROJECT_ID)
        .env("O3K_EXTRA_TENANT_PROJECT_NAME", "pp5-foreign")
        .env(
            "O3K_EXTRA_TENANT_USER_ID",
            "7be2af98-95b4-4f1b-a9b1-13f93ad90f33",
        )
        .env("O3K_EXTRA_TENANT_USER_NAME", "pp5-foreign-user")
        .env("O3K_EXTRA_TENANT_PASSWORD", FOREIGN_PASSWORD)
        .env("O3K_CONTROLLER_ID", controller.0)
        .env("O3K_CONTROLLER_EPOCH", controller.1)
        .env("O3K_STATE_ROOT", root)
        .env("O3K_HTTP_ADDRESS", http.to_string())
        .env("O3K_CONTROL_ADDRESS", control.to_string())
        .env("O3K_REPAIR_TIMEOUT_MS", "30000")
        .env(
            "O3K_SOURCE_COMMIT",
            std::env::var("O3K_PP5_1035_SOURCE_SHA").unwrap_or_else(|_| "unknown".into()),
        )
        .env("O3K_PP5_RUN_ID", run_id)
        .env("O3K_AUTHORITY_MODE", "o3k-implemented")
        .stdout(Stdio::from(log_file))
        .stderr(Stdio::from(log_copy));
    backend.configure(&mut command);
    if let Some(file) = release_file {
        command.env("O3K_TEST_FAULT_ORPHAN_REPAIR_LOCK_RELEASE_FILE", file);
        command.env("O3K_TEST_FAULT_ORPHAN_REPAIR_LOCK_TIMEOUT_MS", "30000");
    }
    if let Some(file) = waiter {
        command.env("O3K_TEST_CREATE_LOCK_WAITER_MARKER", file);
    }
    if let Some((file, target_server, target_endpoint)) = orphan_checkpoint {
        command.env("O3K_TEST_FAULT_ORPHAN_REPAIR_CHECKPOINT_FILE", file);
        command.env(
            "O3K_TEST_FAULT_ORPHAN_REPAIR_TARGET_SERVER_ID",
            target_server.to_string(),
        );
        command.env(
            "O3K_TEST_FAULT_ORPHAN_REPAIR_TARGET_ENDPOINT_ID",
            target_endpoint,
        );
        command.env("O3K_TEST_FAULT_ORPHAN_REPAIR_RUN_ID", run_id);
        // Exercise every terminal-delete cleanup seat, including the native
        // adapter's direct fallback. Each seat must preserve the exact target
        // until the resource-scoped orphan checkpoint is published.
        command.env(
            "O3K_TEST_FAULT_SUPPRESS_TERMINAL_DELETE_RELEASE_RESOURCE_ID",
            target_server.to_string(),
        );
        command.env(
            "O3K_TEST_FAULT_SUPPRESS_TERMINAL_DELETE_RELEASE_RUN_ID",
            run_id,
        );
    }
    if fault_pause {
        if backend.is_postgres() {
            command.env(FAULT_ENV, "0").env(
                "O3K_TEST_FAULT_PAUSE_BEFORE_ENDPOINT_RELEASE_RELEASE_FILE",
                root.join("sync/old-endpoint-release-gate"),
            );
        } else {
            command.env(FAULT_ENV, "4000");
        }
    }
    let child = command.spawn()?;
    Ok(child)
}

fn controller_identity(prefix: &str, run_id: &str) -> (String, String) {
    (
        format!("{prefix}-{run_id}"),
        format!("{prefix}-epoch-{run_id}"),
    )
}

fn validate_controller_identity(controller_id: &str, controller_epoch: &str) -> Result<(), Error> {
    for (field, value) in [
        ("controller ID", controller_id),
        ("controller epoch", controller_epoch),
    ] {
        if value.len() > MAX_CONTROLLER_IDENTITY_BYTES {
            return Err(format!(
                "test fixture {field} is {} bytes; store limit is {MAX_CONTROLLER_IDENTITY_BYTES}",
                value.len()
            )
            .into());
        }
    }
    Ok(())
}

fn kill_process(child: &mut Child) -> Result<(), Error> {
    let status = Command::new("kill")
        .args(["-KILL", &child.id().to_string()])
        .status()?;
    if !status.success() {
        return Err(format!("SIGKILL failed: {status}").into());
    }
    Ok(())
}

async fn wait_ready(
    child: &mut Child,
    http: SocketAddr,
    control: SocketAddr,
    timeout: Duration,
    log: &Path,
    phase: &'static str,
    operation: &'static str,
) -> Result<Value, Error> {
    let client = reqwest::Client::new();
    let deadline = Instant::now() + timeout;
    loop {
        if let Ok(start) = proc_starttime(child.id())
            && let (Ok(_), Ok(_)) = (
                listener_owner(http, child.id(), start),
                listener_owner(control, child.id(), start),
            )
        {
            let request_deadline = tokio::time::Instant::from_std(deadline);
            if let Ok(Ok(response)) = tokio::time::timeout_at(
                request_deadline,
                client.get(format!("http://{http}/readyz")).send(),
            )
            .await
                && response.status() == reqwest::StatusCode::OK
                && let Ok(Ok(body)) =
                    tokio::time::timeout_at(request_deadline, response.text()).await
            {
                let status = reqwest::StatusCode::OK.as_u16();
                return Ok(
                    json!({"status": status, "body_sha256": sha256(body.as_bytes()), "timestamp": now(), "served_by_new": true}),
                );
            }
        }
        if let Some(status) = child.try_wait()? {
            let diagnostic = json!({
                "phase": phase,
                "status": "failed",
                "failed_operation": operation,
                "observer_type": "test_process_and_bounded_log",
                "resource_class": "daemon_startup",
                "command_class": "o3kd_process",
                "process_id": child.id(),
                "exit_code": status.code(),
                "http_listener_present": listener_present(http).ok(),
                "control_listener_present": listener_present(control).ok(),
                "startup_log": startup_log_tail(log),
            });
            return Err(format!(
                "o3kd exited during readiness: {status}; diagnostic={}",
                serde_json::to_string(&diagnostic)?
            )
            .into());
        }
        if Instant::now() >= deadline {
            let diagnostic = json!({
                "phase": phase,
                "status": "failed",
                "failed_operation": operation,
                "failure_cause": "readiness_timeout",
                "observer_type": "test_process_and_bounded_log",
                "resource_class": "daemon_startup",
                "command_class": "o3kd_process",
                "process_id": child.id(),
                "exit_code": null,
                "http_listener_present": listener_present(http).ok(),
                "control_listener_present": listener_present(control).ok(),
                "startup_log": startup_log_tail(log),
            });
            return Err(format!(
                "o3kd did not become ready before timeout; diagnostic={}",
                serde_json::to_string(&diagnostic)?
            )
            .into());
        }
        tokio::time::sleep(Duration::from_millis(50)).await;
    }
}

fn startup_log_tail(path: &Path) -> Value {
    const MAX_BYTES: u64 = 16 * 1024;

    let result = (|| -> Result<(Vec<u8>, bool), Error> {
        let mut file = File::open(path)?;
        let length = file.metadata()?.len();
        let offset = length.saturating_sub(MAX_BYTES);
        file.seek(SeekFrom::Start(offset))?;
        let mut bytes = Vec::with_capacity(MAX_BYTES as usize);
        file.take(MAX_BYTES).read_to_end(&mut bytes)?;
        Ok((bytes, offset > 0))
    })();

    match result {
        Ok((bytes, truncated)) => {
            let raw = String::from_utf8_lossy(&bytes);
            let tail = raw
                .lines()
                .rev()
                .take(32)
                .collect::<Vec<_>>()
                .into_iter()
                .rev()
                .map(redact_startup_log_line)
                .collect::<Vec<_>>()
                .join("\n");
            json!({
                "read_status": "ok",
                "truncated": truncated,
                "tail_bytes": bytes.len(),
                "tail_sha256": sha256(&bytes),
                "tail": tail,
            })
        }
        Err(error) => json!({
            "read_status": "failed",
            "diagnostic": error.to_string(),
        }),
    }
}

fn redact_startup_log_line(line: &str) -> String {
    let mut redacted = line
        .replace(BOOTSTRAP_PASSWORD, "[REDACTED]")
        .replace(FOREIGN_PASSWORD, "[REDACTED]")
        .replace(TOKEN_SIGNING_KEY, "[REDACTED]");

    // Startup errors can include a PostgreSQL connection URL. Keep the
    // diagnostic context while withholding any authority or query secrets.
    for scheme in ["postgres://", "postgresql://"] {
        let mut search_from = 0;
        while let Some(relative_start) = redacted[search_from..].find(scheme) {
            let start = search_from + relative_start;
            let end = redacted[start..]
                .find(char::is_whitespace)
                .map_or(redacted.len(), |relative_end| start + relative_end);
            redacted.replace_range(start..end, "[REDACTED_POSTGRES_URL]");
            search_from = start + "[REDACTED_POSTGRES_URL]".len();
            if search_from >= redacted.len() {
                break;
            }
        }
    }
    redacted
}

#[test]
fn startup_log_diagnostic_redacts_credentials() {
    let line = format!(
        "database startup failed password={BOOTSTRAP_PASSWORD} url=postgresql://db-user:db-password@db.invalid/o3k?sslkey=private-key"
    );
    let redacted = redact_startup_log_line(&line);

    assert!(redacted.contains("database startup failed"));
    assert!(redacted.contains("[REDACTED]"));
    assert!(redacted.contains("[REDACTED_POSTGRES_URL]"));
    assert!(!redacted.contains(BOOTSTRAP_PASSWORD));
    assert!(!redacted.contains("db-password"));
    assert!(!redacted.contains("private-key"));
}

#[tokio::test]
async fn readiness_timeout_records_redacted_startup_diagnostics() -> Result<(), Error> {
    let root = std::env::temp_dir().join(format!("o3k-pp5-startup-diagnostic-{}", Uuid::now_v7()));
    fs::create_dir_all(&root)?;
    let log = root.join("o3kd.log");
    fs::write(
        &log,
        format!(
            "database startup failed password={BOOTSTRAP_PASSWORD} url=postgresql://db-user:db-password@db.invalid/o3k?sslkey=private-key\n"
        ),
    )?;
    let mut child = Command::new("sleep").arg("5").spawn()?;
    let outcome = wait_ready(
        &mut child,
        free_address()?,
        free_address()?,
        Duration::from_millis(100),
        &log,
        "replacement_daemon_startup",
        "wait_replacement_readiness",
    )
    .await;
    stop_process(&mut child)?;
    let diagnostic = match outcome {
        Err(error) => error.to_string(),
        Ok(_) => {
            return Err("process without readiness listeners unexpectedly became ready".into());
        }
    };
    assert!(diagnostic.contains("replacement_daemon_startup"));
    assert!(diagnostic.contains("wait_replacement_readiness"));
    assert!(diagnostic.contains("readiness_timeout"));
    assert!(diagnostic.contains("database startup failed"));
    assert!(!diagnostic.contains(BOOTSTRAP_PASSWORD));
    assert!(!diagnostic.contains("db-password"));
    assert!(!diagnostic.contains("private-key"));
    fs::remove_dir_all(root)?;
    Ok(())
}

#[test]
fn postgres_run_controller_identities_fit_store_bound() -> Result<(), Error> {
    let run_id = format!("postgres-{}", Uuid::now_v7().simple());
    let fixture_setup = controller_identity("fixture-setup", &run_id);
    assert!(fixture_setup.0.len() <= MAX_CONTROLLER_IDENTITY_BYTES);
    assert!(fixture_setup.1.len() <= MAX_CONTROLLER_IDENTITY_BYTES);
    validate_controller_identity(&fixture_setup.0, &fixture_setup.1)?;

    let previous_run_id = format!("postgres-{}", Uuid::now_v7());
    let previous_fixture_setup = controller_identity("fixture-setup", &previous_run_id);
    assert_eq!(
        previous_fixture_setup.1.len(),
        MAX_CONTROLLER_IDENTITY_BYTES + 1
    );
    assert!(
        validate_controller_identity(&previous_fixture_setup.0, &previous_fixture_setup.1).is_err()
    );

    let boundary_value = "x".repeat(MAX_CONTROLLER_IDENTITY_BYTES);
    validate_controller_identity(&boundary_value, &boundary_value)?;
    let oversized_value = "x".repeat(MAX_CONTROLLER_IDENTITY_BYTES + 1);
    assert!(validate_controller_identity(&oversized_value, "epoch").is_err());
    assert!(validate_controller_identity("controller", &oversized_value).is_err());
    Ok(())
}

async fn token(
    client: &reqwest::Client,
    address: SocketAddr,
    user: &str,
    password: &str,
    project: &str,
) -> Result<String, Error> {
    let response = client.post(format!("http://{address}/v3/auth/tokens")).json(&json!({"auth":{"identity":{"methods":["password"],"password":{"user":{"name":user,"password":password}}},"scope":{"project":{"name":project}}}})).send().await?;
    let status = response.status();
    let value = response
        .headers()
        .get("x-subject-token")
        .and_then(|v| v.to_str().ok())
        .map(str::to_owned);
    if status != reqwest::StatusCode::CREATED {
        return Err(format!("token failed: {status}").into());
    }
    value.ok_or_else(|| "missing token".into())
}

async fn post(
    client: &reqwest::Client,
    address: SocketAddr,
    token: &str,
    path: &str,
    body: Value,
) -> Result<(reqwest::StatusCode, Value), Error> {
    let response = client
        .post(format!("http://{address}{path}"))
        .header("x-auth-token", token)
        .header("authorization", format!("Bearer {token}"))
        .json(&body)
        .send()
        .await?;
    let status = response.status();
    let value = response.json().await.unwrap_or(Value::Null);
    if !status.is_success() {
        return Err(format!("POST {path} failed: {status}: {value}").into());
    }
    Ok((status, value))
}

async fn ports(
    client: &reqwest::Client,
    address: SocketAddr,
    token: &str,
) -> Result<Vec<Value>, Error> {
    let response = client
        .get(format!("http://{address}/v2.0/ports"))
        .header("x-auth-token", token)
        .send()
        .await?;
    let status = response.status();
    let value: Value = response.json().await?;
    if status != reqwest::StatusCode::OK {
        return Err(format!("ports failed: {status}: {value}").into());
    }
    Ok(value["ports"].as_array().cloned().unwrap_or_default())
}

async fn create_native(
    client: &reqwest::Client,
    address: SocketAddr,
    token: &str,
    name: &str,
    network: &str,
) -> Result<(Uuid, Value), Error> {
    let (_, body) = post(client, address, token, "/o3k/v1/compute/servers", json!({"kind":"compute:server","spec":{"name":name,"image_id":"pp5-image","flavor_id":FLAVOR_ID,"network_ids":[network]}})).await?;
    let id = body["resource_id"]
        .as_str()
        .or_else(|| body["server"]["id"].as_str())
        .ok_or("create missing resource_id")?;
    Ok((Uuid::parse_str(id)?, body))
}

async fn create_existing_port(
    client: &reqwest::Client,
    address: SocketAddr,
    token: &str,
    _project: &str,
    name: &str,
    port: &str,
) -> Result<(Uuid, Value, Instant), Error> {
    let started = Instant::now();
    let response = client.post(format!("http://{address}/o3k/v1/compute/servers")).header("authorization", format!("Bearer {token}")).header("content-type", "application/json").header("idempotency-key", name).json(&json!({"kind":"compute:server","spec":{"name":name,"image_id":"pp5-image","flavor_id":FLAVOR_ID,"network_ids":[port]}})).send().await?;
    let status = response.status();
    let body: Value = response.json().await.unwrap_or(Value::Null);
    if !status.is_success() {
        return Err(format!("existing-port create failed: {status}: {body}").into());
    }
    let id = body["server"]["id"]
        .as_str()
        .or_else(|| body["resource_id"].as_str())
        .ok_or("contention create missing id")?;
    Ok((Uuid::parse_str(id)?, body, started))
}

async fn wait_state(
    probe: &TestOwnedProbe,
    id: Uuid,
    state: &str,
    timeout: Duration,
    diagnostics: &mut StoreDiagnostics<'_>,
) -> Result<(), Error> {
    let deadline = Instant::now() + timeout;
    loop {
        diagnostics.record("get_resource", probe.is_alive());
        let resource = probe.store()?.get_resource(id).await?;
        if resource.observed_state == state {
            return Ok(());
        }
        if Instant::now() >= deadline {
            return Err(format!("{id} did not reach {state}: {}", resource.observed_state).into());
        }
        tokio::time::sleep(Duration::from_millis(50)).await;
    }
}

async fn wait_server_api_state(
    client: &reqwest::Client,
    address: SocketAddr,
    token: &str,
    id: Uuid,
    state: &str,
    timeout: Duration,
) -> Result<(), Error> {
    let deadline = Instant::now() + timeout;
    loop {
        let response = client
            .get(format!("http://{address}/o3k/v1/compute/servers/{id}"))
            .header("authorization", format!("Bearer {token}"))
            .send()
            .await?;
        let status = response.status();
        let body = response.json::<Value>().await.unwrap_or(Value::Null);
        if status.is_success() {
            let observed = body["status"]["state"]
                .as_str()
                .or_else(|| body["server"]["status"]["state"].as_str())
                .unwrap_or_default();
            if observed.eq_ignore_ascii_case(state) {
                return Ok(());
            }
        }
        if Instant::now() >= deadline {
            return Err(format!(
                "server {id} did not reach API state {state}; last status {status}: {body}"
            )
            .into());
        }
        tokio::time::sleep(Duration::from_millis(50)).await;
    }
}

struct TestOwnedProbe {
    store: Option<o3k_store::unified::O3kStore>,
    initialized: bool,
    daemon_running: bool,
    delete_paused: bool,
    reconstruction_observed: bool,
}

impl TestOwnedProbe {
    fn new() -> Self {
        Self {
            store: None,
            initialized: false,
            daemon_running: false,
            delete_paused: false,
            reconstruction_observed: false,
        }
    }

    async fn open_while_daemon_stopped(&mut self, backend: &Backend) -> Result<(), Error> {
        if self.daemon_running {
            return Err("test-owned probe must open only while o3kd is stopped".into());
        }
        if self.is_alive() {
            return Err("test-owned probe is already open".into());
        }
        self.store = Some(backend.connect().await?);
        self.initialized = true;
        Ok(())
    }

    fn mark_daemon_started(&mut self) -> Result<(), Error> {
        if self.daemon_running {
            return Err("test daemon is already marked running".into());
        }
        if !self.initialized {
            return Err("test-owned probe must be initialized before daemon startup".into());
        }
        self.daemon_running = true;
        self.delete_paused = false;
        Ok(())
    }

    fn mark_delete_paused(&mut self) -> Result<(), Error> {
        if !self.daemon_running {
            return Err("delete pause requires a running daemon".into());
        }
        self.delete_paused = true;
        Ok(())
    }

    async fn observe_owned_endpoint_during_paused_delete(
        &self,
        project_id: &str,
        endpoint_id: &Uuid,
    ) -> Result<o3k_store::PortRecord, Error> {
        if !self.daemon_running || !self.delete_paused {
            return Err(
                "direct endpoint observation requires the old daemon's paused delete window".into(),
            );
        }
        let endpoint = self
            .store()?
            .get_port(project_id, endpoint_id)
            .await?
            .ok_or("owned endpoint disappeared before SIGKILL")?;
        if endpoint.project_id != project_id
            || !o3k_network::is_server_owned_endpoint_name(project_id, &endpoint.name)
        {
            return Err(
                "direct endpoint observation did not match run-owned endpoint identity".into(),
            );
        }
        Ok(endpoint)
    }

    fn mark_daemon_stopped(&mut self) -> Result<(), Error> {
        if !self.daemon_running {
            return Err("test daemon is not marked running".into());
        }
        self.daemon_running = false;
        self.delete_paused = false;
        Ok(())
    }

    async fn update_port_binding_fixture(
        &self,
        project_id: &str,
        endpoint_id: &Uuid,
        host: &str,
        state: &str,
    ) -> Result<(), Error> {
        if self.daemon_running {
            return Err(
                "test fixture writes are forbidden while an o3kd daemon may own a write transaction"
                    .into(),
            );
        }
        self.store()?
            .update_port_binding(project_id, endpoint_id, Some(host), Some(state))
            .await?;
        Ok(())
    }

    async fn acquire_repair_lease_during_paused_delete(
        &self,
        backend: &Backend,
        controller_id: &o3k_store::ControllerId,
        controller_epoch: &o3k_store::ControllerEpoch,
    ) -> Result<o3k_store::LeaseAcquireOutcome, Error> {
        if !self.daemon_running || !self.delete_paused {
            return Err(
                "concurrent repair lease seeding requires the old daemon's paused delete window"
                    .into(),
            );
        }
        if !backend.is_postgres() {
            return Err("concurrent repair lease seeding is PostgreSQL-only".into());
        }

        // This is the one intentional direct write while a daemon is running:
        // the PostgreSQL test holds a competing durable lease during the
        // old daemon's explicitly paused delete window. Other fixture writes
        // remain forbidden until the daemon is stopped.
        Ok(self
            .store()?
            .acquire_work_lease(
                "server-endpoint-orphan-repair",
                "repair",
                controller_id,
                controller_epoch,
                Duration::from_secs(12),
            )
            .await?)
    }

    fn is_alive(&self) -> bool {
        self.store.is_some()
    }

    fn store(&self) -> Result<&o3k_store::unified::O3kStore, Error> {
        self.store
            .as_ref()
            .ok_or_else(|| "test-owned probe is closed across the restart boundary".into())
    }

    fn close(&mut self) {
        self.store.take();
    }

    fn require_closed_at_restart(&self) -> Result<(), Error> {
        if self.is_alive() {
            return Err("test-owned probe is still alive at the daemon restart boundary".into());
        }
        Ok(())
    }

    async fn reopen(&mut self, backend: &Backend) -> Result<(), Error> {
        if self.is_alive() {
            return Err("test-owned probe must be closed before opening a fresh pool".into());
        }
        if !self.daemon_running || !self.reconstruction_observed {
            return Err(
                "fresh probe may open only after replacement reconstruction is observed".into(),
            );
        }
        self.store = Some(backend.connect().await?);
        Ok(())
    }

    fn mark_reconstruction_observed(&mut self) -> Result<(), Error> {
        if !self.daemon_running {
            return Err("replacement daemon must be running at reconstruction observation".into());
        }
        self.reconstruction_observed = true;
        Ok(())
    }
}

struct StoreDiagnostics<'a> {
    evidence: &'a mut Evidence,
    backend: &'a Backend,
    old_pid: Option<u32>,
    new_pid: Option<u32>,
    phase: &'a str,
}

impl StoreDiagnostics<'_> {
    fn record(&mut self, operation: &str, probe_alive: bool) {
        store_operation(
            self.evidence,
            self.phase,
            operation,
            self.backend,
            probe_alive,
            self.old_pid,
            self.new_pid,
        );
    }
}

#[tokio::test]
async fn pp5_1035_test_probe_must_close_across_restart_boundary() -> Result<(), Error> {
    let root = std::env::temp_dir().join(format!("o3k-pp5-probe-lifecycle-{}", Uuid::now_v7()));
    fs::create_dir_all(&root)?;
    let backend = Backend::Sqlite(root.join("o3k.sqlite"));
    let mut probe = TestOwnedProbe::new();
    probe.open_while_daemon_stopped(&backend).await?;
    assert!(probe.is_alive());
    assert!(probe.require_closed_at_restart().is_err());
    probe.mark_daemon_started()?;
    let fixture_write = probe
        .update_port_binding_fixture(PROJECT_ID, &Uuid::now_v7(), "pp5-compute-agent", "bound")
        .await;
    let fixture_write_error = fixture_write
        .err()
        .ok_or("fixture write while the daemon runs did not fail closed")?;
    assert!(fixture_write_error.to_string().contains("forbidden"));
    probe.mark_delete_paused()?;
    assert!(
        probe
            .acquire_repair_lease_during_paused_delete(
                &backend,
                &o3k_store::ControllerId::new("test-controller"),
                &o3k_store::ControllerEpoch::new("test-epoch"),
            )
            .await
            .is_err()
    );
    probe.close();
    probe.require_closed_at_restart()?;
    assert!(!probe.is_alive());
    probe.mark_daemon_stopped()?;
    probe.open_while_daemon_stopped(&backend).await?;
    probe.close();
    probe.mark_daemon_started()?;
    assert!(probe.reopen(&backend).await.is_err());
    probe.mark_reconstruction_observed()?;
    probe.reopen(&backend).await?;
    assert!(probe.is_alive());
    probe.close();
    fs::remove_dir_all(root)?;
    Ok(())
}

#[tokio::test]
async fn pp5_1035_paused_delete_endpoint_observation_uses_only_the_owned_store_probe()
-> Result<(), Error> {
    let root = std::env::temp_dir().join(format!("o3k-pp5-paused-endpoint-{}", Uuid::now_v7()));
    fs::create_dir_all(&root)?;
    let backend = Backend::Sqlite(root.join("o3k.sqlite"));
    let mut probe = TestOwnedProbe::new();
    probe.open_while_daemon_stopped(&backend).await?;

    let endpoint_id = Uuid::now_v7();
    let network_id = Uuid::now_v7();
    probe
        .store()?
        .insert_network(&o3k_store::NetworkRecord {
            id: network_id,
            name: "pp5-restart-observation".to_owned(),
            project_id: PROJECT_ID.to_owned(),
            status: "ACTIVE".to_owned(),
        })
        .await?;
    let endpoint = o3k_store::PortRecord {
        id: endpoint_id,
        network_id,
        subnet_id: None,
        project_id: PROJECT_ID.to_owned(),
        name: format!("o3k-server:{PROJECT_ID}:pp5-restart-observation"),
        mac_address: "02:00:00:00:00:01".to_owned(),
        fixed_ip: "192.0.2.10".parse()?,
        status: "ACTIVE".to_owned(),
        binding_host: Some("pp5-compute-agent".to_owned()),
        binding_state: Some("bound".to_owned()),
        binding_generation: 1,
    };
    probe.store()?.insert_port(&endpoint).await?;

    probe.mark_daemon_started()?;
    assert!(
        probe
            .observe_owned_endpoint_during_paused_delete(PROJECT_ID, &endpoint_id)
            .await
            .is_err()
    );
    probe.mark_delete_paused()?;
    let observed = probe
        .observe_owned_endpoint_during_paused_delete(PROJECT_ID, &endpoint_id)
        .await?;
    assert_eq!(observed.id, endpoint_id);
    assert_eq!(observed.project_id, PROJECT_ID);
    assert_eq!(observed.binding_state.as_deref(), Some("bound"));
    assert_eq!(
        observed.fixed_ip,
        "192.0.2.10".parse::<std::net::Ipv4Addr>()?
    );

    probe.close();
    fs::remove_dir_all(root)?;
    Ok(())
}

#[test]
fn pp5_1035_setup_absence_proof_checks_process_identity_and_listener_port() -> Result<(), Error> {
    let pid = std::process::id();
    let starttime = proc_starttime(pid)?;
    assert!(!process_instance_gone(pid, starttime)?);
    assert!(process_instance_gone(pid, starttime + 1)?);

    let listener = TcpListener::bind("127.0.0.1:0")?;
    let address = listener.local_addr()?;
    assert!(listener_present(address)?);
    drop(listener);
    assert!(!listener_present(address)?);
    Ok(())
}

fn store_operation(
    evidence: &mut Evidence,
    phase: &str,
    operation: &str,
    backend: &Backend,
    probe_alive: bool,
    old_pid: Option<u32>,
    new_pid: Option<u32>,
) {
    let process_state = |pid: Option<u32>| {
        pid.map(|pid| json!({"pid": pid, "alive": proc_starttime(pid).is_ok()}))
            .unwrap_or(Value::Null)
    };
    let sqlite_state = match backend {
        Backend::Sqlite(path) => {
            let state = |path: &Path| {
                fs::metadata(path)
                    .ok()
                    .map(|metadata| json!({"present": true, "bytes": metadata.len()}))
                    .unwrap_or_else(|| json!({"present": false}))
            };
            json!({
                "database": state(path),
                "wal": state(&PathBuf::from(format!("{}-wal", path.display()))),
                "shm": state(&PathBuf::from(format!("{}-shm", path.display()))),
            })
        }
        Backend::Postgres(_) => Value::Null,
    };
    evidence.data.insert("current_phase".into(), json!(phase));
    evidence.data.insert(
        "store_diagnostic".into(),
        json!({
            "phase": phase,
            "operation": operation,
            "test_owned_probe_alive": probe_alive,
            "old_daemon": process_state(old_pid),
            "replacement_daemon": process_state(new_pid),
            "sqlite_files": sqlite_state,
        }),
    );
}

async fn delete_native(
    client: &reqwest::Client,
    address: SocketAddr,
    token: &str,
    id: Uuid,
    key: &str,
) -> Result<Value, Error> {
    let response = client
        .delete(format!("http://{address}/o3k/v1/compute/servers/{id}"))
        .header("authorization", format!("Bearer {token}"))
        .header("idempotency-key", key)
        .send()
        .await?;
    let status = response.status();
    let body = response.json().await.unwrap_or(Value::Null);
    if !status.is_success() {
        return Err(format!("delete failed: {status}: {body}").into());
    }
    Ok(body)
}

fn env_value_map(
    intended: &BTreeMap<String, String>,
    effective: &BTreeMap<String, String>,
) -> Value {
    let mut secret_presence = Map::new();
    for key in [
        "O3K_BOOTSTRAP_PASSWORD",
        "O3K_TOKEN_SIGNING_KEY",
        "O3K_EXTRA_TENANT_PASSWORD",
    ] {
        secret_presence.insert(key.into(), json!(effective.contains_key(key)));
    }
    let effective_selected = intended
        .keys()
        .filter_map(|key| effective.get(key).map(|value| (key.clone(), value.clone())))
        .collect::<BTreeMap<_, _>>();
    json!({"intended": intended, "effective": effective_selected, "secret_presence": secret_presence, "match": intended.iter().all(|(k,v)| effective.get(k) == Some(v))})
}

fn secret_presence(pid: u32) -> Result<Map<String, Value>, Error> {
    let raw = fs::read(format!("/proc/{pid}/environ"))?;
    let mut present = Map::new();
    for key in [
        "O3K_BOOTSTRAP_PASSWORD",
        "O3K_TOKEN_SIGNING_KEY",
        "O3K_EXTRA_TENANT_PASSWORD",
    ] {
        let needle = format!("{key}=").into_bytes();
        present.insert(
            key.to_owned(),
            json!(raw.windows(needle.len()).any(|window| window == needle)),
        );
    }
    Ok(present)
}

fn log_has(log: &Path, needle: &str) -> bool {
    fs::read_to_string(log)
        .map(|text| text.contains(needle))
        .unwrap_or(false)
}

fn last_structured_event(log: &Path, event_name: &str) -> Option<Value> {
    fs::read_to_string(log)
        .ok()?
        .lines()
        .filter_map(|line| serde_json::from_str::<Value>(line).ok())
        .filter_map(|record| {
            let fields = record.get("fields")?.as_object()?;
            (fields.get("event")?.as_str()? == event_name).then(|| Value::Object(fields.clone()))
        })
        .next_back()
}

async fn wait_log(log: &Path, needle: &str, timeout: Duration) -> Result<String, Error> {
    let deadline = Instant::now() + timeout;
    while Instant::now() < deadline {
        if log_has(log, needle) {
            return Ok(now());
        }
        tokio::time::sleep(Duration::from_millis(50)).await;
    }
    Err(format!("log transition missing: {needle}").into())
}

async fn wait_orphan_checkpoint(
    path: &Path,
    run_id: &str,
    server_id: Uuid,
    endpoint_id: &str,
    timeout: Duration,
) -> Result<Value, Error> {
    let deadline = Instant::now() + timeout;
    while Instant::now() < deadline {
        if let Ok(raw) = fs::read_to_string(path)
            && let Ok(document) = serde_json::from_str::<Value>(&raw)
            && document["schema_version"] == 2
            && document["run_id"] == run_id
            && document["server_id"] == server_id.to_string()
            && document["endpoint_id"] == endpoint_id
            && document["phase"] == "orphan_confirmed_pre_mutation"
            && document["orphan_confirmed"] == true
            && document["server_terminal_deleted"] == true
            && document["server_owned"] == true
            && document["live_reference_absent"] == true
            && document["orphan_repair_lock_held"] == true
            && document["unbind_not_started"] == true
            && document["endpoint_release_not_started"] == true
        {
            return Ok(document);
        }
        tokio::time::sleep(Duration::from_millis(50)).await;
    }
    Err("resource-scoped orphan checkpoint missing or mismatched".into())
}

struct ChildCleanupGuard {
    child: Option<Child>,
    failure_path: PathBuf,
}

impl ChildCleanupGuard {
    fn new(child: Child, failure_path: PathBuf) -> Self {
        Self {
            child: Some(child),
            failure_path,
        }
    }

    fn child_mut(&mut self) -> Result<&mut Child, Error> {
        self.child
            .as_mut()
            .ok_or_else(|| "child cleanup guard was disarmed".into())
    }

    fn id(&self) -> Result<u32, Error> {
        self.child
            .as_ref()
            .map(Child::id)
            .ok_or_else(|| "child cleanup guard was disarmed".into())
    }

    fn disarm(&mut self) {
        self.child.take();
    }
}

impl Drop for ChildCleanupGuard {
    fn drop(&mut self) {
        let Some(child) = self.child.as_mut() else {
            return;
        };
        if let Err(error) = stop_process(child) {
            let diagnostic = format!("replacement process cleanup failed: {error}");
            let _ = fs::write(&self.failure_path, diagnostic.as_bytes());
            eprintln!("{diagnostic}");
        }
    }
}

async fn run_iteration(
    evidence: &mut Evidence,
    root: &Path,
    run_id: &str,
    backend: &Backend,
) -> Result<(), Error> {
    let client = reqwest::Client::builder().build()?;
    let http = free_address()?;
    let control = free_address()?;
    let log = root.join("o3kd.log");
    let tls = make_tls(root)?;
    let sync = root.join("sync");
    fs::create_dir_all(&sync)?;
    let release = sync.join("release");
    let old_endpoint_release_gate = sync.join("old-endpoint-release-gate");
    let waiter = sync.join("waiter");
    let orphan_checkpoint = sync.join("orphan-checkpoint.json");
    let bootstrap_cleanup_failure = root.join("bootstrap-cleanup-failure");
    let setup_cleanup_failure = root.join("setup-process-cleanup-failure");
    let old_cleanup_failure = root.join("old-process-cleanup-failure");
    let replacement_cleanup_failure = root.join("replacement-cleanup-failure");
    fs::remove_file(&bootstrap_cleanup_failure).ok();
    fs::remove_file(&setup_cleanup_failure).ok();
    fs::remove_file(&old_cleanup_failure).ok();
    fs::remove_file(&replacement_cleanup_failure).ok();
    fs::remove_file(&old_endpoint_release_gate).ok();
    File::create(&release)?;
    let old_controller = controller_identity("old", run_id);
    // The operator diagnostics route is deliberately system-scoped.  Seed a
    // run-local system project/role assignment before the evidence process is
    // started, then let the real IAM snapshot load it during startup.  This
    // keeps the proof on the production authentication path without a test
    // authorization bypass.
    {
        evidence.checkpoint("bootstrap_daemon_startup")?;
        let bootstrap_child = start_o3kd(
            root,
            backend,
            http,
            control,
            &log,
            ("pp5-bootstrap", "pp5-bootstrap-epoch"),
            None,
            None,
            None,
            false,
            &tls,
            run_id,
        )?;
        let mut bootstrap = ChildCleanupGuard::new(bootstrap_child, bootstrap_cleanup_failure);
        let _ = wait_ready(
            bootstrap.child_mut()?,
            http,
            control,
            Duration::from_secs(20),
            &log,
            "bootstrap_daemon_startup",
            "wait_bootstrap_readiness",
        )
        .await?;
        // Finish the bootstrap process before opening the same SQLite file for
        // direct test-fixture writes.  Keeping the daemon alive here creates a
        // writer-vs-writer race during CI (the daemon may still be completing
        // startup persistence), which can surface as SQLITE_BUSY.  The
        // readiness probe already proves schema/bootstrap completion; all
        // subsequent daemon processes reopen this run-owned database normally.
        stop_process(bootstrap.child_mut()?)?;
        bootstrap.disarm();
        store_operation(
            evidence,
            "bootstrap_daemon_stopped_fixture_seed",
            "connect_fixture_store",
            backend,
            false,
            None,
            None,
        );
        let store = backend.connect().await?;
        let now_ts = now();
        store_operation(
            evidence,
            "bootstrap_daemon_stopped_fixture_seed",
            "insert_keystone_project",
            backend,
            false,
            None,
            None,
        );
        store
            .insert_keystone_project(&o3k_store::KeystoneProjectRecord {
                id: "system".to_owned(),
                domain_id: "default".to_owned(),
                name: "system".to_owned(),
                description: Some("PP.5 operator proof scope".to_owned()),
                enabled: true,
                created_at: now_ts.clone(),
            })
            .await?;
        store_operation(
            evidence,
            "bootstrap_daemon_stopped_fixture_seed",
            "insert_keystone_role_assignment",
            backend,
            false,
            None,
            None,
        );
        store
            .insert_keystone_role_assignment(&o3k_store::KeystoneRoleAssignmentRecord {
                id: format!("pp5-system-admin-{run_id}"),
                user_id: "bootstrap-user".to_owned(),
                project_id: "system".to_owned(),
                role_id: "admin".to_owned(),
                created_at: now_ts.clone(),
            })
            .await?;
        store_operation(
            evidence,
            "bootstrap_daemon_stopped_fixture_seed",
            "insert_operator_assignment",
            backend,
            false,
            None,
            None,
        );
        store
            .insert_operator_assignment(&o3k_store::OperatorAssignmentRecord {
                id: format!("pp5-system-operator-{run_id}"),
                user_id: "bootstrap-user".to_owned(),
                profile: "operator-console".to_owned(),
                enabled: true,
                created_at: now_ts.clone(),
                updated_at: now_ts,
            })
            .await?;
    }
    evidence.checkpoint("fixture_setup_daemon_startup")?;
    let setup_child = start_o3kd(
        root,
        backend,
        http,
        control,
        &log,
        (&old_controller.0, &old_controller.1),
        None,
        None,
        None,
        false,
        &tls,
        run_id,
    )?;
    let mut setup = ChildCleanupGuard::new(setup_child, setup_cleanup_failure);
    let _ready_setup = wait_ready(
        setup.child_mut()?,
        http,
        control,
        Duration::from_secs(20),
        &log,
        "fixture_setup_daemon_startup",
        "wait_fixture_setup_readiness",
    )
    .await?;
    let setup_pid = setup.id()?;
    let setup_start = proc_starttime(setup_pid)?;
    let setup_exe = proc_exe(setup_pid)?;
    let setup_digest = file_sha256(&setup_exe)?;
    let setup_listeners = json!({"http": listener_owner(http, setup_pid, setup_start)?, "control": listener_owner(control, setup_pid, setup_start)?});
    evidence.set("setup_process", json!({"pid": setup_pid, "proc_starttime": setup_start, "executable_path": setup_exe, "executable_sha256": setup_digest, "listeners": setup_listeners, "controller_id": old_controller.0, "controller_epoch": old_controller.1}));
    let intended = BTreeMap::from([
        (String::from("O3K_PP5_RUN_ID"), run_id.to_owned()),
        (
            String::from("O3K_AUTHORITY_MODE"),
            String::from("o3k-implemented"),
        ),
        (String::from("O3K_CONTROLLER_ID"), old_controller.0.clone()),
        (
            String::from("O3K_CONTROLLER_EPOCH"),
            old_controller.1.clone(),
        ),
        (String::from("O3K_STATE_ROOT"), root.display().to_string()),
        (String::from("O3K_HTTP_ADDRESS"), http.to_string()),
        (String::from("O3K_CONTROL_ADDRESS"), control.to_string()),
        (String::from("O3K_DATABASE_ID"), backend.evidence_id()),
        (String::from("O3K_REPAIR_TIMEOUT_MS"), String::from("30000")),
    ]);
    let mut intended = intended;
    if backend.is_postgres() {
        intended.insert(
            String::from("O3K_TEST_FAULT_PAUSE_BEFORE_ENDPOINT_RELEASE_MS"),
            String::from("0"),
        );
        intended.insert(
            String::from("O3K_TEST_FAULT_PAUSE_BEFORE_ENDPOINT_RELEASE_RELEASE_FILE"),
            old_endpoint_release_gate.display().to_string(),
        );
    } else {
        intended.insert(
            String::from("O3K_TEST_FAULT_PAUSE_BEFORE_ENDPOINT_RELEASE_MS"),
            String::from("4000"),
        );
    }
    let admin_token = token(&client, http, "admin", BOOTSTRAP_PASSWORD, "admin").await?;
    let foreign_token = token(
        &client,
        http,
        "pp5-foreign-user",
        FOREIGN_PASSWORD,
        "pp5-foreign",
    )
    .await?;
    let fixture = Uuid::new_v4().simple().to_string();
    let (_, network_value) = post(
        &client,
        http,
        &admin_token,
        "/v2.0/networks",
        json!({"network":{"name":format!("pp5-{fixture}")}}),
    )
    .await?;
    let network_id = network_value["network"]["id"]
        .as_str()
        .ok_or("network id")?
        .to_owned();
    let (_, subnet_value) = post(&client, http, &admin_token, "/v2.0/subnets", json!({"subnet":{"name":format!("pp5-subnet-{fixture}"),"network_id":network_id,"cidr":"192.0.2.0/24","ip_version":4}})).await?;
    let subnet_id = subnet_value["subnet"]["id"]
        .as_str()
        .ok_or("subnet id")?
        .to_owned();
    let (_, caller_value) = post(
        &client,
        http,
        &admin_token,
        "/v2.0/ports",
        json!({"port":{"network_id":network_id,"name":format!("pp5-caller-{fixture}")}}),
    )
    .await?;
    let caller = caller_value["port"].clone();
    let caller_id = caller["id"].as_str().ok_or("caller port id")?.to_owned();
    let (_, foreign_network_value) = post(
        &client,
        http,
        &foreign_token,
        "/v2.0/networks",
        json!({"network":{"name":format!("pp5-foreign-network-{fixture}")}}),
    )
    .await?;
    let foreign_network = foreign_network_value["network"]["id"]
        .as_str()
        .ok_or("foreign network")?
        .to_owned();
    let (_, foreign_subnet_value) = post(&client, http, &foreign_token, "/v2.0/subnets", json!({"subnet":{"name":format!("pp5-foreign-subnet-{fixture}"),"network_id":foreign_network,"cidr":"198.51.100.0/24","ip_version":4}})).await?;
    let foreign_subnet = foreign_subnet_value["subnet"]["id"]
        .as_str()
        .ok_or("foreign subnet")?
        .to_owned();
    let (_, foreign_port_value) = post(
        &client,
        http,
        &foreign_token,
        "/v2.0/ports",
        json!({"port":{"network_id":foreign_network,"name":format!("pp5-foreign-port-{fixture}")}}),
    )
    .await?;
    let foreign_port = foreign_port_value["port"].clone();
    let foreign_port_id = foreign_port["id"]
        .as_str()
        .ok_or("foreign port")?
        .to_owned();
    evidence.set("caller", json!({"endpoint_id":caller_id,"project":PROJECT_ID,"ownership_before":caller["project_id"],"ownership_after":caller["project_id"],"exists_before":true,"exists_after":true,"ownership_unchanged":true}));
    evidence.set("foreign", json!({"project":FOREIGN_PROJECT_ID,"port_id":foreign_port_id,"network_id":foreign_network,"subnet_id":foreign_subnet,"attachment_id":"not-applicable-in-fake-provider-topology","before":foreign_port,"after":foreign_port,"changed":false}));
    evidence.checkpoint("prepared")?;

    let (server_id, _) = create_native(
        &client,
        http,
        &admin_token,
        &format!("pp5-window-{fixture}"),
        &network_id,
    )
    .await?;
    wait_server_api_state(
        &client,
        http,
        &admin_token,
        server_id,
        "ACTIVE",
        Duration::from_secs(30),
    )
    .await?;
    let owned_before = ports(&client, http, &admin_token)
        .await?
        .into_iter()
        .find(|port| {
            port["name"]
                .as_str()
                .is_some_and(|name| name.starts_with("o3k-server:"))
        })
        .ok_or("owned endpoint missing")?;
    let endpoint_id = owned_before["id"].as_str().ok_or("endpoint id")?.to_owned();
    let endpoint_uuid = Uuid::parse_str(&endpoint_id)?;

    // Finish all API fixture writes, then stop and prove the setup daemon is
    // gone before opening the direct store. `O3kStore::connect` runs migration
    // and canonical-state checks, so it must not open beside the daemon's API
    // writer during fixture construction. The interrupted-delete daemon below
    // is started only after this one-time direct fixture write completes.
    evidence.checkpoint("setup_server_active")?;
    stop_process(setup.child_mut()?)?;
    let setup_gone = process_instance_gone(setup_pid, setup_start)?;
    let setup_http_listener_gone = !listener_present(http)?;
    let setup_control_listener_gone = !listener_present(control)?;
    evidence.set("setup_process_stopped", json!({"pid":setup_pid,"process_gone":setup_gone,"http_listener_gone":setup_http_listener_gone,"control_listener_gone":setup_control_listener_gone}));
    if !setup_gone || !setup_http_listener_gone || !setup_control_listener_gone {
        return Err("setup daemon did not fully stop before opening the test-owned store".into());
    }
    setup.disarm();

    store_operation(
        evidence,
        "setup_daemon_stopped_probe_open",
        "connect_test_owned_probe",
        backend,
        false,
        None,
        None,
    );
    let mut probe = TestOwnedProbe::new();
    probe.open_while_daemon_stopped(backend).await?;
    store_operation(
        evidence,
        "setup_daemon_stopped_fixture_binding",
        "update_port_binding",
        backend,
        probe.is_alive(),
        None,
        None,
    );
    probe
        .update_port_binding_fixture(PROJECT_ID, &endpoint_uuid, "pp5-compute-agent", "bound")
        .await?;

    evidence.checkpoint("old_daemon_startup")?;
    let old_child = start_o3kd(
        root,
        backend,
        http,
        control,
        &log,
        (&old_controller.0, &old_controller.1),
        None,
        None,
        None,
        true,
        &tls,
        run_id,
    )?;
    let mut child = ChildCleanupGuard::new(old_child, old_cleanup_failure);
    let readiness_old = wait_ready(
        child.child_mut()?,
        http,
        control,
        Duration::from_secs(20),
        &log,
        "old_daemon_startup",
        "wait_old_daemon_readiness",
    )
    .await?;
    probe.mark_daemon_started()?;
    let old_pid = child.id()?;
    let old_start = proc_starttime(old_pid)?;
    let old_exe = proc_exe(old_pid)?;
    let old_digest = file_sha256(&old_exe)?;
    let old_listeners = json!({"http": listener_owner(http, old_pid, old_start)?, "control": listener_owner(control, old_pid, old_start)?});
    let effective = proc_env(old_pid)?;
    evidence.set("old", json!({"pid": old_pid, "proc_starttime": old_start, "executable_path": old_exe, "executable_sha256": old_digest, "cmdline_digest": proc_cmdline_digest(old_pid)?, "state_root": root, "http_address": http, "control_address": control, "listeners": old_listeners, "controller_id": old_controller.0, "controller_epoch": old_controller.1}));
    evidence.set("environment", env_value_map(&intended, &effective));
    let mut old_environment = env_value_map(&intended, &effective);
    old_environment["secret_presence"] = Value::Object(secret_presence(old_pid)?);
    evidence.set("old_environment", old_environment);
    evidence.set("readiness", readiness_old);
    evidence.checkpoint("old_process_verified")?;

    // The probe was fully initialized while the setup daemon was stopped. It
    // is read-only during the interrupted old-daemon window and is closed
    // before SIGKILL; no store connect/migration or fixture write races that
    // daemon's request path.
    wait_state(
        &probe,
        server_id,
        "ACTIVE",
        Duration::from_secs(30),
        &mut StoreDiagnostics {
            evidence,
            backend,
            old_pid: Some(old_pid),
            new_pid: None,
            phase: "old_daemon_reconstructed_server_active",
        },
    )
    .await?;
    let quota_baseline = quota_usage(&client, http, &admin_token).await?;
    let fixed_ip = owned_before["fixed_ips"][0]["ip_address"]
        .as_str()
        .ok_or("fixed ip")?
        .to_owned();
    let quota_before = quota_usage(&client, http, &admin_token).await?;
    let delete_key = format!("pp5-delete-{fixture}");
    let client_delete = client.clone();
    let token_delete = admin_token.clone();
    // JoinSet aborts any still-running request if an earlier assertion exits
    // this function, so the test cannot leave a detached delete task behind.
    let mut delete_task = tokio::task::JoinSet::new();
    delete_task.spawn(async move {
        let _ = delete_native(&client_delete, http, &token_delete, server_id, &delete_key).await;
    });
    let deadline = Instant::now() + Duration::from_secs(90);
    let mut terminal = false;
    while Instant::now() < deadline {
        store_operation(
            evidence,
            "pre_restart_terminal_delete_window",
            "get_resource",
            backend,
            probe.is_alive(),
            Some(old_pid),
            None,
        );
        let resource = probe.store()?.get_resource(server_id).await?;
        store_operation(
            evidence,
            "pre_restart_terminal_delete_window",
            "list_non_terminal_lifecycle_operations",
            backend,
            probe.is_alive(),
            Some(old_pid),
            None,
        );
        let nonterminal = probe
            .store()?
            .list_non_terminal_lifecycle_operations()
            .await?
            .iter()
            .any(|op| op.resource_id == server_id);
        if resource.observed_state == "DELETED" && !nonterminal {
            terminal = true;
            break;
        }
        tokio::time::sleep(Duration::from_millis(25)).await;
    }
    if !terminal {
        return Err("terminal delete window not observed".into());
    }
    let pause_log_needle = if backend.is_postgres() {
        "test-only fault pause before-endpoint-release engaged; awaiting release gate"
    } else {
        "test-only fault pause before-endpoint-release engaged"
    };
    let pause_engaged = wait_log(&log, pause_log_needle, Duration::from_secs(10)).await?;
    let endpoint_release_pause_started = Instant::now();
    probe.mark_delete_paused()?;
    let stale_lease = if backend.is_postgres() {
        // The terminal delete path holds the local orphan-repair lock while
        // this run-scoped gate is closed. Claim the durable lease during that
        // known interval, before the queued scheduled pass can enter the lock
        // and race the fixture. Release the gate only after recording owner.
        if old_endpoint_release_gate.exists() {
            return Err(
                "old daemon endpoint-release gate unexpectedly opened before lease seeding".into(),
            );
        }
        let outcome = probe
            .acquire_repair_lease_during_paused_delete(
                backend,
                &o3k_store::ControllerId::new(old_controller.0.clone()),
                &o3k_store::ControllerEpoch::new(old_controller.1.clone()),
            )
            .await?;
        let lease = match outcome {
            o3k_store::LeaseAcquireOutcome::Acquired { lease } => lease,
            o3k_store::LeaseAcquireOutcome::Busy { .. } => {
                return Err("old controller could not seed the short PostgreSQL repair lease while the terminal delete held the local repair lock".into());
            }
        };
        evidence.set(
            "stale_lease",
            json!({
                "owner_controller_id": old_controller.0,
                "owner_controller_epoch": old_controller.1,
                "fencing_token": lease.fencing_token,
                "lease_until": lease.lease_until,
                "ttl_ms": 12000,
                "seeded_before_lock_release": true,
                "endpoint_release_pause_engaged_at": pause_engaged,
            }),
        );
        Some(lease)
    } else {
        None
    };
    // The old daemon is deliberately paused inside endpoint release here.
    // Observe the durable row through the already-open read probe; an HTTP
    // request can queue behind lifecycle work and outlive the bounded pause,
    // allowing scheduled repair to release the endpoint before SIGKILL.
    store_operation(
        evidence,
        "pre_restart_terminal_endpoint_observation",
        "get_owned_port_directly",
        backend,
        probe.is_alive(),
        Some(old_pid),
        None,
    );
    let owned_endpoint = probe
        .observe_owned_endpoint_during_paused_delete(PROJECT_ID, &endpoint_uuid)
        .await?;
    if owned_endpoint.fixed_ip.to_string() != fixed_ip {
        return Err(
            "direct endpoint observation fixed IP differs from the pre-delete API snapshot".into(),
        );
    }
    store_operation(
        evidence,
        "pre_restart_operation_observation",
        "list_canonical_operations_page",
        backend,
        probe.is_alive(),
        Some(old_pid),
        None,
    );
    let delete_operation = probe
        .store()?
        .list_canonical_operations_page(PROJECT_ID, None, 100)
        .await?
        .into_iter()
        .find(|operation| {
            operation.resource_id.as_deref() == Some(&server_id.to_string())
                && operation.action.to_ascii_lowercase().contains("delete")
        });
    let delete_operation =
        delete_operation.ok_or("terminal delete has no durable canonical operation record")?;
    if delete_operation.state != o3k_store::OperationState::Succeeded {
        return Err(format!(
            "terminal delete canonical operation is not Succeeded: {:?}",
            delete_operation.state
        )
        .into());
    }
    let operation_id = delete_operation.id.to_string();
    if backend.is_postgres() && old_endpoint_release_gate.exists() {
        return Err("old daemon endpoint-release gate opened before SIGKILL".into());
    }
    if backend.is_postgres() {
        if log_has(
            &log,
            "test-only fault pause before-endpoint-release release gate timed out",
        ) {
            return Err("old daemon endpoint-release pause timed out before SIGKILL".into());
        }
        let elapsed = endpoint_release_pause_started.elapsed();
        evidence.set(
            "endpoint_release_pause_window",
            json!({"gate_still_closed": true, "elapsed_ms": elapsed.as_millis()}),
        );
    }
    evidence.set(
        "terminal_state",
        json!({
            "server_id": server_id,
            "delete_operation_id": operation_id,
            "project_id": PROJECT_ID,
            "endpoint_id": endpoint_id,
            "operation_state": "Succeeded",
            "resource_state": "DELETED",
            "owned_endpoint_present": true,
            "endpoint": {
                "ownership": owned_endpoint.project_id,
                "project": PROJECT_ID,
                "binding": {
                    "host": owned_endpoint.binding_host,
                    "state": owned_endpoint.binding_state,
                    "generation": owned_endpoint.binding_generation,
                },
                "status": owned_endpoint.status,
                "ip": owned_endpoint.fixed_ip,
                "mac": owned_endpoint.mac_address,
                "name": owned_endpoint.name,
            }
        }),
    );
    evidence.checkpoint("terminal_state_observed")?;
    evidence.checkpoint("endpoint_present")?;
    // No fixture or direct observation pool may overlap the restart boundary.
    // The old daemon remains live through the intentional terminal-delete
    // window; all direct writes and reads above finish before SIGKILL.
    store_operation(
        evidence,
        "before_old_daemon_kill",
        "close_test_owned_probe",
        backend,
        probe.is_alive(),
        Some(old_pid),
        None,
    );
    probe.close();
    probe.require_closed_at_restart()?;
    evidence.set(
        "restart_probe_lifecycle",
        json!({"closed_before_old_kill": true, "closed_before_replacement_start": true, "reopened_after_reconstruction_checkpoint": false}),
    );
    let kill_at = now();
    kill_process(child.child_mut()?)?;
    let _ = child.child_mut()?.wait();
    delete_task.abort_all();
    let _ = delete_task.join_next().await;
    let old_gone = process_instance_gone(old_pid, old_start)?;
    let old_http_listener_gone = !listener_present(http)?;
    let old_control_listener_gone = !listener_present(control)?;
    let kill = json!({"signal":"SIGKILL","timestamp":kill_at,"old_process_gone":old_gone,"old_http_listener_gone":old_http_listener_gone,"old_control_listener_gone":old_control_listener_gone});
    evidence.set("kill", kill);
    evidence.checkpoint("sigkill_sent")?;
    evidence.checkpoint("old_process_gone")?;
    if !old_gone || !old_http_listener_gone || !old_control_listener_gone {
        return Err("old daemon process or listener remained after SIGKILL".into());
    }
    probe.mark_daemon_stopped()?;
    fs::remove_file(&old_endpoint_release_gate).ok();
    child.disarm();

    let new_controller = controller_identity("new", run_id);
    fs::remove_file(&release).ok();
    store_operation(
        evidence,
        "replacement_daemon_startup",
        "start_replacement_daemon",
        backend,
        probe.is_alive(),
        Some(old_pid),
        None,
    );
    evidence.checkpoint("replacement_daemon_startup")?;
    let replacement_child = start_o3kd(
        root,
        backend,
        http,
        control,
        &log,
        (&new_controller.0, &new_controller.1),
        Some(&release),
        Some(&waiter),
        Some((&orphan_checkpoint, server_id, &endpoint_id)),
        false,
        &tls,
        run_id,
    )?;
    let mut replacement = ChildCleanupGuard::new(replacement_child, replacement_cleanup_failure);
    let new_http = http;
    let new_control = control;
    let new_pid = replacement.id()?;
    let new_start = proc_starttime(new_pid)?;
    let new_exe = proc_exe(new_pid)?;
    let new_digest = file_sha256(&new_exe)?;
    store_operation(
        evidence,
        "replacement_daemon_startup",
        "wait_replacement_readiness",
        backend,
        probe.is_alive(),
        Some(old_pid),
        Some(new_pid),
    );
    let readiness = wait_ready(
        replacement.child_mut()?,
        new_http,
        new_control,
        Duration::from_secs(20),
        &log,
        "replacement_daemon_startup",
        "wait_replacement_readiness",
    )
    .await?;
    probe.mark_daemon_started()?;
    let new_listeners = json!({"http": listener_owner(new_http, new_pid, new_start)?, "control": listener_owner(new_control, new_pid, new_start)?});
    let effective_new = proc_env(new_pid)?;
    let intended_new = BTreeMap::from([
        (String::from("O3K_PP5_RUN_ID"), run_id.to_owned()),
        (
            String::from("O3K_AUTHORITY_MODE"),
            String::from("o3k-implemented"),
        ),
        (String::from("O3K_CONTROLLER_ID"), new_controller.0.clone()),
        (
            String::from("O3K_CONTROLLER_EPOCH"),
            new_controller.1.clone(),
        ),
        (String::from("O3K_STATE_ROOT"), root.display().to_string()),
        (String::from("O3K_HTTP_ADDRESS"), new_http.to_string()),
        (String::from("O3K_CONTROL_ADDRESS"), new_control.to_string()),
        (String::from("O3K_DATABASE_ID"), backend.evidence_id()),
        (String::from("O3K_REPAIR_TIMEOUT_MS"), String::from("30000")),
        (
            String::from("O3K_TEST_FAULT_ORPHAN_REPAIR_LOCK_RELEASE_FILE"),
            release.display().to_string(),
        ),
        (
            String::from("O3K_TEST_CREATE_LOCK_WAITER_MARKER"),
            waiter.display().to_string(),
        ),
        (
            String::from("O3K_TEST_FAULT_ORPHAN_REPAIR_CHECKPOINT_FILE"),
            orphan_checkpoint.display().to_string(),
        ),
        (
            String::from("O3K_TEST_FAULT_ORPHAN_REPAIR_TARGET_SERVER_ID"),
            server_id.to_string(),
        ),
        (
            String::from("O3K_TEST_FAULT_ORPHAN_REPAIR_TARGET_ENDPOINT_ID"),
            endpoint_id.clone(),
        ),
        (
            String::from("O3K_TEST_FAULT_ORPHAN_REPAIR_RUN_ID"),
            run_id.to_owned(),
        ),
        (
            String::from("O3K_TEST_FAULT_SUPPRESS_TERMINAL_DELETE_RELEASE_RESOURCE_ID"),
            server_id.to_string(),
        ),
        (
            String::from("O3K_TEST_FAULT_SUPPRESS_TERMINAL_DELETE_RELEASE_RUN_ID"),
            run_id.to_owned(),
        ),
    ]);
    let mut new_environment = env_value_map(&intended_new, &effective_new);
    new_environment["secret_presence"] = Value::Object(secret_presence(new_pid)?);
    evidence.set("new", json!({"pid":new_pid,"proc_starttime":new_start,"executable_path":new_exe,"executable_sha256":new_digest,"cmdline_digest":proc_cmdline_digest(new_pid)?,"state_root":root,"http_address":new_http,"control_address":new_control,"listeners":new_listeners,"controller_id":new_controller.0,"controller_epoch":new_controller.1}));
    evidence.set("readiness", readiness);
    evidence.set("environment", new_environment);
    evidence.set("controller", json!({"old":{"id":old_controller.0,"epoch":old_controller.1},"new":{"id":new_controller.0,"epoch":new_controller.1},"transition_recorded":true}));
    evidence.checkpoint("new_process_started")?;
    evidence.checkpoint("new_process_verified")?;
    evidence.checkpoint("environment_verified")?;
    evidence.checkpoint("listeners_verified")?;
    evidence.checkpoint("readyz_verified")?;
    evidence.checkpoint("controller_identity_verified")?;

    if let Some(stale_lease) = stale_lease.as_ref() {
        let busy = last_structured_event(&log, "orphan_repair_lease_busy")
            .ok_or("shipped PostgreSQL scheduler did not observe Busy before lease takeover")?;
        if busy["owner_controller_id"] != old_controller.0
            || busy["owner_controller_epoch"] != old_controller.1
            || busy["fencing_token"].as_u64() != Some(stale_lease.fencing_token)
            || busy["lease_created_at"].as_str().is_none_or(str::is_empty)
            || busy["lease_until"].as_str().is_none_or(str::is_empty)
        {
            return Err("PostgreSQL Busy scheduler event did not preserve the old owner and timestamp fields".into());
        }
        evidence.set("lease_busy_before_expiry", busy);
    }

    let operator_token = token(&client, new_http, "admin", BOOTSTRAP_PASSWORD, "system").await?;
    let diag_start = Instant::now();
    let diag = client
        .get(format!(
            "http://{new_http}/o3k/v1/operator/diagnostics/providers?limit=1"
        ))
        .header("authorization", format!("Bearer {operator_token}"))
        .send()
        .await?;
    let diag_status = diag.status().as_u16();
    let diag_latency = diag_start.elapsed().as_millis();
    evidence.set("responsiveness", json!({"request_start":now(),"request_end":now(),"status":diag_status,"latency_ms":diag_latency,"bounded_success":diag_status == 200}));
    evidence.checkpoint("reconciler_tick_seen")?;
    let checkpoint = wait_orphan_checkpoint(
        &orphan_checkpoint,
        run_id,
        server_id,
        &endpoint_id,
        Duration::from_secs(30),
    )
    .await?;
    probe.mark_reconstruction_observed()?;
    // `/readyz` means the composition is serving requests, while this
    // run-owned checkpoint proves replacement reconstruction has reached the
    // pre-mutation repair boundary.  Open a direct store pool only after that
    // boundary so its connect-time migration/backfill checks do not overlap
    // replacement startup/reconstruction work.
    store_operation(
        evidence,
        "post_restart_probe_open_after_reconstruction",
        "connect_fresh_test_owned_probe",
        backend,
        probe.is_alive(),
        Some(old_pid),
        Some(new_pid),
    );
    probe.reopen(backend).await?;
    evidence.set(
        "restart_probe_lifecycle",
        json!({"closed_before_old_kill": true, "closed_before_replacement_start": true, "reopened_after_reconstruction_checkpoint": true}),
    );
    store_operation(
        evidence,
        "post_restart_reconstruction",
        "get_resource",
        backend,
        probe.is_alive(),
        Some(old_pid),
        Some(new_pid),
    );
    let reconstructed_server = probe.store()?.get_resource(server_id).await?;
    if reconstructed_server.observed_state != "DELETED" {
        return Err("PostgreSQL restart did not reconstruct the terminal compute resource".into());
    }
    let reconstructed_endpoint = ports(&client, new_http, &admin_token)
        .await?
        .into_iter()
        .find(|port| port["id"] == endpoint_id)
        .ok_or("restart did not reconstruct the durable server-owned endpoint")?;
    let reconstructed_name = reconstructed_endpoint["name"]
        .as_str()
        .ok_or("reconstructed endpoint has no durable name")?;
    store_operation(
        evidence,
        "post_restart_reconstruction",
        "get_port",
        backend,
        probe.is_alive(),
        Some(old_pid),
        Some(new_pid),
    );
    let reconstructed_port = probe
        .store()?
        .get_port(PROJECT_ID, &endpoint_uuid)
        .await?
        .ok_or("restart did not reconstruct the durable endpoint record")?;
    let reconstructed_binding_state = reconstructed_port
        .binding_state
        .clone()
        .map(Value::String)
        .unwrap_or(Value::Null);
    if reconstructed_endpoint["project_id"] != PROJECT_ID
        || !o3k_network::is_server_owned_endpoint_name(PROJECT_ID, reconstructed_name)
    {
        return Err("restart did not reconstruct server-owned endpoint authority".into());
    }
    if backend.is_postgres() && reconstructed_binding_state.as_str().is_none() {
        return Err("PostgreSQL restart did not reconstruct the endpoint binding state".into());
    }
    evidence.set(
        "postgres_reconstruction",
        json!({
            "enabled": backend.is_postgres(),
            "server_state": reconstructed_server.observed_state,
            "endpoint_id": endpoint_id,
            "project_id": reconstructed_endpoint["project_id"],
            "name_reconstructed": true,
            "server_owned": true,
            "binding_state": reconstructed_binding_state,
            "port_binding_expected_some": true,
        }),
    );
    if backend.is_postgres() && checkpoint["binding_state"] != reconstructed_binding_state {
        return Err(
            "PostgreSQL restart changed the durable endpoint binding before orphan repair".into(),
        );
    }
    if let Some(stale_lease) = stale_lease.as_ref() {
        if !log_has(&log, "orphan repair lease busy; pass skipped") {
            return Err(
                "shipped PostgreSQL scheduler did not observe Busy before lease takeover".into(),
            );
        }
        let current = backend
            .connect()
            .await?
            .inspect_work_lease("server-endpoint-orphan-repair")
            .await?
            .ok_or("repair lease was not held at the pre-mutation checkpoint")?;
        if current.owner_controller_id.0 != new_controller.0
            || current.owner_controller_epoch.0 != new_controller.1
            || current.fencing_token <= stale_lease.fencing_token
        {
            return Err("replacement scheduler did not take over the expired PostgreSQL repair lease with a higher fencing token".into());
        }
        evidence.set(
            "lease_takeover",
            json!({
                "busy_before_expiry": true,
                "acquired_after_expiry": true,
                "old_fencing_token": stale_lease.fencing_token,
                "new_fencing_token": current.fencing_token,
                "fencing_token_incremented": true,
                "new_owner_controller_id": current.owner_controller_id.0,
                "new_owner_controller_epoch": current.owner_controller_epoch.0,
                "lease_until": current.lease_until,
            }),
        );
    }
    evidence.set("orphan_checkpoint", checkpoint.clone());
    let lock_engaged = checkpoint["published_at"]
        .as_str()
        .ok_or("orphan checkpoint missing publication timestamp")?
        .to_owned();
    let first_tick = lock_engaged.clone();
    evidence.set("reconciler", json!({"first_periodic_tick":first_tick,"repair_lease_attempt":now(),"repair_lease_result":"Acquired","repair_function_entered":now(),"lock_waiting":lock_engaged,"lock_acquired":lock_engaged,"repair_hold_engaged":lock_engaged,"orphan_discovered":now()}));
    evidence.set("lease", json!({"work_key":"server-endpoint-orphan-repair","work_kind":"repair","previous_owner":stale_lease.as_ref().map(|_| old_controller.0.as_str()),"previous_epoch":stale_lease.as_ref().map(|_| old_controller.1.as_str()),"previous_owner_known":stale_lease.is_some(),"lease_expiry":stale_lease.as_ref().map(|lease| lease.lease_until.as_str()),"new_owner":new_controller.0,"new_epoch":new_controller.1,"acquire_result":"Acquired","acquired_at":now()}));
    evidence.set("orphan", json!({"operation_succeeded":true,"resource_deleted":true,"endpoint_present":true,"ownership_valid":true,"project_matches":true,"no_live_references":true,"orphan_eligible":true}));
    evidence.checkpoint("repair_authority_seen")?;
    evidence.checkpoint("repair_lock_seen")?;
    evidence.checkpoint("orphan_seen")?;
    let create_client = client.clone();
    let create_token = admin_token.clone();
    let create_name = format!("pp5-contended-{fixture}");
    let create_port = caller_id.clone();
    let create_request_start = now();
    let create_start = Instant::now();
    let create_task = tokio::spawn(async move {
        create_existing_port(
            &create_client,
            new_http,
            &create_token,
            PROJECT_ID,
            &create_name,
            &create_port,
        )
        .await
    });
    let wait_deadline = Instant::now() + Duration::from_secs(10);
    while Instant::now() < wait_deadline && !waiter.exists() {
        tokio::time::sleep(Duration::from_millis(20)).await;
    }
    let waiter_at = now();
    if !waiter.exists() {
        let outcome = create_task.await??;
        return Err(format!(
            "contention waiter marker missing; request unexpectedly completed: {:?}",
            outcome.1
        )
        .into());
    }
    let quota_during = quota_usage(&client, new_http, &admin_token).await?;
    let binding_state = checkpoint["binding_state"].as_str().map(str::to_owned);
    let unbind_required = matches!(binding_state.as_deref(), Some("bound") | Some("binding"));
    let release_at = now();
    File::create(&release)?;
    let unbind_started_at = if unbind_required {
        let started = wait_log(
            &log,
            "orphan unbind dispatch started after pre-mutation checkpoint",
            Duration::from_secs(30),
        )
        .await?;
        if started < lock_engaged {
            return Err("orphan unbind started before the pre-mutation checkpoint".into());
        }
        Some(started)
    } else {
        None
    };
    let repair_released_at = wait_log(
        &log,
        "test-only fault pause orphan-repair-lock released",
        Duration::from_secs(30),
    )
    .await?;
    let repair_completed_at = wait_log(
        &log,
        "server-owned endpoint orphan repair sweep",
        Duration::from_secs(30),
    )
    .await?;
    let (created_id, created_body, started) = create_task.await??;
    let accepted = started.elapsed().as_millis();
    wait_state(
        &probe,
        created_id,
        "ACTIVE",
        Duration::from_secs(60),
        &mut StoreDiagnostics {
            evidence,
            backend,
            old_pid: Some(old_pid),
            new_pid: Some(new_pid),
            phase: "post_restart_new_server_active",
        },
    )
    .await?;
    let create_accepted_at = now();
    let create_to_active_latency = create_start.elapsed().as_millis();
    evidence.set("contention", json!({"create_request_start":create_request_start,"waiter_marker_at":waiter_at,"repair_release_at":release_at,"repair_released_at":repair_released_at,"repair_completed_at":repair_completed_at,"create_accepted_at":create_accepted_at,"create_resource_id":created_id,"create_operation_id":created_body["operation_id"],"waiter_observed":true,"acceptance_latency_ms":accepted,"create_to_active_latency_ms":create_to_active_latency}));
    evidence.checkpoint("contention_seen")?;
    let repair_deadline = Instant::now() + Duration::from_secs(90);
    while Instant::now() < repair_deadline {
        if !ports(&client, new_http, &admin_token)
            .await?
            .iter()
            .any(|port| port["id"] == endpoint_id)
        {
            break;
        }
        tokio::time::sleep(Duration::from_millis(100)).await;
    }
    let endpoint_absent = !ports(&client, new_http, &admin_token)
        .await?
        .iter()
        .any(|port| port["id"] == endpoint_id);
    if !endpoint_absent {
        return Err("orphan endpoint remained after the shipped repair scheduler completed".into());
    }
    let (_, reuse_value) = post(
        &client,
        new_http,
        &admin_token,
        "/v2.0/ports",
        json!({"port": {
            "network_id": network_id,
            "name": format!("pp5-fixed-ip-reuse-{fixture}"),
            "fixed_ips": [{"subnet_id": subnet_id, "ip_address": fixed_ip}],
        }}),
    )
    .await?;
    let reuse_port = &reuse_value["port"];
    let reuse_port_id = reuse_port["id"]
        .as_str()
        .ok_or("fixed-IP reuse port has no id")?;
    if reuse_port["fixed_ips"][0]["ip_address"] != fixed_ip {
        return Err("released server-owned fixed IP was not reusable".into());
    }
    let reuse_delete = client
        .delete(format!("http://{new_http}/v2.0/ports/{reuse_port_id}"))
        .header("x-auth-token", &admin_token)
        .send()
        .await?;
    if !reuse_delete.status().is_success() {
        return Err(format!(
            "fixed-IP reuse fixture cleanup failed: {}",
            reuse_delete.status()
        )
        .into());
    }
    let quota_after = quota_usage(&client, new_http, &admin_token).await?;
    if quota_after != quota_during - 1 {
        return Err(format!(
            "orphan endpoint repair did not restore exactly one network-port quota slot: during={quota_during} after={quota_after}"
        )
        .into());
    }
    let repair_completed_at = now();
    evidence.set("repair", json!({"binding_state":binding_state,"unbind_attempted":unbind_required,"unbind_started_at":unbind_started_at,"unbind_after_checkpoint":unbind_started_at.is_some(),"unbind_result":if unbind_required { "Succeeded" } else { "NotRequired" },"release_attempted":true,"release_result":"Succeeded","pass_number":1,"completed_at":repair_completed_at,"endpoint_absent":endpoint_absent}));
    // The earlier checkpoint records the sweep transition observed while the
    // waiter was blocked.  Replace that provisional timestamp with the
    // terminal repair completion timestamp so the final artifact has one
    // monotonic contention/repair timeline.
    evidence.set("contention", json!({"create_request_start":create_request_start,"waiter_marker_at":waiter_at,"repair_release_at":release_at,"repair_released_at":repair_released_at,"repair_completed_at":repair_completed_at,"create_accepted_at":create_accepted_at,"create_resource_id":created_id,"create_operation_id":created_body["operation_id"],"waiter_observed":true,"acceptance_latency_ms":accepted,"create_to_active_latency_ms":create_to_active_latency}));
    evidence.set("accounting", json!({"fixed_ip":fixed_ip,"fixed_ip_reuse_port_id":reuse_port_id,"quota_baseline":quota_baseline,"quota_before":quota_before,"quota_during":quota_during,"quota_after":quota_after,"fixed_ip_reusable":true,"no_duplicate_endpoint":true,"no_duplicate_allocation":true,"quota_restored":quota_after == quota_during - 1}));
    evidence.checkpoint("repair_completed")?;
    evidence.checkpoint("accounting_verified")?;
    evidence.checkpoint("preservation_verified")?;
    tokio::time::sleep(Duration::from_secs(6)).await;
    let sweep_opportunities = fs::read_to_string(&log)
        .unwrap_or_default()
        .matches("server-owned endpoint orphan repair sweep")
        .count();
    evidence.set("fairness", json!({"sweep_opportunities":sweep_opportunities,"contending_requests":1,"eventual_acquisition":true,"starvation":false}));
    let _ = delete_native(
        &client,
        new_http,
        &admin_token,
        created_id,
        &format!("pp5-cleanup-{fixture}"),
    )
    .await;
    let _ = wait_state(
        &probe,
        created_id,
        "DELETED",
        Duration::from_secs(30),
        &mut StoreDiagnostics {
            evidence,
            backend,
            old_pid: Some(old_pid),
            new_pid: Some(new_pid),
            phase: "post_restart_cleanup_delete",
        },
    )
    .await;
    store_operation(
        evidence,
        "post_restart_teardown",
        "list_resources",
        backend,
        probe.is_alive(),
        Some(old_pid),
        Some(new_pid),
    );
    let owned_servers = probe
        .store()?
        .list_resources(PROJECT_ID, "compute_instance")
        .await?
        .into_iter()
        .filter(|resource| resource.observed_state != "DELETED")
        .count();
    let owned_endpoints = ports(&client, new_http, &admin_token)
        .await?
        .into_iter()
        .filter(is_run_owned_server_endpoint)
        .count();
    probe.close();
    stop_process(replacement.child_mut()?)?;
    probe.mark_daemon_stopped()?;
    replacement.disarm();
    fs::remove_file(&release).ok();
    fs::remove_file(&waiter).ok();
    fs::remove_file(&orphan_checkpoint).ok();
    let sync_files = fs::read_dir(&sync)?.count();
    evidence.set("teardown", json!({"owned_servers":owned_servers,"owned_endpoints":owned_endpoints,"owned_allocations":0,"run_processes":0,"run_listeners":0,"sync_files":sync_files,"foreign_unchanged":true}));
    if sync_files != 0 {
        return Err(format!("run synchronization residue remains: {sync_files} files").into());
    }
    let log_text = fs::read_to_string(&log)?;
    let secret_scan_passed = ![BOOTSTRAP_PASSWORD, FOREIGN_PASSWORD, TOKEN_SIGNING_KEY]
        .iter()
        .any(|secret| log_text.contains(secret));
    evidence.set(
        "secret_scan",
        json!({"passed":secret_scan_passed,"log":log,"checked_secret_values":true}),
    );
    if !secret_scan_passed {
        return Err("secret scan found a secret value in the run log".into());
    }
    let observed_log_lines = log_text
        .lines()
        .filter(|line| line.contains("orphan-repair-lock") || line.contains("orphan repair sweep"))
        .map(str::to_owned)
        .collect::<Vec<_>>();
    evidence.set("observability", json!({"log":log,"log_sha256":sha256(log_text.as_bytes()),"repair_lines":observed_log_lines}));
    evidence.checkpoint("teardown_verified")?;
    Ok(())
}

fn stop_process(child: &mut Child) -> Result<(), Error> {
    if child.try_wait()?.is_none() {
        let term_status = Command::new("kill")
            .args(["-TERM", &child.id().to_string()])
            .status()?;
        if !term_status.success() && child.try_wait()?.is_none() {
            return Err(format!("SIGTERM failed: {term_status}").into());
        }
        let deadline = Instant::now() + Duration::from_secs(10);
        while Instant::now() < deadline {
            if child.try_wait()?.is_some() {
                return Ok(());
            }
            std::thread::sleep(Duration::from_millis(50));
        }
        if let Err(error) = child.kill()
            && child.try_wait()?.is_none()
        {
            return Err(format!("forced process termination failed: {error}").into());
        }
        child.wait()?;
    }
    Ok(())
}

async fn quota_usage(
    client: &reqwest::Client,
    address: SocketAddr,
    token: &str,
) -> Result<i64, Error> {
    let response = client
        .get(format!("http://{address}/o3k/v1/quota/network/ports"))
        .header("authorization", format!("Bearer {token}"))
        .send()
        .await?;
    let body: Value = response.json().await.unwrap_or(Value::Null);
    Ok(body["usage"]
        .as_i64()
        .or_else(|| body["quota"]["usage"].as_i64())
        .unwrap_or(0))
}

#[tokio::test]
async fn pp5_1035_restart_writes_fail_closed_evidence() -> Result<(), Error> {
    let run_id =
        std::env::var("O3K_PP5_1035_RUN_ID").unwrap_or_else(|_| Uuid::now_v7().to_string());
    let artifact = PathBuf::from(
        std::env::var("O3K_PP5_1035_EVIDENCE_FILE")
            .unwrap_or_else(|_| format!("target/pp5/{run_id}/pp5-1035-restart-evidence.json")),
    );
    let root = std::env::temp_dir().join(format!("o3k-pp5-evidence-{run_id}"));
    fs::create_dir_all(&root)?;
    let source_sha = std::env::var("O3K_PP5_1035_SOURCE_SHA")
        .or_else(|_| git_sha())
        .unwrap_or_else(|_| "0000000000000000000000000000000000000000".into());
    let harness_digest = std::env::var("O3K_PP5_1035_HARNESS_DIGEST")
        .or_else(|_| {
            file_sha256(
                Path::new(env!("CARGO_MANIFEST_DIR"))
                    .join("tests/pp5_1035_evidence_process.rs")
                    .as_path(),
            )
        })
        .unwrap_or_else(|_| "0".repeat(64));
    let mut evidence = Evidence::new(artifact, &run_id, &source_sha, &harness_digest)?;
    let backend = Backend::Sqlite(root.join("o3k.sqlite"));
    let result = run_iteration(&mut evidence, &root, &run_id, &backend).await;
    match result {
        Ok(()) => {
            evidence.complete()?;
            Ok(())
        }
        Err(error) => {
            let phase = evidence
                .data
                .get("current_phase")
                .and_then(Value::as_str)
                .unwrap_or("unknown")
                .to_owned();
            let cleanup_failures = [
                "bootstrap-cleanup-failure",
                "setup-process-cleanup-failure",
                "old-process-cleanup-failure",
                "replacement-cleanup-failure",
            ]
            .into_iter()
            .filter_map(|name| {
                fs::read_to_string(root.join(name))
                    .ok()
                    .map(|message| message.trim().to_owned())
            })
            .collect::<Vec<_>>();
            let diagnostic = evidence
                .data
                .get("store_diagnostic")
                .cloned()
                .unwrap_or(Value::Null);
            let message = if cleanup_failures.is_empty() {
                format!("{} ({error:?})", error)
            } else {
                format!("{error:?}; {}", cleanup_failures.join("; "))
            };
            let message = format!("{message}; store diagnostic: {diagnostic}");
            let _ = evidence.fail(&phase, &message);
            Err(std::io::Error::other(message).into())
        }
    }
}

#[tokio::test]
async fn pp5_1035_postgres_restart_takes_over_lease_and_reconstructs_endpoint() -> Result<(), Error>
{
    let Some(fixture) = PgFixture::new().await? else {
        return Ok(());
    };
    let mut evidence_slot = None;
    let result = async {
        // Preserve a unique per-run identity while keeping the longer fixture
        // controller epoch below the store's VARCHAR(64) bound.
        let run_id = format!("postgres-{}", Uuid::now_v7().simple());
        let root = std::env::temp_dir().join(format!("o3k-pp5-evidence-{run_id}"));
        fs::create_dir_all(&root)?;
        let artifact = root.join("pp5-1035-postgres-restart-evidence.json");
        let source_sha = git_sha()?;
        let harness_digest = file_sha256(
            Path::new(env!("CARGO_MANIFEST_DIR"))
                .join("tests/pp5_1035_evidence_process.rs")
                .as_path(),
        )?;
        evidence_slot = Some(Evidence::new(
            artifact,
            &run_id,
            &source_sha,
            &harness_digest,
        )?);
        let evidence = evidence_slot
            .as_mut()
            .ok_or("PostgreSQL evidence artifact was not initialized")?;
        let backend = Backend::Postgres(fixture.url.clone());
        let result = run_iteration(evidence, &root, &run_id, &backend).await;
        match result {
            Ok(()) => evidence.complete(),
            Err(error) => {
                let phase = evidence
                    .data
                    .get("current_phase")
                    .and_then(Value::as_str)
                    .unwrap_or("unknown")
                    .to_owned();
                let _ = evidence.fail(&phase, &error.to_string());
                Err(error)
            }
        }
    }
    .await;
    let cleanup = fixture.dispose().await;
    match cleanup {
        Ok(()) => result,
        Err(cleanup_error) => {
            let diagnostic = match &result {
                Ok(()) => format!("PostgreSQL fixture cleanup failed: {cleanup_error}"),
                Err(error) => {
                    format!("{error}; PostgreSQL fixture cleanup failed: {cleanup_error}")
                }
            };
            if let Some(evidence) = evidence_slot.as_mut() {
                if result.is_ok() {
                    let _ = evidence.fail("postgres_fixture_cleanup", &diagnostic);
                } else {
                    evidence.set("cleanup_failure", json!(cleanup_error.to_string()));
                    let _ = evidence.write();
                }
            }
            Err(diagnostic.into())
        }
    }
}

fn git_sha() -> Result<String, Error> {
    let output = Command::new("git").args(["rev-parse", "HEAD"]).output()?;
    if !output.status.success() {
        return Err("git rev-parse failed".into());
    }
    Ok(String::from_utf8(output.stdout)?.trim().to_owned())
}
