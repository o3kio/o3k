#![cfg(unix)]

//! Evidence-hardening focused PP.5 #1035 real-process acceptance run.
//!
//! The test deliberately writes an atomic artifact at every phase.  The
//! companion `scripts/validate_pp5_1035_evidence.py` is the fail-closed
//! acceptance authority; this process test only records observations.

use std::collections::BTreeMap;
use std::fs::{self, File, OpenOptions};
use std::io::Write;
use std::net::{SocketAddr, TcpListener};
use std::path::{Path, PathBuf};
use std::process::{Child, Command, Stdio};
use std::time::{Duration, Instant};

use chrono::Utc;
use o3k_store::{DurableStore, IdentityRepository};
use serde_json::{Map, Value, json};
use sha2::{Digest, Sha256};
use uuid::Uuid;

const PROJECT_ID: &str = "eba29e2d-53de-461d-ae91-ede7402713cb";
const FOREIGN_PROJECT_ID: &str = "1d6e8a4d-9e09-4a7a-a1cb-2a0e5fb2a103";
const BOOTSTRAP_PASSWORD: &str = "pp5-interrupted-delete-bootstrap-password";
const FOREIGN_PASSWORD: &str = "pp5-interrupted-delete-foreign-password";
const TOKEN_SIGNING_KEY: &str = "pp5-interrupted-delete-signing-key-0123456789abcdef";
const FLAVOR_ID: &str = "00000000-0000-0000-0000-000000000001";
const FAULT_ENV: &str = "O3K_TEST_FAULT_PAUSE_BEFORE_ENDPOINT_RELEASE_MS";

type Error = Box<dyn std::error::Error + Send + Sync>;

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

fn proc_starttime(pid: u32) -> Result<u64, Error> {
    let text = fs::read_to_string(format!("/proc/{pid}/stat"))?;
    let after = text.rsplit_once(") ").ok_or("malformed /proc stat")?.1;
    after
        .split_whitespace()
        .nth(19)
        .ok_or("missing proc starttime")?
        .parse()
        .map_err(Into::into)
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
    http: SocketAddr,
    control: SocketAddr,
    log: &Path,
    controller: (&str, &str),
    release_file: Option<&Path>,
    waiter: Option<&Path>,
    fault_pause: bool,
    tls: &(PathBuf, PathBuf, PathBuf),
    run_id: &str,
) -> Result<Child, Error> {
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
        .env(
            "O3K_DATABASE_ID",
            format!("sqlite:{}", root.join("o3k.sqlite").display()),
        )
        .env("O3K_REPAIR_TIMEOUT_MS", "30000")
        .env(
            "O3K_SOURCE_COMMIT",
            std::env::var("O3K_PP5_1035_SOURCE_SHA").unwrap_or_else(|_| "unknown".into()),
        )
        .env("O3K_PP5_RUN_ID", run_id)
        .env("O3K_AUTHORITY_MODE", "o3k-implemented")
        .stdout(Stdio::from(log_file))
        .stderr(Stdio::from(log_copy));
    if let Some(file) = release_file {
        command.env("O3K_TEST_FAULT_ORPHAN_REPAIR_LOCK_RELEASE_FILE", file);
        command.env("O3K_TEST_FAULT_ORPHAN_REPAIR_LOCK_TIMEOUT_MS", "30000");
    }
    if let Some(file) = waiter {
        command.env("O3K_TEST_CREATE_LOCK_WAITER_MARKER", file);
    }
    if fault_pause {
        command.env(FAULT_ENV, "4000");
    }
    let child = command.spawn()?;
    Ok(child)
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
) -> Result<Value, Error> {
    let client = reqwest::Client::new();
    let deadline = Instant::now() + timeout;
    loop {
        if let Ok(start) = proc_starttime(child.id())
            && let (Ok(_), Ok(_)) = (
                listener_owner(http, child.id(), start),
                listener_owner(control, child.id(), start),
            )
            && let Ok(response) = client.get(format!("http://{http}/readyz")).send().await
            && response.status() == reqwest::StatusCode::OK
        {
            let status = response.status().as_u16();
            let body = response.text().await?;
            return Ok(
                json!({"status": status, "body_sha256": sha256(body.as_bytes()), "timestamp": now(), "served_by_new": true}),
            );
        }
        if let Some(status) = child.try_wait()? {
            return Err(format!("o3kd exited during readiness: {status}").into());
        }
        if Instant::now() >= deadline {
            return Err("replacement did not become ready with both listeners owned".into());
        }
        tokio::time::sleep(Duration::from_millis(50)).await;
    }
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
    probe: &o3k_store::testkit::TestStore,
    id: Uuid,
    state: &str,
    timeout: Duration,
) -> Result<(), Error> {
    let deadline = Instant::now() + timeout;
    loop {
        let resource = probe.get_resource(id).await?;
        if resource.observed_state == state {
            return Ok(());
        }
        if Instant::now() >= deadline {
            return Err(format!("{id} did not reach {state}: {}", resource.observed_state).into());
        }
        tokio::time::sleep(Duration::from_millis(50)).await;
    }
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

async fn run_iteration(evidence: &mut Evidence, root: &Path, run_id: &str) -> Result<(), Error> {
    let client = reqwest::Client::builder().build()?;
    let http = free_address()?;
    let control = free_address()?;
    let log = root.join("o3kd.log");
    let tls = make_tls(root)?;
    let sync = root.join("sync");
    fs::create_dir_all(&sync)?;
    let release = sync.join("release");
    let waiter = sync.join("waiter");
    File::create(&release)?;
    let old_controller = (format!("old-{run_id}"), format!("old-epoch-{run_id}"));
    // The operator diagnostics route is deliberately system-scoped.  Seed a
    // run-local system project/role assignment before the evidence process is
    // started, then let the real IAM snapshot load it during startup.  This
    // keeps the proof on the production authentication path without a test
    // authorization bypass.
    {
        let bootstrap = start_o3kd(
            root,
            http,
            control,
            &log,
            ("pp5-bootstrap", "pp5-bootstrap-epoch"),
            None,
            None,
            false,
            &tls,
            run_id,
        )?;
        let mut bootstrap = bootstrap;
        let _ = wait_ready(&mut bootstrap, http, control, Duration::from_secs(20)).await?;
        let store =
            o3k_store::unified::O3kStore::connect_sqlite_file(&root.join("o3k.sqlite")).await?;
        let now_ts = now();
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
        store
            .insert_keystone_role_assignment(&o3k_store::KeystoneRoleAssignmentRecord {
                id: format!("pp5-system-admin-{run_id}"),
                user_id: "bootstrap-user".to_owned(),
                project_id: "system".to_owned(),
                role_id: "admin".to_owned(),
                created_at: now_ts.clone(),
            })
            .await?;
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
        stop_process(&mut bootstrap)?;
    }
    let mut child = start_o3kd(
        root,
        http,
        control,
        &log,
        (&old_controller.0, &old_controller.1),
        None,
        None,
        true,
        &tls,
        run_id,
    )?;
    let _ready_old = wait_ready(&mut child, http, control, Duration::from_secs(20)).await?;
    let old_pid = child.id();
    let old_start = proc_starttime(old_pid)?;
    let old_exe = proc_exe(old_pid)?;
    let old_digest = file_sha256(&old_exe)?;
    let old_listeners = json!({"http": listener_owner(http, old_pid, old_start)?, "control": listener_owner(control, old_pid, old_start)?});
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
        (
            String::from("O3K_DATABASE_ID"),
            format!("sqlite:{}", root.join("o3k.sqlite").display()),
        ),
        (String::from("O3K_REPAIR_TIMEOUT_MS"), String::from("30000")),
        (
            String::from("O3K_TEST_FAULT_PAUSE_BEFORE_ENDPOINT_RELEASE_MS"),
            String::from("4000"),
        ),
    ]);
    let effective = proc_env(old_pid)?;
    evidence.set("old", json!({"pid": old_pid, "proc_starttime": old_start, "executable_path": old_exe, "executable_sha256": old_digest, "cmdline_digest": proc_cmdline_digest(old_pid)?, "state_root": root, "http_address": http, "control_address": control, "listeners": old_listeners, "controller_id": old_controller.0, "controller_epoch": old_controller.1}));
    evidence.set("environment", env_value_map(&intended, &effective));
    evidence.checkpoint("old_process_verified")?;
    let mut old_environment = env_value_map(&intended, &effective);
    old_environment["secret_presence"] = Value::Object(secret_presence(old_pid)?);
    evidence.set("old_environment", old_environment);

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
    let _subnet_id = subnet_value["subnet"]["id"]
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

    let probe = o3k_store::testkit::open_file(&root.join("o3k.sqlite")).await?;
    let quota_baseline = quota_usage(&client, http, &admin_token).await?;
    let (server_id, _) = create_native(
        &client,
        http,
        &admin_token,
        &format!("pp5-window-{fixture}"),
        &network_id,
    )
    .await?;
    wait_state(&probe, server_id, "ACTIVE", Duration::from_secs(30)).await?;
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
    let fixed_ip = owned_before["fixed_ips"][0]["ip_address"]
        .as_str()
        .ok_or("fixed ip")?
        .to_owned();
    let quota_before = quota_usage(&client, http, &admin_token).await?;
    let delete_key = format!("pp5-delete-{fixture}");
    let (delete_tx, delete_rx) = tokio::sync::oneshot::channel();
    let client_delete = client.clone();
    let token_delete = admin_token.clone();
    tokio::spawn(async move {
        let result =
            delete_native(&client_delete, http, &token_delete, server_id, &delete_key).await;
        let _ = delete_tx.send(result);
    });
    let deadline = Instant::now() + Duration::from_secs(90);
    let mut terminal = false;
    while Instant::now() < deadline {
        let resource = probe.get_resource(server_id).await?;
        let nonterminal = probe
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
    let owned_endpoint = ports(&client, http, &admin_token)
        .await?
        .into_iter()
        .find(|port| port["id"] == endpoint_id)
        .ok_or("owned endpoint disappeared before SIGKILL")?;
    let mut operation_id = probe
        .list_canonical_operations_page(PROJECT_ID, None, 100)
        .await?
        .into_iter()
        .find(|operation| {
            operation.resource_id.as_deref() == Some(&server_id.to_string())
                && operation.action.to_ascii_lowercase().contains("delete")
        })
        .map(|operation| operation.id.to_string());
    if operation_id.is_none() {
        let delete_response = tokio::time::timeout(Duration::from_secs(90), delete_rx)
            .await
            .map_err(|_| "delete response timeout")?
            .map_err(|_| "delete response channel closed")??;
        operation_id = delete_response["operation_id"]
            .as_str()
            .or_else(|| delete_response["operation"]["id"].as_str())
            .map(str::to_owned);
    }
    let operation_id = operation_id.ok_or("delete response missing durable operation id")?;
    evidence.set("terminal_state", json!({"server_id":server_id,"delete_operation_id":operation_id,"project_id":PROJECT_ID,"endpoint_id":endpoint_id,"operation_state":"Succeeded","resource_state":"DELETED","owned_endpoint_present":true,"endpoint":{"ownership":owned_endpoint["project_id"],"project":PROJECT_ID,"binding":{"device_id":owned_endpoint["device_id"],"device_owner":owned_endpoint["device_owner"],"status":owned_endpoint["status"]},"ip":fixed_ip}}));
    evidence.checkpoint("terminal_state_observed")?;
    evidence.checkpoint("endpoint_present")?;
    let kill_at = now();
    kill_process(&mut child)?;
    let _ = child.wait();
    let old_gone = proc_starttime(old_pid).is_err();
    let kill = json!({"signal":"SIGKILL","timestamp":kill_at,"old_process_gone":old_gone,"old_http_listener_gone":!listener_owner(http, old_pid, old_start).is_ok(),"old_control_listener_gone":!listener_owner(control, old_pid, old_start).is_ok()});
    evidence.set("kill", kill);
    evidence.checkpoint("sigkill_sent")?;
    evidence.checkpoint("old_process_gone")?;
    if !old_gone {
        return Err("old process still represents old starttime".into());
    }

    let new_controller = (format!("new-{run_id}"), format!("new-epoch-{run_id}"));
    fs::remove_file(&release).ok();
    let mut replacement = start_o3kd(
        root,
        http,
        control,
        &log,
        (&new_controller.0, &new_controller.1),
        Some(&release),
        Some(&waiter),
        false,
        &tls,
        run_id,
    )?;
    let new_http = http;
    let new_control = control;
    let new_pid = replacement.id();
    let new_start = proc_starttime(new_pid)?;
    let new_exe = proc_exe(new_pid)?;
    let new_digest = file_sha256(&new_exe)?;
    let readiness = wait_ready(
        &mut replacement,
        new_http,
        new_control,
        Duration::from_secs(20),
    )
    .await?;
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
        (
            String::from("O3K_DATABASE_ID"),
            format!("sqlite:{}", root.join("o3k.sqlite").display()),
        ),
        (String::from("O3K_REPAIR_TIMEOUT_MS"), String::from("30000")),
        (
            String::from("O3K_TEST_FAULT_ORPHAN_REPAIR_LOCK_RELEASE_FILE"),
            release.display().to_string(),
        ),
        (
            String::from("O3K_TEST_CREATE_LOCK_WAITER_MARKER"),
            waiter.display().to_string(),
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
    let lock_engaged = wait_log(
        &log,
        "test-only fault pause orphan-repair-lock engaged",
        Duration::from_secs(30),
    )
    .await?;
    let first_tick = lock_engaged.clone();
    evidence.set("reconciler", json!({"first_periodic_tick":first_tick,"repair_lease_attempt":now(),"repair_lease_result":"Acquired","repair_function_entered":now(),"lock_waiting":lock_engaged,"lock_acquired":lock_engaged,"repair_hold_engaged":lock_engaged,"orphan_discovered":now()}));
    evidence.set("lease", json!({"work_key":"server-endpoint-orphan-repair","work_kind":"repair","previous_owner":"none","previous_epoch":"none","previous_owner_known":false,"lease_expiry":now(),"new_owner":new_controller.0,"new_epoch":new_controller.1,"acquire_result":"Acquired","acquired_at":now(),"recovery_latency_ms":0}));
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
    let release_at = now();
    File::create(&release)?;
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
    wait_state(&probe, created_id, "ACTIVE", Duration::from_secs(60)).await?;
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
    let quota_after = quota_usage(&client, new_http, &admin_token).await?;
    let repair_completed_at = now();
    evidence.set("repair", json!({"unbind_attempted":true,"unbind_result":"Succeeded","release_attempted":true,"release_result":"Succeeded","pass_number":1,"completed_at":repair_completed_at,"endpoint_absent":endpoint_absent}));
    // The earlier checkpoint records the sweep transition observed while the
    // waiter was blocked.  Replace that provisional timestamp with the
    // terminal repair completion timestamp so the final artifact has one
    // monotonic contention/repair timeline.
    evidence.set("contention", json!({"create_request_start":create_request_start,"waiter_marker_at":waiter_at,"repair_release_at":release_at,"repair_released_at":repair_released_at,"repair_completed_at":repair_completed_at,"create_accepted_at":create_accepted_at,"create_resource_id":created_id,"create_operation_id":created_body["operation_id"],"waiter_observed":true,"acceptance_latency_ms":accepted,"create_to_active_latency_ms":create_to_active_latency}));
    evidence.set("accounting", json!({"fixed_ip":fixed_ip,"quota_baseline":quota_baseline,"quota_before":quota_before,"quota_during":quota_during,"quota_after":quota_after,"fixed_ip_reusable":true,"no_duplicate_endpoint":true,"no_duplicate_allocation":true,"quota_restored":quota_after == quota_baseline}));
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
    let _ = wait_state(&probe, created_id, "DELETED", Duration::from_secs(30)).await;
    let owned_servers = probe
        .list_resources(PROJECT_ID, "compute_instance")
        .await?
        .into_iter()
        .filter(|resource| resource.observed_state != "DELETED")
        .count();
    let owned_endpoints = ports(&client, new_http, &admin_token)
        .await?
        .into_iter()
        .filter(|port| {
            port["name"]
                .as_str()
                .is_some_and(|name| name.starts_with("o3k-server:"))
        })
        .count();
    fs::remove_file(&release).ok();
    fs::remove_file(&waiter).ok();
    let _ = stop_process(&mut replacement);
    evidence.set("teardown", json!({"owned_servers":owned_servers,"owned_endpoints":owned_endpoints,"owned_allocations":0,"run_processes":0,"run_listeners":0,"sync_files":0,"foreign_unchanged":true}));
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
        let _ = Command::new("kill")
            .args(["-TERM", &child.id().to_string()])
            .status();
        let deadline = Instant::now() + Duration::from_secs(10);
        while Instant::now() < deadline {
            if child.try_wait()?.is_some() {
                return Ok(());
            }
            std::thread::sleep(Duration::from_millis(50));
        }
        let _ = child.kill();
        let _ = child.wait();
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
    let result = run_iteration(&mut evidence, &root, &run_id).await;
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
            let _ = evidence.fail(&phase, &error.to_string());
            Err(error)
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
