//! ISSUE #907 — Integrated production-profile northbound convergence gate.
//!
//! This is evidence/test infrastructure, not a product feature. It proves that
//! the merged #887–#906 northbound contracts converge together in ONE real
//! production-profile environment: the real `o3kd` binary (spawned as a
//! subprocess via `CARGO_BIN_EXE_o3kd`) on an ephemeral loopback socket, real
//! env-var production configuration, a real Keycloak RS256 OIDC provider as the
//! federated issuer, and a real durable store (PostgreSQL when
//! `O3K_DATABASE_URL` is set, otherwise SQLite at `<O3K_DATA_DIR>/o3k.sqlite`).
//!
//! The provider is `O3K_PROVIDER=fake`, the accepted execution-boundary
//! fixture; the gate never bypasses the adapter/router/auth layers.
//!
//! # Required environment (provided by tests/araf-p2-convergence.sh)
//!
//! ```text
//! O3K_P12_7_ISSUER            Keycloak realm issuer URL
//! O3K_P12_7_DISCOVERY_URL     Keycloak OIDC discovery URL
//! O3K_P12_7_ALICE_TOKEN       RS256 access token for tenant "alice"
//! O3K_P12_7_BOB_TOKEN         RS256 access token for tenant "bob"
//! O3K_P12_7_OPERATOR_TOKEN    RS256 access token for "operator"
//! O3K_P12_7_UNBOUND_TOKEN     RS256 access token for an unbound user
//! O3K_P12_7_ALICE_SUBJECT     OIDC subject of alice
//! O3K_P12_7_BOB_SUBJECT       OIDC subject of bob
//! O3K_P12_7_OPERATOR_SUBJECT  OIDC subject of operator
//! O3K_P12_7_BOOTSTRAP_SECRET  seed password for data-plane users
//! O3K_DATABASE_URL            optional; PostgreSQL URL for the PG pass
//! ```
//!
//! Gates on `O3K_P12_7_*`; marked `#[ignore]` per repo convention for
//! real-infra tests.
#![allow(clippy::expect_used, clippy::panic)]

use o3k_store::DurableStore;
use o3k_store::IdentityRepository;
use o3k_store::unified::O3kStore;
use serde_json::{Value, json};
use std::{
    net::TcpListener,
    process::{Child, Command},
    time::{Duration, Instant},
};
const LISTEN: &str = "127.0.0.1";
const SIGNING_KEY: &str = "araf-p2-token-signing-key-0123456789abcdef";
const CURSOR_KEY: &str = "araf-p2-native-cursor-signing-key-0123456789abcdef";

fn required(name: &str) -> String {
    std::env::var(name).unwrap_or_else(|_| panic!("missing required env {name}"))
}

enum Backend {
    Postgres(String),
    Sqlite(std::path::PathBuf),
}

fn resolve_backend(data_dir: &std::path::Path) -> Backend {
    if let Ok(url) = std::env::var("O3K_DATABASE_URL") {
        Backend::Postgres(url)
    } else {
        Backend::Sqlite(data_dir.join("o3k.sqlite"))
    }
}

async fn open_store(backend: &Backend) -> Result<O3kStore, Box<dyn std::error::Error>> {
    match backend {
        Backend::Postgres(url) => O3kStore::connect_postgres(url).await,
        Backend::Sqlite(path) => O3kStore::connect_sqlite_file(path).await,
    }
    .map_err(Into::into)
}

fn ephemeral_port() -> u16 {
    let listener = TcpListener::bind((LISTEN, 0)).expect("bind ephemeral");
    let port = listener.local_addr().expect("local addr").port();
    drop(listener);
    port
}

fn spawn_o3kd(port: u16, data_dir: &std::path::Path, backend: &Backend) -> Child {
    let mut envs: Vec<(String, String)> = vec![
        ("O3K_LISTEN_ADDR".to_owned(), format!("{LISTEN}:{port}")),
        ("O3K_DATA_DIR".to_owned(), data_dir.display().to_string()),
        ("O3K_PROVIDER".to_owned(), "fake".to_owned()),
        (
            "O3K_BOOTSTRAP_PASSWORD".to_owned(),
            required("O3K_P12_7_BOOTSTRAP_SECRET"),
        ),
        ("O3K_TOKEN_SIGNING_KEY".to_owned(), SIGNING_KEY.to_owned()),
        ("O3K_OIDC_TRUST_ID".to_owned(), "p12-7-keycloak".to_owned()),
        ("O3K_OIDC_ISSUER".to_owned(), required("O3K_P12_7_ISSUER")),
        ("O3K_OIDC_AUDIENCE".to_owned(), "o3k".to_owned()),
        (
            "O3K_OIDC_DISCOVERY_URL".to_owned(),
            required("O3K_P12_7_DISCOVERY_URL"),
        ),
        (
            "O3K_OIDC_ALLOW_INSECURE_LOCAL".to_owned(),
            "true".to_owned(),
        ),
        (
            "O3K_LOG_FILTER".to_owned(),
            "sqlx=debug,o3k_store=debug,o3k_compute=debug".to_owned(),
        ),
        (
            "O3K_NATIVE_CURSOR_HMAC_KEY".to_owned(),
            CURSOR_KEY.to_owned(),
        ),
        (
            "O3K_LOCATIONS".to_owned(),
            r#"[{"id":"region-a","availability_domains":[{"id":"az-1"},{"id":"az-2"}]}]"#
                .to_owned(),
        ),
    ];
    if let Backend::Postgres(url) = backend {
        envs.push(("O3K_DATABASE_BACKEND".to_owned(), "postgres".to_owned()));
        envs.push(("O3K_DATABASE_URL".to_owned(), url.clone()));
    } else {
        envs.push(("O3K_DATABASE_BACKEND".to_owned(), "sqlite".to_owned()));
    }
    let mut command = Command::new(env!("CARGO_BIN_EXE_o3kd"));
    let log_path = data_dir.join("o3kd.log");
    // Append rather than truncate: both process generations of the restart
    // journey must remain available for the item-13 log secret scan.
    let log_file = std::fs::OpenOptions::new()
        .create(true)
        .append(true)
        .open(&log_path)
        .expect("open o3kd log");
    command
        .args(["--listen-addr", &format!("{LISTEN}:{port}")])
        .stdout(log_file.try_clone().expect("clone o3kd stdout"))
        .stderr(log_file);
    for (key, value) in envs {
        command.env(&key, &value);
    }
    command.spawn().expect("spawn o3kd")
}

async fn wait_healthy(base: &str, log_path: &std::path::Path) {
    let client = reqwest::Client::new();
    let deadline = Instant::now() + Duration::from_secs(60);
    loop {
        if let Ok(response) = client.get(format!("{base}/healthz")).send().await
            && response.status().is_success()
        {
            return;
        }
        if Instant::now() >= deadline {
            // Keep health-timeout failures actionable without exposing the
            // process log (which is also an evidence surface for secrets).
            // Only startup/error lines are emitted, and common connection
            // material is redacted before it reaches CI output.
            if let Ok(log) = std::fs::read_to_string(log_path) {
                let diagnostics: String = log
                    .lines()
                    .filter(|line| {
                        let lower = line.to_ascii_lowercase();
                        lower.contains("error")
                            || lower.contains("panic")
                            || lower.contains("failed")
                            || lower.contains("database")
                            || lower.contains("listen")
                    })
                    .take(80)
                    .map(|line| {
                        line.replace("postgres://", "<redacted-dsn>")
                            .replace("postgresql://", "<redacted-dsn>")
                    })
                    .collect::<Vec<_>>()
                    .join("\n");
                if !diagnostics.is_empty() {
                    eprintln!("o3kd startup diagnostics (redacted):\n{diagnostics}");
                }
            }
            panic!("o3kd did not become healthy at {base}");
        }
        tokio::time::sleep(Duration::from_millis(250)).await;
    }
}

/// Seeds the durable store with the two-tenant identity defaults, the three
/// federated bindings, and the durable operator assignment. This is documented
/// environment setup (there is no canonical HTTP API for federated subject
/// bindings); the AuthContext derivation itself always goes through the
/// production token/scope endpoints.
async fn seed_store(backend: &Backend) -> Result<(), Box<dyn std::error::Error>> {
    let store = open_store(backend).await?;
    o3k_identity::seed_identity_defaults(
        &store,
        &o3k_identity::BootstrapConfig {
            catalog_endpoint: "http://127.0.0.1:8080".to_owned(),
            bootstrap_password: o3k_identity::Secret::new(required("O3K_P12_7_BOOTSTRAP_SECRET")),
            cinder_password: None,
            cinder_endpoint: None,
            pbkdf2_iterations: 1_000,
            extra_projects: vec![
                o3k_identity::ExtraProjectSeed {
                    project_id: "project-a".to_owned(),
                    project_name: "project-a".to_owned(),
                    user_id: "user-a".to_owned(),
                    user_name: "alice".to_owned(),
                    password: o3k_identity::Secret::new(required("O3K_P12_7_BOOTSTRAP_SECRET")),
                },
                o3k_identity::ExtraProjectSeed {
                    project_id: "project-b".to_owned(),
                    project_name: "project-b".to_owned(),
                    user_id: "user-b".to_owned(),
                    user_name: "bob".to_owned(),
                    password: o3k_identity::Secret::new(required("O3K_P12_7_BOOTSTRAP_SECRET")),
                },
            ],
        },
    )
    .await?;
    let now = "2026-09-11T00:00:00Z".to_owned();
    let issuer = required("O3K_P12_7_ISSUER");
    let bindings = [
        (
            "araf-p2-alice",
            required("O3K_P12_7_ALICE_SUBJECT"),
            "user-a",
        ),
        ("araf-p2-bob", required("O3K_P12_7_BOB_SUBJECT"), "user-b"),
        (
            "araf-p2-operator",
            required("O3K_P12_7_OPERATOR_SUBJECT"),
            "bootstrap-user",
        ),
    ];
    for (id, subject, principal) in bindings {
        // The binding is keyed on (trusted_issuer_id, subject); treat seeding
        // as idempotent so a shared store (e.g. one the P12-IAM.7 suite has
        // already primed) does not reject a duplicate.
        if store
            .find_federated_binding("p12-7-keycloak", &subject)
            .await?
            .is_none()
        {
            store
                .insert_federated_binding(&o3k_store::FederatedBindingRecord {
                    id: id.to_owned(),
                    trusted_issuer_id: "p12-7-keycloak".to_owned(),
                    issuer: issuer.clone(),
                    subject,
                    principal_id: principal.to_owned(),
                    principal_type: "user".to_owned(),
                    enabled: true,
                    created_at: now.clone(),
                    updated_at: now.clone(),
                })
                .await?;
        }
    }
    if store.list_operator_assignments().await?.is_empty() {
        store
            .insert_operator_assignment(&o3k_store::OperatorAssignmentRecord {
                id: "araf-p2-operator-assignment".to_owned(),
                user_id: "bootstrap-user".to_owned(),
                profile: "operator-console".to_owned(),
                enabled: true,
                created_at: now.clone(),
                updated_at: now.clone(),
            })
            .await?;
    }
    // Provenance: the operator principal the federated binding maps to must
    // carry the canonical durable operator assignment — fail loudly here if a
    // shared store lacks the expected authority instead of deriving a system
    // token from whatever assignment happens to exist.
    let assignment = store
        .list_operator_assignments()
        .await?
        .into_iter()
        .find(|assignment| assignment.user_id == "bootstrap-user")
        .ok_or_else(|| {
            std::io::Error::new(
                std::io::ErrorKind::NotFound,
                "no durable operator assignment for the operator principal bootstrap-user",
            )
        })?;
    if !assignment.enabled || assignment.profile != "operator-console" {
        return Err(std::io::Error::new(
            std::io::ErrorKind::InvalidData,
            format!(
                "operator assignment for bootstrap-user is not the canonical enabled operator-console authority: {:?}",
                assignment
            ),
        )
        .into());
    }
    Ok(())
}

#[derive(Clone)]
struct RawResponse {
    status: reqwest::StatusCode,
    body: String,
    json: Value,
}

struct Api {
    base: String,
    client: reqwest::Client,
    /// Every response body produced by the journey, retained for the item 13
    /// secret scan.
    bodies: Vec<String>,
}

impl Api {
    fn new(base: String) -> Self {
        Self {
            base,
            client: reqwest::Client::new(),
            bodies: Vec::new(),
        }
    }

    fn url(&self, path: &str) -> String {
        format!("{}{}", self.base, path)
    }

    async fn raw(
        &mut self,
        method: reqwest::Method,
        path: &str,
        token: Option<&str>,
        body: Option<Value>,
        idempotency_key: Option<&str>,
        if_match: Option<&str>,
    ) -> RawResponse {
        let url = self.url(path);
        let mut request = self
            .client
            .request(method.clone(), url)
            .header("accept", "application/json");
        if let Some(token) = token {
            request = request.bearer_auth(token);
        }
        if let Some(key) = idempotency_key {
            request = request.header("idempotency-key", key);
        }
        if let Some(if_match) = if_match {
            request = request.header("if-match", if_match);
        }
        if let Some(body) = body {
            request = request
                .header("content-type", "application/json")
                .json(&body);
        }
        let response = request.send().await.expect("http request");
        let status = response.status();
        let body = response.text().await.expect("response text");
        let json = serde_json::from_str(&body).unwrap_or(Value::Null);
        self.bodies
            .push(format!("{method} {path} -> {status}: {body}"));
        RawResponse { status, body, json }
    }

    async fn get(&mut self, path: &str, token: Option<&str>) -> RawResponse {
        self.raw(reqwest::Method::GET, path, token, None, None, None)
            .await
    }

    async fn post(
        &mut self,
        path: &str,
        token: Option<&str>,
        body: Value,
        idempotency_key: Option<&str>,
    ) -> RawResponse {
        self.raw(
            reqwest::Method::POST,
            path,
            token,
            Some(body),
            idempotency_key,
            None,
        )
        .await
    }

    async fn put(&mut self, path: &str, token: Option<&str>, body: Value) -> RawResponse {
        self.raw(reqwest::Method::PUT, path, token, Some(body), None, None)
            .await
    }

    async fn delete(
        &mut self,
        path: &str,
        token: Option<&str>,
        if_match: Option<&str>,
    ) -> RawResponse {
        self.raw(reqwest::Method::DELETE, path, token, None, None, if_match)
            .await
    }

    async fn action(
        &mut self,
        collection: &str,
        id: &str,
        action: &str,
        token: &str,
        idempotency_key: &str,
    ) -> RawResponse {
        self.post(
            &format!("/o3k/v1/{collection}/{id}/actions/{}", action),
            Some(token),
            json!({}),
            Some(idempotency_key),
        )
        .await
    }

    async fn exchange(
        &mut self,
        access_token: &str,
        project_id: Option<&str>,
        system: bool,
    ) -> RawResponse {
        let body = if system {
            json!({"auth": {"method": "federated", "federated": {"access_token": access_token, "scope": {"kind": "system"}}}})
        } else {
            json!({"auth": {"method": "federated", "project_id": project_id, "federated": {"access_token": access_token}}})
        };
        self.post("/o3k/v1/identity/tokens", None, body, None).await
    }

    /// Sends an OpenStack-compatible request authenticated with `x-auth-token`.
    async fn send_keystone(
        &mut self,
        method: reqwest::Method,
        path: &str,
        token: &str,
        body: Value,
    ) -> (reqwest::StatusCode, Value) {
        let url = self.url(path);
        let response = self
            .client
            .request(method, url)
            .header("accept", "application/json")
            .header("x-auth-token", token)
            .header("content-type", "application/json")
            .json(&body)
            .send()
            .await
            .expect("http request");
        let status = response.status();
        let text = response.text().await.expect("response text");
        self.bodies
            .push(format!("keystone {path} -> {status}: {text}"));
        (status, serde_json::from_str(&text).unwrap_or(Value::Null))
    }
}

fn get_token(response: &RawResponse) -> String {
    response.json["token"]["id"]
        .as_str()
        .expect("issued native token id")
        .to_owned()
}

/// Keystone-compatible password grant returning the `x-subject-token`.
async fn keystone_password_grant(
    api: &mut Api,
    user: &str,
    password: &str,
    project: &str,
) -> Result<String, Box<dyn std::error::Error>> {
    let url = api.url("/v3/auth/tokens");
    let payload = json!({
        "auth": {
            "identity": {
                "methods": ["password"],
                "password": {"user": {"name": user, "password": password}}
            },
            "scope": {"project": {"name": project}}
        }
    });
    let response = api
        .client
        .post(url.clone())
        .header("accept", "application/json")
        .header("content-type", "application/json")
        .json(&payload)
        .send()
        .await?;
    let status = response.status();
    // The subject token is a response header: read it before consuming the
    // body below.
    let token = response
        .headers()
        .get("x-subject-token")
        .and_then(|value| value.to_str().ok())
        .map(str::to_owned);
    // The grant response body is retained for the item-13 secret scan like
    // every other journey response.
    let body = response.text().await.unwrap_or_default();
    api.bodies
        .push(format!("POST /v3/auth/tokens -> {status}: {body}"));
    if status != reqwest::StatusCode::CREATED {
        panic!("keystone password grant failed: {status}: {body}");
    }
    Ok(token.ok_or("missing x-subject-token")?)
}

/// Generic compute:server create used across the journey.
async fn create_server(
    api: &mut Api,
    token: &str,
    name: &str,
    key: &str,
    port_id: &str,
    flavor_id: &str,
) -> RawResponse {
    api.post(
        "/o3k/v1/compute/servers",
        Some(token),
        json!({"kind": "compute:server", "spec": {"name": name, "image_id": "image-a", "flavor_id": flavor_id, "network_ids": [port_id]}}),
        Some(key),
    )
    .await
}

async fn wait_server_state(
    api: &mut Api,
    id: &str,
    wanted: &[&str],
    token: &str,
    backend: &Backend,
) {
    // The native read projection intentionally hides deleted servers, so a
    // 404 is the terminal success signal for the "deleted" wait.
    let deleted = wanted.iter().any(|w| w.eq_ignore_ascii_case("deleted"));
    let deadline = Instant::now() + Duration::from_secs(120);
    loop {
        let response = api
            .get(&format!("/o3k/v1/compute/servers/{id}"), Some(token))
            .await;
        if deleted && response.status == reqwest::StatusCode::NOT_FOUND {
            return;
        }
        if response.status.is_success() {
            let state = response.json["status"]["state"]
                .as_str()
                .unwrap_or_default()
                .to_lowercase();
            if wanted.iter().any(|w| w.eq_ignore_ascii_case(&state)) {
                return;
            }
        }
        if Instant::now() >= deadline {
            let store_state = if let Ok(store) = open_store(backend).await
                && let Ok(id_uuid) = uuid::Uuid::parse_str(id)
                && let Ok(resource) = store.get_resource(id_uuid).await
            {
                format!(
                    "observed_state={} generation={}",
                    resource.observed_state, resource.generation
                )
            } else {
                "store-unreadable".to_owned()
            };
            panic!(
                "server {id} did not reach {:?}; last show={:?}; store={store_state}",
                wanted, response.json["status"]["state"]
            );
        }
        tokio::time::sleep(Duration::from_millis(150)).await;
    }
}

fn next_hour_boundary_ms() -> i64 {
    let now = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_millis() as i64)
        .unwrap_or(0);
    let hour = 3_600_000;
    let remainder = now % hour;
    if remainder == 0 {
        now
    } else {
        now + (hour - remainder) + hour
    }
}

fn rfc3339(unix_ms: i64) -> String {
    chrono::DateTime::from_timestamp_millis(unix_ms)
        .expect("representable instant")
        .to_rfc3339_opts(chrono::SecondsFormat::Millis, true)
}

/// Owns a spawned `o3kd` child so a panicking assertion mid-journey cannot
/// orphan the real process (and its loopback socket): the guard terminates
/// and reaps on drop.
struct O3kdGuard {
    child: Option<Child>,
}

impl O3kdGuard {
    fn spawn(port: u16, data_dir: &std::path::Path, backend: &Backend) -> Self {
        Self {
            child: Some(spawn_o3kd(port, data_dir, backend)),
        }
    }

    /// Terminate and reap now, releasing the guard.
    async fn terminate(mut self) {
        let mut child = self.child.take().expect("o3kd child present");
        terminate(&mut child).await;
    }
}

impl Drop for O3kdGuard {
    fn drop(&mut self) {
        if let Some(mut child) = self.child.take() {
            let _ = Command::new("kill")
                .args(["-TERM", &child.id().to_string()])
                .status();
            let deadline = Instant::now() + Duration::from_secs(5);
            loop {
                if matches!(child.try_wait(), Ok(Some(_))) {
                    break;
                }
                if Instant::now() >= deadline {
                    let _ = child.kill();
                    let _ = child.wait();
                    break;
                }
                std::thread::sleep(Duration::from_millis(50));
            }
        }
    }
}

/// Sends SIGTERM and waits for a clean exit (mirrors shutdown.rs semantics).
async fn terminate(o3kd: &mut Child) {
    let _ = Command::new("kill")
        .args(["-TERM", &o3kd.id().to_string()])
        .status();
    let deadline = Instant::now() + Duration::from_secs(10);
    loop {
        if let Some(status) = o3kd.try_wait().expect("try_wait") {
            assert!(
                status.success(),
                "o3kd did not exit cleanly on SIGTERM: {status}"
            );
            return;
        }
        if Instant::now() >= deadline {
            o3kd.kill().ok();
            panic!("o3kd did not shut down after SIGTERM");
        }
        tokio::time::sleep(Duration::from_millis(50)).await;
    }
}

const HONEST_STATUS: [&str; 5] = ["healthy", "degraded", "unavailable", "stale", "unknown"];

/// Item-13 log surface: the o3kd process logs (both generations, appended to
/// `<data_dir>/o3kd.log` by `spawn_o3kd`) must not contain any secret marker.
fn scan_o3kd_log(data_dir: &std::path::Path, secrets: &[(&str, String)]) {
    let log_path = data_dir.join("o3kd.log");
    let content = std::fs::read_to_string(&log_path)
        .unwrap_or_else(|error| panic!("read {}: {error}", log_path.display()));
    for (label, secret) in secrets {
        assert!(
            !content.contains(secret.as_str()),
            "secret scan failed ({label}) leaked into the o3kd log {}",
            log_path.display()
        );
    }
    assert!(
        !content.contains("-----BEGIN"),
        "private-key marker leaked into the o3kd log {}",
        log_path.display()
    );
    // `postgres://` (DSN material) must never reach the log. `agent_epoch`
    // is intentionally body-only: it is a legitimate tracing field and SQL
    // column name inside the process, and only the diagnostics *contract*
    // forbids it in responses.
    assert!(
        !content.contains("postgres://"),
        "DSN marker leaked into the o3kd log {}",
        log_path.display()
    );
}

#[tokio::test]
#[ignore = "requires the Keycloak testbed + durable store started by tests/araf-p2-convergence.sh"]
async fn araf_p2_northbound_convergence() -> Result<(), Box<dyn std::error::Error>> {
    let run_tag = uuid::Uuid::new_v4().simple().to_string();
    let data_dir = std::env::temp_dir().join(format!("araf-p2-{run_tag}"));
    std::fs::create_dir_all(&data_dir)?;
    let backend = resolve_backend(&data_dir);
    seed_store(&backend).await?;

    // ── Phase 1: first o3kd process ───────────────────────────────────────
    let port = ephemeral_port();
    let base = format!("http://{LISTEN}:{port}");
    let child = O3kdGuard::spawn(port, &data_dir, &backend);
    wait_healthy(&base, &data_dir.join("o3kd.log")).await;
    let mut api = Api::new(base.clone());

    // 1. Federated login.
    let alice_discovery = api
        .post(
            "/o3k/v1/identity/scopes",
            None,
            json!({"federated": {"access_token": required("O3K_P12_7_ALICE_TOKEN")}}),
            None,
        )
        .await;
    assert_eq!(alice_discovery.status, 200, "{}", alice_discovery.body);
    let scopes = alice_discovery.json["scopes"]
        .as_array()
        .cloned()
        .unwrap_or_default();
    assert!(
        scopes.iter().any(|s| s["id"] == "project-a"),
        "alice must discover project-a: {}",
        alice_discovery.body
    );
    let alice_exchange = api
        .exchange(&required("O3K_P12_7_ALICE_TOKEN"), Some("project-a"), false)
        .await;
    assert_eq!(alice_exchange.status, 201, "{}", alice_exchange.body);
    let alice_token = get_token(&alice_exchange);
    let bob_exchange = api
        .exchange(&required("O3K_P12_7_BOB_TOKEN"), Some("project-b"), false)
        .await;
    assert_eq!(bob_exchange.status, 201, "{}", bob_exchange.body);
    let bob_token = get_token(&bob_exchange);
    let operator_exchange = api
        .exchange(&required("O3K_P12_7_OPERATOR_TOKEN"), None, true)
        .await;
    assert_eq!(operator_exchange.status, 201, "{}", operator_exchange.body);
    let operator_token = get_token(&operator_exchange);

    // Negatives: unbound subject, foreign project scope, tenant system scope.
    // The canonical federated-exchange denial is 401 Unauthorized (the
    // composition token issuer maps every federated validation/scope denial
    // to ProblemDetails::unauthorized).
    let unbound = api
        .exchange(
            &required("O3K_P12_7_UNBOUND_TOKEN"),
            Some("project-a"),
            false,
        )
        .await;
    assert_eq!(unbound.status, 401, "{}", unbound.body);
    let bob_in_a = api
        .exchange(&required("O3K_P12_7_BOB_TOKEN"), Some("project-a"), false)
        .await;
    assert_eq!(bob_in_a.status, 401, "{}", bob_in_a.body);
    let alice_system = api
        .exchange(&required("O3K_P12_7_ALICE_TOKEN"), None, true)
        .await;
    assert_eq!(alice_system.status, 401, "{}", alice_system.body);
    let me = api.get("/o3k/v1/identity/me", Some(&alice_token)).await;
    assert_eq!(me.status, 200, "{}", me.body);
    assert_eq!(me.json["effective_scope_id"], "project-a");

    // 2. Discovery.
    for path in [
        "/o3k/v1/services",
        "/o3k/v1/resource-types",
        "/o3k/v1/regions",
        "/o3k/v1/resource-schemas/compute/servers/v1",
    ] {
        let response = api.get(path, None).await;
        assert_eq!(response.status, 200, "GET {path}: {}", response.body);
    }
    let services = api.get("/o3k/v1/services", None).await;
    let service_ids: Vec<&str> = services.json["services"]
        .as_array()
        .map(|items| items.iter().filter_map(|i| i["id"].as_str()).collect())
        .unwrap_or_default();
    for wanted in ["compute", "network", "identity"] {
        assert!(
            service_ids.contains(&wanted),
            "missing {wanted}: {}",
            services.body
        );
    }
    let resource_types = api.get("/o3k/v1/resource-types", None).await;
    let compute = resource_types.json["resource_types"]
        .as_array()
        .and_then(|items| {
            items
                .iter()
                .find(|i| i["namespace"] == "compute" && i["name"] == "server")
        })
        .cloned()
        .expect("compute:server advertised");
    assert_eq!(compute["ready"], true, "{}", compute);
    let lifecycle: Vec<&str> = compute["lifecycle_actions"]
        .as_object()
        .map(|m| m.keys().map(String::as_str).collect())
        .unwrap_or_default();
    for capability in ["create", "show", "list", "update", "delete"] {
        assert!(
            lifecycle.contains(&capability),
            "compute:server advertises {capability}"
        );
    }
    // The `actions` array projects the canonical lifecycle action metadata
    // (SPEC-0040: clients never infer undeclared actions; domain actions are
    // manifest-declared and exercised by this journey's stop/start/reboot
    // steps rather than part of this metadata projection).
    let action_names: Vec<&str> = compute["actions"]
        .as_array()
        .map(|items| items.iter().filter_map(|a| a["name"].as_str()).collect())
        .unwrap_or_default();
    for wanted in ["CreateServer", "ReadServer", "UpdateServer", "DeleteServer"] {
        assert!(
            action_names.contains(&wanted),
            "compute:server must advertise the {wanted} lifecycle action metadata: {}",
            compute["actions"]
        );
    }
    let schema = api
        .get("/o3k/v1/resource-schemas/compute/servers/v1", None)
        .await;
    assert_eq!(schema.json["x-o3k-resource-type"], "compute:server");
    let regions = api.get("/o3k/v1/regions", None).await;
    assert_eq!(regions.json["count"], 1, "{}", regions.body);
    assert_eq!(
        regions.json["regions"][0]["availability_domains"]
            .as_array()
            .map(Vec::len)
            .unwrap_or(0),
        2,
        "{}",
        regions.body
    );

    // 16/3. Keystone password grant mints a project-a token (item 16) used by
    // the OpenStack-compatible Neutron surface to create the subnet/port, and
    // later to list the natively-created server through Nova.
    let keystone_token = self::keystone_password_grant(
        &mut api,
        "alice",
        &required("O3K_P12_7_BOOTSTRAP_SECRET"),
        "project-a",
    )
    .await?;

    // 3/6. The network realm is created through the native generic route
    // (network:network has a declared native create contract). subnet and port
    // are created through the OpenStack-compatible Neutron surface on the same
    // canonical network authority (the native generic create contract is only
    // registered for contract-bearing native resources).
    let net_create = api
        .post(
            "/o3k/v1/network/networks",
            Some(&alice_token),
            json!({"kind": "network:network", "spec": {"name": format!("araf-net-{run_tag}")}}),
            Some("araf-net-create"),
        )
        .await;
    assert_eq!(net_create.status, 201, "{}", net_create.body);
    let network_id = net_create.json["resource_id"]
        .as_str()
        .expect("network id")
        .to_owned();

    let subnet_create = api
        .send_keystone(
            reqwest::Method::POST,
            "/v2.0/subnets",
            &keystone_token,
            json!({"subnet": {"network_id": network_id, "name": format!("araf-subnet-{run_tag}"), "cidr": "192.0.2.0/24", "gateway_ip": "192.0.2.1"}}),
        )
        .await;
    assert_eq!(subnet_create.0, 201, "{}", subnet_create.1);
    let port_create = api
        .send_keystone(
            reqwest::Method::POST,
            "/v2.0/ports",
            &keystone_token,
            json!({"port": {"network_id": network_id, "name": format!("araf-port-{run_tag}")}}),
        )
        .await;
    assert_eq!(port_create.0, 201, "{}", port_create.1);
    let port_id = port_create.1["port"]["id"]
        .as_str()
        .expect("port id")
        .to_owned();

    // 7. Quota: finite limit, allocation to the limit, clean rejection. The
    // shared durable store may already hold servers (the P12 suite shares this
    // PostgreSQL), so the finite limit is set relative to live usage: the gate
    // proves "allocate to the limit -> reject -> release -> allocate again"
    // against real usage U rather than assuming U == 0.
    let flavor_id = "00000000-0000-0000-0000-000000000001";
    let quota_uri = "/o3k/v1/operator/quotas/project-a/compute/servers";
    let quota_before = api
        .get("/o3k/v1/operator/quotas/project-a", Some(&operator_token))
        .await;
    assert_eq!(quota_before.status, 200, "{}", quota_before.body);
    let compute_item = quota_before.json["items"].as_array().and_then(|items| {
        items
            .iter()
            .find(|i| i["namespace"] == "compute" && i["key"] == "servers")
    });
    let generation = compute_item
        .and_then(|i| i["generation"].as_u64())
        .unwrap_or(0);
    let initial_usage = compute_item.and_then(|i| i["usage"].as_u64()).unwrap_or(0);
    // Exactly one server fits; usage equals the limit after the first create.
    let limit = initial_usage + 1;
    let quota_set = api
        .put(
            quota_uri,
            Some(&operator_token),
            json!({"limit": {"kind": "maximum", "value": limit}, "expected_generation": generation}),
        )
        .await;
    assert_eq!(quota_set.status, 200, "{}", quota_set.body);
    assert_eq!(
        quota_set.json["limit"]["value"], limit,
        "{}",
        quota_set.body
    );

    let server_a = create_server(
        &mut api,
        &alice_token,
        &format!("araf-srv-a-{run_tag}"),
        "araf-srv-a",
        &port_id,
        flavor_id,
    )
    .await;
    assert!(server_a.status.is_success(), "{}", server_a.body);
    let server_a_id = server_a.json["resource_id"]
        .as_str()
        .expect("server id")
        .to_owned();
    let server_a_replay = create_server(
        &mut api,
        &alice_token,
        &format!("araf-srv-a-{run_tag}"),
        "araf-srv-a",
        &port_id,
        flavor_id,
    )
    .await;
    assert!(
        server_a_replay.status.is_success(),
        "{}",
        server_a_replay.body
    );
    assert_eq!(
        server_a_replay.json["resource_id"], server_a_id,
        "{}",
        server_a_replay.body
    );
    wait_server_state(
        &mut api,
        &server_a_id,
        &["active", "running"],
        &alice_token,
        &backend,
    )
    .await;
    let srv_a_show = api
        .get(
            &format!("/o3k/v1/compute/servers/{server_a_id}"),
            Some(&alice_token),
        )
        .await;
    assert_eq!(srv_a_show.status, 200, "{}", srv_a_show.body);
    assert_eq!(srv_a_show.json["metadata"]["owner_scope"], "project-a");
    let server_a_generation = srv_a_show.json["metadata"]["generation"]
        .as_i64()
        .expect("generation");

    // 12 (live-resource probes): Tenant B is concealed from server A while it
    // is ACTIVE — a 404 here cannot be explained by the resource being
    // deleted, so the scoping denial is genuine.
    let bob_live_show = api
        .get(
            &format!("/o3k/v1/compute/servers/{server_a_id}"),
            Some(&bob_token),
        )
        .await;
    assert_eq!(bob_live_show.status, 404, "{}", bob_live_show.body);
    let bob_live_action = api
        .action(
            "compute/servers",
            &server_a_id,
            "StopServer",
            &bob_token,
            "bob-live-stop",
        )
        .await;
    assert_eq!(bob_live_action.status, 404, "{}", bob_live_action.body);
    // Tenant A's resource is unaffected by the foreign probes.
    let srv_a_untouched = api
        .get(
            &format!("/o3k/v1/compute/servers/{server_a_id}"),
            Some(&alice_token),
        )
        .await;
    assert_eq!(srv_a_untouched.status, 200, "{}", srv_a_untouched.body);
    assert!(
        ["active", "running"].contains(
            &srv_a_untouched.json["status"]["state"]
                .as_str()
                .unwrap_or_default()
                .to_lowercase()
                .as_str()
        ),
        "foreign probes must not disturb the live server: {}",
        srv_a_untouched.body
    );

    // 16. OpenStack-compatible convergence: Nova lists the natively-created
    // server (same canonical resource and ID), and Neutron shows the network
    // that was created natively — one shared authority, two protocol surfaces.
    let nova = api
        .send_keystone(
            reqwest::Method::GET,
            "/v2.1/project-a/servers",
            &keystone_token,
            json!({}),
        )
        .await;
    assert_eq!(nova.0, 200, "{}", nova.1);
    let nova_ids: Vec<&str> = nova.1["servers"]
        .as_array()
        .map(|items| items.iter().filter_map(|s| s["id"].as_str()).collect())
        .unwrap_or_default();
    assert!(
        nova_ids.contains(&server_a_id.as_str()),
        "Nova must list the natively-created server ({}): {}",
        server_a_id,
        nova.1
    );
    let neutron_network = api
        .send_keystone(
            reqwest::Method::GET,
            &format!("/v2.0/networks/{network_id}"),
            &keystone_token,
            json!({}),
        )
        .await;
    assert_eq!(neutron_network.0, 200, "{}", neutron_network.1);
    assert_eq!(
        neutron_network.1["network"]["id"],
        Value::from(network_id.clone())
    );

    let quota_now = api
        .get("/o3k/v1/quota/compute/servers", Some(&alice_token))
        .await;
    assert_eq!(quota_now.status, 200, "{}", quota_now.body);
    assert_eq!(quota_now.json["usage"], limit, "{}", quota_now.body);
    let server_b_rejected = create_server(
        &mut api,
        &alice_token,
        &format!("araf-srv-b-{run_tag}"),
        "araf-srv-b",
        &port_id,
        flavor_id,
    )
    .await;
    assert_eq!(
        server_b_rejected.status, 403,
        "quota exhaustion must reject with the canonical 403: {}",
        server_b_rejected.body
    );
    let quota_after_rejected = api
        .get("/o3k/v1/quota/compute/servers", Some(&alice_token))
        .await;
    assert_eq!(
        quota_after_rejected.json["usage"], limit,
        "no reservation leak: {}",
        quota_after_rejected.body
    );
    // Stale-generation quota mutation rejected.
    let stale_quota = api
        .put(
            quota_uri,
            Some(&operator_token),
            json!({"limit": {"kind": "unlimited"}, "expected_generation": generation}),
        )
        .await;
    assert_eq!(stale_quota.status, 409, "{}", stale_quota.body);
    // Tenant self-administering its own operator route denied.
    let self_admin = api
        .put(
            quota_uri,
            Some(&alice_token),
            json!({"limit": {"kind": "unlimited"}, "expected_generation": generation + 1}),
        )
        .await;
    assert_eq!(self_admin.status, 403, "{}", self_admin.body);
    // Tenant B cannot read Project A quota.
    let foreign_quota = api
        .get("/o3k/v1/operator/quotas/project-a", Some(&bob_token))
        .await;
    assert_eq!(foreign_quota.status, 403, "{}", foreign_quota.body);

    // 4. Domain actions: stop, start, reboot.
    let stop = api
        .action(
            "compute/servers",
            &server_a_id,
            "StopServer",
            &alice_token,
            "araf-stop",
        )
        .await;
    assert!(stop.status.is_success(), "{}", stop.body);
    let stop_op = stop.json["operation_id"]
        .as_str()
        .expect("op id")
        .to_owned();
    wait_server_state(
        &mut api,
        &server_a_id,
        &["shutoff", "stopped"],
        &alice_token,
        &backend,
    )
    .await;
    let start = api
        .action(
            "compute/servers",
            &server_a_id,
            "StartServer",
            &alice_token,
            "araf-start",
        )
        .await;
    assert!(start.status.is_success(), "{}", start.body);
    let start_op = start.json["operation_id"]
        .as_str()
        .expect("op id")
        .to_owned();
    wait_server_state(
        &mut api,
        &server_a_id,
        &["active", "running"],
        &alice_token,
        &backend,
    )
    .await;
    let reboot = api
        .action(
            "compute/servers",
            &server_a_id,
            "RebootServer",
            &alice_token,
            "araf-reboot",
        )
        .await;
    assert!(reboot.status.is_success(), "{}", reboot.body);
    let reboot_op = reboot.json["operation_id"]
        .as_str()
        .expect("op id")
        .to_owned();
    // Wait for the reboot to converge before reading a generation: the
    // terminal observation write advances the durable generation, so a
    // generation read while the action is still converging would race the
    // projection (the honest 409 is re-verified explicitly below).
    wait_server_state(
        &mut api,
        &server_a_id,
        &["active", "running"],
        &alice_token,
        &backend,
    )
    .await;

    // 3/6. Relationships: bounded canonical projection over a real durable
    // row. The relationship WRITE authority in this profile is the
    // external-controller composition path (CompositionResourceHandler,
    // opt-in O3K_COMPOSITION_*), exercised at store level by
    // bins/o3kd/tests/p12_6_process.rs; there is no northbound writer. As
    // documented environment setup through that same canonical durable
    // authority, seed one canonical relationship row (parent = the Tenant A
    // server, child = the Tenant A network created above) so the gate proves
    // the northbound READ projection through the real production router.
    let server_a_uuid = uuid::Uuid::parse_str(&server_a_id).expect("server uuid");
    let network_uuid = uuid::Uuid::parse_str(&network_id).expect("network uuid");
    let parent_operation_uuid = server_a.json["operation_id"]
        .as_str()
        .and_then(|id| uuid::Uuid::parse_str(id).ok())
        .unwrap_or_else(|| {
            uuid::Uuid::new_v5(
                &uuid::Uuid::NAMESPACE_URL,
                format!("araf-p2-rel-parent:{server_a_id}").as_bytes(),
            )
        });
    let child_operation_uuid = uuid::Uuid::new_v5(
        &uuid::Uuid::NAMESPACE_URL,
        format!("araf-p2-rel-child:{network_id}").as_bytes(),
    );
    {
        let store = open_store(&backend).await?;
        // Vocabulary mirrors CompositionResourceHandler::relationship_record:
        // "exclusive" ownership, "reserved" at reserve time (the store forces
        // the canonical state constant), then bound via bind_relationship.
        let record = o3k_store::ResourceRelationshipRecord {
            parent_resource_id: server_a_uuid,
            parent_resource_type: "compute:server".to_owned(),
            slot: "network-primary".to_owned(),
            expected_child_resource_type: "network:network".to_owned(),
            child_resource_id: Some(network_uuid),
            ownership: "exclusive".to_owned(),
            parent_operation_id: parent_operation_uuid,
            child_operation_id: Some(child_operation_uuid),
            owner_scope: "project-a".to_owned(),
            state: "reserved".to_owned(),
            fingerprint: format!("araf-p2-relationship:{run_tag}"),
        };
        // Bounded retry: on SQLite the running binary holds the same file,
        // so a writer lock can briefly bounce the seeding insert.
        let mut last_error = None;
        let mut seeded = false;
        for _ in 0..20 {
            match store.reserve_relationship(&record).await {
                Ok(_) | Err(o3k_store::StoreError::IdempotencyConflict) => {
                    // IdempotencyConflict is the replay-safe duplicate shape:
                    // the row is already reserved from an earlier attempt.
                    seeded = true;
                    break;
                }
                Err(error) => {
                    last_error = Some(error);
                    tokio::time::sleep(Duration::from_millis(100)).await;
                }
            }
        }
        assert!(
            seeded,
            "relationship seeding through the canonical authority failed: {last_error:?}"
        );
        store
            .bind_relationship(
                server_a_uuid,
                "network-primary",
                network_uuid,
                child_operation_uuid,
            )
            .await?;
    }

    let relationships = api
        .get(
            &format!("/o3k/v1/compute/servers/{server_a_id}/relationships"),
            Some(&alice_token),
        )
        .await;
    assert_eq!(relationships.status, 200, "{}", relationships.body);
    assert_eq!(
        relationships.json["has_more"], false,
        "{}",
        relationships.body
    );
    let rel_items = relationships.json["items"]
        .as_array()
        .cloned()
        .unwrap_or_default();
    let seeded_rel = rel_items
        .iter()
        .find(|item| item["slot"] == "network-primary");
    let seeded_rel = match seeded_rel {
        Some(item) => item,
        None => panic!("seeded relationship not projected: {}", relationships.body),
    };
    assert_eq!(
        seeded_rel["resource_type"], "network:network",
        "{seeded_rel}"
    );
    assert_eq!(seeded_rel["state"], "bound", "{seeded_rel}");
    assert_eq!(seeded_rel["ownership"], "exclusive", "{seeded_rel}");
    // The child is surfaced under its canonical public UUID — never a
    // provider-private identifier.
    assert_eq!(
        seeded_rel["resource_id"],
        Value::from(network_id.clone()),
        "{seeded_rel}"
    );
    for item in &rel_items {
        let resource_type = item["resource_type"].as_str().unwrap_or_default();
        assert!(
            resource_type.chars().filter(|c| *c == ':').count() == 1
                && resource_type
                    .chars()
                    .all(|c| c.is_ascii_alphanumeric() || matches!(c, ':' | '-' | '_')),
            "relationship entries must use canonical resource types: {item}"
        );
        if let Some(child) = item["resource_id"].as_str() {
            assert!(
                uuid::Uuid::parse_str(child).is_ok(),
                "relationship entries must carry canonical public IDs, never provider-private ones: {item}"
            );
        }
    }
    // Foreign probing conceals the seeded row: with real durable rows present,
    // Tenant B still receives 404 — genuine concealment, not an empty page.
    let bob_relationships = api
        .get(
            &format!("/o3k/v1/compute/servers/{server_a_id}/relationships"),
            Some(&bob_token),
        )
        .await;
    assert_eq!(bob_relationships.status, 404, "{}", bob_relationships.body);

    // 5. Operations: show each mutation's operation + bounded collection.
    for op in [&stop_op, &start_op, &reboot_op] {
        let response = api
            .get(&format!("/o3k/v1/operations/{op}"), Some(&alice_token))
            .await;
        assert_eq!(response.status, 200, "{}", response.body);
        assert_eq!(
            response.json["id"],
            Value::from(op.clone()),
            "{}",
            response.body
        );
    }
    let ops_first = api
        .get("/o3k/v1/operations?limit=1", Some(&alice_token))
        .await;
    assert_eq!(ops_first.status, 200, "{}", ops_first.body);
    let page1_ids: Vec<String> = ops_first.json["items"]
        .as_array()
        .map(|items| {
            items
                .iter()
                .filter_map(|item| item["id"].as_str().map(str::to_owned))
                .collect()
        })
        .unwrap_or_default();
    assert!(!page1_ids.is_empty(), "{}", ops_first.body);
    if let Some(cursor) = ops_first.json["next_cursor"].as_str().map(str::to_owned) {
        // A cursor is only offered when more rows exist; page 2 must then be
        // non-empty and must not repeat page 1's item — a real page advance.
        let ops_second = api
            .get(
                &format!("/o3k/v1/operations?limit=1&cursor={cursor}"),
                Some(&alice_token),
            )
            .await;
        assert_eq!(ops_second.status, 200, "{}", ops_second.body);
        let page2_ids: Vec<String> = ops_second.json["items"]
            .as_array()
            .map(|items| {
                items
                    .iter()
                    .filter_map(|item| item["id"].as_str().map(str::to_owned))
                    .collect()
            })
            .unwrap_or_default();
        assert!(
            !page2_ids.is_empty(),
            "a continuation cursor was offered but page 2 is empty: {}",
            ops_second.body
        );
        assert!(
            page1_ids.iter().all(|id| !page2_ids.contains(id)),
            "cursor continuation must advance the page: {page1_ids:?} vs {page2_ids:?}"
        );
    }

    // 3. Update via PUT with If-Match generation (#905). The domain actions
    // above advance the durable generation, so re-read the current one: a
    // stale precondition must be rejected and the live one accepted.
    let current_generation = {
        let show = api
            .get(
                &format!("/o3k/v1/compute/servers/{server_a_id}"),
                Some(&alice_token),
            )
            .await;
        assert_eq!(show.status, 200, "{}", show.body);
        show.json["metadata"]["generation"]
            .as_i64()
            .expect("current generation")
    };
    assert!(
        current_generation > server_a_generation,
        "domain actions must advance the durable generation: before={server_a_generation} after={current_generation}"
    );
    // Missing If-Match must be rejected. The probe carries an idempotency
    // key (so the observed 400 is provably the missing-precondition rule,
    // not the missing-key rule, which is checked first).
    let no_match = api
        .raw(
            reqwest::Method::PUT,
            &format!("/o3k/v1/compute/servers/{server_a_id}"),
            Some(&alice_token),
            Some(json!({"spec": {"name": "no-match-probe"}})),
            Some("araf-update-no-if-match"),
            None,
        )
        .await;
    assert_eq!(no_match.status, 400, "{}", no_match.body);
    let stale_update = api
        .raw(
            reqwest::Method::PUT,
            &format!("/o3k/v1/compute/servers/{server_a_id}"),
            Some(&alice_token),
            Some(json!({"spec": {"name": "stale"}})),
            Some("araf-update-stale"),
            Some(&format!("generation-{}", current_generation - 1)),
        )
        .await;
    assert_eq!(stale_update.status, 409, "{}", stale_update.body);
    // The good update uses its own idempotency key: the stale attempt above
    // was rejected before any durable write (it reserved nothing), and a
    // different body/generation under one key is an IdempotencyConflict by
    // design.
    let good_update = api
        .raw(
            reqwest::Method::PUT,
            &format!("/o3k/v1/compute/servers/{server_a_id}"),
            Some(&alice_token),
            Some(json!({"spec": {"name": format!("araf-srv-a-renamed-{run_tag}")}})),
            Some("araf-update"),
            Some(&format!("generation-{current_generation}")),
        )
        .await;
    assert_eq!(good_update.status, 200, "{}", good_update.body);

    // Deleting A frees the quota slot.
    let delete_a = api
        .delete(
            &format!("/o3k/v1/compute/servers/{server_a_id}"),
            Some(&alice_token),
            None,
        )
        .await;
    assert_eq!(delete_a.status, 204, "{}", delete_a.body);
    wait_server_state(&mut api, &server_a_id, &["deleted"], &alice_token, &backend).await;
    let quota_after_release = api
        .get("/o3k/v1/quota/compute/servers", Some(&alice_token))
        .await;
    assert_eq!(
        quota_after_release.json["usage"], initial_usage,
        "{}",
        quota_after_release.body
    );

    // 11-meter journey on server B (reuses the freed slot), closed via delete.
    let server_b = create_server(
        &mut api,
        &alice_token,
        &format!("araf-srv-b2-{run_tag}"),
        "araf-srv-b2",
        &port_id,
        flavor_id,
    )
    .await;
    assert!(server_b.status.is_success(), "{}", server_b.body);
    let server_b_id = server_b.json["resource_id"]
        .as_str()
        .expect("server id")
        .to_owned();
    let server_b_op = server_b.json["operation_id"]
        .as_str()
        .expect("server b create operation id")
        .to_owned();
    wait_server_state(
        &mut api,
        &server_b_id,
        &["active", "running"],
        &alice_token,
        &backend,
    )
    .await;
    api.action(
        "compute/servers",
        &server_b_id,
        "StopServer",
        &alice_token,
        "araf-stop-b",
    )
    .await;
    wait_server_state(
        &mut api,
        &server_b_id,
        &["shutoff", "stopped"],
        &alice_token,
        &backend,
    )
    .await;
    api.action(
        "compute/servers",
        &server_b_id,
        "StartServer",
        &alice_token,
        "araf-start-b",
    )
    .await;
    wait_server_state(
        &mut api,
        &server_b_id,
        &["active", "running"],
        &alice_token,
        &backend,
    )
    .await;
    let delete_b = api
        .delete(
            &format!("/o3k/v1/compute/servers/{server_b_id}"),
            Some(&alice_token),
            None,
        )
        .await;
    assert_eq!(delete_b.status, 204, "{}", delete_b.body);
    wait_server_state(&mut api, &server_b_id, &["deleted"], &alice_token, &backend).await;

    // 11. Metering: honest non-advertisement of the volume meter.
    let definitions = api
        .get("/o3k/v1/metering/definitions", Some(&alice_token))
        .await;
    assert_eq!(definitions.status, 200, "{}", definitions.body);
    let def_keys: Vec<&str> = definitions.json["definitions"]
        .as_array()
        .map(|defs| defs.iter().filter_map(|d| d["key"].as_str()).collect())
        .unwrap_or_default();
    assert!(
        def_keys.contains(&"compute:instance_seconds"),
        "{}",
        definitions.body
    );
    let compute_definition = definitions.json["definitions"]
        .as_array()
        .and_then(|defs| defs.iter().find(|d| d["key"] == "compute:instance_seconds"))
        .expect("compute:instance_seconds definition");
    assert_eq!(compute_definition["unit"], "instance_second");
    assert!(
        !def_keys.contains(&"volume:allocated_byte_seconds"),
        "volume meter must be honestly non-advertised (no native storage): {}",
        definitions.body
    );
    // Usage over an explicit, hour-aligned window containing the closed
    // journey. The restart-stable total comparison is narrowed to the gate's
    // own server B journey (its intervals are closed by the delete, so the
    // total is frozen): the shared store may hold other projects' or earlier
    // suites' still-open intervals, whose live accrual must not make the
    // before/after comparison flaky.
    let end = next_hour_boundary_ms();
    let start = end - 24 * 3_600_000;
    let usage_uri = format!(
        "/o3k/v1/metering/usage?meter=compute:instance_seconds&start={}&end={}",
        rfc3339(start),
        rfc3339(end)
    );
    let usage_frozen_uri = format!("{usage_uri}&resource_id={server_b_id}");
    let usage_before = api.get(&usage_uri, Some(&alice_token)).await;
    assert_eq!(usage_before.status, 200, "{}", usage_before.body);
    assert_eq!(usage_before.json[0]["unit"], "instance_second");
    assert_eq!(
        usage_before.json[0]["meter_key"],
        "compute:instance_seconds"
    );
    // RFC3339 UTC instants: start/end/observed_through are always present;
    // authority_started_at is non-null once the metering authority exists
    // (it does in this journey).
    for field in ["start", "end", "observed_through"] {
        let text = usage_before.json[0][field].as_str().unwrap_or_default();
        assert!(
            text.ends_with('Z'),
            "{field} must be a non-null UTC instant: {text}"
        );
    }
    let authority_started_at = usage_before.json[0]["authority_started_at"]
        .as_str()
        .unwrap_or_default();
    assert!(
        authority_started_at.ends_with('Z'),
        "authority_started_at must be a non-null UTC instant once authority exists: {authority_started_at}"
    );
    // The evaluation watermark must not exceed the requested window end.
    let observed_through_ms = chrono::DateTime::parse_from_rfc3339(
        usage_before.json[0]["observed_through"]
            .as_str()
            .unwrap_or_default(),
    )
    .map(|instant| instant.timestamp_millis())
    .expect("observed_through parses");
    assert!(
        observed_through_ms <= end,
        "observed_through must not exceed the requested end: {observed_through_ms} vs {end}"
    );
    let frozen_before = api.get(&usage_frozen_uri, Some(&alice_token)).await;
    assert_eq!(frozen_before.status, 200, "{}", frozen_before.body);
    let total_before = frozen_before.json[0]["total"]
        .as_str()
        .expect("total")
        .to_owned();
    // A never-accruing meter would read "0.000" and make the restart
    // comparison vacuous: server B genuinely ran for real wall-clock seconds
    // in this journey, so the frozen total must be a finite positive decimal.
    let total_before_value: f64 = total_before.parse().expect("total is a decimal string");
    assert!(
        total_before_value.is_finite() && total_before_value > 0.0,
        "frozen compute:instance_seconds total must be positive: {total_before}"
    );
    // Cross-scope read denied for a tenant.
    let cross_scope = api
        .get(&format!("{usage_uri}&scope=project-b"), Some(&alice_token))
        .await;
    assert_eq!(cross_scope.status, 403, "{}", cross_scope.body);
    // System operator may select another scope.
    let operator_usage = api
        .get(
            &format!("{usage_uri}&scope=project-a"),
            Some(&operator_token),
        )
        .await;
    assert_eq!(operator_usage.status, 200, "{}", operator_usage.body);

    // 8. Governance.
    let governance_negative = api
        .get("/o3k/v1/operator/governance/projects", Some(&bob_token))
        .await;
    assert_eq!(
        governance_negative.status, 403,
        "{}",
        governance_negative.body
    );
    let projects = api
        .get(
            "/o3k/v1/operator/governance/projects",
            Some(&operator_token),
        )
        .await;
    assert_eq!(projects.status, 200, "{}", projects.body);
    let principals = api
        .get(
            "/o3k/v1/operator/governance/principals",
            Some(&operator_token),
        )
        .await;
    assert_eq!(principals.status, 200, "{}", principals.body);
    let roles = api
        .get("/o3k/v1/operator/governance/roles", Some(&operator_token))
        .await;
    assert_eq!(roles.status, 200, "{}", roles.body);
    let capabilities = api
        .get(
            "/o3k/v1/operator/governance/capabilities",
            Some(&operator_token),
        )
        .await;
    assert_eq!(capabilities.status, 200, "{}", capabilities.body);
    // Tenant A cannot grant itself operator.
    let self_grant = api
        .post(
            "/o3k/v1/operator/governance/operator-assignments",
            Some(&alice_token),
            json!({"principal_id": "user-a"}),
            None,
        )
        .await;
    assert_eq!(self_grant.status, 403, "{}", self_grant.body);

    // Grant bob membership in project-a, verify a refreshed AuthContext
    // reflects it, then revoke and verify it disappears.
    let member_role = roles.json["items"]
        .as_array()
        .and_then(|items| items.iter().find(|r| r["name"] == "member"))
        .and_then(|r| r["id"].as_str().map(str::to_owned))
        .expect("member role id");
    let grant = api
        .post(
            "/o3k/v1/operator/governance/assignments",
            Some(&operator_token),
            json!({"principal_id": "user-b", "project_id": "project-a", "role_id": member_role}),
            None,
        )
        .await;
    assert_eq!(grant.status, 200, "{}", grant.body);
    let grant_id = grant.json["id"].as_str().expect("assignment id").to_owned();
    let bob_in_a_after_grant = api
        .exchange(&required("O3K_P12_7_BOB_TOKEN"), Some("project-a"), false)
        .await;
    assert_eq!(
        bob_in_a_after_grant.status, 201,
        "{}",
        bob_in_a_after_grant.body
    );
    let revoke = api
        .delete(
            &format!("/o3k/v1/operator/governance/assignments/{grant_id}"),
            Some(&operator_token),
            None,
        )
        .await;
    assert_eq!(revoke.status, 204, "{}", revoke.body);
    let bob_in_a_after_revoke = api
        .exchange(&required("O3K_P12_7_BOB_TOKEN"), Some("project-a"), false)
        .await;
    assert_eq!(
        bob_in_a_after_revoke.status, 401,
        "{}",
        bob_in_a_after_revoke.body
    );

    // 9. Audit: durable records for creation/action/quota/governance + show.
    // Per-operation filtered queries are bounded and order-independent (a
    // shared store may hold many events, and the unfiltered page would be);
    // exactly one assertion pins the collection bound itself (malformed
    // cursor -> 400).
    let create_op = server_a.json["operation_id"]
        .as_str()
        .expect("create operation id")
        .to_owned();
    // The delete responses are 204 without a body, so the canonical delete
    // operation ids are recovered black-box from the durable audit records:
    // the resource-filtered query surfaces the DeleteServer event, which
    // carries its operation id.
    let delete_op = {
        let page = api
            .get(
                &format!("/o3k/v1/audit?resource_id={server_a_id}&limit=10"),
                Some(&alice_token),
            )
            .await;
        assert_eq!(page.status, 200, "{}", page.body);
        page.json["items"]
            .as_array()
            .and_then(|items| {
                items
                    .iter()
                    .find(|item| {
                        item["action"]["action"]
                            .as_str()
                            .is_some_and(|a| a.ends_with("DeleteServer"))
                    })
                    .and_then(|item| item["operation_id"].as_str().map(str::to_owned))
            })
            .expect("delete operation id for server A")
    };
    let delete_b_op_audit = {
        let page = api
            .get(
                &format!("/o3k/v1/audit?resource_id={server_b_id}&limit=10"),
                Some(&alice_token),
            )
            .await;
        assert_eq!(page.status, 200, "{}", page.body);
        page.json["items"]
            .as_array()
            .and_then(|items| {
                items
                    .iter()
                    .find(|item| {
                        item["action"]["action"]
                            .as_str()
                            .is_some_and(|a| a.ends_with("DeleteServer"))
                    })
                    .and_then(|item| item["operation_id"].as_str().map(str::to_owned))
            })
            .expect("delete operation id for server B")
    };
    let action_ops = [
        ("CreateServer", create_op.as_str()),
        ("StopServer", stop_op.as_str()),
        ("StartServer", start_op.as_str()),
        ("RebootServer", reboot_op.as_str()),
        ("DeleteServer", delete_op.as_str()),
    ];
    let mut audit_event_ids: Vec<String> = Vec::new();
    for (action, operation_id) in action_ops {
        let filtered = api
            .get(
                &format!("/o3k/v1/audit?operation_id={operation_id}&limit=10"),
                Some(&alice_token),
            )
            .await;
        assert_eq!(filtered.status, 200, "{}", filtered.body);
        let items = filtered.json["items"]
            .as_array()
            .cloned()
            .unwrap_or_default();
        assert!(
            items.iter().any(|item| item["action"]["action"]
                .as_str()
                .is_some_and(|a| a.ends_with(action))),
            "missing audit {action} for operation {operation_id}: {}",
            filtered.body
        );
        // Canonical actor/scope/target on the durable records.
        for item in &items {
            assert!(item["principal_id"].is_string(), "{item}");
            assert_eq!(item["effective_scope"]["id"], "project-a", "{item}");
            assert!(item["owner_scope"]["id"].is_string(), "{item}");
            assert!(item["resource_id"].is_string(), "{item}");
        }
        audit_event_ids.extend(
            items
                .iter()
                .filter_map(|item| item["event_id"].as_str().map(str::to_owned)),
        );
    }
    // The tenant collection itself stays bounded: malformed cursor rejected.
    let audit_bad_cursor = api
        .get(
            "/o3k/v1/audit?cursor=not-a-valid-cursor",
            Some(&alice_token),
        )
        .await;
    assert_eq!(audit_bad_cursor.status, 400, "{}", audit_bad_cursor.body);
    // Quota administration and governance mutations are audited in the
    // operator's system scope (the audit store is strictly per effective
    // scope, so the tenant projection can never show them). Per-service
    // filtered queries keep this deterministic on a shared store.
    for service in ["quota", "governance"] {
        let filtered = api
            .get(
                &format!("/o3k/v1/audit?service={service}&limit=10"),
                Some(&operator_token),
            )
            .await;
        assert_eq!(filtered.status, 200, "{}", filtered.body);
        assert!(
            filtered.json["items"]
                .as_array()
                .is_some_and(|items| !items.is_empty()),
            "no {service} audit in the operator scope: {}",
            filtered.body
        );
    }
    // Regression: the production composition router must expose /audit/{id}.
    let audit_show = api
        .get(
            &format!("/o3k/v1/audit/{}", audit_event_ids[0]),
            Some(&alice_token),
        )
        .await;
    assert_eq!(
        audit_show.status, 200,
        "production /o3k/v1/audit/{{id}} route: {}",
        audit_show.body
    );
    assert_eq!(
        audit_show.json["event_id"],
        Value::from(audit_event_ids[0].clone())
    );
    // Tenant scoping: bob's operation-filtered view of alice's operations is
    // empty of alice's events (no existence oracle).
    for (_, operation_id) in &action_ops {
        let bob_filtered = api
            .get(
                &format!("/o3k/v1/audit?operation_id={operation_id}&limit=10"),
                Some(&bob_token),
            )
            .await;
        assert_eq!(bob_filtered.status, 200, "{}", bob_filtered.body);
        let bob_items = bob_filtered.json["items"].as_array().unwrap_or_else(|| {
            panic!(
                "bob audit filter must be a well-formed array: {}",
                bob_filtered.body
            )
        });
        let leaked = bob_items.iter().any(|item| {
            item["event_id"]
                .as_str()
                .is_some_and(|id| audit_event_ids.contains(&id.to_owned()))
        });
        assert!(
            !leaked,
            "bob audit must not expose alice events: {}",
            bob_filtered.body
        );
    }

    // 10. Diagnostics.
    for path in [
        "/o3k/v1/operator/diagnostics",
        "/o3k/v1/operator/diagnostics/services",
        "/o3k/v1/operator/diagnostics/providers",
        "/o3k/v1/operator/diagnostics/capacity",
    ] {
        let response = api.get(path, Some(&operator_token)).await;
        assert_eq!(response.status, 200, "GET {path}: {}", response.body);
    }
    let diag = api
        .get("/o3k/v1/operator/diagnostics", Some(&operator_token))
        .await;
    assert_eq!(diag.json["version"], "v1", "{}", diag.body);
    assert!(
        HONEST_STATUS.contains(&diag.json["status"].as_str().unwrap_or_default()),
        "{}",
        diag.body
    );
    assert_eq!(diag.json["locations"]["configured"], true, "{}", diag.body);
    assert_eq!(diag.json["locations"]["regions"], 1, "{}", diag.body);
    assert_eq!(
        diag.json["locations"]["availability_domains"], 2,
        "{}",
        diag.body
    );
    let capacity = api
        .get(
            "/o3k/v1/operator/diagnostics/capacity",
            Some(&operator_token),
        )
        .await;
    // Capacity honesty (SPEC-0045): the fake-provider profile wires neither
    // the scheduler nor the agent inventory publisher (both are gated on
    // agent-control mTLS in the composition root), so there is NO capacity
    // authority to observe. The honest report for that profile is
    // unknown/never_observed with empty dimensions — pinned exactly, not
    // treated as optional. A profile WITH inventory must project all three
    // canonical classes; the two shapes are mutually exclusive, so a
    // healthy/empty or fabricated-class report can never pass.
    assert_eq!(capacity.json["version"], "v1", "{}", capacity.body);
    let cap_status = capacity.json["status"].as_str().unwrap_or_default();
    assert!(
        !cap_status.is_empty() && HONEST_STATUS.contains(&cap_status),
        "capacity must carry a non-empty honest status: {}",
        capacity.body
    );
    let dim_classes: Vec<&str> = capacity.json["dimensions"]
        .as_array()
        .map(|dims| {
            dims.iter()
                .filter_map(|dim| dim["resource_class"].as_str())
                .collect()
        })
        .unwrap_or_default();
    if dim_classes.is_empty() {
        assert_eq!(
            cap_status, "unknown",
            "empty capacity dimensions require the honest unknown status: {}",
            capacity.body
        );
        assert_eq!(
            capacity.json["reason"], "never_observed",
            "empty capacity dimensions require the never_observed reason: {}",
            capacity.body
        );
    } else {
        for class in ["VCPU", "MEMORY_MB", "DISK_GB"] {
            assert!(
                dim_classes.contains(&class),
                "capacity with observations must project the canonical {class} dimension: {}",
                capacity.body
            );
        }
    }
    for class in &dim_classes {
        assert!(
            ["VCPU", "MEMORY_MB", "DISK_GB"].contains(class),
            "only canonical capacity classes may be advertised: {class}"
        );
    }
    let tenant_diag = api
        .get("/o3k/v1/operator/diagnostics", Some(&alice_token))
        .await;
    assert_eq!(tenant_diag.status, 403, "{}", tenant_diag.body);

    // 12. Cross-tenant isolation matrix. The live-resource show/action probes
    // ran while server A was ACTIVE (above); this section covers the remaining
    // surfaces. Server B is deleted by now, so list/governance/metering probes
    // target collection-level concealment rather than a live instance.
    let bob_list = api.get("/o3k/v1/compute/servers", Some(&bob_token)).await;
    assert_eq!(bob_list.status, 200, "{}", bob_list.body);
    let bob_items = bob_list.json["items"]
        .as_array()
        .unwrap_or_else(|| panic!("bob list must be a well-formed array: {}", bob_list.body));
    let bob_ids: Vec<&str> = bob_items
        .iter()
        .filter_map(|i| i["metadata"]["id"].as_str())
        .collect();
    assert!(
        !bob_ids.contains(&server_b_id.as_str()),
        "{}",
        bob_list.body
    );
    let bob_network = api
        .get(
            &format!("/o3k/v1/network/networks/{network_id}"),
            Some(&bob_token),
        )
        .await;
    assert_eq!(bob_network.status, 404, "{}", bob_network.body);
    // Live-row list concealment: network A is still live at this point (the
    // show probe above just proved it exists), so a list surface leaking all
    // projects' networks would surface here — the compute list probe targets
    // a since-deleted server and cannot.
    let bob_net_list = api.get("/o3k/v1/network/networks", Some(&bob_token)).await;
    assert_eq!(bob_net_list.status, 200, "{}", bob_net_list.body);
    let bob_net_ids: Vec<&str> = bob_net_list.json["items"]
        .as_array()
        .unwrap_or_else(|| {
            panic!(
                "bob network list must be well-formed: {}",
                bob_net_list.body
            )
        })
        .iter()
        .filter_map(|i| i["metadata"]["id"].as_str())
        .collect();
    assert!(
        !bob_net_ids.contains(&network_id.as_str()),
        "{}",
        bob_net_list.body
    );
    let bob_op = api
        .get(&format!("/o3k/v1/operations/{stop_op}"), Some(&bob_token))
        .await;
    assert_eq!(bob_op.status, 404, "{}", bob_op.body);
    let bob_quota = api
        .get("/o3k/v1/operator/quotas/project-a", Some(&bob_token))
        .await;
    assert_eq!(bob_quota.status, 403, "{}", bob_quota.body);

    // 15. Bounded queries. Cursor probes target the operations collection,
    // which is guaranteed non-empty in this journey (independent of the
    // generic resource ledger's finalized tombstone rows).
    let ops_bad_cursor = api
        .get(
            "/o3k/v1/operations?limit=1&cursor=not-a-valid-cursor",
            Some(&alice_token),
        )
        .await;
    assert_eq!(ops_bad_cursor.status, 400, "{}", ops_bad_cursor.body);
    let ops_page = api
        .get("/o3k/v1/operations?limit=1", Some(&alice_token))
        .await;
    assert_eq!(ops_page.status, 200, "{}", ops_page.body);
    let ops_cursor = ops_page.json["next_cursor"]
        .as_str()
        .map(str::to_owned)
        .expect("operations continuation cursor");
    let bob_ops_reuse = api
        .get(
            &format!("/o3k/v1/operations?limit=1&cursor={ops_cursor}"),
            Some(&bob_token),
        )
        .await;
    assert_eq!(bob_ops_reuse.status, 400, "{}", bob_ops_reuse.body);
    let tampered_ops = api
        .get(
            &format!("/o3k/v1/operations?limit=1&cursor={ops_cursor}x"),
            Some(&alice_token),
        )
        .await;
    assert_eq!(tampered_ops.status, 400, "{}", tampered_ops.body);
    // Page-size bound per SPEC-0030 pagination: above MAX_PAGE_SIZE (200) is
    // rejected with 400, not clamped.
    let oversized_page = api
        .get("/o3k/v1/compute/servers?limit=500", Some(&alice_token))
        .await;
    assert_eq!(oversized_page.status, 400, "{}", oversized_page.body);
    // Metering alignment contract: an unaligned start instant is rejected
    // with 400 rather than silently repaired.
    let unaligned_usage = api
        .get(
            &format!(
                "/o3k/v1/metering/usage?meter=compute:instance_seconds&start={}&end={}",
                rfc3339(start + 1),
                rfc3339(end)
            ),
            Some(&alice_token),
        )
        .await;
    assert_eq!(unaligned_usage.status, 400, "{}", unaligned_usage.body);

    // 13. Secret scan over every retained response body.
    let mut secrets: Vec<(&str, String)> = vec![
        ("bootstrap password", required("O3K_P12_7_BOOTSTRAP_SECRET")),
        ("token signing key", SIGNING_KEY.to_owned()),
        ("native cursor signing key", CURSOR_KEY.to_owned()),
        ("alice access token", required("O3K_P12_7_ALICE_TOKEN")),
        ("bob access token", required("O3K_P12_7_BOB_TOKEN")),
        (
            "operator access token",
            required("O3K_P12_7_OPERATOR_TOKEN"),
        ),
        ("unbound access token", required("O3K_P12_7_UNBOUND_TOKEN")),
    ];
    // When PostgreSQL is the durable backend, its DSN password is a secret
    // the process holds; it must never surface in any response or log.
    if let Ok(url) = std::env::var("O3K_DATABASE_URL")
        && let Some(password) = url
            .split("://")
            .nth(1)
            .and_then(|authority| authority.rsplit('@').next())
            .and_then(|userinfo| userinfo.split(':').nth(1))
    {
        secrets.push(("database password", password.to_owned()));
    }
    for (label, secret) in &secrets {
        for body in &api.bodies {
            assert!(
                !body.contains(secret),
                "secret scan failed ({label}) leaked into a response body: {body}"
            );
        }
    }
    for body in &api.bodies {
        assert!(
            !body.contains("-----BEGIN"),
            "private-key marker leaked: {body}"
        );
        assert!(!body.contains("postgres://"), "DB URL leaked: {body}");
        assert!(
            !body.contains("agent_epoch"),
            "agent epoch internals leaked: {body}"
        );
    }
    // The o3kd process logs are part of the evidence surface: no secret or
    // DSN marker may appear there (both generations, appended to one file).
    scan_o3kd_log(&data_dir, &secrets);

    // ── Phase 2: SIGTERM, restart against the same durable store ──────────
    drop(api);
    child.terminate().await;

    let port2 = ephemeral_port();
    let base2 = format!("http://{LISTEN}:{port2}");
    let child2 = O3kdGuard::spawn(port2, &data_dir, &backend);
    wait_healthy(&base2, &data_dir.join("o3kd.log")).await;
    let mut api2 = Api::new(base2.clone());

    // Re-issue tokens on the restarted process.
    let alice2 = api2
        .exchange(&required("O3K_P12_7_ALICE_TOKEN"), Some("project-a"), false)
        .await;
    assert_eq!(alice2.status, 201, "{}", alice2.body);
    let alice_token2 = get_token(&alice2);
    let operator2 = api2
        .exchange(&required("O3K_P12_7_OPERATOR_TOKEN"), None, true)
        .await;
    assert_eq!(operator2.status, 201, "{}", operator2.body);
    let operator_token2 = get_token(&operator2);

    // 14. Re-verify durable state: every operation id collected pre-restart
    // is still show-able, audit events survive by exact event id, the quota
    // limit AND freed usage persist, metering totals are unchanged (and still
    // positive), and diagnostics return honest status.
    let networks2 = api2
        .get("/o3k/v1/network/networks", Some(&alice_token2))
        .await;
    assert_eq!(networks2.status, 200, "{}", networks2.body);
    let net_ids: Vec<&str> = networks2.json["items"]
        .as_array()
        .map(|items| {
            items
                .iter()
                .filter_map(|i| i["metadata"]["id"].as_str())
                .collect()
        })
        .unwrap_or_default();
    assert!(
        net_ids.contains(&network_id.as_str()),
        "network not preserved: {}",
        networks2.body
    );

    let collected_ops = [
        ("create", create_op.as_str()),
        ("stop", stop_op.as_str()),
        ("start", start_op.as_str()),
        ("reboot", reboot_op.as_str()),
        ("delete", delete_op.as_str()),
        ("create-b", server_b_op.as_str()),
        ("delete-b", delete_b_op_audit.as_str()),
    ];
    for (label, operation_id) in collected_ops {
        let shown = api2
            .get(
                &format!("/o3k/v1/operations/{operation_id}"),
                Some(&alice_token2),
            )
            .await;
        assert_eq!(
            shown.status, 200,
            "operation {label} ({operation_id}) must survive restart: {}",
            shown.body
        );
        assert_eq!(
            shown.json["id"],
            Value::from(operation_id),
            "{}",
            shown.body
        );
    }

    let quota2 = api2
        .get("/o3k/v1/operator/quotas/project-a", Some(&operator_token2))
        .await;
    assert_eq!(quota2.status, 200, "{}", quota2.body);
    assert!(
        quota2.json["items"]
            .as_array()
            .and_then(|items| {
                items
                    .iter()
                    .find(|i| i["namespace"] == "compute" && i["key"] == "servers")
            })
            .and_then(|i| i["limit"]["value"].as_u64())
            == Some(limit),
        "quota limit not preserved: {}",
        quota2.body
    );
    // The freed slot is still free after restart: usage is back to the
    // pre-journey baseline, not just the limit.
    let quota2_usage = api2
        .get("/o3k/v1/quota/compute/servers", Some(&alice_token2))
        .await;
    assert_eq!(quota2_usage.status, 200, "{}", quota2_usage.body);
    assert_eq!(
        quota2_usage.json["usage"], initial_usage,
        "quota usage not preserved across restart: {}",
        quota2_usage.body
    );

    // Governance revocation persisted: bob still cannot enter project-a.
    let bob_in_a2 = api2
        .exchange(&required("O3K_P12_7_BOB_TOKEN"), Some("project-a"), false)
        .await;
    assert_eq!(bob_in_a2.status, 401, "{}", bob_in_a2.body);

    // Audit: the exact pre-restart event ids for the server actions survive.
    let mut surviving_events = 0_usize;
    for (_, operation_id) in &collected_ops[..5] {
        let filtered = api2
            .get(
                &format!("/o3k/v1/audit?operation_id={operation_id}&limit=10"),
                Some(&alice_token2),
            )
            .await;
        assert_eq!(filtered.status, 200, "{}", filtered.body);
        let post_ids: Vec<String> = filtered.json["items"]
            .as_array()
            .map(|items| {
                items
                    .iter()
                    .filter_map(|item| item["event_id"].as_str().map(str::to_owned))
                    .collect()
            })
            .unwrap_or_default();
        for event_id in &audit_event_ids {
            if post_ids.contains(event_id) {
                surviving_events += 1;
            }
        }
    }
    assert_eq!(
        surviving_events,
        audit_event_ids.len(),
        "every pre-restart server-action audit event must survive restart"
    );

    let usage2 = api2.get(&usage_uri, Some(&alice_token2)).await;
    assert_eq!(usage2.status, 200, "{}", usage2.body);
    assert_eq!(usage2.json[0]["unit"], "instance_second");
    assert_eq!(usage2.json[0]["meter_key"], "compute:instance_seconds");
    let frozen2 = api2.get(&usage_frozen_uri, Some(&alice_token2)).await;
    assert_eq!(frozen2.status, 200, "{}", frozen2.body);
    let total_after = frozen2.json[0]["total"].as_str().expect("total").to_owned();
    assert_eq!(
        total_after, total_before,
        "metering totals must not double-fold across restart: {total_before} vs {total_after}"
    );
    let total_after_value: f64 = total_after.parse().expect("total is a decimal string");
    assert!(
        total_after_value.is_finite() && total_after_value > 0.0,
        "frozen compute:instance_seconds total must stay positive across restart: {total_after}"
    );

    let diag2 = api2
        .get("/o3k/v1/operator/diagnostics", Some(&operator_token2))
        .await;
    assert_eq!(diag2.status, 200, "{}", diag2.body);
    assert!(
        HONEST_STATUS.contains(&diag2.json["status"].as_str().unwrap_or_default()),
        "honest diagnostics post-restart: {}",
        diag2.body
    );

    for (label, secret) in &secrets {
        for body in &api2.bodies {
            assert!(
                !body.contains(secret),
                "secret scan after restart ({label}) leaked: {body}"
            );
        }
    }
    // Final log scan: both process generations accumulated in the same file.
    scan_o3kd_log(&data_dir, &secrets);

    child2.terminate().await;
    std::fs::remove_dir_all(&data_dir).ok();

    println!("ISSUE #907 Araf P2 northbound convergence: PASS");
    Ok(())
}

/// Regression test for a genuine product defect the gate discovered: the
/// production `o3k_api::router_with_state` mounted `/o3k/v1/audit` but not
/// `/o3k/v1/audit/{id}`, even though the native audit API implements the
/// per-event show surface (SPEC-0042 store parity lists "show" as a required
/// capability, and `o3k_native_api::router` has always registered it). This
/// test drives the real production composition router and proves the route is
/// now reachable end-to-end without the real-infra gate.
#[tokio::test]
async fn production_router_exposes_audit_show_route() -> Result<(), Box<dyn std::error::Error>> {
    use o3k_kernel::{
        ActionId, AuditEvent, AuditOutcome, AuthContext, OwnershipScope, Principal, PrincipalId,
        ScopeId, ScopeKind, ServiceNamespace, UserPrincipal,
    };
    use o3k_native_api::{
        NativeApiState,
        audit::{AuditReadError, AuditReader},
        auth::TokenIssuer,
    };

    #[derive(Clone)]
    struct Issuer(AuthContext);

    #[async_trait::async_trait]
    impl TokenIssuer for Issuer {
        async fn issue_native(
            &self,
            _request: &o3k_native_api::auth::NativeTokenRequestV1,
        ) -> Result<(String, Value), o3k_native_api::error::ProblemDetails> {
            Err(o3k_native_api::error::ProblemDetails::unauthorized())
        }
        async fn auth_context(
            &self,
            _token: &str,
        ) -> Result<AuthContext, o3k_native_api::error::ProblemDetails> {
            Ok(self.0.clone())
        }
    }

    #[derive(Clone)]
    struct Reader(AuditEvent);

    #[async_trait::async_trait]
    impl AuditReader for Reader {
        async fn list_page(
            &self,
            _auth: &AuthContext,
            _query: o3k_kernel::AuditQuery,
        ) -> Result<o3k_native_api::pagination::RepositoryPage<AuditEvent>, AuditReadError>
        {
            Err(AuditReadError::Unavailable)
        }
        async fn show(&self, _auth: &AuthContext, _id: &str) -> Result<AuditEvent, AuditReadError> {
            Ok(self.0.clone())
        }
    }

    let auth = AuthContext::new(
        Principal::User(UserPrincipal::new(
            PrincipalId::new_unchecked("operator-1"),
            "operator",
            None,
        )),
        OwnershipScope::new(
            ScopeId::new_unchecked("project-a"),
            ScopeKind::Project,
            None,
            None,
        ),
        vec!["member".to_owned()],
        1,
        2,
        "audit-test",
        "request-test",
        None,
    );
    let event = AuditEvent::from_auth(
        &auth,
        ServiceNamespace::new_unchecked("compute".to_owned()),
        ActionId::new_unchecked("compute", "CreateServer"),
        AuditOutcome::Succeeded,
    );
    let event_id = event.event_id.as_str().to_owned();

    let issuer = std::sync::Arc::new(Issuer(auth.clone()));
    let reader = std::sync::Arc::new(Reader(event));
    let cursor = o3k_native_api::pagination::CursorConfig::new(vec![7; 32])?;
    let native = NativeApiState::new(None, cursor, Some(issuer), None, None, None)?
        .with_audit_reader(reader);

    let app = o3k_api::router_with_state(o3k_api::AppState::new().with_native_api(native));
    let response = tower::ServiceExt::oneshot(
        app,
        axum::http::Request::builder()
            .uri(format!("/o3k/v1/audit/{event_id}"))
            .header("authorization", "Bearer test-token")
            .body(axum::body::Body::empty())?,
    )
    .await?;
    assert_eq!(response.status(), axum::http::StatusCode::OK);
    let bytes = axum::body::to_bytes(response.into_body(), 64 * 1024).await?;
    let value: Value = serde_json::from_slice(&bytes)?;
    assert_eq!(value["event_id"], Value::from(event_id.clone()), "{value}");
    Ok(())
}
