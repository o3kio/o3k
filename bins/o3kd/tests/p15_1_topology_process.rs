//! ISSUE #931 — P15.1 production-composition convergence (real-process half).
//!
//! Real-process evidence that canonical topology converges through a REAL
//! `o3kd` subprocess (via `CARGO_BIN_EXE_o3kd`) on a durable store, survives
//! restart, and projects into the Keystone catalog from canonical state rather
//! than the hard-coded `RegionOne` default.
//!
//! # Evidence boundary (recorded in SPEC-0047 §4.1)
//!
//! `topology:ManageTopology` is a system-scope operator action. In a real
//! deployment the bearer that satisfies it is a federated (OIDC) system token;
//! a password grant only ever yields a project-scoped token (see
//! `TokenService::issue` / the native `TokenIssuerAdapter`). There is no
//! offline, non-OIDC path to a System-scoped operator token, so operator-
//! authenticated topology CRUD cannot be exercised against a real offline
//! subprocess. This file therefore proves what an offline real process CAN
//! honestly show with real Keystone password auth:
//!
//!   * durable region/AZ convergence from `O3K_LOCATIONS`;
//!   * the derived Keystone catalog region (canonical when exactly one region
//!     is configured, else `RegionOne` — asserted both directions so the
//!     derivation is proven, not coincidence);
//!   * durable reconstruction of failure-domain hierarchy + bindings seeded
//!     directly into the real `TopologyStore` (the store is the authority; no
//!     env-only reconstruction);
//!   * restart survival of every id, link, class, name, metadata, binding and
//!     region/AZ, and a repeat restart that does not duplicate state;
//!   * the real authorization boundary: a project-scoped token gets 403 on any
//!     topology mutation while reads succeed.
//!
//! Operator-authenticated CRUD is proven in-process against the production
//! router + the accepted `TokenIssuer` in `p15_1_topology_operator.rs`.
//!
//! Runs for real, NOT `#[ignore]`: the SQLite pass always runs; the PostgreSQL
//! pass runs when `O3K_DATABASE_URL` is set, using a disposable per-run
//! database provisioned from its admin URL (mirrors the store tests), so the
//! shared database and repeated local runs are never affected.
#![allow(clippy::expect_used, clippy::panic)]

use o3k_kernel::{
    BindingTarget, BindingTargetKind, FailureDomain, FailureDomainClass, TopologyBinding,
    TopologyStore,
};
use o3k_store::unified::O3kStore;
use serde_json::{Value, json};
use sqlx::postgres::PgPoolOptions;
use std::{
    collections::BTreeMap,
    net::TcpListener,
    path::{Path, PathBuf},
    process::{Child, Command},
    time::{Duration, Instant},
};

const LISTEN: &str = "127.0.0.1";
const SIGNING_KEY: &str = "p15-1-token-signing-key-0123456789abcdef";
const CURSOR_KEY: &str = "p15-1-native-cursor-signing-key-0123456789abcdef";
const BOOTSTRAP_PASSWORD: &str = "p15-1-bootstrap-password-not-a-secret";
/// Canonical single-region declaration converged into the store (SPEC-0047).
const LOCATIONS: &str = r#"[{"id":"region-a","availability_domains":[{"id":"az-1"}]}]"#;

type TestResult = Result<(), Box<dyn std::error::Error>>;

enum Backend {
    Postgres(String),
    Sqlite(PathBuf),
}

/// A disposable PostgreSQL database so the PostgreSQL pass never touches the
/// shared `O3K_DATABASE_URL` database directly (mirrors
/// `crates/o3k-store/tests/postgres_topology.rs`). The database name embeds a
/// UUID, so repeated local runs never collide with leftover state.
struct PgFixture {
    admin_url: String,
    database: String,
    url: String,
}

impl PgFixture {
    async fn new() -> Result<Self, Box<dyn std::error::Error>> {
        let url = std::env::var("O3K_DATABASE_URL")?;
        let parsed = url::Url::parse(&url)?;
        let database = format!("o3k_p15_1_topology_{}", uuid::Uuid::now_v7().simple());
        let mut base = parsed.clone();
        base.set_path("/postgres");
        let admin_url = base.to_string();
        let admin = PgPoolOptions::new()
            .max_connections(1)
            .connect(&admin_url)
            .await?;
        sqlx::query(&format!("CREATE DATABASE {database}"))
            .execute(&admin)
            .await?;
        // Close the creator session before any store connects, so the admin
        // connection can never be the lingering backend that blocks the drop.
        admin.close().await;
        let mut isolated = parsed;
        isolated.set_path(&format!("/{database}"));
        Ok(Self {
            admin_url,
            database,
            url: isolated.to_string(),
        })
    }

    /// Drops the disposable database with the established robust teardown:
    /// terminate any leftover backends, then `DROP DATABASE ... WITH (FORCE)`
    /// with a bounded retry. Every `o3kd` subprocess has been SIGTERM'd and
    /// reaped before this is called.
    async fn dispose(self) {
        let admin = PgPoolOptions::new()
            .max_connections(1)
            .connect(&self.admin_url)
            .await
            .expect("connect admin to dispose disposable db");
        let _ = sqlx::query(
            "SELECT pg_terminate_backend(pid) FROM pg_stat_activity \
             WHERE datname = $1 AND pid <> pg_backend_pid()",
        )
        .bind(&self.database)
        .execute(&admin)
        .await;
        let mut last_error: Option<sqlx::Error> = None;
        for attempt in 0..5u64 {
            match sqlx::query(&format!("DROP DATABASE {} WITH (FORCE)", self.database))
                .execute(&admin)
                .await
            {
                Ok(_) => {
                    admin.close().await;
                    return;
                }
                Err(error) => {
                    last_error = Some(error);
                    tokio::time::sleep(Duration::from_millis(100 * (attempt + 1))).await;
                }
            }
        }
        admin.close().await;
        panic!(
            "failed to drop disposable database {} after retries: {last_error:?}",
            self.database
        );
    }
}

fn sqlite_backend(path: PathBuf) -> Backend {
    Backend::Sqlite(path)
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

/// Spawns a real `o3kd` subprocess. `locations == None` omits `O3K_LOCATIONS`
/// (no canonical topology declared -> RegionOne catalog fallback).
fn spawn_o3kd(port: u16, data_dir: &Path, backend: &Backend, locations: Option<&str>) -> Child {
    let mut envs: Vec<(String, String)> = vec![
        ("O3K_LISTEN_ADDR".to_owned(), format!("{LISTEN}:{port}")),
        ("O3K_DATA_DIR".to_owned(), data_dir.display().to_string()),
        ("O3K_PROVIDER".to_owned(), "fake".to_owned()),
        (
            "O3K_BOOTSTRAP_PASSWORD".to_owned(),
            BOOTSTRAP_PASSWORD.to_owned(),
        ),
        ("O3K_TOKEN_SIGNING_KEY".to_owned(), SIGNING_KEY.to_owned()),
        (
            "O3K_NATIVE_CURSOR_HMAC_KEY".to_owned(),
            CURSOR_KEY.to_owned(),
        ),
        ("O3K_LOG_FILTER".to_owned(), "info".to_owned()),
    ];
    if let Some(locations) = locations {
        envs.push(("O3K_LOCATIONS".to_owned(), locations.to_owned()));
    }
    if let Backend::Postgres(url) = backend {
        envs.push(("O3K_DATABASE_BACKEND".to_owned(), "postgres".to_owned()));
        envs.push(("O3K_DATABASE_URL".to_owned(), url.clone()));
    } else {
        envs.push(("O3K_DATABASE_BACKEND".to_owned(), "sqlite".to_owned()));
    }
    let mut command = Command::new(env!("CARGO_BIN_EXE_o3kd"));
    let log_path = data_dir.join("o3kd.log");
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

async fn wait_healthy(base: &str, log_path: &Path) {
    let client = reqwest::Client::new();
    let deadline = Instant::now() + Duration::from_secs(60);
    loop {
        if let Ok(response) = client.get(format!("{base}/healthz")).send().await
            && response.status().is_success()
        {
            return;
        }
        if Instant::now() >= deadline {
            let tail = std::fs::read(log_path)
                .map(|bytes| {
                    let start = bytes.len().saturating_sub(8192);
                    String::from_utf8_lossy(&bytes[start..]).into_owned()
                })
                .unwrap_or_else(|_| "<o3kd log unreadable>".to_owned());
            panic!("o3kd did not become healthy at {base}; o3kd log tail:\n{tail}");
        }
        tokio::time::sleep(Duration::from_millis(250)).await
    }
}

/// Owns a spawned `o3kd` child so a panicking assertion mid-journey cannot
/// orphan the real process (and its loopback socket): terminate + reap on drop.
struct O3kdGuard {
    child: Option<Child>,
    log_path: std::path::PathBuf,
}

impl O3kdGuard {
    fn spawn(port: u16, data_dir: &Path, backend: &Backend, locations: Option<&str>) -> Self {
        Self {
            child: Some(spawn_o3kd(port, data_dir, backend, locations)),
            log_path: data_dir.join("o3kd.log"),
        }
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

/// Sends SIGTERM and waits for a clean exit.
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
        tokio::time::sleep(Duration::from_millis(50)).await
    }
}

/// Terminates a running guard's child cleanly, taking ownership out of the
/// guard so the guard's Drop does not double-act.
async fn terminate_guard(child: &mut Option<Child>) {
    let mut child = child.take().expect("o3kd child present");
    terminate(&mut child).await;
}

struct Api {
    base: String,
    client: reqwest::Client,
}

impl Api {
    fn new(base: String) -> Self {
        Self {
            base,
            client: reqwest::Client::new(),
        }
    }

    async fn get(&self, path: &str, token: Option<&str>) -> (reqwest::StatusCode, Value) {
        let mut request = self
            .client
            .get(format!("{}{}", self.base, path))
            .header("accept", "application/json");
        if let Some(token) = token {
            request = request.bearer_auth(token);
        }
        self.send(request).await
    }

    async fn post(
        &self,
        path: &str,
        token: Option<&str>,
        body: Value,
    ) -> (reqwest::StatusCode, Value) {
        let mut request = self
            .client
            .post(format!("{}{}", self.base, path))
            .header("accept", "application/json")
            .header("content-type", "application/json");
        if let Some(token) = token {
            request = request.bearer_auth(token);
        }
        self.send(request.json(&body)).await
    }

    async fn put(&self, path: &str, token: Option<&str>) -> (reqwest::StatusCode, Value) {
        let mut request = self
            .client
            .put(format!("{}{}", self.base, path))
            .header("accept", "application/json");
        if let Some(token) = token {
            request = request.bearer_auth(token);
        }
        self.send(request).await
    }

    async fn send(&self, request: reqwest::RequestBuilder) -> (reqwest::StatusCode, Value) {
        let response = request.send().await.expect("http request");
        let status = response.status();
        let body = response.text().await.expect("response text");
        (status, serde_json::from_str(&body).unwrap_or(Value::Null))
    }

    /// Keystone-compatible password grant for the bootstrap `admin` user scoped
    /// to a project; returns `(x-subject-token, response body)`.
    async fn admin_token(&self, project: &str) -> (String, Value) {
        let url = format!("{}/v3/auth/tokens", self.base);
        let payload = json!({
            "auth": {
                "identity": {
                    "methods": ["password"],
                    "password": {"user": {"name": "admin", "password": BOOTSTRAP_PASSWORD}}
                },
                "scope": {"project": {"name": project}}
            }
        });
        let response = self
            .client
            .post(url)
            .header("accept", "application/json")
            .header("content-type", "application/json")
            .json(&payload)
            .send()
            .await
            .expect("keystone grant");
        let status = response.status();
        let token = response
            .headers()
            .get("x-subject-token")
            .and_then(|value| value.to_str().ok())
            .map(str::to_owned);
        let body = response.text().await.unwrap_or_default();
        let value: Value = serde_json::from_str(&body).unwrap_or(Value::Null);
        assert_eq!(
            status,
            reqwest::StatusCode::CREATED,
            "admin password grant failed: {status}: {body}"
        );
        (token.expect("x-subject-token header"), value)
    }

    /// All distinct `region` values across every catalog endpoint.
    fn catalog_regions(&self, token_body: &Value) -> Vec<String> {
        let mut regions: Vec<String> = token_body["token"]["catalog"]
            .as_array()
            .map(|services| {
                services
                    .iter()
                    .filter_map(|service| service["endpoints"].as_array())
                    .flatten()
                    .filter_map(|endpoint| endpoint["region"].as_str().map(str::to_owned))
                    .collect()
            })
            .unwrap_or_default();
        regions.sort();
        regions.dedup();
        regions
    }
}

/// Seeds the real durable `TopologyStore` (the same store the daemon opens)
/// with region-b + az-b + a nested failure-domain hierarchy under az-1 and a
/// resource-provider binding. This is environment setup through the canonical
/// durable authority — not a mutation through the HTTP boundary (there is no
/// offline system-operator token; see module docs).
async fn seed_store(backend: &Backend) -> TestResult {
    let store = open_store(backend).await?;
    // Parent-before-child ordering so store-level FK referential integrity
    // (a parent row must exist) is satisfied.
    let domains = [
        FailureDomain {
            id: "site-1".to_owned(),
            class: FailureDomainClass::Site,
            name: "Site One".to_owned(),
            availability_domain: "az-1".to_owned(),
            parent: None,
            generation: 1,
            metadata: BTreeMap::from([("tier".to_owned(), "edge".to_owned())]),
        },
        FailureDomain {
            id: "rack-1".to_owned(),
            class: FailureDomainClass::Rack,
            name: "Rack One".to_owned(),
            availability_domain: "az-1".to_owned(),
            parent: Some("site-1".to_owned()),
            generation: 1,
            metadata: BTreeMap::new(),
        },
        FailureDomain {
            id: "power-domain-1".to_owned(),
            class: FailureDomainClass::PowerDomain,
            name: "Power Domain One".to_owned(),
            availability_domain: "az-1".to_owned(),
            parent: Some("rack-1".to_owned()),
            generation: 1,
            metadata: BTreeMap::from([("voltage".to_owned(), "480v".to_owned())]),
        },
    ];
    store.insert_region("region-b", None).await?;
    store
        .insert_availability_domain("region-b", "az-b", None)
        .await?;
    for domain in &domains {
        store.insert_failure_domain(domain, None).await?;
    }
    store
        .insert_binding(
            &TopologyBinding {
                failure_domain: "rack-1".to_owned(),
                target: BindingTarget {
                    kind: BindingTargetKind::ResourceProvider,
                    id: "rp-1".to_owned(),
                },
            },
            None,
        )
        .await?;
    Ok(())
}

/// Asserts `GET /o3k/v1/regions` contains the expected region/AZ pairs.
async fn assert_regions(api: &Api, expected: &[(&str, &[&str])]) {
    let (status, body) = api.get("/o3k/v1/regions", None).await;
    assert_eq!(status, reqwest::StatusCode::OK, "regions: {body}");
    let regions = body["regions"].as_array().expect("regions array");
    for (region_id, azs) in expected {
        let region = regions
            .iter()
            .find(|r| r["id"].as_str() == Some(*region_id))
            .unwrap_or_else(|| panic!("missing region {region_id}: {body}"));
        for az in *azs {
            assert!(
                region["availability_domains"]
                    .as_array()
                    .is_some_and(|items| items.iter().any(|a| a["id"].as_str() == Some(*az))),
                "region {region_id} missing az {az}: {region}"
            );
        }
    }
}

/// Asserts every catalog endpoint advertises exactly `expected`.
fn assert_catalog_region(api: &Api, token_body: &Value, expected: &str) {
    let regions = api.catalog_regions(token_body);
    assert!(
        !regions.is_empty(),
        "catalog must advertise endpoints: {token_body}"
    );
    assert_eq!(
        regions,
        vec![expected.to_owned()],
        "catalog region must be derived from canonical topology ({expected}), not hard-coded"
    );
}

/// Fetches one failure-domain detail document by id.
async fn failure_domain(api: &Api, token: &str, id: &str) -> (reqwest::StatusCode, Value) {
    api.get(
        &format!("/o3k/v1/topology/failure-domains/{id}"),
        Some(token),
    )
    .await
}

/// Asserts a failure-domain document carries the exact identity/hierarchy.
fn assert_fd_doc(doc: &Value, id: &str, class: &str, parent: Option<&str>, name: &str) {
    assert_eq!(doc["id"], Value::from(id), "{doc}");
    assert_eq!(doc["class"], Value::from(class), "{doc}");
    assert_eq!(doc["name"], Value::from(name), "{doc}");
    assert_eq!(doc["availability_domain"], Value::from("az-1"), "{doc}");
    match parent {
        Some(p) => assert_eq!(doc["parent"], Value::from(p), "{doc}"),
        None => assert!(
            doc.get("parent").is_none() || doc["parent"].is_null(),
            "{doc}"
        ),
    }
    assert_eq!(doc["generation"], Value::from(1), "{doc}");
}

/// Proves a project-scoped token hits the real authorization boundary: 403 on
/// every mutation route, while reads succeed.
async fn assert_project_token_authorization_boundary(api: &Api, token: &str) {
    // Reads succeed for an authenticated principal (ReadTopology is open).
    let (status, list) = api
        .get("/o3k/v1/topology/failure-domains", Some(token))
        .await;
    assert_eq!(
        status,
        reqwest::StatusCode::OK,
        "authenticated read must succeed: {list}"
    );

    // Mutations require the system-scope operator identity (ManageTopology).
    let (status, _) = api
        .post(
            "/o3k/v1/topology/failure-domains",
            Some(token),
            json!({"id":"unauthorized-fd","class":"site","name":"nope","availability_domain":"az-1"}),
        )
        .await;
    assert_eq!(
        status,
        reqwest::StatusCode::FORBIDDEN,
        "project token must be 403 on fd create"
    );
    let (status, _) = api.put("/o3k/v1/regions/region-c", Some(token)).await;
    assert_eq!(
        status,
        reqwest::StatusCode::FORBIDDEN,
        "project token must be 403 on region declare"
    );
}

async fn run_process_journey(backend: &Backend, data_dir: &Path) -> TestResult {
    // ── Boot A: fresh store, single canonical region ─────────────────────
    let port = ephemeral_port();
    let base = format!("http://{LISTEN}:{port}");
    let mut guard_a = O3kdGuard::spawn(port, data_dir, backend, Some(LOCATIONS));
    wait_healthy(&base, &guard_a.log_path).await;
    let api = Api::new(base.clone());

    let (admin_token, token_meta) = api.admin_token("admin").await;
    assert_eq!(token_meta["token"]["project"]["name"], "admin");

    // 1. Canonical region converged from O3K_LOCATIONS.
    assert_regions(&api, &[("region-a", &["az-1"])]).await;

    // 2. Keystone catalog region derived from the single canonical region.
    assert_catalog_region(&api, &token_meta, "region-a");

    // 3. Real authorization boundary with a real password-grant token.
    assert_project_token_authorization_boundary(&api, &admin_token).await;

    terminate_guard(&mut guard_a.child).await;

    // 4. Fail-before value: with NO O3K_LOCATIONS the derived catalog region
    //    falls back to RegionOne. This boot always uses a fresh hermetic
    //    SQLite file (independent of the main backend) so it can never leak
    //    another run's converged regions into the "no topology" case.
    let fb_dir = data_dir.join("no-locations");
    std::fs::create_dir_all(&fb_dir)?;
    let fb_backend = sqlite_backend(fb_dir.join("o3k.sqlite"));
    let fb_port = ephemeral_port();
    let fb_base = format!("http://{LISTEN}:{fb_port}");
    let mut fb_guard = O3kdGuard::spawn(fb_port, &fb_dir, &fb_backend, None);
    wait_healthy(&fb_base, &fb_guard.log_path).await;
    let fb_api = Api::new(fb_base.clone());
    let (_, fb_meta) = fb_api.admin_token("admin").await;
    assert_catalog_region(&fb_api, &fb_meta, "RegionOne");
    let (_, regions) = fb_api.get("/o3k/v1/regions", None).await;
    assert_eq!(
        regions["count"], 0,
        "no locations => empty regions: {regions}"
    );
    terminate_guard(&mut fb_guard.child).await;
    let _ = std::fs::remove_dir_all(&fb_dir);

    // ── Seed durable topology directly through the real TopologyStore ────
    seed_store(backend).await?;

    // ── Boot B: same store + same O3K_LOCATIONS; durable reconstruction ──
    let port2 = ephemeral_port();
    let base2 = format!("http://{LISTEN}:{port2}");
    let mut guard_b = O3kdGuard::spawn(port2, data_dir, backend, Some(LOCATIONS));
    wait_healthy(&base2, &guard_b.log_path).await;
    let api2 = Api::new(base2.clone());
    let (admin_token2, _) = api2.admin_token("admin").await;

    // The store is the authority: region-b/az-b (seeded, NOT in O3K_LOCATIONS)
    // are reconstructed alongside region-a/az-1.
    assert_regions(&api2, &[("region-a", &["az-1"]), ("region-b", &["az-b"])]).await;

    let (status, list) = api2
        .get("/o3k/v1/topology/failure-domains", Some(&admin_token2))
        .await;
    assert_eq!(status, reqwest::StatusCode::OK, "fd list: {list}");
    let ids: Vec<String> = list["items"]
        .as_array()
        .map(|items| {
            items
                .iter()
                .filter_map(|item| item["id"].as_str().map(str::to_owned))
                .collect()
        })
        .unwrap_or_default();
    for wanted in ["site-1", "rack-1", "power-domain-1"] {
        assert!(
            ids.iter().any(|id| id == wanted),
            "missing fd {wanted}: {list}"
        );
    }

    for (id, class, parent, name) in [
        ("site-1", "site", None, "Site One"),
        ("rack-1", "rack", Some("site-1"), "Rack One"),
        (
            "power-domain-1",
            "power-domain",
            Some("rack-1"),
            "Power Domain One",
        ),
    ] {
        let (status, doc) = failure_domain(&api2, &admin_token2, id).await;
        assert_eq!(status, reqwest::StatusCode::OK, "show {id}: {doc}");
        assert_fd_doc(&doc, id, class, parent, name);
    }
    let (_, site) = failure_domain(&api2, &admin_token2, "site-1").await;
    assert_eq!(site["metadata"]["tier"], "edge", "{site}");
    let (_, pd) = failure_domain(&api2, &admin_token2, "power-domain-1").await;
    assert_eq!(pd["metadata"]["voltage"], "480v", "{pd}");

    // The binding is reported through the real API.
    let (status, bindings) = api2
        .get(
            "/o3k/v1/topology/failure-domains/rack-1/bindings",
            Some(&admin_token2),
        )
        .await;
    assert_eq!(status, reqwest::StatusCode::OK, "bindings: {bindings}");
    assert_eq!(bindings["items"][0]["failure_domain"], "rack-1");
    assert_eq!(bindings["items"][0]["target"]["kind"], "resource-provider");
    assert_eq!(bindings["items"][0]["target"]["id"], "rp-1");

    // Authorization still holds after reconstruction.
    assert_project_token_authorization_boundary(&api2, &admin_token2).await;

    terminate_guard(&mut guard_b.child).await;

    // ── Boot C: final restart; every id/link/class/name/metadata/binding ──
    //    must survive unchanged, and a repeat restart must not duplicate.
    let port3 = ephemeral_port();
    let base3 = format!("http://{LISTEN}:{port3}");
    let mut guard_c = O3kdGuard::spawn(port3, data_dir, backend, Some(LOCATIONS));
    wait_healthy(&base3, &guard_c.log_path).await;
    let api3 = Api::new(base3.clone());
    let (admin_token3, _) = api3.admin_token("admin").await;

    assert_regions(&api3, &[("region-a", &["az-1"]), ("region-b", &["az-b"])]).await;

    let (status, list3) = api3
        .get("/o3k/v1/topology/failure-domains", Some(&admin_token3))
        .await;
    assert_eq!(
        status,
        reqwest::StatusCode::OK,
        "fd list after restart: {list3}"
    );
    let ids3: Vec<String> = list3["items"]
        .as_array()
        .map(|items| {
            items
                .iter()
                .filter_map(|i| i["id"].as_str().map(str::to_owned))
                .collect()
        })
        .unwrap_or_default();
    assert_eq!(
        ids3, ids,
        "repeat restart must not duplicate or reorder failure domains: {list3}"
    );

    for (id, class, parent, name) in [
        ("site-1", "site", None, "Site One"),
        ("rack-1", "rack", Some("site-1"), "Rack One"),
        (
            "power-domain-1",
            "power-domain",
            Some("rack-1"),
            "Power Domain One",
        ),
    ] {
        let (status, doc) = failure_domain(&api3, &admin_token3, id).await;
        assert_eq!(
            status,
            reqwest::StatusCode::OK,
            "show {id} after restart: {doc}"
        );
        assert_fd_doc(&doc, id, class, parent, name);
    }
    let (_, site3) = failure_domain(&api3, &admin_token3, "site-1").await;
    assert_eq!(
        site3["metadata"]["tier"], "edge",
        "metadata must survive restart"
    );
    let (status, bindings3) = api3
        .get(
            "/o3k/v1/topology/failure-domains/rack-1/bindings",
            Some(&admin_token3),
        )
        .await;
    assert_eq!(
        status,
        reqwest::StatusCode::OK,
        "bindings after restart: {bindings3}"
    );
    assert_eq!(bindings3["items"][0]["target"]["id"], "rp-1");
    assert_eq!(bindings3["items"][0]["target"]["kind"], "resource-provider");
    assert_eq!(bindings3["items"][0]["failure_domain"], "rack-1");

    // No in-process topology mutations were performed here (there is no offline
    // system-operator token), so the real-process half performs no in-process
    // topology mutation and therefore produces no topology mutation audit rows
    // to verify; operator-mutation audit is covered in p15_1_topology_operator.rs.

    terminate_guard(&mut guard_c.child).await;
    Ok(())
}

#[tokio::test]
async fn p15_1_topology_process_sqlite() -> TestResult {
    let data_dir = std::env::temp_dir().join(format!("p15-1-{}", uuid::Uuid::new_v4().simple()));
    std::fs::create_dir_all(&data_dir)?;
    let backend = sqlite_backend(data_dir.join("o3k.sqlite"));
    run_process_journey(&backend, &data_dir).await?;
    let _ = std::fs::remove_dir_all(&data_dir);
    println!("P15.1 topology process (SQLite): PASS");
    Ok(())
}

#[tokio::test]
async fn p15_1_topology_process_postgres() -> TestResult {
    if std::env::var_os("O3K_DATABASE_URL").is_none() {
        println!("P15.1 topology process (PostgreSQL): SKIP (O3K_DATABASE_URL not set)");
        return Ok(());
    }
    // Provision a disposable database from the admin URL and hand ONLY that
    // database to o3kd, so the shared `O3K_DATABASE_URL` database is never
    // mutated and repeated runs cannot collide (uuid-based name).
    let fixture = PgFixture::new()
        .await
        .map_err(|error| format!("failed to provision disposable PostgreSQL database: {error}"))?;
    let backend = Backend::Postgres(fixture.url.clone());
    let data_dir = std::env::temp_dir().join(format!("p15-1-pg-{}", uuid::Uuid::new_v4().simple()));
    std::fs::create_dir_all(&data_dir)?;
    // Dispose even when the journey returns Err, so a mid-test failure does
    // not leak the disposable database.
    let result = run_process_journey(&backend, &data_dir).await;
    let _ = std::fs::remove_dir_all(&data_dir);
    fixture.dispose().await;
    if result.is_ok() {
        println!("P15.1 topology process (PostgreSQL): PASS");
    }
    result
}
