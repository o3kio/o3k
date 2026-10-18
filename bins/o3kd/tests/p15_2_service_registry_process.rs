//! P15.2 real-process proof: all public service views are projections of the
//! one runtime `ManifestRegistry` authority.
#![allow(clippy::expect_used, clippy::panic)]

use reqwest::Client;
use serde_json::Value;
use sqlx::postgres::PgPoolOptions;
use std::{
    net::TcpListener,
    path::PathBuf,
    process::{Child, Command},
    time::{Duration, Instant},
};

const PASSWORD: &str = "p15-2-bootstrap-password-not-a-secret";
const SIGNING_KEY: &str = "p15-2-token-signing-key-0123456789abcdef";
const CURSOR_KEY: &str = "p15-2-native-cursor-signing-key-0123456789abcdef";

fn port() -> u16 {
    let listener = TcpListener::bind(("127.0.0.1", 0)).expect("ephemeral port");
    let port = listener.local_addr().expect("local address").port();
    drop(listener);
    port
}

enum Backend {
    Sqlite,
    Postgres(String),
}

struct PgFixture {
    admin_url: String,
    database: String,
    url: String,
}

impl PgFixture {
    async fn new() -> Result<Self, Box<dyn std::error::Error>> {
        let base_url = std::env::var("O3K_DATABASE_URL")?;
        let parsed = url::Url::parse(&base_url)?;
        let database = format!("o3k_p15_2_service_{}", uuid::Uuid::now_v7().simple());
        let mut admin_url = parsed.clone();
        admin_url.set_path("/postgres");
        let admin_url = admin_url.to_string();
        let admin = PgPoolOptions::new()
            .max_connections(1)
            .connect(&admin_url)
            .await?;
        sqlx::query(&format!("CREATE DATABASE {database}"))
            .execute(&admin)
            .await?;
        admin.close().await;
        let mut isolated = parsed;
        isolated.set_path(&format!("/{database}"));
        Ok(Self {
            admin_url,
            database,
            url: isolated.to_string(),
        })
    }

    async fn dispose(self) {
        let admin = PgPoolOptions::new()
            .max_connections(1)
            .connect(&self.admin_url)
            .await
            .expect("connect postgres admin for teardown");
        let _ = sqlx::query(
            "SELECT pg_terminate_backend(pid) FROM pg_stat_activity \
             WHERE datname = $1 AND pid <> pg_backend_pid()",
        )
        .bind(&self.database)
        .execute(&admin)
        .await;
        sqlx::query(&format!("DROP DATABASE {} WITH (FORCE)", self.database))
            .execute(&admin)
            .await
            .expect("drop disposable p15.2 database");
        admin.close().await;
    }
}

fn spawn(port: u16, data_dir: &PathBuf, backend: &Backend, cinder_endpoint: Option<&str>) -> Child {
    let mut command = Command::new(env!("CARGO_BIN_EXE_o3kd"));
    command
        .args(["--listen-addr", &format!("127.0.0.1:{port}")])
        .env("O3K_LISTEN_ADDR", format!("127.0.0.1:{port}"))
        .env("O3K_DATA_DIR", data_dir)
        .env("O3K_PROVIDER", "fake")
        .env("O3K_BOOTSTRAP_PASSWORD", PASSWORD)
        .env("O3K_TOKEN_SIGNING_KEY", SIGNING_KEY)
        .env("O3K_NATIVE_CURSOR_HMAC_KEY", CURSOR_KEY)
        .env("O3K_LOG_FILTER", "warn");
    match backend {
        Backend::Sqlite => {
            command
                .env("O3K_DATABASE_BACKEND", "sqlite")
                .env_remove("O3K_DATABASE_URL");
        }
        Backend::Postgres(url) => {
            command
                .env("O3K_DATABASE_BACKEND", "postgres")
                .env("O3K_DATABASE_URL", url);
        }
    }
    if let Some(endpoint) = cinder_endpoint {
        command
            .env("O3K_CINDER_ENDPOINT", endpoint)
            .env("O3K_CINDER_PASSWORD", "unavailable-cinder-password");
    } else {
        command
            .env_remove("O3K_CINDER_ENDPOINT")
            .env_remove("O3K_CINDER_PASSWORD");
    }
    command.spawn().expect("spawn o3kd")
}

async fn wait_healthy(client: &Client, base: &str) {
    let deadline = Instant::now() + Duration::from_secs(45);
    loop {
        if let Ok(response) = client.get(format!("{base}/healthz")).send().await
            && response.status().is_success()
        {
            return;
        }
        assert!(Instant::now() < deadline, "o3kd did not become healthy");
        tokio::time::sleep(Duration::from_millis(200)).await;
    }
}

async fn stop(child: &mut Child) {
    let _ = Command::new("kill")
        .args(["-TERM", &child.id().to_string()])
        .status();
    let deadline = Instant::now() + Duration::from_secs(10);
    loop {
        if let Some(status) = child.try_wait().expect("wait") {
            assert!(status.success(), "o3kd exited unsuccessfully: {status}");
            return;
        }
        assert!(Instant::now() < deadline, "o3kd did not stop");
        tokio::time::sleep(Duration::from_millis(100)).await;
    }
}

async fn json(client: &Client, url: String) -> Value {
    client
        .get(url)
        .send()
        .await
        .expect("request")
        .json()
        .await
        .expect("json response")
}

#[tokio::test]
async fn p15_2_real_process_views_converge_and_reconstruct() {
    let mut backends = vec![Backend::Sqlite];
    let postgres = if std::env::var("O3K_DATABASE_URL").is_ok() {
        match PgFixture::new().await {
            Ok(fixture) => {
                backends.push(Backend::Postgres(fixture.url.clone()));
                Some(fixture)
            }
            Err(error) => panic!("PostgreSQL evidence setup failed: {error}"),
        }
    } else {
        eprintln!("P15.2 PostgreSQL process evidence skipped: O3K_DATABASE_URL unavailable");
        None
    };

    for backend in &backends {
        let data_dir = std::env::temp_dir().join(format!("o3k-p15-2-{}", uuid::Uuid::now_v7()));
        std::fs::create_dir_all(&data_dir).expect("data directory");
        #[cfg(unix)]
        std::fs::set_permissions(
            &data_dir,
            std::os::unix::fs::PermissionsExt::from_mode(0o700),
        )
        .expect("private data directory");
        let port = port();
        let base = format!("http://127.0.0.1:{port}");
        let client = Client::new();
        let mut child = spawn(port, &data_dir, backend, None);
        wait_healthy(&client, &base).await;

        let services = json(&client, format!("{base}/o3k/v1/services")).await;
        let resource_types = json(&client, format!("{base}/o3k/v1/resource-types")).await;
        let token_response = client
        .post(format!("{base}/v3/auth/tokens"))
        .json(&serde_json::json!({
            "auth": {
                "identity": {"methods": ["password"], "password": {"user": {"name": "admin", "password": PASSWORD}}},
                "scope": {"project": {"name": "admin"}}
            }
        }))
        .send()
        .await
        .expect("token request");
        assert_eq!(token_response.status(), reqwest::StatusCode::CREATED);
        assert!(token_response.headers().get("x-subject-token").is_some());
        let token_body: Value = token_response.json().await.expect("token JSON");

        let service_ids: Vec<&str> = services["services"]
            .as_array()
            .expect("services array")
            .iter()
            .filter_map(|service| service["id"].as_str())
            .collect();
        assert!(service_ids.contains(&"compute"));
        assert!(service_ids.contains(&"network"));
        let volume = services["services"]
            .as_array()
            .expect("services array")
            .iter()
            .find(|service| service["id"] == "volume")
            .expect("volume service");
        assert_eq!(volume["lifecycle_state"], "not_ready");
        assert!(resource_types["resource_types"].is_array());
        let catalog = token_body["token"]["catalog"].as_array().expect("catalog");
        // The configured fake compute/network/image/identity paths are Ready, so
        // their compatibility projections are advertised from the same authority.
        for service_type in ["compute", "network", "image", "identity"] {
            assert!(
                catalog
                    .iter()
                    .any(|service| service["type"] == service_type)
            );
        }
        // The native volume identity remains discoverable while its unavailable
        // provider keeps it NotReady; the subordinate volumev3 projection cannot
        // make it executable in Keystone.
        assert!(!catalog.iter().any(|service| service["type"] == "volumev3"));

        stop(&mut child).await;
        let mut restarted = spawn(port, &data_dir, backend, None);
        wait_healthy(&client, &base).await;
        let restarted_services = json(&client, format!("{base}/o3k/v1/services")).await;
        assert_eq!(services, restarted_services);
        let restarted_token = client
            .post(format!("{base}/v3/auth/tokens"))
            .json(&serde_json::json!({
                "auth": {
                    "identity": {"methods": ["password"], "password": {"user": {"name": "admin", "password": PASSWORD}}},
                    "scope": {"project": {"name": "admin"}}
                }
            }))
            .send()
            .await
            .expect("restarted token request");
        assert_eq!(restarted_token.status(), reqwest::StatusCode::CREATED);
        let restarted_body: Value = restarted_token.json().await.expect("restarted token JSON");
        assert_eq!(
            token_body["token"]["catalog"],
            restarted_body["token"]["catalog"]
        );
        stop(&mut restarted).await;
        let _ = std::fs::remove_dir_all(&data_dir);
    }
    if let Some(fixture) = postgres {
        fixture.dispose().await;
    }
}

#[tokio::test]
async fn configured_but_unavailable_cinder_is_not_advertised() {
    let data_dir = std::env::temp_dir().join(format!("o3k-p15-2-cinder-{}", uuid::Uuid::now_v7()));
    std::fs::create_dir_all(&data_dir).expect("data directory");
    #[cfg(unix)]
    std::fs::set_permissions(
        &data_dir,
        std::os::unix::fs::PermissionsExt::from_mode(0o700),
    )
    .expect("private data directory");
    let port = port();
    let base = format!("http://127.0.0.1:{port}");
    let client = Client::new();
    let mut child = spawn(
        port,
        &data_dir,
        &Backend::Sqlite,
        Some("http://127.0.0.1:1"),
    );
    wait_healthy(&client, &base).await;
    let response = client
        .post(format!("{base}/v3/auth/tokens"))
        .json(&serde_json::json!({
            "auth": {
                "identity": {"methods": ["password"], "password": {"user": {"name": "admin", "password": PASSWORD}}},
                "scope": {"project": {"name": "admin"}}
            }
        }))
        .send()
        .await
        .expect("token request");
    assert_eq!(response.status(), reqwest::StatusCode::CREATED);
    let body: Value = response.json().await.expect("token JSON");
    assert!(
        !body["token"]["catalog"]
            .as_array()
            .expect("catalog array")
            .iter()
            .any(|entry| entry["type"] == "volumev3")
    );
    stop(&mut child).await;
    let _ = std::fs::remove_dir_all(&data_dir);
}
