#![cfg(unix)]

//! PP.5 #1035 process-level crash-window regression for the accepted test fault
//! hook `O3K_TEST_FAULT_PAUSE_BEFORE_ENDPOINT_RELEASE_MS` on the server delete
//! request path.
//!
//! The hook pauses a delete request after the terminal lifecycle committed
//! durably (issue #1041) and before the request-path server-owned endpoint
//! release runs. This test starts a real `o3kd` (fake provider) with the hook
//! armed, proves the durable window mid-request — the server resource is
//! `DELETED`, no non-terminal lifecycle operation remains, the `o3k-server:`
//! endpoint is still present, and the delete response has not been sent — then
//! SIGKILLs the daemon inside that window, restarts it over the same durable
//! data directory, and proves the shipped orphan-repair sweep releases the
//! orphaned endpoint and restores address reuse.
//!
//! Without the hook (or with it placed after the endpoint release) the delete
//! completes in milliseconds, the window poll never observes the orphaned
//! endpoint, and the test fails. The in-process repair invariants this process
//! exercises end-to-end live in `composition/pp4_endpoint_lifecycle.rs`.

use std::io::{Read, Write};
use std::net::{TcpListener, TcpStream};
use std::path::Path;
use std::process::{Child, Command, Stdio};
use std::sync::Arc;
use std::sync::atomic::{AtomicBool, Ordering};
use std::thread;
use std::time::{Duration, Instant};

use o3k_store::DurableStore;
use serde_json::{Value, json};
use uuid::Uuid;

const PROJECT_ID: &str = "eba29e2d-53de-461d-ae91-ede7402713cb";
const BOOTSTRAP_PASSWORD: &str = "pp5-interrupted-delete-bootstrap-password";
const TOKEN_SIGNING_KEY: &str = "pp5-interrupted-delete-signing-key-0123456789abcdef";
const FAULT_ENV: &str = "O3K_TEST_FAULT_PAUSE_BEFORE_ENDPOINT_RELEASE_MS";
const FAULT_PAUSE_MS: &str = "4000";
const FLAVOR_ID: &str = "00000000-0000-0000-0000-000000000001";

fn free_address() -> Result<std::net::SocketAddr, Box<dyn std::error::Error>> {
    let listener = TcpListener::bind("127.0.0.1:0")?;
    Ok(listener.local_addr()?)
}

fn wait_ready(
    child: &mut Child,
    address: std::net::SocketAddr,
) -> Result<(), Box<dyn std::error::Error>> {
    let deadline = Instant::now() + Duration::from_secs(15);
    while Instant::now() < deadline {
        if let Ok(mut stream) = TcpStream::connect(address) {
            stream.set_read_timeout(Some(Duration::from_secs(2)))?;
            stream.write_all(
                b"GET /readyz HTTP/1.1\r\nHost: localhost\r\nConnection: close\r\n\r\n",
            )?;
            let mut response = Vec::new();
            stream.read_to_end(&mut response)?;
            if response.starts_with(b"HTTP/1.1 200 OK") {
                return Ok(());
            }
        }
        if let Some(status) = child.try_wait()? {
            return Err(format!("o3kd exited during startup: {status}").into());
        }
        thread::sleep(Duration::from_millis(50));
    }
    Err("o3kd did not become ready".into())
}

/// Starts a real o3kd over `data_dir`, optionally with the #1035 delete-path
/// fault pause armed in the child environment.
fn start_o3kd(
    data_dir: &Path,
    address: std::net::SocketAddr,
    fault_pause_ms: Option<&str>,
) -> Result<Child, Box<dyn std::error::Error>> {
    let mut command = Command::new(env!("CARGO_BIN_EXE_o3kd"));
    command
        .args([
            "--provider",
            "fake",
            "--listen-addr",
            &address.to_string(),
            "--data-dir",
            data_dir.to_str().ok_or("non-utf8 data path")?,
            "--log-filter",
            "off",
        ])
        .env("O3K_BOOTSTRAP_PASSWORD", BOOTSTRAP_PASSWORD)
        .env("O3K_TOKEN_SIGNING_KEY", TOKEN_SIGNING_KEY)
        .stdout(Stdio::null())
        .stderr(Stdio::null());
    if let Some(ms) = fault_pause_ms {
        command.env(FAULT_ENV, ms);
    }
    let mut child = command.spawn()?;
    if let Err(error) = wait_ready(&mut child, address) {
        let _ = child.kill();
        let _ = child.wait();
        return Err(error);
    }
    Ok(child)
}

async fn stop(mut child: Child) -> Result<(), Box<dyn std::error::Error>> {
    let status = Command::new("kill")
        .args(["-TERM", &child.id().to_string()])
        .status()?;
    if !status.success() {
        child.kill()?;
    }
    let deadline = Instant::now() + Duration::from_secs(15);
    while Instant::now() < deadline {
        if let Some(status) = child.try_wait()? {
            if !status.success() {
                return Err(format!("o3kd shutdown failed: {status}").into());
            }
            return Ok(());
        }
        thread::sleep(Duration::from_millis(50));
    }
    child.kill()?;
    let _ = child.wait();
    Err("o3kd did not shut down".into())
}

async fn keystone_token(
    client: &reqwest::Client,
    address: std::net::SocketAddr,
) -> Result<String, Box<dyn std::error::Error>> {
    let response = client
        .post(format!("http://{address}/v3/auth/tokens"))
        .header("content-type", "application/json")
        .json(&json!({
            "auth": {
                "identity": {
                    "methods": ["password"],
                    "password": {"user": {"name": "admin", "password": BOOTSTRAP_PASSWORD}}
                },
                "scope": {"project": {"name": "admin"}}
            }
        }))
        .send()
        .await?;
    let status = response.status();
    let token = response
        .headers()
        .get("x-subject-token")
        .and_then(|value| value.to_str().ok())
        .map(str::to_owned);
    if status != reqwest::StatusCode::CREATED {
        return Err(format!("keystone password grant failed: {status}").into());
    }
    token.ok_or_else(|| "missing x-subject-token".into())
}

async fn post_compat(
    client: &reqwest::Client,
    address: std::net::SocketAddr,
    token: &str,
    path: &str,
    body: Value,
) -> Result<Value, Box<dyn std::error::Error>> {
    let response = client
        .post(format!("http://{address}{path}"))
        .header("x-auth-token", token)
        .header("content-type", "application/json")
        .json(&body)
        .send()
        .await?;
    let status = response.status();
    let value: Value = response.json().await.unwrap_or(Value::Null);
    if !status.is_success() {
        return Err(format!("POST {path} failed: {status}: {value}").into());
    }
    Ok(value)
}

/// The project's `o3k-server:` endpoints as (port id, fixed ip) pairs, as the
/// tenant-facing port list sees them.
async fn server_owned_ports(
    client: &reqwest::Client,
    address: std::net::SocketAddr,
    token: &str,
) -> Result<Vec<(String, String)>, Box<dyn std::error::Error>> {
    let response = client
        .get(format!("http://{address}/v2.0/ports"))
        .header("x-auth-token", token)
        .send()
        .await?;
    let status = response.status();
    let body: Value = response.json().await.unwrap_or(Value::Null);
    if status != reqwest::StatusCode::OK {
        return Err(format!("GET /v2.0/ports failed: {status}: {body}").into());
    }
    Ok(body["ports"]
        .as_array()
        .map(|ports| {
            ports
                .iter()
                .filter(|port| {
                    port["name"]
                        .as_str()
                        .is_some_and(|name| name.starts_with("o3k-server:"))
                })
                .filter_map(|port| {
                    let id = port["id"].as_str()?.to_owned();
                    let ip = port["fixed_ips"]
                        .as_array()?
                        .first()?
                        .get("ip_address")?
                        .as_str()?
                        .to_owned();
                    Some((id, ip))
                })
                .collect()
        })
        .unwrap_or_default())
}

async fn create_server(
    client: &reqwest::Client,
    address: std::net::SocketAddr,
    token: &str,
    name: &str,
    network_id: &str,
) -> Result<Uuid, Box<dyn std::error::Error>> {
    let response = client
        .post(format!("http://{address}/o3k/v1/compute/servers"))
        .header("authorization", format!("Bearer {token}"))
        .header("content-type", "application/json")
        .header("idempotency-key", name)
        .json(&json!({
            "kind": "compute:server",
            "spec": {
                "name": name,
                "image_id": "pp5-image",
                "flavor_id": FLAVOR_ID,
                "network_ids": [network_id],
            }
        }))
        .send()
        .await?;
    let status = response.status();
    let body: Value = response.json().await.unwrap_or(Value::Null);
    if !status.is_success() {
        return Err(format!("native create {name} failed: {status}: {body}").into());
    }
    let id = body["resource_id"]
        .as_str()
        .or_else(|| body["server"]["id"].as_str())
        .ok_or("native create response has no server id")?;
    Ok(Uuid::parse_str(id)?)
}

async fn wait_resource_state(
    probe: &o3k_store::testkit::TestStore,
    id: Uuid,
    state: &str,
    deadline: Instant,
) -> Result<(), Box<dyn std::error::Error>> {
    loop {
        let resource = probe.get_resource(id).await?;
        if resource.observed_state == state {
            return Ok(());
        }
        if Instant::now() >= deadline {
            return Err(format!(
                "server {id} did not reach {state} (observed {})",
                resource.observed_state
            )
            .into());
        }
        tokio::time::sleep(Duration::from_millis(50)).await;
    }
}

/// The full #1035 window against a real daemon: with the fault pause armed on
/// the delete path, the durable mid-request state is "server DELETED, delete
/// terminal, endpoint still present"; SIGKILL inside that window leaves exactly
/// the orphan the shipped sweep must repair, and the freed address must be
/// reusable afterwards.
#[tokio::test]
async fn fault_pause_interrupted_delete_orphan_is_repaired_and_reuse_is_restored()
-> Result<(), Box<dyn std::error::Error>> {
    let root = std::env::temp_dir().join(format!("o3k-pp5-interrupted-{}", Uuid::now_v7()));
    std::fs::create_dir_all(&root)?;
    let client = reqwest::Client::builder().build()?;

    // 1. A real control plane with the #1035 delete-path fault pause armed.
    let address = free_address()?;
    let mut child = start_o3kd(&root, address, Some(FAULT_PAUSE_MS))?;
    let token = keystone_token(&client, address).await?;

    let fixture = Uuid::new_v4().simple().to_string();
    let network = post_compat(
        &client,
        address,
        &token,
        "/v2.0/networks",
        json!({"network": {"name": format!("pp5-interrupted-network-{fixture}")}}),
    )
    .await?;
    let network_id = network["network"]["id"]
        .as_str()
        .ok_or("network response has no id")?
        .to_owned();
    post_compat(
        &client,
        address,
        &token,
        "/v2.0/subnets",
        json!({
            "subnet": {
                "name": format!("pp5-interrupted-subnet-{fixture}"),
                "network_id": network_id,
                "cidr": "192.0.2.0/24",
                "ip_version": 4,
            }
        }),
    )
    .await?;

    // 2. A server with an O3K-owned endpoint, converged before the delete.
    let probe = o3k_store::testkit::open_file(&root.join("o3k.sqlite")).await?;
    let server_id = create_server(
        &client,
        address,
        &token,
        &format!("pp5-window-{fixture}"),
        &network_id,
    )
    .await?;
    wait_resource_state(
        &probe,
        server_id,
        "ACTIVE",
        Instant::now() + Duration::from_secs(30),
    )
    .await?;
    let ports = server_owned_ports(&client, address, &token).await?;
    assert_eq!(
        ports.len(),
        1,
        "exactly one server-owned endpoint: {ports:?}"
    );
    let (orphan_port_id, orphan_ip) = ports[0].clone();

    // 3. Delete on a background task; poll the durable window while the
    // request is held open by the fault pause.
    let delete_done = Arc::new(AtomicBool::new(false));
    let (delete_tx, delete_rx) = tokio::sync::oneshot::channel::<String>();
    {
        let client = client.clone();
        let delete_done = delete_done.clone();
        let url = format!("http://{address}/o3k/v1/compute/servers/{server_id}");
        let token = token.clone();
        let delete_key = format!("pp5-interrupted-delete-{fixture}");
        tokio::spawn(async move {
            let outcome = match client
                .delete(url)
                .header("authorization", format!("Bearer {token}"))
                .header("idempotency-key", delete_key)
                .send()
                .await
            {
                Ok(response) => {
                    format!("delete returned {}", response.status())
                }
                Err(error) => format!("delete request aborted: {error}"),
            };
            delete_done.store(true, Ordering::SeqCst);
            let _ = delete_tx.send(outcome);
        });
    }

    let window_deadline = Instant::now() + Duration::from_secs(30);
    loop {
        if delete_done.load(Ordering::SeqCst) {
            let outcome = delete_rx
                .await
                .unwrap_or_else(|_| "delete outcome lost".to_owned());
            return Err(format!(
                "the delete completed before the window was observed \
                 ({outcome}); the fault pause is missing or misplaced"
            )
            .into());
        }
        if let Some(status) = child.try_wait()? {
            return Err(format!("o3kd exited before the window was observed: {status}").into());
        }
        let resource = probe.get_resource(server_id).await?;
        let terminal_window = resource.observed_state == "DELETED"
            && probe
                .list_non_terminal_lifecycle_operations()
                .await?
                .into_iter()
                .all(|operation| operation.resource_id != server_id);
        if terminal_window {
            // The durable terminal delete is committed while the owned
            // endpoint is still present and the request is still open.
            let ports = server_owned_ports(&client, address, &token).await?;
            assert!(
                ports.iter().any(|(id, _)| id == &orphan_port_id),
                "the owned endpoint must still be present inside the window: {ports:?}"
            );
            break;
        }
        if Instant::now() >= window_deadline {
            return Err(
                "the #1035 window was never observed; the fault pause is missing or misplaced"
                    .into(),
            );
        }
        tokio::time::sleep(Duration::from_millis(25)).await;
    }

    // 4. Kill the daemon inside the window: the delete response never leaves,
    // leaving exactly the interrupted-terminal-delete residue. The endpoint row
    // must be durably present right after the kill — the release provably never
    // ran.
    child.kill()?;
    let _ = child.wait();
    let _ = delete_rx.await;
    let orphan_endpoint = Uuid::parse_str(&orphan_port_id)?;
    assert!(
        probe
            .get_canonical_endpoint(PROJECT_ID, &orphan_endpoint)
            .await?
            .is_some(),
        "the orphaned endpoint must be durably present right after the kill"
    );

    // 5. Restart over the same durable state, without the fault pause. The
    // shipped sweep's first periodic pass repairs the orphan; the post-restart
    // presence of the row is proven durably above (the sweep may legitimately
    // run before the first HTTP observation after readyz).
    let address = free_address()?;
    let child = start_o3kd(&root, address, None)?;
    let token = keystone_token(&client, address).await?;

    // 6. The shipped sweep repairs the orphan.
    let sweep_deadline = Instant::now() + Duration::from_secs(120);
    loop {
        let ports = server_owned_ports(&client, address, &token).await?;
        if !ports.iter().any(|(id, _)| id == &orphan_port_id) {
            break;
        }
        if Instant::now() >= sweep_deadline {
            return Err(
                "the shipped orphan-repair sweep did not release the interrupted-delete orphan"
                    .into(),
            );
        }
        tokio::time::sleep(Duration::from_millis(250)).await;
    }

    // 7. The released address is reusable: a new server on the same network
    // re-allocates the exact freed address and no endpoint leaks.
    let recreated = create_server(
        &client,
        address,
        &token,
        &format!("pp5-window-after-{fixture}"),
        &network_id,
    )
    .await?;
    wait_resource_state(
        &probe,
        recreated,
        "ACTIVE",
        Instant::now() + Duration::from_secs(30),
    )
    .await?;
    let ports = server_owned_ports(&client, address, &token).await?;
    assert_eq!(ports.len(), 1, "no leaked endpoint after repair: {ports:?}");
    assert_eq!(
        ports[0].1, orphan_ip,
        "the released address must be re-allocated: {ports:?}"
    );

    stop(child).await?;
    std::fs::remove_dir_all(&root)?;
    Ok(())
}
