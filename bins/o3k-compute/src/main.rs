//! O3K Compute host execution runtime.
//!
//! ## Responsibility
//!
//! This binary is the host-level compute runtime. It wires libvirt
//! hypervisor access, the compute-agent protocol bridge, TAP/networking
//! setup, config-drive publishing, and the runtime health/probe endpoint.
//!
//! ## Boundary
//!
//! Host execution (libvirt, qemu-img, network CLI) belongs here — not
//! in the control-plane o3kd binary. The compute service logic (server
//! CRUD, reconciler dispatch, port binding projection) lives in the
//! `o3k-compute` crate and is wired through the o3kd composition root.
//!
//! ## Sub-modules
//!
//! - `iscsi` — host connector and iSCSI lifecycle
//! - `process` — process ownership and pidfd safety
//! - `dhcp` — DHCP runtime and orphan recovery
//! - `network` — network preparation, rollback, and recovery
//! - `cleanup` — artifact and config-drive cleanup
//! - `runtime` — compute command execution and startup restoration
//! - `main.rs` — configuration, construction, health server, startup
//!   coordination, and shutdown

mod cleanup;
mod dhcp;
mod iscsi;
mod network;
mod process;
mod runtime;

use cleanup::reap_orphaned_transfer_parts;
use dhcp::DhcpRuntime;
use runtime::{
    CommandJournalStartupRefresh, LibvirtCommandExecutor, NetworkStartupTapRestore,
    reap_startup_residue, reconcile_dhcp_on_startup, restore_expected_running_domains,
};

use std::{
    env,
    net::SocketAddr,
    path::PathBuf,
    sync::{Arc, Mutex},
    time::Duration,
};

use axum::{Router, extract::State, http::StatusCode, response::IntoResponse, routing::get};
use o3k_compute_agent::{AgentClient, AgentConfig, AgentError, TlsFiles};
use o3k_libvirt::{LibvirtAdapter, LibvirtConfig};
use o3k_provider_contract::compute_proto as proto;
use tokio::net::TcpListener;
use tracing::info;
use tracing_subscriber::EnvFilter;

fn normalized_hostname(value: &str) -> Option<String> {
    let value =
        value.trim_matches(|character: char| character == '\0' || character.is_whitespace());
    if value.is_empty()
        || value.len() > 253
        || value.chars().any(|character| character.is_control())
    {
        None
    } else {
        Some(value.to_owned())
    }
}

/// Test-only fault pause (issue #87): sleeps the configured duration when the
/// named env var is set. Absent, empty, non-numeric, or zero values are no-ops;
/// production configuration never sets these variables.
fn test_fault_pause_ms(name: &str, env_var: &str) {
    let Some(ms) = test_fault_pause_ms_value(std::env::var(env_var).ok()) else {
        return;
    };
    tracing::info!(pause_ms = ms, "test-only fault pause {} enabled", name);
    std::thread::sleep(std::time::Duration::from_millis(ms));
}

/// Parse/guard half of `test_fault_pause_ms`; split out so the no-op
/// conditions can be unit-tested without sleeping.
fn test_fault_pause_ms_value(raw: Option<String>) -> Option<u64> {
    let raw = raw?;
    let Ok(ms) = raw.parse::<u64>() else {
        return None;
    };
    if ms == 0 {
        return None;
    }
    Some(ms)
}

#[derive(Clone)]
struct HealthState {
    agent: AgentClient,
    /// Live agent identity captured at startup; `o3k doctor` reads it from
    /// the loopback `/readyz` (issue #617). Never secrets.
    agent_id: String,
    software_version: String,
    capabilities: proto::Capabilities,
    libvirt_ready: bool,
    libvirt_error: Option<String>,
}

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    let mut config = config_from_env()?;
    tracing_subscriber::fmt()
        .json()
        .with_env_filter(EnvFilter::from_default_env())
        .init();
    let libvirt = LibvirtAdapter::new(LibvirtConfig::default())?;
    let (libvirt_ready, libvirt_error) = match libvirt.capabilities().await {
        Ok(capabilities) => {
            let max_disk_gb = config.capabilities.max_disk_gb;
            config.capabilities = o3k_provider_contract::compute_proto::Capabilities {
                max_disk_gb,
                ..capabilities.to_protocol_capabilities()
            };
            (true, None)
        }
        Err(error) => {
            let message = error.to_string();
            tracing::warn!(error = %message, "local libvirt is unavailable");
            (false, Some(message))
        }
    };
    let agent = AgentClient::new(config.clone())?;
    let agent_id = agent.load_identity()?;
    let artifact_root = agent.identity_file().with_extension("artifacts");
    let network_root = env::var_os("O3K_COMPUTE_NETWORK_ROOT")
        .map(PathBuf::from)
        .unwrap_or_else(|| {
            agent
                .identity_file()
                .parent()
                .unwrap_or_else(|| std::path::Path::new("."))
                .join("network")
        });
    let network = Arc::new(o3k_network::HostNetworkManager::with_ownership_root(
        o3k_network::HostNetworkConfig {
            bridge_name: env::var("O3K_COMPUTE_BRIDGE_NAME")
                .unwrap_or_else(|_| "o3k-br0".to_owned()),
            uplink: env::var("O3K_COMPUTE_UPLINK").ok(),
        },
        network_root.clone(),
    )?);
    let network_owned_by_external_agent = matches!(
        env::var("O3K_COMPUTE_NETWORK_EXTERNAL").as_deref(),
        Ok("1" | "true" | "yes")
    );
    let local_host = if network_owned_by_external_agent {
        env::var("O3K_COMPUTE_FABRIC_HOST_ID").map_err(|_| {
            std::io::Error::new(
                std::io::ErrorKind::InvalidInput,
                "O3K_COMPUTE_FABRIC_HOST_ID is required when external networking is enabled",
            )
        })?
    } else {
        String::new()
    };
    let fabric_attachments = if network_owned_by_external_agent {
        let root = env::var_os("O3K_COMPUTE_FABRIC_STATE_ROOT")
            .map(PathBuf::from)
            .ok_or_else(|| {
                std::io::Error::new(
                    std::io::ErrorKind::InvalidInput,
                    "O3K_COMPUTE_FABRIC_STATE_ROOT is required when external networking is enabled",
                )
            })?;
        Some(Arc::new(o3k_network::LinuxFabricAttachmentResolver::open(
            root,
            local_host.clone(),
        )?))
    } else {
        None
    };
    let bridge_name = env::var("O3K_COMPUTE_BRIDGE_NAME").unwrap_or_else(|_| "o3k-br0".to_owned());
    let service_root = agent
        .identity_file()
        .parent()
        .unwrap_or_else(|| std::path::Path::new("."));
    let dhcp = Arc::new(Mutex::new(DhcpRuntime::open(
        service_root.join("dhcp"),
        env::var("O3K_COMPUTE_DHCP_BINARY").unwrap_or_else(|_| "dnsmasq".to_owned()),
        bridge_name.clone(),
    )?));
    // Startup residue cleanup (issue #87 S3 rerun #5, issue #88 S3/S4
    // reruns): the stale-network reap removes the persisted DHCP bindings
    // and TAPs of instances whose domains provably do not exist FIRST, then
    // the owned-dnsmasq reap stops EVERY owned dnsmasq — at startup the
    // supervisor is always None, so any owned dnsmasq is a leftover of a
    // previous process regardless of bindings (a live-bound orphan would
    // hold the DHCP socket and block the fresh supervisor). Live bindings
    // then get their fresh supervisor below. Errors are logged and retried
    // on the next restart; startup is never blocked.
    if !network_owned_by_external_agent
        && let Err(error) = reap_startup_residue(&network, &dhcp, &libvirt).await
    {
        tracing::warn!(
            error = %error,
            "startup residue reap failed; retried on the next restart"
        );
    }
    // Reap incomplete-transfer `.part` files that can never be resumed
    // (issue #88 S5 supplementary): a crashed agent's part survives its
    // restart and the resource delete (the delete arm reaps config-drive
    // artifacts only), and the control plane expires the abandoned transfer
    // row (#571) without ever resuming it. The rule mirrors
    // `artifact_statuses`: a part with no manifest or an expired incomplete
    // transfer is an orphan; a non-expired incomplete transfer is resumed
    // with the SAME transfer id after reconnect and its part is kept.
    // Best-effort and never fatal; the inventory catches residue.
    reap_orphaned_transfer_parts(&artifact_root, &agent_id, None);
    // A DHCP that cannot start at boot (missing capabilities, a port
    // conflict, the host's own dnsmasq on 127.0.0.1:53, ...) must not take
    // the agent down: the failure is logged, the agent stays up, and DHCP
    // is retried on the next restart or the next create. Create-time DHCP
    // failures remain fail-closed in DhcpRuntime::apply.
    if !network_owned_by_external_agent
        && let Err(error) = reconcile_dhcp_on_startup(&dhcp, &network)
    {
        tracing::warn!(
            error = %error,
            "DHCP reconciliation failed at startup; the agent stays up and \
             retries on the next restart or create"
        );
    }
    // Host-reboot restoration (issue #613 blocker A): domains whose last
    // lifecycle mutation provably left them running are started again inside
    // a bounded window. The restore runs as a task next to the control
    // connection so a slow restore can never delay agent registration, and
    // it only ever starts domains the agent's own journal proves were
    // running. A failed restore is logged and retried on the next restart.
    let restore_states = match o3k_compute_agent::load_journal_lifecycle_resource_states(
        agent.identity_file(),
        &agent_id,
    ) {
        Ok(states) => states,
        Err(error) => {
            tracing::warn!(
                error = %error,
                "command journal could not be read for domain restoration; \
                 restoration skipped for this start"
            );
            std::collections::HashMap::new()
        }
    };
    let restore_journal_refresh = CommandJournalStartupRefresh {
        identity_path: agent.identity_file().to_path_buf(),
        agent_id: agent_id.clone(),
    };
    let restore_identity_path = agent.identity_file().to_path_buf();
    let restore_agent_id = agent_id.clone();
    let restore_fabric_attachments = fabric_attachments.clone();
    let restore_local_host = local_host.clone();
    let restore_task = tokio::spawn({
        let adapter = libvirt.clone();
        let network = Arc::clone(&network);
        async move {
            let tap_restorer = NetworkStartupTapRestore {
                network,
                fabric_attachments: restore_fabric_attachments,
                external_owner: network_owned_by_external_agent,
                local_host: restore_local_host,
                identity_path: restore_identity_path,
                agent_id: restore_agent_id,
            };
            // The unconverged outcome is logged once inside the restore pass
            // (with the pending count); the returned error needs no second
            // log site here.
            let _ = restore_expected_running_domains(
                &tap_restorer,
                &adapter,
                &restore_journal_refresh,
                &restore_states,
            )
            .await;
        }
    });
    let executor = Arc::new(LibvirtCommandExecutor {
        adapter: libvirt.clone(),
        artifact_root,
        image_materializer: o3k_compute_agent::ImageMaterializer::open(
            o3k_compute_agent::ArtifactStore::open(
                agent.identity_file().with_extension("artifacts"),
                agent_id.clone(),
            )?,
            service_root.join("image-cache"),
            2 * 1024 * 1024 * 1024,
        )?,
        network,
        fabric_attachments,
        local_host,
        dhcp,
        max_disk_gb: config.capabilities.max_disk_gb,
        network_owned_by_external_agent,
    });
    info!(
        endpoint = %config.endpoint,
        host_label = %config.host_label,
        bridge = %bridge_name,
        network_root = %network_root.display(),
        network_owned_by_external_agent,
        "o3k-compute starting"
    );
    let health_addr = env::var("O3K_COMPUTE_HEALTH_ADDR")
        .unwrap_or_else(|_| "127.0.0.1:9100".to_owned())
        .parse::<SocketAddr>()?;
    let state = HealthState {
        agent: agent.clone(),
        agent_id: agent_id.clone(),
        software_version: config.software_version.clone(),
        capabilities: config.capabilities.clone(),
        libvirt_ready,
        libvirt_error,
    };
    let health_server = axum::serve(TcpListener::bind(health_addr).await?, health_router(state));
    tokio::select! {
        result = agent.run_with_executor(shutdown_signal(), executor) => {
            restore_task.abort();
            let _ = restore_task.await;
            result?;
        }
        result = health_server.with_graceful_shutdown(shutdown_signal()) => {
            restore_task.abort();
            let _ = restore_task.await;
            result?;
        }
    }
    info!("o3k-compute stopped");
    Ok(())
}

fn health_router(state: HealthState) -> Router {
    Router::new()
        .route("/healthz", get(liveness))
        .route("/readyz", get(readiness))
        .route("/metrics", get(metrics))
        .with_state(state)
}

async fn liveness() -> impl IntoResponse {
    (StatusCode::OK, "{\"status\":\"alive\"}\n")
}

/// The 200 `/readyz` body (issue #617): the existing `status` key plus the
/// agent's live, loopback-only identity. `agent_epoch` is omitted until the
/// control plane has validated the current registration — a ready agent has
/// always published one first, but the field stays `skip_serializing_if None`
/// so the doctor can parse leniently. No secrets.
#[derive(serde::Serialize)]
struct ReadyBody {
    status: &'static str,
    agent_id: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    agent_epoch: Option<String>,
    software_version: String,
    capabilities: ReadyCapabilities,
}

#[derive(serde::Serialize)]
struct ReadyCapabilities {
    max_vcpus: u32,
    max_memory_mib: u64,
    max_disk_gb: u64,
}

async fn readiness(State(state): State<HealthState>) -> impl IntoResponse {
    if state.agent.is_ready() && state.libvirt_ready {
        let body = ReadyBody {
            status: "ready",
            agent_id: state.agent_id.clone(),
            agent_epoch: state.agent.current_epoch().await,
            software_version: state.software_version.clone(),
            capabilities: ReadyCapabilities {
                max_vcpus: state.capabilities.max_vcpus,
                max_memory_mib: state.capabilities.max_memory_mib,
                max_disk_gb: state.capabilities.max_disk_gb,
            },
        };
        let body = match serde_json::to_string(&body) {
            Ok(serialized) => serialized,
            // Plain string/integer fields cannot fail JSON serialization;
            // never panic on the health path.
            Err(_) => "{\"status\":\"ready\"}".to_owned(),
        };
        (StatusCode::OK, format!("{body}\n"))
    } else {
        let error = state
            .libvirt_error
            .as_deref()
            .unwrap_or("control plane is not connected");
        (
            StatusCode::SERVICE_UNAVAILABLE,
            format!(
                "{{\"status\":\"not_ready\",\"reason\":{}}}\n",
                serde_json::to_string(error).unwrap_or_else(|_| "\"unavailable\"".to_owned())
            ),
        )
    }
}

async fn metrics(State(state): State<HealthState>) -> impl IntoResponse {
    let ready = u8::from(state.agent.is_ready() && state.libvirt_ready);
    (StatusCode::OK, format!("o3k_compute_ready {ready}\n"))
}

async fn shutdown_signal() {
    let ctrl_c = async {
        let _ = tokio::signal::ctrl_c().await;
    };
    #[cfg(unix)]
    let terminate = async {
        if let Ok(mut signal) =
            tokio::signal::unix::signal(tokio::signal::unix::SignalKind::terminate())
        {
            let _ = signal.recv().await;
        }
    };
    #[cfg(not(unix))]
    let terminate = std::future::pending::<()>();
    tokio::select! { _ = ctrl_c => {}, _ = terminate => {} }
}

fn config_from_env() -> Result<AgentConfig, Box<dyn std::error::Error>> {
    let data_dir = PathBuf::from(
        env::var("O3K_COMPUTE_DATA_DIR").unwrap_or_else(|_| "./compute-data".to_owned()),
    );
    let endpoint = env::var("O3K_COMPUTE_CONTROL_ENDPOINT")
        .unwrap_or_else(|_| "https://127.0.0.1:50051".to_owned());
    let server_name =
        env::var("O3K_COMPUTE_SERVER_NAME").unwrap_or_else(|_| "o3k-control-plane".to_owned());
    let host_label =
        env::var("O3K_COMPUTE_HOST_LABEL").unwrap_or_else(|_| "compute-host".to_owned());
    let software_version =
        env::var("O3K_COMPUTE_VERSION").unwrap_or_else(|_| env!("CARGO_PKG_VERSION").to_owned());
    let tls_dir = PathBuf::from(
        env::var("O3K_COMPUTE_TLS_DIR").unwrap_or_else(|_| "./compute-tls".to_owned()),
    );
    Ok(AgentConfig {
        endpoint,
        server_name,
        tls: TlsFiles {
            ca_certificate: tls_dir.join("ca.pem"),
            certificate: tls_dir.join("agent.pem"),
            private_key: tls_dir.join("agent-key.pem"),
        },
        identity_file: data_dir.join("agent-id"),
        host_label,
        software_version,
        heartbeat_interval: Duration::from_secs(5),
        max_reconnect_delay: Duration::from_secs(30),
        capabilities: o3k_provider_contract::compute_proto::Capabilities {
            architecture: env::consts::ARCH.to_owned(),
            agent_provider_name: "o3k-compute".to_owned(),
            agent_provider_version: env!("CARGO_PKG_VERSION").to_owned(),
            max_disk_gb: env::var("O3K_COMPUTE_MAX_DISK_GB")
                .unwrap_or_else(|_| "0".to_owned())
                .parse()?,
            ..Default::default()
        },
    })
}

#[cfg(test)]
#[allow(clippy::module_inception)]
mod tests;
