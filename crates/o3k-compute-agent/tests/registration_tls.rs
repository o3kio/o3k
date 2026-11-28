use std::{path::PathBuf, sync::Arc, time::Duration};

use o3k_compute_agent::{
    AgentClient, AgentConfig, AuthorizedAgent, ControlPlaneServer, ControlPlaneTls, NodeRegistry,
    TlsFiles,
};
use o3k_provider_contract::compute_proto as proto;
use tokio::{sync::oneshot, time};

fn fixture(name: &str) -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .join("tests/fixtures")
        .join(name)
}

#[tokio::test]
async fn mutual_tls_registration_and_heartbeat_are_black_box_observable()
-> Result<(), Box<dyn std::error::Error>> {
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await?;
    let address = listener.local_addr()?;
    let registry = NodeRegistry::default();
    registry
        .register(&proto::RegisterRequest {
            agent_id: "node-test".to_owned(),
            agent_epoch: "seed-epoch".to_owned(),
            software_version: "test".to_owned(),
            host_label: "seed-host".to_owned(),
            supported_versions: vec![o3k_compute_agent::PROTOCOL_VERSION],
            capabilities: Some(proto::Capabilities {
                architecture: "x86_64".to_owned(),
                agent_provider_name: "o3k-compute".to_owned(),
                agent_provider_version: "test".to_owned(),
                ..Default::default()
            }),
        })
        .await?;
    registry
        .set_desired_state("node-test", proto::AdministrativeState::Draining)
        .await?;
    let server = ControlPlaneServer {
        registry: registry.clone(),
        address,
        tls: ControlPlaneTls {
            server_certificate: fixture("server-chain.pem"),
            server_private_key: fixture("server-key.pem"),
            client_ca_certificate: fixture("ca.pem"),
        },
        authorized_agents: vec![AuthorizedAgent::new(
            "node-test",
            &std::fs::read(fixture("agent.pem"))?,
        )],
    };
    let (server_stop, server_shutdown) = oneshot::channel::<()>();
    let server_task = tokio::spawn(async move {
        server
            .serve_listener(listener, async {
                let _ = server_shutdown.await;
            })
            .await
    });
    let identity = std::env::temp_dir().join(format!("o3k-compute-test-{}", uuid::Uuid::now_v7()));
    std::fs::write(&identity, "node-test\n")?;
    let agent = AgentClient::new(AgentConfig {
        endpoint: format!("https://{address}"),
        server_name: "o3k-control-plane".to_owned(),
        tls: TlsFiles {
            ca_certificate: fixture("ca.pem"),
            certificate: fixture("agent-chain.pem"),
            private_key: fixture("agent-key-pkcs8.pem"),
        },
        identity_file: identity.clone(),
        agent_epoch: Some("seed-epoch".to_owned()),
        host_label: "black-box-host".to_owned(),
        software_version: "test".to_owned(),
        heartbeat_interval: Duration::from_millis(50),
        max_reconnect_delay: Duration::from_millis(100),
        capabilities: proto::Capabilities {
            architecture: "x86_64".to_owned(),
            agent_provider_name: "o3k-compute".to_owned(),
            agent_provider_version: "test".to_owned(),
            ..Default::default()
        },
    })?;
    let (agent_stop, agent_shutdown) = oneshot::channel::<()>();
    let agent_task = tokio::spawn({
        let agent = Arc::new(agent);
        async move {
            agent
                .run(async {
                    let _ = agent_shutdown.await;
                })
                .await
        }
    });
    let mut registered = false;
    for _ in 0..40 {
        if let Some(node) = registry.all().await.first() {
            registered = node.availability == o3k_compute_agent::Availability::Available
                && node.last_heartbeat_sequence > 0;
            if registered {
                break;
            }
        }
        time::sleep(Duration::from_millis(25)).await;
    }
    if !registered {
        if server_task.is_finished() {
            eprintln!("server task ended: {:?}", server_task.await);
        }
        return Err("agent did not register and heartbeat".into());
    }
    let node = registry.all().await.pop().ok_or("registered node")?;
    assert_eq!(node.agent_epoch, "seed-epoch");
    assert_eq!(node.host_label, "black-box-host");
    assert_eq!(
        node.last_heartbeat_state,
        proto::AdministrativeState::Draining as i32
    );
    assert_eq!(
        std::fs::read_to_string(o3k_compute_agent::administrative_state_file(&identity))?.trim(),
        (proto::AdministrativeState::Draining as i32).to_string()
    );
    let transition = registry
        .set_desired_state("node-test", proto::AdministrativeState::Disabled)
        .await?;
    for _ in 0..40 {
        if let Some(node) = registry.snapshot("node-test").await
            && node.applied_state == proto::AdministrativeState::Disabled as i32
            && node.transition_sequence == transition
        {
            break;
        }
        time::sleep(Duration::from_millis(25)).await;
    }
    let node = registry
        .snapshot("node-test")
        .await
        .ok_or("registered node")?;
    assert_eq!(
        node.applied_state,
        proto::AdministrativeState::Disabled as i32
    );
    assert_eq!(
        std::fs::read_to_string(o3k_compute_agent::administrative_state_file(&identity))?.trim(),
        (proto::AdministrativeState::Disabled as i32).to_string()
    );
    agent_stop.send(()).map_err(|_| "agent already stopped")?;
    server_stop.send(()).map_err(|_| "server already stopped")?;
    let _ = agent_task.await?;
    let _ = server_task.await?;
    let _ = std::fs::remove_file(o3k_compute_agent::administrative_state_file(&identity));
    let _ = std::fs::remove_file(identity);
    Ok(())
}

#[tokio::test]
async fn untrusted_client_ca_is_rejected_before_registration()
-> Result<(), Box<dyn std::error::Error>> {
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await?;
    let address = listener.local_addr()?;
    let registry = NodeRegistry::default();
    let server = ControlPlaneServer {
        registry: registry.clone(),
        address,
        tls: ControlPlaneTls {
            server_certificate: fixture("server-chain.pem"),
            server_private_key: fixture("server-key.pem"),
            client_ca_certificate: fixture("untrusted-ca.pem"),
        },
        authorized_agents: vec![AuthorizedAgent::new(
            "node-test",
            &std::fs::read(fixture("agent.pem"))?,
        )],
    };
    let (server_stop, server_shutdown) = oneshot::channel::<()>();
    let server_task = tokio::spawn(async move {
        server
            .serve_listener(listener, async {
                let _ = server_shutdown.await;
            })
            .await
    });
    let identity =
        std::env::temp_dir().join(format!("o3k-compute-untrusted-{}", uuid::Uuid::now_v7()));
    std::fs::write(&identity, "node-test\n")?;
    let agent = AgentClient::new(AgentConfig {
        endpoint: format!("https://{address}"),
        server_name: "o3k-control-plane".to_owned(),
        tls: TlsFiles {
            ca_certificate: fixture("ca.pem"),
            certificate: fixture("agent-chain.pem"),
            private_key: fixture("agent-key-pkcs8.pem"),
        },
        identity_file: identity.clone(),
        agent_epoch: None,
        host_label: "untrusted-host".to_owned(),
        software_version: "test".to_owned(),
        heartbeat_interval: Duration::from_millis(25),
        max_reconnect_delay: Duration::from_millis(50),
        capabilities: proto::Capabilities {
            architecture: "x86_64".to_owned(),
            agent_provider_name: "o3k-compute".to_owned(),
            agent_provider_version: "test".to_owned(),
            ..Default::default()
        },
    })?;
    let (agent_stop, agent_shutdown) = oneshot::channel::<()>();
    let agent_task = tokio::spawn(async move {
        agent
            .run(async {
                let _ = agent_shutdown.await;
            })
            .await
    });
    time::sleep(Duration::from_millis(150)).await;
    assert!(registry.all().await.is_empty());
    agent_stop.send(()).map_err(|_| "agent already stopped")?;
    server_stop.send(()).map_err(|_| "server already stopped")?;
    let _ = agent_task.await?;
    let _ = server_task.await?;
    let _ = std::fs::remove_file(identity);
    Ok(())
}
