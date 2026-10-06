use std::{
    path::PathBuf,
    sync::{Arc, Mutex},
    time::Duration,
};

use async_trait::async_trait;
use o3k_compute_agent::{
    AgentClient, AgentComputeProvider, AgentConfig, AuthorizedAgent, ControlPlaneServer,
    ControlPlaneTls, FakeCommandExecutor, NodeRegistry, TlsFiles,
};
use o3k_provider::{
    AgentNodeSnapshot, ArtifactKind, ComputeProvider, CreateArtifactResolver,
    CreateInstanceRequest, NetworkAttachmentSpec, OperationState, ProviderError,
    ResolvedCreateArtifact, ResolvedCreateInputs, ResolvedCreateResolver,
};
use o3k_provider_contract::compute_proto as proto;
use tokio::{sync::oneshot, time};
use uuid::Uuid;

fn fixture(name: &str) -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .join("../o3k-compute-agent/tests/fixtures")
        .join(name)
}

#[derive(Debug)]
struct TestResolver(bool);

#[async_trait]
impl ResolvedCreateResolver for TestResolver {
    async fn resolve(
        &self,
        _request: &CreateInstanceRequest,
        _agent: &AgentNodeSnapshot,
    ) -> Result<ResolvedCreateInputs, ProviderError> {
        Ok(ResolvedCreateInputs {
            flavor_id: "flavor.test".to_owned(),
            image_artifact_id: "artifact.test".to_owned(),
            image_sha256: "af6909578b3b4fc1d8a75a4c975636adc669b7d6ccbabdcc841a3520dafe6b05"
                .to_owned(),
            image_format: "qcow2".to_owned(),
            disk_gib: 10,
            config_drive: self.0.then(|| o3k_provider::ResolvedConfigDrive {
                artifact_id: "config-drive.test".to_owned(),
                sha256: "300ff2a3635c8ab1608e2ea2d00859be4535efd5949e3b149437b66de80bbef4"
                    .to_owned(),
            }),
            network_attachments: vec![NetworkAttachmentSpec {
                port_id: "port.test".to_owned(),
                mac: "52:54:00:12:34:56".to_owned(),
                fixed_ipv4: "192.0.2.10".to_owned(),
                subnet_cidr: "192.0.2.0/24".to_owned(),
                gateway_ipv4: "192.0.2.1".to_owned(),
            }],
        })
    }
}

#[derive(Debug, Default, Clone)]
struct TestArtifactResolver(Arc<Mutex<Vec<Vec<ArtifactKind>>>>);

#[async_trait]
impl CreateArtifactResolver for TestArtifactResolver {
    async fn resolve_artifacts(
        &self,
        _request: &CreateInstanceRequest,
        _agent: &AgentNodeSnapshot,
        inputs: &ResolvedCreateInputs,
    ) -> Result<Vec<ResolvedCreateArtifact>, ProviderError> {
        let mut artifacts = vec![ResolvedCreateArtifact {
            artifact_id: inputs.image_artifact_id.clone(),
            kind: ArtifactKind::ImageBase,
            sha256: inputs.image_sha256.clone(),
            format: inputs.image_format.clone(),
            bytes: b"image-artifact".to_vec(),
        }];
        if let Some(config_drive) = inputs.config_drive.as_ref() {
            artifacts.push(ResolvedCreateArtifact {
                artifact_id: config_drive.artifact_id.clone(),
                kind: ArtifactKind::ConfigDriveIso,
                sha256: config_drive.sha256.clone(),
                format: "iso".to_owned(),
                bytes: b"config-drive-artifact".to_vec(),
            });
        }
        self.0
            .lock()
            .map_err(|_| ProviderError::Storage)?
            .push(artifacts.iter().map(|artifact| artifact.kind).collect());
        Ok(artifacts)
    }
}

#[tokio::test]
async fn agent_provider_command_crosses_mutual_tls_and_observes_completion()
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

    let identity = std::env::temp_dir().join(format!("o3k-agent-mtls-{}", Uuid::now_v7()));
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
        host_label: "mtls-test-host".to_owned(),
        software_version: "test".to_owned(),
        heartbeat_interval: Duration::from_millis(25),
        max_reconnect_delay: Duration::from_millis(50),
        capabilities: proto::Capabilities {
            architecture: "x86_64".to_owned(),
            agent_provider_name: "o3k-compute".to_owned(),
            agent_provider_version: "test".to_owned(),
            max_vcpus: 4,
            max_memory_mib: 4096,
            max_disk_gb: 20,
            flags: vec![proto::CapabilityFlag {
                name: "artifact_transfer".to_owned(),
                supported: true,
                bounded_value: String::new(),
            }],
            ..Default::default()
        },
    })?;
    let executor = FakeCommandExecutor::default();
    let (agent_stop, agent_shutdown) = oneshot::channel::<()>();
    let agent_task = tokio::spawn({
        let agent = Arc::new(agent);
        let executor = Arc::new(executor.clone());
        async move {
            agent
                .run_with_executor(
                    async {
                        let _ = agent_shutdown.await;
                    },
                    executor,
                )
                .await
        }
    });

    for _ in 0..80 {
        if registry
            .snapshot("node-test")
            .await
            .is_some_and(|node| node.availability == o3k_compute_agent::Availability::Available)
        {
            break;
        }
        time::sleep(Duration::from_millis(25)).await;
    }
    assert!(registry.snapshot("node-test").await.is_some());

    let artifact_observations = TestArtifactResolver::default();
    let provider = AgentComputeProvider::new(registry.clone(), Arc::new(TestResolver(true)))
        .with_artifact_resolver(Arc::new(artifact_observations.clone()));
    let operation_id = Uuid::now_v7();
    let server_id = Uuid::now_v7();
    let request = CreateInstanceRequest {
        operation_id,
        o3k_server_id: server_id,
        project_id: "project-a".to_owned(),
        name: "mtls-server".to_owned(),
        vcpus: 1,
        memory_mib: 512,
        flavor_id: String::new(),
        disk_gib: 0,
        image_id: Some("image-a".to_owned()),
        key_name: None,
        keypair_id: None,
        network_ids: vec!["port.test".to_owned()],
        placement_provider_id: Some("node-test".to_owned()),
        placement_allocation_id: Some("allocation-a".to_owned()),
        config_drive: None,
        idempotency_key: "mtls-request".to_owned(),
    };
    let accepted = provider
        .create_instance(request)
        .await
        .map_err(|error| format!("config-drive mTLS create failed: {error:?}"))?;
    assert_eq!(accepted.state, OperationState::Accepted);

    let mut observed = None;
    for _ in 0..80 {
        let operation = provider.get_operation(operation_id).await?;
        if operation.state == OperationState::Succeeded {
            observed = operation.provider_resource_id;
            break;
        }
        time::sleep(Duration::from_millis(25)).await;
    }
    let provider_resource_id = observed.ok_or("agent completion was not observed")?;
    assert_eq!(executor.resource_count(), 1);

    // Exercise the real artifact-transfer protocol with an explicit no-media
    // resolved create. Only the image artifact is offered for this command.
    let no_drive_provider = AgentComputeProvider::new(registry, Arc::new(TestResolver(false)))
        .with_artifact_resolver(Arc::new(artifact_observations.clone()));
    let no_drive_operation_id = Uuid::now_v7();
    let no_drive_server_id = Uuid::now_v7();
    let no_drive_request = CreateInstanceRequest {
        operation_id: no_drive_operation_id,
        o3k_server_id: no_drive_server_id,
        project_id: "project-a".to_owned(),
        name: "mtls-server-no-config-drive".to_owned(),
        vcpus: 1,
        memory_mib: 512,
        flavor_id: String::new(),
        disk_gib: 0,
        image_id: Some("image-a".to_owned()),
        key_name: None,
        keypair_id: None,
        network_ids: vec!["port.test".to_owned()],
        placement_provider_id: Some("node-test".to_owned()),
        placement_allocation_id: Some("allocation-no-drive".to_owned()),
        config_drive: None,
        idempotency_key: "mtls-request-no-config-drive".to_owned(),
    };
    let no_drive_accepted = no_drive_provider
        .create_instance(no_drive_request)
        .await
        .map_err(|error| format!("no-config-drive mTLS create failed: {error:?}"))?;
    assert_eq!(no_drive_accepted.state, OperationState::Accepted);
    let mut no_drive_succeeded = false;
    for _ in 0..80 {
        if no_drive_provider
            .get_operation(no_drive_operation_id)
            .await?
            .state
            == OperationState::Succeeded
        {
            no_drive_succeeded = true;
            break;
        }
        time::sleep(Duration::from_millis(25)).await;
    }
    assert!(
        no_drive_succeeded,
        "no-config-drive create did not complete over mTLS"
    );
    assert_eq!(executor.resource_count(), 2);
    assert_eq!(executor.artifact_count(), 6);
    let artifact_observations = {
        let observations = artifact_observations
            .0
            .lock()
            .map_err(|_| std::io::Error::other("artifact observation lock poisoned"))?;
        observations.clone()
    };
    assert_eq!(
        artifact_observations.as_slice(),
        [
            vec![ArtifactKind::ImageBase, ArtifactKind::ConfigDriveIso],
            vec![ArtifactKind::ImageBase],
        ],
        "the no-config-drive create resolves only the image for mTLS transfer"
    );
    let inspect_operation_id = Uuid::now_v7();
    let accepted_inspect = provider
        .inspect_instance(
            "node-test",
            &server_id.to_string(),
            &provider_resource_id,
            inspect_operation_id,
            "inspect-request",
        )
        .await?;
    assert_eq!(accepted_inspect.state, OperationState::Accepted);
    let mut inspected = None;
    for _ in 0..80 {
        let operation = provider.get_operation(inspect_operation_id).await?;
        if operation.state == OperationState::Succeeded {
            inspected = Some(operation);
            break;
        }
        time::sleep(Duration::from_millis(25)).await;
    }
    let inspected = inspected.ok_or("agent inspect completion was not observed")?;
    assert_eq!(
        inspected.provider_resource_id.as_deref(),
        Some(provider_resource_id.as_str())
    );
    println!(
        "O3K_AGENT_MTLS_EVIDENCE={}",
        serde_json::json!({
            "status": "passed",
            "transport": "mutual_tls",
            "command_state": "accepted",
            "observation_state": "succeeded",
            "provider_resource_id": provider_resource_id,
            "redacted": true,
        })
    );

    agent_stop.send(()).map_err(|_| "agent already stopped")?;
    server_stop.send(()).map_err(|_| "server already stopped")?;
    let _ = agent_task.await?;
    let _ = server_task.await?;
    let _ = std::fs::remove_file(&identity);
    let _ = std::fs::remove_file(o3k_compute_agent::administrative_state_file(&identity));
    Ok(())
}
