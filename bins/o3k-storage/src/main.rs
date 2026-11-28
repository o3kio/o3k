use o3k_controller_protocol::storage::{
    ExecuteResponse, StorageCommand, StorageObservation as WireObservation,
    storage_executor_server::{StorageExecutor, StorageExecutorServer},
};
use o3k_domain::{StorageAction, StorageCommandEnvelope, StorageCommandPayload};
use o3k_storage::storage_payload_fingerprint;
use o3k_storage::{
    LvmConfig, LvmStorageProvider, StorageAttachmentRequest, StorageJournal, StorageProvider,
    StorageVolumeRequest,
};
use openssl::x509::X509;
use std::{env, net::SocketAddr, path::PathBuf, sync::Arc};
use tonic::transport::{Certificate, Identity, Server, ServerTlsConfig};
use tonic::{Request, Response, Status};

#[derive(Clone)]
struct Executor {
    journal: Arc<StorageJournal>,
    agent_id: String,
    agent_epoch: String,
    provider: Arc<LvmStorageProvider>,
    controller_identity: String,
}

#[tonic::async_trait]
impl StorageExecutor for Executor {
    async fn execute(
        &self,
        request: Request<StorageCommand>,
    ) -> Result<Response<ExecuteResponse>, Status> {
        let peer_certs = request
            .peer_certs()
            .ok_or_else(|| Status::unauthenticated("controller client certificate missing"))?;
        let peer = peer_certs
            .first()
            .ok_or_else(|| Status::unauthenticated("controller client certificate missing"))?;
        let cert = X509::from_der(peer.as_ref())
            .map_err(|_| Status::unauthenticated("invalid controller client certificate"))?;
        let identity_ok = cert
            .subject_alt_names()
            .map(|names| {
                names
                    .iter()
                    .any(|name| name.uri() == Some(self.controller_identity.as_str()))
            })
            .unwrap_or(false);
        if !identity_ok {
            return Err(Status::permission_denied(
                "controller certificate identity mismatch",
            ));
        }
        let command = request.into_inner();
        let envelope: StorageCommandEnvelope = serde_json::from_slice(&command.envelope_json)
            .map_err(|_| Status::invalid_argument("invalid storage command envelope"))?;
        envelope
            .validate_for_rpc()
            .map_err(|_| Status::invalid_argument("invalid storage command envelope"))?;
        let payload: StorageCommandPayload = serde_json::from_slice(&command.payload_json)
            .map_err(|_| Status::invalid_argument("invalid storage payload"))?;
        if storage_payload_fingerprint(&payload)
            .map_err(|_| Status::invalid_argument("invalid storage payload"))?
            != envelope.canonical_payload_fingerprint
        {
            return Err(Status::invalid_argument(
                "storage payload does not match command envelope",
            ));
        }
        let (resource_id, project_id, generation) = match &payload {
            StorageCommandPayload::Volume(p) => {
                (p.volume_id.to_string(), p.project_id.as_str(), p.generation)
            }
            StorageCommandPayload::Attachment(p) => (
                p.attachment_id.to_string(),
                p.project_id.as_str(),
                p.volume_generation,
            ),
        };
        if resource_id != envelope.resource_id
            || project_id != envelope.project_id
            || generation != envelope.resource_generation
        {
            return Err(Status::invalid_argument(
                "storage payload does not match command envelope",
            ));
        }
        if let Some(existing) = self
            .journal
            .get(&envelope.idempotency_key)
            .map_err(|_| Status::internal("journal lookup failed"))?
        {
            // Accepted/Running means the provider side effect may have happened
            // before this process lost the response.  Never replay a mutation
            // blindly: return an explicit unknown outcome for controller
            // reconciliation/inspection.
            if matches!(
                existing.operation_state,
                o3k_domain::StorageOperationState::Accepted
                    | o3k_domain::StorageOperationState::Running
            ) {
                let mut unknown = existing;
                unknown.operation_state = o3k_domain::StorageOperationState::UnknownOutcome;
                unknown.resource_state = "unknown".to_owned();
                self.journal
                    .record_observation(&envelope.idempotency_key, unknown.clone())
                    .map_err(|_| Status::internal("journal outcome persistence failed"))?;
                let bytes = serde_json::to_vec(&unknown)
                    .map_err(|_| Status::internal("observation encoding failed"))?;
                return Ok(Response::new(ExecuteResponse {
                    observation: Some(WireObservation {
                        observation_json: bytes,
                    }),
                    error: String::new(),
                }));
            }
            let bytes = serde_json::to_vec(&existing)
                .map_err(|_| Status::internal("observation encoding failed"))?;
            return Ok(Response::new(ExecuteResponse {
                observation: Some(WireObservation {
                    observation_json: bytes,
                }),
                error: String::new(),
            }));
        }
        let observation = self
            .journal
            .accept(envelope.clone(), &self.agent_id, &self.agent_epoch)
            .map_err(|_| Status::failed_precondition("storage command fenced or conflicting"))?;
        let mut provider_resource_id = None;
        let mut device_path = None;
        let mut resource_state = "available".to_owned();
        let result = match (envelope.action, payload) {
            (StorageAction::CreateVolume, StorageCommandPayload::Volume(p)) => self
                .provider
                .create_volume(&StorageVolumeRequest {
                    volume_id: p.volume_id,
                    project_id: p.project_id,
                    size_bytes: p.size_bytes,
                    generation: p.generation,
                })
                .await
                .map(|o| {
                    provider_resource_id = Some(o.provider_reference.resource_id);
                }),
            (StorageAction::InspectVolume, StorageCommandPayload::Volume(p)) => self
                .provider
                .inspect_volume(&StorageVolumeRequest {
                    volume_id: p.volume_id,
                    project_id: p.project_id,
                    size_bytes: p.size_bytes,
                    generation: p.generation,
                })
                .await
                .map(|o| {
                    provider_resource_id = Some(o.provider_reference.resource_id);
                }),
            (StorageAction::DeleteVolume, StorageCommandPayload::Volume(p)) => {
                self.provider
                    .delete_volume(&StorageVolumeRequest {
                        volume_id: p.volume_id,
                        project_id: p.project_id,
                        size_bytes: p.size_bytes,
                        generation: p.generation,
                    })
                    .await
            }
            (action, StorageCommandPayload::Attachment(p))
                if matches!(
                    action,
                    StorageAction::PrepareAttachment
                        | StorageAction::TerminateAttachment
                        | StorageAction::Reconcile
                ) =>
            {
                let request = StorageAttachmentRequest {
                    attachment_id: p.attachment_id,
                    volume_id: p.volume_id,
                    project_id: p.project_id,
                    volume_generation: p.volume_generation,
                    host_id: p.server_id.to_string(),
                    access_mode: p.access_mode,
                };
                match action {
                    StorageAction::PrepareAttachment => {
                        self.provider.prepare_attachment(&request).await.map(|o| {
                            provider_resource_id = Some(o.provider_reference.resource_id.clone());
                            device_path = Some(o.device_path().to_owned());
                            resource_state = "attached".to_owned();
                        })
                    }
                    StorageAction::TerminateAttachment => {
                        self.provider.terminate_attachment(&request).await.map(|o| {
                            provider_resource_id = Some(o.provider_reference.resource_id);
                            resource_state = "available".to_owned();
                        })
                    }
                    StorageAction::Reconcile => {
                        self.provider.inspect_attachment(&request).await.map(|o| {
                            provider_resource_id = Some(o.provider_reference.resource_id);
                            resource_state =
                                if o.attached { "attached" } else { "available" }.to_owned();
                        })
                    }
                    _ => unreachable!(),
                }
            }
            _ => Err(o3k_storage::StorageProviderError::InvalidRequest),
        };
        let mut terminal = observation;
        terminal.observation_sequence = 2;
        terminal.operation_state = if result.is_ok() {
            o3k_domain::StorageOperationState::Succeeded
        } else if result
            .as_ref()
            .err()
            .is_some_and(o3k_storage::StorageProviderError::is_unknown_outcome)
        {
            o3k_domain::StorageOperationState::UnknownOutcome
        } else {
            o3k_domain::StorageOperationState::Failed
        };
        terminal.resource_state = if result.is_ok() {
            resource_state
        } else {
            "unknown".to_owned()
        };
        terminal.provider_resource_id = provider_resource_id;
        terminal.device_path = device_path;
        self.journal
            .record_observation(&envelope.idempotency_key, terminal.clone())
            .map_err(|_| Status::internal("journal outcome persistence failed"))?;
        let bytes = serde_json::to_vec(&terminal)
            .map_err(|_| Status::internal("observation encoding failed"))?;
        Ok(Response::new(ExecuteResponse {
            observation: Some(WireObservation {
                observation_json: bytes,
            }),
            error: String::new(),
        }))
    }
}

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    // Feature unification can expose multiple Rustls crypto providers in
    // workspace/all-features builds. Select the same explicit provider as the
    // other O3K daemons before tonic constructs the server TLS state.
    let _ = rustls::crypto::ring::default_provider().install_default();
    let address: SocketAddr = env::var("O3K_STORAGE_LISTEN")
        .unwrap_or_else(|_| "127.0.0.1:9444".into())
        .parse()?;
    let journal = PathBuf::from(
        env::var("O3K_STORAGE_JOURNAL")
            .unwrap_or_else(|_| "/var/lib/o3k/storage-journal.json".into()),
    );
    let executor = Executor {
        journal: Arc::new(StorageJournal::open(journal)?),
        agent_id: env::var("O3K_STORAGE_AGENT_ID")?,
        agent_epoch: env::var("O3K_STORAGE_AGENT_EPOCH")
            .ok()
            .filter(|epoch| !epoch.trim().is_empty())
            .ok_or("O3K_STORAGE_AGENT_EPOCH is required")?,
        provider: Arc::new(LvmStorageProvider::new(LvmConfig {
            volume_group: env::var("O3K_STORAGE_VOLUME_GROUP")?,
            thin_pool: env::var("O3K_STORAGE_THIN_POOL")?,
            provider_namespace: env::var("O3K_STORAGE_NAMESPACE").unwrap_or_else(|_| "o3k".into()),
        })?),
        controller_identity: env::var("O3K_STORAGE_CONTROLLER_IDENTITY")?,
    };
    tracing_subscriber::fmt::init();
    let cert = std::fs::read(env::var("O3K_STORAGE_TLS_CERT")?)?;
    let key = std::fs::read(env::var("O3K_STORAGE_TLS_KEY")?)?;
    let ca = std::fs::read(env::var("O3K_STORAGE_TLS_CLIENT_CA")?)?;
    let tls = ServerTlsConfig::new()
        .identity(Identity::from_pem(cert, key))
        .client_ca_root(Certificate::from_pem(ca))
        .client_auth_optional(false);
    Server::builder()
        .tls_config(tls)?
        .add_service(StorageExecutorServer::new(executor))
        .serve(address)
        .await?;
    Ok(())
}
