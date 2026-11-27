use o3k_controller_protocol::storage::{
    ExecuteResponse, StorageCommand, StorageObservation as WireObservation,
    storage_executor_server::{StorageExecutor, StorageExecutorServer},
};
use o3k_domain::StorageCommandEnvelope;
use o3k_storage::{
    LvmConfig, LvmStorageProvider, StorageJournal, StorageProvider, StorageVolumeRequest,
};
use sha2::{Digest, Sha256};
use std::{env, net::SocketAddr, path::PathBuf, sync::Arc};
use tonic::transport::{Certificate, Identity, Server, ServerTlsConfig};
use tonic::{Request, Response, Status};

#[derive(Clone)]
struct Executor {
    journal: Arc<StorageJournal>,
    agent_id: String,
    agent_epoch: u64,
    provider: Arc<LvmStorageProvider>,
}

#[tonic::async_trait]
impl StorageExecutor for Executor {
    async fn execute(
        &self,
        request: Request<StorageCommand>,
    ) -> Result<Response<ExecuteResponse>, Status> {
        let command = request.into_inner();
        let envelope: StorageCommandEnvelope = serde_json::from_slice(&command.envelope_json)
            .map_err(|_| Status::invalid_argument("invalid storage command envelope"))?;
        let payload: StorageVolumeRequest = serde_json::from_slice(&command.payload_json)
            .map_err(|_| Status::invalid_argument("invalid storage payload"))?;
        if payload.volume_id.to_string() != envelope.resource_id
            || payload.project_id != envelope.project_id
            || payload.generation != envelope.resource_generation
            || hex::encode(Sha256::digest(&command.payload_json))
                != envelope.canonical_payload_fingerprint
        {
            return Err(Status::invalid_argument(
                "storage payload does not match command envelope",
            ));
        }
        if let Some(existing) = self
            .journal
            .get(&envelope.idempotency_key)
            .map_err(|_| Status::internal("journal lookup failed"))?
            && !matches!(
                existing.operation_state,
                o3k_domain::StorageOperationState::Accepted
                    | o3k_domain::StorageOperationState::Running
            )
        {
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
            .accept(envelope.clone(), &self.agent_id, self.agent_epoch)
            .map_err(|_| Status::failed_precondition("storage command fenced or conflicting"))?;
        let result = match envelope.action {
            o3k_domain::StorageAction::CreateVolume => {
                self.provider.create_volume(&payload).await.map(|_| ())
            }
            o3k_domain::StorageAction::InspectVolume => {
                self.provider.inspect_volume(&payload).await.map(|_| ())
            }
            o3k_domain::StorageAction::DeleteVolume => self.provider.delete_volume(&payload).await,
            _ => Err(o3k_storage::StorageProviderError::InvalidRequest),
        };
        let mut terminal = observation;
        terminal.observation_sequence = 2;
        terminal.operation_state = if result.is_ok() {
            o3k_domain::StorageOperationState::Succeeded
        } else {
            o3k_domain::StorageOperationState::Failed
        };
        terminal.resource_state = if result.is_ok() {
            "available"
        } else {
            "unknown"
        }
        .to_owned();
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
        agent_epoch: env::var("O3K_STORAGE_AGENT_EPOCH")?.parse()?,
        provider: Arc::new(LvmStorageProvider::new(LvmConfig {
            volume_group: env::var("O3K_STORAGE_VOLUME_GROUP")?,
            thin_pool: env::var("O3K_STORAGE_THIN_POOL")?,
            provider_namespace: env::var("O3K_STORAGE_NAMESPACE").unwrap_or_else(|_| "o3k".into()),
        })?),
    };
    tracing_subscriber::fmt::init();
    let cert = std::fs::read(env::var("O3K_STORAGE_TLS_CERT")?)?;
    let key = std::fs::read(env::var("O3K_STORAGE_TLS_KEY")?)?;
    let ca = std::fs::read(env::var("O3K_STORAGE_TLS_CLIENT_CA")?)?;
    let tls = ServerTlsConfig::new()
        .identity(Identity::from_pem(cert, key))
        .client_ca_root(Certificate::from_pem(ca));
    Server::builder()
        .tls_config(tls)?
        .add_service(StorageExecutorServer::new(executor))
        .serve(address)
        .await?;
    Ok(())
}
