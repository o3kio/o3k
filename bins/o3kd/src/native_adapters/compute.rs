use std::sync::Arc;

use o3k_native_api::{compute::ServerItem, error::NativeReadError};
use uuid::Uuid;

fn native_server_state(state: o3k_domain::ServerState) -> String {
    o3k_store::server_state_to_storage(state).to_owned()
}

/// Store-backed adapter for native Compute server reads.
pub struct ServerReaderAdapter {
    pub service: Arc<o3k_compute::ComputeService>,
}

/// Composition-root application adapter for generic native reads. It delegates
/// only to canonical native application/read ports; it never reaches a
/// provider or controller directly. Mutations remain unsupported until a
/// canonical mutation service is wired for the resource.
#[async_trait::async_trait]
impl o3k_native_api::compute::ServerReader for ServerReaderAdapter {
    async fn show_server(
        &self,
        auth: &o3k_kernel::AuthContext,
        id: Uuid,
    ) -> Result<ServerItem, NativeReadError> {
        match self
            .service
            .show_server_for_auth(auth, o3k_domain::ServerId::from_uuid(id))
            .await
        {
            Ok(s) => {
                let generation = self.service.server_generation_for_auth(auth, s.id).await
                    .map_err(|error| {
                        tracing::error!(%error, server_id = %id, "native server metadata read failed");
                        NativeReadError::Internal
                    })?;
                let (migration_id, source_key) = self
                    .service
                    .server_migration_metadata_for_auth(auth, s.id)
                    .await
                    .map_err(|error| {
                        tracing::error!(%error, server_id = %id, "native server ownership metadata read failed");
                        NativeReadError::Internal
                    })?;
                Ok(ServerItem {
                    id: id.to_string(),
                    name: s.name,
                    project_id: s.project_id,
                    flavor_id: s.flavor_id.to_string(),
                    image_id: s.image_id,
                    // Native compute status uses the same Nova-compatible
                    // uppercase lifecycle projection as the durable store.
                    // Serializing `ServerState` directly would expose its
                    // Rust/serde snake_case spelling ("active"), which is
                    // not the public compute contract and causes real
                    // clients to wait forever for ACTIVE.
                    state: native_server_state(s.state),
                    created_at: None,
                    generation,
                    migration_id,
                    source_key,
                })
            }
            Err(e) => {
                tracing::error!(error = %e, server_id = %id, "native server show failed");
                Err(match e {
                    o3k_compute::ComputeError::Unauthorized
                    | o3k_compute::ComputeError::NotFound => NativeReadError::NotFound,
                    _ => NativeReadError::Internal,
                })
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::native_server_state;
    use o3k_domain::ServerState;

    #[test]
    fn native_compute_state_uses_public_uppercase_projection() {
        assert_eq!(native_server_state(ServerState::Active), "ACTIVE");
        assert_eq!(native_server_state(ServerState::Stopped), "SHUTOFF");
        assert_eq!(native_server_state(ServerState::Building), "BUILD");
    }
}
