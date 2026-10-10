use std::path::PathBuf;
use thiserror::Error;

#[derive(Debug, Error)]
pub enum StoreError {
    #[error("database error")]
    Database(#[source] sqlx::Error),
    #[error("database migration error")]
    Migration(#[source] sqlx::migrate::MigrateError),
    #[error("resource not found")]
    ResourceNotFound,
    #[error("operation not found")]
    OperationNotFound,
    #[error("resource generation is stale")]
    StaleGeneration,
    #[error("resource already exists")]
    ResourceAlreadyExists,
    #[error("idempotency key conflicts with an existing request")]
    IdempotencyConflict,
    #[error("provider reference already exists")]
    ProviderReferenceAlreadyExists,
    #[error("provider reference not found")]
    ProviderReferenceNotFound,
    #[error("cannot create data directory {path}: {source}")]
    CreateDataDirectory {
        path: PathBuf,
        source: std::io::Error,
    },
    #[error("invalid UUID in durable state")]
    InvalidUuid(#[source] uuid::Error),
    #[error("corrupt durable state: {0}")]
    Corrupt(String),
    #[error("audit event identifier conflicts with existing event")]
    AuditEventConflict,
    #[error("keypair not found")]
    KeypairNotFound,
    #[error("keypair already exists")]
    KeypairAlreadyExists,
    #[error("invalid keypair: {0}")]
    InvalidKeypair(String),
    #[error("keypair is still attached to a server")]
    KeypairInUse,
    #[error("keypair and server ownership do not match")]
    KeypairOwnershipConflict,
    #[error("canonical network ownership conflict")]
    OwnershipConflict,
    #[error("attached policies have incompatible unmatched actions")]
    PolicyCompositionConflict,
    #[error("image not found")]
    ImageNotFound,
    #[error("image is already active")]
    ImageAlreadyActive,
    #[error("artifact transfer not found")]
    ArtifactTransferNotFound,
    #[error("artifact transfer epoch does not match durable state")]
    ArtifactTransferEpochConflict,
    #[error("artifact transfer conflict: {0}")]
    ArtifactTransferConflict(String),
    #[error("invalid artifact transfer: {0}")]
    InvalidArtifactTransfer(String),
    #[error("image overlay ownership not found")]
    ImageOverlayNotFound,
    #[error("image overlay ownership epoch does not match durable state")]
    ImageOverlayEpochConflict,
    #[error("image overlay ownership conflict: {0}")]
    ImageOverlayConflict(String),
    #[error("invalid image overlay ownership: {0}")]
    InvalidImageOverlay(String),
    #[error("network resource not found")]
    NetworkNotFound,
    #[error("network resource is still in use")]
    NetworkInUse,
    #[error("network intent not found")]
    NetworkIntentNotFound,
    #[error("network address pool is exhausted")]
    NetworkAddressExhausted,
    #[error("network address allocation conflict")]
    NetworkAddressConflict,
    #[error("placement provider not found")]
    PlacementProviderNotFound,
    #[error("placement provider generation is stale")]
    PlacementStaleGeneration,
    #[error("placement allocation conflicts with existing allocation")]
    PlacementAllocationConflict,
    #[error("placement allocation intent conflicts with existing intent")]
    PlacementIntentConflict,
    #[error("placement allocation referenced by the create intent no longer exists")]
    PlacementAllocationNotFound,
    #[error("quota exceeded for {key}: limit {limit}, used {used}, requested {requested}")]
    QuotaExceeded {
        key: o3k_kernel::LimitKey,
        limit: o3k_kernel::LimitValue,
        used: u64,
        requested: u64,
    },
    #[error("quota limit generation is stale")]
    QuotaGenerationConflict,
    #[error("reservation conflict for operation {0}")]
    ReservationConflict(String),
    #[error("reservation not found")]
    ReservationNotFound,
    #[error("durable work lease no longer owns this transition")]
    Fenced,
}
