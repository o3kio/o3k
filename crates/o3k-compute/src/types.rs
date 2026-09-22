//! Compute-domain types: flavors, keypairs, server creation input,
//! compute error types.
//!
//! ## Boundary
//!
//! Reconciler-domain types (journal events, lifecycle actions, reconcile
//! errors) live in `o3k-reconciler::types`.

use serde::{Deserialize, Serialize};

use o3k_domain::Server;
use o3k_kernel::{LimitKey, LimitValue};
use o3k_provider::{ConfigDriveRequest, ProviderError};
use o3k_reconciler::ReconcileError;
use o3k_scheduler::SchedulerError;
use o3k_store::StoreError;
use thiserror::Error;
use uuid::Uuid;

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct Flavor {
    pub id: Uuid,
    pub name: String,
    pub vcpus: u32,
    pub ram_mib: u64,
    pub disk_gib: u64,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct Keypair {
    pub id: Uuid,
    pub user_id: String,
    pub project_id: String,
    pub name: String,
    pub key_type: String,
    pub public_key: String,
    pub fingerprint: String,
    pub created_at: String,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ServerCreateInput {
    pub user_id: String,
    pub project_id: String,
    pub name: String,
    pub image_id: String,
    pub flavor_id: Uuid,
    pub network_ids: Vec<String>,
    pub key_name: Option<String>,
    pub config_drive: Option<ConfigDriveRequest>,
    pub idempotency_key: String,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct MutationReceipt<T> {
    pub resource: T,
    pub operation_id: Uuid,
    pub operation_state: o3k_store::OperationState,
    pub replayed: bool,
}

pub(crate) struct CreateMutationReceipt {
    pub(crate) server: Server,
    pub(crate) operation_id: Uuid,
    pub(crate) operation_state: o3k_store::OperationState,
    pub(crate) replayed: bool,
}

#[derive(Debug, Error)]
pub enum ComputeError {
    #[error("unauthorized")]
    Unauthorized,
    #[error("compute resource was not found")]
    NotFound,
    #[error("compute request conflicts with existing state")]
    Conflict,
    #[error("compute request is invalid")]
    InvalidRequest,
    #[error("quota exceeded for {key}: limit {limit}, used {used}, requested {requested}")]
    QuotaExceeded {
        key: LimitKey,
        limit: LimitValue,
        used: u64,
        requested: u64,
    },
    #[error("compute store error")]
    Store(#[from] StoreError),
    #[error("compute reconciliation error")]
    Reconcile(#[from] ReconcileError),
    #[error("compute provider error")]
    Provider(#[from] ProviderError),
    #[error("compute scheduler error")]
    Scheduler(#[from] SchedulerError),
    #[error("metering projection failed: {0}")]
    Metering(String),
    #[error("server network dependency release failed: {0}")]
    EndpointRelease(String),
    #[error("compute service is unavailable or misconfigured")]
    Unavailable,
}
