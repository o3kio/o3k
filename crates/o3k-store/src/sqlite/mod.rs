//! SQLite persistence adapter for the O3K store.

//! This module owns the stable SqliteStore facade and assembles the
//! responsibility-oriented SQLite implementation modules.

use sqlx::SqlitePool;
use std::sync::Arc;

mod audit_store;
mod building_block;
mod composition;
mod core;
mod helpers;
mod identity;
mod image;
mod metering;
mod network;
mod placement;
mod relationship;
mod topology;
mod volume_attachment;

pub use helpers::validate_public_key;
pub(crate) use helpers::{
    checked_generation, map_canonical_insert_error, parse_uuid, sqlite_sequence,
    validate_canonical_state, validate_ipv4_cidr, validate_network_intent_transition,
    validate_network_intent_update,
};

#[derive(Clone, Debug)]
pub struct SqliteStore {
    pub(crate) pool: SqlitePool,
    agent_command_projection_lock: Arc<tokio::sync::Mutex<()>>,
}
