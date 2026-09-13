//! Canonical Cloud Kernel bootstrap and enrollment contracts.
//!
//! This module deliberately contains no transport, database, or certificate
//! implementation.  Adapters persist these values and perform the bounded
//! side effects through the existing IAM, topology, Placement, and
//! BuildingBlock authorities.

use std::collections::BTreeMap;

use serde::{Deserialize, Serialize};
use thiserror::Error;
use uuid::Uuid;

/// Durable phase of the control-plane bootstrap workflow.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum BootstrapPhase {
    Uninitialized,
    Initialized,
    Enrolling,
    Ready,
    Failed,
}

/// Canonical bootstrap state.  It is intentionally a projection of existing
/// authorities, not an inventory or topology database.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct BootstrapState {
    pub generation: u64,
    pub phase: BootstrapPhase,
    pub cloud_identity_id: String,
    pub cloud_profile_id: String,
    pub enrolled_agents: BTreeMap<String, String>,
}

impl BootstrapState {
    pub fn uninitialized() -> Self {
        Self {
            generation: 0,
            phase: BootstrapPhase::Uninitialized,
            cloud_identity_id: String::new(),
            cloud_profile_id: String::new(),
            enrolled_agents: BTreeMap::new(),
        }
    }

    /// Applies init idempotently.  A different profile or identity is a
    /// conflict, never an implicit replacement of the canonical cloud.
    pub fn initialize(
        &mut self,
        cloud_identity_id: &str,
        cloud_profile_id: &str,
    ) -> Result<(), BootstrapError> {
        validate_id(cloud_identity_id, "cloud identity")?;
        validate_id(cloud_profile_id, "cloud profile")?;
        if self.phase != BootstrapPhase::Uninitialized
            && (self.cloud_identity_id != cloud_identity_id
                || self.cloud_profile_id != cloud_profile_id)
        {
            return Err(BootstrapError::Conflict);
        }
        let was_uninitialized = self.phase == BootstrapPhase::Uninitialized;
        self.cloud_identity_id = cloud_identity_id.to_owned();
        self.cloud_profile_id = cloud_profile_id.to_owned();
        if was_uninitialized {
            self.phase = BootstrapPhase::Initialized;
            self.generation = self.generation.saturating_add(1);
        }
        Ok(())
    }

    pub fn begin_enrollment(&mut self) -> Result<(), BootstrapError> {
        if self.phase == BootstrapPhase::Uninitialized {
            return Err(BootstrapError::NotInitialized);
        }
        if self.phase != BootstrapPhase::Ready {
            self.phase = BootstrapPhase::Enrolling;
            self.generation = self.generation.saturating_add(1);
        }
        Ok(())
    }

    pub fn record_agent(
        &mut self,
        agent_id: &str,
        certificate_fingerprint: &str,
    ) -> Result<(), BootstrapError> {
        validate_id(agent_id, "agent")?;
        validate_id(certificate_fingerprint, "certificate fingerprint")?;
        if let Some(previous) = self.enrolled_agents.get(agent_id)
            && previous != certificate_fingerprint
        {
            return Err(BootstrapError::Conflict);
        }
        self.enrolled_agents
            .insert(agent_id.to_owned(), certificate_fingerprint.to_owned());
        self.phase = BootstrapPhase::Ready;
        self.generation = self.generation.saturating_add(1);
        Ok(())
    }

    pub fn is_ready(&self) -> bool {
        self.phase == BootstrapPhase::Ready
    }
}

/// Single-purpose, short-lived enrollment grant.  Only the digest is stored;
/// the bearer token itself must never be persisted or logged.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct EnrollmentGrant {
    pub grant_id: Uuid,
    pub agent_id: String,
    pub token_digest: String,
    pub issued_at_unix_ms: u64,
    pub expires_at_unix_ms: u64,
    pub used_at_unix_ms: Option<u64>,
}

impl EnrollmentGrant {
    pub fn new(
        agent_id: &str,
        token_digest: String,
        now_unix_ms: u64,
        ttl_ms: u64,
    ) -> Result<Self, BootstrapError> {
        validate_id(agent_id, "agent")?;
        if token_digest.trim().is_empty() || ttl_ms == 0 {
            return Err(BootstrapError::InvalidGrant);
        }
        Ok(Self {
            grant_id: Uuid::new_v4(),
            agent_id: agent_id.to_owned(),
            token_digest,
            issued_at_unix_ms: now_unix_ms,
            expires_at_unix_ms: now_unix_ms.saturating_add(ttl_ms),
            used_at_unix_ms: None,
        })
    }

    pub fn consume(
        &mut self,
        token_digest: &str,
        agent_id: &str,
        now_unix_ms: u64,
    ) -> Result<(), BootstrapError> {
        if self.used_at_unix_ms.is_some() || now_unix_ms >= self.expires_at_unix_ms {
            return Err(BootstrapError::GrantExpired);
        }
        if self.agent_id != agent_id || self.token_digest != token_digest {
            return Err(BootstrapError::Unauthorized);
        }
        self.used_at_unix_ms = Some(now_unix_ms);
        Ok(())
    }
}

#[derive(Debug, Error, PartialEq, Eq)]
pub enum BootstrapError {
    #[error("bootstrap identifier is invalid")]
    InvalidIdentifier,
    #[error("bootstrap is not initialized")]
    NotInitialized,
    #[error("bootstrap state conflicts with canonical identity")]
    Conflict,
    #[error("enrollment grant is invalid")]
    InvalidGrant,
    #[error("enrollment grant is expired or already used")]
    GrantExpired,
    #[error("enrollment grant is not authorized for this agent")]
    Unauthorized,
}

fn validate_id(value: &str, _kind: &str) -> Result<(), BootstrapError> {
    let trimmed = value.trim();
    if trimmed.is_empty() || trimmed.len() > 256 || trimmed != value {
        return Err(BootstrapError::InvalidIdentifier);
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn init_and_join_are_idempotent() -> Result<(), BootstrapError> {
        let mut state = BootstrapState::uninitialized();
        state.initialize("cloud", "default")?;
        state.initialize("cloud", "default")?;
        state.begin_enrollment()?;
        state.record_agent("node-1", "a".repeat(64).as_str())?;
        state.record_agent("node-1", "a".repeat(64).as_str())?;
        assert!(state.is_ready());
        let generation = state.generation;
        state.initialize("cloud", "default")?;
        assert!(state.is_ready());
        assert_eq!(state.generation, generation);
        Ok(())
    }

    #[test]
    fn grants_are_single_use_and_bound() -> Result<(), BootstrapError> {
        let mut grant = EnrollmentGrant::new("node-1", "digest".into(), 10, 100)?;
        assert_eq!(
            grant.consume("wrong", "node-1", 20),
            Err(BootstrapError::Unauthorized)
        );
        grant.consume("digest", "node-1", 20)?;
        assert_eq!(
            grant.consume("digest", "node-1", 21),
            Err(BootstrapError::GrantExpired)
        );
        Ok(())
    }
}
