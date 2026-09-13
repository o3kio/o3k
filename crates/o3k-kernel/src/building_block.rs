//! Cloud Kernel deployment Building Block lifecycle.
//!
//! A Building Block is deliberately a link/lifecycle object.  It owns neither
//! placement capacity, topology, agent identity nor desired service state;
//! those authorities remain in Placement, LocationRegistry, the authenticated
//! agent registry and CloudProfile respectively (ADR-0184/SPEC-0047).

use std::collections::BTreeSet;

use serde::{Deserialize, Serialize};
use thiserror::Error;

pub const MAX_BUILDING_BLOCK_ID_BYTES: usize = 128;
pub const MAX_BUILDING_BLOCK_REFS: usize = 256;
pub const MAX_DRAIN_BLOCKERS: usize = 16;

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum BuildingBlockState {
    Enrolling,
    Ready,
    Unavailable,
    Draining,
    Removed,
    Failed,
}

impl BuildingBlockState {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Enrolling => "enrolling",
            Self::Ready => "ready",
            Self::Unavailable => "unavailable",
            Self::Draining => "draining",
            Self::Removed => "removed",
            Self::Failed => "failed",
        }
    }
}

impl std::fmt::Display for BuildingBlockState {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(self.as_str())
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum DrainBlockerKind {
    Workload,
    LocalStorage,
    Attachment,
}

impl DrainBlockerKind {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Workload => "workload",
            Self::LocalStorage => "local_storage",
            Self::Attachment => "attachment",
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct DrainBlocker {
    pub kind: DrainBlockerKind,
    pub count: u64,
}

#[derive(Debug, Error, Clone, PartialEq, Eq)]
pub enum BuildingBlockError {
    #[error("building block identifier is invalid")]
    InvalidId,
    #[error("building block reference is invalid")]
    InvalidReference,
    #[error("building block has too many references")]
    TooManyReferences,
    #[error("building block has too many drain blockers")]
    TooManyBlockers,
    #[error("building block generation overflow")]
    GenerationOverflow,
    #[error("invalid building block lifecycle transition")]
    InvalidTransition,
    #[error("building block drain is blocked")]
    DrainBlocked(Vec<DrainBlocker>),
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct BuildingBlock {
    pub id: String,
    pub generation: u64,
    pub state: BuildingBlockState,
    /// Existing authenticated execution identity (normally an agent ID).
    pub execution_identity: String,
    /// Existing Placement provider IDs.  Capacity is never copied here.
    #[serde(default)]
    pub resource_provider_ids: Vec<String>,
    /// Existing canonical LocationRegistry failure-domain ID.
    #[serde(default)]
    pub failure_domain_id: Option<String>,
    /// Existing desired CloudProfile ID, if the block participates in one.
    #[serde(default)]
    pub cloud_profile_id: Option<String>,
    /// Last observed blockers.  These are evidence for drain decisions, not
    /// an evacuation plan or a second workload inventory.
    #[serde(default)]
    pub drain_blockers: Vec<DrainBlocker>,
}

impl BuildingBlock {
    pub fn enrolling(
        id: impl Into<String>,
        execution_identity: impl Into<String>,
        resource_provider_ids: Vec<String>,
        failure_domain_id: Option<String>,
        cloud_profile_id: Option<String>,
    ) -> Result<Self, BuildingBlockError> {
        let block = Self {
            id: id.into(),
            generation: 1,
            state: BuildingBlockState::Enrolling,
            execution_identity: execution_identity.into(),
            resource_provider_ids,
            failure_domain_id,
            cloud_profile_id,
            drain_blockers: Vec::new(),
        };
        block.validate()?;
        Ok(block)
    }

    pub fn validate(&self) -> Result<(), BuildingBlockError> {
        if !valid_ref(&self.id) || self.id.len() > MAX_BUILDING_BLOCK_ID_BYTES {
            return Err(BuildingBlockError::InvalidId);
        }
        if !valid_ref(&self.execution_identity) {
            return Err(BuildingBlockError::InvalidReference);
        }
        if self.resource_provider_ids.len() > MAX_BUILDING_BLOCK_REFS {
            return Err(BuildingBlockError::TooManyReferences);
        }
        let mut providers = BTreeSet::new();
        for provider in &self.resource_provider_ids {
            if !valid_ref(provider) || !providers.insert(provider) {
                return Err(BuildingBlockError::InvalidReference);
            }
        }
        for reference in [
            self.failure_domain_id.as_ref(),
            self.cloud_profile_id.as_ref(),
        ]
        .into_iter()
        .flatten()
        {
            if !valid_ref(reference) {
                return Err(BuildingBlockError::InvalidReference);
            }
        }
        if self.drain_blockers.len() > MAX_DRAIN_BLOCKERS {
            return Err(BuildingBlockError::TooManyBlockers);
        }
        let mut kinds = BTreeSet::new();
        for blocker in &self.drain_blockers {
            if blocker.count == 0 || !kinds.insert(blocker.kind.as_str()) {
                return Err(BuildingBlockError::InvalidReference);
            }
        }
        Ok(())
    }

    /// Apply one administrative transition.  No provider or topology side
    /// effect is performed by this state machine.
    pub fn transition(
        &self,
        target: BuildingBlockState,
        blockers: Vec<DrainBlocker>,
    ) -> Result<Self, BuildingBlockError> {
        let mut next = self.clone();
        let allowed = match (self.state, target) {
            (BuildingBlockState::Enrolling, BuildingBlockState::Ready)
            | (BuildingBlockState::Enrolling, BuildingBlockState::Unavailable)
            | (BuildingBlockState::Enrolling, BuildingBlockState::Failed)
            | (BuildingBlockState::Ready, BuildingBlockState::Unavailable)
            | (BuildingBlockState::Ready, BuildingBlockState::Draining)
            | (BuildingBlockState::Ready, BuildingBlockState::Failed)
            | (BuildingBlockState::Unavailable, BuildingBlockState::Ready)
            | (BuildingBlockState::Unavailable, BuildingBlockState::Draining)
            | (BuildingBlockState::Unavailable, BuildingBlockState::Failed)
            | (BuildingBlockState::Draining, BuildingBlockState::Ready)
            | (BuildingBlockState::Draining, BuildingBlockState::Unavailable)
            | (BuildingBlockState::Draining, BuildingBlockState::Removed)
            | (BuildingBlockState::Draining, BuildingBlockState::Failed)
            | (BuildingBlockState::Failed, BuildingBlockState::Unavailable) => true,
            _ if self.state == target => true,
            _ => false,
        };
        if !allowed {
            return Err(BuildingBlockError::InvalidTransition);
        }
        if target == BuildingBlockState::Removed && !blockers.is_empty() {
            return Err(BuildingBlockError::DrainBlocked(blockers));
        }
        next.drain_blockers = blockers;
        next.state = target;
        next.generation = self
            .generation
            .checked_add(1)
            .ok_or(BuildingBlockError::GenerationOverflow)?;
        next.validate()?;
        Ok(next)
    }
}

fn valid_ref(value: &str) -> bool {
    !value.is_empty()
        && value.len() <= MAX_BUILDING_BLOCK_ID_BYTES
        && !value.chars().any(|c| c.is_control() || c.is_whitespace())
}

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::expect_used)]
mod tests {
    use super::*;

    #[test]
    fn lifecycle_rejects_invalid_transitions_and_blocks_remove() {
        let block = BuildingBlock::enrolling("block-a", "agent-a", vec![], None, None).unwrap();
        assert_eq!(
            block.transition(BuildingBlockState::Removed, vec![]),
            Err(BuildingBlockError::InvalidTransition)
        );
        let ready = block.transition(BuildingBlockState::Ready, vec![]).unwrap();
        let blockers = vec![DrainBlocker {
            kind: DrainBlockerKind::Workload,
            count: 1,
        }];
        let draining = ready
            .transition(BuildingBlockState::Draining, blockers.clone())
            .unwrap();
        assert_eq!(
            draining
                .transition(BuildingBlockState::Removed, blockers.clone())
                .unwrap_err(),
            BuildingBlockError::DrainBlocked(blockers)
        );
    }

    #[test]
    fn transitions_are_fenced_and_deterministic() {
        let block =
            BuildingBlock::enrolling("block-a", "agent-a", vec!["p-a".into()], None, None).unwrap();
        let next = block.transition(BuildingBlockState::Ready, vec![]).unwrap();
        assert_eq!(next.generation, 2);
        assert_eq!(next.resource_provider_ids, vec!["p-a"]);
    }
}
