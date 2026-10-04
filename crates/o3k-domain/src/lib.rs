mod network;
mod storage;

pub use network::{
    AddressPool, AddressRealm, EgressIntent, EndpointDirectoryError, EndpointIntent,
    EndpointLocation, FabricEndpointRoute, FabricHostIdentity, FabricHostTransportIdentity,
    FabricPeer, FabricProviderKind, GatewayIntent, GenevePacketMetadata,
    GenevePacketValidationError, Ipv4Prefix, L3Gateway, L3GatewayAttachment,
    L3GatewayAttachmentState, L3GatewayExecutionAttachment, L3GatewayExecutionPlan, L3GatewayState,
    NamespacedRoutedFabricPlan, NeighborResolution, Network, NetworkCapability, NetworkIntent,
    NetworkIntentState, NetworkPlanIntent, NetworkPolicy, NetworkPolicyRule, NetworkProtocol,
    NetworkState, PolicyAction, PolicyAddressFamily, PolicyAttachment, PolicyDefaultIntent,
    PolicyDirection, PolicyIntent, PolicyLifecycleState, PolicyStatefulMode, PortRange,
    PublicAddressBindingIntent, RealmBindingError, RealmEncapsulationBinding,
    RealmEncapsulationRegistry, RealmEndpointDirectory, RouteIntent, SecurityGroupBinding,
    SecurityGroupIntent, SecurityGroupRuleIntent, SecurityGroupState, realm_proxy_mac,
};
pub use storage::{
    AttachmentAccessMode, ProviderReference as StorageProviderReference, Snapshot,
    SnapshotConsistency, SnapshotId, SnapshotState, StorageAction, StorageBackend,
    StorageCapabilities, StorageCommandEnvelope, StorageErrorCategory, StorageExecutionScope,
    StorageObservation, StorageOperationState, StorageTransitionError, StorageValidationError,
    Volume, VolumeAttachment, VolumeAttachmentId, VolumeAttachmentState, VolumeId, VolumeState,
};

use serde::{Deserialize, Serialize};
use std::fmt;
use thiserror::Error;
use uuid::Uuid;

/// Durable canonical identity of an O3K server. All durable server references
/// (resources, operations, provider references, attachments) derive from this
/// identity; the underlying storage representation is a UUID.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(transparent)]
pub struct ServerId(Uuid);

impl ServerId {
    /// Creates a new version-7 server identity.
    #[must_use]
    pub fn new() -> Self {
        Self(Uuid::now_v7())
    }

    /// Wraps an existing UUID-backed identity, e.g. when rehydrating a
    /// durable resource ledger record.
    #[must_use]
    pub const fn from_uuid(id: Uuid) -> Self {
        Self(id)
    }

    /// Exposes the underlying UUID for store and provider boundaries that
    /// persist or address resources by UUID.
    #[must_use]
    pub const fn as_uuid(self) -> Uuid {
        self.0
    }
}

impl Default for ServerId {
    fn default() -> Self {
        Self::new()
    }
}

impl From<Uuid> for ServerId {
    fn from(id: Uuid) -> Self {
        Self::from_uuid(id)
    }
}

impl From<ServerId> for Uuid {
    fn from(id: ServerId) -> Self {
        id.as_uuid()
    }
}

impl fmt::Display for ServerId {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        self.0.fmt(formatter)
    }
}

/// Canonical O3K server lifecycle state. This is the single state machine for
/// the durable server lifecycle: Nova status strings (o3k-api), persisted
/// observed values (o3k-store), and provider observations (o3k-provider) are
/// projections of this model, not competing state machines.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ServerState {
    /// Create intent is durably recorded; the provider has not been invoked.
    Requested,
    /// A provider create operation is converging.
    Building,
    /// The server is running and serves workloads.
    Active,
    /// A stop action is converging.
    Stopping,
    /// The server is powered off but retains its identity and attachments.
    Stopped,
    /// A start action is converging.
    Starting,
    /// A reboot action is converging.
    Rebooting,
    /// A delete action is converging; deletion cannot be cancelled.
    Deleting,
    /// The server lifecycle is finished and the record is no longer visible.
    Deleted,
    /// The server failed and only deletion is a valid next transition.
    Error,
}

#[derive(Debug, Error, PartialEq, Eq)]
pub enum TransitionError {
    #[error("invalid server transition from {from:?} to {to:?}")]
    Invalid { from: ServerState, to: ServerState },
}

impl ServerState {
    /// Advances the lifecycle from `self` to `to`, rejecting transitions that
    /// are not part of the canonical lifecycle.
    pub fn transition(self, to: Self) -> Result<Self, TransitionError> {
        let valid = matches!(
            (self, to),
            (Self::Requested, Self::Building)
                | (Self::Building, Self::Active)
                | (Self::Requested, Self::Error)
                | (Self::Building, Self::Error)
                | (Self::Active, Self::Error)
                | (Self::Stopping, Self::Error)
                | (Self::Stopped, Self::Error)
                | (Self::Starting, Self::Error)
                | (Self::Rebooting, Self::Error)
                | (Self::Deleting, Self::Error)
                | (Self::Active, Self::Stopping)
                | (Self::Stopped, Self::Starting)
                | (Self::Starting, Self::Active)
                | (Self::Stopping, Self::Stopped)
                | (Self::Active, Self::Rebooting)
                | (Self::Stopped, Self::Rebooting)
                | (Self::Rebooting, Self::Active)
                | (Self::Requested, Self::Deleting)
                | (Self::Building, Self::Deleting)
                | (Self::Active, Self::Deleting)
                | (Self::Stopping, Self::Deleting)
                | (Self::Stopped, Self::Deleting)
                | (Self::Starting, Self::Deleting)
                | (Self::Rebooting, Self::Deleting)
                | (Self::Error, Self::Deleting)
                | (Self::Deleting, Self::Deleted)
        );

        valid
            .then_some(to)
            .ok_or(TransitionError::Invalid { from: self, to })
    }

    /// Whether the lifecycle has finished. Only `Deleted` is terminal:
    /// `Error` retains the delete transition.
    #[must_use]
    pub fn is_terminal(self) -> bool {
        matches!(self, Self::Deleted)
    }
}

/// Canonical durable O3K server record. The identity (`ServerId`) and
/// lifecycle state (`ServerState`) are the only canonical semantics here;
/// the remaining fields are carried from the current TestLab profile without
/// redesigning flavors, keypairs, or networking.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Server {
    pub id: ServerId,
    pub name: String,
    pub project_id: String,
    pub flavor_id: Uuid,
    pub image_id: String,
    pub state: ServerState,
    pub key_name: Option<String>,
    pub config_drive: bool,
    pub network_ids: Vec<String>,
    /// Durable scheduler-selected compute host (placement provider identity),
    /// projected as Nova's `OS-EXT-SRV-ATTR:host`. `None` only when the create
    /// intent carries no placement decision.
    pub host: Option<String>,
}

#[cfg(test)]
mod tests {
    use super::{ServerId, ServerState, TransitionError};
    use uuid::Uuid;

    #[test]
    fn server_id_round_trips_its_uuid_identity() {
        let id = Uuid::from_u128(42);
        assert_eq!(ServerId::from_uuid(id).as_uuid(), id);
        assert_eq!(Uuid::from(ServerId::from_uuid(id)), id);
        assert_eq!(ServerId::from(id).as_uuid(), id);
        assert_eq!(ServerId::from_uuid(id).to_string(), id.to_string());
    }

    #[test]
    fn complete_canonical_transition_table() {
        let valid = [
            // Create: intent is durably recorded before the provider is
            // invoked; the provider observation projects the outcome.
            (ServerState::Requested, ServerState::Building),
            (ServerState::Building, ServerState::Active),
            // Every non-terminal state except Error may fail into Error; the
            // failure is durable and visible while deletion stays possible.
            (ServerState::Requested, ServerState::Error),
            (ServerState::Building, ServerState::Error),
            (ServerState::Active, ServerState::Error),
            (ServerState::Stopping, ServerState::Error),
            (ServerState::Stopped, ServerState::Error),
            (ServerState::Starting, ServerState::Error),
            (ServerState::Rebooting, ServerState::Error),
            (ServerState::Deleting, ServerState::Error),
            // Stop/start converge synchronously in the current profile.
            (ServerState::Active, ServerState::Stopping),
            (ServerState::Stopping, ServerState::Stopped),
            (ServerState::Stopped, ServerState::Starting),
            (ServerState::Starting, ServerState::Active),
            // Reboot applies to running and stopped servers.
            (ServerState::Active, ServerState::Rebooting),
            (ServerState::Stopped, ServerState::Rebooting),
            (ServerState::Rebooting, ServerState::Active),
            // Deletion is reachable from every non-terminal state and
            // converges only through Deleting to the terminal Deleted state.
            (ServerState::Requested, ServerState::Deleting),
            (ServerState::Building, ServerState::Deleting),
            (ServerState::Active, ServerState::Deleting),
            (ServerState::Stopping, ServerState::Deleting),
            (ServerState::Stopped, ServerState::Deleting),
            (ServerState::Starting, ServerState::Deleting),
            (ServerState::Rebooting, ServerState::Deleting),
            (ServerState::Error, ServerState::Deleting),
            (ServerState::Deleting, ServerState::Deleted),
        ];

        for (from, to) in valid {
            assert_eq!(from.transition(to), Ok(to), "{from:?} -> {to:?}");
        }
        assert_eq!(valid.len(), 26);
    }

    #[test]
    fn every_other_pair_is_an_invalid_transition() {
        let states = [
            ServerState::Requested,
            ServerState::Building,
            ServerState::Active,
            ServerState::Stopping,
            ServerState::Stopped,
            ServerState::Starting,
            ServerState::Rebooting,
            ServerState::Deleting,
            ServerState::Deleted,
            ServerState::Error,
        ];
        let valid = [
            (ServerState::Requested, ServerState::Building),
            (ServerState::Building, ServerState::Active),
            (ServerState::Requested, ServerState::Error),
            (ServerState::Building, ServerState::Error),
            (ServerState::Active, ServerState::Error),
            (ServerState::Stopping, ServerState::Error),
            (ServerState::Stopped, ServerState::Error),
            (ServerState::Starting, ServerState::Error),
            (ServerState::Rebooting, ServerState::Error),
            (ServerState::Deleting, ServerState::Error),
            (ServerState::Active, ServerState::Stopping),
            (ServerState::Stopped, ServerState::Starting),
            (ServerState::Starting, ServerState::Active),
            (ServerState::Stopping, ServerState::Stopped),
            (ServerState::Active, ServerState::Rebooting),
            (ServerState::Stopped, ServerState::Rebooting),
            (ServerState::Rebooting, ServerState::Active),
            (ServerState::Requested, ServerState::Deleting),
            (ServerState::Building, ServerState::Deleting),
            (ServerState::Active, ServerState::Deleting),
            (ServerState::Stopping, ServerState::Deleting),
            (ServerState::Stopped, ServerState::Deleting),
            (ServerState::Starting, ServerState::Deleting),
            (ServerState::Rebooting, ServerState::Deleting),
            (ServerState::Error, ServerState::Deleting),
            (ServerState::Deleting, ServerState::Deleted),
        ];
        for from in states {
            for to in states {
                let expected = valid.contains(&(from, to));
                assert_eq!(
                    from.transition(to).is_ok(),
                    expected,
                    "{from:?} -> {to:?} validity mismatch"
                );
            }
        }
    }

    #[test]
    fn invalid_server_transition_is_rejected() {
        assert_eq!(
            ServerState::Requested.transition(ServerState::Active),
            Err(TransitionError::Invalid {
                from: ServerState::Requested,
                to: ServerState::Active,
            })
        );
        assert_eq!(
            ServerState::Deleted.transition(ServerState::Active),
            Err(TransitionError::Invalid {
                from: ServerState::Deleted,
                to: ServerState::Active,
            })
        );
        assert_eq!(
            ServerState::Deleted.transition(ServerState::Deleting),
            Err(TransitionError::Invalid {
                from: ServerState::Deleted,
                to: ServerState::Deleting,
            })
        );
    }

    #[test]
    fn deleted_is_the_only_terminal_state() {
        let states = [
            ServerState::Requested,
            ServerState::Building,
            ServerState::Active,
            ServerState::Stopping,
            ServerState::Stopped,
            ServerState::Starting,
            ServerState::Rebooting,
            ServerState::Deleting,
            ServerState::Deleted,
            ServerState::Error,
        ];
        for state in states {
            assert_eq!(state.is_terminal(), state == ServerState::Deleted);
        }
    }
}
