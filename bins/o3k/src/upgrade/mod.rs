//! O3K upgrade/rollback machinery (issue #626).
//!
//! The upgrade engine lives inside the operator CLI: it is orchestration of
//! the kernel's installation, never a new authority. Design authority:
//! `docs/plan/o3k-upgrade.md`.

pub mod backup;
pub mod engine;
pub mod fence;
pub mod output;
pub mod release_identity;
pub mod runner;
pub mod state;

pub use backup::{BackupManifest, RecordKind, RollbackChain, RollbackRecord};
pub use engine::{DoctorOutcome, InstalledRelease, UpgradeArgs, UpgradeIo, UpgradeOutcome};
pub use fence::{FenceError, UpgradeFence};
pub use output::{UpgradeJson, UpgradeStatus};
pub use release_identity::{BackupReleaseIdentity, backup_release_identity};
pub use runner::SystemUpgradeIo;
pub use state::{UpgradePhase, UpgradeState, default_state_path};
