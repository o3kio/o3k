//! Root-authorized C1 pre-provisioning for fresh installations.
//!
//! This is deliberately an installer primitive, not an authority: it creates
//! the exact per-installation recovery directories and emits an unsigned,
//! non-secret provisioning descriptor for the disconnected offline signer.
//! It never creates keys, never signs or synthesizes policy/state/trust, and
//! never claims authentication. The signed documents come back through
//! `recovery_provision::provision` in a separate, operator-driven step.

use std::{
    fs,
    os::unix::fs::{DirBuilderExt, PermissionsExt},
    path::{Path, PathBuf},
};

use serde::Serialize;

use crate::{
    recovery_files::{self, ProtectedDirectory},
    recovery_installation::{self},
    upgrade::release_identity::{self, BackupReleaseIdentity},
};

const PROVISIONING_FORMAT: &str = "o3k-recovery-provisioning-v1";
const RECOVERY_STATE_PARENT: &str = "/var/lib/o3k-recovery-state";
const JOURNAL_PARENT: &str = "/var/lib/o3k-recovery";
const TRUST_BUNDLE_PATH: &str = "/etc/o3k/recovery-trust.json";

#[derive(Debug)]
pub enum PrepareError {
    NotRoot,
    Input(String),
    Unsafe(String),
    Identity(String),
    Persistence(String),
}

impl std::fmt::Display for PrepareError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{self:?}")
    }
}

impl std::error::Error for PrepareError {}

/// Public, non-secret values the offline signer binds into the signed
/// installation policy. `unsigned` is always true: this document is operator
/// staging input, never evidence.
#[derive(Debug, Clone, Serialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct ProvisioningDescriptor {
    pub format: String,
    pub unsigned: bool,
    pub authentication: String,
    pub installation_id: String,
    pub site_id: String,
    pub profile: String,
    pub backend: String,
    pub release_identity: String,
    pub policy_authority: ProvisioningPolicyAuthority,
    pub data_root: String,
    pub data_root_device: u64,
    pub data_root_inode: u64,
    pub recovery_state_root: String,
    pub recovery_state_device: u64,
    pub recovery_state_inode: u64,
    pub journal_directory: String,
    pub journal_device: u64,
    pub journal_inode: u64,
    pub policy_path: String,
    pub trust_bundle_path: String,
}

#[derive(Debug, Clone, Serialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct ProvisioningPolicyAuthority {
    pub key_id: String,
    pub ed25519_public_key: String,
    pub policy_format: String,
    pub policy_path: String,
}

/// Creates the per-installation recovery directories and returns the
/// provisioning descriptor.  Idempotent for an identical earlier result;
/// fails closed on any conflicting or non-empty existing directory.
pub fn prepare(data_root: &Path, backend: &str) -> Result<ProvisioningDescriptor, PrepareError> {
    if rustix::process::geteuid().as_raw() != 0 {
        return Err(PrepareError::NotRoot);
    }
    if !matches!(backend, "sqlite" | "postgresql") {
        return Err(PrepareError::Input(format!(
            "unsupported backend {backend:?} (expected sqlite or postgresql)"
        )));
    }
    if !data_root.is_absolute()
        || data_root.components().any(|c| {
            !matches!(
                c,
                std::path::Component::RootDir | std::path::Component::Normal(_)
            )
        })
    {
        return Err(PrepareError::Input(
            "data root must be an absolute canonical path".to_string(),
        ));
    }
    let data_root = fs::canonicalize(data_root)
        .map_err(|e| PrepareError::Input(format!("data root is unavailable: {e}")))?;
    let manifest =
        release_identity::read_fixed_installed_release_manifest().map_err(PrepareError::Unsafe)?;
    let release =
        BackupReleaseIdentity::from_manifest_bytes(&manifest).map_err(PrepareError::Unsafe)?;
    let authority = BackupReleaseIdentity::c1_authority_from_manifest(&manifest)
        .map_err(PrepareError::Unsafe)?;
    let (uid, gid) = recovery_installation::service_identity()
        .map_err(|e| PrepareError::Identity(e.to_string()))?;
    let compute_gid = recovery_installation::compute_group_gid().ok();

    // The data root must already carry an accepted installed posture; the
    // descriptor binds the observed device/inode, never a caller-supplied one.
    let data_directory = ProtectedDirectory::open_postured(
        &data_root,
        &recovery_installation::data_root_postures(uid, gid, compute_gid),
    )
    .map_err(|e| PrepareError::Unsafe(format!("data root posture is not accepted: {e:?}")))?;
    let (data_root_device, data_root_inode) = data_directory.identity();

    let (installation, site) = o3k_store::identity_tokens(&data_root).map_err(|e| {
        PrepareError::Identity(format!("installation identity cannot be derived: {e}"))
    })?;
    let installation_id = hex::encode(installation);
    let site_id = hex::encode(site);

    let recovery_state_root = PathBuf::from(RECOVERY_STATE_PARENT).join(&installation_id);
    let journal_directory = PathBuf::from(JOURNAL_PARENT).join(&installation_id);
    // The parents are part of the accepted packaged layout (root:root 0755);
    // create them on a clean host instead of requiring a prior full run.
    ensure_recovery_parent(Path::new(RECOVERY_STATE_PARENT))?;
    ensure_recovery_parent(Path::new(JOURNAL_PARENT))?;
    let state_directory = provision_directory(
        &recovery_state_root,
        0,
        gid,
        0o750,
        "recovery-state directory",
    )?;
    let journal = provision_directory(
        &journal_directory,
        uid,
        gid,
        0o700,
        "recovery journal directory",
    )?;
    let (recovery_state_device, recovery_state_inode) = state_directory.identity();
    let (journal_device, journal_inode) = journal.identity();

    Ok(ProvisioningDescriptor {
        format: PROVISIONING_FORMAT.to_string(),
        unsigned: true,
        authentication: "none".to_string(),
        installation_id,
        site_id,
        profile: release.profile_id,
        backend: backend.to_string(),
        release_identity: release.release_artifact_sha256,
        policy_authority: ProvisioningPolicyAuthority {
            key_id: authority.key_id,
            ed25519_public_key: authority.ed25519_public_key,
            policy_format: authority.policy_format,
            policy_path: authority.policy_path,
        },
        data_root: data_root.to_string_lossy().into_owned(),
        data_root_device,
        data_root_inode,
        recovery_state_root: recovery_state_root.to_string_lossy().into_owned(),
        recovery_state_device,
        recovery_state_inode,
        journal_directory: journal_directory.to_string_lossy().into_owned(),
        journal_device,
        journal_inode,
        policy_path: release_identity::C1_INSTALLATION_POLICY_PATH.to_string(),
        trust_bundle_path: TRUST_BUNDLE_PATH.to_string(),
    })
}

/// Creates one recovery directory with the exact accepted owner/mode on
/// verified local ext4, or revalidates an identical earlier result.
/// Existing content is never ignored: any entry fails closed because it may
/// be recovery evidence that requires an authenticated disposition.  Created
/// modes are set exactly after creation because `mkdir` modes are subject to
/// the process umask.
fn provision_directory(
    path: &Path,
    uid: u32,
    gid: u32,
    mode: u32,
    label: &str,
) -> Result<ProtectedDirectory, PrepareError> {
    match fs::symlink_metadata(path) {
        Ok(metadata) => {
            if !metadata.is_dir() {
                return Err(PrepareError::Unsafe(format!(
                    "{label} exists and is not a directory"
                )));
            }
        }
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => {
            recovery_files::check_ancestors(path).map_err(|e| {
                PrepareError::Unsafe(format!("{label} ancestors are unsafe: {e:?}"))
            })?;
            fs::DirBuilder::new()
                .mode(mode)
                .create(path)
                .map_err(|e| PrepareError::Persistence(format!("{label} creation failed: {e}")))?;
            std::os::unix::fs::chown(path, Some(uid), Some(gid)).map_err(|e| {
                PrepareError::Persistence(format!("{label} ownership cannot be set: {e}"))
            })?;
            fs::set_permissions(path, fs::Permissions::from_mode(mode)).map_err(|e| {
                PrepareError::Persistence(format!("{label} mode cannot be set: {e}"))
            })?;
        }
        Err(error) => {
            return Err(PrepareError::Unsafe(format!(
                "{label} cannot be inspected: {error}"
            )));
        }
    }
    let directory = ProtectedDirectory::open_postured(
        path,
        &[crate::recovery_files::DirectoryPosture { uid, gid, mode }],
    )
    .map_err(|e| PrepareError::Unsafe(format!("{label} posture is not exact: {e:?}")))?;
    if fs::read_dir(path)
        .map_err(|e| PrepareError::Unsafe(format!("{label} cannot be listed: {e}")))?
        .next()
        .is_some()
    {
        return Err(PrepareError::Unsafe(format!(
            "{label} already contains recovery content; an authenticated recovery disposition is required"
        )));
    }
    Ok(directory)
}

/// Validates (or creates with the exact mode) one recovery parent directory.
/// Parents are created `root:root` `0755` on verified local ext4; an existing
/// parent with any other posture is operator state and fails closed rather
/// than being silently reinterpreted.
fn ensure_recovery_parent(path: &Path) -> Result<(), PrepareError> {
    let label = format!("recovery parent {}", path.display());
    match fs::symlink_metadata(path) {
        Ok(metadata) => {
            if !metadata.is_dir() {
                return Err(PrepareError::Unsafe(format!(
                    "{label} exists and is not a directory"
                )));
            }
        }
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => {
            recovery_files::check_ancestors(path).map_err(|e| {
                PrepareError::Unsafe(format!("{label} ancestors are unsafe: {e:?}"))
            })?;
            fs::DirBuilder::new()
                .mode(0o755)
                .create(path)
                .map_err(|e| PrepareError::Persistence(format!("{label} creation failed: {e}")))?;
            std::os::unix::fs::chown(path, Some(0), Some(0)).map_err(|e| {
                PrepareError::Persistence(format!("{label} ownership cannot be set: {e}"))
            })?;
            fs::set_permissions(path, fs::Permissions::from_mode(0o755)).map_err(|e| {
                PrepareError::Persistence(format!("{label} mode cannot be set: {e}"))
            })?;
        }
        Err(error) => {
            return Err(PrepareError::Unsafe(format!(
                "{label} cannot be inspected: {error}"
            )));
        }
    }
    // The no-follow protected-directory open proves the exact root:root 0755
    // posture on the verified filesystem.
    ProtectedDirectory::open_postured(
        path,
        &[crate::recovery_files::DirectoryPosture {
            uid: 0,
            gid: 0,
            mode: 0o755,
        }],
    )
    .map(|_| ())
    .map_err(|e| PrepareError::Unsafe(format!("{label} posture is not exact: {e:?}")))
}

#[cfg(test)]
#[allow(clippy::expect_used, clippy::unwrap_used)]
mod tests {
    use super::*;

    #[test]
    fn rejects_relative_and_noncanonical_data_roots() {
        for path in [
            Path::new("relative"),
            Path::new(""),
            Path::new("/var/lib/../lib/o3k"),
        ] {
            let error = prepare_input_check(path);
            assert!(
                matches!(error, Err(PrepareError::Input(_))),
                "path {path:?} must fail the input check"
            );
        }
    }

    fn prepare_input_check(data_root: &Path) -> Result<(), PrepareError> {
        if !data_root.is_absolute()
            || data_root.components().any(|c| {
                !matches!(
                    c,
                    std::path::Component::RootDir | std::path::Component::Normal(_)
                )
            })
        {
            return Err(PrepareError::Input(
                "data root must be an absolute canonical path".to_string(),
            ));
        }
        Ok(())
    }
}
