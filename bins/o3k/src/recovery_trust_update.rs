//! Root-only signed revocation refresh.  Certificate/key rotation is
//! intentionally outside this narrow operation.
use crate::{
    recovery_files::ProtectedDirectory, recovery_identity as identity,
    recovery_installation::read_protected_config, recovery_trust, upgrade::release_identity,
};
use ed25519_dalek::VerifyingKey;
use sha2::{Digest, Sha256};
use std::{fs, path::Path};

#[derive(Debug)]
pub enum TrustUpdateError {
    Root,
    Reject(String),
    Persist(String),
}
impl std::fmt::Display for TrustUpdateError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{self:?}")
    }
}
impl std::error::Error for TrustUpdateError {}

pub fn update(policy_input: &Path, trust_input: &Path) -> Result<(), TrustUpdateError> {
    if rustix::process::geteuid().as_raw() != 0 {
        return Err(TrustUpdateError::Root);
    }
    let manifest = release_identity::read_fixed_installed_release_manifest()
        .map_err(|e| TrustUpdateError::Reject(e.to_string()))?;
    let authority = release_identity::BackupReleaseIdentity::c1_authority_from_manifest(&manifest)
        .map_err(|error| TrustUpdateError::Reject(error.to_owned()))?;
    let (uid, gid) = service_identity()?;
    let installed_policy = read_protected_config(Path::new(&authority.policy_path), gid)
        .map_err(|error| TrustUpdateError::Reject(error.to_owned()))?;
    let supplied_policy = read_input(policy_input)?;
    if supplied_policy != installed_policy {
        return Err(TrustUpdateError::Reject(
            "policy input differs from installed policy".into(),
        ));
    }
    let policy_key = key(&authority.ed25519_public_key)?;
    let policy: identity::InstallationPolicy = identity::verify_signed(
        &installed_policy,
        &authority.policy_format,
        &authority.key_id,
        &policy_key,
    )
    .map_err(|e| TrustUpdateError::Reject(e.to_string()))?;
    identity::verify_policy(&policy, &authority.key_id)
        .map_err(|e| TrustUpdateError::Reject(e.to_string()))?;
    // Serialize with rotation and every canonical store opener, then recheck
    // the policy read before acquiring the retained data-directory lock.
    let data_dir = ProtectedDirectory::open_accepted(
        Path::new(&policy.data_root),
        &crate::recovery_installation::data_root_postures(
            uid,
            gid,
            crate::recovery_installation::compute_group_gid().ok(),
        ),
        policy.target_device,
        policy.target_inode,
    )
    .map_err(|e| TrustUpdateError::Reject(format!("{e:?}")))?;
    data_dir
        .lock()
        .map_err(|e| TrustUpdateError::Reject(format!("{e:?}")))?;
    if read_protected_config(Path::new(&authority.policy_path), gid)
        .map_err(|e| TrustUpdateError::Reject(e.to_string()))?
        != installed_policy
    {
        return Err(TrustUpdateError::Reject(
            "installed policy changed before quiescence".into(),
        ));
    }
    let state_dir = ProtectedDirectory::open(
        Path::new(&policy.recovery_state_root),
        0,
        gid,
        0o750,
        policy.recovery_state_device,
        policy.recovery_state_inode,
    )
    .map_err(|e| TrustUpdateError::Persist(format!("{e:?}")))?;
    let checkpoint = state_dir
        .read_bounded("policy.json", 0, gid, 0o640, 1024 * 1024)
        .map_err(|e| TrustUpdateError::Reject(format!("{e:?}")))?;
    if checkpoint != installed_policy {
        return Err(TrustUpdateError::Reject(
            "policy checkpoint mismatch".into(),
        ));
    }
    let old = state_dir
        .read_bounded("trust.json", 0, gid, 0o640, 1024 * 1024)
        .map_err(|e| TrustUpdateError::Reject(format!("{e:?}")))?;
    let old_bundle: identity::TrustBundle =
        identity::decode_canonical(&old).map_err(|e| TrustUpdateError::Reject(e.to_string()))?;
    let new_bytes = read_input(trust_input)?;
    let new_bundle: identity::TrustBundle = identity::decode_canonical(&new_bytes)
        .map_err(|e| TrustUpdateError::Reject(e.to_string()))?;
    if new_bundle.installation_id != policy.installation_id
        || new_bundle.site_id != policy.site_id
        || new_bundle.profile != policy.profile
        || new_bundle.backend != policy.backend
        || new_bundle.journal_root_key_id != old_bundle.journal_root_key_id
        || new_bundle.journal_root_public_key != old_bundle.journal_root_public_key
        || new_bundle.evidence_root_key_id != old_bundle.evidence_root_key_id
        || new_bundle.evidence_root_public_key != old_bundle.evidence_root_public_key
        || new_bundle.journal_certificate != old_bundle.journal_certificate
        || new_bundle.evidence_certificate != old_bundle.evidence_certificate
    {
        return Err(TrustUpdateError::Reject(
            "trust roots or certificates changed".into(),
        ));
    }
    let digest = |r: &identity::Signed<identity::RevocationDocument>| {
        identity::digest(r).map_err(|e| TrustUpdateError::Reject(e.to_string()))
    };
    let old_j = old_bundle.journal_revocations.payload.sequence;
    let old_e = old_bundle.evidence_revocations.payload.sequence;
    let new_j = new_bundle.journal_revocations.payload.sequence;
    let new_e = new_bundle.evidence_revocations.payload.sequence;
    if new_j < old_j
        || new_e < old_e
        || (new_j == old_j
            && digest(&new_bundle.journal_revocations)? != digest(&old_bundle.journal_revocations)?)
        || (new_e == old_e
            && digest(&new_bundle.evidence_revocations)?
                != digest(&old_bundle.evidence_revocations)?)
    {
        return Err(TrustUpdateError::Reject(
            "revocation high-water rollback or equivocation".into(),
        ));
    }
    recovery_trust::verify_revocation_update(
        new_bundle.clone(),
        &key(&new_bundle.journal_root_public_key)?,
        &key(&new_bundle.evidence_root_public_key)?,
        chrono::Utc::now().timestamp(),
        Some((old_j, &digest(&old_bundle.journal_revocations)?)),
        Some((old_e, &digest(&old_bundle.evidence_revocations)?)),
    )
    .map_err(|_| TrustUpdateError::Reject("new trust bundle is invalid or stale".into()))?;
    let old_digest = hex::encode(Sha256::digest(&old));
    let archive = format!("trust-{old_digest}.json");
    match state_dir.read_bounded(&archive, 0, gid, 0o640, 1024 * 1024) {
        Ok(bytes) if bytes == old => {}
        Err(crate::recovery_files::RecoveryFileError::Io(error))
            if error.kind() == std::io::ErrorKind::NotFound =>
        {
            state_dir
                .atomic_write(&archive, None, &old, gid)
                .map_err(|e| TrustUpdateError::Persist(format!("{e:?}")))?;
        }
        _ => {
            return Err(TrustUpdateError::Reject(
                "prior trust archive conflicts or is unsafe".into(),
            ));
        }
    }
    state_dir
        .atomic_write("trust.json", Some(&old), &new_bytes, gid)
        .map_err(|e| TrustUpdateError::Persist(format!("{e:?}")))?;
    Ok(())
}

fn key(s: &str) -> Result<VerifyingKey, TrustUpdateError> {
    let b: [u8; 32] = hex::decode(s)
        .map_err(|_| TrustUpdateError::Reject("bad key".into()))?
        .try_into()
        .map_err(|_| TrustUpdateError::Reject("bad key length".into()))?;
    VerifyingKey::from_bytes(&b).map_err(|_| TrustUpdateError::Reject("bad key".into()))
}
fn service_identity() -> Result<(u32, u32), TrustUpdateError> {
    for l in fs::read_to_string("/etc/passwd")
        .map_err(|e| TrustUpdateError::Reject(e.to_string()))?
        .lines()
    {
        let f: Vec<_> = l.split(':').collect();
        if f.first() == Some(&"o3k") && f.len() > 3 {
            return Ok((
                f[2].parse()
                    .map_err(|_| TrustUpdateError::Reject("invalid service uid".into()))?,
                f[3].parse()
                    .map_err(|_| TrustUpdateError::Reject("invalid service gid".into()))?,
            ));
        }
    }
    Err(TrustUpdateError::Reject("o3k identity unavailable".into()))
}
fn read_input(p: &Path) -> Result<Vec<u8>, TrustUpdateError> {
    read_protected_config(p, 0).map_err(|error| TrustUpdateError::Reject(error.to_owned()))
}
