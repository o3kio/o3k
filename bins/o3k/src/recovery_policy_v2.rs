//! Read-only verifier for the accepted PP.6 A10.1 policy selector.
//!
//! The installation-state tip selects the format. A policy file, release
//! manifest, staging file, or high-water record can never select v2 by itself.
//! This module deliberately has no publication or repair API.

use crate::{recovery_identity as identity, upgrade::release_identity::BackupReleaseIdentity};
use ed25519_dalek::VerifyingKey;
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};

pub const POLICY_V1: &str = "o3k-installation-policy-v1";
pub const POLICY_V2: &str = "o3k-installation-policy-v2";
pub const MIGRATION_V1: &str = "o3k-installation-policy-migration-v1";
pub const FIXED_POLICY_PATH: &str = "/etc/o3k/installation-policy.json";

type Result<T> = std::result::Result<T, &'static str>;

#[derive(Debug, Clone, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct PolicyV2 {
    pub format: String,
    pub installation_id: String,
    pub site_id: String,
    pub profile: String,
    pub backend: String,
    pub backend_version: String,
    pub deployment: String,
    pub restore_branch_authorization: String,
    pub release_identity: String,
    pub release_version: String,
    pub source_commit: String,
    pub release_manifest_sha256: String,
    pub data_root: String,
    pub target_device: u64,
    pub target_inode: u64,
    pub policy_revision: u64,
    pub prior_policy_digest: String,
    pub policy_path: String,
    pub trust_bundle_path: String,
    pub trust_bundle_digest: String,
    pub recovery_state_root: String,
    pub recovery_state_device: u64,
    pub recovery_state_inode: u64,
    pub journal_directory: String,
    pub journal_device: u64,
    pub journal_inode: u64,
    pub journal_trust_root_id: String,
    pub journal_trust_root_public_key: String,
    pub evidence_trust_root_id: String,
    pub evidence_trust_root_public_key: String,
    pub signer_key_id: String,
}

#[derive(Debug, Clone, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct MigrationPayload {
    pub format: String,
    pub installation_id: String,
    pub site_id: String,
    pub sequence: u64,
    pub prior_record_digest: String,
    pub preserved_state: String,
    pub prior_policy_format: String,
    pub prior_policy_revision: u64,
    pub prior_policy_digest: String,
    pub new_policy_format: String,
    pub new_policy_revision: u64,
    pub new_policy_digest: String,
    pub prior_release_manifest_sha256: String,
    pub new_release_manifest_sha256: String,
    pub prior_release_identity: ReleaseIdentity,
    pub new_release_identity: ReleaseIdentity,
    pub target_device: u64,
    pub target_inode: u64,
    pub trust_bundle_digest: String,
    pub checkpoint_digest: Option<String>,
    pub signer_manifest_digest: String,
}

#[derive(Debug, Clone, Deserialize, Serialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct ReleaseIdentity {
    pub version: String,
    pub source_commit: String,
    pub release_artifact_sha256: String,
    pub profile_id: String,
    pub schema_version: u64,
}

#[derive(Debug, Clone, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
struct PolicyHighWaterV2 {
    format_epoch: u64,
    revision: u64,
    digest: String,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum SelectedPolicy {
    V1,
    V2 { revision: u64, digest: String },
}

/// Verifies one complete selector generation from isolated bytes. Callers
/// must obtain `prior_state` and `prior_policy` from the content-addressed
/// recovery-state archive, never from mutable staging input.
pub fn verify_selected_policy_v2(
    manifest_bytes: &[u8],
    policy_bytes: &[u8],
    high_water_bytes: &[u8],
    state_tip_bytes: &[u8],
    prior_state_bytes: &[u8],
    prior_policy_bytes: &[u8],
) -> Result<SelectedPolicy> {
    let authority = v2_authority(manifest_bytes)?;
    let manifest_digest = sha256(manifest_bytes);
    let release = BackupReleaseIdentity::from_manifest_bytes(manifest_bytes)
        .map_err(|_| "installed release identity is invalid")?;
    let release_view = ReleaseIdentity {
        version: release.o3k_version,
        source_commit: release.source_sha,
        release_artifact_sha256: release.release_artifact_sha256,
        profile_id: release.profile_id,
        schema_version: release.schema_version,
    };

    let policy: PolicyV2 =
        identity::verify_signed(policy_bytes, POLICY_V2, &authority.0, &authority.1)
            .map_err(|_| "v2 installation policy signature is invalid")?;
    verify_policy_payload(
        &policy,
        &authority.0,
        authority.1.as_bytes(),
        &manifest_digest,
        &release_view,
    )?;
    let policy_digest = sha256(policy_bytes);

    let event: MigrationPayload =
        identity::verify_signed(state_tip_bytes, MIGRATION_V1, &authority.0, &authority.1)
            .map_err(|_| "installation policy migration selector is invalid")?;
    let prior_state: identity::Signed<serde_json::Value> =
        identity::decode_canonical(prior_state_bytes)
            .map_err(|_| "installation state predecessor is malformed")?;
    let prior_policy: identity::InstallationPolicy =
        identity::verify_signed(prior_policy_bytes, POLICY_V1, &authority.0, &authority.1)
            .map_err(|_| "prior v1 installation policy signature is invalid")?;
    identity::verify_policy(&prior_policy, &authority.0)
        .map_err(|_| "prior v1 installation policy binding is invalid")?;
    let prior_initial_state: identity::InstallationState = identity::verify_signed(
        prior_state_bytes,
        "o3k-installation-state-v1",
        &authority.0,
        &authority.1,
    )
    .map_err(|_| "installation state predecessor signature is invalid")?;
    identity::verify_initial_state_transition(None, &prior_initial_state, &prior_policy)
        .map_err(|_| "installation state predecessor is invalid")?;

    let previous_format = prior_state
        .payload
        .get("format")
        .and_then(serde_json::Value::as_str)
        .ok_or("installation state predecessor format is missing")?;
    if previous_format != "o3k-installation-state-v1" {
        return Err("migration selector predecessor is unsupported");
    }
    let previous_sequence = prior_state
        .payload
        .get("sequence")
        .and_then(serde_json::Value::as_u64)
        .ok_or("installation state predecessor sequence is invalid")?;
    let previous_state = prior_state
        .payload
        .get("state")
        .and_then(serde_json::Value::as_str)
        .ok_or("installation state predecessor state is invalid")?;
    let previous_policy_digest = prior_state
        .payload
        .get("policy_digest")
        .and_then(serde_json::Value::as_str)
        .ok_or("installation state predecessor policy binding is invalid")?;
    let previous_target_device = prior_state
        .payload
        .get("target_device")
        .and_then(serde_json::Value::as_u64)
        .ok_or("installation state predecessor target is invalid")?;
    let previous_target_inode = prior_state
        .payload
        .get("target_inode")
        .and_then(serde_json::Value::as_u64)
        .ok_or("installation state predecessor target is invalid")?;
    let previous_installation = prior_state
        .payload
        .get("installation_id")
        .and_then(serde_json::Value::as_str)
        .ok_or("installation state predecessor identity is invalid")?;
    let previous_site = prior_state
        .payload
        .get("site_id")
        .and_then(serde_json::Value::as_str)
        .ok_or("installation state predecessor identity is invalid")?;

    if event.format != MIGRATION_V1
        || event.installation_id != policy.installation_id
        || event.site_id != policy.site_id
        || event.installation_id != previous_installation
        || event.site_id != previous_site
        || event.sequence
            != previous_sequence
                .checked_add(1)
                .ok_or("state sequence overflow")?
        || event.prior_record_digest != sha256(prior_state_bytes)
        || event.preserved_state != previous_state
        || event.prior_policy_format != POLICY_V1
        || event.prior_policy_revision != prior_policy.policy_revision
        || event.prior_policy_digest != sha256(prior_policy_bytes)
        || !is_lower_sha256(&event.prior_policy_digest)
        || event.prior_policy_digest != previous_policy_digest
        || event.new_policy_format != POLICY_V2
        || event.new_policy_revision != policy.policy_revision
        || event.new_policy_digest != policy_digest
        || !is_lower_sha256(&event.new_policy_digest)
        || event.new_release_manifest_sha256 != manifest_digest
        || !is_lower_sha256(&event.prior_release_manifest_sha256)
        || !is_lower_sha256(&event.new_release_manifest_sha256)
        || event.signer_manifest_digest != manifest_digest
        || event.new_release_identity != release_view
        || event.target_device != policy.target_device
        || event.target_inode != policy.target_inode
        || event.target_device != previous_target_device
        || event.target_inode != previous_target_inode
        || event.trust_bundle_digest != policy.trust_bundle_digest
        || !is_lower_sha256(&event.trust_bundle_digest)
        || event.prior_release_identity.release_artifact_sha256 != prior_policy.release_identity
        || event.prior_release_identity.profile_id != prior_policy.profile
        || prior_policy.policy_revision.checked_add(1) != Some(policy.policy_revision)
        || policy.prior_policy_digest != event.prior_policy_digest
        || policy.installation_id != prior_policy.installation_id
        || policy.site_id != prior_policy.site_id
        || policy.data_root != prior_policy.data_root
        || policy.target_device != prior_policy.target_device
        || policy.target_inode != prior_policy.target_inode
        || policy.policy_path != prior_policy.policy_path
        || policy.trust_bundle_path != prior_policy.trust_bundle_path
        || policy.trust_bundle_digest != prior_policy.trust_bundle_digest
        || policy.recovery_state_root != prior_policy.recovery_state_root
        || policy.recovery_state_device != prior_policy.recovery_state_device
        || policy.recovery_state_inode != prior_policy.recovery_state_inode
        || policy.journal_directory != prior_policy.journal_directory
        || policy.journal_device != prior_policy.journal_device
        || policy.journal_inode != prior_policy.journal_inode
        || policy.journal_trust_root_id != prior_policy.journal_trust_root_id
        || policy.journal_trust_root_public_key != prior_policy.journal_trust_root_public_key
        || policy.evidence_trust_root_id != prior_policy.evidence_trust_root_id
        || policy.evidence_trust_root_public_key != prior_policy.evidence_trust_root_public_key
        || event.prior_release_manifest_sha256 == manifest_digest
        || event.prior_release_identity.profile_id != "o3k-small-edge-v1"
        || !is_lower_hex(&event.prior_release_identity.source_commit, 40)
        || !is_lower_sha256(&event.prior_release_identity.release_artifact_sha256)
        || event.prior_release_identity.version.is_empty()
        || event.prior_release_identity.schema_version == 0
        || previous_state != "NEVER_RECOVERED"
        || (previous_state == "NEVER_RECOVERED" && event.checkpoint_digest.is_some())
        || (previous_state != "NEVER_RECOVERED" && event.checkpoint_digest.is_none())
    {
        return Err("installation policy migration bindings do not match");
    }

    let high_water: PolicyHighWaterV2 = identity::decode_canonical(high_water_bytes)
        .map_err(|_| "v2 policy high-water is malformed")?;
    if high_water.format_epoch != 2
        || high_water.revision != policy.policy_revision
        || high_water.digest != policy_digest
        || event.prior_policy_revision.checked_add(1) != Some(high_water.revision)
    {
        return Err("v2 policy high-water is stale or downgraded");
    }
    Ok(SelectedPolicy::V2 {
        revision: high_water.revision,
        digest: high_water.digest,
    })
}

fn verify_policy_payload(
    p: &PolicyV2,
    signer: &str,
    signer_public_key: &[u8; 32],
    manifest_digest: &str,
    release: &ReleaseIdentity,
) -> Result<()> {
    if p.format != POLICY_V2
        || p.signer_key_id != signer
        || p.profile != "o3k-small-edge-v1"
        || p.backend != "postgresql"
        || p.backend_version != "16"
        || p.deployment != "virtualized"
        || p.restore_branch_authorization != "inactive-materialization-only"
        || p.release_identity != release.release_artifact_sha256
        || release.profile_id != p.profile
        || p.release_version != release.version
        || p.source_commit != release.source_commit
        || !is_lower_hex(&p.source_commit, 40)
        || p.release_manifest_sha256 != manifest_digest
        || !is_lower_sha256(&p.release_identity)
        || !is_lower_sha256(&p.release_manifest_sha256)
        || !is_lower_sha256(&p.prior_policy_digest)
        || !is_lower_sha256(&p.trust_bundle_digest)
        || p.policy_path != FIXED_POLICY_PATH
        || !absolute_canonical_path(&p.data_root)
        || !absolute_canonical_path(&p.trust_bundle_path)
        || !absolute_canonical_path(&p.recovery_state_root)
        || !absolute_canonical_path(&p.journal_directory)
        || p.policy_revision < 2
        || p.target_device == 0
        || p.target_inode == 0
        || p.recovery_state_device == 0
        || p.recovery_state_inode == 0
        || p.journal_device == 0
        || p.journal_inode == 0
        || !is_lower_hex(&p.installation_id, 32)
        || !is_lower_hex(&p.site_id, 32)
        || p.journal_trust_root_id.is_empty()
        || p.evidence_trust_root_id.is_empty()
        || p.journal_trust_root_id == p.evidence_trust_root_id
        || p.journal_trust_root_public_key == p.evidence_trust_root_public_key
        || !is_lower_hex(&p.journal_trust_root_public_key, 64)
        || !is_lower_hex(&p.evidence_trust_root_public_key, 64)
        || p.journal_trust_root_public_key == hex::encode(signer_public_key)
        || p.evidence_trust_root_public_key == hex::encode(signer_public_key)
        || VerifyingKey::from_bytes(
            &hex::decode(&p.journal_trust_root_public_key)
                .map_err(|_| "journal trust root key is invalid")?
                .try_into()
                .map_err(|_| "journal trust root key is invalid")?,
        )
        .is_err()
        || VerifyingKey::from_bytes(
            &hex::decode(&p.evidence_trust_root_public_key)
                .map_err(|_| "evidence trust root key is invalid")?
                .try_into()
                .map_err(|_| "evidence trust root key is invalid")?,
        )
        .is_err()
    {
        return Err("v2 installation policy binding is invalid");
    }
    Ok(())
}

fn absolute_canonical_path(value: &str) -> bool {
    let path = std::path::Path::new(value);
    path.is_absolute()
        && path.components().all(|component| {
            matches!(
                component,
                std::path::Component::RootDir | std::path::Component::Normal(_)
            )
        })
}

fn v2_authority(manifest_bytes: &[u8]) -> Result<(String, VerifyingKey)> {
    let value: serde_json::Value = serde_json::from_slice(manifest_bytes)
        .map_err(|_| "installed release manifest is malformed")?;
    let auth = value
        .get("installation_policy_v2_authority")
        .and_then(serde_json::Value::as_object)
        .ok_or("release manifest does not authorize policy v2")?;
    if auth.len() != 4
        || auth.get("format").and_then(serde_json::Value::as_str) != Some(POLICY_V2)
        || auth.get("policy_path").and_then(serde_json::Value::as_str) != Some(FIXED_POLICY_PATH)
    {
        return Err("release manifest v2 authority is invalid");
    }
    let key_id = auth
        .get("key_id")
        .and_then(serde_json::Value::as_str)
        .filter(|s| !s.is_empty())
        .ok_or("release manifest v2 signer id is missing")?;
    let key_hex = auth
        .get("ed25519_public_key")
        .and_then(serde_json::Value::as_str)
        .ok_or("release manifest v2 signer key is missing")?;
    let key_bytes: [u8; 32] = hex::decode(key_hex)
        .map_err(|_| "release manifest v2 signer key is invalid")?
        .try_into()
        .map_err(|_| "release manifest v2 signer key is invalid")?;
    let key = VerifyingKey::from_bytes(&key_bytes)
        .map_err(|_| "release manifest v2 signer key is invalid")?;
    let old = crate::upgrade::release_identity::BackupReleaseIdentity::c1_authority_from_manifest(
        manifest_bytes,
    )
    .map_err(|_| "release manifest v1 authority is invalid")?;
    if old.key_id != key_id || old.ed25519_public_key != key_hex {
        return Err("policy v2 signer differs from the existing installation-policy authority");
    }
    Ok((key_id.to_owned(), key))
}

fn sha256(bytes: &[u8]) -> String {
    hex::encode(Sha256::digest(bytes))
}

fn is_lower_sha256(value: &str) -> bool {
    is_lower_hex(value, 64)
}

fn is_lower_hex(value: &str, length: usize) -> bool {
    value.len() == length
        && value
            .bytes()
            .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte))
}

#[cfg(test)]
#[allow(clippy::expect_used, clippy::unwrap_used)]
mod tests {
    use super::*;
    use crate::recovery_identity::{InstallationPolicy, InstallationState, RecoveryState};
    use ed25519_dalek::{Signer, SigningKey};

    struct Fixture {
        signing_key: SigningKey,
        manifest: Vec<u8>,
        policy: Vec<u8>,
        high_water: Vec<u8>,
        selector: Vec<u8>,
        prior_state: Vec<u8>,
        prior_policy: Vec<u8>,
    }

    fn sign<T: Serialize + Clone>(payload: &T, key: &SigningKey) -> Vec<u8> {
        let canonical = identity::canonical(payload).unwrap();
        let signature = key.sign(&canonical);
        let signed: identity::Signed<T> = identity::Signed {
            payload: payload.clone(),
            envelope: identity::SignatureEnvelope {
                algorithm: "Ed25519".into(),
                signer_key_id: "installation-key".into(),
                signature: hex::encode(signature.to_bytes()),
            },
        };
        identity::canonical(&signed).unwrap()
    }

    fn fixture() -> Fixture {
        let signing_key = SigningKey::from_bytes(&[17; 32]);
        let public_key = hex::encode(signing_key.verifying_key().to_bytes());
        let journal_root_key =
            hex::encode(SigningKey::from_bytes(&[20; 32]).verifying_key().to_bytes());
        let evidence_root_key =
            hex::encode(SigningKey::from_bytes(&[21; 32]).verifying_key().to_bytes());
        let old_release = ReleaseIdentity {
            version: "0.4.0-rc.4".into(),
            source_commit: "a".repeat(40),
            release_artifact_sha256: "1".repeat(64),
            profile_id: "o3k-small-edge-v1".into(),
            schema_version: 1,
        };
        let new_release = ReleaseIdentity {
            version: "0.4.0-rc.5".into(),
            source_commit: "b".repeat(40),
            release_artifact_sha256: "2".repeat(64),
            profile_id: "o3k-small-edge-v1".into(),
            schema_version: 1,
        };
        let old_manifest = serde_jcs::to_vec(&serde_json::json!({
            "version": old_release.version,
            "source_commit": old_release.source_commit,
            "release_artifact_sha256": old_release.release_artifact_sha256,
            "profile_id": old_release.profile_id,
            "schema_version": old_release.schema_version,
            "installation_policy_format": POLICY_V1,
            "installation_policy_path": FIXED_POLICY_PATH,
            "installation_policy_authority": {
                "key_id": "installation-key",
                "ed25519_public_key": public_key,
            }
        }))
        .unwrap();
        let manifest = serde_jcs::to_vec(&serde_json::json!({
            "version": new_release.version,
            "source_commit": new_release.source_commit,
            "release_artifact_sha256": new_release.release_artifact_sha256,
            "profile_id": new_release.profile_id,
            "schema_version": new_release.schema_version,
            "installation_policy_format": POLICY_V1,
            "installation_policy_path": FIXED_POLICY_PATH,
            "installation_policy_authority": {
                "key_id": "installation-key",
                "ed25519_public_key": public_key,
            },
            "installation_policy_v2_authority": {
                "format": POLICY_V2,
                "policy_path": FIXED_POLICY_PATH,
                "key_id": "installation-key",
                "ed25519_public_key": public_key,
            }
        }))
        .unwrap();
        let old_policy_payload = InstallationPolicy {
            format: POLICY_V1.into(),
            installation_id: "11".repeat(16),
            site_id: "22".repeat(16),
            profile: "o3k-small-edge-v1".into(),
            backend: "postgresql".into(),
            release_identity: old_release.release_artifact_sha256.clone(),
            data_root: "/var/lib/o3k".into(),
            target_device: 2049,
            target_inode: 12_345,
            policy_revision: 1,
            prior_policy_digest: String::new(),
            policy_path: FIXED_POLICY_PATH.into(),
            trust_bundle_path: "/etc/o3k/recovery-trust.json".into(),
            trust_bundle_digest: "3".repeat(64),
            recovery_state_root: format!("/var/lib/o3k-recovery-state/{}", "11".repeat(16)),
            recovery_state_device: 2049,
            recovery_state_inode: 12_346,
            journal_directory: format!("/var/lib/o3k-recovery/{}", "11".repeat(16)),
            journal_device: 2049,
            journal_inode: 12_347,
            journal_trust_root_id: "journal-root".into(),
            journal_trust_root_public_key: journal_root_key,
            evidence_trust_root_id: "evidence-root".into(),
            evidence_trust_root_public_key: evidence_root_key,
            signer_key_id: "installation-key".into(),
        };
        let prior_policy = sign(&old_policy_payload, &signing_key);
        let prior_policy_digest = sha256(&prior_policy);
        let prior_state_payload = InstallationState {
            format: "o3k-installation-state-v1".into(),
            installation_id: old_policy_payload.installation_id.clone(),
            site_id: old_policy_payload.site_id.clone(),
            profile: old_policy_payload.profile.clone(),
            backend: old_policy_payload.backend.clone(),
            policy_revision: old_policy_payload.policy_revision,
            policy_digest: prior_policy_digest.clone(),
            target_device: old_policy_payload.target_device,
            target_inode: old_policy_payload.target_inode,
            sequence: 0,
            prior_record_digest: String::new(),
            state: RecoveryState::NeverRecovered,
            operation_id: None,
            artifact_sha256: None,
            recovery_directory_digest: None,
            trust_bundle_digest: None,
            terminal_journal_digest: None,
            evidence_digest: None,
        };
        let prior_state = sign(&prior_state_payload, &signing_key);
        let policy_payload = PolicyV2 {
            format: POLICY_V2.into(),
            installation_id: old_policy_payload.installation_id.clone(),
            site_id: old_policy_payload.site_id.clone(),
            profile: old_policy_payload.profile.clone(),
            backend: old_policy_payload.backend.clone(),
            backend_version: "16".into(),
            deployment: "virtualized".into(),
            restore_branch_authorization: "inactive-materialization-only".into(),
            release_identity: new_release.release_artifact_sha256.clone(),
            release_version: new_release.version.clone(),
            source_commit: new_release.source_commit.clone(),
            release_manifest_sha256: sha256(&manifest),
            data_root: old_policy_payload.data_root.clone(),
            target_device: old_policy_payload.target_device,
            target_inode: old_policy_payload.target_inode,
            policy_revision: 2,
            prior_policy_digest: prior_policy_digest.clone(),
            policy_path: old_policy_payload.policy_path.clone(),
            trust_bundle_path: old_policy_payload.trust_bundle_path.clone(),
            trust_bundle_digest: old_policy_payload.trust_bundle_digest.clone(),
            recovery_state_root: old_policy_payload.recovery_state_root.clone(),
            recovery_state_device: old_policy_payload.recovery_state_device,
            recovery_state_inode: old_policy_payload.recovery_state_inode,
            journal_directory: old_policy_payload.journal_directory.clone(),
            journal_device: old_policy_payload.journal_device,
            journal_inode: old_policy_payload.journal_inode,
            journal_trust_root_id: old_policy_payload.journal_trust_root_id.clone(),
            journal_trust_root_public_key: old_policy_payload.journal_trust_root_public_key.clone(),
            evidence_trust_root_id: old_policy_payload.evidence_trust_root_id.clone(),
            evidence_trust_root_public_key: old_policy_payload
                .evidence_trust_root_public_key
                .clone(),
            signer_key_id: "installation-key".into(),
        };
        let policy = sign(&policy_payload, &signing_key);
        let selector_payload = MigrationPayload {
            format: MIGRATION_V1.into(),
            installation_id: old_policy_payload.installation_id.clone(),
            site_id: old_policy_payload.site_id.clone(),
            sequence: 1,
            prior_record_digest: sha256(&prior_state),
            preserved_state: "NEVER_RECOVERED".into(),
            prior_policy_format: POLICY_V1.into(),
            prior_policy_revision: 1,
            prior_policy_digest,
            new_policy_format: POLICY_V2.into(),
            new_policy_revision: 2,
            new_policy_digest: sha256(&policy),
            prior_release_manifest_sha256: sha256(&old_manifest),
            new_release_manifest_sha256: sha256(&manifest),
            prior_release_identity: old_release,
            new_release_identity: new_release,
            target_device: old_policy_payload.target_device,
            target_inode: old_policy_payload.target_inode,
            trust_bundle_digest: old_policy_payload.trust_bundle_digest,
            checkpoint_digest: None,
            signer_manifest_digest: sha256(&manifest),
        };
        let selector = sign(&selector_payload, &signing_key);
        let high_water = serde_jcs::to_vec(&serde_json::json!({
            "format_epoch": 2,
            "revision": 2,
            "digest": sha256(&policy),
        }))
        .unwrap();
        Fixture {
            signing_key,
            manifest,
            policy,
            high_water,
            selector,
            prior_state,
            prior_policy,
        }
    }

    #[test]
    fn complete_signed_migration_is_selected_from_state_tip() {
        let f = fixture();
        let decoded: identity::Signed<PolicyV2> = serde_json::from_slice(&f.policy).unwrap();
        assert_eq!(identity::canonical(&decoded).unwrap(), f.policy);
        let authority = v2_authority(&f.manifest).unwrap();
        assert!(
            identity::verify_signed::<PolicyV2>(&f.policy, POLICY_V2, &authority.0, &authority.1)
                .is_ok()
        );
        let result = verify_selected_policy_v2(
            &f.manifest,
            &f.policy,
            &f.high_water,
            &f.selector,
            &f.prior_state,
            &f.prior_policy,
        );
        assert!(
            matches!(result, Ok(SelectedPolicy::V2 { revision: 2, .. })),
            "{result:?}"
        );
    }

    #[test]
    fn partial_generation_never_falls_back_to_v1() {
        let f = fixture();
        for policy in [&[][..], b"truncated".as_slice()] {
            assert!(
                verify_selected_policy_v2(
                    &f.manifest,
                    policy,
                    &f.high_water,
                    &f.selector,
                    &f.prior_state,
                    &f.prior_policy,
                )
                .is_err()
            );
        }
    }

    #[test]
    fn stale_high_water_and_wrong_manifest_are_denied() {
        let f = fixture();
        let stale = serde_jcs::to_vec(&serde_json::json!({
            "format_epoch": 1,
            "revision": 1,
            "digest": sha256(&f.prior_policy),
        }))
        .unwrap();
        assert!(
            verify_selected_policy_v2(
                &f.manifest,
                &f.policy,
                &stale,
                &f.selector,
                &f.prior_state,
                &f.prior_policy,
            )
            .is_err()
        );
        let mut wrong_manifest: serde_json::Value = serde_json::from_slice(&f.manifest).unwrap();
        wrong_manifest["version"] = serde_json::json!("0.4.0-rc.6");
        let wrong_manifest = serde_jcs::to_vec(&wrong_manifest).unwrap();
        assert!(
            verify_selected_policy_v2(
                &wrong_manifest,
                &f.policy,
                &f.high_water,
                &f.selector,
                &f.prior_state,
                &f.prior_policy,
            )
            .is_err()
        );
    }

    #[test]
    fn selector_replay_corruption_and_unsupported_downgrade_are_denied() {
        let f = fixture();
        let mut corrupted = f.selector.clone();
        corrupted[0] ^= 1;
        assert!(
            verify_selected_policy_v2(
                &f.manifest,
                &f.policy,
                &f.high_water,
                &corrupted,
                &f.prior_state,
                &f.prior_policy,
            )
            .is_err()
        );
        let mut replay: serde_json::Value = serde_json::from_slice(&f.selector).unwrap();
        replay["payload"]["sequence"] = serde_json::json!(0);
        let replay = sign(&replay["payload"], &f.signing_key);
        assert!(
            verify_selected_policy_v2(
                &f.manifest,
                &f.policy,
                &f.high_water,
                &replay,
                &f.prior_state,
                &f.prior_policy,
            )
            .is_err()
        );
        let mut downgrade: serde_json::Value = serde_json::from_slice(&f.selector).unwrap();
        downgrade["payload"]["new_policy_format"] = serde_json::json!(POLICY_V1);
        let downgrade = sign(&downgrade["payload"], &f.signing_key);
        assert!(
            verify_selected_policy_v2(
                &f.manifest,
                &f.policy,
                &f.high_water,
                &downgrade,
                &f.prior_state,
                &f.prior_policy,
            )
            .is_err()
        );
    }

    #[test]
    fn missing_v2_trust_authority_is_denied() {
        let f = fixture();
        let mut manifest: serde_json::Value = serde_json::from_slice(&f.manifest).unwrap();
        manifest
            .as_object_mut()
            .unwrap()
            .remove("installation_policy_v2_authority");
        let manifest = serde_jcs::to_vec(&manifest).unwrap();
        assert!(
            verify_selected_policy_v2(
                &manifest,
                &f.policy,
                &f.high_water,
                &f.selector,
                &f.prior_state,
                &f.prior_policy,
            )
            .is_err()
        );
    }
}
