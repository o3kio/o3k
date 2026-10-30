//! Pure A10.1 format-selector verification.
//!
//! This module only authenticates signed documents and their cross-record
//! bindings. It performs no filesystem, store, lease, listener, or provider
//! operation. Publication and startup admission are owned by callers.

use ed25519_dalek::VerifyingKey;
use serde::{Deserialize, Serialize};

use crate::recovery_identity as identity;

pub const V2_FORMAT: &str = "o3k-installation-policy-v2";
pub const MIGRATION_FORMAT: &str = "o3k-installation-policy-migration-v1";

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct InstallationPolicyV2 {
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

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct ReleaseIdentity {
    pub version: String,
    pub source_commit: String,
    pub release_artifact_sha256: String,
    pub profile_id: String,
    pub schema_version: u64,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct InstallationPolicyMigrationV1 {
    pub format: String,
    pub installation_id: String,
    pub site_id: String,
    pub sequence: u64,
    pub prior_record_digest: String,
    pub preserved_state: identity::RecoveryState,
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

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum SelectorError {
    Invalid,
    Signature,
    Binding,
}

fn digest(s: &str) -> bool {
    s.len() == 64
        && s.bytes()
            .all(|b| b.is_ascii_hexdigit() && !b.is_ascii_uppercase())
}
fn nonempty(s: &str) -> bool {
    !s.is_empty()
}
fn absolute_path(s: &str) -> bool {
    let p = std::path::Path::new(s);
    p.is_absolute()
        && p.components().all(|c| {
            matches!(
                c,
                std::path::Component::RootDir | std::path::Component::Normal(_)
            )
        })
}
fn valid_release(r: &ReleaseIdentity) -> bool {
    nonempty(&r.version)
        && commit(&r.source_commit)
        && digest(&r.release_artifact_sha256)
        && r.profile_id == "o3k-small-edge-v1"
        && r.schema_version >= 1
}
fn successor(value: u64) -> Option<u64> {
    value.checked_add(1)
}
fn key_hex(s: &str) -> bool {
    s.len() == 64
        && s.bytes()
            .all(|b| b.is_ascii_hexdigit() && !b.is_ascii_uppercase())
}
fn commit(s: &str) -> bool {
    s.len() == 40
        && s.bytes()
            .all(|b| b.is_ascii_hexdigit() && !b.is_ascii_uppercase())
}

pub fn verify_v2_policy(
    bytes: &[u8],
    key_id: &str,
    key: &VerifyingKey,
    manifest_digest: &str,
    release_identity: &str,
    release_version: &str,
    source_commit: &str,
) -> Result<InstallationPolicyV2, SelectorError> {
    let p: InstallationPolicyV2 = identity::verify_signed(bytes, V2_FORMAT, key_id, key)
        .map_err(|_| SelectorError::Signature)?;
    if p.format != V2_FORMAT
        || !nonempty(&p.installation_id)
        || !nonempty(&p.site_id)
        || !nonempty(&p.profile)
        || !nonempty(&p.backend)
        || !nonempty(&p.release_version)
        || !absolute_path(&p.data_root)
        || !absolute_path(&p.trust_bundle_path)
        || !absolute_path(&p.recovery_state_root)
        || !absolute_path(&p.journal_directory)
        || p.profile != "o3k-small-edge-v1"
        || p.backend != "postgresql"
        || p.backend_version != "16"
        || p.deployment != "virtualized"
        || p.restore_branch_authorization != "inactive-materialization-only"
        || p.policy_revision < 2
        || p.policy_path != "/etc/o3k/installation-policy.json"
        || p.release_manifest_sha256 != manifest_digest
        || p.release_identity != release_identity
        || p.release_version != release_version
        || p.source_commit != source_commit
        || !digest(&p.release_manifest_sha256)
        || !digest(&p.release_identity)
        || !digest(&p.prior_policy_digest)
        || !digest(&p.trust_bundle_digest)
        || !commit(&p.source_commit)
        || !key_hex(&p.journal_trust_root_public_key)
        || !key_hex(&p.evidence_trust_root_public_key)
        || p.signer_key_id != key_id
        || p.target_device == 0
        || p.target_inode == 0
        || p.recovery_state_device == 0
        || p.recovery_state_inode == 0
        || p.journal_device == 0
        || p.journal_inode == 0
    {
        return Err(SelectorError::Binding);
    }
    Ok(p)
}

#[derive(Debug, Clone, Copy)]
pub struct MigrationBindings<'a> {
    pub prior_sequence: u64,
    pub prior_tip_digest: &'a str,
    pub prior_policy_digest: &'a str,
    pub prior_policy_revision: u64,
    pub new_policy_digest: &'a str,
    pub prior_manifest_digest: &'a str,
    pub new_manifest_digest: &'a str,
    pub target_device: u64,
    pub target_inode: u64,
    pub trust_digest: &'a str,
}

pub fn verify_migration(
    bytes: &[u8],
    key_id: &str,
    key: &VerifyingKey,
    bindings: &MigrationBindings<'_>,
) -> Result<InstallationPolicyMigrationV1, SelectorError> {
    let m: InstallationPolicyMigrationV1 =
        identity::verify_signed(bytes, MIGRATION_FORMAT, key_id, key)
            .map_err(|_| SelectorError::Signature)?;
    if m.format != MIGRATION_FORMAT
        || successor(bindings.prior_sequence) != Some(m.sequence)
        || m.prior_record_digest != bindings.prior_tip_digest
        || m.prior_policy_format != "o3k-installation-policy-v1"
        || m.prior_policy_revision != bindings.prior_policy_revision
        || m.prior_policy_digest != bindings.prior_policy_digest
        || m.new_policy_format != V2_FORMAT
        || successor(bindings.prior_policy_revision) != Some(m.new_policy_revision)
        || m.new_policy_digest != bindings.new_policy_digest
        || m.prior_release_manifest_sha256 != bindings.prior_manifest_digest
        || m.new_release_manifest_sha256 != bindings.new_manifest_digest
        || m.signer_manifest_digest != bindings.new_manifest_digest
        || m.target_device != bindings.target_device
        || m.target_inode != bindings.target_inode
        || m.trust_bundle_digest != bindings.trust_digest
        || !digest(&m.prior_record_digest)
        || !digest(&m.prior_policy_digest)
        || !digest(&m.new_policy_digest)
        || !digest(&m.prior_release_manifest_sha256)
        || !digest(&m.new_release_manifest_sha256)
        || !digest(&m.trust_bundle_digest)
        || !nonempty(&m.installation_id)
        || !nonempty(&m.site_id)
        || !valid_release(&m.prior_release_identity)
        || !valid_release(&m.new_release_identity)
        || m.prior_release_identity.profile_id != m.new_release_identity.profile_id
        || m.prior_release_identity.source_commit.is_empty()
        || (m.preserved_state != identity::RecoveryState::NeverRecovered
            && m.checkpoint_digest.is_none())
        || m.checkpoint_digest.as_deref().is_some_and(|d| !digest(d))
    {
        return Err(SelectorError::Binding);
    }
    Ok(m)
}

/// Applies the installation and preserved-state bindings supplied by the
/// already-authenticated v1 generation. Callers must use this wrapper when
/// selecting the active format; the basic parser intentionally has no local
/// filesystem authority to infer these values.
pub fn verify_migration_identity(
    migration: &InstallationPolicyMigrationV1,
    installation_id: &str,
    site_id: &str,
    preserved_state: identity::RecoveryState,
) -> Result<(), SelectorError> {
    if migration.installation_id != installation_id
        || migration.site_id != site_id
        || migration.preserved_state != preserved_state
    {
        return Err(SelectorError::Binding);
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use ed25519_dalek::{Signer, SigningKey};

    #[allow(clippy::panic)]
    fn signed<T: Serialize>(_format: &str, value: &T, key: &SigningKey, signer: &str) -> Vec<u8> {
        let payload = match identity::canonical(value) {
            Ok(bytes) => bytes,
            Err(error) => panic!("test payload must canonicalize: {error:?}"),
        };
        let envelope = identity::SignatureEnvelope {
            algorithm: "Ed25519".into(),
            signer_key_id: signer.into(),
            signature: hex::encode(key.sign(&payload).to_bytes()),
        };
        match serde_jcs::to_vec(&identity::Signed {
            payload: value,
            envelope,
        }) {
            Ok(bytes) => bytes,
            Err(error) => panic!("test envelope must canonicalize: {error}"),
        }
    }

    fn policy() -> InstallationPolicyV2 {
        InstallationPolicyV2 {
            format: V2_FORMAT.into(),
            installation_id: "i".into(),
            site_id: "s".into(),
            profile: "o3k-small-edge-v1".into(),
            backend: "postgresql".into(),
            backend_version: "16".into(),
            deployment: "virtualized".into(),
            restore_branch_authorization: "inactive-materialization-only".into(),
            release_identity: "a".repeat(64),
            release_version: "v1".into(),
            source_commit: "b".repeat(40),
            release_manifest_sha256: "c".repeat(64),
            data_root: "/var/lib/o3k".into(),
            target_device: 1,
            target_inode: 2,
            policy_revision: 2,
            prior_policy_digest: "d".repeat(64),
            policy_path: "/etc/o3k/installation-policy.json".into(),
            trust_bundle_path: "/etc/o3k/recovery-trust.json".into(),
            trust_bundle_digest: "e".repeat(64),
            recovery_state_root: "/var/lib/o3k-recovery-state/i".into(),
            recovery_state_device: 3,
            recovery_state_inode: 4,
            journal_directory: "/var/lib/o3k-recovery/i".into(),
            journal_device: 5,
            journal_inode: 6,
            journal_trust_root_id: "jr".into(),
            journal_trust_root_public_key: "f".repeat(64),
            evidence_trust_root_id: "er".into(),
            evidence_trust_root_public_key: "1".repeat(64),
            signer_key_id: "policy".into(),
        }
    }

    fn release() -> ReleaseIdentity {
        ReleaseIdentity {
            version: "v1".into(),
            source_commit: "b".repeat(40),
            release_artifact_sha256: "a".repeat(64),
            profile_id: "o3k-small-edge-v1".into(),
            schema_version: 1,
        }
    }

    fn migration() -> InstallationPolicyMigrationV1 {
        InstallationPolicyMigrationV1 {
            format: MIGRATION_FORMAT.into(),
            installation_id: "i".into(),
            site_id: "s".into(),
            sequence: 5,
            prior_record_digest: "1".repeat(64),
            preserved_state: identity::RecoveryState::NeverRecovered,
            prior_policy_format: "o3k-installation-policy-v1".into(),
            prior_policy_revision: 5,
            prior_policy_digest: "2".repeat(64),
            new_policy_format: V2_FORMAT.into(),
            new_policy_revision: 6,
            new_policy_digest: "3".repeat(64),
            prior_release_manifest_sha256: "4".repeat(64),
            new_release_manifest_sha256: "5".repeat(64),
            prior_release_identity: release(),
            new_release_identity: release(),
            target_device: 7,
            target_inode: 8,
            trust_bundle_digest: "6".repeat(64),
            checkpoint_digest: None,
            signer_manifest_digest: "5".repeat(64),
        }
    }
    #[test]
    fn strict_types_reject_unknown_fields() {
        let value = serde_json::json!({"format": V2_FORMAT, "extra": true});
        assert!(serde_json::from_value::<InstallationPolicyV2>(value).is_err());
    }
    #[test]
    fn lowercase_hex_is_required() {
        assert!(digest(&"a".repeat(64)));
        assert!(!digest(&"A".repeat(64)));
    }

    #[test]
    fn successor_overflow_is_denied() {
        assert_eq!(successor(u64::MAX), None);
        assert_eq!(successor(7), Some(8));
    }

    #[test]
    fn valid_signed_v2_policy_and_bad_signature() {
        let key = SigningKey::from_bytes(&[7u8; 32]);
        let bytes = signed(V2_FORMAT, &policy(), &key, "policy");
        assert!(
            verify_v2_policy(
                &bytes,
                "policy",
                &key.verifying_key(),
                &"c".repeat(64),
                &"a".repeat(64),
                "v1",
                &"b".repeat(40)
            )
            .is_ok()
        );
        let other = SigningKey::from_bytes(&[8u8; 32]);
        assert!(matches!(
            verify_v2_policy(
                &bytes,
                "policy",
                &other.verifying_key(),
                &"c".repeat(64),
                &"a".repeat(64),
                "v1",
                &"b".repeat(40)
            ),
            Err(SelectorError::Signature)
        ));
    }

    #[test]
    fn valid_signed_migration_binds_sequence_signer_and_identity() {
        let key = SigningKey::from_bytes(&[9u8; 32]);
        let migration = migration();
        let bytes = signed(MIGRATION_FORMAT, &migration, &key, "policy");
        assert!(
            verify_migration(
                &bytes,
                "policy",
                &key.verifying_key(),
                &MigrationBindings {
                    prior_sequence: 4,
                    prior_tip_digest: &"1".repeat(64),
                    prior_policy_digest: &"2".repeat(64),
                    prior_policy_revision: 5,
                    new_policy_digest: &"3".repeat(64),
                    prior_manifest_digest: &"4".repeat(64),
                    new_manifest_digest: &"5".repeat(64),
                    target_device: 7,
                    target_inode: 8,
                    trust_digest: &"6".repeat(64),
                },
            )
            .is_ok()
        );
        assert!(
            verify_migration(
                &bytes,
                "policy",
                &key.verifying_key(),
                &MigrationBindings {
                    prior_sequence: 5,
                    prior_tip_digest: &"1".repeat(64),
                    prior_policy_digest: &"2".repeat(64),
                    prior_policy_revision: 5,
                    new_policy_digest: &"3".repeat(64),
                    prior_manifest_digest: &"4".repeat(64),
                    new_manifest_digest: &"5".repeat(64),
                    target_device: 7,
                    target_inode: 8,
                    trust_digest: &"6".repeat(64),
                },
            )
            .is_err()
        );
        assert!(matches!(
            verify_migration_identity(
                &migration,
                "other-installation",
                "s",
                identity::RecoveryState::NeverRecovered,
            ),
            Err(SelectorError::Binding)
        ));

        let other_key = SigningKey::from_bytes(&[10u8; 32]);
        assert!(matches!(
            verify_migration(
                &bytes,
                "policy",
                &other_key.verifying_key(),
                &MigrationBindings {
                    prior_sequence: 4,
                    prior_tip_digest: &"1".repeat(64),
                    prior_policy_digest: &"2".repeat(64),
                    prior_policy_revision: 5,
                    new_policy_digest: &"3".repeat(64),
                    prior_manifest_digest: &"4".repeat(64),
                    new_manifest_digest: &"5".repeat(64),
                    target_device: 7,
                    target_inode: 8,
                    trust_digest: &"6".repeat(64),
                },
            ),
            Err(SelectorError::Signature)
        ));

        let mut wrong_release = migration.clone();
        wrong_release.prior_release_identity.profile_id = "wrong-profile".into();
        let wrong_release_bytes = signed(MIGRATION_FORMAT, &wrong_release, &key, "policy");
        assert!(
            verify_migration(
                &wrong_release_bytes,
                "policy",
                &key.verifying_key(),
                &MigrationBindings {
                    prior_sequence: 4,
                    prior_tip_digest: &"1".repeat(64),
                    prior_policy_digest: &"2".repeat(64),
                    prior_policy_revision: 5,
                    new_policy_digest: &"3".repeat(64),
                    prior_manifest_digest: &"4".repeat(64),
                    new_manifest_digest: &"5".repeat(64),
                    target_device: 7,
                    target_inode: 8,
                    trust_digest: &"6".repeat(64),
                },
            )
            .is_err()
        );
    }
}
