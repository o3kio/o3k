use ed25519_dalek::{Signature, Verifier, VerifyingKey};
use serde::{Deserialize, Serialize, de::DeserializeOwned};
use sha2::{Digest, Sha256};
use std::collections::BTreeSet;

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum IdentityError {
    InvalidDocument,
    InvalidSignature,
    BindingMismatch,
    InvalidSequence,
    TrustInvalid,
}
impl std::fmt::Display for IdentityError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{self:?}")
    }
}
impl std::error::Error for IdentityError {}
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct SignatureEnvelope {
    pub algorithm: String,
    pub signer_key_id: String,
    pub signature: String,
}
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct Signed<T> {
    pub payload: T,
    pub envelope: SignatureEnvelope,
}
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct InstallationPolicy {
    pub format: String,
    pub installation_id: String,
    pub site_id: String,
    pub profile: String,
    pub backend: String,
    pub release_identity: String,
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
#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "SCREAMING_SNAKE_CASE")]
pub enum RecoveryState {
    NeverRecovered,
    RecoveryDesignated,
    Released,
}
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct InstallationState {
    pub format: String,
    pub installation_id: String,
    pub site_id: String,
    pub profile: String,
    pub backend: String,
    pub policy_revision: u64,
    pub policy_digest: String,
    pub target_device: u64,
    pub target_inode: u64,
    pub sequence: u64,
    pub prior_record_digest: String,
    pub state: RecoveryState,
    pub operation_id: Option<String>,
    pub artifact_sha256: Option<String>,
    pub recovery_directory_digest: Option<String>,
    pub trust_bundle_digest: Option<String>,
    pub terminal_journal_digest: Option<String>,
    pub evidence_digest: Option<String>,
}
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct TrustCertificate {
    pub format: String,
    pub key_id: String,
    pub public_key: String,
    pub purpose: String,
    pub site_id: String,
    pub installation_id: String,
    pub profile: String,
    pub backend: String,
    pub serial: String,
    pub not_before: i64,
    pub not_after: i64,
    pub issuer: String,
}
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct RevocationDocument {
    pub format: String,
    pub site_id: String,
    pub profile: String,
    pub sequence: u64,
    pub issued_at: i64,
    pub next_update: i64,
    pub revoked_serials: Vec<String>,
    pub revoked_key_ids: Vec<String>,
}
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct TrustBundle {
    pub format: String,
    pub site_id: String,
    pub profile: String,
    pub installation_id: String,
    pub backend: String,
    pub journal_root_key_id: String,
    pub journal_root_public_key: String,
    pub evidence_root_key_id: String,
    pub evidence_root_public_key: String,
    pub journal_revocation_sequence: u64,
    pub journal_revocation_digest: String,
    pub evidence_revocation_sequence: u64,
    pub evidence_revocation_digest: String,
    pub journal_certificate: Signed<TrustCertificate>,
    pub evidence_certificate: Signed<TrustCertificate>,
    pub journal_revocations: Signed<RevocationDocument>,
    pub evidence_revocations: Signed<RevocationDocument>,
}
pub fn canonical<T: Serialize>(v: &T) -> Result<Vec<u8>, IdentityError> {
    serde_jcs::to_vec(v).map_err(|_| IdentityError::InvalidDocument)
}
pub fn digest<T: Serialize>(v: &T) -> Result<String, IdentityError> {
    Ok(hex::encode(Sha256::digest(&canonical(v)?)))
}
pub fn decode_canonical<T: DeserializeOwned + Serialize>(b: &[u8]) -> Result<T, IdentityError> {
    let v: T = serde_json::from_slice(b).map_err(|_| IdentityError::InvalidDocument)?;
    if canonical(&v)? != b {
        return Err(IdentityError::InvalidDocument);
    }
    Ok(v)
}
pub fn verify_signed<T: DeserializeOwned + Serialize>(
    b: &[u8],
    format: &str,
    id: &str,
    key: &VerifyingKey,
) -> Result<T, IdentityError> {
    let s: Signed<T> = decode_canonical(b)?;
    if s.envelope.algorithm != "Ed25519" || s.envelope.signer_key_id != id {
        return Err(IdentityError::BindingMismatch);
    }
    let sig = hex::decode(&s.envelope.signature).map_err(|_| IdentityError::InvalidSignature)?;
    let sig = Signature::from_slice(&sig).map_err(|_| IdentityError::InvalidSignature)?;
    key.verify(canonical(&s.payload)?.as_slice(), &sig)
        .map_err(|_| IdentityError::InvalidSignature)?;
    let x = serde_json::to_value(&s.payload).map_err(|_| IdentityError::InvalidDocument)?;
    if x.get("format").and_then(|v| v.as_str()) != Some(format) {
        return Err(IdentityError::BindingMismatch);
    }
    Ok(s.payload)
}
pub fn verify_policy(p: &InstallationPolicy, id: &str) -> Result<(), IdentityError> {
    if p.format != "o3k-installation-policy-v1"
        || p.signer_key_id != id
        || [
            &p.installation_id,
            &p.site_id,
            &p.profile,
            &p.backend,
            &p.data_root,
            &p.policy_path,
            &p.trust_bundle_path,
            &p.trust_bundle_digest,
            &p.recovery_state_root,
            &p.journal_directory,
            &p.journal_trust_root_id,
            &p.evidence_trust_root_id,
        ]
        .iter()
        .any(|x| x.is_empty())
        || !matches!(p.profile.as_str(), "o3k-demo-v1" | "o3k-small-edge-v1")
        || !matches!(p.backend.as_str(), "sqlite" | "postgresql")
        || !absolute_canonical_path(&p.data_root)
        || !absolute_canonical_path(&p.policy_path)
        || !absolute_canonical_path(&p.trust_bundle_path)
        || !absolute_canonical_path(&p.recovery_state_root)
        || !absolute_canonical_path(&p.journal_directory)
        // Device/inode bindings of zero cannot describe a real directory;
        // accepting them would let a zero-initialized policy bind anywhere.
        || p.target_device == 0
        || p.target_inode == 0
        || p.recovery_state_device == 0
        || p.recovery_state_inode == 0
        || p.journal_device == 0
        || p.journal_inode == 0
        || !key32_hex(&p.journal_trust_root_public_key)
        || !key32_hex(&p.evidence_trust_root_public_key)
        || p.journal_trust_root_id == p.evidence_trust_root_id
        || p.signer_key_id == p.journal_trust_root_id
        || p.signer_key_id == p.evidence_trust_root_id
        || p.journal_trust_root_public_key == p.evidence_trust_root_public_key
    {
        return Err(IdentityError::BindingMismatch);
    }
    Ok(())
}

fn absolute_canonical_path(s: &str) -> bool {
    let path = std::path::Path::new(s);
    path.is_absolute()
        && path.components().all(|c| {
            matches!(
                c,
                std::path::Component::RootDir | std::path::Component::Normal(_)
            )
        })
}

fn key32_hex(s: &str) -> bool {
    hex_digest(s) && hex::decode(s).is_ok_and(|bytes| bytes.len() == 32)
}
fn hex_digest(s: &str) -> bool {
    s.len() == 64
        && s.bytes()
            .all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(&b))
}
fn valid_operation_id(value: &Option<String>) -> bool {
    value
        .as_deref()
        .is_some_and(|value| uuid::Uuid::parse_str(value).is_ok())
}
/// Verifies the sequence-zero `NEVER_RECOVERED` record signed by the
/// installation-policy authority.  This is the only transition that does not
/// bind a prior record digest; every later record must be validated with
/// [`verify_state_transition_with_previous_digest`] so the exact predecessor
/// is part of the check.
pub fn verify_initial_state_transition(
    prev: Option<&InstallationState>,
    next: &InstallationState,
    p: &InstallationPolicy,
) -> Result<(), IdentityError> {
    if prev.is_some() {
        return Err(IdentityError::InvalidSequence);
    };
    verify_state_transition_inner(prev, next, p, None)
}
fn verify_state_transition_inner(
    prev: Option<&InstallationState>,
    n: &InstallationState,
    p: &InstallationPolicy,
    expected: Option<&str>,
) -> Result<(), IdentityError> {
    if n.format != "o3k-installation-state-v1"
        || n.installation_id != p.installation_id
        || n.site_id != p.site_id
        || n.profile != p.profile
        || n.backend != p.backend
        || n.policy_revision != p.policy_revision
        || n.target_device != p.target_device
        || n.target_inode != p.target_inode
    {
        return Err(IdentityError::BindingMismatch);
    }
    match (prev, n.state) {
        (None, RecoveryState::NeverRecovered)
            if n.sequence == 0
                && n.prior_record_digest.is_empty()
                && hex_digest(&n.policy_digest)
                && n.operation_id.is_none()
                && n.artifact_sha256.is_none()
                && n.recovery_directory_digest.is_none()
                && n.trust_bundle_digest.is_none()
                && n.terminal_journal_digest.is_none()
                && n.evidence_digest.is_none() =>
        {
            Ok(())
        }
        (Some(o), RecoveryState::RecoveryDesignated)
            if o.state == RecoveryState::NeverRecovered
                && o.sequence.checked_add(1) == Some(n.sequence)
                && Some(n.prior_record_digest.as_str()) == expected
                && valid_operation_id(&n.operation_id)
                && n.artifact_sha256.as_deref().is_some_and(hex_digest)
                && n.recovery_directory_digest
                    .as_deref()
                    .is_some_and(hex_digest)
                && n.trust_bundle_digest.as_deref().is_some_and(hex_digest)
                && n.terminal_journal_digest.is_none()
                && n.evidence_digest.is_none() =>
        {
            Ok(())
        }
        (Some(o), RecoveryState::Released)
            if o.state == RecoveryState::RecoveryDesignated
                && o.sequence.checked_add(1) == Some(n.sequence)
                && Some(n.prior_record_digest.as_str()) == expected
                && n.terminal_journal_digest.as_deref().is_some_and(hex_digest)
                && n.evidence_digest.as_deref().is_some_and(hex_digest)
                && n.policy_digest == o.policy_digest
                && n.operation_id == o.operation_id
                && n.artifact_sha256 == o.artifact_sha256 =>
        {
            Ok(())
        }
        _ => Err(IdentityError::InvalidSequence),
    }
}
pub fn verify_state_transition_with_previous_digest(
    prev: Option<&InstallationState>,
    d: Option<&str>,
    n: &InstallationState,
    p: &InstallationPolicy,
) -> Result<(), IdentityError> {
    if prev.is_some() && !d.is_some_and(hex_digest) {
        return Err(IdentityError::InvalidSequence);
    }
    verify_state_transition_inner(prev, n, p, d)
}
pub struct CertificateScope<'a> {
    pub purpose: &'a str,
    pub site: &'a str,
    pub installation: &'a str,
    pub profile: &'a str,
    pub backend: &'a str,
    pub issuer: &'a str,
    pub now: i64,
}

pub fn verify_certificate_binding(
    c: &TrustCertificate,
    scope: CertificateScope<'_>,
) -> Result<(), IdentityError> {
    let fmt = match scope.purpose {
        "restore_journal" => "o3k-journal-authority-v1",
        "recovery_evidence" => "o3k-evidence-authority-v1",
        _ => "",
    };
    if c.format != fmt
        || c.purpose != scope.purpose
        || c.site_id != scope.site
        || c.installation_id != scope.installation
        || c.profile != scope.profile
        || c.backend != scope.backend
        || c.issuer != scope.issuer
        || c.serial.is_empty()
        || c.key_id.is_empty()
        || c.public_key.is_empty()
        || c.not_after <= c.not_before
        || c.not_after
            .checked_sub(c.not_before)
            .is_none_or(|x| x > 90 * 86400)
        || scope.now < c.not_before
        || scope.now >= c.not_after
    {
        return Err(IdentityError::TrustInvalid);
    }
    Ok(())
}
pub fn verify_revocation(
    d: &RevocationDocument,
    site: &str,
    profile: &str,
    now: i64,
    prior: Option<(u64, &str)>,
) -> Result<(), IdentityError> {
    let dg = digest(d)?;
    if d.format != "o3k-recovery-revocations-v1"
        || d.site_id != site
        || d.profile != profile
        || d.next_update <= d.issued_at
        || now < d.issued_at
        || now >= d.next_update
        || d.next_update
            .checked_sub(d.issued_at)
            .is_none_or(|x| x > 86400)
        || prior.is_some_and(|(s, h)| d.sequence < s || (d.sequence == s && h != dg))
    {
        return Err(IdentityError::TrustInvalid);
    }
    let mut a = BTreeSet::new();
    let mut b = BTreeSet::new();
    if !d.revoked_serials.iter().all(|x| a.insert(x))
        || !d.revoked_key_ids.iter().all(|x| b.insert(x))
    {
        return Err(IdentityError::TrustInvalid);
    }
    Ok(())
}
impl From<serde_json::Error> for IdentityError {
    fn from(_: serde_json::Error) -> Self {
        Self::InvalidDocument
    }
}

#[cfg(test)]
#[allow(clippy::expect_used, clippy::unwrap_used)]
mod tests {
    use super::*;
    use ed25519_dalek::{Signer, SigningKey};

    const POLICY_SIGNER_ID: &str = "policy-signer-1";
    const JOURNAL_ROOT_ID: &str = "journal-root-1";
    const EVIDENCE_ROOT_ID: &str = "evidence-root-1";
    const NOW: i64 = 1_800_000_000;

    fn keypair(seed: u8) -> (SigningKey, VerifyingKey) {
        let signing = SigningKey::from_bytes(&[seed; 32]);
        let verifying = signing.verifying_key();
        (signing, verifying)
    }

    fn key_id_hex(verifying: &VerifyingKey) -> String {
        hex::encode(verifying.as_bytes())
    }

    fn sign_payload<T: Serialize + Clone>(
        payload: &T,
        signing: &SigningKey,
        signer_key_id: &str,
    ) -> Vec<u8> {
        let canonical_payload = canonical(payload).expect("canonical payload");
        let envelope = SignatureEnvelope {
            algorithm: "Ed25519".to_string(),
            signer_key_id: signer_key_id.to_string(),
            signature: hex::encode(signing.sign(&canonical_payload).to_bytes()),
        };
        canonical(&Signed {
            payload: payload.clone(),
            envelope,
        })
        .expect("canonical signed document")
    }

    fn hex64(seed: u8) -> String {
        hex::encode([seed; 32])
    }

    fn valid_policy(
        signer_id: &str,
        journal_root_pub: &str,
        evidence_root_pub: &str,
    ) -> InstallationPolicy {
        InstallationPolicy {
            format: "o3k-installation-policy-v1".to_string(),
            installation_id: "inst-1".to_string(),
            site_id: "site-1".to_string(),
            profile: "o3k-demo-v1".to_string(),
            backend: "sqlite".to_string(),
            release_identity: hex64(9),
            data_root: "/var/lib/o3k".to_string(),
            target_device: 2049,
            target_inode: 12_345,
            policy_revision: 1,
            prior_policy_digest: hex64(8),
            policy_path: "/etc/o3k/installation-policy.json".to_string(),
            trust_bundle_path: "/etc/o3k/recovery-trust.json".to_string(),
            trust_bundle_digest: hex64(7),
            recovery_state_root: "/var/lib/o3k-recovery-state/inst-1".to_string(),
            recovery_state_device: 2049,
            recovery_state_inode: 45_678,
            journal_directory: "/var/lib/o3k-recovery/inst-1".to_string(),
            journal_device: 2049,
            journal_inode: 78_901,
            journal_trust_root_id: JOURNAL_ROOT_ID.to_string(),
            journal_trust_root_public_key: journal_root_pub.to_string(),
            evidence_trust_root_id: EVIDENCE_ROOT_ID.to_string(),
            evidence_trust_root_public_key: evidence_root_pub.to_string(),
            signer_key_id: signer_id.to_string(),
        }
    }

    fn valid_initial_state(policy: &InstallationPolicy) -> InstallationState {
        InstallationState {
            format: "o3k-installation-state-v1".to_string(),
            installation_id: policy.installation_id.clone(),
            site_id: policy.site_id.clone(),
            profile: policy.profile.clone(),
            backend: policy.backend.clone(),
            policy_revision: policy.policy_revision,
            policy_digest: hex64(3),
            target_device: policy.target_device,
            target_inode: policy.target_inode,
            sequence: 0,
            prior_record_digest: String::new(),
            state: RecoveryState::NeverRecovered,
            operation_id: None,
            artifact_sha256: None,
            recovery_directory_digest: None,
            trust_bundle_digest: None,
            terminal_journal_digest: None,
            evidence_digest: None,
        }
    }

    fn valid_designation(policy: &InstallationPolicy, previous_digest: &str) -> InstallationState {
        InstallationState {
            sequence: 1,
            prior_record_digest: previous_digest.to_string(),
            state: RecoveryState::RecoveryDesignated,
            operation_id: Some(uuid::Uuid::now_v7().to_string()),
            artifact_sha256: Some(hex64(4)),
            recovery_directory_digest: Some(hex64(5)),
            trust_bundle_digest: Some(policy.trust_bundle_digest.clone()),
            terminal_journal_digest: None,
            evidence_digest: None,
            ..valid_initial_state(policy)
        }
    }

    fn valid_release(designated: &InstallationState, prior_digest: &str) -> InstallationState {
        InstallationState {
            sequence: designated.sequence + 1,
            prior_record_digest: prior_digest.to_string(),
            state: RecoveryState::Released,
            terminal_journal_digest: Some(hex64(6)),
            evidence_digest: Some(hex64(11)),
            ..designated.clone()
        }
    }

    #[test]
    fn canonical_digest_and_decode_roundtrip() {
        let policy = valid_policy(POLICY_SIGNER_ID, &hex64(1), &hex64(2));
        let bytes = canonical(&policy).expect("canonical");
        let decoded: InstallationPolicy = decode_canonical(&bytes).expect("decode");
        assert_eq!(decoded, policy);
        assert_eq!(
            digest(&policy).expect("digest"),
            hex::encode(Sha256::digest(&bytes))
        );
        // Bytes whose key order already differs from canonical JCS order
        // (JCS emits "backend" before "format") are not canonical.
        let reordered = br#"{"format":"o3k-installation-policy-v1","backend":"sqlite"}"#;
        assert!(decode_canonical::<serde_json::Value>(reordered).is_err());
    }

    #[test]
    fn verify_signed_accepts_valid_document() {
        let (signing, verifying) = keypair(1);
        let bytes = sign_payload(
            &valid_initial_state(&valid_policy(
                POLICY_SIGNER_ID,
                &key_id_hex(&keypair(2).1),
                &key_id_hex(&keypair(3).1),
            )),
            &signing,
            "state-signer",
        );
        let _: InstallationState = verify_signed(
            &bytes,
            "o3k-installation-state-v1",
            "state-signer",
            &verifying,
        )
        .expect("valid signature verifies");
    }

    #[test]
    fn verify_signed_rejects_wrong_algorithm_signer_and_format() {
        let (signing, verifying) = keypair(1);
        let payload = valid_initial_state(&valid_policy(
            POLICY_SIGNER_ID,
            &key_id_hex(&keypair(2).1),
            &key_id_hex(&keypair(3).1),
        ));
        let mut envelope = SignatureEnvelope {
            algorithm: "Ed25519".to_string(),
            signer_key_id: "state-signer".to_string(),
            signature: hex::encode(signing.sign(&canonical(&payload).unwrap()).to_bytes()),
        };
        let document = |envelope: &SignatureEnvelope| {
            canonical(&Signed {
                payload: payload.clone(),
                envelope: envelope.clone(),
            })
            .unwrap()
        };
        envelope.algorithm = "Ed25519ph".to_string();
        assert_eq!(
            verify_signed::<InstallationState>(
                &document(&envelope),
                "o3k-installation-state-v1",
                "state-signer",
                &verifying
            ),
            Err(IdentityError::BindingMismatch)
        );
        envelope.algorithm = "Ed25519".to_string();
        envelope.signer_key_id = "other-signer".to_string();
        assert_eq!(
            verify_signed::<InstallationState>(
                &document(&envelope),
                "o3k-installation-state-v1",
                "state-signer",
                &verifying
            ),
            Err(IdentityError::BindingMismatch)
        );
        envelope.signer_key_id = "state-signer".to_string();
        let (_, other) = keypair(42);
        envelope.signature = hex::encode(other.as_bytes());
        assert_eq!(
            verify_signed::<InstallationState>(
                &document(&envelope),
                "o3k-installation-state-v1",
                "state-signer",
                &verifying
            ),
            Err(IdentityError::InvalidSignature)
        );
    }

    #[test]
    fn verify_signed_rejects_payload_format_mismatch() {
        let (signing, verifying) = keypair(1);
        let mut payload = valid_initial_state(&valid_policy(
            POLICY_SIGNER_ID,
            &key_id_hex(&keypair(2).1),
            &key_id_hex(&keypair(3).1),
        ));
        payload.format = "o3k-installation-state-v2".to_string();
        let bytes = sign_payload(&payload, &signing, "state-signer");
        assert_eq!(
            verify_signed::<InstallationState>(
                &bytes,
                "o3k-installation-state-v1",
                "state-signer",
                &verifying
            ),
            Err(IdentityError::BindingMismatch)
        );
    }

    #[test]
    fn verify_policy_accepts_valid_policy() {
        let (_, journal_root) = keypair(2);
        let (_, evidence_root) = keypair(3);
        let policy = valid_policy(
            POLICY_SIGNER_ID,
            &key_id_hex(&journal_root),
            &key_id_hex(&evidence_root),
        );
        assert_eq!(verify_policy(&policy, POLICY_SIGNER_ID), Ok(()));
    }

    #[test]
    fn verify_policy_rejects_empty_fields_and_bad_profile_backend() {
        let (_, journal_root) = keypair(2);
        let (_, evidence_root) = keypair(3);
        let journal_pub = key_id_hex(&journal_root);
        let evidence_pub = key_id_hex(&evidence_root);
        let base = || valid_policy(POLICY_SIGNER_ID, &journal_pub, &evidence_pub);
        for policy in [
            {
                let mut p = base();
                p.installation_id.clear();
                p
            },
            {
                let mut p = base();
                p.site_id.clear();
                p
            },
            {
                let mut p = base();
                p.data_root.clear();
                p
            },
            {
                let mut p = base();
                p.trust_bundle_digest.clear();
                p
            },
            {
                let mut p = base();
                p.policy_path.clear();
                p
            },
            {
                let mut p = base();
                p.recovery_state_root.clear();
                p
            },
            {
                let mut p = base();
                p.journal_directory.clear();
                p
            },
            {
                let mut p = base();
                p.journal_trust_root_id.clear();
                p
            },
            {
                let mut p = base();
                p.signer_key_id.clear();
                p
            },
        ] {
            assert_eq!(
                verify_policy(&policy, POLICY_SIGNER_ID),
                Err(IdentityError::BindingMismatch),
                "policy with cleared field {:?} must fail",
                policy.installation_id
            );
        }
        let mut policy = base();
        policy.profile = "o3k-large-cloud-v1".to_string();
        assert_eq!(
            verify_policy(&policy, POLICY_SIGNER_ID),
            Err(IdentityError::BindingMismatch)
        );
        let mut policy = base();
        policy.backend = "mysql".to_string();
        assert_eq!(
            verify_policy(&policy, POLICY_SIGNER_ID),
            Err(IdentityError::BindingMismatch)
        );
        let mut policy = base();
        policy.signer_key_id = "someone-else".to_string();
        assert_eq!(
            verify_policy(&policy, POLICY_SIGNER_ID),
            Err(IdentityError::BindingMismatch)
        );
    }

    #[test]
    fn verify_policy_rejects_noncanonical_paths_zero_identities_and_key_confusion() {
        let (_, journal_root) = keypair(2);
        let (_, evidence_root) = keypair(3);
        let journal_pub = key_id_hex(&journal_root);
        let evidence_pub = key_id_hex(&evidence_root);
        let base = || valid_policy(POLICY_SIGNER_ID, &journal_pub, &evidence_pub);

        let mut policy = base();
        policy.data_root = "var/lib/o3k".to_string();
        assert_eq!(
            verify_policy(&policy, POLICY_SIGNER_ID),
            Err(IdentityError::BindingMismatch)
        );
        let mut policy = base();
        policy.journal_directory = "/var/lib/o3k-recovery/../o3k-other".to_string();
        assert_eq!(
            verify_policy(&policy, POLICY_SIGNER_ID),
            Err(IdentityError::BindingMismatch)
        );

        for zero in [
            {
                let mut p = base();
                p.target_device = 0;
                p
            },
            {
                let mut p = base();
                p.target_inode = 0;
                p
            },
            {
                let mut p = base();
                p.recovery_state_device = 0;
                p
            },
            {
                let mut p = base();
                p.recovery_state_inode = 0;
                p
            },
            {
                let mut p = base();
                p.journal_device = 0;
                p
            },
            {
                let mut p = base();
                p.journal_inode = 0;
                p
            },
        ] {
            assert_eq!(
                verify_policy(&zero, POLICY_SIGNER_ID),
                Err(IdentityError::BindingMismatch)
            );
        }

        let mut policy = base();
        policy.journal_trust_root_public_key = "zz".repeat(32);
        assert_eq!(
            verify_policy(&policy, POLICY_SIGNER_ID),
            Err(IdentityError::BindingMismatch)
        );
        let mut policy = base();
        policy.journal_trust_root_public_key = hex::encode([1u8; 16]);
        assert_eq!(
            verify_policy(&policy, POLICY_SIGNER_ID),
            Err(IdentityError::BindingMismatch)
        );

        let mut policy = base();
        policy.journal_trust_root_id = policy.evidence_trust_root_id.clone();
        assert_eq!(
            verify_policy(&policy, POLICY_SIGNER_ID),
            Err(IdentityError::BindingMismatch)
        );
        let mut policy = base();
        policy.signer_key_id = JOURNAL_ROOT_ID.to_string();
        assert_eq!(
            verify_policy(&policy, JOURNAL_ROOT_ID),
            Err(IdentityError::BindingMismatch)
        );
        let mut policy = base();
        policy.journal_trust_root_public_key = policy.evidence_trust_root_public_key.clone();
        assert_eq!(
            verify_policy(&policy, POLICY_SIGNER_ID),
            Err(IdentityError::BindingMismatch)
        );
    }

    #[test]
    fn initial_transition_accepts_exact_sequence_zero_record() {
        let (_, journal_root) = keypair(2);
        let (_, evidence_root) = keypair(3);
        let policy = valid_policy(
            POLICY_SIGNER_ID,
            &key_id_hex(&journal_root),
            &key_id_hex(&evidence_root),
        );
        let initial = valid_initial_state(&policy);
        assert_eq!(
            verify_initial_state_transition(None, &initial, &policy),
            Ok(())
        );
    }

    #[test]
    fn initial_transition_rejects_rollback_equivocation_and_foreign_binding() {
        let (_, journal_root) = keypair(2);
        let (_, evidence_root) = keypair(3);
        let policy = valid_policy(
            POLICY_SIGNER_ID,
            &key_id_hex(&journal_root),
            &key_id_hex(&evidence_root),
        );
        let mut initial = valid_initial_state(&policy);

        // A predecessor is never acceptable for sequence zero.
        let mut later = valid_designation(&policy, &hex64(20));
        later.sequence = 0;
        assert_eq!(
            verify_initial_state_transition(Some(&initial), &later, &policy),
            Err(IdentityError::InvalidSequence)
        );

        initial.sequence = 1;
        assert_eq!(
            verify_initial_state_transition(None, &initial, &policy),
            Err(IdentityError::InvalidSequence)
        );
        initial.sequence = 0;
        initial.prior_record_digest = hex64(20);
        assert_eq!(
            verify_initial_state_transition(None, &initial, &policy),
            Err(IdentityError::InvalidSequence)
        );
        initial.prior_record_digest.clear();
        initial.policy_digest = "not-hex".to_string();
        assert_eq!(
            verify_initial_state_transition(None, &initial, &policy),
            Err(IdentityError::InvalidSequence)
        );
        initial.policy_digest = hex64(3);
        initial.operation_id = Some(uuid::Uuid::now_v7().to_string());
        assert_eq!(
            verify_initial_state_transition(None, &initial, &policy),
            Err(IdentityError::InvalidSequence)
        );
        initial.operation_id = None;
        initial.evidence_digest = Some(hex64(21));
        assert_eq!(
            verify_initial_state_transition(None, &initial, &policy),
            Err(IdentityError::InvalidSequence)
        );
        initial.evidence_digest = None;

        // A signed non-initial state can never be validated as sequence zero.
        let designated = valid_designation(&policy, &hex64(22));
        assert_eq!(
            verify_initial_state_transition(None, &designated, &policy),
            Err(IdentityError::InvalidSequence)
        );

        // Binding to a different policy fails even for a well-formed record.
        let mut foreign = valid_initial_state(&policy);
        foreign.installation_id = "inst-2".to_string();
        assert_eq!(
            verify_initial_state_transition(None, &foreign, &policy),
            Err(IdentityError::BindingMismatch)
        );
    }

    #[test]
    fn designation_requires_exact_predecessor_digest_and_complete_binding() {
        let (_, journal_root) = keypair(2);
        let (_, evidence_root) = keypair(3);
        let policy = valid_policy(
            POLICY_SIGNER_ID,
            &key_id_hex(&journal_root),
            &key_id_hex(&evidence_root),
        );
        let initial = valid_initial_state(&policy);
        let initial_digest = digest(&initial).expect("digest");
        let designated = valid_designation(&policy, &initial_digest);
        assert_eq!(
            verify_state_transition_with_previous_digest(
                Some(&initial),
                Some(&initial_digest),
                &designated,
                &policy
            ),
            Ok(())
        );

        // The previous digest is mandatory and must be the exact predecessor.
        assert_eq!(
            verify_state_transition_with_previous_digest(
                Some(&initial),
                None,
                &designated,
                &policy
            ),
            Err(IdentityError::InvalidSequence)
        );
        assert_eq!(
            verify_state_transition_with_previous_digest(
                Some(&initial),
                Some("abcd"),
                &designated,
                &policy
            ),
            Err(IdentityError::InvalidSequence)
        );
        let other_digest = hex64(30);
        assert_eq!(
            verify_state_transition_with_previous_digest(
                Some(&initial),
                Some(&other_digest),
                &designated,
                &policy
            ),
            Err(IdentityError::InvalidSequence)
        );

        // Sequence must advance by exactly one from the observed predecessor.
        let mut fork = designated.clone();
        fork.sequence = 3;
        assert_eq!(
            verify_state_transition_with_previous_digest(
                Some(&initial),
                Some(&initial_digest),
                &fork,
                &policy
            ),
            Err(IdentityError::InvalidSequence)
        );

        // The predecessor state must be the exact sequence-zero record.
        let designated_again = valid_designation(&policy, &initial_digest);
        assert_eq!(
            verify_state_transition_with_previous_digest(
                Some(&designated),
                Some(&initial_digest),
                &designated_again,
                &policy
            ),
            Err(IdentityError::InvalidSequence)
        );
    }

    #[test]
    fn designation_rejects_missing_or_noncanonical_binding_fields() {
        let (_, journal_root) = keypair(2);
        let (_, evidence_root) = keypair(3);
        let policy = valid_policy(
            POLICY_SIGNER_ID,
            &key_id_hex(&journal_root),
            &key_id_hex(&evidence_root),
        );
        let initial = valid_initial_state(&policy);
        let initial_digest = digest(&initial).expect("digest");

        let mut bad_operation = valid_designation(&policy, &initial_digest);
        bad_operation.operation_id = None;
        assert!(
            verify_state_transition_with_previous_digest(
                Some(&initial),
                Some(&initial_digest),
                &bad_operation,
                &policy
            )
            .is_err()
        );
        let mut bad_operation = valid_designation(&policy, &initial_digest);
        bad_operation.operation_id = Some("not-a-uuid".to_string());
        assert!(
            verify_state_transition_with_previous_digest(
                Some(&initial),
                Some(&initial_digest),
                &bad_operation,
                &policy
            )
            .is_err()
        );
        for bad in [
            {
                let mut d = valid_designation(&policy, &initial_digest);
                d.artifact_sha256 = None;
                d
            },
            {
                let mut d = valid_designation(&policy, &initial_digest);
                d.artifact_sha256 = Some("zz".repeat(32));
                d
            },
            {
                let mut d = valid_designation(&policy, &initial_digest);
                d.recovery_directory_digest = None;
                d
            },
            {
                let mut d = valid_designation(&policy, &initial_digest);
                d.trust_bundle_digest = None;
                d
            },
            {
                let mut d = valid_designation(&policy, &initial_digest);
                d.terminal_journal_digest = Some(hex64(31));
                d
            },
            {
                let mut d = valid_designation(&policy, &initial_digest);
                d.evidence_digest = Some(hex64(32));
                d
            },
        ] {
            assert!(
                verify_state_transition_with_previous_digest(
                    Some(&initial),
                    Some(&initial_digest),
                    &bad,
                    &policy
                )
                .is_err(),
                "designation with corrupted field {:?} must fail",
                bad.state
            );
        }
    }

    #[test]
    fn released_requires_designated_predecessor_and_exact_continuity() {
        let (_, journal_root) = keypair(2);
        let (_, evidence_root) = keypair(3);
        let policy = valid_policy(
            POLICY_SIGNER_ID,
            &key_id_hex(&journal_root),
            &key_id_hex(&evidence_root),
        );
        let initial = valid_initial_state(&policy);
        let initial_digest = digest(&initial).expect("digest");
        let designated = valid_designation(&policy, &initial_digest);
        let designated_digest = digest(&designated).expect("digest");
        let released = valid_release(&designated, &designated_digest);
        assert_eq!(
            verify_state_transition_with_previous_digest(
                Some(&designated),
                Some(&designated_digest),
                &released,
                &policy
            ),
            Ok(())
        );

        // RELEASED from NEVER_RECOVERED skips the designation and is rejected.
        assert_eq!(
            verify_state_transition_with_previous_digest(
                Some(&initial),
                Some(&initial_digest),
                &released,
                &policy
            ),
            Err(IdentityError::InvalidSequence)
        );
        // Wrong predecessor digest or a sequence gap is anti-rollback failure.
        assert_eq!(
            verify_state_transition_with_previous_digest(
                Some(&designated),
                Some(&initial_digest),
                &released,
                &policy
            ),
            Err(IdentityError::InvalidSequence)
        );
        let mut gap = released.clone();
        gap.sequence = 4;
        assert_eq!(
            verify_state_transition_with_previous_digest(
                Some(&designated),
                Some(&designated_digest),
                &gap,
                &policy
            ),
            Err(IdentityError::InvalidSequence)
        );

        // Continuity of policy, operation and artifact is mandatory.
        let mut changed_policy = released.clone();
        changed_policy.policy_digest = hex64(40);
        assert_eq!(
            verify_state_transition_with_previous_digest(
                Some(&designated),
                Some(&designated_digest),
                &changed_policy,
                &policy
            ),
            Err(IdentityError::InvalidSequence)
        );
        let mut changed_operation = released.clone();
        changed_operation.operation_id = Some(uuid::Uuid::now_v7().to_string());
        assert_eq!(
            verify_state_transition_with_previous_digest(
                Some(&designated),
                Some(&designated_digest),
                &changed_operation,
                &policy
            ),
            Err(IdentityError::InvalidSequence)
        );
        let mut changed_artifact = released.clone();
        changed_artifact.artifact_sha256 = Some(hex64(41));
        assert_eq!(
            verify_state_transition_with_previous_digest(
                Some(&designated),
                Some(&designated_digest),
                &changed_artifact,
                &policy
            ),
            Err(IdentityError::InvalidSequence)
        );

        // Terminal journal and evidence digests must be present and canonical.
        for corrupted in [
            {
                let mut r = released.clone();
                r.terminal_journal_digest = None;
                r
            },
            {
                let mut r = released.clone();
                r.terminal_journal_digest = Some("short".to_string());
                r
            },
            {
                let mut r = released.clone();
                r.evidence_digest = None;
                r
            },
            {
                let mut r = released.clone();
                r.evidence_digest = Some("zz".repeat(32));
                r
            },
        ] {
            assert_eq!(
                verify_state_transition_with_previous_digest(
                    Some(&designated),
                    Some(&designated_digest),
                    &corrupted,
                    &policy
                ),
                Err(IdentityError::InvalidSequence),
                "RELEASED with corrupted terminal fields must fail"
            );
        }
    }

    fn valid_certificate(
        purpose: &str,
        key_id: &str,
        public_key: &str,
        issuer: &str,
    ) -> TrustCertificate {
        let format = match purpose {
            "restore_journal" => "o3k-journal-authority-v1",
            "recovery_evidence" => "o3k-evidence-authority-v1",
            _ => "unknown",
        };
        TrustCertificate {
            format: format.to_string(),
            key_id: key_id.to_string(),
            public_key: public_key.to_string(),
            purpose: purpose.to_string(),
            site_id: "site-1".to_string(),
            installation_id: "inst-1".to_string(),
            profile: "o3k-demo-v1".to_string(),
            backend: "sqlite".to_string(),
            serial: "serial-1".to_string(),
            not_before: NOW - 1000,
            not_after: NOW + 1000,
            issuer: issuer.to_string(),
        }
    }

    fn certificate_scope(issuer: &'static str) -> CertificateScope<'static> {
        CertificateScope {
            purpose: "restore_journal",
            site: "site-1",
            installation: "inst-1",
            profile: "o3k-demo-v1",
            backend: "sqlite",
            issuer,
            now: NOW,
        }
    }

    #[test]
    fn certificate_binding_accepts_exact_purpose_and_scope() {
        let (_, journal_root) = keypair(2);
        let public = key_id_hex(&journal_root);
        let cert = valid_certificate(
            "restore_journal",
            "journal-signer-1",
            &public,
            JOURNAL_ROOT_ID,
        );
        assert_eq!(
            verify_certificate_binding(&cert, certificate_scope(JOURNAL_ROOT_ID)),
            Ok(())
        );
    }

    #[test]
    fn certificate_binding_rejects_wrong_purpose_scope_and_validity() {
        let (_, journal_root) = keypair(2);
        let public = key_id_hex(&journal_root);
        let base = || {
            valid_certificate(
                "restore_journal",
                "journal-signer-1",
                &public,
                JOURNAL_ROOT_ID,
            )
        };

        let mut cert = base();
        cert.purpose = "backup_artifact".to_string();
        assert_eq!(
            verify_certificate_binding(&cert, certificate_scope(JOURNAL_ROOT_ID)),
            Err(IdentityError::TrustInvalid)
        );

        for cert in [
            {
                let mut c = base();
                c.format = "o3k-evidence-authority-v1".to_string();
                c
            },
            {
                let mut c = base();
                c.site_id = "site-2".to_string();
                c
            },
            {
                let mut c = base();
                c.installation_id = "inst-2".to_string();
                c
            },
            {
                let mut c = base();
                c.profile = "o3k-small-edge-v1".to_string();
                c
            },
            {
                let mut c = base();
                c.backend = "postgresql".to_string();
                c
            },
            {
                let mut c = base();
                c.issuer = EVIDENCE_ROOT_ID.to_string();
                c
            },
            {
                let mut c = base();
                c.serial.clear();
                c
            },
            {
                let mut c = base();
                c.key_id.clear();
                c
            },
            {
                let mut c = base();
                c.public_key.clear();
                c
            },
            {
                let mut c = base();
                c.not_after = c.not_before;
                c
            },
            {
                let mut c = base();
                c.not_after = c.not_before + 91 * 86400;
                c
            },
            {
                let mut c = base();
                c.not_after = NOW - 1;
                c
            },
            {
                let mut c = base();
                c.not_before = NOW + 1;
                c
            },
        ] {
            assert_eq!(
                verify_certificate_binding(&cert, certificate_scope(JOURNAL_ROOT_ID)),
                Err(IdentityError::TrustInvalid),
                "certificate {:?} must fail",
                cert.purpose
            );
        }
    }

    fn valid_revocation() -> RevocationDocument {
        RevocationDocument {
            format: "o3k-recovery-revocations-v1".to_string(),
            site_id: "site-1".to_string(),
            profile: "o3k-demo-v1".to_string(),
            sequence: 1,
            issued_at: NOW - 100,
            next_update: NOW + 100,
            revoked_serials: vec![],
            revoked_key_ids: vec![],
        }
    }

    #[test]
    fn revocation_accepts_fresh_monotonic_document() {
        let document = valid_revocation();
        assert_eq!(
            verify_revocation(&document, "site-1", "o3k-demo-v1", NOW, None),
            Ok(())
        );
        // Equal sequence with the identical digest is idempotent.
        let dg = digest(&document).expect("digest");
        assert_eq!(
            verify_revocation(&document, "site-1", "o3k-demo-v1", NOW, Some((1, &dg))),
            Ok(())
        );
    }

    #[test]
    fn revocation_rejects_scope_freshness_rollback_and_duplicates() {
        let base = valid_revocation;
        for document in [
            {
                let mut d = base();
                d.format = "o3k-recovery-revocations-v2".to_string();
                d
            },
            {
                let mut d = base();
                d.site_id = "site-2".to_string();
                d
            },
            {
                let mut d = base();
                d.profile = "o3k-small-edge-v1".to_string();
                d
            },
            {
                let mut d = base();
                d.next_update = d.issued_at;
                d
            },
            {
                let mut d = base();
                d.next_update = d.issued_at + 86401;
                d
            },
            {
                let mut d = base();
                d.issued_at = NOW + 10;
                d
            },
            {
                let mut d = base();
                d.next_update = NOW - 10;
                d
            },
            {
                let mut d = base();
                d.revoked_serials = vec!["s1".to_string(), "s1".to_string()];
                d
            },
            {
                let mut d = base();
                d.revoked_key_ids = vec!["k1".to_string(), "k1".to_string()];
                d
            },
        ] {
            assert_eq!(
                verify_revocation(&document, "site-1", "o3k-demo-v1", NOW, None),
                Err(IdentityError::TrustInvalid),
                "revocation {:?} must fail",
                document.sequence
            );
        }
        // Lower sequence than the installed high-water is rollback.
        let document = base();
        assert_eq!(
            verify_revocation(
                &document,
                "site-1",
                "o3k-demo-v1",
                NOW,
                Some((2, &hex64(50)))
            ),
            Err(IdentityError::TrustInvalid)
        );
        // Same sequence with a different digest is equivocation.
        assert_eq!(
            verify_revocation(
                &document,
                "site-1",
                "o3k-demo-v1",
                NOW,
                Some((1, &hex64(51)))
            ),
            Err(IdentityError::TrustInvalid)
        );
    }
}
