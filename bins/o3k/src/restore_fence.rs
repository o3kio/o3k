//! Target-side verifier for independently attested PP.6 source-fence evidence.
//!
//! This module verifies signed recovery-host observations and short-lived
//! monitor challenges. It does not query a BMC, control its management ACL, or
//! prove firmware behavior; those remain independent deployment authorities.

use ed25519_dalek::{Signature, Verifier, VerifyingKey};
use ring::rand::{SecureRandom, SystemRandom};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use std::time::{Duration, Instant};
use uuid::Uuid;

pub const FENCE_EVIDENCE_FORMAT: &str = "o3k-pp6-fence-evidence-v1";
const HEARTBEAT_FORMAT: &str = "o3k-pp6-fence-heartbeat-v1";
const EVIDENCE_MAX_AGE_MS: u64 = 300_000;
const CHALLENGE_MAX_AGE: Duration = Duration::from_secs(2);

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct FenceIdentity {
    pub operation_id: Uuid,
    pub site_id: String,
    pub source_installation_id: String,
    pub source_serial: String,
    pub target_installation_id: String,
    pub bmc_certificate_sha256: String,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum SourcePowerState {
    Off,
    On,
    Unknown,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct FenceEvidence {
    pub format: String,
    pub identity: FenceIdentity,
    pub authorized_actor_id: String,
    pub evidence_key_id: String,
    pub observed_at_unix_ms: u64,
    pub power_state: SourcePowerState,
    pub nonce: String,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct SignedFenceEvidence {
    pub evidence: FenceEvidence,
    pub signature: String,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum FenceError {
    InvalidEvidence,
    EvidenceExpired,
    IdentityMismatch,
    NonceReplayed,
    SignatureInvalid,
    WrongKey,
    ChallengeBusy,
    ChallengeExpired,
    ChallengeReplayed,
    SequenceMismatch,
    JournalMismatch,
    SourceNotOff,
    ManagementAclNotHeld,
}

/// Production implementations must durably consume each nonce before
/// returning success and reject conflicting duplicate response/sequence
/// records. If a crash burns a nonce before the next signed phase is durable,
/// recovery must acquire fresh BMC evidence; it must not reuse that response.
pub trait FenceEvidenceReplayStore {
    fn consume_nonce(&mut self, nonce: &str) -> Result<(), FenceError>;
}

#[derive(Serialize)]
struct FenceEvidenceSigningBytes<'a> {
    format: &'a str,
    identity: &'a FenceIdentity,
    authorized_actor_id: &'a str,
    evidence_key_id: &'a str,
    observed_at_unix_ms: u64,
    power_state: SourcePowerState,
    nonce: &'a str,
}

pub fn canonical_evidence(evidence: &FenceEvidence) -> Result<Vec<u8>, FenceError> {
    validate_identity(&evidence.identity)?;
    if evidence.format != FENCE_EVIDENCE_FORMAT
        || !valid_id(&evidence.authorized_actor_id)
        || !valid_id(&evidence.evidence_key_id)
        || !valid_nonce(&evidence.nonce)
    {
        return Err(FenceError::InvalidEvidence);
    }
    let signing_bytes = FenceEvidenceSigningBytes {
        format: &evidence.format,
        identity: &evidence.identity,
        authorized_actor_id: &evidence.authorized_actor_id,
        evidence_key_id: &evidence.evidence_key_id,
        observed_at_unix_ms: evidence.observed_at_unix_ms,
        power_state: evidence.power_state,
        nonce: &evidence.nonce,
    };
    serde_jcs::to_vec(&signing_bytes).map_err(|_| FenceError::InvalidEvidence)
}

/// Verifies an offline-signed operator observation and asks the owning
/// durable journal to consume its nonce before returning success.
pub fn verify_fence_evidence(
    signed: &SignedFenceEvidence,
    expected_identity: &FenceIdentity,
    expected_key_id: &str,
    expected_authorized_actor_id: &str,
    verifying_key: &VerifyingKey,
    now_unix_ms: u64,
    replay_store: &mut impl FenceEvidenceReplayStore,
) -> Result<String, FenceError> {
    let evidence = &signed.evidence;
    if &evidence.identity != expected_identity {
        return Err(FenceError::IdentityMismatch);
    }
    if evidence.evidence_key_id != expected_key_id {
        return Err(FenceError::WrongKey);
    }
    if evidence.authorized_actor_id != expected_authorized_actor_id {
        return Err(FenceError::IdentityMismatch);
    }
    if evidence.power_state != SourcePowerState::Off {
        return Err(FenceError::SourceNotOff);
    }
    let age = now_unix_ms
        .checked_sub(evidence.observed_at_unix_ms)
        .ok_or(FenceError::EvidenceExpired)?;
    if age > EVIDENCE_MAX_AGE_MS {
        return Err(FenceError::EvidenceExpired);
    }
    let bytes = canonical_evidence(evidence)?;
    let signature_bytes =
        hex::decode(&signed.signature).map_err(|_| FenceError::SignatureInvalid)?;
    let signature =
        Signature::from_slice(&signature_bytes).map_err(|_| FenceError::SignatureInvalid)?;
    verifying_key
        .verify(&bytes, &signature)
        .map_err(|_| FenceError::SignatureInvalid)?;
    replay_store.consume_nonce(&evidence.nonce)?;
    Ok(hex::encode(Sha256::digest(bytes)))
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct FenceHeartbeat {
    pub format: String,
    pub identity: FenceIdentity,
    pub challenge: String,
    pub sequence: u64,
    pub journal_hash: String,
    pub power_state: SourcePowerState,
    pub recovery_acl_held: bool,
    pub monitor_key_id: String,
    pub signature: String,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct VerifiedFenceHeartbeat {
    pub identity: FenceIdentity,
    pub challenge: String,
    pub sequence: u64,
    pub journal_hash: String,
    pub response_sha256: String,
}

/// The production adapter must persist challenge consumption and sequence
/// under the signed restore journal (file fsync, rename, directory fsync),
/// reject conflicting duplicate response/sequence records, and only then
/// return `Ok(())`.
pub trait FenceHeartbeatJournal {
    fn persist_heartbeat_consumption(
        &mut self,
        heartbeat: &VerifiedFenceHeartbeat,
    ) -> Result<(), FenceError>;
}

#[derive(Serialize)]
struct HeartbeatSigningBytes<'a> {
    format: &'a str,
    identity: &'a FenceIdentity,
    challenge: &'a str,
    sequence: u64,
    journal_hash: &'a str,
    power_state: SourcePowerState,
    recovery_acl_held: bool,
    monitor_key_id: &'a str,
}

fn canonical_heartbeat(response: &FenceHeartbeat) -> Result<Vec<u8>, FenceError> {
    let signing_bytes = HeartbeatSigningBytes {
        format: &response.format,
        identity: &response.identity,
        challenge: &response.challenge,
        sequence: response.sequence,
        journal_hash: &response.journal_hash,
        power_state: response.power_state,
        recovery_acl_held: response.recovery_acl_held,
        monitor_key_id: &response.monitor_key_id,
    };
    serde_jcs::to_vec(&signing_bytes).map_err(|_| FenceError::InvalidEvidence)
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct MonitorChallenge {
    pub challenge: String,
    pub sequence: u64,
    pub journal_hash: String,
    issued_at: Instant,
}

/// Tracks one outstanding monitor challenge. The monitor signing key's
/// protocol is trusted to query the BMC after receiving each unpredictable
/// challenge; the target separately enforces a two-second monotonic deadline.
/// Durable sequence and challenge consumption still belong in the signed
/// restore journal before advancing.
pub struct FenceLeaseVerifier {
    identity: FenceIdentity,
    monitor_key_id: String,
    sequence: u64,
    outstanding: Option<MonitorChallenge>,
}

impl FenceLeaseVerifier {
    /// `last_accepted_sequence` must come from the authenticated durable restore
    /// journal; never recreate this verifier with a default sequence on resume.
    pub fn new(
        identity: FenceIdentity,
        monitor_key_id: String,
        last_accepted_sequence: u64,
    ) -> Result<Self, FenceError> {
        validate_identity(&identity)?;
        if !valid_id(&monitor_key_id) {
            return Err(FenceError::InvalidEvidence);
        }
        Ok(Self {
            identity,
            monitor_key_id,
            sequence: last_accepted_sequence,
            outstanding: None,
        })
    }

    pub fn issue_challenge(
        &mut self,
        journal_hash: String,
    ) -> Result<MonitorChallenge, FenceError> {
        self.issue_challenge_at(journal_hash, Instant::now())
    }

    fn issue_challenge_at(
        &mut self,
        journal_hash: String,
        issued_at: Instant,
    ) -> Result<MonitorChallenge, FenceError> {
        if self.outstanding.is_some() {
            return Err(FenceError::ChallengeBusy);
        }
        if !valid_hash(&journal_hash) {
            return Err(FenceError::JournalMismatch);
        }
        let mut nonce = [0_u8; 32];
        SystemRandom::new()
            .fill(&mut nonce)
            .map_err(|_| FenceError::InvalidEvidence)?;
        let challenge = MonitorChallenge {
            challenge: hex::encode(nonce),
            sequence: self
                .sequence
                .checked_add(1)
                .ok_or(FenceError::SequenceMismatch)?,
            journal_hash,
            issued_at,
        };
        self.outstanding = Some(challenge.clone());
        Ok(challenge)
    }

    pub fn accept_response(
        &mut self,
        challenge: &MonitorChallenge,
        response: &FenceHeartbeat,
        verifying_key: &VerifyingKey,
        journal: &mut impl FenceHeartbeatJournal,
    ) -> Result<(), FenceError> {
        self.accept_response_at(challenge, response, verifying_key, journal, Instant::now())
    }

    fn accept_response_at(
        &mut self,
        challenge: &MonitorChallenge,
        response: &FenceHeartbeat,
        verifying_key: &VerifyingKey,
        journal: &mut impl FenceHeartbeatJournal,
        received_at: Instant,
    ) -> Result<(), FenceError> {
        let Some(expected) = self.outstanding.as_ref() else {
            return Err(FenceError::ChallengeReplayed);
        };
        if expected != challenge
            || response.challenge != expected.challenge
            || response.sequence != expected.sequence
        {
            return Err(FenceError::ChallengeReplayed);
        }
        if received_at
            .checked_duration_since(expected.issued_at)
            .is_none_or(|age| age >= CHALLENGE_MAX_AGE)
        {
            self.outstanding = None;
            return Err(FenceError::ChallengeExpired);
        }
        if response.identity != self.identity || response.monitor_key_id != self.monitor_key_id {
            return Err(FenceError::IdentityMismatch);
        }
        if response.journal_hash != expected.journal_hash {
            return Err(FenceError::JournalMismatch);
        }
        if response.power_state != SourcePowerState::Off {
            return Err(FenceError::SourceNotOff);
        }
        if !response.recovery_acl_held {
            return Err(FenceError::ManagementAclNotHeld);
        }
        if response.format != HEARTBEAT_FORMAT || !valid_nonce(&response.challenge) {
            return Err(FenceError::InvalidEvidence);
        }
        let bytes = canonical_heartbeat(response)?;
        let signature_bytes =
            hex::decode(&response.signature).map_err(|_| FenceError::SignatureInvalid)?;
        let signature =
            Signature::from_slice(&signature_bytes).map_err(|_| FenceError::SignatureInvalid)?;
        verifying_key
            .verify(&bytes, &signature)
            .map_err(|_| FenceError::SignatureInvalid)?;
        let wire = serde_jcs::to_vec(response).map_err(|_| FenceError::InvalidEvidence)?;
        journal.persist_heartbeat_consumption(&VerifiedFenceHeartbeat {
            identity: self.identity.clone(),
            challenge: expected.challenge.clone(),
            sequence: expected.sequence,
            journal_hash: expected.journal_hash.clone(),
            response_sha256: hex::encode(Sha256::digest(wire)),
        })?;
        self.sequence = expected.sequence;
        self.outstanding = None;
        Ok(())
    }
}

fn validate_identity(identity: &FenceIdentity) -> Result<(), FenceError> {
    if identity.operation_id.is_nil()
        || !valid_id(&identity.site_id)
        || !valid_id(&identity.source_installation_id)
        || !valid_id(&identity.source_serial)
        || !valid_id(&identity.target_installation_id)
        || !valid_hash(&identity.bmc_certificate_sha256)
    {
        return Err(FenceError::InvalidEvidence);
    }
    Ok(())
}

fn valid_id(value: &str) -> bool {
    !value.is_empty()
        && value.len() <= 128
        && value
            .bytes()
            .all(|byte| byte.is_ascii_alphanumeric() || b"-_.:".contains(&byte))
}

fn valid_hash(value: &str) -> bool {
    value.len() == 64
        && value
            .bytes()
            .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte))
}

fn valid_nonce(value: &str) -> bool {
    value.len() == 64
        && value.bytes().all(|byte| byte.is_ascii_hexdigit())
        && value.bytes().all(|byte| !byte.is_ascii_uppercase())
}

#[cfg(test)]
#[allow(clippy::unwrap_used)]
fn signed_heartbeat(
    identity: &FenceIdentity,
    challenge: &MonitorChallenge,
    key: &ed25519_dalek::SigningKey,
    key_id: &str,
    recovery_acl_held: bool,
    power_off: bool,
) -> FenceHeartbeat {
    use ed25519_dalek::Signer;
    let mut response = FenceHeartbeat {
        format: HEARTBEAT_FORMAT.to_owned(),
        identity: identity.clone(),
        challenge: challenge.challenge.clone(),
        sequence: challenge.sequence,
        journal_hash: challenge.journal_hash.clone(),
        power_state: if power_off {
            SourcePowerState::Off
        } else {
            SourcePowerState::On
        },
        recovery_acl_held,
        monitor_key_id: key_id.to_owned(),
        signature: String::new(),
    };
    response.signature = hex::encode(
        key.sign(&canonical_heartbeat(&response).unwrap())
            .to_bytes(),
    );
    response
}

#[cfg(test)]
#[allow(clippy::unwrap_used)]
mod tests {
    use super::*;
    use ed25519_dalek::{Signer, SigningKey};
    use std::collections::HashSet;
    use std::time::{Duration, Instant};
    use uuid::Uuid;

    const TEST_KEY_ID: &str = "test-only-fence-key";

    #[derive(Default)]
    struct TestReplayStore(HashSet<String>);

    impl FenceEvidenceReplayStore for TestReplayStore {
        fn consume_nonce(&mut self, nonce: &str) -> Result<(), FenceError> {
            if self.0.insert(nonce.to_owned()) {
                Ok(())
            } else {
                Err(FenceError::NonceReplayed)
            }
        }
    }

    #[derive(Default)]
    struct TestHeartbeatJournal(Vec<VerifiedFenceHeartbeat>);

    impl FenceHeartbeatJournal for TestHeartbeatJournal {
        fn persist_heartbeat_consumption(
            &mut self,
            heartbeat: &VerifiedFenceHeartbeat,
        ) -> Result<(), FenceError> {
            self.0.push(heartbeat.clone());
            Ok(())
        }
    }

    fn identity() -> FenceIdentity {
        FenceIdentity {
            operation_id: Uuid::from_u128(1),
            site_id: "site-a".to_owned(),
            source_installation_id: "source-a".to_owned(),
            source_serial: "serial-1".to_owned(),
            target_installation_id: "target-a".to_owned(),
            bmc_certificate_sha256: "ab".repeat(32),
        }
    }

    fn evidence(identity: &FenceIdentity, key: &SigningKey) -> SignedFenceEvidence {
        let value = FenceEvidence {
            format: FENCE_EVIDENCE_FORMAT.to_owned(),
            identity: identity.clone(),
            authorized_actor_id: "operator-1".to_owned(),
            evidence_key_id: TEST_KEY_ID.to_owned(),
            observed_at_unix_ms: 1_000_000,
            power_state: SourcePowerState::Off,
            nonce: hex::encode([9; 32]),
        };
        SignedFenceEvidence {
            signature: hex::encode(key.sign(&canonical_evidence(&value).unwrap()).to_bytes()),
            evidence: value,
        }
    }

    #[test]
    fn signed_evidence_is_bound_to_site_source_target_actor_and_freshness() {
        let key = SigningKey::from_bytes(&[71; 32]);
        let identity = identity();
        let signed = evidence(&identity, &key);
        let mut replay_store = TestReplayStore::default();
        assert!(
            verify_fence_evidence(
                &signed,
                &identity,
                TEST_KEY_ID,
                "operator-1",
                &key.verifying_key(),
                1_299_999,
                &mut replay_store,
            )
            .is_ok()
        );
        assert_eq!(
            verify_fence_evidence(
                &signed,
                &identity,
                TEST_KEY_ID,
                "operator-1",
                &key.verifying_key(),
                1_000_001,
                &mut replay_store,
            ),
            Err(FenceError::NonceReplayed)
        );
        assert_eq!(
            verify_fence_evidence(
                &signed,
                &identity,
                TEST_KEY_ID,
                "operator-1",
                &key.verifying_key(),
                1_300_001,
                &mut replay_store,
            ),
            Err(FenceError::EvidenceExpired)
        );
        let mut wrong_identity = identity.clone();
        wrong_identity.source_serial = "other-serial".to_owned();
        assert_eq!(
            verify_fence_evidence(
                &signed,
                &wrong_identity,
                TEST_KEY_ID,
                "operator-1",
                &key.verifying_key(),
                1_000_001,
                &mut replay_store,
            ),
            Err(FenceError::IdentityMismatch)
        );
        assert_eq!(
            verify_fence_evidence(
                &signed,
                &identity,
                TEST_KEY_ID,
                "operator-other",
                &key.verifying_key(),
                1_000_001,
                &mut TestReplayStore::default(),
            ),
            Err(FenceError::IdentityMismatch)
        );
        let mut changed = signed.clone();
        changed.signature = hex::encode([0_u8; 64]);
        assert_eq!(
            verify_fence_evidence(
                &changed,
                &identity,
                TEST_KEY_ID,
                "operator-1",
                &key.verifying_key(),
                1_000_001,
                &mut replay_store,
            ),
            Err(FenceError::SignatureInvalid)
        );
    }

    #[test]
    fn lease_response_requires_fresh_challenge_exact_sequence_and_journal_hash() {
        let identity = identity();
        let key = SigningKey::from_bytes(&[72; 32]);
        let started = Instant::now();
        let mut lease =
            FenceLeaseVerifier::new(identity.clone(), TEST_KEY_ID.to_owned(), 0).unwrap();
        let challenge = lease.issue_challenge_at("cd".repeat(32), started).unwrap();
        let response = signed_heartbeat(&identity, &challenge, &key, TEST_KEY_ID, true, true);
        let mut journal = TestHeartbeatJournal::default();
        assert!(
            lease
                .accept_response_at(
                    &challenge,
                    &response,
                    &key.verifying_key(),
                    &mut journal,
                    started,
                )
                .is_ok()
        );
        assert_eq!(journal.0[0].sequence, 1);
        assert_eq!(
            lease.accept_response_at(
                &challenge,
                &response,
                &key.verifying_key(),
                &mut journal,
                started,
            ),
            Err(FenceError::ChallengeReplayed)
        );

        let next_started = started + Duration::from_secs(1);
        let next = lease
            .issue_challenge_at("ef".repeat(32), next_started)
            .unwrap();
        let next_response = signed_heartbeat(&identity, &next, &key, TEST_KEY_ID, true, true);
        assert_eq!(
            lease.accept_response_at(
                &next,
                &next_response,
                &key.verifying_key(),
                &mut journal,
                next_started + Duration::from_millis(2_001),
            ),
            Err(FenceError::ChallengeExpired)
        );
    }
}
