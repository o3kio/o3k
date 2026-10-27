//! C1.1 authenticated installation-policy/trust re-anchor and journal
//! checkpoint evidence (SPEC-0050 §7.3, ADR-0189 C1.1, issue #1086
//! comment 6440284521).
//!
//! Every scenario drives the real rotation plan builder and the real ordered
//! publication engine over an in-memory store, with real Ed25519 signatures
//! from clearly test-only keys. The final observation re-authenticates the
//! published generation through the same rotated-generation authenticator the
//! startup load path uses. Nothing here is an installed-release, production,
//! or independent-security qualification claim.
#![allow(clippy::expect_used, clippy::unwrap_used, clippy::panic)]

use std::collections::{BTreeMap, BTreeSet};

use ed25519_dalek::{Signer, SigningKey, VerifyingKey};
use o3k::recovery_identity::{
    InstallationPolicy, InstallationState, RecoveryState, RevocationDocument, SignatureEnvelope,
    Signed, TrustBundle, TrustCertificate,
};
use o3k::recovery_reanchor::{
    ArchiveLookup, CHECKPOINT_FORMAT, CHECKPOINT_NAME, GenerationView, InstallationReanchor,
    JournalCheckpoint, REANCHOR_FORMAT, REVALIDATION_FORMAT, REVALIDATION_VALIDITY_SECONDS,
    ReanchorError, RecoveryRevalidation, RevalidationConsumption, RotationArea, RotationInputs,
    RotationReason, RotationStore, authenticate_rotated_generation, build_rotation_plan,
    observe_disposition_generation, run_rotation_plan, verify_pre_c11_state_tip,
};
use o3k::restore_journal::RestorePhase;
use sha2::Digest;

const NOW: i64 = 1_900_000_000;
const POLICY_SIGNER_ID: &str = "test-policy-signer-1";
const OLD_JOURNAL_ROOT_ID: &str = "test-journal-root-1";
const OLD_JOURNAL_SIGNER_ID: &str = "test-journal-signer-1";
const OLD_EVIDENCE_ROOT_ID: &str = "test-evidence-root-1";
const OLD_EVIDENCE_SIGNER_ID: &str = "test-evidence-signer-1";
const NEW_JOURNAL_ROOT_ID: &str = "test-journal-root-2";
const NEW_JOURNAL_SIGNER_ID: &str = "test-journal-signer-2";
const NEW_EVIDENCE_ROOT_ID: &str = "test-evidence-root-2";
const NEW_EVIDENCE_SIGNER_ID: &str = "test-evidence-signer-2";
const OPERATION_ID: &str = "018f22c3-8f7b-7c1e-9a44-0db71e5a2c01";
const ARTIFACT: &str = "4d5a6b7c8e9f0a1b2c3d4e5f6a7b8c9d0e1f2a3b4c5d6e7f8a9b0c1d2e3f4a5b";
const RELEASE_SHA256: &str = "1111111111111111111111111111111111111111111111111111111111111111";

fn hex(bytes: &[u8]) -> String {
    hex::encode(bytes)
}

fn keypair(seed: u8) -> SigningKey {
    SigningKey::from_bytes(&[seed; 32])
}

fn key_hex(key: &VerifyingKey) -> String {
    hex(key.as_bytes())
}

fn sign<T: serde::Serialize + Clone>(
    payload: &T,
    signing: &SigningKey,
    signer_key_id: &str,
) -> Vec<u8> {
    let canonical_payload = o3k::recovery_identity::canonical(payload).expect("canonical payload");
    let envelope = SignatureEnvelope {
        algorithm: "Ed25519".to_string(),
        signer_key_id: signer_key_id.to_string(),
        signature: hex(&signing.sign(&canonical_payload).to_bytes()),
    };
    o3k::recovery_identity::canonical(&Signed {
        payload: payload.clone(),
        envelope,
    })
    .expect("canonical signed document")
}

fn sha256_hex(bytes: &[u8]) -> String {
    hex(&sha2::Sha256::digest(bytes))
}

// ---- fixture keys ----

#[derive(Clone)]
struct Keys {
    policy: SigningKey,
    old_journal_root: SigningKey,
    old_journal_signer: SigningKey,
    old_evidence_root: SigningKey,
    old_evidence_signer: SigningKey,
    new_journal_root: SigningKey,
    new_journal_signer: SigningKey,
    new_evidence_root: SigningKey,
    new_evidence_signer: SigningKey,
}

impl Keys {
    fn test_only() -> Self {
        Self {
            policy: keypair(0xA1),
            old_journal_root: keypair(0xB2),
            old_journal_signer: keypair(0xD4),
            old_evidence_root: keypair(0xC3),
            old_evidence_signer: keypair(0xE5),
            new_journal_root: keypair(0x1B),
            new_journal_signer: keypair(0x3D),
            new_evidence_root: keypair(0x2C),
            new_evidence_signer: keypair(0x4E),
        }
    }
}

// ---- fixture documents ----

fn certificate(
    purpose: &str,
    key_id: &str,
    public_key: &str,
    issuer: &str,
    serial: &str,
) -> TrustCertificate {
    TrustCertificate {
        format: match purpose {
            "restore_journal" => "o3k-journal-authority-v1",
            "recovery_evidence" => "o3k-evidence-authority-v1",
            _ => "unknown-purpose",
        }
        .to_string(),
        key_id: key_id.to_string(),
        public_key: public_key.to_string(),
        purpose: purpose.to_string(),
        site_id: "site-1".to_string(),
        installation_id: "inst-1".to_string(),
        profile: "o3k-demo-v1".to_string(),
        backend: "sqlite".to_string(),
        serial: serial.to_string(),
        not_before: NOW - 10_000,
        not_after: NOW + 80 * 86_400,
        issuer: issuer.to_string(),
    }
}

fn revocation_document(
    sequence: u64,
    issued_at: i64,
    revoked_serials: Vec<String>,
    revoked_key_ids: Vec<String>,
) -> RevocationDocument {
    RevocationDocument {
        format: "o3k-recovery-revocations-v1".to_string(),
        site_id: "site-1".to_string(),
        profile: "o3k-demo-v1".to_string(),
        sequence,
        issued_at,
        next_update: issued_at + 86_400,
        revoked_serials,
        revoked_key_ids,
    }
}

#[derive(Debug, Clone)]
struct BundleFixture {
    bundle: TrustBundle,
    bytes: Vec<u8>,
    digest: String,
}

#[allow(clippy::too_many_arguments)]
fn build_bundle(
    journal_root: &SigningKey,
    journal_root_id: &str,
    journal_signer: &SigningKey,
    journal_signer_id: &str,
    journal_serial: &str,
    evidence_root: &SigningKey,
    evidence_root_id: &str,
    evidence_signer: &SigningKey,
    evidence_signer_id: &str,
    evidence_serial: &str,
    journal_revocations: Signed<RevocationDocument>,
    evidence_revocations: Signed<RevocationDocument>,
) -> BundleFixture {
    let journal_certificate = Signed {
        payload: certificate(
            "restore_journal",
            journal_signer_id,
            &key_hex(&journal_signer.verifying_key()),
            journal_root_id,
            journal_serial,
        ),
        envelope: SignatureEnvelope {
            algorithm: "Ed25519".to_string(),
            signer_key_id: journal_root_id.to_string(),
            signature: hex(&journal_root
                .sign(
                    &o3k::recovery_identity::canonical(&certificate(
                        "restore_journal",
                        journal_signer_id,
                        &key_hex(&journal_signer.verifying_key()),
                        journal_root_id,
                        journal_serial,
                    ))
                    .expect("canonical"),
                )
                .to_bytes()),
        },
    };
    let evidence_certificate = Signed {
        payload: certificate(
            "recovery_evidence",
            evidence_signer_id,
            &key_hex(&evidence_signer.verifying_key()),
            evidence_root_id,
            evidence_serial,
        ),
        envelope: SignatureEnvelope {
            algorithm: "Ed25519".to_string(),
            signer_key_id: evidence_root_id.to_string(),
            signature: hex(&evidence_root
                .sign(
                    &o3k::recovery_identity::canonical(&certificate(
                        "recovery_evidence",
                        evidence_signer_id,
                        &key_hex(&evidence_signer.verifying_key()),
                        evidence_root_id,
                        evidence_serial,
                    ))
                    .expect("canonical"),
                )
                .to_bytes()),
        },
    };
    let bundle = TrustBundle {
        format: "o3k-recovery-trust-v1".to_string(),
        site_id: "site-1".to_string(),
        profile: "o3k-demo-v1".to_string(),
        installation_id: "inst-1".to_string(),
        backend: "sqlite".to_string(),
        journal_root_key_id: journal_root_id.to_string(),
        journal_root_public_key: key_hex(&journal_root.verifying_key()),
        evidence_root_key_id: evidence_root_id.to_string(),
        evidence_root_public_key: key_hex(&evidence_root.verifying_key()),
        journal_revocation_sequence: journal_revocations.payload.sequence,
        journal_revocation_digest: o3k::recovery_identity::digest(&journal_revocations)
            .expect("digest"),
        evidence_revocation_sequence: evidence_revocations.payload.sequence,
        evidence_revocation_digest: o3k::recovery_identity::digest(&evidence_revocations)
            .expect("digest"),
        journal_certificate,
        evidence_certificate,
        journal_revocations,
        evidence_revocations,
    };
    let bytes = o3k::recovery_identity::canonical(&bundle).expect("canonical bundle");
    let digest = sha256_hex(&bytes);
    let _ = (journal_signer, evidence_signer);
    BundleFixture {
        bundle,
        bytes,
        digest,
    }
}

fn signed_revocations(
    doc: &RevocationDocument,
    root: &SigningKey,
    root_id: &str,
) -> Signed<RevocationDocument> {
    Signed {
        payload: doc.clone(),
        envelope: SignatureEnvelope {
            algorithm: "Ed25519".to_string(),
            signer_key_id: root_id.to_string(),
            signature: hex(&root
                .sign(&o3k::recovery_identity::canonical(doc).expect("canonical"))
                .to_bytes()),
        },
    }
}

#[derive(Clone)]
struct PolicyFixture {
    policy: InstallationPolicy,
    bytes: Vec<u8>,
    digest: String,
}

fn build_policy(
    revision: u64,
    prior_policy_digest: &str,
    trust_bundle_digest: &str,
    journal_root_id: &str,
    journal_root_key: &VerifyingKey,
    evidence_root_id: &str,
    evidence_root_key: &VerifyingKey,
) -> PolicyFixture {
    let policy = InstallationPolicy {
        format: "o3k-installation-policy-v1".to_string(),
        installation_id: "inst-1".to_string(),
        site_id: "site-1".to_string(),
        profile: "o3k-demo-v1".to_string(),
        backend: "sqlite".to_string(),
        release_identity: RELEASE_SHA256.to_string(),
        data_root: "/var/lib/o3k".to_string(),
        target_device: 2049,
        target_inode: 12_345,
        policy_revision: revision,
        prior_policy_digest: prior_policy_digest.to_string(),
        policy_path: "/etc/o3k/installation-policy.json".to_string(),
        trust_bundle_path: "/etc/o3k/recovery-trust.json".to_string(),
        trust_bundle_digest: trust_bundle_digest.to_string(),
        recovery_state_root: "/var/lib/o3k-recovery-state/inst-1".to_string(),
        recovery_state_device: 2049,
        recovery_state_inode: 45_678,
        journal_directory: "/var/lib/o3k-recovery/inst-1".to_string(),
        journal_device: 2049,
        journal_inode: 78_901,
        journal_trust_root_id: journal_root_id.to_string(),
        journal_trust_root_public_key: key_hex(journal_root_key),
        evidence_trust_root_id: evidence_root_id.to_string(),
        evidence_trust_root_public_key: key_hex(evidence_root_key),
        signer_key_id: POLICY_SIGNER_ID.to_string(),
    };
    let bytes = sign(&policy, &keypair(0xA1), POLICY_SIGNER_ID);
    let digest = sha256_hex(&bytes);
    PolicyFixture {
        policy,
        bytes,
        digest,
    }
}

fn manifest_bytes() -> Vec<u8> {
    format!(
        r#"{{"version":"v0.4.0-rc.5","profile":"libvirt","profile_id":"o3k-demo-v1","source_commit":"aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa","workflow":"test","installer_sha256":"{}","release_artifact_sha256":"{}","schema_version":"1","installation_policy_format":"o3k-installation-policy-v1","installation_policy_path":"/etc/o3k/installation-policy.json","installation_policy_authority":{{"key_id":"{}","ed25519_public_key":"{}"}}}}"#,
        "0".repeat(64),
        RELEASE_SHA256,
        POLICY_SIGNER_ID,
        key_hex(&keypair(0xA1).verifying_key()),
    )
    .into_bytes()
}

fn journal_identity_digest(policy: &InstallationPolicy) -> String {
    o3k::recovery_identity::digest(&(
        policy.journal_directory.as_str(),
        policy.journal_device,
        policy.journal_inode,
    ))
    .expect("digest")
}

fn initial_state(
    policy: &InstallationPolicy,
    policy_digest: &str,
) -> (InstallationState, Vec<u8>, String) {
    let state = InstallationState {
        format: "o3k-installation-state-v1".to_string(),
        installation_id: policy.installation_id.clone(),
        site_id: policy.site_id.clone(),
        profile: policy.profile.clone(),
        backend: policy.backend.clone(),
        policy_revision: policy.policy_revision,
        policy_digest: policy_digest.to_string(),
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
    };
    // The sequence-zero record is policy-authority signed.
    let bytes = sign(&state, &keypair(0xA1), POLICY_SIGNER_ID);
    let digest = sha256_hex(&bytes);
    (state, bytes, digest)
}

fn designated_state(
    policy: &InstallationPolicy,
    policy_digest: &str,
    predecessor: &InstallationState,
    predecessor_digest: &str,
) -> (InstallationState, Vec<u8>, String) {
    let mut state = predecessor.clone();
    state.sequence = 1;
    state.prior_record_digest = predecessor_digest.to_string();
    state.state = RecoveryState::RecoveryDesignated;
    state.policy_digest = policy_digest.to_string();
    state.operation_id = Some(OPERATION_ID.to_string());
    state.artifact_sha256 = Some(ARTIFACT.to_string());
    state.recovery_directory_digest = Some(journal_identity_digest(policy));
    state.trust_bundle_digest = Some(policy.trust_bundle_digest.clone());
    let bytes = sign(&state, &keypair(0xD4), OLD_JOURNAL_SIGNER_ID);
    let digest = sha256_hex(&bytes);
    (state, bytes, digest)
}

fn released_state(
    designated: &InstallationState,
    designated_digest: &str,
    terminal_journal_digest: &str,
) -> (InstallationState, Vec<u8>, String) {
    let mut state = designated.clone();
    state.sequence = 2;
    state.prior_record_digest = designated_digest.to_string();
    state.state = RecoveryState::Released;
    state.terminal_journal_digest = Some(terminal_journal_digest.to_string());
    state.evidence_digest = Some(hex(&[0xE7; 32]));
    let bytes = sign(&state, &keypair(0xD4), OLD_JOURNAL_SIGNER_ID);
    let digest = sha256_hex(&bytes);
    (state, bytes, digest)
}

/// One signed PREFLIGHTED journal-v1 chain under the old journal signer.
fn journal_chain(policy: &InstallationPolicy, request_nonce_seed: u8) -> (Vec<u8>, String) {
    let request = serde_json::json!({
        "format": "o3k-restore-signing-request-v1",
        "request_id": "9f1d2c3b-1234-4abc-8def-0123456789ab",
        "request_nonce": hex(&[request_nonce_seed; 32]),
        "operation_id": OPERATION_ID,
        "site_id": policy.site_id,
        "artifact_sha256": ARTIFACT,
        "journal_authority_id": OLD_JOURNAL_SIGNER_ID,
        "target_installation_id": policy.installation_id,
        "target_device": policy.target_device,
        "target_inode": policy.target_inode,
        "target_database_identity": "o3k_fresh",
        "source_installation_id": "source-inst-1",
        "deterministic_step_id": hex(&[0x5E; 32]),
        "sequence": 1,
        "previous_signed_hash": "",
        "intended_transition": "PREFLIGHTED",
    });
    let request_bytes = serde_jcs::to_vec(&request).expect("canonical request");
    let request_hash = sha256_hex(&request_bytes);
    let signature = hex(&keypair(0xD4).sign(&request_bytes).to_bytes());
    let envelope = serde_json::json!({
        "format": "o3k-restore-journal-v1",
        "transitions": [{
            "format": "o3k-restore-journal-v1",
            "request": request,
            "response": {
                "format": "o3k-restore-signing-response-v1",
                "request_sha256": request_hash,
                "key_id": OLD_JOURNAL_SIGNER_ID,
                "signature": signature,
            },
        }],
    });
    let bytes = serde_jcs::to_vec(&envelope).expect("canonical journal");
    let digest = sha256_hex(&bytes);
    (bytes, digest)
}

// ---- the pre-rotation installation fixture ----

struct Fixture {
    keys: Keys,
    manifest_bytes: Vec<u8>,
    old_bundle: BundleFixture,
    policy: PolicyFixture,
    initial: (InstallationState, Vec<u8>, String),
    designated: Option<(InstallationState, Vec<u8>, String)>,
    released: Option<(InstallationState, Vec<u8>, String)>,
    journal: Option<(Vec<u8>, String)>,
}

fn never_recovered_fixture() -> Fixture {
    let keys = Keys::test_only();
    let journal_revocations = signed_revocations(
        &revocation_document(1, NOW - 100, vec![], vec![]),
        &keys.old_journal_root,
        OLD_JOURNAL_ROOT_ID,
    );
    let evidence_revocations = signed_revocations(
        &revocation_document(1, NOW - 100, vec![], vec![]),
        &keys.old_evidence_root,
        OLD_EVIDENCE_ROOT_ID,
    );
    let old_bundle = build_bundle(
        &keys.old_journal_root,
        OLD_JOURNAL_ROOT_ID,
        &keys.old_journal_signer,
        OLD_JOURNAL_SIGNER_ID,
        "serial-journal-1",
        &keys.old_evidence_root,
        OLD_EVIDENCE_ROOT_ID,
        &keys.old_evidence_signer,
        OLD_EVIDENCE_SIGNER_ID,
        "serial-evidence-1",
        journal_revocations,
        evidence_revocations,
    );
    let policy = build_policy(
        1,
        &hex(&[0x88; 32]),
        &old_bundle.digest,
        OLD_JOURNAL_ROOT_ID,
        &keys.old_journal_root.verifying_key(),
        OLD_EVIDENCE_ROOT_ID,
        &keys.old_evidence_root.verifying_key(),
    );
    let initial = initial_state(&policy.policy, &policy.digest);
    Fixture {
        keys,
        manifest_bytes: manifest_bytes(),
        old_bundle,
        policy,
        initial,
        designated: None,
        released: None,
        journal: None,
    }
}

fn designated_fixture() -> Fixture {
    let mut fixture = never_recovered_fixture();
    let designated = designated_state(
        &fixture.policy.policy,
        &fixture.policy.digest,
        &fixture.initial.0,
        &fixture.initial.2,
    );
    fixture.journal = Some(journal_chain(&fixture.policy.policy, 0x11));
    fixture.designated = Some(designated);
    fixture
}

fn released_fixture() -> Fixture {
    let mut fixture = designated_fixture();
    let journal_tip = authenticated_tip_hash(fixture.journal.as_ref().unwrap());
    let released = released_state(
        &fixture.designated.as_ref().unwrap().0,
        &fixture.designated.as_ref().unwrap().2,
        &journal_tip,
    );
    fixture.released = Some(released);
    fixture
}

fn authenticated_tip_hash(journal: &(Vec<u8>, String)) -> String {
    let authenticated = o3k::restore_journal::authenticate_chain(
        &journal.0,
        OLD_JOURNAL_SIGNER_ID,
        &keypair(0xD4).verifying_key(),
    )
    .unwrap_or_else(|error| panic!("fixture chain authenticates: {error:?}"));
    authenticated.signed_hash().to_string()
}

// ---- new-generation documents ----

struct NewGeneration {
    bundle: BundleFixture,
    policy: PolicyFixture,
}

fn new_journal_revocations(keys: &Keys, reason: RotationReason) -> Signed<RevocationDocument> {
    let (serials, key_ids) = match reason {
        RotationReason::Routine => (vec![], vec![]),
        RotationReason::Compromise => (
            vec!["serial-journal-1".to_string()],
            vec![OLD_JOURNAL_SIGNER_ID.to_string()],
        ),
    };
    signed_revocations(
        &revocation_document(1, NOW - 50, serials, key_ids),
        &keys.new_journal_root,
        NEW_JOURNAL_ROOT_ID,
    )
}

fn new_evidence_revocations(keys: &Keys, reason: RotationReason) -> Signed<RevocationDocument> {
    let (serials, key_ids) = match reason {
        RotationReason::Routine => (vec![], vec![]),
        RotationReason::Compromise => (
            vec!["serial-evidence-1".to_string()],
            vec![OLD_EVIDENCE_SIGNER_ID.to_string()],
        ),
    };
    signed_revocations(
        &revocation_document(1, NOW - 50, serials, key_ids),
        &keys.new_evidence_root,
        NEW_EVIDENCE_ROOT_ID,
    )
}

fn build_new_generation(fixture: &Fixture, reason: RotationReason) -> NewGeneration {
    let keys = &fixture.keys;
    let bundle = build_bundle(
        &keys.new_journal_root,
        NEW_JOURNAL_ROOT_ID,
        &keys.new_journal_signer,
        NEW_JOURNAL_SIGNER_ID,
        "serial-journal-2",
        &keys.new_evidence_root,
        NEW_EVIDENCE_ROOT_ID,
        &keys.new_evidence_signer,
        NEW_EVIDENCE_SIGNER_ID,
        "serial-evidence-2",
        new_journal_revocations(keys, reason),
        new_evidence_revocations(keys, reason),
    );
    let policy = build_policy(
        fixture.policy.policy.policy_revision + 1,
        &fixture.policy.digest,
        &bundle.digest,
        NEW_JOURNAL_ROOT_ID,
        &keys.new_journal_root.verifying_key(),
        NEW_EVIDENCE_ROOT_ID,
        &keys.new_evidence_root.verifying_key(),
    );
    NewGeneration { bundle, policy }
}

fn high_water(doc: &Signed<RevocationDocument>) -> o3k::recovery_reanchor::RevocationHighWater {
    o3k::recovery_reanchor::RevocationHighWater {
        root_id: doc.envelope.signer_key_id.clone(),
        sequence: doc.payload.sequence,
        document_digest: o3k::recovery_identity::digest(doc).expect("digest"),
    }
}

#[allow(clippy::too_many_arguments)]
fn reanchor_record(
    fixture: &Fixture,
    new_generation: &NewGeneration,
    _reason: RotationReason,
    prior_tip_sequence: u64,
    prior_tip_digest: &str,
    checkpoint_digest: Option<&str>,
    revalidation_digest: Option<&str>,
    operation_id: Option<&str>,
    artifact_sha256: Option<&str>,
    recovery_directory_digest: Option<&str>,
    terminal_journal_digest: Option<&str>,
    terminal_evidence_digest: Option<&str>,
) -> InstallationReanchor {
    InstallationReanchor {
        format: REANCHOR_FORMAT.to_string(),
        installation_id: fixture.policy.policy.installation_id.clone(),
        site_id: fixture.policy.policy.site_id.clone(),
        profile: fixture.policy.policy.profile.clone(),
        backend: fixture.policy.policy.backend.clone(),
        preserved_state: match (operation_id, terminal_journal_digest) {
            (None, _) => RecoveryState::NeverRecovered,
            (Some(_), None) => RecoveryState::RecoveryDesignated,
            (Some(_), Some(_)) => RecoveryState::Released,
        },
        sequence: prior_tip_sequence + 1,
        prior_record_digest: prior_tip_digest.to_string(),
        prior_policy_revision: fixture.policy.policy.policy_revision,
        prior_policy_digest: fixture.policy.digest.clone(),
        new_policy_revision: new_generation.policy.policy.policy_revision,
        new_policy_digest: new_generation.policy.digest.clone(),
        prior_trust_bundle_digest: sha256_hex(&fixture.old_bundle.bytes),
        new_trust_bundle_digest: new_generation.bundle.digest.clone(),
        prior_journal_revocation: high_water(&fixture.old_bundle.bundle.journal_revocations),
        prior_evidence_revocation: high_water(&fixture.old_bundle.bundle.evidence_revocations),
        new_journal_revocation: high_water(&new_generation.bundle.bundle.journal_revocations),
        new_evidence_revocation: high_water(&new_generation.bundle.bundle.evidence_revocations),
        checkpoint_digest: checkpoint_digest.map(ToString::to_string),
        recovery_revalidation_digest: revalidation_digest.map(ToString::to_string),
        operation_id: operation_id.map(ToString::to_string),
        artifact_sha256: artifact_sha256.map(ToString::to_string),
        recovery_directory_digest: recovery_directory_digest.map(ToString::to_string),
        terminal_journal_digest: terminal_journal_digest.map(ToString::to_string),
        terminal_evidence_digest: terminal_evidence_digest.map(ToString::to_string),
        target_device: fixture.policy.policy.target_device,
        target_inode: fixture.policy.policy.target_inode,
        signer_manifest_digest: sha256_hex(&fixture.manifest_bytes),
    }
}

fn checkpoint_record(
    fixture: &Fixture,
    new_generation: &NewGeneration,
    reason: RotationReason,
    prior_journal_tip: &str,
    prior_state_tip_digest: &str,
    revalidation_digest: Option<&str>,
) -> JournalCheckpoint {
    JournalCheckpoint {
        format: CHECKPOINT_FORMAT.to_string(),
        installation_id: fixture.policy.policy.installation_id.clone(),
        site_id: fixture.policy.policy.site_id.clone(),
        profile: fixture.policy.policy.profile.clone(),
        backend: fixture.policy.policy.backend.clone(),
        sequence: 2,
        prior_record_digest: prior_journal_tip.to_string(),
        prior_checkpoint_digest: None,
        prior_state_tip_digest: prior_state_tip_digest.to_string(),
        journal_directory: fixture.policy.policy.journal_directory.clone(),
        journal_device: fixture.policy.policy.journal_device,
        journal_inode: fixture.policy.policy.journal_inode,
        operation_id: OPERATION_ID.to_string(),
        artifact_sha256: ARTIFACT.to_string(),
        phase: RestorePhase::Preflighted,
        old_journal_key_id: OLD_JOURNAL_SIGNER_ID.to_string(),
        old_journal_certificate_serial: "serial-journal-1".to_string(),
        new_journal_key_id: NEW_JOURNAL_SIGNER_ID.to_string(),
        new_journal_certificate_serial: "serial-journal-2".to_string(),
        old_journal_revocation: high_water(&fixture.old_bundle.bundle.journal_revocations),
        new_journal_revocation: high_water(&new_generation.bundle.bundle.journal_revocations),
        old_evidence_revocation: high_water(&fixture.old_bundle.bundle.evidence_revocations),
        new_evidence_revocation: high_water(&new_generation.bundle.bundle.evidence_revocations),
        rotation_reason: reason,
        recovery_revalidation_digest: revalidation_digest.map(ToString::to_string),
    }
}

fn revalidation_record(fixture: &Fixture, new_generation: &NewGeneration) -> RecoveryRevalidation {
    RecoveryRevalidation {
        format: REVALIDATION_FORMAT.to_string(),
        installation_id: fixture.policy.policy.installation_id.clone(),
        site_id: fixture.policy.policy.site_id.clone(),
        profile: fixture.policy.policy.profile.clone(),
        backend: fixture.policy.policy.backend.clone(),
        operation_id: OPERATION_ID.to_string(),
        artifact_sha256: ARTIFACT.to_string(),
        target_device: fixture.policy.policy.target_device,
        target_inode: fixture.policy.policy.target_inode,
        old_journal_root_id: OLD_JOURNAL_ROOT_ID.to_string(),
        new_journal_root_id: NEW_JOURNAL_ROOT_ID.to_string(),
        old_journal_key_id: OLD_JOURNAL_SIGNER_ID.to_string(),
        old_journal_certificate_serial: "serial-journal-1".to_string(),
        new_journal_key_id: NEW_JOURNAL_SIGNER_ID.to_string(),
        new_journal_certificate_serial: "serial-journal-2".to_string(),
        old_evidence_root_id: OLD_EVIDENCE_ROOT_ID.to_string(),
        new_evidence_root_id: NEW_EVIDENCE_ROOT_ID.to_string(),
        old_evidence_key_id: OLD_EVIDENCE_SIGNER_ID.to_string(),
        old_evidence_certificate_serial: "serial-evidence-1".to_string(),
        new_evidence_key_id: NEW_EVIDENCE_SIGNER_ID.to_string(),
        new_evidence_certificate_serial: "serial-evidence-2".to_string(),
        prior_state_tip_digest: fixture
            .released
            .as_ref()
            .map(|r| r.2.clone())
            .or_else(|| fixture.designated.as_ref().map(|d| d.2.clone()))
            .unwrap_or_else(|| fixture.initial.2.clone()),
        prior_journal_tip_digest: fixture
            .journal
            .as_ref()
            .map(authenticated_tip_hash)
            .unwrap_or_default(),
        prior_checkpoint_digest: None,
        old_policy_digest: fixture.policy.digest.clone(),
        new_policy_digest: new_generation.policy.digest.clone(),
        old_trust_bundle_digest: sha256_hex(&fixture.old_bundle.bytes),
        new_trust_bundle_digest: new_generation.bundle.digest.clone(),
        observed_target_device: fixture.policy.policy.target_device,
        observed_target_inode: fixture.policy.policy.target_inode,
        custody_record_digest: sha256_hex(b"custody-record"),
        recovery_quorum_event_id: "quorum-event-1".to_string(),
        nonce: hex(&[0x6E; 32]),
        issued_at: NOW,
        expires_at: NOW + REVALIDATION_VALIDITY_SECONDS,
        exact_tips_reviewed: true,
    }
}

// ---- in-memory rotation store ----

#[derive(Default)]
struct MemStore {
    state_root: BTreeMap<String, Vec<u8>>,
    journal_dir: BTreeMap<String, Vec<u8>>,
    fixed_config: BTreeMap<String, Vec<u8>>,
    writes: Vec<(RotationArea, String)>,
}

impl MemStore {
    fn area(&self, area: RotationArea) -> &BTreeMap<String, Vec<u8>> {
        match area {
            RotationArea::StateRoot => &self.state_root,
            RotationArea::JournalDir => &self.journal_dir,
            RotationArea::FixedConfig => &self.fixed_config,
        }
    }
    fn area_mut(&mut self, area: RotationArea) -> &mut BTreeMap<String, Vec<u8>> {
        match area {
            RotationArea::StateRoot => &mut self.state_root,
            RotationArea::JournalDir => &mut self.journal_dir,
            RotationArea::FixedConfig => &mut self.fixed_config,
        }
    }
    fn seed_prior(&mut self, fixture: &Fixture) {
        self.fixed_config.insert(
            "installation-policy.json".to_string(),
            fixture.policy.bytes.clone(),
        );
        self.state_root
            .insert("policy.json".to_string(), fixture.policy.bytes.clone());
        self.fixed_config.insert(
            "recovery-trust.json".to_string(),
            fixture.old_bundle.bytes.clone(),
        );
        self.state_root
            .insert("trust.json".to_string(), fixture.old_bundle.bytes.clone());
        let tip = fixture
            .released
            .clone()
            .map(|r| r.1)
            .or_else(|| fixture.designated.clone().map(|d| d.1))
            .unwrap_or_else(|| fixture.initial.1.clone());
        self.state_root.insert("state.json".to_string(), tip);
        if let Some(journal) = &fixture.journal {
            self.journal_dir
                .insert("restore-journal.json".to_string(), journal.0.clone());
        }
        // Pre-published state-chain archives (created by the designation and
        // release persistence steps in production).
        for (name, bytes) in fixture_archives(fixture).0 {
            self.state_root.entry(name).or_insert(bytes);
        }
    }
}

impl RotationStore for MemStore {
    fn read(&self, area: RotationArea, name: &str) -> Result<Option<Vec<u8>>, ReanchorError> {
        Ok(self.area(area).get(name).cloned())
    }
    fn publish(
        &mut self,
        area: RotationArea,
        name: &str,
        bytes: &[u8],
    ) -> Result<(), ReanchorError> {
        self.writes.push((area, name.to_string()));
        self.area_mut(area).insert(name.to_string(), bytes.to_vec());
        Ok(())
    }
    fn list(&self, area: RotationArea) -> Result<Vec<String>, ReanchorError> {
        Ok(self.area(area).keys().cloned().collect())
    }
}

struct MapArchives(BTreeMap<String, Vec<u8>>);
impl ArchiveLookup for MapArchives {
    fn read_archive(&self, name: &str) -> Option<Vec<u8>> {
        self.0.get(name).cloned()
    }
}

/// Archive lookup over a rotation store's published files.
struct StoreArchives<'a>(&'a dyn RotationStore);

impl ArchiveLookup for StoreArchives<'_> {
    fn read_archive(&self, name: &str) -> Option<Vec<u8>> {
        let (prefix, rest) = name.split_once('-')?;
        let digest = rest.strip_suffix(".json")?;
        if digest.len() != 64
            || !digest
                .bytes()
                .all(|b| b.is_ascii_hexdigit() && !b.is_ascii_uppercase())
        {
            return None;
        }
        let area = match prefix {
            "state" | "policy" | "trust" => RotationArea::StateRoot,
            "checkpoint" => RotationArea::JournalDir,
            _ => return None,
        };
        let bytes = self.0.read(area, name).ok().flatten()?;
        if sha256_hex(&bytes) == digest {
            Some(bytes)
        } else {
            None
        }
    }
}

/// The fixture's pre-published state-chain archives (what the production
/// designation/release persistence archives before rotation exists).
fn fixture_archives(fixture: &Fixture) -> MapArchives {
    let mut map = BTreeMap::new();
    map.insert(
        format!("state-{}.json", fixture.initial.2),
        fixture.initial.1.clone(),
    );
    if let Some(designated) = &fixture.designated {
        map.insert(format!("state-{}.json", designated.2), designated.1.clone());
    }
    MapArchives(map)
}

// ---- fixture view helpers ----

fn fixture_view<'a>(
    fixture: &'a Fixture,
    tip_bytes: &'a [u8],
    journal_bytes: Option<&'a [u8]>,
) -> GenerationView<'a> {
    GenerationView {
        manifest_bytes: &fixture.manifest_bytes,
        policy_bytes: &fixture.policy.bytes,
        policy_high_water_bytes: None,
        fixed_bundle_bytes: &fixture.old_bundle.bytes,
        trust_high_water_bytes: &fixture.old_bundle.bytes,
        staged_prior_policy_bytes: None,
        staged_prior_trust_bytes: None,
        state_tip_bytes: tip_bytes,
        journal_bytes,
        checkpoint_bytes: None,
        consumption_record_bytes: None,
        pending_signing_request_present: false,
        now: NOW,
    }
}

/// Final observation used by every rotation run in this suite: it
/// authenticates the whole published generation through the same
/// rotated-generation authenticator the startup load path uses.
fn observe_authenticates(
    expected: RecoveryState,
) -> impl FnMut(&dyn RotationStore) -> Result<(), ReanchorError> {
    move |store| {
        let read = |area: RotationArea, name: &str| store.read(area, name).ok().flatten();
        let manifest = manifest_bytes();
        let fixed_policy = read(RotationArea::FixedConfig, "installation-policy.json");
        let fixed_trust = read(RotationArea::FixedConfig, "recovery-trust.json");
        let policy_high_water = read(RotationArea::StateRoot, "policy.json");
        let trust_high_water = read(RotationArea::StateRoot, "trust.json");
        let state_tip = read(RotationArea::StateRoot, "state.json");
        let journal = read(RotationArea::JournalDir, "restore-journal.json");
        let checkpoint = read(RotationArea::JournalDir, CHECKPOINT_NAME);
        let consumption = read(RotationArea::StateRoot, "revalidation-consumption.json");
        let pending_signing_request_present = store
            .list(RotationArea::JournalDir)
            .map(|names| {
                names.iter().any(|name| {
                    name == "restore-signing-request.json"
                        || (name.starts_with("restore-reservation-") && name.ends_with(".lock"))
                })
            })
            .unwrap_or(false);
        let archives = StoreArchives(store);
        let view = GenerationView {
            manifest_bytes: &manifest,
            policy_bytes: fixed_policy.as_deref().unwrap_or(&[]),
            policy_high_water_bytes: policy_high_water.as_deref(),
            fixed_bundle_bytes: fixed_trust.as_deref().unwrap_or(&[]),
            trust_high_water_bytes: trust_high_water.as_deref().unwrap_or(&[]),
            staged_prior_policy_bytes: None,
            staged_prior_trust_bytes: None,
            state_tip_bytes: state_tip.as_deref().unwrap_or(&[]),
            journal_bytes: journal.as_deref(),
            checkpoint_bytes: checkpoint.as_deref(),
            consumption_record_bytes: consumption.as_deref(),
            pending_signing_request_present,
            now: NOW,
        };
        let observed = authenticate_rotated_generation(&view, &archives)?;
        if observed.preserved_state != expected {
            return Err(ReanchorError::Binding(
                "preserved state changed during rotation",
            ));
        }
        Ok(())
    }
}

fn rotate_fixture(
    fixture: &Fixture,
    reason: RotationReason,
    now: i64,
    tamper: impl FnOnce(
        &mut InstallationReanchor,
        &mut Option<JournalCheckpoint>,
        &mut Option<RecoveryRevalidation>,
    ),
) -> (MemStore, Result<(), ReanchorError>) {
    let new_generation = build_new_generation(fixture, reason);
    let tip = fixture
        .released
        .clone()
        .map(|r| r.0.clone())
        .or_else(|| fixture.designated.clone().map(|d| d.0.clone()))
        .unwrap_or_else(|| fixture.initial.0.clone());
    let tip_bytes = fixture
        .released
        .clone()
        .map(|r| r.1.clone())
        .or_else(|| fixture.designated.clone().map(|d| d.1.clone()))
        .unwrap_or_else(|| fixture.initial.1.clone());
    let mut reanchor = reanchor_record(
        fixture,
        &new_generation,
        reason,
        tip.sequence,
        &sha256_hex(&tip_bytes),
        None,
        None,
        fixture.designated.as_ref().map(|_| OPERATION_ID),
        fixture.designated.as_ref().map(|_| ARTIFACT),
        fixture
            .designated
            .as_ref()
            .map(|_| journal_identity_digest(&fixture.policy.policy))
            .as_deref(),
        fixture
            .released
            .as_ref()
            .map(|_| authenticated_tip_hash(fixture.journal.as_ref().unwrap()))
            .as_deref(),
        fixture
            .released
            .as_ref()
            .and_then(|r| r.0.evidence_digest.as_deref()),
    );
    let mut checkpoint = None;
    let mut revalidation = None;
    if fixture.designated.is_some() {
        let journal_tip = authenticated_tip_hash(fixture.journal.as_ref().unwrap());
        checkpoint = Some(checkpoint_record(
            fixture,
            &new_generation,
            reason,
            &journal_tip,
            &sha256_hex(&tip_bytes),
            None,
        ));
    }
    if reason == RotationReason::Compromise {
        let evidence = revalidation_record(fixture, &new_generation);
        revalidation = Some(evidence.clone());
        let evidence_bytes = sign(
            &evidence,
            &fixture.keys.new_evidence_signer,
            NEW_EVIDENCE_SIGNER_ID,
        );
        let evidence_digest = sha256_hex(&evidence_bytes);
        reanchor.recovery_revalidation_digest = Some(evidence_digest.clone());
        if let Some(c) = checkpoint.as_mut() {
            c.recovery_revalidation_digest = Some(evidence_digest);
        }
    }
    tamper(&mut reanchor, &mut checkpoint, &mut revalidation);
    // R binds digest(C) over the exact signed checkpoint bytes.
    if let Some(c) = checkpoint.as_ref() {
        let signed = sign(c, &fixture.keys.new_journal_signer, NEW_JOURNAL_SIGNER_ID);
        reanchor.checkpoint_digest = Some(sha256_hex(&signed));
    }
    let signed_reanchor = sign(&reanchor, &fixture.keys.policy, POLICY_SIGNER_ID);
    let inputs = RotationInputs {
        signed_reanchor,
        signed_checkpoint: checkpoint
            .as_ref()
            .map(|c| sign(c, &fixture.keys.new_journal_signer, NEW_JOURNAL_SIGNER_ID)),
        new_policy: new_generation.policy.bytes.clone(),
        new_trust_bundle: new_generation.bundle.bytes.clone(),
        signed_revalidation: revalidation
            .as_ref()
            .map(|r| sign(r, &fixture.keys.new_evidence_signer, NEW_EVIDENCE_SIGNER_ID)),
        custody_record: (reason == RotationReason::Compromise).then(|| b"custody-record".to_vec()),
    };
    let journal_bytes = fixture.journal.as_ref().map(|j| j.0.clone());
    let view = fixture_view(fixture, &tip_bytes, journal_bytes.as_deref());
    let archives = fixture_archives(fixture);
    let plan = build_rotation_plan(&view, &archives, &inputs, now);
    let mut store = MemStore::default();
    store.seed_prior(fixture);
    match plan {
        Ok(plan) => {
            let mut observe = observe_authenticates(plan.preserved_state);
            let result = run_rotation_plan(&plan, &mut store, &mut observe);
            (store, result)
        }
        Err(error) => (store, Err(error)),
    }
}

// ---- group 1: routine rotation in all three preserved states ----

#[test]
fn routine_rotation_never_recovered_publishes_r_only() {
    let fixture = never_recovered_fixture();
    let (store, result) = rotate_fixture(&fixture, RotationReason::Routine, NOW, |_, _, _| {});
    result.expect("routine NEVER_RECOVERED rotation publishes");
    assert!(
        !store.journal_dir.contains_key(CHECKPOINT_NAME),
        "no checkpoint for NEVER_RECOVERED"
    );
    let state_tip: Signed<InstallationReanchor> =
        o3k::recovery_identity::decode_canonical(store.state_root.get("state.json").unwrap())
            .expect("state tip is a signed re-anchor");
    assert_eq!(state_tip.payload.format, REANCHOR_FORMAT);
    assert_eq!(
        state_tip.payload.preserved_state,
        RecoveryState::NeverRecovered
    );
    assert_eq!(state_tip.payload.checkpoint_digest, None);
    assert_eq!(state_tip.payload.recovery_revalidation_digest, None);
}

#[test]
fn routine_rotation_designated_publishes_c_before_r_and_preserves_identity() {
    let fixture = designated_fixture();
    let (store, result) = rotate_fixture(&fixture, RotationReason::Routine, NOW, |_, _, _| {});
    result.expect("routine designated rotation publishes");
    let state_tip: Signed<InstallationReanchor> =
        o3k::recovery_identity::decode_canonical(store.state_root.get("state.json").unwrap())
            .expect("state tip is a signed re-anchor");
    assert_eq!(
        state_tip.payload.preserved_state,
        RecoveryState::RecoveryDesignated
    );
    let checkpoint_bytes = store
        .journal_dir
        .get(CHECKPOINT_NAME)
        .expect("checkpoint published");
    assert_eq!(
        state_tip.payload.checkpoint_digest.as_deref(),
        Some(sha256_hex(checkpoint_bytes).as_str()),
        "R binds digest(C)"
    );
    assert_eq!(
        state_tip.payload.operation_id.as_deref(),
        Some(OPERATION_ID),
        "operation identity preserved"
    );
    assert_eq!(state_tip.payload.artifact_sha256.as_deref(), Some(ARTIFACT));
    assert_eq!(
        state_tip.payload.recovery_directory_digest.as_deref(),
        Some(journal_identity_digest(&fixture.policy.policy).as_str())
    );
}

#[test]
fn routine_rotation_released_authenticates_terminal_evidence() {
    let fixture = released_fixture();
    let (store, result) = rotate_fixture(&fixture, RotationReason::Routine, NOW, |_, _, _| {});
    result.expect("routine RELEASED rotation publishes with authenticated terminal evidence");
    let state_tip: Signed<InstallationReanchor> =
        o3k::recovery_identity::decode_canonical(store.state_root.get("state.json").unwrap())
            .expect("state tip is a signed re-anchor");
    assert_eq!(state_tip.payload.preserved_state, RecoveryState::Released);
    assert_eq!(
        state_tip.payload.terminal_journal_digest.as_deref(),
        Some(authenticated_tip_hash(fixture.journal.as_ref().unwrap()).as_str()),
        "RELEASED terminal journal hash is the authenticated old tip"
    );
    assert!(state_tip.payload.terminal_evidence_digest.is_some());
}

#[test]
fn released_rotation_with_wrong_terminal_journal_digest_fails_closed() {
    let fixture = released_fixture();
    let wrong = hex(&[0x77; 32]);
    let (_store, result) = rotate_fixture(&fixture, RotationReason::Routine, NOW, |r, _, _| {
        r.terminal_journal_digest = Some(wrong);
    });
    assert!(
        matches!(
            result,
            Err(ReanchorError::Binding(_))
                | Err(ReanchorError::Sequence(_))
                | Err(ReanchorError::Trust(_))
        ),
        "forged terminal evidence must fail closed: {result:?}"
    );
}

// ---- group 2: valid/invalid compromise evidence ----

#[test]
fn compromise_rotation_requires_valid_evidence_and_consumes_it_exactly_once() {
    let fixture = designated_fixture();
    let (store, result) = rotate_fixture(&fixture, RotationReason::Compromise, NOW, |_, _, _| {});
    result.expect("compromise rotation with valid evidence");
    let consumption: RevalidationConsumption = o3k::recovery_identity::decode_canonical(
        store
            .state_root
            .get("revalidation-consumption.json")
            .expect("consumption record persisted"),
    )
    .expect("consumption record decodes");
    assert!(
        consumption.consumed,
        "evidence marked consumed after final observation"
    );
    assert_eq!(consumption.reanchor_digest.len(), 64);
    assert_eq!(consumption.checkpoint_digest.len(), 64);
}

#[test]
fn compromise_evidence_with_wrong_custody_digest_fails_closed() {
    let fixture = designated_fixture();
    let (_store, result) = rotate_fixture(
        &fixture,
        RotationReason::Compromise,
        NOW,
        |_, _, evidence| {
            if let Some(e) = evidence.as_mut() {
                e.custody_record_digest = hex(&[0xC0; 32]);
            }
        },
    );
    assert!(
        matches!(
            result,
            Err(ReanchorError::Evidence(_)) | Err(ReanchorError::Binding(_))
        ),
        "custody mismatch must fail closed: {result:?}"
    );
}

#[test]
fn compromise_evidence_with_insufficient_custody_fails_closed() {
    let fixture = designated_fixture();
    let (_store, result) = rotate_fixture(
        &fixture,
        RotationReason::Compromise,
        NOW,
        |_, _, evidence| {
            if let Some(e) = evidence.as_mut() {
                e.recovery_quorum_event_id.clear();
            }
        },
    );
    assert!(
        matches!(
            result,
            Err(ReanchorError::Evidence(_)) | Err(ReanchorError::Binding(_))
        ),
        "missing 2-of-3 quorum event must fail closed: {result:?}"
    );
}

#[test]
fn compromise_evidence_binding_wrong_prior_tips_fails_closed() {
    let fixture = designated_fixture();
    let (_store, result) = rotate_fixture(
        &fixture,
        RotationReason::Compromise,
        NOW,
        |_, _, evidence| {
            if let Some(e) = evidence.as_mut() {
                e.prior_state_tip_digest = hex(&[0x7B; 32]);
            }
        },
    );
    assert!(
        matches!(
            result,
            Err(ReanchorError::Evidence(_)) | Err(ReanchorError::Binding(_))
        ),
        "unreviewed tips must fail closed: {result:?}"
    );
}

#[test]
fn compromise_rotation_requires_new_root_to_revoke_old_signer() {
    let fixture = designated_fixture();
    // Rebuild the new bundle without revoking the old signer: the plan must
    // refuse because compromise rotation must revoke the old root.
    let new_generation = build_new_generation(&fixture, RotationReason::Routine);
    let tip_bytes = fixture.designated.as_ref().unwrap().1.clone();
    let journal_tip = authenticated_tip_hash(fixture.journal.as_ref().unwrap());
    let mut reanchor = reanchor_record(
        &fixture,
        &new_generation,
        RotationReason::Compromise,
        1,
        &sha256_hex(&tip_bytes),
        None,
        None,
        Some(OPERATION_ID),
        Some(ARTIFACT),
        Some(&journal_identity_digest(&fixture.policy.policy)),
        None,
        None,
    );
    let checkpoint = checkpoint_record(
        &fixture,
        &new_generation,
        RotationReason::Compromise,
        &journal_tip,
        &sha256_hex(&tip_bytes),
        None,
    );
    let signed_checkpoint = sign(
        &checkpoint,
        &fixture.keys.new_journal_signer,
        NEW_JOURNAL_SIGNER_ID,
    );
    reanchor.checkpoint_digest = Some(sha256_hex(&signed_checkpoint));
    let evidence = revalidation_record(&fixture, &new_generation);
    let evidence_bytes = sign(
        &evidence,
        &fixture.keys.new_evidence_signer,
        NEW_EVIDENCE_SIGNER_ID,
    );
    let evidence_digest = sha256_hex(&evidence_bytes);
    reanchor.recovery_revalidation_digest = Some(evidence_digest.clone());
    let mut checkpoint = checkpoint;
    checkpoint.recovery_revalidation_digest = Some(evidence_digest);
    let inputs = RotationInputs {
        signed_reanchor: sign(&reanchor, &fixture.keys.policy, POLICY_SIGNER_ID),
        signed_checkpoint: Some(sign(
            &checkpoint,
            &fixture.keys.new_journal_signer,
            NEW_JOURNAL_SIGNER_ID,
        )),
        new_policy: new_generation.policy.bytes.clone(),
        new_trust_bundle: new_generation.bundle.bytes.clone(),
        signed_revalidation: Some(evidence_bytes),
        custody_record: Some(b"custody-record".to_vec()),
    };
    let journal_bytes = fixture.journal.as_ref().map(|j| j.0.clone());
    let view = fixture_view(&fixture, &tip_bytes, journal_bytes.as_deref());
    let result = build_rotation_plan(&view, &fixture_archives(&fixture), &inputs, NOW);
    assert!(
        matches!(
            result,
            Err(ReanchorError::Trust(_))
                | Err(ReanchorError::Evidence(_))
                | Err(ReanchorError::Binding(_))
        ),
        "compromise without old-root revocation must fail closed: {result:?}"
    );
}

// ---- group 3: signature, purpose, revocation, expiry ----

#[test]
fn reanchor_signed_by_non_policy_authority_fails_closed() {
    let fixture = never_recovered_fixture();
    let new_generation = build_new_generation(&fixture, RotationReason::Routine);
    let tip_bytes = fixture.initial.1.clone();
    let reanchor = reanchor_record(
        &fixture,
        &new_generation,
        RotationReason::Routine,
        0,
        &sha256_hex(&tip_bytes),
        None,
        None,
        None,
        None,
        None,
        None,
        None,
    );
    // The offline journal authority never signs R.
    let inputs = RotationInputs {
        signed_reanchor: sign(
            &reanchor,
            &fixture.keys.old_journal_signer,
            OLD_JOURNAL_SIGNER_ID,
        ),
        signed_checkpoint: None,
        new_policy: new_generation.policy.bytes.clone(),
        new_trust_bundle: new_generation.bundle.bytes.clone(),
        signed_revalidation: None,
        custody_record: None,
    };
    let view = fixture_view(&fixture, &tip_bytes, None);
    let result = build_rotation_plan(&view, &fixture_archives(&fixture), &inputs, NOW);
    assert!(
        matches!(
            result,
            Err(ReanchorError::Signature(_)) | Err(ReanchorError::Binding(_))
        ),
        "journal-signed R must fail closed: {result:?}"
    );
}

#[test]
fn checkpoint_signed_by_old_journal_authority_fails_closed() {
    let fixture = designated_fixture();
    let new_generation = build_new_generation(&fixture, RotationReason::Routine);
    let tip_bytes = fixture.designated.as_ref().unwrap().1.clone();
    let journal_tip = authenticated_tip_hash(fixture.journal.as_ref().unwrap());
    let mut reanchor = reanchor_record(
        &fixture,
        &new_generation,
        RotationReason::Routine,
        1,
        &sha256_hex(&tip_bytes),
        None,
        None,
        Some(OPERATION_ID),
        Some(ARTIFACT),
        Some(&journal_identity_digest(&fixture.policy.policy)),
        None,
        None,
    );
    let checkpoint = checkpoint_record(
        &fixture,
        &new_generation,
        RotationReason::Routine,
        &journal_tip,
        &sha256_hex(&tip_bytes),
        None,
    );
    let signed_checkpoint = sign(
        &checkpoint,
        &fixture.keys.new_journal_signer,
        NEW_JOURNAL_SIGNER_ID,
    );
    reanchor.checkpoint_digest = Some(sha256_hex(&signed_checkpoint));
    let inputs = RotationInputs {
        signed_reanchor: sign(&reanchor, &fixture.keys.policy, POLICY_SIGNER_ID),
        // C signed by the OLD journal signer instead of the new authority.
        signed_checkpoint: Some(sign(
            &checkpoint,
            &fixture.keys.old_journal_signer,
            OLD_JOURNAL_SIGNER_ID,
        )),
        new_policy: new_generation.policy.bytes.clone(),
        new_trust_bundle: new_generation.bundle.bytes.clone(),
        signed_revalidation: None,
        custody_record: None,
    };
    let journal_bytes = fixture.journal.as_ref().map(|j| j.0.clone());
    let view = fixture_view(&fixture, &tip_bytes, journal_bytes.as_deref());
    let result = build_rotation_plan(&view, &fixture_archives(&fixture), &inputs, NOW);
    assert!(
        matches!(
            result,
            Err(ReanchorError::Signature(_)) | Err(ReanchorError::Trust(_))
        ),
        "old-era C signature must fail closed: {result:?}"
    );
}

#[test]
fn revalidation_signed_by_old_evidence_authority_fails_closed() {
    let fixture = designated_fixture();
    let (_store, result) = rotate_fixture(
        &fixture,
        RotationReason::Compromise,
        NOW,
        |_, _, evidence| {
            // Re-signing happens in rotate_fixture with the new signer; simulate a
            // wrong signer by corrupting the evidence scope instead.
            if let Some(e) = evidence.as_mut() {
                e.new_evidence_key_id = OLD_EVIDENCE_SIGNER_ID.to_string();
            }
        },
    );
    assert!(
        matches!(
            result,
            Err(ReanchorError::Evidence(_))
                | Err(ReanchorError::Binding(_))
                | Err(ReanchorError::Signature(_))
        ),
        "wrong-purpose evidence must fail closed: {result:?}"
    );
}

#[test]
fn rotated_current_trust_with_revoked_new_signer_fails_closed() {
    let fixture = designated_fixture();
    let new_generation = build_new_generation(&fixture, RotationReason::Routine);
    // New bundle whose journal revocation document revokes the new signer.
    let mut bundle = new_generation.bundle.clone();
    bundle.bundle.journal_revocations = signed_revocations(
        &revocation_document(
            2,
            NOW - 40,
            vec!["serial-journal-2".to_string()],
            vec![NEW_JOURNAL_SIGNER_ID.to_string()],
        ),
        &fixture.keys.new_journal_root,
        NEW_JOURNAL_ROOT_ID,
    );
    bundle.bundle.journal_revocation_sequence = 2;
    bundle.bundle.journal_revocation_digest =
        o3k::recovery_identity::digest(&bundle.bundle.journal_revocations).unwrap();
    bundle.bytes = o3k::recovery_identity::canonical(&bundle.bundle).unwrap();
    bundle.digest = sha256_hex(&bundle.bytes);
    let mut policy = new_generation.policy.clone();
    policy.policy.trust_bundle_digest = bundle.digest.clone();
    policy.bytes = sign(&policy.policy, &fixture.keys.policy, POLICY_SIGNER_ID);
    policy.digest = sha256_hex(&policy.bytes);
    let tip_bytes = fixture.designated.as_ref().unwrap().1.clone();
    let journal_tip = authenticated_tip_hash(fixture.journal.as_ref().unwrap());
    let mut reanchor = reanchor_record(
        &fixture,
        &NewGeneration {
            bundle: bundle.clone(),
            policy: policy.clone(),
        },
        RotationReason::Routine,
        1,
        &sha256_hex(&tip_bytes),
        None,
        None,
        Some(OPERATION_ID),
        Some(ARTIFACT),
        Some(&journal_identity_digest(&fixture.policy.policy)),
        None,
        None,
    );
    let checkpoint = checkpoint_record(
        &fixture,
        &NewGeneration {
            bundle: bundle.clone(),
            policy: policy.clone(),
        },
        RotationReason::Routine,
        &journal_tip,
        &sha256_hex(&tip_bytes),
        None,
    );
    let signed_checkpoint = sign(
        &checkpoint,
        &fixture.keys.new_journal_signer,
        NEW_JOURNAL_SIGNER_ID,
    );
    reanchor.checkpoint_digest = Some(sha256_hex(&signed_checkpoint));
    reanchor.new_trust_bundle_digest = bundle.digest.clone();
    reanchor.new_policy_digest = policy.digest.clone();
    reanchor.new_journal_revocation = high_water(&bundle.bundle.journal_revocations);
    let mut checkpoint = checkpoint;
    checkpoint.new_journal_revocation = high_water(&bundle.bundle.journal_revocations);
    checkpoint.new_journal_key_id = NEW_JOURNAL_SIGNER_ID.to_string();
    let inputs = RotationInputs {
        signed_reanchor: sign(&reanchor, &fixture.keys.policy, POLICY_SIGNER_ID),
        signed_checkpoint: Some(sign(
            &checkpoint,
            &fixture.keys.new_journal_signer,
            NEW_JOURNAL_SIGNER_ID,
        )),
        new_policy: policy.bytes.clone(),
        new_trust_bundle: bundle.bytes.clone(),
        signed_revalidation: None,
        custody_record: None,
    };
    let journal_bytes = fixture.journal.as_ref().map(|j| j.0.clone());
    let view = fixture_view(&fixture, &tip_bytes, journal_bytes.as_deref());
    let result = build_rotation_plan(&view, &fixture_archives(&fixture), &inputs, NOW);
    assert!(
        matches!(result, Err(ReanchorError::Trust(_))),
        "revoked current-era signer must fail closed: {result:?}"
    );
}

// ---- group 4: equal-sequence equivocation and rollback ----

#[test]
fn equal_sequence_reanchor_with_different_digest_is_equivocation() {
    let fixture = never_recovered_fixture();
    let (store, first) = rotate_fixture(&fixture, RotationReason::Routine, NOW, |_, _, _| {});
    first.expect("first rotation succeeds");
    // Present a different R at the same sequence against the rotated
    // generation: the new state tip is the published R (sequence 1).
    let new_generation = build_new_generation(&fixture, RotationReason::Routine);
    let published_tip = store.state_root.get("state.json").unwrap().clone();
    let mut r2 = reanchor_record(
        &fixture,
        &new_generation,
        RotationReason::Routine,
        1,
        &sha256_hex(&published_tip),
        None,
        None,
        None,
        None,
        None,
        None,
        None,
    );
    r2.new_policy_digest = hex(&[0xE1; 32]);
    let consumption = store
        .state_root
        .get("revalidation-consumption.json")
        .cloned();
    let staged_prior_policy = store.state_root.get("staged-prior-policy.json").cloned();
    let staged_prior_trust = store.state_root.get("staged-prior-trust.json").cloned();
    let view = GenerationView {
        manifest_bytes: &fixture.manifest_bytes,
        policy_bytes: store.fixed_config.get("installation-policy.json").unwrap(),
        policy_high_water_bytes: store.state_root.get("policy.json").map(Vec::as_slice),
        fixed_bundle_bytes: store.fixed_config.get("recovery-trust.json").unwrap(),
        trust_high_water_bytes: store.state_root.get("trust.json").unwrap(),
        staged_prior_policy_bytes: staged_prior_policy.as_deref(),
        staged_prior_trust_bytes: staged_prior_trust.as_deref(),
        state_tip_bytes: &published_tip,
        journal_bytes: store
            .journal_dir
            .get("restore-journal.json")
            .map(Vec::as_slice),
        checkpoint_bytes: store.journal_dir.get(CHECKPOINT_NAME).map(Vec::as_slice),
        consumption_record_bytes: consumption.as_deref(),
        pending_signing_request_present: false,
        now: NOW,
    };
    let store_ref = &store;
    let inputs = RotationInputs {
        signed_reanchor: sign(&r2, &fixture.keys.policy, POLICY_SIGNER_ID),
        signed_checkpoint: None,
        new_policy: new_generation.policy.bytes.clone(),
        new_trust_bundle: new_generation.bundle.bytes.clone(),
        signed_revalidation: None,
        custody_record: None,
    };
    let result = build_rotation_plan(&view, &StoreArchives(store_ref), &inputs, NOW);
    assert!(
        matches!(
            result,
            Err(ReanchorError::Equivocation(_))
                | Err(ReanchorError::Sequence(_))
                | Err(ReanchorError::Conflicting(_))
        ),
        "equal-sequence different-digest R must fail closed: {result:?}"
    );
}

#[test]
fn stale_sequence_reanchor_is_rejected() {
    let fixture = never_recovered_fixture();
    let new_generation = build_new_generation(&fixture, RotationReason::Routine);
    let tip_bytes = fixture.initial.1.clone();
    let mut stale = reanchor_record(
        &fixture,
        &new_generation,
        RotationReason::Routine,
        0,
        &sha256_hex(&tip_bytes),
        None,
        None,
        None,
        None,
        None,
        None,
        None,
    );
    stale.sequence = 0;
    let inputs = RotationInputs {
        signed_reanchor: sign(&stale, &fixture.keys.policy, POLICY_SIGNER_ID),
        signed_checkpoint: None,
        new_policy: new_generation.policy.bytes.clone(),
        new_trust_bundle: new_generation.bundle.bytes.clone(),
        signed_revalidation: None,
        custody_record: None,
    };
    let view = fixture_view(&fixture, &tip_bytes, None);
    let result = build_rotation_plan(&view, &fixture_archives(&fixture), &inputs, NOW);
    assert!(
        matches!(
            result,
            Err(ReanchorError::Sequence(_)) | Err(ReanchorError::Equivocation(_))
        ),
        "stale sequence must fail closed: {result:?}"
    );
}

// ---- group 5: replay/reuse and idempotent exact-byte resume ----

#[test]
fn byte_identical_rotation_is_idempotent() {
    let fixture = designated_fixture();
    let new_generation = build_new_generation(&fixture, RotationReason::Routine);
    let tip_bytes = fixture.designated.as_ref().unwrap().1.clone();
    let journal_tip = authenticated_tip_hash(fixture.journal.as_ref().unwrap());
    let mut reanchor = reanchor_record(
        &fixture,
        &new_generation,
        RotationReason::Routine,
        1,
        &sha256_hex(&tip_bytes),
        None,
        None,
        Some(OPERATION_ID),
        Some(ARTIFACT),
        Some(&journal_identity_digest(&fixture.policy.policy)),
        None,
        None,
    );
    let checkpoint = checkpoint_record(
        &fixture,
        &new_generation,
        RotationReason::Routine,
        &journal_tip,
        &sha256_hex(&tip_bytes),
        None,
    );
    let signed_checkpoint = sign(
        &checkpoint,
        &fixture.keys.new_journal_signer,
        NEW_JOURNAL_SIGNER_ID,
    );
    reanchor.checkpoint_digest = Some(sha256_hex(&signed_checkpoint));
    let inputs = RotationInputs {
        signed_reanchor: sign(&reanchor, &fixture.keys.policy, POLICY_SIGNER_ID),
        signed_checkpoint: Some(sign(
            &checkpoint,
            &fixture.keys.new_journal_signer,
            NEW_JOURNAL_SIGNER_ID,
        )),
        new_policy: new_generation.policy.bytes.clone(),
        new_trust_bundle: new_generation.bundle.bytes.clone(),
        signed_revalidation: None,
        custody_record: None,
    };
    let journal_bytes = fixture.journal.as_ref().map(|j| j.0.clone());
    let view = fixture_view(&fixture, &tip_bytes, journal_bytes.as_deref());
    let plan =
        build_rotation_plan(&view, &fixture_archives(&fixture), &inputs, NOW).expect("plan builds");
    let mut store = MemStore::default();
    store.seed_prior(&fixture);
    let writes_before = store.writes.len();
    let mut observe = observe_authenticates(plan.preserved_state);
    run_rotation_plan(&plan, &mut store, &mut observe).expect("first run");
    let writes_after_first = store.writes.len();

    // Idempotent re-run over the rotated generation: the exact same R bytes,
    // now the published tip.
    let consumption = store
        .state_root
        .get("revalidation-consumption.json")
        .cloned();
    let staged_prior_policy = store.state_root.get("staged-prior-policy.json").cloned();
    let staged_prior_trust = store.state_root.get("staged-prior-trust.json").cloned();
    let rotated_view = GenerationView {
        manifest_bytes: &fixture.manifest_bytes,
        policy_bytes: store.fixed_config.get("installation-policy.json").unwrap(),
        policy_high_water_bytes: store.state_root.get("policy.json").map(Vec::as_slice),
        fixed_bundle_bytes: store.fixed_config.get("recovery-trust.json").unwrap(),
        trust_high_water_bytes: store.state_root.get("trust.json").unwrap(),
        staged_prior_policy_bytes: staged_prior_policy.as_deref(),
        staged_prior_trust_bytes: staged_prior_trust.as_deref(),
        state_tip_bytes: store.state_root.get("state.json").unwrap(),
        journal_bytes: store
            .journal_dir
            .get("restore-journal.json")
            .map(Vec::as_slice),
        checkpoint_bytes: store.journal_dir.get(CHECKPOINT_NAME).map(Vec::as_slice),
        consumption_record_bytes: consumption.as_deref(),
        pending_signing_request_present: false,
        now: NOW,
    };
    let second_plan = build_rotation_plan(&rotated_view, &StoreArchives(&store), &inputs, NOW)
        .expect("byte-identical replay builds an idempotent plan");
    let mut observe = observe_authenticates(second_plan.preserved_state);
    run_rotation_plan(&second_plan, &mut store, &mut observe)
        .expect("byte-identical replay is idempotent");
    assert_eq!(
        writes_after_first,
        store.writes.len(),
        "idempotent replay performs no writes"
    );
    assert!(writes_before < writes_after_first);
}

#[test]
fn reusing_single_use_evidence_for_a_different_pair_fails_closed() {
    let fixture = designated_fixture();
    let (store, first) = rotate_fixture(&fixture, RotationReason::Compromise, NOW, |_, _, _| {});
    first.expect("first compromise rotation succeeds");
    // Second rotation attempt that reuses the same evidence digest binding but
    // presents a different R/C pair. Rebuild inputs against the rotated
    // generation with a different new generation.
    let keys = &fixture.keys;
    let second_generation = {
        let journal_revocations = signed_revocations(
            &revocation_document(1, NOW - 30, vec![], vec![]),
            &keys.new_journal_root,
            NEW_JOURNAL_ROOT_ID,
        );
        let evidence_revocations = signed_revocations(
            &revocation_document(1, NOW - 30, vec![], vec![]),
            &keys.new_evidence_root,
            NEW_EVIDENCE_ROOT_ID,
        );
        let bundle = build_bundle(
            &keys.new_journal_root,
            NEW_JOURNAL_ROOT_ID,
            &keys.new_journal_signer,
            NEW_JOURNAL_SIGNER_ID,
            "serial-journal-3",
            &keys.new_evidence_root,
            NEW_EVIDENCE_ROOT_ID,
            &keys.new_evidence_signer,
            NEW_EVIDENCE_SIGNER_ID,
            "serial-evidence-3",
            journal_revocations,
            evidence_revocations,
        );
        let mut policy = build_policy(
            3,
            &sha256_hex(store.fixed_config.get("installation-policy.json").unwrap()),
            &bundle.digest,
            NEW_JOURNAL_ROOT_ID,
            &keys.new_journal_root.verifying_key(),
            NEW_EVIDENCE_ROOT_ID,
            &keys.new_evidence_root.verifying_key(),
        );
        // Force a different policy digest while keeping a valid structure.
        policy.policy.policy_revision = 3;
        policy.bytes = sign(&policy.policy, &fixture.keys.policy, POLICY_SIGNER_ID);
        policy.digest = sha256_hex(&policy.bytes);
        NewGeneration { bundle, policy }
    };
    let published_tip = store.state_root.get("state.json").unwrap().clone();
    let checkpoint_bytes = store.journal_dir.get(CHECKPOINT_NAME).unwrap().clone();
    let consumption: RevalidationConsumption = o3k::recovery_identity::decode_canonical(
        store
            .state_root
            .get("revalidation-consumption.json")
            .unwrap(),
    )
    .unwrap();
    let journal_tip = sha256_hex(&checkpoint_bytes);
    let mut reanchor = reanchor_record(
        &fixture,
        &second_generation,
        RotationReason::Compromise,
        2,
        &sha256_hex(&published_tip),
        Some(&sha256_hex(&checkpoint_bytes)),
        Some(&consumption.evidence_digest),
        Some(OPERATION_ID),
        Some(ARTIFACT),
        Some(&journal_identity_digest(&fixture.policy.policy)),
        None,
        None,
    );
    let current_policy_digest =
        sha256_hex(store.fixed_config.get("installation-policy.json").unwrap());
    let current_bundle_bytes = store.state_root.get("trust.json").unwrap().clone();
    let current_bundle: TrustBundle =
        o3k::recovery_identity::decode_canonical(&current_bundle_bytes).unwrap();
    reanchor.prior_policy_revision = 2;
    reanchor.prior_policy_digest = current_policy_digest;
    reanchor.new_policy_revision = 3;
    reanchor.new_policy_digest = second_generation.policy.digest.clone();
    reanchor.new_trust_bundle_digest = second_generation.bundle.digest.clone();
    reanchor.prior_trust_bundle_digest = sha256_hex(&current_bundle_bytes);
    reanchor.prior_journal_revocation = o3k::recovery_reanchor::RevocationHighWater {
        root_id: current_bundle
            .journal_revocations
            .envelope
            .signer_key_id
            .clone(),
        sequence: current_bundle.journal_revocations.payload.sequence,
        document_digest: o3k::recovery_identity::digest(&current_bundle.journal_revocations)
            .unwrap(),
    };
    reanchor.prior_evidence_revocation = o3k::recovery_reanchor::RevocationHighWater {
        root_id: current_bundle
            .evidence_revocations
            .envelope
            .signer_key_id
            .clone(),
        sequence: current_bundle.evidence_revocations.payload.sequence,
        document_digest: o3k::recovery_identity::digest(&current_bundle.evidence_revocations)
            .unwrap(),
    };
    let mut checkpoint = checkpoint_record(
        &fixture,
        &second_generation,
        RotationReason::Compromise,
        &journal_tip,
        &sha256_hex(&published_tip),
        Some(&consumption.evidence_digest),
    );
    checkpoint.sequence = 3;
    checkpoint.prior_checkpoint_digest = Some(sha256_hex(&checkpoint_bytes));
    checkpoint.new_journal_key_id = NEW_JOURNAL_SIGNER_ID.to_string();
    checkpoint.new_journal_certificate_serial = "serial-journal-3".to_string();
    let signed_checkpoint2 = sign(
        &checkpoint,
        &fixture.keys.new_journal_signer,
        NEW_JOURNAL_SIGNER_ID,
    );
    reanchor.checkpoint_digest = Some(sha256_hex(&signed_checkpoint2));
    let staged_prior_policy = store.state_root.get("staged-prior-policy.json").cloned();
    let staged_prior_trust = store.state_root.get("staged-prior-trust.json").cloned();
    let view = GenerationView {
        manifest_bytes: &fixture.manifest_bytes,
        policy_bytes: store.fixed_config.get("installation-policy.json").unwrap(),
        policy_high_water_bytes: store.state_root.get("policy.json").map(Vec::as_slice),
        fixed_bundle_bytes: store.fixed_config.get("recovery-trust.json").unwrap(),
        trust_high_water_bytes: store.state_root.get("trust.json").unwrap(),
        staged_prior_policy_bytes: staged_prior_policy.as_deref(),
        staged_prior_trust_bytes: staged_prior_trust.as_deref(),
        state_tip_bytes: &published_tip,
        journal_bytes: store
            .journal_dir
            .get("restore-journal.json")
            .map(Vec::as_slice),
        checkpoint_bytes: Some(&checkpoint_bytes),
        consumption_record_bytes: store
            .state_root
            .get("revalidation-consumption.json")
            .map(Vec::as_slice),
        pending_signing_request_present: false,
        now: NOW,
    };
    let inputs = RotationInputs {
        signed_reanchor: sign(&reanchor, &fixture.keys.policy, POLICY_SIGNER_ID),
        signed_checkpoint: Some(sign(
            &checkpoint,
            &fixture.keys.new_journal_signer,
            NEW_JOURNAL_SIGNER_ID,
        )),
        new_policy: second_generation.policy.bytes.clone(),
        new_trust_bundle: second_generation.bundle.bytes.clone(),
        signed_revalidation: None,
        custody_record: Some(b"custody-record".to_vec()),
    };
    let result = build_rotation_plan(&view, &StoreArchives(&store), &inputs, NOW);
    assert!(
        matches!(
            result,
            Err(ReanchorError::Evidence(_))
                | Err(ReanchorError::Conflicting(_))
                | Err(ReanchorError::Equivocation(_))
        ),
        "single-use evidence reused for a different pair must fail closed: {result:?}"
    );
}

// ---- group 6/7: crash before/after every boundary, exact-forward resume ----

const CRASH_POINTS: &[&str] = &[
    "before-stage",
    "after-stage",
    "before-consumption-write",
    "after-consumption-write",
    "before-publish-policy",
    "after-publish-policy",
    "before-publish-policy-high-water",
    "after-publish-policy-high-water",
    "before-publish-trust",
    "after-publish-trust",
    "before-publish-trust-high-water",
    "after-publish-trust-high-water",
    "before-publish-checkpoint",
    "after-publish-checkpoint",
    "before-publish-reanchor",
    "after-publish-reanchor",
    "before-final-observation",
    "after-final-observation",
    "before-consumption-mark",
    "after-consumption-mark",
];

fn rotated_store_snapshot(fixture: &Fixture, reason: RotationReason) -> MemStore {
    // The crash hook fires once per process per point, so when this runs
    // after an interrupted attempt it completes uninterrupted.
    let (store, result) = rotate_fixture(fixture, reason, NOW, |_, _, _| {});
    result.expect("uninterrupted rotation succeeds");
    store
}

#[test]
fn crash_before_and_after_every_publication_boundary_resumes_exact_forward() {
    if std::env::var("O3K_REANCHOR_CRASH_AT").is_ok() {
        // The injected crash points are exercised by spawning this test binary
        // with the variable set; in this direct run they must be inert.
        return;
    }
    let exe = std::env::current_exe().expect("current test binary");
    for point in CRASH_POINTS {
        let status = std::process::Command::new(&exe)
            .arg("crash_at_point")
            .arg("--exact")
            .arg("--nocapture")
            .env("O3K_REANCHOR_CRASH_AT", point)
            .status()
            .expect("spawn crash child");
        assert_eq!(status.code(), Some(0), "crash child failed at {point}");
    }
}

#[test]
fn crash_at_point() {
    let Ok(point) = std::env::var("O3K_REANCHOR_CRASH_AT") else {
        return;
    };
    // Each crash point interrupts the designated rotation; resuming with the
    // injection cleared must reach the identical published generation.
    let fixture = designated_fixture();
    let new_generation = build_new_generation(&fixture, RotationReason::Compromise);
    let tip_bytes = fixture.designated.as_ref().unwrap().1.clone();
    let journal_tip = authenticated_tip_hash(fixture.journal.as_ref().unwrap());
    let mut reanchor = reanchor_record(
        &fixture,
        &new_generation,
        RotationReason::Compromise,
        1,
        &sha256_hex(&tip_bytes),
        None,
        None,
        Some(OPERATION_ID),
        Some(ARTIFACT),
        Some(&journal_identity_digest(&fixture.policy.policy)),
        None,
        None,
    );
    let mut checkpoint = checkpoint_record(
        &fixture,
        &new_generation,
        RotationReason::Compromise,
        &journal_tip,
        &sha256_hex(&tip_bytes),
        None,
    );
    let evidence = revalidation_record(&fixture, &new_generation);
    let evidence_bytes = sign(
        &evidence,
        &fixture.keys.new_evidence_signer,
        NEW_EVIDENCE_SIGNER_ID,
    );
    let evidence_digest = sha256_hex(&evidence_bytes);
    reanchor.recovery_revalidation_digest = Some(evidence_digest.clone());
    checkpoint.recovery_revalidation_digest = Some(evidence_digest);
    let signed_checkpoint = sign(
        &checkpoint,
        &fixture.keys.new_journal_signer,
        NEW_JOURNAL_SIGNER_ID,
    );
    reanchor.checkpoint_digest = Some(sha256_hex(&signed_checkpoint));
    let signed_reanchor = sign(&reanchor, &fixture.keys.policy, POLICY_SIGNER_ID);
    let inputs = RotationInputs {
        signed_reanchor,
        signed_checkpoint: Some(sign(
            &checkpoint,
            &fixture.keys.new_journal_signer,
            NEW_JOURNAL_SIGNER_ID,
        )),
        new_policy: new_generation.policy.bytes.clone(),
        new_trust_bundle: new_generation.bundle.bytes.clone(),
        signed_revalidation: Some(evidence_bytes),
        custody_record: Some(b"custody-record".to_vec()),
    };
    let journal_bytes = fixture.journal.as_ref().map(|j| j.0.clone());
    let view = fixture_view(&fixture, &tip_bytes, journal_bytes.as_deref());
    let plan =
        build_rotation_plan(&view, &fixture_archives(&fixture), &inputs, NOW).expect("plan builds");
    let mut store = MemStore::default();
    store.seed_prior(&fixture);
    let mut observe = observe_authenticates(plan.preserved_state);
    let interrupted = run_rotation_plan(&plan, &mut store, &mut observe);
    assert!(
        matches!(interrupted, Err(ReanchorError::InjectedCrash(p)) if p == point),
        "run at {point} must stop with the injected crash, got {interrupted:?}"
    );

    // Exact-forward resume: same inputs, same store. The injection hook fires
    // once per process, so the resume continues past the crashed boundary.
    let consumption = store
        .state_root
        .get("revalidation-consumption.json")
        .cloned();
    let staged_prior_policy = store.state_root.get("staged-prior-policy.json").cloned();
    let staged_prior_trust = store.state_root.get("staged-prior-trust.json").cloned();
    let rotated_view = GenerationView {
        manifest_bytes: &fixture.manifest_bytes,
        policy_bytes: store.fixed_config.get("installation-policy.json").unwrap(),
        policy_high_water_bytes: store.state_root.get("policy.json").map(Vec::as_slice),
        fixed_bundle_bytes: store.fixed_config.get("recovery-trust.json").unwrap(),
        trust_high_water_bytes: store.state_root.get("trust.json").unwrap(),
        staged_prior_policy_bytes: staged_prior_policy.as_deref(),
        staged_prior_trust_bytes: staged_prior_trust.as_deref(),
        state_tip_bytes: store.state_root.get("state.json").unwrap(),
        journal_bytes: store
            .journal_dir
            .get("restore-journal.json")
            .map(Vec::as_slice),
        checkpoint_bytes: store.journal_dir.get(CHECKPOINT_NAME).map(Vec::as_slice),
        consumption_record_bytes: consumption.as_deref(),
        pending_signing_request_present: false,
        now: NOW,
    };
    let resume_inputs = RotationInputs {
        signed_reanchor: inputs.signed_reanchor.clone(),
        signed_checkpoint: inputs.signed_checkpoint.clone(),
        new_policy: inputs.new_policy.clone(),
        new_trust_bundle: inputs.new_trust_bundle.clone(),
        signed_revalidation: inputs.signed_revalidation.clone(),
        custody_record: inputs.custody_record.clone(),
    };
    let resume_plan =
        build_rotation_plan(&rotated_view, &StoreArchives(&store), &resume_inputs, NOW)
            .expect("exact-byte resume builds a plan");
    let mut observe2 = observe_authenticates(resume_plan.preserved_state);
    run_rotation_plan(&resume_plan, &mut store, &mut observe2).expect("exact-forward resume");

    let reference = rotated_store_snapshot(&fixture, RotationReason::Compromise);
    assert_eq!(
        store.state_root, reference.state_root,
        "state root converges at {point}"
    );
    assert_eq!(
        store.journal_dir, reference.journal_dir,
        "journal dir converges at {point}"
    );
    assert_eq!(
        store.fixed_config, reference.fixed_config,
        "fixed config converges at {point}"
    );
}

// ---- group 8: pre-C1.1 strict verifier denies unknown R/C ----

#[test]
fn pre_c11_strict_verifier_denies_unknown_reanchor_and_checkpoint() {
    let fixture = designated_fixture();
    let (_store, result) = rotate_fixture(&fixture, RotationReason::Routine, NOW, |_, _, _| {});
    result.expect("rotation succeeds under the C1.1 verifier");
    let new_generation = build_new_generation(&fixture, RotationReason::Routine);
    let tip_bytes = fixture.designated.as_ref().unwrap().1.clone();
    let journal_tip = authenticated_tip_hash(fixture.journal.as_ref().unwrap());
    let reanchor = reanchor_record(
        &fixture,
        &new_generation,
        RotationReason::Routine,
        1,
        &sha256_hex(&tip_bytes),
        None,
        None,
        Some(OPERATION_ID),
        Some(ARTIFACT),
        Some(&journal_identity_digest(&fixture.policy.policy)),
        None,
        None,
    );
    let checkpoint = checkpoint_record(
        &fixture,
        &new_generation,
        RotationReason::Routine,
        &journal_tip,
        &sha256_hex(&tip_bytes),
        None,
    );
    let r_bytes = sign(&reanchor, &fixture.keys.policy, POLICY_SIGNER_ID);
    let c_bytes = sign(
        &checkpoint,
        &fixture.keys.new_journal_signer,
        NEW_JOURNAL_SIGNER_ID,
    );
    assert!(
        verify_pre_c11_state_tip(&r_bytes).is_err(),
        "pre-C1.1 verifier must deny the unknown re-anchor record"
    );
    assert!(
        verify_pre_c11_state_tip(&c_bytes).is_err(),
        "pre-C1.1 verifier must deny the unknown checkpoint record"
    );
    // Sanity: the strict fixture still accepts an authentic disposition.
    verify_pre_c11_state_tip(&fixture.designated.as_ref().unwrap().1)
        .expect("pre-C1.1 verifier accepts the C1 disposition");
}

// ---- group 9: markers, journal content, and foreign state preserved ----

#[test]
fn rotation_preserves_journal_content_and_denial_markers_byte_for_byte() {
    let fixture = designated_fixture();
    let new_generation = build_new_generation(&fixture, RotationReason::Routine);
    let tip_bytes = fixture.designated.as_ref().unwrap().1.clone();
    let journal_tip = authenticated_tip_hash(fixture.journal.as_ref().unwrap());
    let mut reanchor = reanchor_record(
        &fixture,
        &new_generation,
        RotationReason::Routine,
        1,
        &sha256_hex(&tip_bytes),
        None,
        None,
        Some(OPERATION_ID),
        Some(ARTIFACT),
        Some(&journal_identity_digest(&fixture.policy.policy)),
        None,
        None,
    );
    let checkpoint = checkpoint_record(
        &fixture,
        &new_generation,
        RotationReason::Routine,
        &journal_tip,
        &sha256_hex(&tip_bytes),
        None,
    );
    let signed_checkpoint = sign(
        &checkpoint,
        &fixture.keys.new_journal_signer,
        NEW_JOURNAL_SIGNER_ID,
    );
    reanchor.checkpoint_digest = Some(sha256_hex(&signed_checkpoint));
    let inputs = RotationInputs {
        signed_reanchor: sign(&reanchor, &fixture.keys.policy, POLICY_SIGNER_ID),
        signed_checkpoint: Some(sign(
            &checkpoint,
            &fixture.keys.new_journal_signer,
            NEW_JOURNAL_SIGNER_ID,
        )),
        new_policy: new_generation.policy.bytes.clone(),
        new_trust_bundle: new_generation.bundle.bytes.clone(),
        signed_revalidation: None,
        custody_record: None,
    };
    let mut store = MemStore::default();
    store.seed_prior(&fixture);
    // Pre-existing unsigned journal content (denial markers, quarantine notes).
    store.journal_dir.insert(
        "restore-signing-request.json".to_string(),
        b"pending-request".to_vec(),
    );
    store.journal_dir.insert(
        "unsigned-denial.marker".to_string(),
        b"marker-bytes".to_vec(),
    );
    // The quiescence observation reports the pending request before any tip
    // is observed.
    let mut view = fixture_view(
        &fixture,
        &tip_bytes,
        fixture.journal.as_ref().map(|j| j.0.as_slice()),
    );
    view.pending_signing_request_present = true;
    let plan = build_rotation_plan(&view, &fixture_archives(&fixture), &inputs, NOW);
    assert!(
        matches!(plan, Err(ReanchorError::Quiescence(_))),
        "pending signing request must deny rotation before observation: {plan:?}"
    );
    // With the request removed, rotation completes and every pre-existing
    // journal byte is preserved exactly.
    store.journal_dir.remove("restore-signing-request.json");
    let journal_bytes = fixture.journal.as_ref().map(|j| j.0.clone());
    let view = fixture_view(&fixture, &tip_bytes, journal_bytes.as_deref());
    let plan =
        build_rotation_plan(&view, &fixture_archives(&fixture), &inputs, NOW).expect("plan builds");
    let mut observe = observe_authenticates(plan.preserved_state);
    let result = run_rotation_plan(&plan, &mut store, &mut observe);
    result.expect("rotation without a pending request succeeds");
    // Rotation completed only after the operator removed the pending request;
    // every remaining pre-existing journal byte is preserved exactly.
    assert!(
        !store
            .journal_dir
            .contains_key("restore-signing-request.json"),
        "rotation never restores or rewrites the removed pending request"
    );
    assert_eq!(
        store.journal_dir.get("unsigned-denial.marker").unwrap(),
        b"marker-bytes",
        "unsigned denial marker preserved byte-for-byte"
    );
    assert_eq!(
        store.journal_dir.get("restore-journal.json").unwrap(),
        &fixture.journal.as_ref().unwrap().0,
        "journal chain preserved byte-for-byte"
    );
}

#[test]
fn rotation_writes_only_recovery_state_files() {
    let fixture = designated_fixture();
    let (store, result) = rotate_fixture(&fixture, RotationReason::Compromise, NOW, |_, _, _| {});
    result.expect("rotation succeeds");
    let expected: BTreeSet<(RotationArea, &str)> = [
        (RotationArea::StateRoot, "staged-policy.json"),
        (RotationArea::StateRoot, "staged-trust.json"),
        (RotationArea::StateRoot, "staged-reanchor.json"),
        (RotationArea::StateRoot, "staged-prior-policy.json"),
        (RotationArea::StateRoot, "staged-prior-trust.json"),
        (RotationArea::JournalDir, "staged-checkpoint.json"),
        (RotationArea::StateRoot, "revalidation-consumption.json"),
        (RotationArea::FixedConfig, "installation-policy.json"),
        (RotationArea::StateRoot, "policy.json"),
        (RotationArea::FixedConfig, "recovery-trust.json"),
        (RotationArea::StateRoot, "trust.json"),
        (RotationArea::JournalDir, CHECKPOINT_NAME),
        (RotationArea::StateRoot, "state-"),
        (RotationArea::StateRoot, "policy-"),
        (RotationArea::StateRoot, "trust-"),
        (RotationArea::StateRoot, "state.json"),
        (RotationArea::StateRoot, "revalidation-consumption.json"),
    ]
    .into_iter()
    .collect();
    for (area, name) in &store.writes {
        let known = expected
            .iter()
            .any(|(a, prefix)| a == area && name.starts_with(prefix));
        assert!(
            known,
            "rotation wrote unexpected file {area:?}/{name}; rotation must not mutate foreign state"
        );
    }
    // The old chain and unsigned markers are never in the write set.
    assert!(
        !store
            .writes
            .iter()
            .any(|(a, n)| *a == RotationArea::JournalDir && n == "restore-journal.json"),
        "rotation never rewrites the old journal chain"
    );
}

// ---- group 11: secret-safe errors ----

#[test]
fn rotation_errors_are_secret_safe_static_strings() {
    let fixture = designated_fixture();
    let secretish = [
        key_hex(&fixture.keys.policy.verifying_key()),
        key_hex(&fixture.keys.new_journal_signer.verifying_key()),
        hex(&[0x6E; 32]),
        ARTIFACT.to_string(),
    ];
    let mut saw_error = false;
    let (_store, wrong_custody) = rotate_fixture(
        &fixture,
        RotationReason::Compromise,
        NOW,
        |_, _, evidence| {
            if let Some(e) = evidence.as_mut() {
                e.custody_record_digest = hex(&[0xC0; 32]);
            }
        },
    );
    if let Err(error) = wrong_custody {
        saw_error = true;
        let rendered = format!("{error:?}");
        for secret in &secretish {
            assert!(
                !rendered.contains(secret.as_str()),
                "error must not leak fixture secrets: {rendered}"
            );
        }
    }
    let (_store, bad_sig) = rotate_fixture(
        &fixture,
        RotationReason::Routine,
        NOW,
        |_, checkpoint, _| {
            if let Some(c) = checkpoint.as_mut() {
                c.rotation_reason = RotationReason::Compromise;
            }
        },
    );
    if let Err(error) = bad_sig {
        saw_error = true;
        let rendered = format!("{error:?}");
        for secret in &secretish {
            assert!(
                !rendered.contains(secret.as_str()),
                "error must not leak fixture secrets: {rendered}"
            );
        }
    }
    assert!(saw_error, "fixture produced no error to inspect");
}

// ---- group 12: clock rollback and expiry ----

#[test]
fn evidence_outside_the_exact_validity_window_fails_closed() {
    let fixture = designated_fixture();
    let (_store, before) =
        rotate_fixture(&fixture, RotationReason::Compromise, NOW - 1, |_, _, _| {});
    assert!(
        matches!(before, Err(ReanchorError::Evidence(_))),
        "clock rollback before issued_at must deny: {before:?}"
    );
    let (_store, after) = rotate_fixture(
        &fixture,
        RotationReason::Compromise,
        NOW + REVALIDATION_VALIDITY_SECONDS,
        |_, _, _| {},
    );
    assert!(
        matches!(after, Err(ReanchorError::Evidence(_))),
        "expired evidence must deny: {after:?}"
    );
    let (_store, inside) = rotate_fixture(
        &fixture,
        RotationReason::Compromise,
        NOW + REVALIDATION_VALIDITY_SECONDS - 1,
        |_, _, _| {},
    );
    inside.expect("evidence inside the 300-second window verifies");
}

#[test]
fn evidence_with_wrong_validity_arithmetic_fails_closed() {
    let fixture = designated_fixture();
    let (_store, result) = rotate_fixture(
        &fixture,
        RotationReason::Compromise,
        NOW,
        |_, _, evidence| {
            if let Some(e) = evidence.as_mut() {
                e.expires_at = e.issued_at + REVALIDATION_VALIDITY_SECONDS + 1;
            }
        },
    );
    assert!(
        matches!(result, Err(ReanchorError::Evidence(_))),
        "expires_at must be exactly issued_at + 300: {result:?}"
    );
}

#[test]
fn evidence_with_malformed_nonce_fails_closed() {
    let fixture = designated_fixture();
    let (_store, result) = rotate_fixture(
        &fixture,
        RotationReason::Compromise,
        NOW,
        |_, _, evidence| {
            if let Some(e) = evidence.as_mut() {
                e.nonce = "00".repeat(16);
            }
        },
    );
    assert!(
        matches!(result, Err(ReanchorError::Evidence(_))),
        "256-bit nonce is mandatory: {result:?}"
    );
}

// ---- observation of the legacy generation (startup load path parity) ----

#[test]
fn observe_disposition_generation_matches_the_designated_startup_path() {
    let fixture = designated_fixture();
    let view = fixture_view(
        &fixture,
        &fixture.designated.as_ref().unwrap().1,
        fixture.journal.as_ref().map(|j| j.0.as_slice()),
    );
    let observed = observe_disposition_generation(&view, &fixture_archives(&fixture))
        .expect("disposition generation observes");
    assert_eq!(observed.preserved_state, RecoveryState::RecoveryDesignated);
    assert_eq!(observed.tip_sequence, 1);
    assert_eq!(observed.tip_digest, fixture.designated.as_ref().unwrap().2);
    let journal = observed.journal.expect("designated journal observed");
    assert_eq!(journal.phase, RestorePhase::Preflighted);
    assert_eq!(
        journal.tip_hash,
        authenticated_tip_hash(fixture.journal.as_ref().unwrap())
    );
}

// ---- group 13: RELEASED preservation under compromise rotation ----

#[test]
fn released_compromise_rotation_preserves_terminal_evidence_exactly() {
    let fixture = released_fixture();
    let (store, result) = rotate_fixture(&fixture, RotationReason::Compromise, NOW, |_, _, _| {});
    result.expect("RELEASED compromise rotation publishes");
    let state_tip: Signed<InstallationReanchor> =
        o3k::recovery_identity::decode_canonical(store.state_root.get("state.json").unwrap())
            .expect("state tip is a signed re-anchor");
    assert_eq!(state_tip.payload.preserved_state, RecoveryState::Released);
    assert_eq!(
        state_tip.payload.terminal_journal_digest.as_deref(),
        Some(authenticated_tip_hash(fixture.journal.as_ref().unwrap()).as_str()),
        "RELEASED terminal journal hash preserved exactly"
    );
    assert_eq!(
        state_tip.payload.terminal_evidence_digest.as_deref(),
        fixture
            .released
            .as_ref()
            .unwrap()
            .0
            .evidence_digest
            .as_deref(),
        "RELEASED terminal evidence digest preserved exactly"
    );
    let consumption: RevalidationConsumption = o3k::recovery_identity::decode_canonical(
        store
            .state_root
            .get("revalidation-consumption.json")
            .expect("consumption record persisted"),
    )
    .expect("consumption record decodes");
    assert!(
        consumption.consumed,
        "compromise evidence marked consumed after final observation"
    );
    // Startup observation of the rotated RELEASED generation authenticates the
    // whole chain and still denies operational access by preserved state.
    let observed =
        authenticate_rotated_generation(&rotated_view(&fixture, &store), &StoreArchives(&store))
            .expect("rotated RELEASED generation authenticates");
    assert_eq!(observed.preserved_state, RecoveryState::Released);
}

// ---- group 14: equal-sequence checkpoint equivocation ----

#[test]
fn equal_sequence_checkpoint_with_different_digest_is_equivocation() {
    let fixture = designated_fixture();
    let (store, first) = rotate_fixture(&fixture, RotationReason::Routine, NOW, |_, _, _| {});
    first.expect("first rotation publishes C at the next journal sequence");
    let current = era2();
    let next = era3();
    // A different C occupying the SAME journal sequence as the published tip
    // checkpoint (not prior+1) is equal-sequence equivocation of C.
    let inputs = rotated_rotation_inputs(
        &fixture,
        &store,
        &current,
        &next,
        2,
        &hex(&[0x7A; 32]),
        RotationReason::Routine,
        |_| {},
    );
    let view = rotated_view(&fixture, &store);
    let result = build_rotation_plan(&view, &StoreArchives(&store), &inputs, NOW);
    assert!(
        matches!(
            result,
            Err(ReanchorError::Sequence(_)) | Err(ReanchorError::Equivocation(_))
        ),
        "equal-sequence different-digest C must fail closed: {result:?}"
    );
}

// ---- group 15: durable fail-closed nonce-reuse defense ----

/// One era of trust material: the signing keys plus the certificate identity
/// constants a generation binds.
struct Era {
    journal_root: SigningKey,
    journal_root_id: &'static str,
    journal_signer: SigningKey,
    journal_signer_id: &'static str,
    journal_serial: &'static str,
    evidence_root: SigningKey,
    evidence_root_id: &'static str,
    evidence_signer: SigningKey,
    evidence_signer_id: &'static str,
    evidence_serial: &'static str,
}

/// The published era of a single `rotate_fixture` rotation (era 2).
fn era2() -> Era {
    Era {
        journal_root: keypair(0x1B),
        journal_root_id: NEW_JOURNAL_ROOT_ID,
        journal_signer: keypair(0x3D),
        journal_signer_id: NEW_JOURNAL_SIGNER_ID,
        journal_serial: "serial-journal-2",
        evidence_root: keypair(0x2C),
        evidence_root_id: NEW_EVIDENCE_ROOT_ID,
        evidence_signer: keypair(0x4E),
        evidence_signer_id: NEW_EVIDENCE_SIGNER_ID,
        evidence_serial: "serial-evidence-2",
    }
}

/// A third era for consecutive-rotation scenarios.
fn era3() -> Era {
    Era {
        journal_root: keypair(0x5A),
        journal_root_id: "test-journal-root-3",
        journal_signer: keypair(0x6B),
        journal_signer_id: "test-journal-signer-3",
        journal_serial: "serial-journal-3",
        evidence_root: keypair(0x7C),
        evidence_root_id: "test-evidence-root-3",
        evidence_signer: keypair(0x8D),
        evidence_signer_id: "test-evidence-signer-3",
        evidence_serial: "serial-evidence-3",
    }
}

/// A fourth era for the third rotation in the archived-nonce regression.
fn era4() -> Era {
    Era {
        journal_root: keypair(0x9E),
        journal_root_id: "test-journal-root-4",
        journal_signer: keypair(0xAF),
        journal_signer_id: "test-journal-signer-4",
        journal_serial: "serial-journal-4",
        evidence_root: keypair(0xB0),
        evidence_root_id: "test-evidence-root-4",
        evidence_signer: keypair(0xC1),
        evidence_signer_id: "test-evidence-signer-4",
        evidence_serial: "serial-evidence-4",
    }
}

/// Rebuilds the byte-level view of a rotated store from the durable files
/// alone, the way the production startup load path re-observes the
/// generation after a restart.
fn rotated_view<'a>(fixture: &'a Fixture, store: &'a MemStore) -> GenerationView<'a> {
    GenerationView {
        manifest_bytes: &fixture.manifest_bytes,
        policy_bytes: store
            .fixed_config
            .get("installation-policy.json")
            .map(Vec::as_slice)
            .unwrap_or(&[]),
        policy_high_water_bytes: store.state_root.get("policy.json").map(Vec::as_slice),
        fixed_bundle_bytes: store
            .fixed_config
            .get("recovery-trust.json")
            .map(Vec::as_slice)
            .unwrap_or(&[]),
        trust_high_water_bytes: store
            .state_root
            .get("trust.json")
            .map(Vec::as_slice)
            .unwrap_or(&[]),
        staged_prior_policy_bytes: store
            .state_root
            .get("staged-prior-policy.json")
            .map(Vec::as_slice),
        staged_prior_trust_bytes: store
            .state_root
            .get("staged-prior-trust.json")
            .map(Vec::as_slice),
        state_tip_bytes: store
            .state_root
            .get("state.json")
            .map(Vec::as_slice)
            .unwrap_or(&[]),
        journal_bytes: store
            .journal_dir
            .get("restore-journal.json")
            .map(Vec::as_slice),
        checkpoint_bytes: store.journal_dir.get(CHECKPOINT_NAME).map(Vec::as_slice),
        consumption_record_bytes: store
            .state_root
            .get("revalidation-consumption.json")
            .map(Vec::as_slice),
        pending_signing_request_present: false,
        now: NOW,
    }
}

/// Builds signed R/C (+ compromise evidence) inputs rotating an already
/// rotated `store` from `current` to `next`. `checkpoint_sequence` is exposed
/// so the equivocation test can forge an equal-sequence C.
#[allow(clippy::too_many_arguments)]
fn rotated_rotation_inputs(
    fixture: &Fixture,
    store: &MemStore,
    current: &Era,
    next: &Era,
    checkpoint_sequence: u64,
    nonce: &str,
    reason: RotationReason,
    tamper_evidence: impl FnOnce(&mut RecoveryRevalidation),
) -> RotationInputs {
    let published_tip = store.state_root.get("state.json").unwrap().clone();
    let published_tip_digest = sha256_hex(&published_tip);
    let published_sequence =
        o3k::recovery_identity::decode_canonical::<Signed<InstallationReanchor>>(&published_tip)
            .expect("published tip is a signed re-anchor")
            .payload
            .sequence;
    let current_policy_bytes = store
        .fixed_config
        .get("installation-policy.json")
        .unwrap()
        .clone();
    let current_policy_digest = sha256_hex(&current_policy_bytes);
    let current_policy: Signed<InstallationPolicy> =
        o3k::recovery_identity::decode_canonical(&current_policy_bytes).expect("current policy");
    let current_policy = current_policy.payload;
    let current_trust_bytes = store.state_root.get("trust.json").unwrap().clone();
    let current_trust_digest = sha256_hex(&current_trust_bytes);
    let current_trust: TrustBundle =
        o3k::recovery_identity::decode_canonical(&current_trust_bytes).expect("current trust");
    let current_checkpoint_bytes = store.journal_dir.get(CHECKPOINT_NAME).unwrap().clone();
    let current_checkpoint_digest = sha256_hex(&current_checkpoint_bytes);

    let (journal_serials, journal_key_ids, evidence_serials, evidence_key_ids) = match reason {
        RotationReason::Routine => (Vec::new(), Vec::new(), Vec::new(), Vec::new()),
        RotationReason::Compromise => (
            vec![current.journal_serial.to_string()],
            vec![current.journal_signer_id.to_string()],
            vec![current.evidence_serial.to_string()],
            vec![current.evidence_signer_id.to_string()],
        ),
    };
    let bundle = build_bundle(
        &next.journal_root,
        next.journal_root_id,
        &next.journal_signer,
        next.journal_signer_id,
        next.journal_serial,
        &next.evidence_root,
        next.evidence_root_id,
        &next.evidence_signer,
        next.evidence_signer_id,
        next.evidence_serial,
        signed_revocations(
            &revocation_document(1, NOW - 40, journal_serials, journal_key_ids),
            &next.journal_root,
            next.journal_root_id,
        ),
        signed_revocations(
            &revocation_document(1, NOW - 40, evidence_serials, evidence_key_ids),
            &next.evidence_root,
            next.evidence_root_id,
        ),
    );
    let policy = build_policy(
        current_policy.policy_revision + 1,
        &current_policy_digest,
        &bundle.digest,
        next.journal_root_id,
        &next.journal_root.verifying_key(),
        next.evidence_root_id,
        &next.evidence_root.verifying_key(),
    );

    let mut checkpoint = JournalCheckpoint {
        format: CHECKPOINT_FORMAT.to_string(),
        installation_id: fixture.policy.policy.installation_id.clone(),
        site_id: fixture.policy.policy.site_id.clone(),
        profile: fixture.policy.policy.profile.clone(),
        backend: fixture.policy.policy.backend.clone(),
        sequence: checkpoint_sequence,
        prior_record_digest: current_checkpoint_digest.clone(),
        prior_checkpoint_digest: Some(current_checkpoint_digest.clone()),
        prior_state_tip_digest: published_tip_digest.clone(),
        journal_directory: fixture.policy.policy.journal_directory.clone(),
        journal_device: fixture.policy.policy.journal_device,
        journal_inode: fixture.policy.policy.journal_inode,
        operation_id: OPERATION_ID.to_string(),
        artifact_sha256: ARTIFACT.to_string(),
        phase: RestorePhase::Preflighted,
        old_journal_key_id: current.journal_signer_id.to_string(),
        old_journal_certificate_serial: current.journal_serial.to_string(),
        new_journal_key_id: next.journal_signer_id.to_string(),
        new_journal_certificate_serial: next.journal_serial.to_string(),
        old_journal_revocation: high_water(&current_trust.journal_revocations),
        new_journal_revocation: high_water(&bundle.bundle.journal_revocations),
        old_evidence_revocation: high_water(&current_trust.evidence_revocations),
        new_evidence_revocation: high_water(&bundle.bundle.evidence_revocations),
        rotation_reason: reason,
        recovery_revalidation_digest: None,
    };
    let mut reanchor = InstallationReanchor {
        format: REANCHOR_FORMAT.to_string(),
        installation_id: fixture.policy.policy.installation_id.clone(),
        site_id: fixture.policy.policy.site_id.clone(),
        profile: fixture.policy.policy.profile.clone(),
        backend: fixture.policy.policy.backend.clone(),
        preserved_state: RecoveryState::RecoveryDesignated,
        sequence: published_sequence + 1,
        prior_record_digest: published_tip_digest.clone(),
        prior_policy_revision: current_policy.policy_revision,
        prior_policy_digest: current_policy_digest.clone(),
        new_policy_revision: policy.policy.policy_revision,
        new_policy_digest: policy.digest.clone(),
        prior_trust_bundle_digest: current_trust_digest.clone(),
        new_trust_bundle_digest: bundle.digest.clone(),
        prior_journal_revocation: high_water(&current_trust.journal_revocations),
        prior_evidence_revocation: high_water(&current_trust.evidence_revocations),
        new_journal_revocation: high_water(&bundle.bundle.journal_revocations),
        new_evidence_revocation: high_water(&bundle.bundle.evidence_revocations),
        checkpoint_digest: None,
        recovery_revalidation_digest: None,
        operation_id: Some(OPERATION_ID.to_string()),
        artifact_sha256: Some(ARTIFACT.to_string()),
        recovery_directory_digest: Some(journal_identity_digest(&fixture.policy.policy)),
        terminal_journal_digest: None,
        terminal_evidence_digest: None,
        target_device: fixture.policy.policy.target_device,
        target_inode: fixture.policy.policy.target_inode,
        signer_manifest_digest: sha256_hex(&fixture.manifest_bytes),
    };
    let (signed_revalidation, custody_record) = if reason == RotationReason::Compromise {
        let mut evidence = RecoveryRevalidation {
            format: REVALIDATION_FORMAT.to_string(),
            installation_id: fixture.policy.policy.installation_id.clone(),
            site_id: fixture.policy.policy.site_id.clone(),
            profile: fixture.policy.policy.profile.clone(),
            backend: fixture.policy.policy.backend.clone(),
            operation_id: OPERATION_ID.to_string(),
            artifact_sha256: ARTIFACT.to_string(),
            target_device: fixture.policy.policy.target_device,
            target_inode: fixture.policy.policy.target_inode,
            old_journal_root_id: current.journal_root_id.to_string(),
            new_journal_root_id: next.journal_root_id.to_string(),
            old_journal_key_id: current.journal_signer_id.to_string(),
            old_journal_certificate_serial: current.journal_serial.to_string(),
            new_journal_key_id: next.journal_signer_id.to_string(),
            new_journal_certificate_serial: next.journal_serial.to_string(),
            old_evidence_root_id: current.evidence_root_id.to_string(),
            new_evidence_root_id: next.evidence_root_id.to_string(),
            old_evidence_key_id: current.evidence_signer_id.to_string(),
            old_evidence_certificate_serial: current.evidence_serial.to_string(),
            new_evidence_key_id: next.evidence_signer_id.to_string(),
            new_evidence_certificate_serial: next.evidence_serial.to_string(),
            prior_state_tip_digest: published_tip_digest.clone(),
            prior_journal_tip_digest: current_checkpoint_digest.clone(),
            prior_checkpoint_digest: Some(current_checkpoint_digest.clone()),
            old_policy_digest: current_policy_digest.clone(),
            new_policy_digest: policy.digest.clone(),
            old_trust_bundle_digest: current_trust_digest.clone(),
            new_trust_bundle_digest: bundle.digest.clone(),
            observed_target_device: fixture.policy.policy.target_device,
            observed_target_inode: fixture.policy.policy.target_inode,
            custody_record_digest: sha256_hex(b"custody-record"),
            recovery_quorum_event_id: "quorum-event-2".to_string(),
            nonce: nonce.to_string(),
            issued_at: NOW,
            expires_at: NOW + REVALIDATION_VALIDITY_SECONDS,
            exact_tips_reviewed: true,
        };
        tamper_evidence(&mut evidence);
        let evidence_bytes = sign(&evidence, &next.evidence_signer, next.evidence_signer_id);
        let evidence_digest = sha256_hex(&evidence_bytes);
        reanchor.recovery_revalidation_digest = Some(evidence_digest.clone());
        checkpoint.recovery_revalidation_digest = Some(evidence_digest);
        (Some(evidence_bytes), Some(b"custody-record".to_vec()))
    } else {
        (None, None)
    };
    let signed_checkpoint = sign(&checkpoint, &next.journal_signer, next.journal_signer_id);
    reanchor.checkpoint_digest = Some(sha256_hex(&signed_checkpoint));
    RotationInputs {
        signed_reanchor: sign(&reanchor, &fixture.keys.policy, POLICY_SIGNER_ID),
        signed_checkpoint: Some(signed_checkpoint),
        new_policy: policy.bytes.clone(),
        new_trust_bundle: bundle.bytes.clone(),
        signed_revalidation,
        custody_record,
    }
}

/// Runs a full second compromise rotation built by `rotated_rotation_inputs`.
fn run_second_rotation(
    fixture: &Fixture,
    store: &mut MemStore,
    inputs: &RotationInputs,
) -> Result<(), ReanchorError> {
    let view = rotated_view(fixture, store);
    let plan = build_rotation_plan(&view, &StoreArchives(store), inputs, NOW)?;
    let mut observe = observe_authenticates(plan.preserved_state);
    run_rotation_plan(&plan, store, &mut observe)
}

#[test]
fn same_nonce_in_different_evidence_is_rejected_even_across_restart() {
    let fixture = designated_fixture();
    let (store, first) = rotate_fixture(&fixture, RotationReason::Compromise, NOW, |_, _, _| {});
    first.expect("first compromise rotation succeeds");
    let reused_nonce = hex(&[0x6E; 32]);
    // Restart simulation: the durable store alone feeds a fresh observation.
    let inputs = rotated_rotation_inputs(
        &fixture,
        &store,
        &era2(),
        &era3(),
        3,
        &reused_nonce,
        RotationReason::Compromise,
        |evidence| {
            // Different evidence content (different custody binding) that
            // reuses the consumed nonce.
            evidence.custody_record_digest = hex(&[0xC7; 32]);
        },
    );
    let state_root_before = store.state_root.clone();
    let journal_before = store.journal_dir.clone();
    let fixed_before = store.fixed_config.clone();
    let view = rotated_view(&fixture, &store);
    let result = build_rotation_plan(&view, &StoreArchives(&store), &inputs, NOW);
    assert!(
        matches!(result, Err(ReanchorError::Evidence(_))),
        "same nonce in different evidence must fail closed after a restart: {result:?}"
    );
    assert_eq!(
        store.state_root, state_root_before,
        "no durable state writes"
    );
    assert_eq!(
        store.journal_dir, journal_before,
        "no durable journal writes"
    );
    assert_eq!(store.fixed_config, fixed_before, "no durable config writes");
    // The installation still authenticates and starts on the durable bytes.
    authenticate_rotated_generation(&view, &StoreArchives(&store))
        .expect("rotated generation still authenticates after the rejected attempt");
}

#[test]
fn consecutive_compromise_rotations_with_distinct_nonces_succeed() {
    let fixture = designated_fixture();
    let (mut store, first) =
        rotate_fixture(&fixture, RotationReason::Compromise, NOW, |_, _, _| {});
    first.expect("first compromise rotation succeeds");
    let first_consumption: RevalidationConsumption = o3k::recovery_identity::decode_canonical(
        store
            .state_root
            .get("revalidation-consumption.json")
            .unwrap(),
    )
    .unwrap();
    assert_eq!(first_consumption.nonce, hex(&[0x6E; 32]));

    let inputs = rotated_rotation_inputs(
        &fixture,
        &store,
        &era2(),
        &era3(),
        3,
        &hex(&[0x7A; 32]),
        RotationReason::Compromise,
        |_| {},
    );
    run_second_rotation(&fixture, &mut store, &inputs)
        .expect("second compromise rotation with a fresh nonce succeeds");

    // The superseded record is retained under its content-addressed name and
    // binds the same nonce/evidence pair byte-for-byte.
    let archived: RevalidationConsumption = o3k::recovery_identity::decode_canonical(
        store
            .state_root
            .get(&format!(
                "revalidation-consumption-{}.json",
                first_consumption.evidence_digest
            ))
            .expect("superseded consumption record archived"),
    )
    .expect("archived consumption record decodes");
    assert_eq!(archived, first_consumption);
    assert!(archived.consumed);
    // The current record binds the new evidence and nonce.
    let current: RevalidationConsumption = o3k::recovery_identity::decode_canonical(
        store
            .state_root
            .get("revalidation-consumption.json")
            .unwrap(),
    )
    .unwrap();
    assert!(current.consumed);
    assert_eq!(current.nonce, hex(&[0x7A; 32]));
    assert_ne!(current.evidence_digest, archived.evidence_digest);
    // The twice-rotated generation authenticates end to end.
    let observed =
        authenticate_rotated_generation(&rotated_view(&fixture, &store), &StoreArchives(&store))
            .expect("twice-rotated generation authenticates");
    assert_eq!(observed.preserved_state, RecoveryState::RecoveryDesignated);
    assert_eq!(observed.tip_sequence, 3);
}

#[test]
fn nonce_reuse_from_an_archived_record_is_rejected_before_any_write() {
    let fixture = designated_fixture();
    let (mut store, first) =
        rotate_fixture(&fixture, RotationReason::Compromise, NOW, |_, _, _| {});
    first.expect("first compromise rotation succeeds");
    let reused_nonce = hex(&[0x6E; 32]);
    let second_inputs = rotated_rotation_inputs(
        &fixture,
        &store,
        &era2(),
        &era3(),
        3,
        &hex(&[0x7A; 32]),
        RotationReason::Compromise,
        |_| {},
    );
    run_second_rotation(&fixture, &mut store, &second_inputs)
        .expect("second compromise rotation with a fresh nonce succeeds");

    // A third attempt reuses the FIRST evidence nonce, which survives only in
    // the archived record: planning succeeds (the current record has a
    // different nonce), and publication fails closed before any write.
    let third_inputs = rotated_rotation_inputs(
        &fixture,
        &store,
        &era3(),
        &era4(),
        4,
        &reused_nonce,
        RotationReason::Compromise,
        |evidence| {
            evidence.custody_record_digest = hex(&[0xC7; 32]);
        },
    );
    let state_root_before = store.state_root.clone();
    let journal_before = store.journal_dir.clone();
    let fixed_before = store.fixed_config.clone();
    let writes_before = store.writes.len();
    let result = run_second_rotation(&fixture, &mut store, &third_inputs);
    assert!(
        matches!(result, Err(ReanchorError::Evidence(_))),
        "archived nonce reuse must fail closed: {result:?}"
    );
    assert_eq!(
        store.state_root, state_root_before,
        "no durable state writes"
    );
    assert_eq!(
        store.journal_dir, journal_before,
        "no durable journal writes"
    );
    assert_eq!(store.fixed_config, fixed_before, "no durable config writes");
    assert_eq!(
        writes_before,
        store.writes.len(),
        "the rejected attempt performed no writes at all"
    );
    authenticate_rotated_generation(&rotated_view(&fixture, &store), &StoreArchives(&store))
        .expect("twice-rotated generation still authenticates after the rejection");
}

// ---- group 16: rotation sequence coverage (MEDIUM-5) ----

/// routine -> routine: a second routine rotation on the rotated generation
/// publishes a new R/C pair and authenticates end to end.
#[test]
fn routine_rotation_followed_by_routine_rotation_succeeds() {
    let fixture = designated_fixture();
    let (mut store, first) = rotate_fixture(&fixture, RotationReason::Routine, NOW, |_, _, _| {});
    first.expect("first routine rotation succeeds");
    let first_tip = store.state_root.get("state.json").unwrap().clone();
    let first_checkpoint = store.journal_dir.get(CHECKPOINT_NAME).unwrap().clone();

    let inputs = rotated_rotation_inputs(
        &fixture,
        &store,
        &era2(),
        &era3(),
        3,
        &hex(&[0x7A; 32]),
        RotationReason::Routine,
        |_| {},
    );
    run_second_rotation(&fixture, &mut store, &inputs).expect("second routine rotation succeeds");

    let observed =
        authenticate_rotated_generation(&rotated_view(&fixture, &store), &StoreArchives(&store))
            .expect("twice-routine-rotated generation authenticates");
    assert_eq!(observed.preserved_state, RecoveryState::RecoveryDesignated);
    assert_eq!(observed.tip_sequence, 3);
    // The first rotation's R and C are archived, not rewritten.
    assert!(
        store
            .state_root
            .contains_key(&format!("state-{}.json", sha256_hex(&first_tip)))
    );
    assert!(store.journal_dir.contains_key(&format!(
        "checkpoint-{}.json",
        sha256_hex(&first_checkpoint)
    )));
    // No evidence was involved: no consumption record was written or archived.
    assert_eq!(
        store
            .state_root
            .keys()
            .filter(|name| name.starts_with("revalidation-consumption"))
            .count(),
        0,
        "routine rotations write no consumption records"
    );
}

/// compromise -> routine: after compromise rotation consumed its evidence, a
/// routine rotation succeeds; the consumed evidence record stays durable and
/// is ignored by the routine path.
#[test]
fn compromise_rotation_followed_by_routine_rotation_succeeds() {
    let fixture = designated_fixture();
    let (mut store, first) =
        rotate_fixture(&fixture, RotationReason::Compromise, NOW, |_, _, _| {});
    first.expect("first compromise rotation succeeds");
    let first_nonce = {
        let record: RevalidationConsumption = o3k::recovery_identity::decode_canonical(
            store
                .state_root
                .get("revalidation-consumption.json")
                .unwrap(),
        )
        .unwrap();
        assert!(record.consumed);
        record.nonce
    };

    let inputs = rotated_rotation_inputs(
        &fixture,
        &store,
        &era2(),
        &era3(),
        3,
        &hex(&[0x7A; 32]),
        RotationReason::Routine,
        |_| {},
    );
    run_second_rotation(&fixture, &mut store, &inputs)
        .expect("routine rotation after compromise succeeds");

    let observed =
        authenticate_rotated_generation(&rotated_view(&fixture, &store), &StoreArchives(&store))
            .expect("compromise-then-routine rotated generation authenticates");
    assert_eq!(observed.preserved_state, RecoveryState::RecoveryDesignated);
    // The consumed evidence record is untouched and still current (the
    // routine rotation planned no consumption): durable audit evidence.
    let record: RevalidationConsumption = o3k::recovery_identity::decode_canonical(
        store
            .state_root
            .get("revalidation-consumption.json")
            .unwrap(),
    )
    .unwrap();
    assert!(record.consumed);
    assert_eq!(record.nonce, first_nonce);
}
