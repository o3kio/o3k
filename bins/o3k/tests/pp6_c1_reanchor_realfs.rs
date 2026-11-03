//! C1.1 authenticated rotation evidence over the real protected installer
//! directories (SPEC-0050 §7.3, ADR-0189 C1.1).
//!
//! Unlike the byte-level `pp6_c1_reanchor` suite (in-memory store), these
//! fixtures drive the production rotation driver `rotate()` — including the
//! descriptor-anchored `ProtectedRotationStore` — over a real ext4 filesystem
//! inside a private mount namespace, through the same hidden `o3k`
//! subcommands the installer uses. The journeys prove, on real files:
//!
//! - the startup load path observes and authenticates the rotated generation
//!   (and still denies operational access: rotation grants no activation);
//! - an interrupted rotation resumes exact-forward from the signed R/C only
//!   at every one of the ordered engine's publication boundaries;
//! - a byte-identical replay performs no writes;
//! - unsigned journal markers and foreign files are preserved byte-for-byte;
//! - the data root is never opened (no canonical store file appears);
//! - the service user is denied rotation with no durable side effects;
//! - rotate -> designate -> startup observation works with the real
//!   `recovery-designate` CLI, including designation after an R-only
//!   rotation (base disposition at sequence >= 2);
//! - mixed-generation state fails closed at startup.
//!
//! The fixture is deliberately isolated in a private mount namespace and is
//! not an installed-release, production, or independent-security
//! qualification claim. Test-only Ed25519 keys stand in for the offline
//! ceremony keys.
#![allow(clippy::expect_used, clippy::unwrap_used, clippy::panic)]

use std::{
    collections::BTreeMap,
    fs,
    os::unix::fs::{MetadataExt, PermissionsExt},
    path::{Path, PathBuf},
    process::{Command, ExitStatus},
};

use ed25519_dalek::{Signer, SigningKey, VerifyingKey};
use o3k::recovery_identity::{
    InstallationPolicy, InstallationState, RecoveryState, RevocationDocument, SignatureEnvelope,
    Signed, TrustBundle, TrustCertificate,
};
use o3k::recovery_reanchor::{
    CHECKPOINT_FORMAT, CHECKPOINT_NAME, InstallationReanchor, JournalCheckpoint, REANCHOR_FORMAT,
    REVALIDATION_FORMAT, REVALIDATION_VALIDITY_SECONDS, RevalidationConsumption, RotationReason,
};
use o3k::restore_journal::RestorePhase;
use sha2::Digest;

const POLICY_SIGNER_ID: &str = "test-policy-signer-1";
const OPERATION_ID: &str = "018f22c3-8f7b-7c1e-9a44-0db71e5a2c01";
const POST_ROTATION_OPERATION_ID: &str = "2a8535e6-c142-4a4b-a2e8-9b6e2f6a3b77";
const ARTIFACT: &str = "4d5a6b7c8e9f0a1b2c3d4e5f6a7b8c9d0e1f2a3b4c5d6e7f8a9b0c1d2e3f4a5b";
const RELEASE_SHA256: &str = "1111111111111111111111111111111111111111111111111111111111111111";
const SOURCE_COMMIT: &str = "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa";
const INSTALLER_SHA256: &str = "0000000000000000000000000000000000000000000000000000000000000000";
const DENIAL: &str = "authenticated recovery designation denies operational access";
const DENIED_PREFIX: &str = "canonical store access denied";
const MARKER_BYTES: &[u8] = b"unsigned marker bytes preserved across rotation";
const FOREIGN_BYTES: &[u8] = b"foreign operator note, never adopted by rotation";

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

fn decode_signed<T: serde::de::DeserializeOwned + serde::Serialize>(bytes: &[u8]) -> T {
    o3k::recovery_identity::decode_canonical(bytes).expect("canonical document")
}

// ---- fixture keys and eras ----

#[derive(Debug, Clone)]
struct Keys {
    policy: SigningKey,
}

impl Keys {
    fn test_only() -> Self {
        Self {
            policy: keypair(0xA1),
        }
    }
}

/// One era of trust material. Era 1 is the installed generation, era 2 the
/// first rotation target, and so on; the crash-matrix eras derive
/// deterministically from the rotation index so twenty consecutive rotations
/// each get distinct roots, signers, and serials.
#[derive(Debug, Clone)]
struct Era {
    index: u32,
    journal_root: SigningKey,
    journal_root_id: String,
    journal_signer: SigningKey,
    journal_signer_id: String,
    journal_serial: String,
    evidence_root: SigningKey,
    evidence_root_id: String,
    evidence_signer: SigningKey,
    evidence_signer_id: String,
    evidence_serial: String,
}

fn era(index: u32) -> Era {
    let seed = |base: u8| base.wrapping_add((index as u8).wrapping_mul(16));
    Era {
        index,
        journal_root: keypair(seed(0xB2)),
        journal_root_id: format!("test-journal-root-{index}"),
        journal_signer: keypair(seed(0xD4)),
        journal_signer_id: format!("test-journal-signer-{index}"),
        journal_serial: format!("serial-journal-{index}"),
        evidence_root: keypair(seed(0xC3)),
        evidence_root_id: format!("test-evidence-root-{index}"),
        evidence_signer: keypair(seed(0xE5)),
        evidence_signer_id: format!("test-evidence-signer-{index}"),
        evidence_serial: format!("serial-evidence-{index}"),
    }
}

// ---- fixture documents (bound to the real provisioned directories) ----

fn certificate(
    target: &Target,
    now: i64,
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
        site_id: target.site_id.clone(),
        installation_id: target.installation_id.clone(),
        profile: target.profile.clone(),
        backend: target.backend.clone(),
        serial: serial.to_string(),
        not_before: now - 3_600,
        not_after: now + 80 * 86_400,
        issuer: issuer.to_string(),
    }
}

fn revocation_document(
    target: &Target,
    sequence: u64,
    issued_at: i64,
    revoked_serials: Vec<String>,
    revoked_key_ids: Vec<String>,
) -> RevocationDocument {
    RevocationDocument {
        format: "o3k-recovery-revocations-v1".to_string(),
        site_id: target.site_id.clone(),
        profile: target.profile.clone(),
        sequence,
        issued_at,
        next_update: issued_at + 86_400,
        revoked_serials,
        revoked_key_ids,
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

fn high_water(doc: &Signed<RevocationDocument>) -> o3k::recovery_reanchor::RevocationHighWater {
    o3k::recovery_reanchor::RevocationHighWater {
        root_id: doc.envelope.signer_key_id.clone(),
        sequence: doc.payload.sequence,
        document_digest: o3k::recovery_identity::digest(doc).expect("digest"),
    }
}

#[derive(Debug, Clone)]
struct BundleFixture {
    bundle: TrustBundle,
    bytes: Vec<u8>,
    digest: String,
}

/// Builds the trust bundle for `owner`, revoking the previous era's signers
/// when `revoking` is `Some` (compromise rotation).
fn build_bundle(target: &Target, now: i64, owner: &Era, revoking: Option<&Era>) -> BundleFixture {
    let (journal_serials, journal_key_ids, evidence_serials, evidence_key_ids) = match revoking {
        None => (vec![], vec![], vec![], vec![]),
        Some(prior) => (
            vec![prior.journal_serial.clone()],
            vec![prior.journal_signer_id.clone()],
            vec![prior.evidence_serial.clone()],
            vec![prior.evidence_signer_id.clone()],
        ),
    };
    let journal_cert_payload = certificate(
        target,
        now,
        "restore_journal",
        &owner.journal_signer_id,
        &key_hex(&owner.journal_signer.verifying_key()),
        &owner.journal_root_id,
        &owner.journal_serial,
    );
    let evidence_cert_payload = certificate(
        target,
        now,
        "recovery_evidence",
        &owner.evidence_signer_id,
        &key_hex(&owner.evidence_signer.verifying_key()),
        &owner.evidence_root_id,
        &owner.evidence_serial,
    );
    let journal_certificate = Signed {
        payload: journal_cert_payload.clone(),
        envelope: SignatureEnvelope {
            algorithm: "Ed25519".to_string(),
            signer_key_id: owner.journal_root_id.clone(),
            signature: hex(&owner
                .journal_root
                .sign(&o3k::recovery_identity::canonical(&journal_cert_payload).expect("canonical"))
                .to_bytes()),
        },
    };
    let evidence_certificate = Signed {
        payload: evidence_cert_payload.clone(),
        envelope: SignatureEnvelope {
            algorithm: "Ed25519".to_string(),
            signer_key_id: owner.evidence_root_id.clone(),
            signature: hex(&owner
                .evidence_root
                .sign(
                    &o3k::recovery_identity::canonical(&evidence_cert_payload).expect("canonical"),
                )
                .to_bytes()),
        },
    };
    let journal_revocations = signed_revocations(
        &revocation_document(target, 1, now - 100, journal_serials, journal_key_ids),
        &owner.journal_root,
        &owner.journal_root_id,
    );
    let evidence_revocations = signed_revocations(
        &revocation_document(target, 1, now - 100, evidence_serials, evidence_key_ids),
        &owner.evidence_root,
        &owner.evidence_root_id,
    );
    let bundle = TrustBundle {
        format: "o3k-recovery-trust-v1".to_string(),
        site_id: target.site_id.clone(),
        profile: target.profile.clone(),
        installation_id: target.installation_id.clone(),
        backend: target.backend.clone(),
        journal_root_key_id: owner.journal_root_id.clone(),
        journal_root_public_key: key_hex(&owner.journal_root.verifying_key()),
        evidence_root_key_id: owner.evidence_root_id.clone(),
        evidence_root_public_key: key_hex(&owner.evidence_root.verifying_key()),
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
    BundleFixture {
        bundle,
        bytes,
        digest,
    }
}

#[derive(Clone)]
struct PolicyFixture {
    policy: InstallationPolicy,
    bytes: Vec<u8>,
    digest: String,
}

#[allow(clippy::too_many_arguments)]
fn build_policy(
    target: &Target,
    keys: &Keys,
    revision: u64,
    prior_policy_digest: &str,
    trust_bundle_digest: &str,
    owner: &Era,
) -> PolicyFixture {
    let policy = InstallationPolicy {
        format: "o3k-installation-policy-v1".to_string(),
        installation_id: target.installation_id.clone(),
        site_id: target.site_id.clone(),
        profile: target.profile.clone(),
        backend: target.backend.clone(),
        release_identity: target.release_artifact_digest.clone(),
        data_root: target.data_root.clone(),
        target_device: target.data_root_device,
        target_inode: target.data_root_inode,
        policy_revision: revision,
        prior_policy_digest: prior_policy_digest.to_string(),
        policy_path: "/etc/o3k/installation-policy.json".to_string(),
        trust_bundle_path: "/etc/o3k/recovery-trust.json".to_string(),
        trust_bundle_digest: trust_bundle_digest.to_string(),
        recovery_state_root: target.recovery_state_root.clone(),
        recovery_state_device: target.recovery_state_device,
        recovery_state_inode: target.recovery_state_inode,
        journal_directory: target.journal_directory.clone(),
        journal_device: target.journal_device,
        journal_inode: target.journal_inode,
        journal_trust_root_id: owner.journal_root_id.clone(),
        journal_trust_root_public_key: key_hex(&owner.journal_root.verifying_key()),
        evidence_trust_root_id: owner.evidence_root_id.clone(),
        evidence_trust_root_public_key: key_hex(&owner.evidence_root.verifying_key()),
        signer_key_id: POLICY_SIGNER_ID.to_string(),
    };
    let bytes = sign(&policy, &keys.policy, POLICY_SIGNER_ID);
    let digest = sha256_hex(&bytes);
    PolicyFixture {
        policy,
        bytes,
        digest,
    }
}

fn journal_identity_digest(policy: &InstallationPolicy) -> String {
    o3k::recovery_identity::digest(&(
        policy.journal_directory.as_str(),
        policy.journal_device,
        policy.journal_inode,
    ))
    .expect("digest")
}

fn initial_state(policy: &PolicyFixture, keys: &Keys) -> (InstallationState, Vec<u8>, String) {
    let state = InstallationState {
        format: "o3k-installation-state-v1".to_string(),
        installation_id: policy.policy.installation_id.clone(),
        site_id: policy.policy.site_id.clone(),
        profile: policy.policy.profile.clone(),
        backend: policy.policy.backend.clone(),
        policy_revision: policy.policy.policy_revision,
        policy_digest: policy.digest.clone(),
        target_device: policy.policy.target_device,
        target_inode: policy.policy.target_inode,
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
    let bytes = sign(&state, &keys.policy, POLICY_SIGNER_ID);
    let digest = sha256_hex(&bytes);
    (state, bytes, digest)
}

fn designated_state(
    policy: &PolicyFixture,
    predecessor_digest: &str,
    sequence: u64,
    operation_id: &str,
    signer: &Era,
) -> (InstallationState, Vec<u8>, String) {
    let state = InstallationState {
        format: "o3k-installation-state-v1".to_string(),
        installation_id: policy.policy.installation_id.clone(),
        site_id: policy.policy.site_id.clone(),
        profile: policy.policy.profile.clone(),
        backend: policy.policy.backend.clone(),
        policy_revision: policy.policy.policy_revision,
        policy_digest: policy.digest.clone(),
        target_device: policy.policy.target_device,
        target_inode: policy.policy.target_inode,
        sequence,
        prior_record_digest: predecessor_digest.to_string(),
        state: RecoveryState::RecoveryDesignated,
        operation_id: Some(operation_id.to_string()),
        artifact_sha256: Some(ARTIFACT.to_string()),
        recovery_directory_digest: Some(journal_identity_digest(&policy.policy)),
        trust_bundle_digest: Some(policy.policy.trust_bundle_digest.clone()),
        terminal_journal_digest: None,
        evidence_digest: None,
    };
    let bytes = sign(&state, &signer.journal_signer, &signer.journal_signer_id);
    let digest = sha256_hex(&bytes);
    (state, bytes, digest)
}

/// One signed PREFLIGHTED journal-v1 chain under the given era signer.
fn journal_chain(
    target: &Target,
    policy_revision: u64,
    policy_digest: &str,
    signer: &Era,
    operation_id: &str,
) -> (Vec<u8>, String) {
    let request = serde_json::json!({
        "format": "o3k-restore-signing-request-v1",
        "request_id": "9f1d2c3b-1234-4abc-8def-0123456789ab",
        "request_nonce": hex(&[0x11; 32]),
        "operation_id": operation_id,
        "site_id": target.site_id,
        "artifact_sha256": ARTIFACT,
        "journal_authority_id": signer.journal_signer_id,
        "target_installation_id": target.installation_id,
        "target_device": target.data_root_device,
        "target_inode": target.data_root_inode,
        "target_database_identity": "o3k_fresh",
        "source_installation_id": "source-inst-1",
        "deterministic_step_id": hex(&[0x5E; 32]),
        "sequence": 1,
        "previous_signed_hash": "",
        "intended_transition": "PREFLIGHTED",
    });
    let request_bytes = serde_jcs::to_vec(&request).expect("canonical request");
    let request_hash = sha256_hex(&request_bytes);
    let signature = hex(&signer.journal_signer.sign(&request_bytes).to_bytes());
    let envelope = serde_json::json!({
        "format": "o3k-restore-journal-v1",
        "transitions": [{
            "format": "o3k-restore-journal-v1",
            "request": request,
            "response": {
                "format": "o3k-restore-signing-response-v1",
                "request_sha256": request_hash,
                "key_id": signer.journal_signer_id,
                "signature": signature,
            },
        }],
    });
    let bytes = serde_jcs::to_vec(&envelope).expect("canonical journal");
    let _ = (policy_revision, policy_digest);
    let digest = sha256_hex(&bytes);
    (bytes, digest)
}

fn authenticated_tip_hash(journal: &(Vec<u8>, String), signer: &Era) -> String {
    let authenticated = o3k::restore_journal::authenticate_chain(
        &journal.0,
        &signer.journal_signer_id,
        &signer.journal_signer.verifying_key(),
    )
    .unwrap_or_else(|error| panic!("fixture chain authenticates: {error:?}"));
    authenticated.signed_hash().to_string()
}

// ---- the provisioned target, bound from the prepare descriptor ----

#[derive(Debug, Clone)]
struct Target {
    installation_id: String,
    site_id: String,
    profile: String,
    backend: String,
    release_artifact_digest: String,
    data_root: String,
    data_root_device: u64,
    data_root_inode: u64,
    recovery_state_root: String,
    recovery_state_device: u64,
    recovery_state_inode: u64,
    journal_directory: String,
    journal_device: u64,
    journal_inode: u64,
}

/// Everything the document builders close over, exactly like the offline
/// signer closes over the provisioning descriptor.
struct Ctx {
    target: Target,
    keys: Keys,
    manifest_digest: String,
    now: i64,
}

struct ObservedTips {
    state_tip_digest: String,
    state_tip_sequence: u64,
    checkpoint: Option<(Vec<u8>, String, u64)>,
}

fn read_tips(ctx: &Ctx, var: &Path) -> ObservedTips {
    let state_root = var
        .join("o3k-recovery-state")
        .join(ctx.target.installation_id.clone());
    let journal_dir = var
        .join("o3k-recovery")
        .join(ctx.target.installation_id.clone());
    let state_tip = fs::read(state_root.join("state.json")).unwrap();
    let state_tip_digest = sha256_hex(&state_tip);
    let state_tip_sequence =
        decode_signed::<Signed<serde_json::Value>>(&state_tip).payload["sequence"]
            .as_u64()
            .expect("tip sequence");
    let checkpoint = fs::read(journal_dir.join(CHECKPOINT_NAME))
        .ok()
        .map(|bytes| {
            let digest = sha256_hex(&bytes);
            let sequence = decode_signed::<Signed<JournalCheckpoint>>(&bytes)
                .payload
                .sequence;
            (bytes, digest, sequence)
        });
    ObservedTips {
        state_tip_digest,
        state_tip_sequence,
        checkpoint,
    }
}

fn read_policy(var: &Path, installation_id: &str) -> PolicyFixture {
    let bytes = fs::read(
        var.join("o3k-recovery-state")
            .join(installation_id)
            .join("policy.json"),
    )
    .unwrap();
    let policy = decode_signed::<Signed<InstallationPolicy>>(&bytes).payload;
    let digest = sha256_hex(&bytes);
    PolicyFixture {
        policy,
        bytes,
        digest,
    }
}

fn read_bundle(var: &Path, installation_id: &str) -> BundleFixture {
    let bytes = fs::read(
        var.join("o3k-recovery-state")
            .join(installation_id)
            .join("trust.json"),
    )
    .unwrap();
    let bundle = decode_signed::<TrustBundle>(&bytes);
    let digest = sha256_hex(&bytes);
    BundleFixture {
        bundle,
        bytes,
        digest,
    }
}

/// The signed rotation inputs for one rotation, built from the durable files.
struct RotationDocs {
    reanchor: Vec<u8>,
    checkpoint: Option<Vec<u8>>,
    policy: Vec<u8>,
    trust: Vec<u8>,
    revalidation: Option<Vec<u8>>,
    custody: Option<Vec<u8>>,
    preserved: RecoveryState,
}

/// Builds signed R/C (+ compromise evidence) inputs rotating from era `from`
/// to era `to` on top of the durable generation observed at `tips`.
#[allow(clippy::too_many_arguments)]
fn rotation_docs(
    ctx: &Ctx,
    current_policy: &PolicyFixture,
    current_trust: &BundleFixture,
    from: &Era,
    to: &Era,
    tips: &ObservedTips,
    journal_tip_hash: &str,
    operation_id: &str,
    preserved: RecoveryState,
    reason: RotationReason,
    nonce: &str,
    custody_bytes: &[u8],
    evidence_tamper: impl FnOnce(&mut o3k::recovery_reanchor::RecoveryRevalidation),
) -> RotationDocs {
    let bundle = build_bundle(&ctx.target, ctx.now, to, Some(from));
    let policy = build_policy(
        &ctx.target,
        &ctx.keys,
        current_policy.policy.policy_revision + 1,
        &current_policy.digest,
        &bundle.digest,
        to,
    );
    let checkpoint_sequence = tips
        .checkpoint
        .as_ref()
        .map(|(_, _, sequence)| sequence + 1)
        .unwrap_or(2);
    let (prior_journal_tip, prior_checkpoint_digest) = match &tips.checkpoint {
        Some((_, digest, _)) => (digest.clone(), Some(digest.clone())),
        None => (journal_tip_hash.to_string(), None),
    };
    let mut checkpoint = JournalCheckpoint {
        format: CHECKPOINT_FORMAT.to_string(),
        installation_id: ctx.target.installation_id.clone(),
        site_id: ctx.target.site_id.clone(),
        profile: ctx.target.profile.clone(),
        backend: ctx.target.backend.clone(),
        sequence: checkpoint_sequence,
        prior_record_digest: prior_journal_tip,
        prior_checkpoint_digest,
        prior_state_tip_digest: tips.state_tip_digest.clone(),
        journal_directory: ctx.target.journal_directory.clone(),
        journal_device: ctx.target.journal_device,
        journal_inode: ctx.target.journal_inode,
        operation_id: operation_id.to_string(),
        artifact_sha256: ARTIFACT.to_string(),
        phase: RestorePhase::Preflighted,
        old_journal_key_id: from.journal_signer_id.clone(),
        old_journal_certificate_serial: from.journal_serial.clone(),
        new_journal_key_id: to.journal_signer_id.clone(),
        new_journal_certificate_serial: to.journal_serial.clone(),
        old_journal_revocation: high_water(&current_trust.bundle.journal_revocations),
        new_journal_revocation: high_water(&bundle.bundle.journal_revocations),
        old_evidence_revocation: high_water(&current_trust.bundle.evidence_revocations),
        new_evidence_revocation: high_water(&bundle.bundle.evidence_revocations),
        rotation_reason: reason,
        recovery_revalidation_digest: None,
    };
    let designated_bindings = preserved == RecoveryState::RecoveryDesignated;
    let mut reanchor = InstallationReanchor {
        format: REANCHOR_FORMAT.to_string(),
        installation_id: ctx.target.installation_id.clone(),
        site_id: ctx.target.site_id.clone(),
        profile: ctx.target.profile.clone(),
        backend: ctx.target.backend.clone(),
        preserved_state: preserved,
        sequence: tips.state_tip_sequence + 1,
        prior_record_digest: tips.state_tip_digest.clone(),
        prior_policy_revision: current_policy.policy.policy_revision,
        prior_policy_digest: current_policy.digest.clone(),
        new_policy_revision: policy.policy.policy_revision,
        new_policy_digest: policy.digest.clone(),
        prior_trust_bundle_digest: current_trust.digest.clone(),
        new_trust_bundle_digest: bundle.digest.clone(),
        prior_journal_revocation: high_water(&current_trust.bundle.journal_revocations),
        prior_evidence_revocation: high_water(&current_trust.bundle.evidence_revocations),
        new_journal_revocation: high_water(&bundle.bundle.journal_revocations),
        new_evidence_revocation: high_water(&bundle.bundle.evidence_revocations),
        checkpoint_digest: None,
        recovery_revalidation_digest: None,
        operation_id: designated_bindings.then(|| operation_id.to_string()),
        artifact_sha256: designated_bindings.then(|| ARTIFACT.to_string()),
        recovery_directory_digest: designated_bindings
            .then(|| journal_identity_digest(&current_policy.policy)),
        terminal_journal_digest: None,
        terminal_evidence_digest: None,
        target_device: ctx.target.data_root_device,
        target_inode: ctx.target.data_root_inode,
        signer_manifest_digest: ctx.manifest_digest.clone(),
    };
    let mut revalidation = None;
    let mut custody = None;
    if reason == RotationReason::Compromise {
        let evidence_now = chrono::Utc::now().timestamp();
        let mut evidence = o3k::recovery_reanchor::RecoveryRevalidation {
            format: REVALIDATION_FORMAT.to_string(),
            installation_id: ctx.target.installation_id.clone(),
            site_id: ctx.target.site_id.clone(),
            profile: ctx.target.profile.clone(),
            backend: ctx.target.backend.clone(),
            operation_id: operation_id.to_string(),
            artifact_sha256: ARTIFACT.to_string(),
            target_device: ctx.target.data_root_device,
            target_inode: ctx.target.data_root_inode,
            old_journal_root_id: from.journal_root_id.clone(),
            new_journal_root_id: to.journal_root_id.clone(),
            old_journal_key_id: from.journal_signer_id.clone(),
            old_journal_certificate_serial: from.journal_serial.clone(),
            new_journal_key_id: to.journal_signer_id.clone(),
            new_journal_certificate_serial: to.journal_serial.clone(),
            old_evidence_root_id: from.evidence_root_id.clone(),
            new_evidence_root_id: to.evidence_root_id.clone(),
            old_evidence_key_id: from.evidence_signer_id.clone(),
            old_evidence_certificate_serial: from.evidence_serial.clone(),
            new_evidence_key_id: to.evidence_signer_id.clone(),
            new_evidence_certificate_serial: to.evidence_serial.clone(),
            prior_state_tip_digest: tips.state_tip_digest.clone(),
            prior_journal_tip_digest: match &tips.checkpoint {
                Some((_, digest, _)) => digest.clone(),
                None => journal_tip_hash.to_string(),
            },
            prior_checkpoint_digest: tips
                .checkpoint
                .as_ref()
                .map(|(_, digest, _)| digest.clone()),
            old_policy_digest: current_policy.digest.clone(),
            new_policy_digest: policy.digest.clone(),
            old_trust_bundle_digest: current_trust.digest.clone(),
            new_trust_bundle_digest: bundle.digest.clone(),
            observed_target_device: ctx.target.data_root_device,
            observed_target_inode: ctx.target.data_root_inode,
            custody_record_digest: sha256_hex(custody_bytes),
            recovery_quorum_event_id: format!("quorum-event-{}", to.index),
            nonce: nonce.to_string(),
            issued_at: evidence_now,
            expires_at: evidence_now + REVALIDATION_VALIDITY_SECONDS,
            exact_tips_reviewed: true,
        };
        evidence_tamper(&mut evidence);
        let evidence_bytes = sign(&evidence, &to.evidence_signer, &to.evidence_signer_id);
        let evidence_digest = sha256_hex(&evidence_bytes);
        reanchor.recovery_revalidation_digest = Some(evidence_digest.clone());
        checkpoint.recovery_revalidation_digest = Some(evidence_digest);
        revalidation = Some(evidence_bytes);
        custody = Some(custody_bytes.to_vec());
    }
    let signed_checkpoint = sign(&checkpoint, &to.journal_signer, &to.journal_signer_id);
    reanchor.checkpoint_digest = Some(sha256_hex(&signed_checkpoint));
    RotationDocs {
        reanchor: sign(&reanchor, &ctx.keys.policy, POLICY_SIGNER_ID),
        checkpoint: Some(signed_checkpoint),
        policy: policy.bytes.clone(),
        trust: bundle.bytes.clone(),
        revalidation,
        custody,
        preserved,
    }
}

/// R-only rotation inputs for a `NEVER_RECOVERED` installation: no C, no
/// operation bindings.
fn r_only_rotation_docs(
    ctx: &Ctx,
    current_policy: &PolicyFixture,
    current_trust: &BundleFixture,
    _from: &Era,
    to: &Era,
    tips: &ObservedTips,
) -> RotationDocs {
    let bundle = build_bundle(&ctx.target, ctx.now, to, None);
    let policy = build_policy(
        &ctx.target,
        &ctx.keys,
        current_policy.policy.policy_revision + 1,
        &current_policy.digest,
        &bundle.digest,
        to,
    );
    let reanchor = InstallationReanchor {
        format: REANCHOR_FORMAT.to_string(),
        installation_id: ctx.target.installation_id.clone(),
        site_id: ctx.target.site_id.clone(),
        profile: ctx.target.profile.clone(),
        backend: ctx.target.backend.clone(),
        preserved_state: RecoveryState::NeverRecovered,
        sequence: tips.state_tip_sequence + 1,
        prior_record_digest: tips.state_tip_digest.clone(),
        prior_policy_revision: current_policy.policy.policy_revision,
        prior_policy_digest: current_policy.digest.clone(),
        new_policy_revision: policy.policy.policy_revision,
        new_policy_digest: policy.digest.clone(),
        prior_trust_bundle_digest: current_trust.digest.clone(),
        new_trust_bundle_digest: bundle.digest.clone(),
        prior_journal_revocation: high_water(&current_trust.bundle.journal_revocations),
        prior_evidence_revocation: high_water(&current_trust.bundle.evidence_revocations),
        new_journal_revocation: high_water(&bundle.bundle.journal_revocations),
        new_evidence_revocation: high_water(&bundle.bundle.evidence_revocations),
        checkpoint_digest: None,
        recovery_revalidation_digest: None,
        operation_id: None,
        artifact_sha256: None,
        recovery_directory_digest: None,
        terminal_journal_digest: None,
        terminal_evidence_digest: None,
        target_device: ctx.target.data_root_device,
        target_inode: ctx.target.data_root_inode,
        signer_manifest_digest: ctx.manifest_digest.clone(),
    };
    RotationDocs {
        reanchor: sign(&reanchor, &ctx.keys.policy, POLICY_SIGNER_ID),
        checkpoint: None,
        policy: policy.bytes.clone(),
        trust: bundle.bytes.clone(),
        revalidation: None,
        custody: None,
        preserved: RecoveryState::NeverRecovered,
    }
}

// ---- namespace harness ----

fn root_fixture() -> Result<PathBuf, String> {
    if rustix::process::geteuid().as_raw() != 0 {
        return Err(format!(
            "NOT_RUN: real protected-filesystem fixture requires root (effective uid is {})",
            rustix::process::geteuid().as_raw()
        ));
    }
    let fixture_parent = std::env::var_os("O3K_A10_FIXTURE_ROOT")
        .map(PathBuf::from)
        .unwrap_or_else(|| PathBuf::from("/var/lib"));
    let parent = fs::symlink_metadata(&fixture_parent).map_err(|error| {
        format!(
            "NOT_RUN: cannot inspect fixture parent {}: {error}",
            fixture_parent.display()
        )
    })?;
    if !parent.is_dir() || parent.uid() != 0 || parent.mode() & 0o022 != 0 {
        return Err(format!(
            "NOT_RUN: fixture parent {} is not a protected root-owned directory",
            fixture_parent.display()
        ));
    }
    let path = fixture_parent.join(format!("o3k-c1-reanchor-{}", uuid::Uuid::now_v7()));
    fs::create_dir(&path).map_err(|error| {
        format!(
            "NOT_RUN: cannot create root-owned fixture {}: {error}",
            path.display()
        )
    })?;
    fs::set_permissions(&path, fs::Permissions::from_mode(0o700)).map_err(|error| {
        let _ = fs::remove_dir_all(&path);
        format!(
            "NOT_RUN: cannot protect root fixture {} with mode 0700: {error}",
            path.display()
        )
    })?;
    Ok(path)
}

fn setup_fixture(ctx: &mut Ctx, fixture: &Path, designate: bool) -> Installation {
    setup_fixture_for_release(
        ctx,
        fixture,
        designate,
        "o3k-demo-v1",
        "sqlite",
        RELEASE_SHA256,
        None,
    )
}

fn setup_fixture_for_release(
    ctx: &mut Ctx,
    fixture: &Path,
    designate: bool,
    profile: &str,
    backend: &str,
    release_artifact_digest: &str,
    installed_manifest: Option<Vec<u8>>,
) -> Installation {
    let var = fixture.join("var");
    let etc = var.join("etc-fixture");
    let share = var.join("share-fixture");
    let bins = var.join("bin-fixture");
    let systemd = etc.join("systemd/system");
    let run = var.join("run-fixture");
    fs::create_dir_all(&etc).unwrap();
    fs::create_dir_all(&share).unwrap();
    fs::create_dir_all(&bins).unwrap();
    fs::create_dir_all(&systemd).unwrap();
    fs::create_dir_all(&run).unwrap();
    fs::set_permissions(&etc, fs::Permissions::from_mode(0o755)).unwrap();
    fs::set_permissions(&share, fs::Permissions::from_mode(0o755)).unwrap();
    let data = var.join("o3k");
    fs::create_dir(&data).unwrap();
    // The packaged libvirt posture: o3k:o3k-compute 0711. The visible lock
    // file models a host whose store owner already ran; doctor's read-only
    // acquisition requires it.
    fs::set_permissions(&data, fs::Permissions::from_mode(0o711)).unwrap();
    std::os::unix::fs::chown(&data, Some(900), Some(901)).unwrap();
    write_root_owned(&data.join(".o3k-store.lock"), b"", 900, 900, 0o600);
    fs::write(
        etc.join("passwd"),
        b"root:x:0:0:root:/root:/bin/sh\no3k:x:900:900::/var/lib/o3k:/usr/sbin/nologin\no3k-compute:x:901:901::/var/lib/o3k/compute:/usr/sbin/nologin\n",
    )
    .unwrap();
    fs::write(
        etc.join("group"),
        b"root:x:0:\no3k:x:900:\no3k-compute:x:901:\nkvm:x:108:\n",
    )
    .unwrap();
    let manifest = installed_manifest.unwrap_or_else(|| {
        format!(
            r#"{{"version":"v0.4.0-rc.5","profile":"test","profile_id":"{profile}","source_commit":"{SOURCE_COMMIT}","workflow":"test","installer_sha256":"{INSTALLER_SHA256}","release_artifact_sha256":"{release_artifact_digest}","schema_version":"1","installation_policy_format":"o3k-installation-policy-v1","installation_policy_path":"/etc/o3k/installation-policy.json","installation_policy_authority":{{"key_id":"{POLICY_SIGNER_ID}","ed25519_public_key":"{}"}}}}"#,
            key_hex(&ctx.keys.policy.verifying_key())
        )
        .into_bytes()
    });
    fs::write(share.join("release-manifest.json"), &manifest).unwrap();
    fs::set_permissions(
        share.join("release-manifest.json"),
        fs::Permissions::from_mode(0o644),
    )
    .unwrap();
    let prepare = format!(
        "{{binary}} recovery-provision-prepare --data-root /var/lib/o3k --backend {backend}"
    );
    let (stdout, stderr, status) = run_in_namespace(fixture, &prepare, &[]);
    assert!(stderr.contains("C1_REANCHOR_NAMESPACE_READY"));
    assert!(status.success(), "prepare failed: {stderr}");
    let value = descriptor(&stdout);
    ctx.target = Target {
        installation_id: value["installation_id"].as_str().unwrap().to_string(),
        site_id: value["site_id"].as_str().unwrap().to_string(),
        profile: profile.to_string(),
        backend: backend.to_string(),
        release_artifact_digest: release_artifact_digest.to_string(),
        data_root: value["data_root"].as_str().unwrap().to_string(),
        data_root_device: value["data_root_device"].as_u64().unwrap(),
        data_root_inode: value["data_root_inode"].as_u64().unwrap(),
        recovery_state_root: value["recovery_state_root"].as_str().unwrap().to_string(),
        recovery_state_device: value["recovery_state_device"].as_u64().unwrap(),
        recovery_state_inode: value["recovery_state_inode"].as_u64().unwrap(),
        journal_directory: value["journal_directory"].as_str().unwrap().to_string(),
        journal_device: value["journal_device"].as_u64().unwrap(),
        journal_inode: value["journal_inode"].as_u64().unwrap(),
    };
    assert_eq!(ctx.target.data_root, "/var/lib/o3k");

    ctx.manifest_digest = sha256_hex(&manifest);

    let era1 = era(1);
    let era1_bundle = build_bundle(&ctx.target, ctx.now, &era1, None);
    let era1_policy = build_policy(
        &ctx.target,
        &ctx.keys,
        1,
        &hex(&[0x88; 32]),
        &era1_bundle.digest,
        &era1,
    );
    let initial = initial_state(&era1_policy, &ctx.keys);

    let etc_o3k = etc.join("o3k");
    fs::create_dir(&etc_o3k).unwrap();
    fs::set_permissions(&etc_o3k, fs::Permissions::from_mode(0o755)).unwrap();
    write_root_owned(
        &etc_o3k.join("installation-policy.json"),
        &era1_policy.bytes,
        0,
        900,
        0o640,
    );
    write_root_owned(
        &etc_o3k.join("recovery-trust.json"),
        &era1_bundle.bytes,
        0,
        900,
        0o640,
    );
    let inputs = var.join("inputs");
    fs::create_dir(&inputs).unwrap();
    fs::set_permissions(&inputs, fs::Permissions::from_mode(0o700)).unwrap();
    write_root_owned(&inputs.join("policy.json"), &era1_policy.bytes, 0, 0, 0o600);
    write_root_owned(&inputs.join("state.json"), &initial.1, 0, 0, 0o600);
    write_root_owned(&inputs.join("trust.json"), &era1_bundle.bytes, 0, 0, 0o600);

    let journal_dir = var
        .join("o3k-recovery")
        .join(ctx.target.installation_id.clone());
    let state_root = var
        .join("o3k-recovery-state")
        .join(ctx.target.installation_id.clone());
    write_root_owned(
        &state_root.join("foreign-note.txt"),
        FOREIGN_BYTES,
        0,
        900,
        0o640,
    );
    let journal = if designate {
        let journal = journal_chain(
            &ctx.target,
            era1_policy.policy.policy_revision,
            &era1_policy.digest,
            &era1,
            OPERATION_ID,
        );
        write_root_owned(
            &journal_dir.join("restore-journal.json"),
            &journal.0,
            900,
            900,
            0o600,
        );
        write_root_owned(
            &journal_dir.join("unsigned-denial.marker"),
            MARKER_BYTES,
            900,
            900,
            0o600,
        );
        let designated = designated_state(&era1_policy, &initial.2, 1, OPERATION_ID, &era1);
        write_root_owned(&inputs.join("designated.json"), &designated.1, 0, 0, 0o600);
        journal
    } else {
        write_root_owned(
            &journal_dir.join("unsigned-denial.marker"),
            MARKER_BYTES,
            900,
            900,
            0o600,
        );
        (Vec::new(), String::new())
    };

    let provision = "{binary} installation-provision --policy /var/lib/inputs/policy.json --state /var/lib/inputs/state.json --trust /var/lib/inputs/trust.json";
    let (_, stderr, status) = run_in_namespace(fixture, provision, &[]);
    assert!(status.success(), "installation-provision failed: {stderr}");
    if designate {
        // Publish the offline-signed designation through the real CLI.
        let designate_cmd = "{binary} recovery-designate --state /var/lib/inputs/designated.json";
        let (_, stderr, status) = run_in_namespace(fixture, designate_cmd, &[]);
        assert!(status.success(), "recovery-designate failed: {stderr}");
    }

    Installation {
        var,
        state_root,
        journal_dir,
        journal,
        era1,
        era1_bundle,
        era1_policy,
    }
}

fn run_in_namespace(
    fixture: &Path,
    script: &str,
    envs: &[(&str, &str)],
) -> (String, String, ExitStatus) {
    let binary = envs
        .iter()
        .find(|(key, _)| *key == "O3K_A10_CLI_BINARY")
        .map(|(_, path)| *path)
        .unwrap_or(env!("CARGO_BIN_EXE_o3k"));
    let script = format!(
        "set -eu; umask 077; mount --make-rprivate /; mount --bind {0} /var/lib; mount --bind /var/lib/etc-fixture /etc; mkdir -p /usr/local/share/o3k /etc/systemd/system; mount --bind /var/lib/share-fixture /usr/local/share/o3k; mount --bind /var/lib/bin-fixture /usr/local/bin; mount --bind /var/lib/etc-fixture/systemd/system /etc/systemd/system; mount --bind /var/lib/run-fixture /run; {2}; echo C1_REANCHOR_NAMESPACE_READY >&2; {1}",
        fixture.join("var").display(),
        script.replace("{binary}", binary),
        envs.iter()
            .find(|(key, _)| *key == "O3K_A10_ASSET_DIR")
            .map(|(_, path)| format!(
                "mkdir -p /root/o3k-a10-assets; mount --bind {path} /root/o3k-a10-assets"
            ))
            .unwrap_or_else(|| ":".to_string())
    );
    let mut command = Command::new("unshare");
    command.args(["--mount", "--fork", "--", "sh", "-c", &script]);
    for (key, value) in envs {
        command.env(key, value);
    }
    let output = command.output().expect("unshare");
    (
        String::from_utf8_lossy(&output.stdout).into_owned(),
        String::from_utf8_lossy(&output.stderr).into_owned(),
        output.status,
    )
}

fn descriptor(stdout: &str) -> serde_json::Value {
    serde_json::from_str(stdout.trim()).expect("descriptor is bounded JSON on stdout")
}

fn write_root_owned(path: &Path, bytes: &[u8], uid: u32, gid: u32, mode: u32) {
    fs::write(path, bytes).unwrap();
    std::os::unix::fs::chown(path, Some(uid), Some(gid)).unwrap();
    fs::set_permissions(path, fs::Permissions::from_mode(mode)).unwrap();
}

/// sha256 of every file under `root`, keyed by relative path: the durable
/// snapshot that proves what rotation did and did not touch.
fn hash_tree(root: &Path) -> BTreeMap<String, String> {
    let mut map = BTreeMap::new();
    let mut stack = vec![(root.to_path_buf(), String::new())];
    while let Some((dir, prefix)) = stack.pop() {
        for entry in fs::read_dir(&dir).unwrap() {
            let entry = entry.unwrap();
            let path = entry.path();
            let name = format!("{prefix}{}", entry.file_name().to_string_lossy());
            let metadata = entry.metadata().unwrap();
            if metadata.is_dir() {
                stack.push((path, format!("{name}/")));
            } else {
                map.insert(name, sha256_hex(&fs::read(&path).unwrap()));
            }
        }
    }
    map
}

fn doctor_denial(stdout: &str) -> String {
    let value: serde_json::Value = serde_json::from_str(stdout).expect("doctor JSON");
    value["checks"][0]["summary"]
        .as_str()
        .expect("denial summary")
        .to_string()
}

fn doctor(fixture: &Path, as_service: bool) -> (String, ExitStatus) {
    let script = if as_service {
        "setpriv --reuid=900 --regid=900 --clear-groups {binary} doctor --json".to_string()
    } else {
        "{binary} doctor --json".to_string()
    };
    let (stdout, _, status) = run_in_namespace(fixture, &script, &[]);
    (stdout, status)
}

/// Independently exercises the installed startup and maintenance entry points
/// against a partially published v2 generation. Each command must fail at the
/// authenticated installation-selector gate, before it can open canonical
/// state or advertise readiness. This is process-level evidence: these are
/// the installed fixture binaries at their supported absolute paths, not a
/// verifier classifier.
fn assert_incomplete_v2_consumers_denied(fixture: &Path) {
    let script = r#"
set -eu
deny() {
    name=$1
    shift
    log="/var/lib/a10-consumer-${name}.log"
    set +e
    # A complete-but-inactive v2 generation makes every installed consumer
    # run the full release-inventory verification (including hashing the
    # installed executables) before it denies at the compute-posture gate;
    # in an unoptimized debug build that takes tens of seconds. The bound
    # below must stay large enough for that denial and small enough that a
    # consumer advertising readiness still trips the 124 liveness failure.
    timeout 120 "$@" >"$log" 2>&1
    code=$?
    set -e
    test "$code" -ne 0 || { echo "${name} unexpectedly succeeded" >&2; exit 91; }
    test "$code" -ne 124 || { echo "${name} stayed alive / advertised readiness" >&2; exit 92; }
    grep -Eiq 'installation (policy|authority|state)|selector|migration|installed recovery release|installed release .* authority is unavailable|active release checksum inventory|target release provenance signature is invalid|installed compute admission is incomplete' "$log" || {
        cat "$log" >&2
        echo "${name} failed for a reason other than selector denial" >&2
        exit 93
    }
}
deny o3kd setpriv --reuid=900 --regid=900 --clear-groups /usr/local/bin/o3kd --data-dir /var/lib/o3k --listen-addr 127.0.0.1:0
deny o3k-doctor setpriv --reuid=900 --regid=900 --clear-groups /usr/local/bin/o3k doctor --json
deny o3k-upgrade /usr/local/bin/o3k upgrade --check --json
deny o3k-rollback /usr/local/bin/o3k rollback --json
if test -x /usr/local/bin/o3k-compute; then
    deny o3k-compute setpriv --reuid=901 --regid=901 --clear-groups /usr/local/bin/o3k-compute
else
    set +e
    /usr/local/bin/o3k-compute >/var/lib/a10-compute-exec-denied.log 2>&1
    code=$?
    set -e
    test "$code" -eq 126 || { echo "non-executable compute returned $code, expected kernel denial 126" >&2; exit 94; }
    # Exercise compute's own selector gate as well. The canonical installed
    # inode is deliberately non-executable during migration preparation, so
    # invoke an identical temporary copy to prove that restoring execute
    # permission or moving the bytes cannot bypass the fixed release gate.
    cp /usr/local/bin/o3k-compute /var/lib/a10-compute-probe
    chmod 0755 /var/lib/a10-compute-probe
    deny o3k-compute-probe setpriv --reuid=901 --regid=901 --clear-groups /var/lib/a10-compute-probe
fi
"#;
    let (_, stderr, status) = run_in_namespace(fixture, script, &[]);
    assert!(
        status.success(),
        "an installed consumer did not independently deny the incomplete v2 generation: {stderr}"
    );
}

struct Installation {
    var: PathBuf,
    state_root: PathBuf,
    journal_dir: PathBuf,
    journal: (Vec<u8>, String),
    era1: Era,
    era1_bundle: BundleFixture,
    era1_policy: PolicyFixture,
}

fn stage_rotation_inputs(fixture: &Path, docs: &RotationDocs) {
    let dir = fixture.join("var").join("rotation-inputs");
    fs::create_dir_all(&dir).unwrap();
    fs::set_permissions(&dir, fs::Permissions::from_mode(0o755)).unwrap();
    // The rotation inputs are staged like offline-signer output: any caller
    // may read them (they are signed documents, not secrets); authority comes
    // from the signatures and the root-only installer operation.
    write_root_owned(&dir.join("reanchor.json"), &docs.reanchor, 0, 0, 0o644);
    if let Some(checkpoint) = &docs.checkpoint {
        write_root_owned(&dir.join("checkpoint.json"), checkpoint, 0, 0, 0o644);
    } else {
        let _ = fs::remove_file(dir.join("checkpoint.json"));
    }
    write_root_owned(&dir.join("policy2.json"), &docs.policy, 0, 0, 0o644);
    write_root_owned(&dir.join("trust2.json"), &docs.trust, 0, 0, 0o644);
    if let Some(revalidation) = &docs.revalidation {
        write_root_owned(&dir.join("revalidation.json"), revalidation, 0, 0, 0o644);
        write_root_owned(
            &dir.join("custody.json"),
            docs.custody.as_deref().unwrap_or(&[]),
            0,
            0,
            0o644,
        );
    } else {
        let _ = fs::remove_file(dir.join("revalidation.json"));
        let _ = fs::remove_file(dir.join("custody.json"));
    }
}

fn reanchor_script(with_checkpoint: bool, with_evidence: bool) -> String {
    let checkpoint = if with_checkpoint {
        " --checkpoint /var/lib/rotation-inputs/checkpoint.json"
    } else {
        ""
    };
    let evidence = if with_evidence {
        " --revalidation /var/lib/rotation-inputs/revalidation.json --custody-record /var/lib/rotation-inputs/custody.json"
    } else {
        ""
    };
    format!(
        "{{binary}} recovery-reanchor --reanchor /var/lib/rotation-inputs/reanchor.json{checkpoint} --policy /var/lib/rotation-inputs/policy2.json --trust /var/lib/rotation-inputs/trust2.json{evidence}"
    )
}

fn run_reanchor(
    fixture: &Path,
    with_checkpoint: bool,
    with_evidence: bool,
    envs: &[(&str, &str)],
) -> (String, ExitStatus) {
    let script = reanchor_script(with_checkpoint, with_evidence);
    let (_, stderr, status) = run_in_namespace(fixture, &script, envs);
    (stderr, status)
}

/// Runs a script in the namespace as the o3k service user (uid/gid 900).
fn run_in_namespace_as_service(
    fixture: &Path,
    script: &str,
    envs: &[(&str, &str)],
) -> (String, ExitStatus) {
    let service_script = format!("setpriv --reuid=900 --regid=900 --clear-groups {script}");
    let (_, stderr, status) = run_in_namespace(fixture, &service_script, envs);
    (stderr, status)
}

fn fresh_ctx() -> Ctx {
    Ctx {
        target: Target {
            installation_id: String::new(),
            site_id: String::new(),
            profile: String::new(),
            backend: String::new(),
            release_artifact_digest: String::new(),
            data_root: String::new(),
            data_root_device: 0,
            data_root_inode: 0,
            recovery_state_root: String::new(),
            recovery_state_device: 0,
            recovery_state_inode: 0,
            journal_directory: String::new(),
            journal_device: 0,
            journal_inode: 0,
        },
        keys: Keys::test_only(),
        manifest_digest: String::new(),
        now: chrono::Utc::now().timestamp(),
    }
}

fn a10_release_key() -> openssl::pkey::PKey<openssl::pkey::Private> {
    use openssl::pkey::{Id, PKey};
    // Ed25519 PKCS#8 PrivateKeyInfo for the test-only seed. It is created only
    // in this process and is never written into the fixture or runtime.
    let mut der = vec![
        0x30, 0x2e, 0x02, 0x01, 0x00, 0x30, 0x05, 0x06, 0x03, 0x2b, 0x65, 0x70, 0x04, 0x22, 0x04,
        0x20,
    ];
    der.extend_from_slice(&[0xA3; 32]);
    let key = PKey::private_key_from_der(&der).expect("fixture Ed25519 PKCS#8 key");
    assert_eq!(key.id(), Id::ED25519);
    assert_eq!(
        key.public_key_to_pem().expect("public PEM"),
        include_bytes!("fixtures/a10-release-verify.pub")
    );
    key
}

fn a10_release_signature(message: &[u8]) -> Vec<u8> {
    let key = a10_release_key();
    let mut signer =
        openssl::sign::Signer::new_without_digest(&key).expect("fixture release signer");
    signer
        .sign_oneshot_to_vec(message)
        .expect("fixture release signature")
}

fn a10_release_digests(
    version: &str,
    archive_digest: &str,
    raw_manifest: &[u8],
    sums: &[u8],
    sbom: &[u8],
) -> Vec<u8> {
    let bundle = format!("o3k-{}", version.strip_prefix('v').unwrap_or(version));
    let mut assets = BTreeMap::new();
    assets.insert("install.sh".to_string(), sha256_hex(b"test-only installer"));
    assets.insert(
        format!("{bundle}-linux-x86_64.tar.gz"),
        archive_digest.to_string(),
    );
    assets.insert(
        format!("{bundle}-linux-x86_64.tar.gz.sha256"),
        sha256_hex(archive_digest.as_bytes()),
    );
    assets.insert(format!("{bundle}/manifest.json"), sha256_hex(raw_manifest));
    assets.insert(format!("{bundle}/SHA256SUMS"), sha256_hex(sums));
    assets.insert(format!("{bundle}/sbom.spdx.json"), sha256_hex(sbom));
    // Authentic release provenance includes this signed extra asset. Keeping
    // it in every source and target fixture exercises publisher acceptance.
    assets.insert(
        "provenance.json".to_string(),
        sha256_hex(b"test provenance"),
    );
    assets
        .into_iter()
        .map(|(name, digest)| format!("{digest}  {name}\n"))
        .collect::<String>()
        .into_bytes()
}

fn copy_test_executable(name: &str, destination: &Path, candidate: bool) {
    let source = match name {
        "o3k" if candidate => PathBuf::from(
            std::env::var_os("O3K_A10_CANDIDATE_O3K")
                .unwrap_or_else(|| env!("CARGO_BIN_EXE_o3k").into()),
        ),
        "o3k" => PathBuf::from(
            std::env::var_os("O3K_A10_SOURCE_O3K")
                .expect("qualification harness supplies a separately built source executable"),
        ),
        "o3kd" => source_process_executable("O3K_A10_SOURCE_O3KD", "o3kd"),
        "o3k-compute" => source_process_executable("O3K_A10_SOURCE_O3K_COMPUTE", "o3k-compute-bin"),
        "o3k-network" => source_process_executable("O3K_A10_SOURCE_O3K_NETWORK", "o3k-network-bin"),
        _ => panic!("unknown executable"),
    };
    fs::copy(source, destination).expect("copy source-built executable");
    fs::set_permissions(destination, fs::Permissions::from_mode(0o755)).unwrap();
    let strip = Command::new("strip")
        .args(["--strip-debug"])
        .arg(destination)
        .status()
        .expect("qualification worker must provide strip(1)");
    assert!(strip.success(), "strip --strip-debug failed for {name}");
    if candidate {
        use std::io::Write;
        let mut file = fs::OpenOptions::new()
            .append(true)
            .open(destination)
            .expect("open candidate executable for inert fixture trailer");
        file.write_all(b"\nO3K A10 signed test candidate\n")
            .expect("append inert candidate identity trailer");
        file.sync_all().expect("sync candidate fixture executable");
    }
}

fn source_process_executable(variable: &str, binary_name: &str) -> PathBuf {
    std::env::var_os(variable)
        .map(PathBuf::from)
        .unwrap_or_else(|| {
            PathBuf::from(env!("CARGO_MANIFEST_DIR"))
                .join("../../target/debug")
                .join(binary_name)
        })
}

fn signed_release_manifest(
    version: &str,
    source_commit: &str,
    profile: &str,
    signer: &VerifyingKey,
) -> Vec<u8> {
    let key_hex = key_hex(signer);
    serde_json::to_vec(&serde_json::json!({
        "version": version,
        "profile": "test-small-edge",
        "profile_id": profile,
        "source_commit": source_commit,
        "workflow": "isolated-a10-process-fixture",
        "installer_sha256": INSTALLER_SHA256,
        "schema_version": "1",
        "installation_policy_format": "o3k-installation-policy-v1",
        "installation_policy_path": "/etc/o3k/installation-policy.json",
        "installation_policy_authority": {
            "key_id": POLICY_SIGNER_ID,
            "ed25519_public_key": key_hex,
        },
        "installation_policy_v2_authority": {
            "format": "o3k-installation-policy-v2",
            "policy_path": "/etc/o3k/installation-policy.json",
            "key_id": POLICY_SIGNER_ID,
            "ed25519_public_key": key_hex,
        },
    }))
    .unwrap()
}

fn source_release_manifest(
    version: &str,
    source_commit: &str,
    profile: &str,
    signer: &VerifyingKey,
) -> Vec<u8> {
    serde_json::to_vec(&serde_json::json!({
        "version": version,
        "profile": "test-small-edge",
        "profile_id": profile,
        "source_commit": source_commit,
        "workflow": "isolated-a10-process-fixture",
        "installer_sha256": INSTALLER_SHA256,
        "schema_version": "1",
        "installation_policy_format": "o3k-installation-policy-v1",
        "installation_policy_path": "/etc/o3k/installation-policy.json",
        "installation_policy_authority": {
            "key_id": POLICY_SIGNER_ID,
            "ed25519_public_key": key_hex(signer),
        },
    }))
    .unwrap()
}

fn executable_checksums(bundle: &Path) -> Vec<u8> {
    let mut entries = BTreeMap::new();
    for name in ["o3kd", "o3k", "o3k-compute", "o3k-network"] {
        entries.insert(
            format!("./bin/{name}"),
            sha256_hex(&fs::read(bundle.join("bin").join(name)).unwrap()),
        );
    }
    entries
        .into_iter()
        .map(|(name, digest)| format!("{digest}  {name}\n"))
        .collect::<String>()
        .into_bytes()
}

fn fixture_checksums(bundle: &Path) -> Vec<u8> {
    let mut entries = BTreeMap::new();
    for line in std::str::from_utf8(&executable_checksums(bundle))
        .unwrap()
        .lines()
    {
        let (digest, name) = line.split_once("  ").unwrap();
        entries.insert(name.to_string(), digest.to_string());
    }
    for name in ["manifest.json", "sbom.spdx.json"] {
        entries.insert(
            format!("./{name}"),
            sha256_hex(&fs::read(bundle.join(name)).unwrap()),
        );
    }
    entries
        .into_iter()
        .map(|(name, digest)| format!("{digest}  {name}\n"))
        .collect::<String>()
        .into_bytes()
}

fn make_candidate_archive(bundle: &Path, archive_path: &Path) {
    let tar_file = fs::File::create(archive_path).unwrap();
    let encoder = flate2::write::GzEncoder::new(tar_file, flate2::Compression::fast());
    let mut archive = tar::Builder::new(encoder);
    archive
        .append_dir_all(bundle.file_name().unwrap(), bundle)
        .unwrap();
    archive.finish().unwrap();
    archive
        .into_inner()
        .unwrap()
        .finish()
        .unwrap()
        .sync_all()
        .unwrap();
}

fn install_fake_systemctl(bin_dir: &Path, _systemd_dir: &Path, fixture: &Path) {
    let active = fixture.join("active-units");
    fs::create_dir_all(&active).unwrap();
    for unit in ["o3kd.service", "o3k-network.service", "o3k-compute.service"] {
        fs::write(active.join(unit), b"active").unwrap();
    }
    let script = "#!/bin/sh\nset -eu\ncmd=$1; shift || true\ncase $cmd in\n  show) prop=$1; shift; test \"$1\" = --value && shift; unit=$1; case $prop in --property=ActiveState) if test -e /var/lib/active-units/$unit; then echo active; else echo inactive; fi;; --property=UnitFileState) if test -L /etc/systemd/system/$unit; then echo masked; else echo enabled; fi;; esac;;\n  stop) rm -f /var/lib/active-units/$1;;\n  mask) test \"$1\" = --now && shift; for unit do ln -sfn /dev/null /etc/systemd/system/$unit; done;;\n  unmask) rm -f /etc/systemd/system/$1;;\n  start) : > /var/lib/active-units/$1;;\n  daemon-reload) :;;\n  *) exit 2;;\nesac\n";
    let path = bin_dir.join("systemctl");
    fs::write(&path, script).unwrap();
    fs::set_permissions(&path, fs::Permissions::from_mode(0o755)).unwrap();
}

#[test]
#[ignore = "requires root, private mount namespace, ext4 fixture, test binaries and test-only signer"]
#[cfg(feature = "a10-process-test-hooks")]
fn signed_never_recovered_migration_runs_through_real_cli() {
    let fixture = root_fixture().expect("root fixture available");
    let mut ctx = fresh_ctx();
    let var = fixture.join("var");
    let assets = std::env::temp_dir().join(format!("o3k-a10-assets-{}", uuid::Uuid::now_v7()));
    fs::create_dir_all(assets.join("inputs")).unwrap();
    fs::set_permissions(&assets, fs::Permissions::from_mode(0o700)).unwrap();
    let source_version = "v0.4.0-rc.5";
    let source_commit = SOURCE_COMMIT;
    let source_bundle = var.join("source-bundle/o3k-0.4.0-rc.5");
    fs::create_dir_all(source_bundle.join("bin")).unwrap();
    for name in ["o3kd", "o3k", "o3k-compute", "o3k-network"] {
        copy_test_executable(name, &source_bundle.join("bin").join(name), false);
    }
    let source_raw_manifest = source_release_manifest(
        source_version,
        source_commit,
        "o3k-small-edge-v1",
        &ctx.keys.policy.verifying_key(),
    );
    fs::write(source_bundle.join("manifest.json"), &source_raw_manifest).unwrap();
    let source_sbom = b"test-only source sbom";
    fs::write(source_bundle.join("sbom.spdx.json"), source_sbom).unwrap();
    let source_sums = fixture_checksums(&source_bundle);
    fs::write(source_bundle.join("SHA256SUMS"), &source_sums).unwrap();
    let source_artifact = assets.join("source-release.tar.gz");
    make_candidate_archive(&source_bundle, &source_artifact);
    let source_artifact_digest = sha256_hex(&fs::read(&source_artifact).unwrap());
    let source_installed_manifest =
        o3k::upgrade::release_identity::manifest_with_verified_artifact(
            &source_raw_manifest,
            &source_artifact_digest,
        )
        .unwrap();
    let installation = setup_fixture_for_release(
        &mut ctx,
        &fixture,
        false,
        "o3k-small-edge-v1",
        "postgresql",
        &source_artifact_digest,
        Some(source_installed_manifest.clone()),
    );
    let share = var.join("share-fixture");
    let bin = var.join("bin-fixture");
    let systemd = var.join("etc-fixture/systemd/system");
    let inputs = assets.join("inputs");
    fs::create_dir_all(&inputs).unwrap();
    for name in ["o3kd", "o3k", "o3k-compute", "o3k-network"] {
        // Installed executables must have a single protected pathname. A
        // hard link to the release bundle would correctly fail the publisher's
        // executable identity/link-count gate and would not model installation.
        fs::copy(source_bundle.join("bin").join(name), bin.join(name)).unwrap();
    }
    install_fake_systemctl(&bin, &systemd, &var);

    let source_manifest = source_raw_manifest;
    fs::write(share.join("SHA256SUMS"), &source_sums).unwrap();
    fs::set_permissions(share.join("SHA256SUMS"), fs::Permissions::from_mode(0o644)).unwrap();
    let source_digests = a10_release_digests(
        source_version,
        &source_artifact_digest,
        &source_manifest,
        &source_sums,
        source_sbom,
    );
    let source_signature = a10_release_signature(&source_digests);
    for (name, bytes) in [
        ("source-manifest.json", source_manifest.clone()),
        ("source-release-digests.txt", source_digests.clone()),
        ("source-release-signature.sig", source_signature.clone()),
    ] {
        write_root_owned(&inputs.join(name), &bytes, 0, 0, 0o600);
    }

    let target_version = "v0.4.1-a10";
    let target_commit = "bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb";
    let raw_manifest = signed_release_manifest(
        target_version,
        target_commit,
        "o3k-small-edge-v1",
        &ctx.keys.policy.verifying_key(),
    );
    let bundle = assets.join("candidate-bundle/o3k-0.4.1-a10");
    fs::create_dir_all(bundle.join("bin")).unwrap();
    for name in ["o3kd", "o3k", "o3k-compute", "o3k-network"] {
        copy_test_executable(name, &bundle.join("bin").join(name), true);
        assert_ne!(
            sha256_hex(&fs::read(bundle.join("bin").join(name)).unwrap()),
            sha256_hex(&fs::read(source_bundle.join("bin").join(name)).unwrap()),
            "test release candidate must exercise replacement for {name}"
        );
    }
    fs::write(bundle.join("manifest.json"), &raw_manifest).unwrap();
    fs::write(bundle.join("sbom.spdx.json"), b"test-only sbom").unwrap();
    let target_sums = fixture_checksums(&bundle);
    fs::write(bundle.join("SHA256SUMS"), &target_sums).unwrap();
    let artifact = inputs.join("candidate.tar.gz");
    make_candidate_archive(&bundle, &artifact);
    let artifact_metadata = fs::metadata(&artifact).unwrap();
    eprintln!(
        "A10 fixture artifact: uid={} gid={} mode={:o} nlink={} bytes={}",
        artifact_metadata.uid(),
        artifact_metadata.gid(),
        artifact_metadata.mode() & 0o7777,
        artifact_metadata.nlink(),
        artifact_metadata.len(),
    );
    let artifact_bytes = fs::read(&artifact).unwrap();
    let artifact_digest = sha256_hex(&artifact_bytes);
    let target_manifest = o3k::upgrade::release_identity::manifest_with_verified_artifact(
        &raw_manifest,
        &artifact_digest,
    )
    .unwrap();
    let target_manifest_digest = sha256_hex(&target_manifest);
    let release_digests = a10_release_digests(
        target_version,
        &artifact_digest,
        &raw_manifest,
        &target_sums,
        b"test-only sbom",
    );
    let release_signature = a10_release_signature(&release_digests);

    let source = &installation.era1_policy;
    let policy_payload = serde_json::json!({
        "format": "o3k-installation-policy-v2",
        "installation_id": ctx.target.installation_id,
        "site_id": ctx.target.site_id,
        "profile": source.policy.profile,
        "backend": source.policy.backend,
        "backend_version": "16",
        "deployment": "virtualized",
        "restore_branch_authorization": "inactive-materialization-only",
        "release_identity": artifact_digest,
        "release_version": target_version,
        "source_commit": target_commit,
        "release_manifest_sha256": target_manifest_digest,
        "data_root": source.policy.data_root,
        "target_device": source.policy.target_device,
        "target_inode": source.policy.target_inode,
        "policy_revision": source.policy.policy_revision + 1,
        "prior_policy_digest": source.digest,
        "policy_path": source.policy.policy_path,
        "trust_bundle_path": source.policy.trust_bundle_path,
        "trust_bundle_digest": source.policy.trust_bundle_digest,
        "recovery_state_root": source.policy.recovery_state_root,
        "recovery_state_device": source.policy.recovery_state_device,
        "recovery_state_inode": source.policy.recovery_state_inode,
        "journal_directory": source.policy.journal_directory,
        "journal_device": source.policy.journal_device,
        "journal_inode": source.policy.journal_inode,
        "journal_trust_root_id": source.policy.journal_trust_root_id,
        "journal_trust_root_public_key": source.policy.journal_trust_root_public_key,
        "evidence_trust_root_id": source.policy.evidence_trust_root_id,
        "evidence_trust_root_public_key": source.policy.evidence_trust_root_public_key,
        "signer_key_id": POLICY_SIGNER_ID,
    });
    let policy_bytes = sign(&policy_payload, &ctx.keys.policy, POLICY_SIGNER_ID);
    let state_tip = fs::read(installation.state_root.join("state.json")).unwrap();
    let migration_payload = serde_json::json!({
        "format": "o3k-installation-policy-migration-v1",
        "installation_id": ctx.target.installation_id,
        "site_id": ctx.target.site_id,
        "sequence": 1,
        "prior_record_digest": sha256_hex(&state_tip),
        "preserved_state": "NEVER_RECOVERED",
        "prior_policy_format": "o3k-installation-policy-v1",
        "prior_policy_revision": source.policy.policy_revision,
        "prior_policy_digest": source.digest,
        "new_policy_format": "o3k-installation-policy-v2",
        "new_policy_revision": source.policy.policy_revision + 1,
        "new_policy_digest": sha256_hex(&policy_bytes),
        "prior_release_manifest_sha256": ctx.manifest_digest,
        "new_release_manifest_sha256": target_manifest_digest,
        "prior_release_identity": {
            "version": "v0.4.0-rc.5",
            "source_commit": SOURCE_COMMIT,
            "release_artifact_sha256": source_artifact_digest,
            "profile_id": "o3k-small-edge-v1",
            "schema_version": 1,
        },
        "new_release_identity": {
            "version": target_version,
            "source_commit": target_commit,
            "release_artifact_sha256": artifact_digest,
            "profile_id": "o3k-small-edge-v1",
            "schema_version": 1,
        },
        "target_device": ctx.target.data_root_device,
        "target_inode": ctx.target.data_root_inode,
        "trust_bundle_digest": source.policy.trust_bundle_digest,
        "checkpoint_digest": null,
        "signer_manifest_digest": target_manifest_digest,
    });
    let event_bytes = sign(&migration_payload, &ctx.keys.policy, POLICY_SIGNER_ID);
    for (name, bytes) in [
        ("policy-v2.json", policy_bytes),
        ("migration-event.json", event_bytes),
        ("release-manifest-v2.json", target_manifest.clone()),
        ("release-digests.txt", release_digests.clone()),
        ("release-signature.sig", release_signature.clone()),
    ] {
        write_root_owned(&inputs.join(name), &bytes, 0, 0, 0o600);
    }
    fsync_test_tree(&inputs);

    let invocation = "stat -c 'A10 mounted artifact: uid=%u gid=%g mode=%a links=%h bytes=%s type=%F' /root/o3k-a10-assets/inputs/candidate.tar.gz; {binary} recovery-migrate-v2 --policy /root/o3k-a10-assets/inputs/policy-v2.json --event /root/o3k-a10-assets/inputs/migration-event.json --manifest /root/o3k-a10-assets/inputs/release-manifest-v2.json --artifact /root/o3k-a10-assets/inputs/candidate.tar.gz --release-digests /root/o3k-a10-assets/inputs/release-digests.txt --release-signature /root/o3k-a10-assets/inputs/release-signature.sig --source-manifest /root/o3k-a10-assets/inputs/source-manifest.json --source-release-digests /root/o3k-a10-assets/inputs/source-release-digests.txt --source-release-signature /root/o3k-a10-assets/inputs/source-release-signature.sig";
    let asset_dir = assets.to_str().unwrap();
    let candidate_cli = concat!(
        env!("CARGO_MANIFEST_DIR"),
        "/../../target/a10-fixture/candidate-o3k"
    );
    let v1_policy = fs::read(var.join("etc-fixture/o3k/installation-policy.json")).unwrap();
    let v1_high_water = fs::read(installation.state_root.join("policy.json")).unwrap();
    let v1_manifest = fs::read(share.join("release-manifest.json")).unwrap();
    let v1_selector = fs::read(installation.state_root.join("state.json")).unwrap();
    let v1_selector_digest = sha256_hex(&v1_selector);
    let pristine = root_fixture().expect("pristine fixture snapshot location available");
    let copied = Command::new("cp")
        .args(["-a"])
        .arg(format!("{}/.", fixture.display()))
        .arg(&pristine)
        .status()
        .expect("cp for disposable fixture snapshot");
    assert!(copied.success(), "could not snapshot pristine v1 fixture");
    let crash_env = [
        ("O3K_A10_ASSET_DIR", asset_dir),
        ("O3K_A10_CLI_BINARY", candidate_cli),
        (
            "O3K_A10_MIGRATION_CRASH_AT",
            "state.json:after-rename-before-directory-fsync",
        ),
    ];
    let (_, crash_stderr, crash_status) = run_in_namespace(&fixture, invocation, &crash_env);
    assert_eq!(
        crash_status.code(),
        Some(86),
        "selector rename fault point did not terminate the real publisher: {crash_stderr}"
    );
    assert_eq!(
        fs::read(installation.state_root.join("state.json")).unwrap(),
        fs::read(inputs.join("migration-event.json")).unwrap(),
        "rename-before-directory-fsync process exit must expose only exact signed selector bytes"
    );
    assert_eq!(
        fs::read(var.join("etc-fixture/o3k/installation-policy.json")).unwrap(),
        v1_policy,
        "policy must remain v1 when selector publication is interrupted"
    );
    assert_eq!(
        fs::read(installation.state_root.join("policy.json")).unwrap(),
        v1_high_water,
        "high-water must remain v1 when selector publication is interrupted"
    );
    assert_eq!(
        fs::read(share.join("release-manifest.json")).unwrap(),
        v1_manifest,
        "release manifest must remain v1 when selector publication is interrupted"
    );
    eprintln!(
        "PASS selector rename-before-directory-fsync: exact signed event visible; v1 policy/high-water/manifest preserved"
    );
    let exact_retry = invocation
        .split_once("; ")
        .expect("publisher invocation includes artifact diagnostic")
        .1
        .replace(
            "/root/o3k-a10-assets/inputs/",
            "/root/o3k-a10-assets/removed/",
        );
    let retry_env = [
        ("O3K_A10_ASSET_DIR", asset_dir),
        ("O3K_A10_CLI_BINARY", candidate_cli),
    ];
    let (retry_stdout, retry_stderr, retry_status) =
        run_in_namespace(&fixture, &exact_retry, &retry_env);
    assert!(
        retry_status.success() && retry_stdout.contains("V2Complete"),
        "post-selector process restart did not exact-forward from staged authenticated inputs: stdout={retry_stdout} stderr={retry_stderr}"
    );
    assert_eq!(
        fs::read(share.join("release-manifest.json")).unwrap(),
        target_manifest
    );
    assert!(
        installation
            .journal_dir
            .join("unsigned-denial.marker")
            .exists()
    );
    let selector_before_replay = fs::read(installation.state_root.join("state.json")).unwrap();
    let state_snapshot = hash_tree(&installation.state_root);
    let share_snapshot = hash_tree(&share);
    let (replay_stdout, replay_stderr, replay_status) =
        run_in_namespace(&fixture, &exact_retry, &retry_env);
    assert!(
        replay_status.success() && replay_stdout.contains("V2Complete"),
        "exact-forward replay failed: stdout={replay_stdout} stderr={replay_stderr}"
    );
    assert_eq!(
        fs::read(installation.state_root.join("state.json")).unwrap(),
        selector_before_replay,
        "replay must not publish a second selector"
    );
    assert_eq!(hash_tree(&installation.state_root), state_snapshot);
    assert_eq!(hash_tree(&share), share_snapshot);
    eprintln!(
        "PASS signed NEVER_RECOVERED v1-to-v2 migration, restart exact-forward completion, and idempotent replay"
    );
    for unit in ["o3kd.service", "o3k-network.service", "o3k-compute.service"] {
        assert_eq!(
            fs::read_link(systemd.join(unit)).ok().as_deref(),
            Some(Path::new("/dev/null")),
            "restart retry must preserve a conservative persistent deny for {unit}"
        );
    }
    assert_eq!(
        fs::metadata(bin.join("o3k-compute"))
            .unwrap()
            .permissions()
            .mode()
            & 0o777,
        0o644,
        "restart retry must preserve direct-execution denial"
    );

    // Each case starts from the same inode-bound authenticated v1 fixture.
    // The child is the real publisher; exit 86 is injected only after the
    // named filesystem operation has reached its actual boundary.
    let crash_cases = [
        ("compute-execution-disabled", false),
        ("compute-processes-quiesced", false),
        ("d8-exclusions-acquired", false),
        ("authenticated-inputs-staged", false),
        ("executable-replaced:o3kd", false),
        ("executable-replaced:o3k", false),
        ("executable-replaced:o3k-compute", false),
        ("executable-replaced:o3k-network", false),
        ("state.json:after-temp-write-before-fsync", false),
        ("state.json:after-file-fsync", false),
        ("state.json:after-directory-fsync-before-readback", true),
        (
            "installation-policy.json:after-rename-before-directory-fsync",
            true,
        ),
        ("v2-policy-published", true),
        ("policy.json:after-rename-before-directory-fsync", true),
        ("v2-high-water-published", true),
        (
            "release-manifest.json:after-rename-before-directory-fsync",
            true,
        ),
        ("v2-release-manifest-published", true),
        ("v2-generation-verified-before-guard-release", true),
        ("before-d8-guard-release", true),
        ("after-d8-guard-release", true),
    ];
    let signed_event = fs::read(inputs.join("migration-event.json")).unwrap();
    let signed_policy = fs::read(inputs.join("policy-v2.json")).unwrap();
    for (point, selector_is_v2) in crash_cases {
        restore_test_tree(&pristine, &fixture);
        let case_env = [
            ("O3K_A10_ASSET_DIR", asset_dir),
            ("O3K_A10_CLI_BINARY", candidate_cli),
            ("O3K_A10_MIGRATION_CRASH_AT", point),
        ];
        let (_, case_stderr, case_status) = run_in_namespace(&fixture, invocation, &case_env);
        assert_eq!(
            case_status.code(),
            Some(86),
            "fault point {point} did not terminate after the real publisher boundary: {case_stderr}"
        );
        let selected = fs::read(installation.state_root.join("state.json")).unwrap();
        assert_eq!(
            selected.as_slice(),
            if selector_is_v2 {
                signed_event.as_slice()
            } else {
                v1_selector.as_slice()
            },
            "fault point {point} left an unexpected active selector"
        );
        let policy_after_crash =
            fs::read(var.join("etc-fixture/o3k/installation-policy.json")).unwrap();
        assert!(
            policy_after_crash == v1_policy || policy_after_crash == signed_policy,
            "fault point {point} left policy bytes outside the authenticated endpoints"
        );
        let manifest_after_crash = fs::read(share.join("release-manifest.json")).unwrap();
        assert!(
            manifest_after_crash == v1_manifest || manifest_after_crash == target_manifest,
            "fault point {point} left release-manifest bytes outside the authenticated endpoints"
        );
        if !selector_is_v2 {
            assert_eq!(
                policy_after_crash, v1_policy,
                "pre-selector interruption changed the active v1 policy at {point}"
            );
            assert_eq!(
                fs::read(installation.state_root.join("policy.json")).unwrap(),
                v1_high_water,
                "pre-selector interruption changed v1 high-water at {point}"
            );
            assert_eq!(
                manifest_after_crash, v1_manifest,
                "pre-selector interruption changed the active v1 release manifest at {point}"
            );
        } else {
            // The selector is now v2 authority. Independently run the
            // installed daemon, operator, upgrade, rollback, and compute
            // entry points before allowing exact-forward retry. Their
            // denials must be side-effect free.
            let state_before_consumers = hash_tree(&installation.state_root);
            let journal_before_consumers = hash_tree(&installation.journal_dir);
            let share_before_consumers = hash_tree(&share);
            let canonical_before_consumers = hash_tree(&var.join("o3k"));
            assert_incomplete_v2_consumers_denied(&fixture);
            assert_eq!(
                hash_tree(&installation.state_root),
                state_before_consumers,
                "consumer denial changed authenticated state at {point}"
            );
            assert_eq!(
                hash_tree(&installation.journal_dir),
                journal_before_consumers,
                "consumer denial changed the journal at {point}"
            );
            assert_eq!(
                hash_tree(&share),
                share_before_consumers,
                "consumer denial changed release authority at {point}"
            );
            assert_eq!(
                hash_tree(&var.join("o3k")),
                canonical_before_consumers,
                "consumer denial mutated canonical state at {point}"
            );
            eprintln!(
                "PASS incomplete-generation consumer denial: o3kd, o3k doctor/upgrade/rollback, o3k-compute at {point}"
            );
        }
        let retry = if selector_is_v2 {
            exact_retry.as_str()
        } else {
            invocation
        };
        let (case_stdout, case_stderr, case_status) = run_in_namespace(&fixture, retry, &retry_env);
        assert!(
            case_status.success() && case_stdout.contains("V2Complete"),
            "fault point {point} did not converge via the permitted retry: stdout={case_stdout} stderr={case_stderr}"
        );
        assert_eq!(
            fs::read(installation.state_root.join("state.json")).unwrap(),
            signed_event,
            "fault point {point} retry did not preserve the exact signed selector"
        );
        assert_eq!(
            fs::read(var.join("etc-fixture/o3k/installation-policy.json")).unwrap(),
            signed_policy,
            "fault point {point} retry did not publish exact signed policy bytes"
        );
        assert_eq!(
            fs::read(share.join("release-manifest.json")).unwrap(),
            target_manifest,
            "fault point {point} retry did not publish the exact release manifest"
        );
        let state_after_retry = hash_tree(&installation.state_root);
        let share_after_retry = hash_tree(&share);
        let (replay_out, replay_err, replay_status) =
            run_in_namespace(&fixture, exact_retry.as_str(), &retry_env);
        assert!(
            replay_status.success() && replay_out.contains("V2Complete"),
            "fault point {point} exact-forward replay failed: stdout={replay_out} stderr={replay_err}"
        );
        assert_eq!(hash_tree(&installation.state_root), state_after_retry);
        assert_eq!(hash_tree(&share), share_after_retry);
        eprintln!("PASS A10 publication crash/restart boundary: {point}");
    }
    restore_test_tree(&pristine, &fixture);
    let state_rel = installation
        .state_root
        .strip_prefix(fixture.join("var"))
        .expect("state path is below the fixture's /var bind")
        .display()
        .to_string();
    let publisher_command = invocation
        .split_once("; ")
        .expect("publisher invocation includes artifact posture diagnostic")
        .1;
    let concurrent_script = format!(
        "{publisher_command} >/var/lib/a10-publisher.out 2>/var/lib/a10-publisher.err & publisher=$!; i=0; while test ! -e /var/lib/a10-pause-marker; do i=$((i + 1)); test $i -lt 600 || exit 70; sleep 0.05; done; active=$(sha256sum /var/lib/{state_rel}/state.json | cut -d' ' -f1); test \"$active\" = \"{v1_selector_digest}\"; test ! -x /usr/local/bin/o3k-compute; test \"$(readlink /etc/systemd/system/o3k-compute.service)\" = /dev/null; if /usr/local/bin/o3k-compute; then exit 71; else result=$?; test $result -eq 126; fi; test ! -e /var/lib/active-units/o3k-compute.service; touch /var/lib/a10-resume-marker; wait $publisher"
    );
    let pause_env = [
        ("O3K_A10_ASSET_DIR", asset_dir),
        ("O3K_A10_CLI_BINARY", candidate_cli),
        ("O3K_A10_MIGRATION_PAUSE_AT", "d8-exclusions-acquired"),
        (
            "O3K_A10_MIGRATION_PAUSE_MARKER",
            "/var/lib/a10-pause-marker",
        ),
        (
            "O3K_A10_MIGRATION_RESUME_MARKER",
            "/var/lib/a10-resume-marker",
        ),
    ];
    let (concurrent_out, concurrent_err, concurrent_status) =
        run_in_namespace(&fixture, &concurrent_script, &pause_env);
    assert!(
        concurrent_status.success(),
        "compute direct-start while D8 was held did not remain denied: stdout={concurrent_out} stderr={concurrent_err}"
    );
    assert!(
        fs::read(fixture.join("var/a10-publisher.out"))
            .unwrap()
            .windows(b"V2Complete".len())
            .any(|window| window == b"V2Complete"),
        "paused publisher did not complete after D8 direct-start assertion"
    );
    eprintln!("PASS A10 direct compute invocation denied during D8; publisher resumed");
    fs::remove_dir_all(fixture).unwrap();
    fs::remove_dir_all(pristine).unwrap();
    fs::remove_dir_all(assets).unwrap();
}

fn fsync_test_tree(directory: &Path) {
    for entry in fs::read_dir(directory).unwrap() {
        let path = entry.unwrap().path();
        if path.is_dir() {
            fsync_test_tree(&path);
        } else {
            fs::File::open(path).unwrap().sync_all().unwrap();
        }
    }
    fs::File::open(directory).unwrap().sync_all().unwrap();
}

/// Restores a disposable process-test fixture without replacing any existing
/// directory inode (installation policy binds several of those identities).
fn restore_test_tree(source: &Path, destination: &Path) {
    let source_entries: BTreeMap<_, _> = fs::read_dir(source)
        .unwrap()
        .map(|entry| {
            let entry = entry.unwrap();
            (entry.file_name(), entry.path())
        })
        .collect();
    for entry in fs::read_dir(destination).unwrap() {
        let entry = entry.unwrap();
        if !source_entries.contains_key(&entry.file_name()) {
            let path = entry.path();
            if entry.file_type().unwrap().is_dir() {
                fs::remove_dir_all(path).unwrap();
            } else {
                fs::remove_file(path).unwrap();
            }
        }
    }
    for (name, source_path) in source_entries {
        let target_path = destination.join(&name);
        let source_type = fs::symlink_metadata(&source_path).unwrap().file_type();
        if source_type.is_dir() {
            if fs::symlink_metadata(&target_path)
                .map(|metadata| !metadata.is_dir())
                .unwrap_or(false)
            {
                fs::remove_file(&target_path).unwrap();
            }
            fs::create_dir_all(&target_path).unwrap();
            restore_test_tree(&source_path, &target_path);
        } else if source_type.is_symlink() {
            if fs::symlink_metadata(&target_path).is_ok() {
                fs::remove_file(&target_path).unwrap();
            }
            let link = fs::read_link(&source_path).unwrap();
            std::os::unix::fs::symlink(link, &target_path).unwrap();
        } else {
            fs::copy(&source_path, &target_path).unwrap();
        }
        if source_type.is_dir() || source_type.is_file() {
            let metadata = fs::metadata(&source_path).unwrap();
            fs::set_permissions(
                &target_path,
                fs::Permissions::from_mode(metadata.mode() & 0o7777),
            )
            .unwrap();
            std::os::unix::fs::chown(&target_path, Some(metadata.uid()), Some(metadata.gid()))
                .unwrap();
        }
    }
}

#[test]
#[ignore = "requires root, unshare(1), setpriv(1), and a source-built o3k binary"]
fn rotation_over_real_protected_directories_resumes_and_preserves_exactly() {
    let fixture = root_fixture().unwrap_or_else(|reason| panic!("{reason}"));
    let mut ctx = fresh_ctx();
    let installation = setup_fixture(&mut ctx, &fixture, true);
    let Installation {
        var,
        state_root,
        journal_dir,
        journal,
        era1,
        era1_bundle,
        era1_policy,
        ..
    } = &installation;

    // Startup observation of the designated generation: operational access
    // is denied by the authenticated disposition.
    let (stdout, status) = doctor(&fixture, false);
    assert!(
        !status.success(),
        "designated installation must deny startup"
    );
    assert!(
        doctor_denial(&stdout).contains(DENIAL),
        "unexpected pre-rotation denial: {stdout}"
    );

    // Service-user denial: the o3k user can observe the inputs but never
    // rotate; no durable byte may change.
    let era2 = era(2);
    let tips = read_tips(&ctx, var);
    let docs = rotation_docs(
        &ctx,
        era1_policy,
        era1_bundle,
        era1,
        &era2,
        &tips,
        &authenticated_tip_hash(journal, era1),
        OPERATION_ID,
        RecoveryState::RecoveryDesignated,
        RotationReason::Compromise,
        &hex(&[0x6E; 32]),
        b"custody-record",
        |_| {},
    );
    stage_rotation_inputs(&fixture, &docs);
    let before = hash_tree(var);
    let (stderr, service_status) =
        run_in_namespace_as_service(&fixture, &reanchor_script(true, true), &[]);
    assert!(
        !service_status.success(),
        "service user must never rotate: {stderr}"
    );
    assert!(
        stderr.contains("NotRoot"),
        "service-user denial must be the root-authority check: {stderr}"
    );
    assert_eq!(hash_tree(var), before, "service denial performs no writes");

    // Interrupt the rotation after the new checkpoint is published but
    // before R (when the crash-injection feature is compiled in) and
    // resume exact-forward: the durable generation is now genuinely partial
    // (new fixed policy, high-waters, and checkpoint; the state tip is
    // still the prior disposition), so the resume must re-verify the
    // signed R/C against the durable prior bytes and continue forward only.
    let (_, crashed) = run_reanchor(
        &fixture,
        true,
        true,
        &[("O3K_REANCHOR_CRASH_AT", "after-publish-checkpoint")],
    );
    let interrupted = !crashed.success();
    let (stderr, status) = run_reanchor(&fixture, true, true, &[]);
    assert!(
        status.success(),
        "exact-forward resume must complete: {stderr}"
    );
    let _ = interrupted;

    // Durable-state assertions over the real files.
    let journal_after = hash_tree(journal_dir);
    assert_eq!(
        journal_after.get("unsigned-denial.marker").unwrap(),
        &sha256_hex(MARKER_BYTES),
        "unsigned denial marker preserved byte-for-byte"
    );
    assert_eq!(
        journal_after.get("restore-journal.json").unwrap(),
        &journal.1,
        "journal chain preserved byte-for-byte"
    );
    let state_after = hash_tree(state_root);
    assert_eq!(
        state_after.get("foreign-note.txt").unwrap(),
        &sha256_hex(FOREIGN_BYTES),
        "foreign state never adopted or mutated"
    );
    let tip_bytes = fs::read(state_root.join("state.json")).unwrap();
    assert_eq!(sha256_hex(&tip_bytes), sha256_hex(&docs.reanchor));
    let tip: Signed<InstallationReanchor> = decode_signed(&tip_bytes);
    assert_eq!(
        tip.payload.preserved_state,
        RecoveryState::RecoveryDesignated
    );
    assert_eq!(
        tip.payload.checkpoint_digest.as_deref(),
        Some(sha256_hex(docs.checkpoint.as_ref().unwrap()).as_str()),
        "R binds digest(C) over the published checkpoint"
    );
    assert_eq!(
        fs::read(journal_dir.join(CHECKPOINT_NAME)).unwrap(),
        docs.checkpoint.clone().unwrap()
    );
    assert_eq!(
        fs::read(state_root.join("policy.json")).unwrap(),
        docs.policy,
        "policy high-water advanced"
    );
    assert_eq!(
        fs::read(var.join("etc-fixture/o3k/installation-policy.json")).unwrap(),
        docs.policy,
        "fixed policy advanced"
    );
    assert_eq!(fs::read(state_root.join("trust.json")).unwrap(), docs.trust);
    assert!(
        state_root
            .join(format!("state-{}.json", tips.state_tip_digest))
            .exists()
    );
    assert!(
        state_root
            .join(format!("policy-{}.json", era1_policy.digest))
            .exists()
    );
    assert!(
        state_root
            .join(format!("trust-{}.json", era1_bundle.digest))
            .exists()
    );
    // Rotation never opens the canonical store. Quiescence creates only the
    // lifetime access-lock file; no database, session, or store artifact may
    // appear.
    let unexpected: Vec<_> = fs::read_dir(var.join("o3k"))
        .unwrap()
        .map(|entry| entry.unwrap().file_name())
        .filter(|name| name != ".o3k-store.lock")
        .collect();
    assert!(
        unexpected.is_empty(),
        "rotation granted no store access: unexpected data-root entries {unexpected:?}"
    );

    // Startup observation of the rotated generation: the whole R/C chain
    // authenticates over ext4 and still denies operational access.
    let (stdout, status) = doctor(&fixture, false);
    assert!(
        !status.success(),
        "rotated designated installation must deny startup"
    );
    assert!(
        doctor_denial(&stdout).contains(DENIAL),
        "unexpected post-rotation denial: {stdout}"
    );

    // Tamper differential: a corrupted tip must change the observed denial,
    // proving startup genuinely re-authenticates the rotated chain.
    let original_tip = tip_bytes.clone();
    let mut corrupted = original_tip.clone();
    corrupted[20] ^= 0x01;
    fs::write(state_root.join("state.json"), &corrupted).unwrap();
    let (stdout, status) = doctor(&fixture, false);
    assert!(!status.success());
    let tampered_denial = doctor_denial(&stdout);
    assert!(
        !tampered_denial.contains(DENIAL),
        "tampered tip must change the startup observation: {stdout}"
    );
    fs::write(state_root.join("state.json"), &original_tip).unwrap();
    let (stdout, status) = doctor(&fixture, false);
    assert!(!status.success());
    assert!(
        doctor_denial(&stdout).contains(DENIAL),
        "restored tip must observe the rotated generation again: {stdout}"
    );

    // Byte-identical replay: the exact published R re-presented performs
    // no durable writes at all.
    let before = hash_tree(var);
    let (stderr, status) = run_reanchor(&fixture, true, true, &[]);
    assert!(
        status.success(),
        "byte-identical replay must succeed: {stderr}"
    );
    assert_eq!(
        hash_tree(var),
        before,
        "byte-identical replay performs no writes"
    );

    let _ = fs::remove_dir_all(&fixture);
}

#[test]
#[ignore = "requires root, unshare(1), setpriv(1), and a source-built o3k binary"]
fn rotate_then_real_designate_then_startup_observation_accepts_the_new_designation() {
    let fixture = root_fixture().unwrap_or_else(|reason| panic!("{reason}"));
    let mut ctx = fresh_ctx();
    // A NEVER_RECOVERED installation: no journal, no designation yet.
    let installation = setup_fixture(&mut ctx, &fixture, false);
    let Installation {
        var,
        state_root,
        journal_dir,
        era1,
        era1_bundle,
        era1_policy,
        ..
    } = &installation;

    // Startup observation of the initial generation: no recovery denial (the
    // diagnostics themselves report an empty host, which is not a recovery
    // decision).
    let (stdout, status) = doctor(&fixture, true);
    assert!(
        !stdout.contains(DENIED_PREFIX),
        "never-recovered installation must pass startup observation: {stdout}"
    );
    let _ = status;

    // R-only rotation (no checkpoint binds a NEVER_RECOVERED preservation).
    let era2 = era(2);
    let tips = read_tips(&ctx, var);
    let docs = r_only_rotation_docs(&ctx, era1_policy, era1_bundle, era1, &era2, &tips);
    stage_rotation_inputs(&fixture, &docs);
    let (stderr, status) = run_reanchor(&fixture, false, false, &[]);
    assert!(status.success(), "R-only rotation failed: {stderr}");
    let tip_bytes = fs::read(state_root.join("state.json")).unwrap();
    assert_eq!(sha256_hex(&tip_bytes), sha256_hex(&docs.reanchor));
    let tip: Signed<InstallationReanchor> = decode_signed(&tip_bytes);
    assert_eq!(tip.payload.preserved_state, RecoveryState::NeverRecovered);

    // Startup observation of the rotated NEVER_RECOVERED generation: the
    // whole R chain authenticates and startup is not denied.
    let (stdout, _) = doctor(&fixture, true);
    assert!(
        !stdout.contains(DENIED_PREFIX),
        "rotated never-recovered generation must pass startup observation: {stdout}"
    );

    // Publish a NEW operation's journal chain under the new era, then
    // designate through the real CLI: the designation transitions from the
    // re-anchor tip, so it sits at sequence 2.
    let journal2 = journal_chain(&ctx.target, 0, "", &era2, POST_ROTATION_OPERATION_ID);
    write_root_owned(
        &journal_dir.join("restore-journal.json"),
        &journal2.0,
        900,
        900,
        0o600,
    );
    let current_policy = read_policy(var, &ctx.target.installation_id);
    let designated = designated_state(
        &current_policy,
        &sha256_hex(&tip_bytes),
        2,
        POST_ROTATION_OPERATION_ID,
        &era2,
    );
    let inputs = var.join("inputs");
    write_root_owned(&inputs.join("designated.json"), &designated.1, 0, 0, 0o600);
    let (_, stderr, status) = run_in_namespace(
        &fixture,
        "{binary} recovery-designate --state /var/lib/inputs/designated.json",
        &[],
    );
    assert!(
        status.success(),
        "real recovery-designate after rotation failed: {stderr}"
    );

    // Startup observation of the designated-after-rotation chain: the base
    // disposition sits at sequence 2 and must authenticate.
    let (stdout, status) = doctor(&fixture, true);
    assert!(!status.success());
    assert!(
        doctor_denial(&stdout).contains(DENIAL),
        "designation after rotation must observe as an authenticated designation: {stdout}"
    );

    // Rotate once more over the designated state: the rotated-generation
    // startup path must accept the sequence-2 base disposition.
    let era3 = era(3);
    let tips = read_tips(&ctx, var);
    let current_trust = read_bundle(var, &ctx.target.installation_id);
    let docs2 = rotation_docs(
        &ctx,
        &current_policy,
        &current_trust,
        &era2,
        &era3,
        &tips,
        &authenticated_tip_hash(&journal2, &era2),
        POST_ROTATION_OPERATION_ID,
        RecoveryState::RecoveryDesignated,
        RotationReason::Compromise,
        &hex(&[0x7A; 32]),
        b"custody-after-designate",
        |_| {},
    );
    stage_rotation_inputs(&fixture, &docs2);
    let (stderr, status) = run_reanchor(&fixture, true, true, &[]);
    assert!(
        status.success(),
        "rotation over designation failed: {stderr}"
    );
    let (stdout, status) = doctor(&fixture, false);
    assert!(!status.success());
    assert!(
        doctor_denial(&stdout).contains(DENIAL),
        "twice-rotated designation must observe at startup: {stdout}"
    );

    let _ = fs::remove_dir_all(&fixture);
}

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

/// Driver-level crash matrix: every publication boundary of the ordered
/// engine is interrupted once, and each exact-forward resume completes with
/// the identical published generation — through the real CLI, the real
/// `load_partial`/`generation_view` observation, and the real protected
/// directories, not a hand-built view.
#[test]
#[ignore = "requires root, unshare(1), and a source-built o3k binary"]
fn crash_before_and_after_every_boundary_resumes_exact_forward_driver_level() {
    let fixture = root_fixture().unwrap_or_else(|reason| panic!("{reason}"));
    let mut ctx = fresh_ctx();
    let installation = setup_fixture(&mut ctx, &fixture, true);
    let Installation {
        var,
        state_root,
        journal_dir,
        journal,
        era1,
        ..
    } = &installation;
    let journal_tip = authenticated_tip_hash(journal, era1);

    for (index, point) in CRASH_POINTS.iter().enumerate() {
        let from = era(index as u32 + 1);
        let to = era(index as u32 + 2);
        let tips = read_tips(&ctx, var);
        let current_policy = read_policy(var, &ctx.target.installation_id);
        let current_trust = read_bundle(var, &ctx.target.installation_id);
        let nonce = hex(&[0x40 + index as u8; 32]);
        let custody = format!("custody-{point}").into_bytes();
        let docs = rotation_docs(
            &ctx,
            &current_policy,
            &current_trust,
            &from,
            &to,
            &tips,
            &journal_tip,
            OPERATION_ID,
            RecoveryState::RecoveryDesignated,
            RotationReason::Compromise,
            &nonce,
            &custody,
            |_| {},
        );
        stage_rotation_inputs(&fixture, &docs);

        let (stderr, crashed) =
            run_reanchor(&fixture, true, true, &[("O3K_REANCHOR_CRASH_AT", point)]);
        let interrupted = !crashed.success() && stderr.contains("InjectedCrash");
        if interrupted {
            assert!(
                stderr.contains(point),
                "crash at {point} must name the point: {stderr}"
            );
        }
        // Feature-absent binaries complete the rotation here; the next run is
        // then the byte-identical replay, which must also succeed.
        let (stderr, status) = run_reanchor(&fixture, true, true, &[]);
        assert!(
            status.success(),
            "resume after crash at {point} must complete: {stderr}"
        );

        // The published generation is exactly the planned one.
        let tip_bytes = fs::read(state_root.join("state.json")).unwrap();
        assert_eq!(
            sha256_hex(&tip_bytes),
            sha256_hex(&docs.reanchor),
            "tip after resume at {point}"
        );
        let tip: Signed<InstallationReanchor> = decode_signed(&tip_bytes);
        assert_eq!(
            tip.payload.preserved_state, docs.preserved,
            "preserved state after resume at {point}"
        );
        assert_eq!(
            fs::read(journal_dir.join(CHECKPOINT_NAME)).unwrap(),
            docs.checkpoint.clone().unwrap(),
            "checkpoint after resume at {point}"
        );
        let consumption: RevalidationConsumption =
            decode_signed(&fs::read(state_root.join("revalidation-consumption.json")).unwrap());
        assert!(
            consumption.consumed,
            "evidence consumed after resume at {point}"
        );
        assert_eq!(consumption.nonce, nonce, "nonce bound at {point}");
        assert_eq!(
            fs::read(state_root.join("policy.json")).unwrap(),
            docs.policy,
            "policy high-water after resume at {point}"
        );
        assert_eq!(
            fs::read(journal_dir.join("unsigned-denial.marker")).unwrap(),
            MARKER_BYTES,
            "marker preserved at {point}"
        );
    }

    // Twenty rotations in, the installation still observes at startup and
    // still denies operational access; the old journal chain is intact and
    // every superseded consumption record is archived, consumed, and binds a
    // distinct nonce.
    let (stdout, status) = doctor(&fixture, false);
    assert!(!status.success());
    assert!(
        doctor_denial(&stdout).contains(DENIAL),
        "twenty-rotation installation must observe at startup: {stdout}"
    );
    assert_eq!(
        fs::read(journal_dir.join("restore-journal.json")).unwrap(),
        journal.0,
        "journal chain preserved across twenty rotations"
    );
    let mut archived_names: Vec<String> = fs::read_dir(state_root)
        .unwrap()
        .map(|entry| entry.unwrap().file_name().to_string_lossy().into_owned())
        .filter(|name| name.starts_with("revalidation-consumption-") && name.ends_with(".json"))
        .collect();
    archived_names.sort();
    assert_eq!(
        archived_names.len(),
        CRASH_POINTS.len() - 1,
        "every superseded consumption record is archived"
    );
    let mut archived_nonces = std::collections::BTreeSet::new();
    for name in &archived_names {
        let record: RevalidationConsumption =
            decode_signed(&fs::read(state_root.join(name)).unwrap());
        assert!(record.consumed, "archived consumption record {name}");
        assert!(
            archived_nonces.insert(record.nonce.clone()),
            "archived nonces must be distinct: {name}"
        );
    }

    let _ = fs::remove_dir_all(&fixture);
}

/// Consumer-level startup observation over published rotated generations,
/// with mixed-generation negative cases: each tampered combination must deny
/// startup, and restoring the bytes must observe the rotated generation
/// again.
#[test]
#[ignore = "requires root, unshare(1), and a source-built o3k binary"]
fn startup_observation_rejects_mixed_generations() {
    let fixture = root_fixture().unwrap_or_else(|reason| panic!("{reason}"));
    let mut ctx = fresh_ctx();
    let installation = setup_fixture(&mut ctx, &fixture, true);
    let Installation {
        var,
        state_root,
        journal_dir,
        journal,
        era1,
        era1_bundle,
        era1_policy,
        ..
    } = &installation;

    let era2 = era(2);
    let tips = read_tips(&ctx, var);
    let docs = rotation_docs(
        &ctx,
        era1_policy,
        era1_bundle,
        era1,
        &era2,
        &tips,
        &authenticated_tip_hash(journal, era1),
        OPERATION_ID,
        RecoveryState::RecoveryDesignated,
        RotationReason::Compromise,
        &hex(&[0x6E; 32]),
        b"custody-record",
        |_| {},
    );
    stage_rotation_inputs(&fixture, &docs);
    let (stderr, status) = run_reanchor(&fixture, true, true, &[]);
    assert!(status.success(), "uninterrupted rotation failed: {stderr}");

    let (stdout, status) = doctor(&fixture, false);
    assert!(!status.success());
    assert!(
        doctor_denial(&stdout).contains(DENIAL),
        "rotated generation must observe at startup: {stdout}"
    );

    let trust_high_water = state_root.join("trust.json");
    let fixed_policy = var.join("etc-fixture/o3k/installation-policy.json");
    let fixed_trust = var.join("etc-fixture/o3k/recovery-trust.json");
    let checkpoint = journal_dir.join(CHECKPOINT_NAME);
    let mixed_denies = |stdout: &str, label: &str| {
        assert!(
            stdout.contains(DENIED_PREFIX),
            "mixed generation at {label} must deny startup: {stdout}"
        );
    };

    // Negative 1: durable trust high-water rolled back to the prior era.
    let trust2 = fs::read(&trust_high_water).unwrap();
    fs::write(&trust_high_water, &era1_bundle.bytes).unwrap();
    let (stdout, status) = doctor(&fixture, false);
    assert!(!status.success());
    mixed_denies(&stdout, "trust high-water rollback");
    fs::write(&trust_high_water, &trust2).unwrap();
    let (stdout, status) = doctor(&fixture, false);
    assert!(!status.success());
    assert!(doctor_denial(&stdout).contains(DENIAL));

    // Negative 2: fixed policy rolled back to the prior era (with the fixed
    // trust of the current era: a cross-generation fixed pair).
    let policy2 = fs::read(&fixed_policy).unwrap();
    fs::write(&fixed_policy, &era1_policy.bytes).unwrap();
    let (stdout, status) = doctor(&fixture, false);
    assert!(!status.success());
    mixed_denies(&stdout, "fixed policy rollback");
    fs::write(&fixed_policy, &policy2).unwrap();
    let (stdout, status) = doctor(&fixture, false);
    assert!(!status.success());
    assert!(doctor_denial(&stdout).contains(DENIAL));

    // Negative 3: fixed trust rolled back while the fixed policy stays
    // current (policy/trust from different generations).
    let fixed_trust2 = fs::read(&fixed_trust).unwrap();
    fs::write(&fixed_trust, &era1_bundle.bytes).unwrap();
    let (stdout, status) = doctor(&fixture, false);
    assert!(!status.success());
    mixed_denies(&stdout, "fixed trust rollback");
    fs::write(&fixed_trust, &fixed_trust2).unwrap();
    let (stdout, status) = doctor(&fixture, false);
    assert!(!status.success());
    assert!(doctor_denial(&stdout).contains(DENIAL));

    // Negative 4: the current checkpoint replaced by the raw journal chain
    // (journal content from the prior generation in the checkpoint slot).
    let checkpoint2 = fs::read(&checkpoint).unwrap();
    fs::write(&checkpoint, &journal.0).unwrap();
    let (stdout, status) = doctor(&fixture, false);
    assert!(!status.success());
    mixed_denies(&stdout, "checkpoint/journal mix");
    fs::write(&checkpoint, &checkpoint2).unwrap();
    let (stdout, status) = doctor(&fixture, false);
    assert!(!status.success());
    assert!(doctor_denial(&stdout).contains(DENIAL));

    let _ = fs::remove_dir_all(&fixture);
}

#[test]
#[ignore = "requires root, unshare(1), and a source-built o3k binary"]
fn revocation_refresh_resumes_after_archive_and_is_repeatable() {
    let fixture = root_fixture().unwrap_or_else(|reason| panic!("{reason}"));
    let mut ctx = fresh_ctx();
    let installation = setup_fixture(&mut ctx, &fixture, true);
    let input = installation.var.join("refresh-inputs");
    fs::create_dir(&input).unwrap();
    fs::set_permissions(&input, fs::Permissions::from_mode(0o700)).unwrap();
    write_root_owned(
        &input.join("policy.json"),
        &installation.era1_policy.bytes,
        0,
        0,
        0o640,
    );
    let mut revoked = installation.era1_bundle.bundle.clone();
    let mut revocations = revoked.journal_revocations.payload.clone();
    revocations.sequence += 1;
    revocations
        .revoked_key_ids
        .push(installation.era1.journal_signer_id.clone());
    revoked.journal_revocations = decode_signed(&sign(
        &revocations,
        &installation.era1.journal_root,
        &installation.era1.journal_root_id,
    ));
    revoked.journal_revocation_sequence = revocations.sequence;
    revoked.journal_revocation_digest =
        o3k::recovery_identity::digest(&revoked.journal_revocations).unwrap();
    let revoked_bytes = o3k::recovery_identity::canonical(&revoked).unwrap();
    write_root_owned(&input.join("trust.json"), &revoked_bytes, 0, 0, 0o640);
    // Model a crash after the immutable archive publication but before CAS.
    write_root_owned(
        &installation
            .state_root
            .join(format!("trust-{}.json", installation.era1_bundle.digest)),
        &installation.era1_bundle.bytes,
        0,
        900,
        0o640,
    );
    for attempt in 0..3 {
        let (_, stderr, status) = run_in_namespace(
            &fixture,
            "{binary} recovery-trust-update --policy /var/lib/refresh-inputs/policy.json --trust /var/lib/refresh-inputs/trust.json",
            &[],
        );
        assert!(status.success(), "refresh retry {attempt} failed: {stderr}");
        assert_eq!(
            fs::read(installation.state_root.join("trust.json")).unwrap(),
            revoked_bytes
        );
    }
    let (stdout, status) = doctor(&fixture, false);
    assert!(!status.success(), "revoked active signer must deny startup");
    assert!(
        stdout.contains(DENIED_PREFIX),
        "revocation must quarantine: {stdout}"
    );
    fs::remove_dir_all(&fixture).unwrap();
}
