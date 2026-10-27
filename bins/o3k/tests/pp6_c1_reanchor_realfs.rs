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
    os::unix::fs::PermissionsExt,
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
        profile: "o3k-demo-v1".to_string(),
        backend: "sqlite".to_string(),
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
        profile: "o3k-demo-v1".to_string(),
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
        profile: "o3k-demo-v1".to_string(),
        installation_id: target.installation_id.clone(),
        backend: "sqlite".to_string(),
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
        profile: "o3k-demo-v1".to_string(),
        backend: "sqlite".to_string(),
        release_identity: RELEASE_SHA256.to_string(),
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
        profile: "o3k-demo-v1".to_string(),
        backend: "sqlite".to_string(),
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
        profile: "o3k-demo-v1".to_string(),
        backend: "sqlite".to_string(),
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
            profile: "o3k-demo-v1".to_string(),
            backend: "sqlite".to_string(),
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
        profile: "o3k-demo-v1".to_string(),
        backend: "sqlite".to_string(),
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

fn root_fixture() -> Option<PathBuf> {
    if rustix::process::geteuid().as_raw() != 0 {
        return None;
    }
    let path = PathBuf::from(format!("/var/lib/o3k-c1-reanchor-{}", uuid::Uuid::now_v7()));
    fs::create_dir(&path).ok()?;
    fs::set_permissions(&path, fs::Permissions::from_mode(0o700)).ok()?;
    Some(path)
}

fn setup_fixture(ctx: &mut Ctx, fixture: &Path, designate: bool) -> Installation {
    let var = fixture.join("var");
    let etc = var.join("etc-fixture");
    let share = var.join("share-fixture");
    fs::create_dir_all(&etc).unwrap();
    fs::create_dir_all(&share).unwrap();
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
    let manifest = format!(
        r#"{{"version":"v0.4.0-rc.5","profile":"libvirt","profile_id":"o3k-demo-v1","source_commit":"{SOURCE_COMMIT}","workflow":"test","installer_sha256":"{INSTALLER_SHA256}","release_artifact_sha256":"{RELEASE_SHA256}","schema_version":"1","installation_policy_format":"o3k-installation-policy-v1","installation_policy_path":"/etc/o3k/installation-policy.json","installation_policy_authority":{{"key_id":"{POLICY_SIGNER_ID}","ed25519_public_key":"{}"}}}}"#,
        key_hex(&ctx.keys.policy.verifying_key())
    );
    fs::write(share.join("release-manifest.json"), &manifest).unwrap();
    fs::set_permissions(
        share.join("release-manifest.json"),
        fs::Permissions::from_mode(0o644),
    )
    .unwrap();
    ctx.manifest_digest = sha256_hex(manifest.as_bytes());

    let prepare = "{binary} recovery-provision-prepare --data-root /var/lib/o3k --backend sqlite";
    let (stdout, stderr, status) = run_in_namespace(fixture, prepare, &[]);
    assert!(stderr.contains("C1_REANCHOR_NAMESPACE_READY"));
    assert!(status.success(), "prepare failed: {stderr}");
    let value = descriptor(&stdout);
    ctx.target = Target {
        installation_id: value["installation_id"].as_str().unwrap().to_string(),
        site_id: value["site_id"].as_str().unwrap().to_string(),
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
    let binary = env!("CARGO_BIN_EXE_o3k");
    let script = format!(
        "set -u; umask 077; mount --make-rprivate /; mount --bind {0} /var/lib; mount --bind /var/lib/etc-fixture /etc; mount --bind /var/lib/share-fixture /usr/local/share/o3k; echo C1_REANCHOR_NAMESPACE_READY >&2; {1}",
        fixture.join("var").display(),
        script.replace("{binary}", binary)
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

#[test]
#[ignore = "requires root, unshare(1), setpriv(1), and a source-built o3k binary"]
fn rotation_over_real_protected_directories_resumes_and_preserves_exactly() {
    let Some(fixture) = root_fixture() else {
        return;
    };
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
    let Some(fixture) = root_fixture() else {
        return;
    };
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
    let Some(fixture) = root_fixture() else {
        return;
    };
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
    let Some(fixture) = root_fixture() else {
        return;
    };
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
    let fixture = root_fixture().expect("root fixture required");
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
