//! C1.1 authenticated installation-policy/trust re-anchor and journal
//! checkpoint (SPEC-0050 §7.3, ADR-0189 C1.1).
//!
//! Rotation is a root-authorized installer operation, never a controller,
//! listener, session, lease, provider, quarantine, or activation authority.
//! The three signed formats are RFC 8785 canonical Ed25519 documents with
//! strict envelopes; every digest is the exact SHA-256 of the referenced
//! canonical byte encoding. Private offline keys never enter this module:
//! only detached signed bytes are verified, and every error is a static,
//! secret-safe string.

use ed25519_dalek::VerifyingKey;
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};

use crate::recovery_identity::{
    self as identity, InstallationPolicy, InstallationState, RecoveryState, Signed, TrustBundle,
};
use crate::recovery_trust::VerifiedTrust;
use crate::restore_journal::{self, AuthenticatedJournal, RestorePhase};
use crate::upgrade::release_identity::BackupReleaseIdentity;

pub const REANCHOR_FORMAT: &str = "o3k-installation-reanchor-v1";
pub const CHECKPOINT_FORMAT: &str = "o3k-restore-journal-checkpoint-v1";
pub const REVALIDATION_FORMAT: &str = "o3k-recovery-revalidation-v1";
pub const CONSUMPTION_FORMAT: &str = "o3k-recovery-revalidation-consumption-v1";
/// Exact validity bound for compromise revalidation evidence
/// (`expires_at = issued_at + 300`; SPEC-0050 §7.3.6).
pub const REVALIDATION_VALIDITY_SECONDS: i64 = 300;

pub const CHECKPOINT_NAME: &str = "restore-journal-checkpoint.json";
pub const CONSUMPTION_NAME: &str = "revalidation-consumption.json";
pub const STAGED_POLICY_NAME: &str = "staged-policy.json";
pub const STAGED_TRUST_NAME: &str = "staged-trust.json";
pub const STAGED_REANCHOR_NAME: &str = "staged-reanchor.json";
pub const STAGED_CHECKPOINT_NAME: &str = "staged-checkpoint.json";
pub const STAGED_PRIOR_POLICY_NAME: &str = "staged-prior-policy.json";
pub const STAGED_PRIOR_TRUST_NAME: &str = "staged-prior-trust.json";
pub const PENDING_REQUEST_NAME: &str = "restore-signing-request.json";
pub const STATE_NAME: &str = "state.json";
pub const POLICY_HIGH_WATER_NAME: &str = "policy.json";
pub const TRUST_HIGH_WATER_NAME: &str = "trust.json";
pub const FIXED_POLICY_NAME: &str = "installation-policy.json";
pub const FIXED_TRUST_NAME: &str = "recovery-trust.json";
pub const JOURNAL_CHAIN_NAME: &str = "restore-journal.json";

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ReanchorError {
    NotRoot,
    Quiescence(&'static str),
    Malformed(&'static str),
    Signature(&'static str),
    Binding(&'static str),
    Trust(&'static str),
    Sequence(&'static str),
    Equivocation(&'static str),
    Conflicting(&'static str),
    Evidence(&'static str),
    Persistence(&'static str),
    InjectedCrash(&'static str),
}

impl std::fmt::Display for ReanchorError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{self:?}")
    }
}
impl std::error::Error for ReanchorError {}

/// Per-purpose revocation high-water: root ID, sequence, and the exact
/// SHA-256 of the complete canonical signed revocation document.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct RevocationHighWater {
    pub root_id: String,
    pub sequence: u64,
    pub document_digest: String,
}

fn revocation_high_water(
    doc: &Signed<identity::RevocationDocument>,
) -> Result<RevocationHighWater, ReanchorError> {
    Ok(RevocationHighWater {
        root_id: doc.envelope.signer_key_id.clone(),
        sequence: doc.payload.sequence,
        document_digest: identity::digest(doc)
            .map_err(|_| ReanchorError::Malformed("revocation digest"))?,
    })
}

#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "lowercase")]
pub enum RotationReason {
    Routine,
    Compromise,
}

/// R — the installation-policy-authority-signed re-anchor record. It is a
/// distinct record kind in the same state sequence chain: it changes no state
/// value and is never signed by the journal authority.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct InstallationReanchor {
    pub format: String,
    pub installation_id: String,
    pub site_id: String,
    pub profile: String,
    pub backend: String,
    pub preserved_state: RecoveryState,
    pub sequence: u64,
    pub prior_record_digest: String,
    pub prior_policy_revision: u64,
    pub prior_policy_digest: String,
    pub new_policy_revision: u64,
    pub new_policy_digest: String,
    pub prior_trust_bundle_digest: String,
    pub new_trust_bundle_digest: String,
    pub prior_journal_revocation: RevocationHighWater,
    pub prior_evidence_revocation: RevocationHighWater,
    pub new_journal_revocation: RevocationHighWater,
    pub new_evidence_revocation: RevocationHighWater,
    /// Digest of C; null only for a preserved `NEVER_RECOVERED` state.
    pub checkpoint_digest: Option<String>,
    /// Digest of the compromise revalidation evidence; null for routine.
    pub recovery_revalidation_digest: Option<String>,
    pub operation_id: Option<String>,
    pub artifact_sha256: Option<String>,
    pub recovery_directory_digest: Option<String>,
    pub terminal_journal_digest: Option<String>,
    pub terminal_evidence_digest: Option<String>,
    pub target_device: u64,
    pub target_inode: u64,
    pub signer_manifest_digest: String,
}

/// C — the new-journal-authority-signed journal checkpoint. Journal v1 only;
/// it is not a phase and performs no phase transition. It binds the prior
/// state tip S0 (never R), the old journal tip, and never binds digest(R).
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct JournalCheckpoint {
    pub format: String,
    pub installation_id: String,
    pub site_id: String,
    pub profile: String,
    pub backend: String,
    pub sequence: u64,
    pub prior_record_digest: String,
    pub prior_checkpoint_digest: Option<String>,
    pub prior_state_tip_digest: String,
    pub journal_directory: String,
    pub journal_device: u64,
    pub journal_inode: u64,
    pub operation_id: String,
    pub artifact_sha256: String,
    pub phase: RestorePhase,
    pub old_journal_key_id: String,
    pub old_journal_certificate_serial: String,
    pub new_journal_key_id: String,
    pub new_journal_certificate_serial: String,
    pub old_journal_revocation: RevocationHighWater,
    pub new_journal_revocation: RevocationHighWater,
    pub old_evidence_revocation: RevocationHighWater,
    pub new_evidence_revocation: RevocationHighWater,
    pub rotation_reason: RotationReason,
    pub recovery_revalidation_digest: Option<String>,
}

/// Compromise-recovery revalidation evidence, signed by the new
/// recovery-evidence authority. It names only the prior tips it reviewed so
/// no circular digest bindings arise; R and C name its digest.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct RecoveryRevalidation {
    pub format: String,
    pub installation_id: String,
    pub site_id: String,
    pub profile: String,
    pub backend: String,
    pub operation_id: String,
    pub artifact_sha256: String,
    pub target_device: u64,
    pub target_inode: u64,
    pub old_journal_root_id: String,
    pub new_journal_root_id: String,
    pub old_journal_key_id: String,
    pub old_journal_certificate_serial: String,
    pub new_journal_key_id: String,
    pub new_journal_certificate_serial: String,
    pub old_evidence_root_id: String,
    pub new_evidence_root_id: String,
    pub old_evidence_key_id: String,
    pub old_evidence_certificate_serial: String,
    pub new_evidence_key_id: String,
    pub new_evidence_certificate_serial: String,
    pub prior_state_tip_digest: String,
    pub prior_journal_tip_digest: String,
    pub prior_checkpoint_digest: Option<String>,
    pub old_policy_digest: String,
    pub new_policy_digest: String,
    pub old_trust_bundle_digest: String,
    pub new_trust_bundle_digest: String,
    pub observed_target_device: u64,
    pub observed_target_inode: u64,
    pub custody_record_digest: String,
    pub recovery_quorum_event_id: String,
    pub nonce: String,
    pub issued_at: i64,
    pub expires_at: i64,
    pub exact_tips_reviewed: bool,
}

/// Durable single-use consumption record. It binds the evidence digest, the
/// evidence nonce, and the exact R/C pair before acceptance and is marked
/// consumed only after the full authenticated publication completes. It lives
/// in the protected state root, is cross-checked against the signed R and C on
/// every load, and a consumed record is retained under a content-addressed
/// archive name when a later compromise rotation publishes a new record, so a
/// nonce can never authorize two different evidence documents.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct RevalidationConsumption {
    pub format: String,
    pub evidence_digest: String,
    pub reanchor_digest: String,
    pub checkpoint_digest: String,
    pub nonce: String,
    pub consumed: bool,
}

/// Content-addressed archive name for a superseded consumption record
/// (`revalidation-consumption-<evidence digest>.json`).
pub fn consumption_archive_name(evidence_digest: &str) -> String {
    format!("revalidation-consumption-{evidence_digest}.json")
}

pub fn sha256_hex(bytes: &[u8]) -> String {
    hex::encode(Sha256::digest(bytes))
}

fn decode_signed<T: serde::de::DeserializeOwned + Serialize>(
    bytes: &[u8],
) -> Result<T, ReanchorError> {
    identity::decode_canonical(bytes)
        .map_err(|_| ReanchorError::Malformed("non-canonical document"))
}

fn verify_signed_document<T: serde::de::DeserializeOwned + Serialize>(
    bytes: &[u8],
    format: &'static str,
    key_id: &str,
    key: &VerifyingKey,
    error: ReanchorError,
) -> Result<T, ReanchorError> {
    identity::verify_signed(bytes, format, key_id, key).map_err(|e| match e {
        identity::IdentityError::InvalidSignature => error,
        identity::IdentityError::BindingMismatch => {
            ReanchorError::Signature("signed document signer or purpose does not match")
        }
        _ => ReanchorError::Malformed("non-canonical signed document"),
    })
}

fn hex64(value: &str) -> bool {
    value.len() == 64
        && value
            .bytes()
            .all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(&b))
}

fn decode_key32(value: &str) -> Result<VerifyingKey, ReanchorError> {
    let bytes: [u8; 32] = hex::decode(value)
        .map_err(|_| ReanchorError::Trust("recovery authority key is malformed"))?
        .try_into()
        .map_err(|_| ReanchorError::Trust("recovery authority key length is invalid"))?;
    VerifyingKey::from_bytes(&bytes)
        .map_err(|_| ReanchorError::Trust("recovery authority key is invalid"))
}

// ---------------------------------------------------------------------------
// Byte-level view of one installed generation (no filesystem participation).
// ---------------------------------------------------------------------------

pub struct GenerationView<'a> {
    pub manifest_bytes: &'a [u8],
    pub policy_bytes: &'a [u8],
    /// The durable policy high-water (state-root `policy.json`). On the first
    /// attempt this equals the fixed policy; mid-resume it may still hold the
    /// prior generation's bytes.
    pub policy_high_water_bytes: Option<&'a [u8]>,
    /// The fixed installed bundle (`/etc/o3k/recovery-trust.json`).
    pub fixed_bundle_bytes: &'a [u8],
    /// The durable trust high-water (state-root `trust.json`).
    pub trust_high_water_bytes: &'a [u8],
    /// Exact signed pending R, durably staged only after outgoing verification.
    pub pending_reanchor_bytes: Option<&'a [u8]>,
    /// Inert staged prior-generation bytes (never read by startup verifiers).
    pub staged_prior_policy_bytes: Option<&'a [u8]>,
    pub staged_prior_trust_bytes: Option<&'a [u8]>,
    pub state_tip_bytes: &'a [u8],
    pub journal_bytes: Option<&'a [u8]>,
    pub checkpoint_bytes: Option<&'a [u8]>,
    pub consumption_record_bytes: Option<&'a [u8]>,
    /// True when an unsigned or in-flight journal signing request exists in
    /// the journal directory; rotation is denied at quiescence.
    pub pending_signing_request_present: bool,
    pub now: i64,
}

/// Content-named archive lookup (`state-<digest>.json`, `policy-<digest>.json`,
/// `trust-<digest>.json`, `checkpoint-<digest>.json`).
pub trait ArchiveLookup {
    fn read_archive(&self, name: &str) -> Option<Vec<u8>>;
}

impl<F: Fn(&str) -> Option<Vec<u8>>> ArchiveLookup for F {
    fn read_archive(&self, name: &str) -> Option<Vec<u8>> {
        self(name)
    }
}

pub struct ObservedJournalTip {
    pub sequence: u64,
    /// Old-era transition tip: the authenticated signed hash; rotated tip:
    /// the exact SHA-256 of the checkpoint bytes.
    pub tip_hash: String,
    pub phase: RestorePhase,
    pub checkpoint_digest: Option<String>,
    pub base_chain: Option<AuthenticatedJournal>,
}

pub struct ObservedGeneration {
    pub policy: InstallationPolicy,
    pub policy_digest: String,
    /// The fresh current-era trust; None on an exact-forward resume, where
    /// old-era freshness is not re-required (the first attempt verified it).
    pub trust: Option<VerifiedTrust>,
    pub trust_bundle: TrustBundle,
    /// Exact SHA-256 of the current trust high-water bytes (the prior trust
    /// binding for a planned rotation).
    pub trust_bundle_digest: String,
    pub tip_sequence: u64,
    pub tip_digest: String,
    pub tip_is_reanchor: bool,
    pub preserved_state: RecoveryState,
    pub preserved_operation_id: Option<String>,
    pub preserved_artifact_sha256: Option<String>,
    pub preserved_recovery_directory_digest: Option<String>,
    pub preserved_terminal_journal_digest: Option<String>,
    pub preserved_terminal_evidence_digest: Option<String>,
    /// None for a preserved `NEVER_RECOVERED` state.
    pub journal: Option<ObservedJournalTip>,
    /// The era-1 base disposition record: the tip for a disposition
    /// generation, or the record the oldest re-anchor preserves.
    pub base_disposition: Option<InstallationState>,
}

struct ManifestAuthority {
    key_id: String,
    key: VerifyingKey,
    digest: String,
}

fn manifest_authority(manifest_bytes: &[u8]) -> Result<ManifestAuthority, ReanchorError> {
    let authority =
        BackupReleaseIdentity::c1_authority_from_manifest(manifest_bytes).map_err(|_| {
            ReanchorError::Trust("release manifest does not authenticate a C1 policy authority")
        })?;
    let key = decode_key32(&authority.ed25519_public_key)
        .map_err(|_| ReanchorError::Trust("release policy authority key is invalid"))?;
    Ok(ManifestAuthority {
        key_id: authority.key_id,
        key,
        digest: sha256_hex(manifest_bytes),
    })
}

fn verify_current_policy(
    view: &GenerationView<'_>,
) -> Result<(InstallationPolicy, String, ManifestAuthority), ReanchorError> {
    let authority = manifest_authority(view.manifest_bytes)?;
    let policy: InstallationPolicy = verify_signed_document(
        view.policy_bytes,
        "o3k-installation-policy-v1",
        &authority.key_id,
        &authority.key,
        ReanchorError::Signature("installation policy signature is invalid"),
    )?;
    identity::verify_policy(&policy, &authority.key_id)
        .map_err(|_| ReanchorError::Binding("installation policy binding is invalid"))?;
    let digest = sha256_hex(view.policy_bytes);
    Ok((policy, digest, authority))
}

/// The installed trust high-water verified against the fixed bundle anchors.
/// This is the C1 freshness gate: stale, expired, revoked, equivocated, or
/// rolled-back current trust fails closed.
fn verify_current_trust(
    view: &GenerationView<'_>,
    policy: &InstallationPolicy,
    historical: bool,
) -> Result<(VerifiedTrust, TrustBundle), ReanchorError> {
    if sha256_hex(view.fixed_bundle_bytes) != policy.trust_bundle_digest {
        return Err(ReanchorError::Trust(
            "installed recovery trust digest changed",
        ));
    }
    // The installed bundle is a bare canonical document: its authenticity is
    // the policy digest binding plus the root-signed members inside it.
    let fixed: TrustBundle = decode_signed(view.fixed_bundle_bytes)
        .map_err(|_| ReanchorError::Malformed("installed recovery trust is malformed"))?;
    let current: TrustBundle = decode_signed(view.trust_high_water_bytes)
        .map_err(|_| ReanchorError::Malformed("durable recovery trust state is malformed"))?;
    if current.installation_id != policy.installation_id
        || current.site_id != policy.site_id
        || current.profile != policy.profile
        || current.backend != policy.backend
        || current.journal_root_key_id != policy.journal_trust_root_id
        || current.journal_root_public_key != policy.journal_trust_root_public_key
        || current.evidence_root_key_id != policy.evidence_trust_root_id
        || current.evidence_root_public_key != policy.evidence_trust_root_public_key
    {
        return Err(ReanchorError::Trust(
            "installed recovery trust scope is invalid",
        ));
    }
    let journal_root = decode_key32(&policy.journal_trust_root_public_key)?;
    let evidence_root = decode_key32(&policy.evidence_trust_root_public_key)?;
    let jh = Some((
        fixed.journal_revocations.payload.sequence,
        fixed.journal_revocation_digest.as_str(),
    ));
    let eh = Some((
        fixed.evidence_revocations.payload.sequence,
        fixed.evidence_revocation_digest.as_str(),
    ));
    let trust = if historical {
        crate::recovery_trust::verify_historical_trust(
            current.clone(),
            &journal_root,
            &evidence_root,
            jh,
            eh,
        )
    } else {
        crate::recovery_trust::verify_trust_bundle(
            current.clone(),
            &journal_root,
            &evidence_root,
            view.now,
            jh,
            eh,
        )
    }
    .map_err(|_| {
        ReanchorError::Trust(
            "installed recovery authority is stale, expired, revoked or conflicting",
        )
    })?;
    Ok((trust, current))
}

fn certificate_scope_valid(cert: &identity::TrustCertificate, bundle: &TrustBundle) -> bool {
    cert.site_id == bundle.site_id
        && cert.installation_id == bundle.installation_id
        && cert.profile == bundle.profile
        && cert.backend == bundle.backend
}

/// Historical journal signer key resolved from a retained era bundle. The
/// certificate signature is verified against the bundle's own journal root,
/// so an era bundle cannot mint signer keys for itself. No freshness is
/// required: authenticity of the era bundle itself is carried by the
/// authenticated R bindings, and a retired signer grants no new authority.
fn era_journal_key(bundle: &TrustBundle) -> Result<(String, VerifyingKey), ReanchorError> {
    let cert = &bundle.journal_certificate.payload;
    let root = decode_key32(&bundle.journal_root_public_key)?;
    let _: identity::TrustCertificate = identity::verify_signed(
        &identity::canonical(&bundle.journal_certificate).map_err(|_| {
            ReanchorError::Malformed("era journal certificate cannot be canonicalized")
        })?,
        "o3k-journal-authority-v1",
        &bundle.journal_root_key_id,
        &root,
    )
    .map_err(|_| ReanchorError::Trust("era journal certificate is not root-signed"))?;
    if cert.format != "o3k-journal-authority-v1"
        || cert.purpose != "restore_journal"
        || !certificate_scope_valid(cert, bundle)
        || cert.issuer != bundle.journal_root_key_id
    {
        return Err(ReanchorError::Trust(
            "era journal signer certificate is revoked or invalid",
        ));
    }
    let key = decode_key32(&cert.public_key)?;
    Ok((cert.key_id.clone(), key))
}

fn era_evidence_key(bundle: &TrustBundle) -> Result<(String, VerifyingKey), ReanchorError> {
    let cert = &bundle.evidence_certificate.payload;
    let root = decode_key32(&bundle.evidence_root_public_key)?;
    let _: identity::TrustCertificate = identity::verify_signed(
        &identity::canonical(&bundle.evidence_certificate).map_err(|_| {
            ReanchorError::Malformed("era evidence certificate cannot be canonicalized")
        })?,
        "o3k-evidence-authority-v1",
        &bundle.evidence_root_key_id,
        &root,
    )
    .map_err(|_| ReanchorError::Trust("era evidence certificate is not root-signed"))?;
    if cert.format != "o3k-evidence-authority-v1"
        || cert.purpose != "recovery_evidence"
        || !certificate_scope_valid(cert, bundle)
        || cert.issuer != bundle.evidence_root_key_id
        || bundle
            .evidence_revocations
            .payload
            .revoked_serials
            .iter()
            .any(|s| s == &cert.serial)
        || bundle
            .evidence_revocations
            .payload
            .revoked_key_ids
            .iter()
            .any(|k| k == &cert.key_id)
    {
        return Err(ReanchorError::Trust(
            "era evidence signer certificate is revoked or invalid",
        ));
    }
    let key = decode_key32(&cert.public_key)?;
    Ok((cert.key_id.clone(), key))
}

fn journal_identity_digest(policy: &InstallationPolicy) -> Result<String, ReanchorError> {
    identity::digest(&(
        policy.journal_directory.as_str(),
        policy.journal_device,
        policy.journal_inode,
    ))
    .map_err(|_| ReanchorError::Malformed("recovery directory identity cannot be canonicalized"))
}

// ---------------------------------------------------------------------------
// Disposition-generation observation (the frozen C1 path, byte-level).
// ---------------------------------------------------------------------------

/// Authenticates a generation whose state tip is a C1 disposition record.
/// This is the byte-level equivalent of the startup load path; it never
/// applies the startup gate (RELEASED stays a denial decision for callers).
pub fn observe_disposition_generation(
    view: &GenerationView<'_>,
    archives: &dyn ArchiveLookup,
) -> Result<ObservedGeneration, ReanchorError> {
    observe_disposition_generation_with_history(view, archives, false)
}

fn observe_disposition_generation_with_history(
    view: &GenerationView<'_>,
    archives: &dyn ArchiveLookup,
    historical: bool,
) -> Result<ObservedGeneration, ReanchorError> {
    let (policy, policy_digest, authority) = verify_current_policy(view)?;
    let (trust, trust_bundle) = verify_current_trust(view, &policy, historical)?;
    let signed: Signed<InstallationState> = decode_signed(view.state_tip_bytes)
        .map_err(|_| ReanchorError::Malformed("installation state is malformed"))?;
    if signed.payload.format != "o3k-installation-state-v1" {
        return Err(ReanchorError::Malformed(
            "installation state record kind is unknown",
        ));
    }
    let tip_digest = sha256_hex(view.state_tip_bytes);
    let (
        base_disposition,
        preserved_terminal_journal_digest,
        preserved_terminal_evidence_digest,
        journal,
    ) = match signed.payload.state {
        RecoveryState::NeverRecovered => {
            let verified: InstallationState = verify_signed_document(
                view.state_tip_bytes,
                "o3k-installation-state-v1",
                &authority.key_id,
                &authority.key,
                ReanchorError::Signature("installation state signature is invalid"),
            )?;
            identity::verify_initial_state_transition(None, &verified, &policy).map_err(|_| {
                ReanchorError::Sequence("installation state predecessor is invalid")
            })?;
            if verified.policy_digest != policy_digest {
                return Err(ReanchorError::Binding(
                    "installation state policy digest changed",
                ));
            }
            // A never-recovered installation has no journal dependency. A
            // recovery operator may publish the new operation's signed journal
            // before requesting designation; startup ignores it here and the
            // designation transition authenticates it before persistence.
            (Some(verified), None, None, None)
        }
        RecoveryState::RecoveryDesignated | RecoveryState::Released => {
            let (chain, current) = verify_disposition_chain(
                view.state_tip_bytes,
                &policy,
                policy_digest.as_str(),
                &authority,
                &trust,
                view.journal_bytes,
                archives,
            )?;
            if view.checkpoint_bytes.is_some() {
                return Err(ReanchorError::Binding(
                    "journal checkpoint without a re-anchor record denies startup",
                ));
            }
            (
                Some(current.clone()),
                current.terminal_journal_digest.clone(),
                current.evidence_digest.clone(),
                Some(ObservedJournalTip {
                    sequence: chain.sequence(),
                    tip_hash: chain.signed_hash().to_string(),
                    phase: chain.phase(),
                    checkpoint_digest: None,
                    base_chain: Some(chain),
                }),
            )
        }
    };
    let trust_bundle_digest = sha256_hex(view.trust_high_water_bytes);
    Ok(observed(
        policy,
        policy_digest,
        Some(trust),
        trust_bundle,
        trust_bundle_digest,
        signed.payload.sequence,
        tip_digest,
        false,
        signed.payload.state,
        signed.payload.operation_id.clone(),
        signed.payload.artifact_sha256.clone(),
        signed.payload.recovery_directory_digest.clone(),
        preserved_terminal_journal_digest,
        preserved_terminal_evidence_digest,
        journal,
        base_disposition,
    ))
}

#[allow(clippy::too_many_arguments)]
fn observed(
    policy: InstallationPolicy,
    policy_digest: String,
    trust: Option<VerifiedTrust>,
    trust_bundle: TrustBundle,
    trust_bundle_digest: String,
    tip_sequence: u64,
    tip_digest: String,
    tip_is_reanchor: bool,
    preserved_state: RecoveryState,
    preserved_operation_id: Option<String>,
    preserved_artifact_sha256: Option<String>,
    preserved_recovery_directory_digest: Option<String>,
    preserved_terminal_journal_digest: Option<String>,
    preserved_terminal_evidence_digest: Option<String>,
    journal: Option<ObservedJournalTip>,
    base_disposition: Option<InstallationState>,
) -> ObservedGeneration {
    ObservedGeneration {
        policy,
        policy_digest,
        trust,
        trust_bundle,
        trust_bundle_digest,
        tip_sequence,
        tip_digest,
        tip_is_reanchor,
        preserved_state,
        preserved_operation_id,
        preserved_artifact_sha256,
        preserved_recovery_directory_digest,
        preserved_terminal_journal_digest,
        preserved_terminal_evidence_digest,
        journal,
        base_disposition,
    }
}

/// Verifies a re-anchor document against the release-manifest-authenticated
/// installation-policy authority and returns the record. Startup and
/// designation chain walks use this to authenticate a re-anchor chain link.
pub(crate) fn verify_reanchor_record(
    bytes: &[u8],
    manifest_bytes: &[u8],
) -> Result<InstallationReanchor, ReanchorError> {
    let authority = manifest_authority(manifest_bytes)?;
    Ok(verify_reanchor_document(bytes, &authority)?.record)
}

/// A chain cursor: an in-era disposition record or a re-anchor record. A
/// disposition after rotation transitions from the preserved value of the
/// re-anchor tip, so the walk below both kinds must authenticate each link.
#[allow(clippy::large_enum_variant)]
enum ChainCursor {
    State(InstallationState),
    Reanchor(InstallationReanchor),
}

impl ChainCursor {
    fn sequence(&self) -> u64 {
        match self {
            ChainCursor::State(state) => state.sequence,
            ChainCursor::Reanchor(record) => record.sequence,
        }
    }
    fn prior_digest(&self) -> &str {
        match self {
            ChainCursor::State(state) => state.prior_record_digest.as_str(),
            ChainCursor::Reanchor(record) => record.prior_record_digest.as_str(),
        }
    }
    fn view(&self) -> identity::StateTipView<'_> {
        match self {
            ChainCursor::State(state) => identity::state_tip_view(state),
            ChainCursor::Reanchor(record) => identity::StateTipView {
                sequence: record.sequence,
                state: record.preserved_state,
                policy_digest: record.new_policy_digest.as_str(),
                operation_id: record.operation_id.as_deref(),
                artifact_sha256: record.artifact_sha256.as_deref(),
                trust_bundle_digest: None,
                recovery_directory_digest: record.recovery_directory_digest.as_deref(),
            },
        }
    }
}

/// Verifies a complete disposition chain inside the current era: the tip
/// record, the monotonic predecessor chain back to the era's initial
/// policy-authority-signed `NEVER_RECOVERED` record, and the v1 journal chain
/// for the designated/released operation. Predecessors may be in-era
/// disposition records (journal-signed) or re-anchor records (policy-authority
/// signed): a designation after rotation transitions from the preserved value
/// of the re-anchor tip, and a re-anchor link's authenticity is its verified
/// signature plus its binding of the authenticated policy digest.
fn verify_disposition_chain(
    tip_bytes: &[u8],
    policy: &InstallationPolicy,
    policy_digest: &str,
    authority: &ManifestAuthority,
    trust: &VerifiedTrust,
    journal_bytes: Option<&[u8]>,
    archives: &dyn ArchiveLookup,
) -> Result<(AuthenticatedJournal, InstallationState), ReanchorError> {
    let signed: Signed<InstallationState> = decode_signed(tip_bytes)
        .map_err(|_| ReanchorError::Malformed("installation state is malformed"))?;
    let signer = signed.envelope.signer_key_id.clone();
    let signer_key = trust.journal_key(&signer).ok_or(ReanchorError::Trust(
        "installation state signer is unknown or revoked",
    ))?;
    let tip: InstallationState = verify_signed_document(
        tip_bytes,
        "o3k-installation-state-v1",
        &signer,
        signer_key,
        ReanchorError::Signature("installation state signature is invalid"),
    )?;
    // Walk predecessors back to the era's initial record: sequence 1 names
    // the initial record; a RELEASED tip chains through the designated
    // record; a disposition after rotation chains through the re-anchor tip.
    let mut current = ChainCursor::State(tip);
    loop {
        let previous_bytes = archives
            .read_archive(&format!("state-{}.json", current.prior_digest()))
            .ok_or(ReanchorError::Sequence(
                "installation state predecessor is missing",
            ))?;
        if sha256_hex(&previous_bytes) != current.prior_digest() {
            return Err(ReanchorError::Sequence(
                "installation state predecessor digest changed",
            ));
        }
        let previous = if current.sequence() == 1 {
            // The initial record is always policy-authority signed.
            let initial: InstallationState = verify_signed_document(
                &previous_bytes,
                "o3k-installation-state-v1",
                &authority.key_id,
                &authority.key,
                ReanchorError::Signature("installation initial state signature is invalid"),
            )?;
            identity::verify_initial_state_transition(None, &initial, policy).map_err(|_| {
                ReanchorError::Sequence("installation initial predecessor is invalid")
            })?;
            ChainCursor::State(initial)
        } else {
            let previous_envelope: Signed<serde_json::Value> = decode_signed(&previous_bytes)
                .map_err(|_| {
                    ReanchorError::Malformed("installation state predecessor is malformed")
                })?;
            match previous_envelope
                .payload
                .get("format")
                .and_then(serde_json::Value::as_str)
            {
                Some(REANCHOR_FORMAT) => ChainCursor::Reanchor(
                    verify_reanchor_document(&previous_bytes, authority)?.record,
                ),
                Some("o3k-installation-state-v1") => {
                    let previous_signed: Signed<InstallationState> = decode_signed(&previous_bytes)
                        .map_err(|_| ReanchorError::Malformed("installation state is malformed"))?;
                    let previous_signer = previous_signed.envelope.signer_key_id.clone();
                    let previous_key =
                        trust
                            .journal_key(&previous_signer)
                            .ok_or(ReanchorError::Trust(
                                "installation state signer is unknown or revoked",
                            ))?;
                    ChainCursor::State(verify_signed_document(
                        &previous_bytes,
                        "o3k-installation-state-v1",
                        &previous_signer,
                        previous_key,
                        ReanchorError::Signature("installation state signature is invalid"),
                    )?)
                }
                _ => {
                    return Err(ReanchorError::Malformed(
                        "installation state predecessor kind is unknown",
                    ));
                }
            }
        };
        match &current {
            ChainCursor::State(record) => {
                identity::verify_tip_transition(
                    Some(previous.view()),
                    Some(record.prior_record_digest.as_str()),
                    record,
                    policy,
                )
                .map_err(|_| {
                    ReanchorError::Sequence("installation disposition predecessor is invalid")
                })?;
            }
            ChainCursor::Reanchor(record) => {
                // A re-anchor link changes no state value: its authenticity is
                // the verified policy-authority signature plus its binding of
                // the authenticated policy digest.
                if record.new_policy_digest != policy_digest {
                    return Err(ReanchorError::Binding(
                        "re-anchor chain link does not bind the authenticated policy",
                    ));
                }
            }
        }
        // A policy-authority-signed R is the authenticated boundary of this
        // era. Its predecessor belongs to an older policy and signer era;
        // interpreting that history under the current policy is invalid.
        let reached_boundary = previous.sequence() == 0
            || matches!(&previous, ChainCursor::Reanchor(record) if record.new_policy_digest == policy_digest);
        current = previous;
        if reached_boundary {
            break;
        }
    }
    match &current {
        ChainCursor::State(base)
            if base.sequence == 0 && base.state == RecoveryState::NeverRecovered => {}
        ChainCursor::Reanchor(record) if record.new_policy_digest == policy_digest => {}
        _ => {
            return Err(ReanchorError::Sequence(
                "disposition chain does not reach the initial record",
            ));
        }
    }
    // `current` is now the initial record; recover the tip values by re-reading
    // the tip bytes (the walk consumed them into `current`).
    let tip_signed: Signed<InstallationState> = decode_signed(tip_bytes)
        .map_err(|_| ReanchorError::Malformed("installation state is malformed"))?;
    let tip = tip_signed.payload;
    if tip.policy_digest != policy_digest
        || tip.trust_bundle_digest.as_deref() != Some(policy.trust_bundle_digest.as_str())
        || journal_identity_digest(policy).ok().as_deref()
            != tip.recovery_directory_digest.as_deref()
    {
        return Err(ReanchorError::Binding(
            "installation designation trust or directory binding changed",
        ));
    }
    let journal_bytes = journal_bytes.ok_or(ReanchorError::Binding(
        "recovery journal is unsafe or unavailable",
    ))?;
    let operation_id = tip
        .operation_id
        .as_deref()
        .ok_or(ReanchorError::Binding("recovery operation is missing"))?;
    let artifact = tip
        .artifact_sha256
        .as_deref()
        .ok_or(ReanchorError::Binding("recovery artifact is missing"))?;
    let chain = restore_journal::authenticate_installed_chain(
        journal_bytes,
        policy,
        trust,
        operation_id
            .parse()
            .map_err(|_| ReanchorError::Binding("recovery operation is invalid"))?,
        artifact,
    )
    .map_err(|_| {
        ReanchorError::Trust("recovery journal is unauthenticated or conflicts with designation")
    })?;
    Ok((chain, tip))
}

// ---------------------------------------------------------------------------
// Rotated-generation authentication (state tip is R).
// ---------------------------------------------------------------------------

#[derive(Debug, Clone)]
struct ReanchorTip {
    record: InstallationReanchor,
    digest: String,
}

fn verify_reanchor_document(
    bytes: &[u8],
    authority: &ManifestAuthority,
) -> Result<ReanchorTip, ReanchorError> {
    let record: InstallationReanchor = verify_signed_document(
        bytes,
        REANCHOR_FORMAT,
        &authority.key_id,
        &authority.key,
        ReanchorError::Signature("installation re-anchor signature is invalid"),
    )?;
    Ok(ReanchorTip {
        digest: sha256_hex(bytes),
        record,
    })
}

fn verify_checkpoint_document(
    bytes: &[u8],
    bundle: &TrustBundle,
) -> Result<JournalCheckpoint, ReanchorError> {
    let (key_id, key) = era_journal_key(bundle)?;
    let checkpoint: JournalCheckpoint = verify_signed_document(
        bytes,
        CHECKPOINT_FORMAT,
        &key_id,
        &key,
        ReanchorError::Signature("journal checkpoint signature is invalid"),
    )?;
    Ok(checkpoint)
}

fn verify_revalidation_document(
    bytes: &[u8],
    bundle: &TrustBundle,
) -> Result<RecoveryRevalidation, ReanchorError> {
    let (key_id, key) = era_evidence_key(bundle)?;
    let evidence: RecoveryRevalidation = verify_signed_document(
        bytes,
        REVALIDATION_FORMAT,
        &key_id,
        &key,
        ReanchorError::Signature("recovery revalidation signature is invalid"),
    )?;
    Ok(evidence)
}

struct EraBundle {
    policy: InstallationPolicy,
    policy_digest: String,
    bundle: TrustBundle,
    bundle_digest: String,
}

fn load_era(
    archives: &dyn ArchiveLookup,
    policy_digest: &str,
    bundle_digest: &str,
) -> Result<EraBundle, ReanchorError> {
    let policy_bytes = archives
        .read_archive(&format!("policy-{policy_digest}.json"))
        .ok_or(ReanchorError::Sequence(
            "archived installation policy is missing",
        ))?;
    if sha256_hex(&policy_bytes) != policy_digest {
        return Err(ReanchorError::Sequence(
            "archived installation policy digest changed",
        ));
    }
    let policy: Signed<InstallationPolicy> = decode_signed(&policy_bytes)
        .map_err(|_| ReanchorError::Malformed("archived installation policy is malformed"))?;
    let policy = policy.payload;
    if policy.format != "o3k-installation-policy-v1" {
        return Err(ReanchorError::Malformed(
            "archived installation policy kind is unknown",
        ));
    }
    let bundle_bytes = archives
        .read_archive(&format!("trust-{bundle_digest}.json"))
        .ok_or(ReanchorError::Sequence(
            "archived recovery trust bundle is missing",
        ))?;
    if sha256_hex(&bundle_bytes) != bundle_digest {
        return Err(ReanchorError::Sequence(
            "archived recovery trust bundle digest changed",
        ));
    }
    let bundle: TrustBundle = decode_signed(&bundle_bytes)
        .map_err(|_| ReanchorError::Malformed("archived recovery trust bundle is malformed"))?;
    Ok(EraBundle {
        policy,
        policy_digest: policy_digest.to_string(),
        bundle,
        bundle_digest: bundle_digest.to_string(),
    })
}

fn preserved_bindings_match(
    record: &InstallationReanchor,
    state: RecoveryState,
    operation_id: Option<&str>,
    artifact: Option<&str>,
    recovery_directory_digest: Option<&str>,
    terminal_journal: Option<&str>,
    terminal_evidence: Option<&str>,
) -> Result<(), ReanchorError> {
    let expected = match state {
        RecoveryState::NeverRecovered => {
            record.preserved_state == RecoveryState::NeverRecovered
                && record.operation_id.is_none()
                && record.artifact_sha256.is_none()
                && record.recovery_directory_digest.is_none()
                && record.terminal_journal_digest.is_none()
                && record.terminal_evidence_digest.is_none()
        }
        RecoveryState::RecoveryDesignated => {
            record.preserved_state == RecoveryState::RecoveryDesignated
                && record.operation_id.as_deref() == operation_id
                && record
                    .operation_id
                    .as_deref()
                    .is_some_and(|id| uuid::Uuid::parse_str(id).is_ok())
                && record.artifact_sha256.as_deref() == artifact
                && record.artifact_sha256.as_deref().is_some_and(hex64)
                && record.recovery_directory_digest.as_deref() == recovery_directory_digest
                && record
                    .recovery_directory_digest
                    .as_deref()
                    .is_some_and(hex64)
                && record.terminal_journal_digest.is_none()
                && record.terminal_evidence_digest.is_none()
        }
        RecoveryState::Released => {
            record.preserved_state == RecoveryState::Released
                && record.operation_id.as_deref() == operation_id
                && record.artifact_sha256.as_deref() == artifact
                && record.recovery_directory_digest.as_deref() == recovery_directory_digest
                && record.terminal_journal_digest.as_deref() == terminal_journal
                && record.terminal_journal_digest.as_deref().is_some_and(hex64)
                && record.terminal_evidence_digest.as_deref() == terminal_evidence
                && record
                    .terminal_evidence_digest
                    .as_deref()
                    .is_some_and(hex64)
        }
    };
    if expected {
        Ok(())
    } else {
        Err(ReanchorError::Binding(
            "re-anchor preserved disposition, operation, target, or terminal evidence binding changed",
        ))
    }
}

fn tip_envelope(bytes: &[u8]) -> Result<Signed<serde_json::Value>, ReanchorError> {
    decode_signed(bytes)
}

/// Authenticates a generation whose state tip is the re-anchor record R.
/// Every era is verified with the retained self-contained era bundles; the
/// current-era trust freshness gate still applies to the installed trust.
pub fn authenticate_rotated_generation(
    view: &GenerationView<'_>,
    archives: &dyn ArchiveLookup,
) -> Result<ObservedGeneration, ReanchorError> {
    authenticate_rotated_generation_with_history(view, archives, false)
}

fn authenticate_rotated_generation_with_history(
    view: &GenerationView<'_>,
    archives: &dyn ArchiveLookup,
    historical: bool,
) -> Result<ObservedGeneration, ReanchorError> {
    let (policy, policy_digest, authority) = verify_current_policy(view)?;
    let (trust, trust_bundle) = verify_current_trust(view, &policy, historical)?;
    let tip = verify_reanchor_document(view.state_tip_bytes, &authority)?;
    let r = &tip.record;
    if r.installation_id != policy.installation_id
        || r.site_id != policy.site_id
        || r.profile != policy.profile
        || r.backend != policy.backend
        || r.target_device != policy.target_device
        || r.target_inode != policy.target_inode
    {
        return Err(ReanchorError::Binding(
            "installation identity does not match the authenticated policy",
        ));
    }
    if r.signer_manifest_digest != authority.digest {
        return Err(ReanchorError::Binding(
            "re-anchor signer manifest does not authenticate this release",
        ));
    }
    if r.new_policy_revision != policy.policy_revision || r.new_policy_digest != policy_digest {
        return Err(ReanchorError::Binding(
            "re-anchor new policy binding does not match the installed policy",
        ));
    }
    // §7.3.9: the durable policy high-water must name the same policy the
    // re-anchor binds; a crash before its publication leaves the prior
    // high-water in place and denies startup on the partial generation, and
    // any high-water/R digest conflict is equivocation.
    if let Some(policy_high_water) = view.policy_high_water_bytes
        && sha256_hex(policy_high_water) != policy_digest
    {
        return Err(ReanchorError::Binding(
            "durable policy high-water does not match the authenticated re-anchor policy",
        ));
    }
    let fixed_bundle: TrustBundle = decode_signed(view.fixed_bundle_bytes)?;
    if r.new_trust_bundle_digest != sha256_hex(view.fixed_bundle_bytes) {
        return Err(ReanchorError::Binding(
            "re-anchor new trust binding does not match the policy-authenticated bundle",
        ));
    }
    if r.new_journal_revocation != (revocation_high_water(&fixed_bundle.journal_revocations)?)
        || r.new_evidence_revocation != (revocation_high_water(&fixed_bundle.evidence_revocations)?)
    {
        return Err(ReanchorError::Binding(
            "re-anchor new revocation high-waters do not match the durable trust high-water",
        ));
    }
    let reason = match (&r.recovery_revalidation_digest, &r.checkpoint_digest) {
        (None, None) if r.preserved_state == RecoveryState::NeverRecovered => {
            RotationReason::Routine
        }
        (None, Some(_)) => RotationReason::Routine,
        (Some(_), Some(_)) => RotationReason::Compromise,
        _ => {
            return Err(ReanchorError::Binding(
                "re-anchor evidence or checkpoint binding is inconsistent",
            ));
        }
    };

    // Walk the re-anchor chain back to the base disposition record, verifying
    // each link's new-side bindings against the era it published and each
    // checkpoint under its era's signer certificate.
    let mut current = tip.clone();
    let mut era = EraBundle {
        policy: policy.clone(),
        policy_digest: policy_digest.clone(),
        bundle: fixed_bundle,
        bundle_digest: sha256_hex(view.fixed_bundle_bytes),
    };
    // Newest first: chain[0] is the current tip checkpoint C_n.
    let mut checkpoint_chain: Vec<(JournalCheckpoint, String)> = Vec::new();
    // Assigned by the base-disposition arm before the only `break`; the
    // initial None is never read (the loop exits only through that arm).
    #[allow(unused_assignments)]
    let mut base: Option<(Vec<u8>, InstallationState, EraBundle)> = None;
    #[allow(unused_assignments)]
    let mut first_reanchor: Option<u64> = None;
    loop {
        let record = &current.record;
        if record.new_policy_digest != era.policy_digest
            || record.new_trust_bundle_digest != era.bundle_digest
            || record.new_journal_revocation
                != (revocation_high_water(&era.bundle.journal_revocations)?)
            || record.new_evidence_revocation
                != (revocation_high_water(&era.bundle.evidence_revocations)?)
        {
            return Err(ReanchorError::Binding(
                "re-anchor chain new-side binding does not match the retained era",
            ));
        }
        let prior_tip_bytes = archives
            .read_archive(&format!("state-{}.json", record.prior_record_digest))
            .ok_or(ReanchorError::Sequence(
                "re-anchor predecessor record is missing",
            ))?;
        if sha256_hex(&prior_tip_bytes) != record.prior_record_digest {
            return Err(ReanchorError::Sequence(
                "re-anchor predecessor digest changed",
            ));
        }
        let prior_era = load_era(
            archives,
            &record.prior_policy_digest,
            &record.prior_trust_bundle_digest,
        )?;
        verify_rotation_high_waters(&prior_era.bundle, &era.bundle)?;
        if record.prior_journal_revocation
            != (revocation_high_water(&prior_era.bundle.journal_revocations)?)
            || record.prior_evidence_revocation
                != (revocation_high_water(&prior_era.bundle.evidence_revocations)?)
        {
            return Err(ReanchorError::Binding(
                "re-anchor prior revocation high-waters do not match the retained era",
            ));
        }
        if let Some(checkpoint_digest) = &record.checkpoint_digest {
            let checkpoint_bytes = if checkpoint_chain.is_empty() {
                view.checkpoint_bytes
                    .ok_or(ReanchorError::Binding("re-anchor checkpoint is missing"))?
                    .to_vec()
            } else {
                archives
                    .read_archive(&format!("checkpoint-{checkpoint_digest}.json"))
                    .ok_or(ReanchorError::Sequence(
                        "archived journal checkpoint is missing",
                    ))?
            };
            if sha256_hex(&checkpoint_bytes) != *checkpoint_digest {
                return Err(ReanchorError::Binding(
                    "re-anchor checkpoint digest does not match the journal checkpoint",
                ));
            }
            let checkpoint = verify_checkpoint_document(&checkpoint_bytes, &era.bundle)?;
            verify_checkpoint_bindings(&checkpoint, record, &era, &prior_era, &prior_tip_bytes)?;
            // The chain is built newest-first: each older checkpoint must be
            // exactly one sequence below the checkpoint it precedes.
            if let Some((newer, _)) = checkpoint_chain.last()
                && checkpoint.sequence.checked_add(1) != Some(newer.sequence)
            {
                return Err(ReanchorError::Sequence(
                    "journal checkpoint sequence is not monotonic",
                ));
            }
            checkpoint_chain.push((checkpoint, checkpoint_digest.clone()));
        } else if checkpoint_chain.is_empty() && view.checkpoint_bytes.is_some() {
            return Err(ReanchorError::Binding(
                "journal checkpoint without a re-anchor record denies startup",
            ));
        }

        let prior_signed = tip_envelope(&prior_tip_bytes)?;
        let prior_format = prior_signed
            .payload
            .get("format")
            .and_then(serde_json::Value::as_str)
            .ok_or(ReanchorError::Malformed(
                "re-anchor predecessor kind is unknown",
            ))?;

        match prior_format {
            REANCHOR_FORMAT => {
                let prior_signed: Signed<InstallationReanchor> = decode_signed(&prior_tip_bytes)
                    .map_err(|_| ReanchorError::Malformed("re-anchor predecessor is malformed"))?;
                let prior_record = prior_signed.payload;
                // Older R signatures are verified only while the same policy
                // authority and release manifest authenticate them; otherwise
                // the authenticated tip chain carries them as audit evidence.
                if prior_signed.envelope.signer_key_id == authority.key_id {
                    if prior_record.signer_manifest_digest != authority.digest {
                        return Err(ReanchorError::Binding(
                            "re-anchor chain signer manifest equivocates",
                        ));
                    }
                    let verified = verify_reanchor_document(&prior_tip_bytes, &authority)?;
                    if verified.record != prior_record {
                        return Err(ReanchorError::Signature(
                            "re-anchor chain signature is invalid",
                        ));
                    }
                }
                if prior_record.sequence.checked_add(1) != Some(record.sequence) {
                    return Err(ReanchorError::Sequence(
                        "re-anchor chain sequence is not monotonic",
                    ));
                }
                if prior_record.preserved_state != record.preserved_state {
                    return Err(ReanchorError::Binding(
                        "re-anchor chain preserved state changed",
                    ));
                }
                preserved_bindings_match(
                    record,
                    prior_record.preserved_state,
                    prior_record.operation_id.as_deref(),
                    prior_record.artifact_sha256.as_deref(),
                    prior_record.recovery_directory_digest.as_deref(),
                    prior_record.terminal_journal_digest.as_deref(),
                    prior_record.terminal_evidence_digest.as_deref(),
                )?;
                let prior_anchor_era = load_era(
                    archives,
                    &prior_record.new_policy_digest,
                    &prior_record.new_trust_bundle_digest,
                )?;
                verify_rotation_high_waters(&prior_anchor_era.bundle, &prior_era.bundle)?;
                current = ReanchorTip {
                    record: prior_record,
                    digest: sha256_hex(&prior_tip_bytes),
                };
                era = prior_anchor_era;
            }
            "o3k-installation-state-v1" => {
                let base_signed: Signed<InstallationState> = decode_signed(&prior_tip_bytes)
                    .map_err(|_| ReanchorError::Malformed("re-anchor predecessor is malformed"))?;
                let base_record = base_signed.payload;
                first_reanchor = Some(record.sequence);
                base = Some((prior_tip_bytes, base_record, prior_era));
                break;
            }
            _ => {
                return Err(ReanchorError::Malformed(
                    "re-anchor predecessor kind is unknown",
                ));
            }
        }
    }

    let (base_bytes, base, base_era) = base.ok_or(ReanchorError::Sequence(
        "re-anchor chain does not reach the base disposition",
    ))?;
    let base_state = verify_base_disposition(&base_bytes, &base, &base_era, archives)?;
    if tip.record.preserved_state != base_state {
        return Err(ReanchorError::Binding(
            "re-anchor preserved state does not match the base disposition",
        ));
    }
    preserved_bindings_match(
        &tip.record,
        base_state,
        base.operation_id.as_deref(),
        base.artifact_sha256.as_deref(),
        base.recovery_directory_digest.as_deref(),
        base.terminal_journal_digest.as_deref(),
        base.evidence_digest.as_deref(),
    )?;

    // The first re-anchor occupies exactly base sequence + 1.
    if base.sequence.checked_add(1) != first_reanchor {
        return Err(ReanchorError::Sequence(
            "first re-anchor sequence must be exactly the base sequence plus one",
        ));
    }

    let journal = if base_state == RecoveryState::NeverRecovered {
        if view.checkpoint_bytes.is_some() {
            return Err(ReanchorError::Binding(
                "journal checkpoint on a never-recovered rotated installation requires an authenticated disposition",
            ));
        }
        if tip.record.checkpoint_digest.is_some() {
            return Err(ReanchorError::Binding(
                "never-recovered re-anchor must not bind a checkpoint",
            ));
        }
        if !checkpoint_chain.is_empty() {
            return Err(ReanchorError::Binding(
                "never-recovered re-anchor must not bind a checkpoint",
            ));
        }
        None
    } else {
        let (checkpoint, checkpoint_digest) = checkpoint_chain.first().ok_or(
            ReanchorError::Binding("re-anchor checkpoint chain is missing"),
        )?;
        let base_tip_hash = authenticated_base_tip(
            view,
            &base_era,
            base.operation_id.as_deref(),
            base.artifact_sha256.as_deref(),
        )?;
        if let Some(base_tip_hash) = &base_tip_hash {
            let oldest = &checkpoint_chain
                .last()
                .ok_or(ReanchorError::Binding(
                    "re-anchor checkpoint chain is missing",
                ))?
                .0;
            if oldest.prior_record_digest != *base_tip_hash {
                return Err(ReanchorError::Trust(
                    "RELEASED terminal journal hash does not match the authenticated journal tip",
                ));
            }
        }
        if base_state == RecoveryState::Released {
            let oldest = &checkpoint_chain
                .last()
                .ok_or(ReanchorError::Binding(
                    "re-anchor checkpoint chain is missing",
                ))?
                .0;
            if base.terminal_journal_digest.as_deref() != Some(oldest.prior_record_digest.as_str())
                || tip.record.terminal_journal_digest.as_deref()
                    != Some(oldest.prior_record_digest.as_str())
            {
                return Err(ReanchorError::Trust(
                    "RELEASED terminal evidence cannot be authenticated",
                ));
            }
        }
        // Every checkpoint preserves the unchanged phase.
        for (link, _) in &checkpoint_chain {
            if link.phase != checkpoint.phase {
                return Err(ReanchorError::Binding(
                    "journal checkpoint chain changed the preserved phase",
                ));
            }
        }
        Some(ObservedJournalTip {
            sequence: checkpoint.sequence,
            tip_hash: checkpoint_digest.clone(),
            phase: checkpoint.phase,
            checkpoint_digest: Some(checkpoint_digest.clone()),
            base_chain: None,
        })
    };

    if let Some(evidence_digest) = &tip.record.recovery_revalidation_digest {
        let consumption_bytes = view
            .consumption_record_bytes
            .ok_or(ReanchorError::Evidence(
                "revalidation consumption record is missing",
            ))?;
        let consumption: RevalidationConsumption =
            decode_signed(consumption_bytes).map_err(|_| {
                ReanchorError::Malformed("revalidation consumption record is malformed")
            })?;
        // The consumed flag is set only after the full publication completes;
        // a crash between the final observation and the mark leaves the
        // binding durable but unconsumed, and exact retry re-marks it.
        if consumption.format != CONSUMPTION_FORMAT
            || &consumption.evidence_digest != evidence_digest
            || consumption.reanchor_digest != tip.digest
            || consumption.checkpoint_digest
                != tip.record.checkpoint_digest.as_deref().unwrap_or_default()
            || !hex64(&consumption.nonce)
            || consumption.nonce.chars().all(|c| c == '0')
        {
            return Err(ReanchorError::Evidence(
                "revalidation evidence consumption does not bind this re-anchor pair",
            ));
        }
        let _ = reason;
    }

    let trust_bundle_digest = sha256_hex(view.trust_high_water_bytes);
    Ok(observed(
        policy,
        policy_digest,
        Some(trust),
        trust_bundle,
        trust_bundle_digest,
        tip.record.sequence,
        tip.digest,
        true,
        base_state,
        base.operation_id.clone(),
        base.artifact_sha256.clone(),
        base.recovery_directory_digest.clone(),
        base.terminal_journal_digest.clone(),
        base.evidence_digest.clone(),
        journal,
        Some(base),
    ))
}

/// The authenticated old journal tip: the base chain verified under the
/// retained base-era bundle. Returns None when the retained base-era bundle
/// no longer verifies at `now` (post-overlap eras are audit-only; their
/// authenticity is carried by the authenticated R and C tips).
fn authenticated_base_tip(
    view: &GenerationView<'_>,
    base_era: &EraBundle,
    operation_id: Option<&str>,
    artifact: Option<&str>,
) -> Result<Option<String>, ReanchorError> {
    let Some(journal_bytes) = view.journal_bytes else {
        return Err(ReanchorError::Binding(
            "recovery journal is unsafe or unavailable",
        ));
    };
    let operation_id =
        operation_id.ok_or(ReanchorError::Binding("recovery operation is missing"))?;
    let artifact = artifact.ok_or(ReanchorError::Binding("recovery artifact is missing"))?;
    let journal_root = decode_key32(&base_era.bundle.journal_root_public_key)?;
    let evidence_root = decode_key32(&base_era.bundle.evidence_root_public_key)?;
    let Ok(era_trust) = crate::recovery_trust::verify_historical_trust(
        base_era.bundle.clone(),
        &journal_root,
        &evidence_root,
        None,
        None,
    ) else {
        return Ok(None);
    };
    let chain = restore_journal::authenticate_installed_chain(
        journal_bytes,
        &base_era.policy,
        &era_trust,
        operation_id
            .parse()
            .map_err(|_| ReanchorError::Binding("recovery operation is invalid"))?,
        artifact,
    )
    .map_err(|_| {
        ReanchorError::Trust("recovery journal is unauthenticated or conflicts with designation")
    })?;
    if chain.phase() != RestorePhase::Preflighted {
        return Err(ReanchorError::Trust(
            "journal v1 rotation supports only the accepted PREFLIGHTED phase",
        ));
    }
    Ok(Some(chain.signed_hash().to_string()))
}

/// Verifies the base disposition record and its in-era predecessor chain
/// under the retained base-era journal signer certificate. The era's initial
/// record is policy-authority signed; when the policy authority rotated its
/// authenticity is carried by the era policy archive binding, so the initial
/// record is checked structurally here.
fn verify_base_disposition(
    base_bytes: &[u8],
    base: &InstallationState,
    base_era: &EraBundle,
    archives: &dyn ArchiveLookup,
) -> Result<RecoveryState, ReanchorError> {
    if base.format != "o3k-installation-state-v1"
        || base.installation_id != base_era.policy.installation_id
        || base.site_id != base_era.policy.site_id
        || base.profile != base_era.policy.profile
        || base.backend != base_era.policy.backend
        || base.policy_revision != base_era.policy.policy_revision
        || base.target_device != base_era.policy.target_device
        || base.target_inode != base_era.policy.target_inode
    {
        return Err(ReanchorError::Binding(
            "base disposition does not bind the retained era installation identity",
        ));
    }
    let era_key = (base.sequence > 0)
        .then(|| era_journal_key(&base_era.bundle))
        .transpose()
        .map_err(|_| ReanchorError::Trust("base-era journal signer is unavailable"))?;
    if let Some((key_id, key)) = &era_key {
        let verified: InstallationState = verify_signed_document(
            base_bytes,
            "o3k-installation-state-v1",
            key_id,
            key,
            ReanchorError::Signature("base disposition signature is invalid"),
        )?;
        if verified.state != base.state {
            return Err(ReanchorError::Malformed(
                "base disposition payload is inconsistent",
            ));
        }
    }
    let mut current = ChainCursor::State(base.clone());
    loop {
        if current.sequence() == 0 {
            match &current {
                ChainCursor::State(initial)
                    if initial.state == RecoveryState::NeverRecovered
                        && initial.prior_record_digest.is_empty() => {}
                _ => {
                    return Err(ReanchorError::Sequence(
                        "base era initial record is invalid",
                    ));
                }
            }
            break;
        }
        let previous_digest = current.prior_digest().to_string();
        let previous_bytes = archives
            .read_archive(&format!("state-{previous_digest}.json"))
            .ok_or(ReanchorError::Sequence(
                "base disposition predecessor is missing",
            ))?;
        if sha256_hex(&previous_bytes) != previous_digest {
            return Err(ReanchorError::Sequence(
                "base disposition predecessor digest changed",
            ));
        }
        let previous_envelope = tip_envelope(&previous_bytes)?;
        let previous_format = previous_envelope
            .payload
            .get("format")
            .and_then(serde_json::Value::as_str)
            .ok_or(ReanchorError::Malformed(
                "base disposition predecessor kind is unknown",
            ))?;
        let previous = match previous_format {
            REANCHOR_FORMAT => ChainCursor::Reanchor(
                decode_signed::<Signed<InstallationReanchor>>(&previous_bytes)
                    .map_err(|_| {
                        ReanchorError::Malformed("base disposition predecessor is malformed")
                    })?
                    .payload,
            ),
            "o3k-installation-state-v1" => {
                let previous: Signed<InstallationState> =
                    decode_signed(&previous_bytes).map_err(|_| {
                        ReanchorError::Malformed("base disposition predecessor is malformed")
                    })?;
                if previous.payload.sequence == 0 {
                    // The initial record is policy-authority signed under the
                    // epoch that opened this chain. After a policy rotation
                    // its signature is audit-only, carried by the later
                    // authenticated journal-signed designation; installation
                    // and target identity must still match the retained era.
                    if previous.payload.state != RecoveryState::NeverRecovered
                        || !previous.payload.prior_record_digest.is_empty()
                        || previous.payload.installation_id != base_era.policy.installation_id
                        || previous.payload.site_id != base_era.policy.site_id
                        || previous.payload.profile != base_era.policy.profile
                        || previous.payload.backend != base_era.policy.backend
                        || previous.payload.target_device != base_era.policy.target_device
                        || previous.payload.target_inode != base_era.policy.target_inode
                    {
                        return Err(ReanchorError::Sequence(
                            "base era initial record is invalid",
                        ));
                    }
                } else {
                    let (key_id, key) = era_key.as_ref().ok_or(ReanchorError::Trust(
                        "base-era journal signer is unavailable",
                    ))?;
                    if previous.envelope.signer_key_id != *key_id {
                        return Err(ReanchorError::Signature(
                            "base disposition predecessor signer changed",
                        ));
                    }
                    verify_signed_document::<InstallationState>(
                        &previous_bytes,
                        "o3k-installation-state-v1",
                        key_id,
                        key,
                        ReanchorError::Signature(
                            "base disposition predecessor signature is invalid",
                        ),
                    )?;
                }
                ChainCursor::State(previous.payload)
            }
            _ => {
                return Err(ReanchorError::Malformed(
                    "base disposition predecessor kind is unknown",
                ));
            }
        };
        if previous.sequence().checked_add(1) != Some(current.sequence()) {
            return Err(ReanchorError::Sequence(
                "base disposition predecessor sequence is invalid",
            ));
        }
        match (&current, &previous) {
            (ChainCursor::State(current_state), _) => {
                identity::verify_tip_transition(
                    Some(previous.view()),
                    Some(&previous_digest),
                    current_state,
                    &base_era.policy,
                )
                .map_err(|_| ReanchorError::Sequence("base disposition transition is invalid"))?;
            }
            (ChainCursor::Reanchor(current_record), ChainCursor::State(previous_state)) => {
                if current_record.preserved_state != previous_state.state {
                    return Err(ReanchorError::Binding(
                        "re-anchor predecessor changed the preserved state",
                    ));
                }
            }
            (ChainCursor::Reanchor(current_record), ChainCursor::Reanchor(previous_record)) => {
                if current_record.preserved_state != previous_record.preserved_state {
                    return Err(ReanchorError::Binding(
                        "re-anchor predecessor changed the preserved state",
                    ));
                }
            }
        }
        current = previous;
    }
    Ok(base.state)
}

fn verify_checkpoint_bindings(
    checkpoint: &JournalCheckpoint,
    record: &InstallationReanchor,
    era: &EraBundle,
    prior_era: &EraBundle,
    prior_tip_bytes: &[u8],
) -> Result<(), ReanchorError> {
    let policy = &era.policy;
    if checkpoint.installation_id != policy.installation_id
        || checkpoint.site_id != policy.site_id
        || checkpoint.profile != policy.profile
        || checkpoint.backend != policy.backend
        || checkpoint.journal_directory != policy.journal_directory
        || checkpoint.journal_device != policy.journal_device
        || checkpoint.journal_inode != policy.journal_inode
    {
        return Err(ReanchorError::Binding(
            "journal checkpoint does not bind the rotated installation identity",
        ));
    }
    if checkpoint.prior_state_tip_digest != sha256_hex(prior_tip_bytes) {
        return Err(ReanchorError::Binding(
            "journal checkpoint must bind the prior state tip, never the re-anchor",
        ));
    }
    if checkpoint.old_journal_revocation != record.prior_journal_revocation
        || checkpoint.new_journal_revocation != record.new_journal_revocation
        || checkpoint.old_evidence_revocation != record.prior_evidence_revocation
        || checkpoint.new_evidence_revocation != record.new_evidence_revocation
    {
        return Err(ReanchorError::Binding(
            "journal checkpoint revocation high-waters conflict with the re-anchor",
        ));
    }
    let old_cert = &prior_era.bundle.journal_certificate.payload;
    let new_cert = &era.bundle.journal_certificate.payload;
    if checkpoint.old_journal_key_id != old_cert.key_id
        || checkpoint.old_journal_certificate_serial != old_cert.serial
        || checkpoint.new_journal_key_id != new_cert.key_id
        || checkpoint.new_journal_certificate_serial != new_cert.serial
    {
        return Err(ReanchorError::Binding(
            "journal checkpoint certificate bindings conflict with the retained eras",
        ));
    }
    let expected_reason = match &record.recovery_revalidation_digest {
        Some(digest) => {
            if checkpoint.recovery_revalidation_digest.as_deref() != Some(digest.as_str()) {
                return Err(ReanchorError::Binding(
                    "journal checkpoint does not bind the revalidation evidence digest",
                ));
            }
            RotationReason::Compromise
        }
        None => {
            if checkpoint.recovery_revalidation_digest.is_some() {
                return Err(ReanchorError::Binding(
                    "routine rotation must not bind revalidation evidence",
                ));
            }
            RotationReason::Routine
        }
    };
    if checkpoint.rotation_reason != expected_reason {
        return Err(ReanchorError::Binding(
            "journal checkpoint rotation reason conflicts with the re-anchor",
        ));
    }
    Ok(())
}

// ---------------------------------------------------------------------------
// Rotation plan construction.
// ---------------------------------------------------------------------------

pub struct RotationInputs {
    /// Signed `o3k-installation-reanchor-v1` bytes.
    pub signed_reanchor: Vec<u8>,
    /// Signed `o3k-restore-journal-checkpoint-v1` bytes (required unless the
    /// preserved state is `NEVER_RECOVERED`).
    pub signed_checkpoint: Option<Vec<u8>>,
    /// Signed `o3k-installation-policy-v1` bytes for the new generation.
    pub new_policy: Vec<u8>,
    /// Canonical `o3k-recovery-trust-v1` bytes for the new generation.
    pub new_trust_bundle: Vec<u8>,
    /// Signed `o3k-recovery-revalidation-v1` bytes (compromise only).
    pub signed_revalidation: Option<Vec<u8>>,
    /// The offline custody record whose digest the evidence binds.
    pub custody_record: Option<Vec<u8>>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
pub enum RotationArea {
    StateRoot,
    JournalDir,
    FixedConfig,
}

/// Narrow storage seam for the ordered publication engine. The production
/// implementation is descriptor-anchored and root-only; tests substitute an
/// in-memory store. Nothing outside the named recovery files can be touched.
pub trait RotationStore {
    fn read(&self, area: RotationArea, name: &str) -> Result<Option<Vec<u8>>, ReanchorError>;
    fn publish(
        &mut self,
        area: RotationArea,
        name: &str,
        bytes: &[u8],
    ) -> Result<(), ReanchorError>;
    fn list(&self, area: RotationArea) -> Result<Vec<String>, ReanchorError>;
}

#[derive(Debug, Clone)]
pub struct PriorBytes {
    pub fixed_policy: Vec<u8>,
    pub policy_high_water: Vec<u8>,
    pub fixed_trust: Vec<u8>,
    pub trust_high_water: Vec<u8>,
    pub state_tip: Vec<u8>,
}

#[derive(Debug)]
pub struct RotationPlan {
    pub preserved_state: RecoveryState,
    pub reanchor_digest: String,
    /// True when the exact published generation was re-presented: the plan
    /// performs no publications, only the final observation and the
    /// consumption-state verification.
    pub identity_replay: bool,
    pub staged: Vec<(RotationArea, &'static str, Vec<u8>)>,
    pub fixed_policy: Vec<u8>,
    pub policy_high_water: Vec<u8>,
    pub fixed_trust: Vec<u8>,
    pub trust_high_water: Vec<u8>,
    pub checkpoint: Option<Vec<u8>>,
    /// The checkpoint bytes the checkpoint slot holds before this plan
    /// publishes (None on the first rotation): the immutable current
    /// checkpoint name is reusable across rotations, so the prior bytes make
    /// the replacement an exact resume point rather than a conflict.
    pub checkpoint_prior: Option<Vec<u8>>,
    pub reanchor: Vec<u8>,
    pub archives: Vec<(RotationArea, String, Vec<u8>)>,
    pub consumption: Option<RevalidationConsumption>,
    /// A superseded consumed record, archived under its content-addressed
    /// name before the new consumption record lands. The same bytes are the
    /// `prior` expectation for the reusable consumption-record slot.
    pub consumption_archive: Option<(String, Vec<u8>)>,
    pub prior: PriorBytes,
}

fn observe_current(
    view: &GenerationView<'_>,
    archives: &dyn ArchiveLookup,
) -> Result<ObservedGeneration, ReanchorError> {
    let signed = tip_envelope(view.state_tip_bytes)
        .map_err(|_| ReanchorError::Malformed("installation state is malformed"))?;
    match signed
        .payload
        .get("format")
        .and_then(serde_json::Value::as_str)
    {
        Some(REANCHOR_FORMAT) => authenticate_rotated_generation(view, archives),
        Some("o3k-installation-state-v1") => observe_disposition_generation(view, archives),
        _ => Err(ReanchorError::Malformed(
            "installation state record kind is unknown",
        )),
    }
}

/// Exact-forward resume observation (SPEC-0050 §7.3.9). After a crash the
/// durable generation is partial, so it cannot be authenticated as a whole;
/// the signed R/C inputs are re-verified against the durable prior bytes and
/// the resume continues forward only. Old-era freshness is not re-required:
/// the first attempt verified it, and the authenticated R bindings carry the
/// old generation's authenticity.
fn observe_resume(
    view: &GenerationView<'_>,
    archives: &dyn ArchiveLookup,
    inputs: &RotationInputs,
) -> Result<(ObservedGeneration, PriorBytes), ReanchorError> {
    if view.pending_reanchor_bytes != Some(inputs.signed_reanchor.as_slice()) {
        return Err(ReanchorError::Conflicting(
            "resume requires the exact durably staged signed re-anchor intent",
        ));
    }
    let authority = manifest_authority(view.manifest_bytes)?;
    let r = verify_reanchor_document(&inputs.signed_reanchor, &authority)?.record;

    // The durable state tip is always the prior tip S0 until R publishes.
    if sha256_hex(view.state_tip_bytes) != r.prior_record_digest {
        return Err(ReanchorError::Sequence(
            "resume state tip does not match the re-anchor prior digest",
        ));
    }
    let s0_signed = tip_envelope(view.state_tip_bytes)?;
    let (
        s0_state,
        s0_sequence,
        s0_operation_id,
        s0_artifact,
        s0_recovery_directory,
        s0_terminal_journal,
        s0_terminal_evidence,
    ) = match s0_signed
        .payload
        .get("format")
        .and_then(serde_json::Value::as_str)
    {
        Some("o3k-installation-state-v1") => {
            let signed: Signed<InstallationState> = decode_signed(view.state_tip_bytes)
                .map_err(|_| ReanchorError::Malformed("resume state tip is malformed"))?;
            let p = &signed.payload;
            (
                p.state,
                p.sequence,
                p.operation_id.clone(),
                p.artifact_sha256.clone(),
                p.recovery_directory_digest.clone(),
                p.terminal_journal_digest.clone(),
                p.evidence_digest.clone(),
            )
        }
        Some(REANCHOR_FORMAT) => {
            let signed: Signed<InstallationReanchor> = decode_signed(view.state_tip_bytes)
                .map_err(|_| ReanchorError::Malformed("resume state tip is malformed"))?;
            let p = &signed.payload;
            (
                p.preserved_state,
                p.sequence,
                p.operation_id.clone(),
                p.artifact_sha256.clone(),
                p.recovery_directory_digest.clone(),
                p.terminal_journal_digest.clone(),
                p.terminal_evidence_digest.clone(),
            )
        }
        _ => return Err(ReanchorError::Malformed("resume state tip kind is unknown")),
    };
    if r.sequence != s0_sequence + 1 {
        return Err(ReanchorError::Sequence(
            "resume re-anchor sequence must be exactly the prior tip sequence plus one",
        ));
    }
    if r.preserved_state != s0_state {
        return Err(ReanchorError::Binding(
            "resume re-anchor preserved state does not match the durable tip",
        ));
    }

    // Recover the prior generation bytes: the durable high-waters still hold
    // them until their publication steps; afterwards only the inert staged
    // copies remain, and after the archive step the content-addressed
    // archives bind them by name (the lookup verifies the digest).
    let archived_policy =
        || archives.read_archive(&format!("policy-{}.json", r.prior_policy_digest));
    let old_policy_bytes = [
        view.policy_high_water_bytes,
        Some(view.policy_bytes),
        view.staged_prior_policy_bytes,
        archived_policy().as_deref(),
    ]
    .into_iter()
    .flatten()
    .find(|bytes| sha256_hex(bytes) == r.prior_policy_digest)
    .ok_or(ReanchorError::Conflicting(
        "resume cannot recover the authenticated prior policy bytes",
    ))?
    .to_vec();
    let archived_trust =
        || archives.read_archive(&format!("trust-{}.json", r.prior_trust_bundle_digest));
    let old_trust_bytes = [
        Some(view.trust_high_water_bytes),
        Some(view.fixed_bundle_bytes),
        view.staged_prior_trust_bytes,
        archived_trust().as_deref(),
    ]
    .into_iter()
    .flatten()
    .find(|bytes| sha256_hex(bytes) == r.prior_trust_bundle_digest)
    .ok_or(ReanchorError::Conflicting(
        "resume cannot recover the authenticated prior trust bytes",
    ))?
    .to_vec();
    let old_policy_signed: Signed<InstallationPolicy> = decode_signed(&old_policy_bytes)
        .map_err(|_| ReanchorError::Malformed("resume prior policy is malformed"))?;
    let old_policy = old_policy_signed.payload;
    let old_bundle: TrustBundle = decode_signed(&old_trust_bytes)
        .map_err(|_| ReanchorError::Malformed("resume prior trust is malformed"))?;
    if revocation_high_water(&old_bundle.journal_revocations)? != r.prior_journal_revocation
        || revocation_high_water(&old_bundle.evidence_revocations)? != r.prior_evidence_revocation
    {
        return Err(ReanchorError::Binding(
            "resume prior revocation high-waters do not match the re-anchor",
        ));
    }

    // Journal tip: the previous checkpoint when one exists (bound by the new
    // C's prior-checkpoint digest), otherwise the base chain re-authenticated
    // under the prior era's signer key.
    let journal = if let Some(new_checkpoint_bytes) = &inputs.signed_checkpoint {
        let new_checkpoint = verify_checkpoint_document(new_checkpoint_bytes, &{
            let new_bundle: TrustBundle = decode_signed(&inputs.new_trust_bundle)
                .map_err(|_| ReanchorError::Malformed("new recovery trust bundle is malformed"))?;
            new_bundle
        })?;
        let prior_checkpoint_digest = new_checkpoint.prior_checkpoint_digest.clone();
        match &prior_checkpoint_digest {
            Some(digest) => {
                let bytes = view
                    .checkpoint_bytes
                    .ok_or(ReanchorError::Sequence("resume checkpoint is missing"))?;
                let bytes_digest = sha256_hex(bytes);
                if bytes_digest == *digest {
                    // The prior checkpoint is still current: the crash
                    // happened before the new C published.
                    let signed: Signed<JournalCheckpoint> = decode_signed(bytes)
                        .map_err(|_| ReanchorError::Malformed("resume checkpoint is malformed"))?;
                    let c = signed.payload;
                    ObservedJournalTip {
                        sequence: c.sequence,
                        tip_hash: digest.clone(),
                        phase: c.phase,
                        checkpoint_digest: Some(digest.clone()),
                        base_chain: None,
                    }
                } else if bytes == new_checkpoint_bytes.as_slice() {
                    // The new checkpoint is already published (the crash
                    // happened at or after its publication): the journal tip
                    // is the new C itself, chained at its own sequence.
                    ObservedJournalTip {
                        sequence: new_checkpoint.sequence,
                        tip_hash: bytes_digest.clone(),
                        phase: new_checkpoint.phase,
                        checkpoint_digest: Some(bytes_digest),
                        base_chain: None,
                    }
                } else {
                    return Err(ReanchorError::Sequence(
                        "resume checkpoint does not match the prior-checkpoint digest",
                    ));
                }
            }
            None => {
                let base_tip = authenticated_base_tip(
                    view,
                    &EraBundle {
                        policy: old_policy.clone(),
                        policy_digest: r.prior_policy_digest.clone(),
                        bundle: old_bundle.clone(),
                        bundle_digest: r.prior_trust_bundle_digest.clone(),
                    },
                    s0_operation_id.as_deref(),
                    s0_artifact.as_deref(),
                )?;
                let tip_hash = base_tip.ok_or(ReanchorError::Trust(
                    "resume cannot authenticate the base journal chain",
                ))?;
                let sequence =
                    new_checkpoint
                        .sequence
                        .checked_sub(1)
                        .ok_or(ReanchorError::Sequence(
                            "resume checkpoint sequence is invalid",
                        ))?;
                ObservedJournalTip {
                    sequence,
                    tip_hash,
                    phase: new_checkpoint.phase,
                    checkpoint_digest: None,
                    base_chain: None,
                }
            }
        }
    } else {
        if r.preserved_state != RecoveryState::NeverRecovered {
            return Err(ReanchorError::Binding(
                "resume without a checkpoint requires a never-recovered state",
            ));
        }
        if view.checkpoint_bytes.is_some() {
            return Err(ReanchorError::Binding(
                "journal checkpoint without a re-anchor record denies startup",
            ));
        }
        return Ok((
            observed(
                old_policy,
                r.prior_policy_digest.clone(),
                None,
                old_bundle,
                r.prior_trust_bundle_digest.clone(),
                s0_sequence,
                r.prior_record_digest.clone(),
                false,
                s0_state,
                s0_operation_id,
                s0_artifact,
                s0_recovery_directory,
                None,
                None,
                None,
                None,
            ),
            PriorBytes {
                fixed_policy: old_policy_bytes.clone(),
                policy_high_water: old_policy_bytes.clone(),
                fixed_trust: old_trust_bytes.clone(),
                trust_high_water: old_trust_bytes.clone(),
                state_tip: view.state_tip_bytes.to_vec(),
            },
        ));
    };

    Ok((
        observed(
            old_policy,
            r.prior_policy_digest.clone(),
            None,
            old_bundle,
            r.prior_trust_bundle_digest.clone(),
            s0_sequence,
            r.prior_record_digest.clone(),
            false,
            s0_state,
            s0_operation_id,
            s0_artifact,
            s0_recovery_directory,
            s0_terminal_journal,
            s0_terminal_evidence,
            Some(journal),
            None,
        ),
        PriorBytes {
            fixed_policy: old_policy_bytes.clone(),
            policy_high_water: old_policy_bytes.clone(),
            fixed_trust: old_trust_bytes.clone(),
            trust_high_water: old_trust_bytes.clone(),
            state_tip: view.state_tip_bytes.to_vec(),
        },
    ))
}

/// The consumption planning decision: the record to durably bind before the
/// R/C pair is accepted, and the archive write for a superseded consumed
/// record, when a later compromise rotation replaces it.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ConsumptionDecision {
    /// The record to write at the durable-consumption step; `None` when the
    /// exact published pair was re-presented and nothing remains to write.
    pub record: Option<RevalidationConsumption>,
    /// A prior consumed record bound to a different pair: archive its exact
    /// bytes under the content-addressed name before the new record lands.
    pub archive: Option<(String, Vec<u8>)>,
}

/// Consumption planning: the evidence authorizes exactly one R/C pair. An
/// already-consumed identical pair plans nothing; a matching unconsumed pair
/// plans only the (re-)write; a consumed record bound to a different pair is
/// historical evidence and is archived so a new record can bind the new pair;
/// any other combination — an in-flight record presented with different
/// bytes, or the same nonce reused in a different evidence document — is
/// rejected. The nonce check is enforced again against every retained record
/// at publication time (`run_rotation_plan`), so reuse is rejected even when
/// the colliding record is no longer the current one.
pub fn plan_consumption(
    existing: Option<&RevalidationConsumption>,
    evidence_digest: &str,
    reanchor_digest: &str,
    checkpoint_digest: &str,
    nonce: &str,
) -> Result<ConsumptionDecision, ReanchorError> {
    let record = RevalidationConsumption {
        format: CONSUMPTION_FORMAT.to_string(),
        evidence_digest: evidence_digest.to_string(),
        reanchor_digest: reanchor_digest.to_string(),
        checkpoint_digest: checkpoint_digest.to_string(),
        nonce: nonce.to_string(),
        consumed: false,
    };
    match existing {
        None => Ok(ConsumptionDecision {
            record: Some(record),
            archive: None,
        }),
        Some(existing) => {
            let same_pair = existing.evidence_digest == record.evidence_digest
                && existing.reanchor_digest == record.reanchor_digest
                && existing.checkpoint_digest == record.checkpoint_digest;
            if same_pair {
                if existing.consumed {
                    Ok(ConsumptionDecision {
                        record: None,
                        archive: None,
                    })
                } else {
                    Ok(ConsumptionDecision {
                        record: Some(record),
                        archive: None,
                    })
                }
            } else if !existing.consumed {
                // A crash before the consumption mark allows exact retry only:
                // the same evidence bound to a different pair is a fork.
                Err(ReanchorError::Evidence(
                    "revalidation evidence is already bound to a different re-anchor pair",
                ))
            } else if existing.nonce == nonce {
                Err(ReanchorError::Evidence(
                    "revalidation evidence nonce was already consumed by different evidence",
                ))
            } else {
                Ok(ConsumptionDecision {
                    record: Some(record),
                    archive: Some((
                        consumption_archive_name(&existing.evidence_digest),
                        identity::canonical(existing).map_err(|_| {
                            ReanchorError::Persistence("consumption record cannot be encoded")
                        })?,
                    )),
                })
            }
        }
    }
}

fn verify_new_policy(
    inputs: &RotationInputs,
    observed: &ObservedGeneration,
    authority: &ManifestAuthority,
) -> Result<InstallationPolicy, ReanchorError> {
    let policy: InstallationPolicy = verify_signed_document(
        &inputs.new_policy,
        "o3k-installation-policy-v1",
        &authority.key_id,
        &authority.key,
        ReanchorError::Signature("new installation policy signature is invalid"),
    )?;
    identity::verify_policy(&policy, &authority.key_id)
        .map_err(|_| ReanchorError::Binding("new installation policy binding is invalid"))?;
    // Rotation never rebinds installation, site, profile, backend, target, or
    // the fixed discovery paths; only the policy revision, prior digest, and
    // trust roots advance.
    let old = &observed.policy;
    if policy.installation_id != old.installation_id
        || policy.site_id != old.site_id
        || policy.profile != old.profile
        || policy.backend != old.backend
        || policy.data_root != old.data_root
        || policy.target_device != old.target_device
        || policy.target_inode != old.target_inode
        || policy.policy_path != old.policy_path
        || policy.trust_bundle_path != old.trust_bundle_path
        || policy.recovery_state_root != old.recovery_state_root
        || policy.recovery_state_device != old.recovery_state_device
        || policy.recovery_state_inode != old.recovery_state_inode
        || policy.journal_device != old.journal_device
        || policy.journal_inode != old.journal_inode
        || policy.journal_directory != old.journal_directory
        || policy.release_identity != old.release_identity
    {
        return Err(ReanchorError::Binding(
            "rotation cannot rebind installation, site, target, or release identity",
        ));
    }
    if policy.policy_revision <= old.policy_revision {
        return Err(ReanchorError::Sequence(
            "new policy revision must be monotonic",
        ));
    }
    if policy.prior_policy_digest != observed.policy_digest {
        return Err(ReanchorError::Sequence(
            "new policy must prior-link the installed policy digest",
        ));
    }
    Ok(policy)
}

/// A policy revision does not reset revocation history for an unchanged root.
fn verify_rotation_high_waters(old: &TrustBundle, new: &TrustBundle) -> Result<(), ReanchorError> {
    for (old_id, old_key, old_doc, new_id, new_key, new_doc) in [
        (
            &old.journal_root_key_id,
            &old.journal_root_public_key,
            &old.journal_revocations,
            &new.journal_root_key_id,
            &new.journal_root_public_key,
            &new.journal_revocations,
        ),
        (
            &old.evidence_root_key_id,
            &old.evidence_root_public_key,
            &old.evidence_revocations,
            &new.evidence_root_key_id,
            &new.evidence_root_public_key,
            &new.evidence_revocations,
        ),
    ] {
        if old_id == new_id && old_key != new_key {
            return Err(ReanchorError::Trust(
                "rotation cannot rebind a trust root key ID",
            ));
        }
        if old_key == new_key
            && (new_doc.payload.sequence < old_doc.payload.sequence
                || (new_doc.payload.sequence == old_doc.payload.sequence
                    && identity::digest(new_doc)
                        .map_err(|_| ReanchorError::Trust("invalid revocation digest"))?
                        != identity::digest(old_doc)
                            .map_err(|_| ReanchorError::Trust("invalid revocation digest"))?))
        {
            return Err(ReanchorError::Trust(
                "same-root revocation rollback or equivocation",
            ));
        }
    }
    Ok(())
}

fn verify_new_bundle(
    inputs: &RotationInputs,
    new_policy: &InstallationPolicy,
    now: i64,
) -> Result<TrustBundle, ReanchorError> {
    let bundle: TrustBundle = decode_signed(&inputs.new_trust_bundle)
        .map_err(|_| ReanchorError::Malformed("new recovery trust bundle is malformed"))?;
    if bundle.format != "o3k-recovery-trust-v1" {
        return Err(ReanchorError::Malformed(
            "new recovery trust bundle kind is unknown",
        ));
    }
    if bundle.installation_id != new_policy.installation_id
        || bundle.site_id != new_policy.site_id
        || bundle.profile != new_policy.profile
        || bundle.backend != new_policy.backend
        || bundle.journal_root_key_id != new_policy.journal_trust_root_id
        || bundle.journal_root_public_key != new_policy.journal_trust_root_public_key
        || bundle.evidence_root_key_id != new_policy.evidence_trust_root_id
        || bundle.evidence_root_public_key != new_policy.evidence_trust_root_public_key
    {
        return Err(ReanchorError::Trust(
            "new recovery trust bundle is not bound to the new installation policy",
        ));
    }
    let journal_root = decode_key32(&new_policy.journal_trust_root_public_key)?;
    let evidence_root = decode_key32(&new_policy.evidence_trust_root_public_key)?;
    // A new generation installs at its own initial sequence: high-waters are
    // monotonic only within a root, and the root change is bound explicitly
    // by R and C.
    crate::recovery_trust::verify_trust_bundle(
        bundle.clone(),
        &journal_root,
        &evidence_root,
        now,
        None,
        None,
    )
    .map_err(|_| {
        ReanchorError::Trust("new recovery trust bundle is stale, expired, revoked or conflicting")
    })?;
    Ok(bundle)
}

#[allow(clippy::type_complexity)]
fn verify_inputs(
    view: &GenerationView<'_>,
    observed: &ObservedGeneration,
    inputs: &RotationInputs,
    now: i64,
) -> Result<
    (
        InstallationReanchor,
        Option<Vec<u8>>,
        Option<String>,
        bool,
        Option<String>,
    ),
    ReanchorError,
> {
    // Idempotent replay: the exact published R re-presented byte-for-byte is
    // checked before any new-generation policy semantics.
    if inputs.signed_reanchor == view.state_tip_bytes {
        let record: Signed<InstallationReanchor> = decode_signed(&inputs.signed_reanchor)
            .map_err(|_| ReanchorError::Malformed("installation re-anchor is malformed"))?;
        let record = record.payload;
        if inputs.new_policy.as_slice() != view.policy_bytes
            || inputs.new_trust_bundle.as_slice() != view.fixed_bundle_bytes
        {
            return Err(ReanchorError::Conflicting(
                "idempotent replay conflicts with the published generation",
            ));
        }
        match observed.preserved_state {
            RecoveryState::NeverRecovered => {
                if inputs.signed_checkpoint.is_some() {
                    return Err(ReanchorError::Conflicting(
                        "idempotent replay conflicts with the published generation",
                    ));
                }
            }
            RecoveryState::RecoveryDesignated | RecoveryState::Released => {
                let published = view.checkpoint_bytes.ok_or(ReanchorError::Conflicting(
                    "idempotent replay conflicts with the published generation",
                ))?;
                if inputs.signed_checkpoint.as_deref() != Some(published) {
                    return Err(ReanchorError::Conflicting(
                        "idempotent replay conflicts with the published generation",
                    ));
                }
            }
        }
        verify_replay_consumption(view, &record)?;
        return Ok((record, inputs.signed_checkpoint.clone(), None, true, None));
    }
    let authority = manifest_authority(view.manifest_bytes)?;
    let new_policy = verify_new_policy(inputs, observed, &authority)?;
    let new_policy_digest = sha256_hex(&inputs.new_policy);
    let new_bundle = verify_new_bundle(inputs, &new_policy, now)?;
    verify_rotation_high_waters(&observed.trust_bundle, &new_bundle)?;
    let new_bundle_digest = sha256_hex(&inputs.new_trust_bundle);
    if new_policy.trust_bundle_digest != new_bundle_digest {
        return Err(ReanchorError::Binding(
            "new installation policy does not bind the new trust bundle digest",
        ));
    }

    let signed: Signed<InstallationReanchor> = decode_signed(&inputs.signed_reanchor)
        .map_err(|_| ReanchorError::Malformed("installation re-anchor is malformed"))?;
    let record = signed.payload;
    if record.format != REANCHOR_FORMAT {
        return Err(ReanchorError::Malformed(
            "installation re-anchor kind is unknown",
        ));
    }
    match record.sequence.cmp(&(observed.tip_sequence + 1)) {
        std::cmp::Ordering::Equal => {}
        std::cmp::Ordering::Less => {
            return Err(ReanchorError::Equivocation(
                "re-anchor sequence rollback or equal-sequence equivocation",
            ));
        }
        std::cmp::Ordering::Greater => {
            return Err(ReanchorError::Sequence(
                "re-anchor sequence must be exactly the prior tip sequence plus one",
            ));
        }
    }
    let record = verify_reanchor_document(&inputs.signed_reanchor, &authority)?.record;
    if record.signer_manifest_digest != authority.digest {
        return Err(ReanchorError::Binding(
            "re-anchor signer manifest does not authenticate this release",
        ));
    }
    if record.installation_id != observed.policy.installation_id
        || record.site_id != observed.policy.site_id
        || record.profile != observed.policy.profile
        || record.backend != observed.policy.backend
        || record.target_device != observed.policy.target_device
        || record.target_inode != observed.policy.target_inode
    {
        return Err(ReanchorError::Binding(
            "rotation cannot rebind installation, site, profile, backend, or target identity",
        ));
    }
    if record.prior_record_digest != observed.tip_digest {
        return Err(ReanchorError::Sequence(
            "re-anchor must prior-link the authenticated state tip digest",
        ));
    }
    if record.preserved_state != observed.preserved_state {
        return Err(ReanchorError::Binding(
            "re-anchor preserved state does not match the current state",
        ));
    }
    preserved_bindings_match(
        &record,
        observed.preserved_state,
        observed.preserved_operation_id.as_deref(),
        observed.preserved_artifact_sha256.as_deref(),
        observed.preserved_recovery_directory_digest.as_deref(),
        observed.preserved_terminal_journal_digest.as_deref(),
        observed.preserved_terminal_evidence_digest.as_deref(),
    )?;
    if record.prior_policy_revision != observed.policy.policy_revision
        || record.prior_policy_digest != observed.policy_digest
    {
        return Err(ReanchorError::Binding(
            "re-anchor prior policy bindings do not match the installed generation",
        ));
    }
    if record.new_policy_revision != new_policy.policy_revision
        || record.new_policy_digest != new_policy_digest
        || record.new_trust_bundle_digest != new_bundle_digest
    {
        return Err(ReanchorError::Binding(
            "re-anchor new policy or trust bindings do not match the supplied generation",
        ));
    }
    if record.prior_trust_bundle_digest != observed.trust_bundle_digest {
        return Err(ReanchorError::Binding(
            "re-anchor prior trust binding does not match the durable trust high-water",
        ));
    }
    if record.prior_journal_revocation
        != (revocation_high_water(&observed.trust_bundle.journal_revocations)?)
        || record.prior_evidence_revocation
            != (revocation_high_water(&observed.trust_bundle.evidence_revocations)?)
        || record.new_journal_revocation
            != (revocation_high_water(&new_bundle.journal_revocations)?)
        || record.new_evidence_revocation
            != (revocation_high_water(&new_bundle.evidence_revocations)?)
    {
        return Err(ReanchorError::Binding(
            "re-anchor revocation high-waters do not match the old or new trust",
        ));
    }
    let expected_reason = match (
        &record.recovery_revalidation_digest,
        &inputs.signed_revalidation,
    ) {
        (None, None) => RotationReason::Routine,
        (Some(digest), Some(bytes)) => {
            if sha256_hex(bytes) != *digest {
                return Err(ReanchorError::Evidence(
                    "re-anchor does not bind the supplied revalidation evidence digest",
                ));
            }
            RotationReason::Compromise
        }
        _ => {
            return Err(ReanchorError::Evidence(
                "revalidation evidence is required exactly for compromise rotation",
            ));
        }
    };
    if expected_reason == RotationReason::Compromise
        && (record.checkpoint_digest.is_none()
            || observed.preserved_state == RecoveryState::NeverRecovered)
    {
        return Err(ReanchorError::Evidence(
            "compromise rotation requires a checkpoint and a recovery-designated or released state",
        ));
    }

    let checkpoint = match (observed.preserved_state, &inputs.signed_checkpoint) {
        (RecoveryState::NeverRecovered, None) => None,
        (RecoveryState::RecoveryDesignated | RecoveryState::Released, Some(bytes)) => {
            let checkpoint = verify_checkpoint_document(bytes, &new_bundle)?;
            let journal = observed
                .journal
                .as_ref()
                .ok_or(ReanchorError::Binding("recovery journal is missing"))?;
            let checkpoint_digest = sha256_hex(bytes);
            let checkpoint_already_published = journal.sequence == checkpoint.sequence
                && journal.checkpoint_digest.as_deref() == Some(checkpoint_digest.as_str());
            if !checkpoint_already_published {
                if checkpoint.sequence != journal.sequence + 1 {
                    return Err(ReanchorError::Sequence(
                        "checkpoint must occupy the next journal sequence",
                    ));
                }
                if checkpoint.prior_record_digest != journal.tip_hash {
                    return Err(ReanchorError::Sequence(
                        "checkpoint must prior-link the authenticated journal tip",
                    ));
                }
                if checkpoint.prior_checkpoint_digest != journal.checkpoint_digest {
                    return Err(ReanchorError::Sequence(
                        "checkpoint prior-checkpoint binding changed",
                    ));
                }
            }
            if checkpoint.prior_state_tip_digest != observed.tip_digest {
                return Err(ReanchorError::Binding(
                    "checkpoint must bind the prior state tip, never the re-anchor",
                ));
            }
            if checkpoint.journal_directory != new_policy.journal_directory
                || checkpoint.journal_device != new_policy.journal_device
                || checkpoint.journal_inode != new_policy.journal_inode
            {
                return Err(ReanchorError::Binding(
                    "checkpoint journal directory identity changed",
                ));
            }
            if checkpoint.operation_id
                != observed.preserved_operation_id.clone().unwrap_or_default()
                || checkpoint.artifact_sha256
                    != observed
                        .preserved_artifact_sha256
                        .clone()
                        .unwrap_or_default()
            {
                return Err(ReanchorError::Binding(
                    "checkpoint operation or artifact binding changed",
                ));
            }
            if checkpoint.phase != journal.phase {
                return Err(ReanchorError::Binding(
                    "checkpoint must preserve the authenticated journal phase",
                ));
            }
            let old_cert = &observed.trust_bundle.journal_certificate.payload;
            let new_cert = &new_bundle.journal_certificate.payload;
            if checkpoint.old_journal_key_id != old_cert.key_id
                || checkpoint.old_journal_certificate_serial != old_cert.serial
                || checkpoint.new_journal_key_id != new_cert.key_id
                || checkpoint.new_journal_certificate_serial != new_cert.serial
            {
                return Err(ReanchorError::Binding(
                    "checkpoint certificate bindings do not match the old or new trust",
                ));
            }
            if checkpoint.old_journal_revocation != record.prior_journal_revocation
                || checkpoint.new_journal_revocation != record.new_journal_revocation
                || checkpoint.old_evidence_revocation != record.prior_evidence_revocation
                || checkpoint.new_evidence_revocation != record.new_evidence_revocation
            {
                return Err(ReanchorError::Binding(
                    "checkpoint revocation high-waters conflict with the re-anchor",
                ));
            }
            if checkpoint.rotation_reason != expected_reason {
                return Err(ReanchorError::Binding(
                    "checkpoint rotation reason conflicts with the re-anchor",
                ));
            }
            if checkpoint.recovery_revalidation_digest.as_deref()
                != record.recovery_revalidation_digest.as_deref()
            {
                return Err(ReanchorError::Binding(
                    "checkpoint evidence binding conflicts with the re-anchor",
                ));
            }
            if sha256_hex(bytes) != record.checkpoint_digest.as_deref().unwrap_or_default() {
                return Err(ReanchorError::Binding("re-anchor does not bind digest(C)"));
            }
            Some(bytes.clone())
        }
        (RecoveryState::NeverRecovered, Some(_)) => {
            return Err(ReanchorError::Binding(
                "never-recovered rotation must not supply a checkpoint",
            ));
        }
        (RecoveryState::RecoveryDesignated | RecoveryState::Released, None) => {
            return Err(ReanchorError::Binding(
                "re-anchor without checkpoint where required denies rotation",
            ));
        }
    };

    let evidence_digest = if expected_reason == RotationReason::Compromise {
        let bytes = inputs
            .signed_revalidation
            .as_ref()
            .ok_or(ReanchorError::Evidence(
                "revalidation evidence is required exactly for compromise rotation",
            ))?;
        let custody = inputs
            .custody_record
            .as_ref()
            .ok_or(ReanchorError::Evidence("custody record is required"))?;
        let evidence = verify_revalidation_document(bytes, &new_bundle)?;
        let checkpoint_record: Signed<JournalCheckpoint> = decode_signed(
            checkpoint
                .as_ref()
                .ok_or(ReanchorError::Binding("compromise requires a checkpoint"))?,
        )
        .map_err(|_| ReanchorError::Malformed("checkpoint is malformed"))?;
        let checkpoint_record = checkpoint_record.payload;
        if evidence.installation_id != new_policy.installation_id
            || evidence.site_id != new_policy.site_id
            || evidence.profile != new_policy.profile
            || evidence.backend != new_policy.backend
        {
            return Err(ReanchorError::Evidence(
                "revalidation evidence scope is invalid",
            ));
        }
        if evidence.operation_id != checkpoint_record.operation_id
            || evidence.artifact_sha256 != checkpoint_record.artifact_sha256
        {
            return Err(ReanchorError::Evidence(
                "revalidation evidence does not bind the rotated operation",
            ));
        }
        if evidence.target_device != new_policy.target_device
            || evidence.target_inode != new_policy.target_inode
            || evidence.observed_target_device != new_policy.target_device
            || evidence.observed_target_inode != new_policy.target_inode
        {
            return Err(ReanchorError::Evidence(
                "revalidation evidence target identity changed",
            ));
        }
        if evidence.old_journal_root_id != observed.policy.journal_trust_root_id
            || evidence.new_journal_root_id != new_policy.journal_trust_root_id
            || evidence.old_evidence_root_id != observed.policy.evidence_trust_root_id
            || evidence.new_evidence_root_id != new_policy.evidence_trust_root_id
            || evidence.old_journal_key_id
                != observed.trust_bundle.journal_certificate.payload.key_id
            || evidence.new_journal_key_id != new_bundle.journal_certificate.payload.key_id
            || evidence.old_evidence_key_id
                != observed.trust_bundle.evidence_certificate.payload.key_id
            || evidence.new_evidence_key_id != new_bundle.evidence_certificate.payload.key_id
            || evidence.old_journal_certificate_serial
                != observed.trust_bundle.journal_certificate.payload.serial
            || evidence.new_journal_certificate_serial
                != new_bundle.journal_certificate.payload.serial
            || evidence.old_evidence_certificate_serial
                != observed.trust_bundle.evidence_certificate.payload.serial
            || evidence.new_evidence_certificate_serial
                != new_bundle.evidence_certificate.payload.serial
        {
            return Err(ReanchorError::Evidence(
                "revalidation evidence does not bind the old and new authorities",
            ));
        }
        let checkpoint_signed: Signed<JournalCheckpoint> = decode_signed(
            checkpoint
                .as_ref()
                .ok_or(ReanchorError::Evidence("compromise checkpoint is missing"))?,
        )
        .map_err(|_| ReanchorError::Malformed("journal checkpoint is malformed"))?;
        if evidence.prior_state_tip_digest != observed.tip_digest
            || evidence.prior_journal_tip_digest != checkpoint_signed.payload.prior_record_digest
            || evidence.prior_checkpoint_digest != checkpoint_signed.payload.prior_checkpoint_digest
        {
            return Err(ReanchorError::Evidence(
                "revalidation evidence did not review the exact prior tips",
            ));
        }
        if evidence.old_policy_digest != observed.policy_digest
            || evidence.new_policy_digest != new_policy_digest
            || evidence.old_trust_bundle_digest != observed.trust_bundle_digest
            || evidence.new_trust_bundle_digest != new_bundle_digest
        {
            return Err(ReanchorError::Evidence(
                "revalidation evidence does not bind the old and new generations",
            ));
        }
        if evidence.custody_record_digest != sha256_hex(custody) {
            return Err(ReanchorError::Evidence(
                "revalidation evidence custody record digest changed",
            ));
        }
        if evidence.recovery_quorum_event_id.is_empty() {
            return Err(ReanchorError::Evidence(
                "revalidation evidence lacks the 2-of-3 recovery quorum event",
            ));
        }
        if !hex64(&evidence.nonce) || evidence.nonce.chars().all(|c| c == '0') {
            return Err(ReanchorError::Evidence(
                "revalidation evidence nonce must be a unique 256-bit value",
            ));
        }
        if evidence
            .expires_at
            .checked_sub(evidence.issued_at)
            .filter(|delta| *delta == REVALIDATION_VALIDITY_SECONDS)
            .is_none()
        {
            return Err(ReanchorError::Evidence(
                "revalidation evidence validity is not exactly 300 seconds",
            ));
        }
        if now < evidence.issued_at {
            return Err(ReanchorError::Evidence(
                "clock rollback denies revalidation evidence",
            ));
        }
        if now >= evidence.expires_at {
            return Err(ReanchorError::Evidence("revalidation evidence is expired"));
        }
        if !evidence.exact_tips_reviewed {
            return Err(ReanchorError::Evidence(
                "revalidation evidence must state the exact tips were reviewed",
            ));
        }
        // Compromise rotation revokes the old root by a revocation document
        // signed by the new trust root, authenticated by the new policy.
        let old_journal = &observed.trust_bundle.journal_certificate.payload;
        let old_evidence = &observed.trust_bundle.evidence_certificate.payload;
        let journal_revocations = &new_bundle.journal_revocations.payload;
        let evidence_revocations = &new_bundle.evidence_revocations.payload;
        if !journal_revocations
            .revoked_serials
            .contains(&old_journal.serial)
            || !journal_revocations
                .revoked_key_ids
                .contains(&old_journal.key_id)
            || !evidence_revocations
                .revoked_serials
                .contains(&old_evidence.serial)
            || !evidence_revocations
                .revoked_key_ids
                .contains(&old_evidence.key_id)
        {
            return Err(ReanchorError::Trust(
                "compromise rotation must revoke the old root with the new trust root",
            ));
        }
        (Some(sha256_hex(bytes)), Some(evidence.nonce))
    } else {
        (None, None)
    };
    let (evidence_digest, evidence_nonce) = evidence_digest;
    Ok((record, checkpoint, evidence_digest, false, evidence_nonce))
}

fn verify_replay_consumption(
    view: &GenerationView<'_>,
    record: &InstallationReanchor,
) -> Result<(), ReanchorError> {
    match (
        &record.recovery_revalidation_digest,
        view.consumption_record_bytes,
    ) {
        (None, _) => Ok(()),
        (Some(evidence_digest), Some(bytes)) => {
            let consumption: RevalidationConsumption = decode_signed(bytes).map_err(|_| {
                ReanchorError::Malformed("revalidation consumption record is malformed")
            })?;
            if consumption.format != CONSUMPTION_FORMAT
                || &consumption.evidence_digest != evidence_digest
                || consumption.reanchor_digest != sha256_hex(view.state_tip_bytes)
                || consumption.checkpoint_digest
                    != record.checkpoint_digest.as_deref().unwrap_or_default()
            {
                return Err(ReanchorError::Evidence(
                    "revalidation evidence consumption does not bind this re-anchor pair",
                ));
            }
            Ok(())
        }
        (Some(_), None) => Err(ReanchorError::Evidence(
            "revalidation consumption record is missing",
        )),
    }
}

/// Builds the exact, ordered, crash-safe publication plan. Every input is
/// verified against the authenticated current generation first; the plan
/// carries only byte publications and prior-byte expectations.
pub fn build_rotation_plan(
    view: &GenerationView<'_>,
    archives: &dyn ArchiveLookup,
    inputs: &RotationInputs,
    now: i64,
) -> Result<RotationPlan, ReanchorError> {
    // Quiescence gate: no unsigned or in-flight journal signing request may
    // exist before the state and journal tips are observed.
    if view.pending_signing_request_present {
        return Err(ReanchorError::Quiescence(
            "an unsigned or in-flight journal signing request denies rotation",
        ));
    }
    if let Some(pending_bytes) = view.pending_reanchor_bytes {
        let authority = manifest_authority(view.manifest_bytes)?;
        let pending = verify_reanchor_document(pending_bytes, &authority)?.record;
        if pending.prior_record_digest == sha256_hex(view.state_tip_bytes)
            && pending_bytes != inputs.signed_reanchor.as_slice()
        {
            return Err(ReanchorError::Conflicting(
                "a pending rotation permits only the exact signed re-anchor pair",
            ));
        }
    }
    // A complete current generation observes directly; a partial one (crash
    // resume, §7.3.9) re-verifies the signed R/C against the durable prior
    // bytes and continues forward only.
    let (observed, prior) = match observe_current(view, archives) {
        Ok(observed) => (
            observed,
            PriorBytes {
                fixed_policy: view.policy_bytes.to_vec(),
                policy_high_water: view
                    .policy_high_water_bytes
                    .unwrap_or(view.policy_bytes)
                    .to_vec(),
                fixed_trust: view.fixed_bundle_bytes.to_vec(),
                trust_high_water: view.trust_high_water_bytes.to_vec(),
                state_tip: view.state_tip_bytes.to_vec(),
            },
        ),
        Err(error) => {
            if view.pending_reanchor_bytes == Some(inputs.signed_reanchor.as_slice()) {
                observe_resume(view, archives, inputs)?
            } else {
                let authority = manifest_authority(view.manifest_bytes)?;
                let r = verify_reanchor_document(&inputs.signed_reanchor, &authority)?.record;
                if r.recovery_revalidation_digest.is_none() || inputs.signed_revalidation.is_none()
                {
                    return Err(error);
                }
                // Historical verification supplies no new authority. The
                // policy-signed R and fresh new-authority evidence are fully
                // verified by verify_inputs before any publication plan exists.
                let signed = tip_envelope(view.state_tip_bytes)?;
                let historical = match signed
                    .payload
                    .get("format")
                    .and_then(serde_json::Value::as_str)
                {
                    Some(REANCHOR_FORMAT) => {
                        authenticate_rotated_generation_with_history(view, archives, true)?
                    }
                    Some("o3k-installation-state-v1") => {
                        observe_disposition_generation_with_history(view, archives, true)?
                    }
                    _ => return Err(error),
                };
                (
                    historical,
                    PriorBytes {
                        fixed_policy: view.policy_bytes.to_vec(),
                        policy_high_water: view
                            .policy_high_water_bytes
                            .unwrap_or(view.policy_bytes)
                            .to_vec(),
                        fixed_trust: view.fixed_bundle_bytes.to_vec(),
                        trust_high_water: view.trust_high_water_bytes.to_vec(),
                        state_tip: view.state_tip_bytes.to_vec(),
                    },
                )
            }
        }
    };
    let (_record, checkpoint, evidence_digest, identity_replay, evidence_nonce) =
        verify_inputs(view, &observed, inputs, now)?;
    let reanchor_digest = sha256_hex(&inputs.signed_reanchor);
    let checkpoint_digest = checkpoint.as_deref().map(sha256_hex).unwrap_or_default();

    if identity_replay {
        return Ok(RotationPlan {
            preserved_state: observed.preserved_state,
            reanchor_digest,
            identity_replay: true,
            staged: Vec::new(),
            fixed_policy: Vec::new(),
            policy_high_water: Vec::new(),
            fixed_trust: Vec::new(),
            trust_high_water: Vec::new(),
            checkpoint: None,
            checkpoint_prior: None,
            reanchor: inputs.signed_reanchor.clone(),
            archives: Vec::new(),
            consumption: None,
            consumption_archive: None,
            prior: PriorBytes {
                fixed_policy: Vec::new(),
                policy_high_water: Vec::new(),
                fixed_trust: Vec::new(),
                trust_high_water: Vec::new(),
                state_tip: view.state_tip_bytes.to_vec(),
            },
        });
    }

    let mut staged = vec![
        (
            RotationArea::StateRoot,
            STAGED_POLICY_NAME,
            inputs.new_policy.clone(),
        ),
        (
            RotationArea::StateRoot,
            STAGED_TRUST_NAME,
            inputs.new_trust_bundle.clone(),
        ),
        (
            RotationArea::StateRoot,
            STAGED_REANCHOR_NAME,
            inputs.signed_reanchor.clone(),
        ),
        // Inert staged prior bytes make every crash point resumable even
        // after both high-waters have advanced (§7.3.9 exact-forward resume).
        (
            RotationArea::StateRoot,
            STAGED_PRIOR_POLICY_NAME,
            prior.fixed_policy.clone(),
        ),
        (
            RotationArea::StateRoot,
            STAGED_PRIOR_TRUST_NAME,
            prior.trust_high_water.clone(),
        ),
    ];
    let mut archives_to_write: Vec<(RotationArea, String, Vec<u8>)> = vec![
        (
            RotationArea::StateRoot,
            format!("state-{}.json", observed.tip_digest),
            prior.state_tip.clone(),
        ),
        (
            RotationArea::StateRoot,
            format!("policy-{}.json", observed.policy_digest),
            prior.policy_high_water.clone(),
        ),
        (
            RotationArea::StateRoot,
            format!("trust-{}.json", observed.trust_bundle_digest),
            prior.trust_high_water.clone(),
        ),
    ];
    if let Some(journal) = &observed.journal
        && let (Some(prior_digest), Some(prior_bytes)) =
            (&journal.checkpoint_digest, view.checkpoint_bytes)
    {
        archives_to_write.push((
            RotationArea::JournalDir,
            format!("checkpoint-{prior_digest}.json"),
            prior_bytes.to_vec(),
        ));
    }
    if let Some(checkpoint) = &checkpoint {
        staged.push((
            RotationArea::JournalDir,
            STAGED_CHECKPOINT_NAME,
            checkpoint.clone(),
        ));
    }

    // Single-use evidence: the consumption record is durable before the pair
    // is accepted and marked consumed only after final observation. A consumed
    // record from an earlier compromise rotation is archived under its
    // content-addressed name so the nonce ledger stays durable; the plan-time
    // nonce check rejects an immediate reuse and `run_rotation_plan` repeats
    // the check against every retained record.
    let (consumption, consumption_archive) = match (&evidence_digest, &evidence_nonce) {
        (Some(digest), Some(nonce)) => {
            let existing = view
                .consumption_record_bytes
                .map(|bytes| -> Result<RevalidationConsumption, ReanchorError> {
                    decode_signed(bytes).map_err(|_| {
                        ReanchorError::Malformed("revalidation consumption record is malformed")
                    })
                })
                .transpose()?;
            let decision = plan_consumption(
                existing.as_ref(),
                digest,
                &reanchor_digest,
                &checkpoint_digest,
                nonce,
            )?;
            (decision.record, decision.archive)
        }
        (None, None) => (None, None),
        _ => {
            return Err(ReanchorError::Evidence(
                "revalidation evidence digest or nonce is missing",
            ));
        }
    };

    Ok(RotationPlan {
        preserved_state: observed.preserved_state,
        reanchor_digest,
        identity_replay: false,
        staged,
        fixed_policy: inputs.new_policy.clone(),
        policy_high_water: inputs.new_policy.clone(),
        fixed_trust: inputs.new_trust_bundle.clone(),
        trust_high_water: inputs.new_trust_bundle.clone(),
        checkpoint: checkpoint.clone(),
        checkpoint_prior: view.checkpoint_bytes.map(|bytes| bytes.to_vec()),
        reanchor: inputs.signed_reanchor.clone(),
        archives: archives_to_write,
        consumption,
        consumption_archive,
        prior,
    })
}

// ---------------------------------------------------------------------------
// Ordered, crash-safe publication with exact-forward resume.
// ---------------------------------------------------------------------------

fn crash_at(point: &'static str) -> Result<(), ReanchorError> {
    #[cfg(feature = "backup-test-hooks")]
    {
        // Each boundary fires at most once per process so an exact-forward
        // resume in the same test process continues past the injected crash.
        static FIRED: std::sync::OnceLock<
            std::sync::Mutex<std::collections::BTreeSet<&'static str>>,
        > = std::sync::OnceLock::new();
        if std::env::var("O3K_REANCHOR_CRASH_AT").ok().as_deref() == Some(point)
            && FIRED
                .get_or_init(|| std::sync::Mutex::new(std::collections::BTreeSet::new()))
                .lock()
                .map(|mut fired| fired.insert(point))
                .unwrap_or(false)
        {
            return Err(ReanchorError::InjectedCrash(point));
        }
    }
    let _ = point;
    Ok(())
}

#[derive(Debug, PartialEq, Eq)]
enum SlotState {
    Empty,
    Prior,
    Current,
    Conflicting,
}

fn classify(current: Option<&[u8]>, prior: Option<&[u8]>, expected: &[u8]) -> SlotState {
    match current {
        None => SlotState::Empty,
        Some(bytes) if bytes == expected => SlotState::Current,
        Some(bytes) if prior.is_some_and(|prior| bytes == prior) => SlotState::Prior,
        Some(_) => SlotState::Conflicting,
    }
}

fn publish_step(
    store: &mut dyn RotationStore,
    area: RotationArea,
    name: &str,
    prior: Option<&[u8]>,
    expected: &[u8],
) -> Result<(), ReanchorError> {
    match classify(store.read(area, name)?.as_deref(), prior, expected) {
        SlotState::Current => Ok(()),
        SlotState::Empty if prior.is_none() => store.publish(area, name, expected),
        SlotState::Empty | SlotState::Prior => store.publish(area, name, expected),
        SlotState::Conflicting => Err(ReanchorError::Conflicting(
            "conflicting durable bytes require operator inspection",
        )),
    }
}

/// Every retained consumption record (the current record plus every
/// content-addressed archive) participates in the nonce uniqueness ledger: a
/// nonce bound to a different evidence digest fails closed. The check runs
/// before any publication, so a rejected attempt leaves the durable
/// generation untouched; it repeats the plan-time check for records that are
/// no longer current and survives restarts because the ledger is durable.
fn reject_nonce_reuse(
    store: &dyn RotationStore,
    new_record: &RevalidationConsumption,
) -> Result<(), ReanchorError> {
    for name in store.list(RotationArea::StateRoot)? {
        let archived = name
            .strip_prefix("revalidation-consumption-")
            .and_then(|rest| rest.strip_suffix(".json"))
            .is_some_and(hex64);
        if name != CONSUMPTION_NAME && !archived {
            continue;
        }
        let Some(bytes) = store.read(RotationArea::StateRoot, &name)? else {
            continue;
        };
        let record: RevalidationConsumption = decode_signed(&bytes).map_err(|_| {
            ReanchorError::Malformed("revalidation consumption record is malformed")
        })?;
        if record.format != CONSUMPTION_FORMAT {
            return Err(ReanchorError::Malformed(
                "revalidation consumption record is malformed",
            ));
        }
        if record.nonce == new_record.nonce && record.evidence_digest != new_record.evidence_digest
        {
            return Err(ReanchorError::Evidence(
                "revalidation evidence nonce was already consumed by different evidence",
            ));
        }
    }
    Ok(())
}

/// Publishes the plan in the accepted order. Every boundary is an exact
/// resume point: a crash restarts from the signed R/C and continues forward
/// only; conflicting or equivocated bytes fail closed. `observe` performs the
/// authenticated whole-generation re-read before success is reported.
pub fn run_rotation_plan(
    plan: &RotationPlan,
    store: &mut dyn RotationStore,
    observe: &mut dyn FnMut(&dyn RotationStore) -> Result<(), ReanchorError>,
) -> Result<(), ReanchorError> {
    // The nonce uniqueness ledger is consulted before anything is staged, so
    // a rejected single-use evidence performs no durable writes at all.
    if let Some(consumption) = &plan.consumption {
        reject_nonce_reuse(store, consumption)?;
    }

    if plan.identity_replay {
        crash_at("before-final-observation")?;
        observe(store)?;
        crash_at("after-final-observation")?;
        // A crash between the observation and the mark leaves the durable
        // binding unconsumed; the exact replay completes the mark.
        let replay: Signed<InstallationReanchor> = decode_signed(&plan.reanchor)?;
        if replay.payload.recovery_revalidation_digest.is_some() {
            mark_consumption(store, &plan.reanchor_digest)?;
            crash_at("after-consumption-mark")?;
        }
        return Ok(());
    }

    // 1. Staging: staged bytes are inert and never read by verifiers. The
    // fixed staged names are reusable scratch across rotations, so a prior
    // rotation's staged bytes are simply overwritten; authority slots keep
    // their exact prior-byte expectations below.
    crash_at("before-stage")?;
    for (area, name, bytes) in &plan.staged {
        store.publish(*area, name, bytes)?;
    }
    crash_at("after-stage")?;

    // Archive every prior generation byte before any current-name slot is
    // replaced. Content-addressed archive publication is inert and idempotent;
    // doing it first is what makes a crash after replacing policy, trust, or
    // checkpoint exactly resumable.
    for (area, name, bytes) in &plan.archives {
        publish_step(store, *area, name, None, bytes)?;
    }

    // 2. Durable consumption record before the R/C pair is accepted.
    if let Some(consumption) = &plan.consumption {
        crash_at("before-consumption-write")?;
        if let Some((name, bytes)) = &plan.consumption_archive {
            publish_step(store, RotationArea::StateRoot, name, None, bytes)?;
        }
        let prior = plan
            .consumption_archive
            .as_ref()
            .map(|(_, bytes)| bytes.as_slice());
        let bytes = identity::canonical(consumption)
            .map_err(|_| ReanchorError::Persistence("consumption record cannot be encoded"))?;
        publish_step(
            store,
            RotationArea::StateRoot,
            CONSUMPTION_NAME,
            prior,
            &bytes,
        )?;
        crash_at("after-consumption-write")?;
    }

    // 3. Fixed policy file, then the policy high-water {revision, digest}.
    crash_at("before-publish-policy")?;
    publish_step(
        store,
        RotationArea::FixedConfig,
        FIXED_POLICY_NAME,
        Some(&plan.prior.fixed_policy),
        &plan.fixed_policy,
    )?;
    crash_at("after-publish-policy")?;
    crash_at("before-publish-policy-high-water")?;
    publish_step(
        store,
        RotationArea::StateRoot,
        POLICY_HIGH_WATER_NAME,
        Some(&plan.prior.policy_high_water),
        &plan.policy_high_water,
    )?;
    crash_at("after-publish-policy-high-water")?;

    // 4. Fixed trust bundle, then the trust high-water.
    crash_at("before-publish-trust")?;
    publish_step(
        store,
        RotationArea::FixedConfig,
        FIXED_TRUST_NAME,
        Some(&plan.prior.fixed_trust),
        &plan.fixed_trust,
    )?;
    crash_at("after-publish-trust")?;
    crash_at("before-publish-trust-high-water")?;
    publish_step(
        store,
        RotationArea::StateRoot,
        TRUST_HIGH_WATER_NAME,
        Some(&plan.prior.trust_high_water),
        &plan.trust_high_water,
    )?;
    crash_at("after-publish-trust-high-water")?;

    // 5. The immutable journal checkpoint C before R.
    if let Some(checkpoint) = &plan.checkpoint {
        crash_at("before-publish-checkpoint")?;
        publish_step(
            store,
            RotationArea::JournalDir,
            CHECKPOINT_NAME,
            plan.checkpoint_prior.as_deref(),
            checkpoint,
        )?;
        crash_at("after-publish-checkpoint")?;
    }

    // 6. Publish R as the new state tip after C and the archived prior bytes.
    crash_at("before-publish-reanchor")?;
    publish_step(
        store,
        RotationArea::StateRoot,
        STATE_NAME,
        Some(&plan.prior.state_tip),
        &plan.reanchor,
    )?;
    crash_at("after-publish-reanchor")?;

    // 7. Re-read and authenticate the whole generation before success.
    crash_at("before-final-observation")?;
    observe(store)?;
    crash_at("after-final-observation")?;

    // 8. Only now is the single-use evidence marked consumed.
    if plan.consumption.is_some() {
        crash_at("before-consumption-mark")?;
        mark_consumption(store, &plan.reanchor_digest)?;
        crash_at("after-consumption-mark")?;
    }
    Ok(())
}

/// Marks the durable consumption record consumed when it exists, binds the
/// exact re-anchor digest, and is not yet marked. Binding consistency was
/// authenticated by the final observation.
fn mark_consumption(
    store: &mut dyn RotationStore,
    reanchor_digest: &str,
) -> Result<(), ReanchorError> {
    let Some(bytes) = store.read(RotationArea::StateRoot, CONSUMPTION_NAME)? else {
        return Ok(());
    };
    let mut consumption: RevalidationConsumption = decode_signed(&bytes)
        .map_err(|_| ReanchorError::Malformed("revalidation consumption record is malformed"))?;
    if consumption.reanchor_digest != reanchor_digest {
        return Err(ReanchorError::Evidence(
            "revalidation evidence consumption does not bind this re-anchor pair",
        ));
    }
    if !consumption.consumed {
        consumption.consumed = true;
        let bytes = identity::canonical(&consumption)
            .map_err(|_| ReanchorError::Persistence("consumption record cannot be encoded"))?;
        store.publish(RotationArea::StateRoot, CONSUMPTION_NAME, &bytes)?;
    }
    Ok(())
}

// ---------------------------------------------------------------------------
// Pre-C1.1 strict verifier fixture.
// ---------------------------------------------------------------------------

/// The pre-C1.1 startup verifier accepted only `o3k-installation-state-v1`
/// disposition records. Unknown R and C records deny startup under it, which
/// is why rotation is performed only after every reading verifier supports
/// C1.1. This fixture preserves that strict behavior for regression evidence.
pub fn verify_pre_c11_state_tip(bytes: &[u8]) -> Result<(), ReanchorError> {
    let signed: Signed<InstallationState> = decode_signed(bytes)
        .map_err(|_| ReanchorError::Malformed("pre-C1.1 verifier denies the unknown record"))?;
    if signed.payload.format != "o3k-installation-state-v1" {
        return Err(ReanchorError::Malformed(
            "pre-C1.1 verifier denies the unknown record",
        ));
    }
    Ok(())
}

// ---------------------------------------------------------------------------
// Production driver (root-only installer operation).
// ---------------------------------------------------------------------------

/// Executes a rotation against the authenticated installed recovery state.
/// This is the only filesystem-backed entry point; every structural decision
/// lives in the pure functions above so the behavior is directly testable.
pub fn rotate(
    installed: &crate::recovery_installation::InstalledRecovery,
    inputs: &RotationInputs,
) -> Result<(), ReanchorError> {
    use std::path::Path;
    if rustix::process::geteuid().as_raw() != 0 {
        return Err(ReanchorError::NotRoot);
    }
    let data_dir = Path::new(&installed.policy.data_root);
    // Quiesce all store openers with the existing D4 lifetime exclusive lock:
    // the policy-bound data-directory flock taken here stays held on the
    // installation's directory descriptor for the whole rotation, excluding
    // every store opener that holds the same inode through
    // `o3k_store::StoreAccessLock`. Acquiring `StoreAccessLock` here is
    // deliberately avoided: it requires the data directory to be owned by
    // the caller, which the root installer can never satisfy on the
    // service-owned packaged data root, and its separate lock description
    // would conflict with the D4 lock held above.
    installed.quiesce_data_directory()?;
    // Re-read the complete policy/trust/journal view after acquiring the D4
    // quiescence lock: the caller's snapshot predates the lock, and conflict
    // classification alone cannot observe every drift of the published
    // generation. `load_partial` re-validates every record's posture and
    // signature without requiring the whole generation to authenticate, and
    // carries the durable policy high-water and staged prior-generation bytes
    // the exact-forward resume observation needs.
    let installed = &crate::recovery_installation::InstalledRecovery::load_partial(data_dir)
        .map_err(|_| {
            ReanchorError::Quiescence(
                "protected installation state cannot be observed after quiescence",
            )
        })?;

    let (uid, gid) = crate::recovery_installation::service_identity()
        .map_err(|_| ReanchorError::Quiescence("o3k service identity is unavailable"))?;
    installed.strict_pending_signing_request_exclusion(uid, gid)?;
    let view = installed.generation_view(uid, gid)?;
    let mut store = installed.rotation_store(uid, gid)?;
    let archives = installed.archive_lookup(uid, gid);
    let now = chrono::Utc::now().timestamp();
    let plan = build_rotation_plan(&view, &archives, inputs, now)?;
    run_rotation_plan(&plan, &mut store, &mut |_store| {
        let observed = crate::recovery_installation::InstalledRecovery::load(data_dir)
            .map_err(ReanchorError::Persistence)?;
        if observed.preserved_state() != plan.preserved_state {
            return Err(ReanchorError::Binding(
                "rotation changed the preserved recovery state",
            ));
        }
        Ok(())
    })?;
    Ok(())
}
